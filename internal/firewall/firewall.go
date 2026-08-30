// Package firewall drives nftables directly over netlink (no shelling out to the
// `nft` binary). It owns exactly one table containing one allow-set and the rules
// that gate the game port. The kernel manages set-entry expiry via a per-element
// timeout, so this package stays close to stateless.
//
// SAFETY MODEL
//
//	Enable()  installs: game-port packets from IPs NOT in the allow-set are dropped;
//	          beacon/query ports are always accepted.
//	Allow(ip) adds an IP to the set with a TTL (kernel-expired).
//	Disable() removes the drop rule, reverting the game port to accept-all. This is
//	          the fail-open path and MUST be safe to call at any time, including
//	          from a deferred shutdown handler after a partial setup.
//
// The invariant: if this daemon is not healthy, the drop rule must not be in
// place. Disable() is how we guarantee that.
package firewall

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// policyAccept is the chain's default verdict. Accept, always: the drop must come
// from an explicit rule we can delete, never from the chain policy — a policy we
// failed to reset would lock every player out.
var policyAccept = nftables.ChainPolicyAccept

type Config struct {
	Table      string
	Set        string
	GamePort   uint16
	BeaconPort uint16
	QueryPort  uint16
	AllowTTL   time.Duration
}

type Firewall struct {
	cfg   Config
	conn  *nftables.Conn
	table *nftables.Table
	set   *nftables.Set
	// dropRule is retained so Disable() can delete precisely what Enable() added.
	dropRule *nftables.Rule
}

func New(cfg Config) (*Firewall, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("open netlink: %w", err)
	}
	return &Firewall{cfg: cfg, conn: c}, nil
}

// EnsureTableAndSet creates the table and the allow-set if absent. Idempotent:
// safe to call on every startup. Does NOT install the drop rule — that is Enable().
// This split lets log-only mode maintain the allow-set (so the set is warm and
// validated) without ever dropping a packet.
func (f *Firewall) EnsureTableAndSet() error {
	f.table = f.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   f.cfg.Table,
	})

	f.set = &nftables.Set{
		Table:      f.table,
		Name:       f.cfg.Set,
		KeyType:    nftables.TypeIPAddr,
		HasTimeout: true, // kernel expires entries
		Timeout:    f.cfg.AllowTTL,
	}
	if err := f.conn.AddSet(f.set, nil); err != nil {
		return fmt.Errorf("add set: %w", err)
	}
	return f.conn.Flush()
}

// Allow adds ip to the allow-set with the configured TTL. Cheap; called on every
// beacon-authed event. Only IPv4 handled here — extend for v6 if your player base
// needs it (the KeyType/set would need widening).
func (f *Firewall) Allow(ip netip.Addr) error {
	if !ip.Is4() {
		return fmt.Errorf("non-ipv4 address not supported: %s", ip)
	}
	v4 := ip.As4()
	err := f.conn.SetAddElements(f.set, []nftables.SetElement{
		{Key: v4[:], Timeout: f.cfg.AllowTTL},
	})
	if err != nil {
		return fmt.Errorf("add element %s: %w", ip, err)
	}
	return f.conn.Flush()
}

// Enable installs the gating chain and drop rule. After this, game-port traffic
// from IPs not in the allow-set is dropped. Beacon and query ports are accepted
// unconditionally so players can always authenticate.
//
// Chain layout (inet family, input hook):
//
//	udp dport {beacon,query}                accept
//	udp dport game  ip saddr @allowed       accept
//	udp dport game                          drop   <-- retained as f.dropRule
func (f *Firewall) Enable() error {
	chain := f.conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    f.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityRef(-10), // ahead of most default rules
		Policy:   &policyAccept, // fail-open default: an empty/half-built chain accepts
	})

	// accept beacon
	f.acceptUDPPort(chain, f.cfg.BeaconPort)
	// accept query
	f.acceptUDPPort(chain, f.cfg.QueryPort)
	// accept game when source is in the allow-set
	f.acceptGameIfAllowed(chain)
	// drop everything else on the game port — kept for precise teardown
	f.dropRule = f.dropGamePort(chain)

	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("enable: %w", err)
	}
	return nil
}

// Disable reverts to accept-all by deleting the whole gating chain. Safe to call
// even if Enable was never run or only partially ran: missing objects are ignored.
// This is the fail-open guarantee.
func (f *Firewall) Disable() error {
	if f.table == nil {
		return nil
	}
	// Deleting the chain removes its rules atomically. The allow-set and table are
	// left intact so a subsequent Enable is cheap. Errors here are logged by the
	// caller but must not block shutdown.
	f.conn.DelChain(&nftables.Chain{
		Name:    "input",
		Table:   f.table,
		Type:    nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput,
	})
	f.dropRule = nil
	return f.conn.Flush()
}

// --- rule builders -------------------------------------------------------------
// These construct the expression sequences for each rule. Extracted for
// readability; each returns the created rule where the caller needs a handle.

func (f *Firewall) acceptUDPPort(chain *nftables.Chain, port uint16) {
	f.conn.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: chain,
		Exprs: append(matchUDPDport(port), &expr.Verdict{Kind: expr.VerdictAccept}),
	})
}

func (f *Firewall) acceptGameIfAllowed(chain *nftables.Chain) {
	exprs := matchUDPDport(f.cfg.GamePort)
	// load source address, look it up in the allow-set
	exprs = append(exprs,
		&expr.Payload{ // ip saddr into reg 1
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12, // src addr offset in IPv4 header
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        f.cfg.Set,
			SetID:          f.set.ID,
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	f.conn.AddRule(&nftables.Rule{Table: f.table, Chain: chain, Exprs: exprs})
}

func (f *Firewall) dropGamePort(chain *nftables.Chain) *nftables.Rule {
	r := &nftables.Rule{
		Table: f.table,
		Chain: chain,
		Exprs: append(matchUDPDport(f.cfg.GamePort), &expr.Verdict{Kind: expr.VerdictDrop}),
	}
	return f.conn.AddRule(r)
}

// matchUDPDport builds the expr sequence matching "udp dport == port".
func matchUDPDport(port uint16) []expr.Any {
	return []expr.Any{
		// meta l4proto == udp
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x11}}, // 17 = UDP
		// udp dport == port (offset 2 in UDP header, transport base)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(port)},
	}
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
