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
	"golang.org/x/sys/unix"
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

	// LogDropped puts the source address of dropped packets into the kernel log.
	// Off by default: it is the one path where an attacker controls how much you
	// write to disk. LogRate caps that, but the safest volume is none.
	LogDropped bool
	// LogRate is the per-second ceiling on those log lines. Zero means 10.
	LogRate uint64
}

type Firewall struct {
	cfg   Config
	conn  *nftables.Conn
	table *nftables.Table
	set   *nftables.Set
	// dropRule is retained so Disable() can delete precisely what Enable() added
	// and so DropCount() can read its counter. The log rule needs no handle: it
	// goes away with the chain.
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
		Policy:   &policyAccept,                  // fail-open default: an empty/half-built chain accepts
	})

	// accept beacon
	f.acceptUDPPort(chain, f.cfg.BeaconPort)
	// accept query
	f.acceptUDPPort(chain, f.cfg.QueryPort)
	// accept game when source is in the allow-set
	f.acceptGameIfAllowed(chain)
	// log a rate-limited sample of what is about to be dropped, for IOC sharing
	if f.cfg.LogDropped {
		f.logDropped(chain)
	}
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
		// The counter makes the drop visible at all: without it a blocked packet
		// leaves no trace anywhere, and an attack looks identical to silence.
		Exprs: append(matchUDPDport(f.cfg.GamePort), &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}),
	}
	return f.conn.AddRule(r)
}

// logDropped logs a rate-limited sample of the packets the NEXT rule drops, so
// the attacker's source addresses land in the kernel log (journalctl -k) where
// they can be pulled out and shared with other hosts.
//
// SAFETY: this is a SEPARATE rule with NO verdict, sitting immediately before the
// drop rule. It must stay that way. Folding the limit into the drop rule would
// invert the filter: a limit expression does not match once the rate is exceeded,
// so the rule would stop early and the packet would fall through to the chain's
// accept policy — i.e. flooding fast enough would defeat the gate entirely. Here,
// exceeding the rate merely stops the logging; the drop below is unconditional.
//
// The rate cap is what keeps an attacker from turning your disk into the target:
// 10 lines/second regardless of how many packets arrive.
func (f *Firewall) logDropped(chain *nftables.Chain) *nftables.Rule {
	rate := f.cfg.LogRate
	if rate == 0 {
		rate = 10
	}
	exprs := append(matchUDPDport(f.cfg.GamePort),
		&expr.Limit{
			Type:  expr.LimitTypePkts,
			Rate:  rate,
			Unit:  expr.LimitTimeSecond,
			Burst: 5,
		},
		&expr.Log{
			Key:  1 << unix.NFTA_LOG_PREFIX,
			Data: []byte("pstnhub-guardian drop: "),
		},
	)
	return f.conn.AddRule(&nftables.Rule{Table: f.table, Chain: chain, Exprs: exprs})
}

// DropCount returns the packet and byte totals on the drop rule, or ok=false if
// the rule is not installed (log-only mode) or cannot be read.
func (f *Firewall) DropCount() (packets, bytes uint64, ok bool) {
	if f.dropRule == nil || f.table == nil {
		return 0, 0, false
	}
	rules, err := f.conn.GetRules(f.table, f.dropRule.Chain)
	if err != nil {
		return 0, 0, false
	}
	for _, r := range rules {
		if r.Handle != f.dropRule.Handle {
			continue
		}
		for _, e := range r.Exprs {
			if c, isCounter := e.(*expr.Counter); isCounter {
				return c.Packets, c.Bytes, true
			}
		}
	}
	return 0, 0, false
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
