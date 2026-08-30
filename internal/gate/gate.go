// Package gate is the decision layer. It consumes parsed events and:
//   - on a beacon-authed event, allow-lists the IP (always, both modes)
//   - on a game-accepted event whose IP is NOT allow-listed, records a would-be
//     drop (log-only mode) or notes the anomaly (enforce mode — where the kernel
//     already dropped earlier attempts, so a game-accepted from an unknown IP is
//     itself notable)
//
// It keeps a mirror of the allow-set in memory purely so log-only mode can answer
// "would this have been dropped?" without querying the kernel per packet. The
// kernel set remains the source of truth for actual enforcement.
package gate

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/pstnhub/pstnhub-guardian/internal/firewall"
	"github.com/pstnhub/pstnhub-guardian/internal/notifier"
	"github.com/pstnhub/pstnhub-guardian/internal/parser"
)

type Gate struct {
	fw      *firewall.Firewall
	notif   *notifier.Notifier
	log     *slog.Logger
	enforce bool
	ttl     time.Duration
	// server names this gate in alerts. Logs get it from the logger category,
	// but Discord titles are shared across servers and must say which one.
	server string

	mu      sync.Mutex
	allowed map[netip.Addr]time.Time // in-memory mirror, value = expiry
	eos     map[netip.Addr]string    // last EOS id seen beaconing from that IP
	// banned IPs are refused re-entry to the allow-list. Populated only by the
	// exploit path. In memory only: a restart clears it, deliberately — a
	// permanent ban belongs in your admin list against the EOS id, not here.
	banned map[netip.Addr]bool
}

func New(fw *firewall.Firewall, notif *notifier.Notifier, log *slog.Logger, enforce bool, ttl time.Duration, server string) *Gate {
	return &Gate{
		fw:      fw,
		notif:   notif,
		log:     log,
		enforce: enforce,
		ttl:     ttl,
		server:  server,
		allowed: make(map[netip.Addr]time.Time),
		eos:     make(map[netip.Addr]string),
		banned:  make(map[netip.Addr]bool),
	}
}

// Seed pre-populates the in-memory mirror and the kernel set from persisted state
// on startup. Critical for the crash->restart->crash window: without it every
// reconnecting player looks unauthenticated until they re-beacon.
func (g *Gate) Seed(ips map[netip.Addr]time.Time) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for ip, exp := range ips {
		if exp.Before(now) {
			continue
		}
		g.allowed[ip] = exp
		if err := g.fw.Allow(ip); err != nil {
			g.log.Warn("seed allow failed", "ip", ip, "err", err)
		}
	}
}

// Snapshot returns the current non-expired allow-list for persistence.
func (g *Gate) Snapshot() map[netip.Addr]time.Time {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[netip.Addr]time.Time, len(g.allowed))
	for ip, exp := range g.allowed {
		if exp.After(now) {
			out[ip] = exp
		}
	}
	return out
}

// Handle processes one parsed event.
func (g *Gate) Handle(ev parser.Event) {
	switch ev.Kind {
	case parser.KindBeaconAuthed:
		g.allow(ev.IP, ev.EOSID, ev.At)
	case parser.KindGameAccepted:
		g.checkGame(ev.IP)
	case parser.KindExploit:
		g.revoke(ev.IP)
	}
}

// allow puts ip on the allow-list until at+ttl. at is the moment the beacon
// actually completed: time.Now() for a live line, an age-corrected clock time
// for one replayed by Backfill (zero means "now"). Backfilled and live events
// race by design, so the later expiry always wins — a replayed line from ten
// minutes ago must never shorten an allow just granted.
func (g *Gate) allow(ip netip.Addr, eos string, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	exp := at.Add(g.ttl)

	g.mu.Lock()
	if g.banned[ip] {
		g.mu.Unlock()
		g.log.Warn("refused re-allow of banned IP", "ip", ip, "eos", eos)
		return
	}
	if eos != "" {
		g.eos[ip] = eos
	}
	if cur, ok := g.allowed[ip]; !ok || exp.After(cur) {
		g.allowed[ip] = exp
	}
	g.mu.Unlock()

	// ponytail: the kernel set gets the full TTL, not the remaining one, so a
	// backfilled IP sits in nftables a little longer than in the mirror. Harmless
	// (it only ever over-allows an IP that did authenticate); switch to a
	// per-element timeout if that slack ever matters.
	if err := g.fw.Allow(ip); err != nil {
		g.log.Error("allow failed", "ip", ip, "err", err)
		// An allow failure in enforce mode means a legitimate player may be
		// dropped. Surface it as a health alert — this is a guardian problem,
		// not an attacker one.
		g.notif.Health("Allow-list write failed ["+g.server+"]", ip.String()+": "+err.Error())
		return
	}
	g.log.Info("allowed player", "ip", ip, "eos", eos)
}

// revoke handles the exploit footprint: an IP that beaconed legitimately and then
// sent the crash payload at the game port. Passing the beacon is cheap, so the
// allow-list has to be revocable. The EOS id it authenticated with is what you
// actually ban — the IP rotates, the account costs something.
func (g *Gate) revoke(ip netip.Addr) {
	g.mu.Lock()
	id := g.eos[ip]
	delete(g.allowed, ip)
	g.banned[ip] = true
	g.mu.Unlock()

	if err := g.fw.Revoke(ip); err != nil {
		g.log.Error("revoke failed", "ip", ip, "err", err)
		g.notif.Health("Revoke failed ["+g.server+"]", ip.String()+": "+err.Error())
	}
	if id == "" {
		id = "unknown (no beacon seen this run)"
	}
	g.log.Warn("exploit payload, IP revoked and banned", "ip", ip, "eos", id)
	g.notif.Incident(ip, "Exploit payload ["+g.server+"]",
		ip.String()+" sent a payload the engine refused (LogSecurity close). Revoked and banned. EOS id: "+id)
}

func (g *Gate) checkGame(ip netip.Addr) {
	g.mu.Lock()
	exp, ok := g.allowed[ip]
	allowed := ok && exp.After(time.Now())
	g.mu.Unlock()

	if allowed {
		return // normal: authed player's game connection
	}

	// Unauthenticated game connection.
	if g.enforce {
		// In enforce mode the kernel should have dropped this IP's earlier packets.
		// Seeing a game-accepted line for an unknown IP means either a race (game
		// conn between beacon-close and our allow write — unlikely given the
		// multi-second gap) or a gap in coverage. Worth an incident either way.
		g.log.Warn("game connection from non-allowed IP", "ip", ip)
		g.notif.Incident(ip, "Unallowed game connection ["+g.server+"]", ip.String()+" reached the game port without a beacon auth")
	} else {
		// log-only mode: this is the would-be drop we are validating against.
		g.log.Info("WOULD DROP, game connection from non-allowed IP", "ip", ip)
		g.notif.Incident(ip, "Would-drop, log-only ["+g.server+"]", ip.String()+" would have been dropped: no beacon auth")
	}
}
