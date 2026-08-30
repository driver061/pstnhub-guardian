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

	"github.com/yourorg/squad-gatekeeper/internal/firewall"
	"github.com/yourorg/squad-gatekeeper/internal/notifier"
	"github.com/yourorg/squad-gatekeeper/internal/parser"
)

type Gate struct {
	fw       *firewall.Firewall
	notif    *notifier.Notifier
	log      *slog.Logger
	enforce  bool
	ttl      time.Duration

	mu      sync.Mutex
	allowed map[netip.Addr]time.Time // in-memory mirror, value = expiry
}

func New(fw *firewall.Firewall, notif *notifier.Notifier, log *slog.Logger, enforce bool, ttl time.Duration) *Gate {
	return &Gate{
		fw:      fw,
		notif:   notif,
		log:     log,
		enforce: enforce,
		ttl:     ttl,
		allowed: make(map[netip.Addr]time.Time),
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
		g.allow(ev.IP, ev.EOSID)
	case parser.KindGameAccepted:
		g.checkGame(ev.IP)
	}
}

func (g *Gate) allow(ip netip.Addr, eos string) {
	g.mu.Lock()
	g.allowed[ip] = time.Now().Add(g.ttl)
	g.mu.Unlock()

	if err := g.fw.Allow(ip); err != nil {
		g.log.Error("allow failed", "ip", ip, "err", err)
		// An allow failure in enforce mode means a legitimate player may be
		// dropped. Surface it as a health alert — this is a gatekeeper problem,
		// not an attacker one.
		g.notif.Health("allow-list write failed", ip.String()+": "+err.Error())
		return
	}
	g.log.Info("allowed", "ip", ip, "eos", eos)
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
		g.log.Warn("game connection from non-allowed IP (enforce mode)", "ip", ip)
		g.notif.Incident(ip, "Unallowed game connection", ip.String()+" reached the game port without a beacon auth")
	} else {
		// log-only mode: this is the would-be drop we are validating against.
		g.log.Info("WOULD DROP: game connection from non-allowed IP", "ip", ip)
		g.notif.Incident(ip, "Would-drop (log-only)", ip.String()+" would have been dropped: no beacon auth")
	}
}
