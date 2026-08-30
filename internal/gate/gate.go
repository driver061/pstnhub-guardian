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
	"strconv"
	"sync"
	"time"

	"github.com/pstnhub/pstnhub-guardian/internal/notifier"
	"github.com/pstnhub/pstnhub-guardian/internal/parser"
)

type Gate struct {
	fw      Firewall
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
	// banned IPs are refused re-entry to the allow-list and dropped in the kernel
	// (beacon port included) until the expiry. Persisted: the beacon crash KILLS
	// the server, so a ban that did not survive a restart would be forgotten
	// exactly when it is needed.
	banned map[netip.Addr]time.Time
	// conns binds a beacon connection object name to its source address. The
	// LogBeacon progress lines carry only the name.
	conns map[string]netip.Addr
	// stalled tracks connections that reached "Beacon Hello" and have not yet
	// spoken the beacon protocol. Entries that survive stallWindow are the
	// attack signature.
	stalled map[string]stall
	// suspects is the recent unauthenticated beacon-connect history, IP -> last
	// seen and count. It is the only evidence available when the server dies:
	// the crashing peer never resolves an EOS id, so nothing else names it.
	suspects map[netip.Addr]*suspect
}

type suspect struct {
	last  time.Time
	count int
}

type stall struct {
	ip netip.Addr
	// seen is the log's own clock; wall is ours. Both are kept because neither
	// works alone: the log clock is the only one that means anything when
	// replaying a capture, and it is the only one that advances during a live
	// attack — but it advances ONLY when a matching line arrives, and the
	// attacker's whole trick is to go silent. Replaying the 15:59 capture with
	// the log clock alone banned the attacker 128ms before the crash instead of
	// 1.5s before it: technically detected, practically too late.
	//
	// They are never compared to each other. See Event.At for why that matters.
	seen time.Time
	wall time.Time
}

// stallWindow is how long a connection may sit at "Beacon Hello" without
// speaking. Real clients send "Client netspeed" in the same millisecond — this
// is two orders of magnitude of slack, and still caught every observed attack.
const stallWindow = 2 * time.Second

// connsMax bounds the conn->IP binding map. Nothing guarantees a close line for
// every connection (the server may die first), so the map is trimmed by size
// rather than trusting cleanup to arrive.
// ponytail: crude but bounded. A proper LRU only matters if this ever shows up
// in a heap profile.
const connsMax = 4096

// banTTL is how long an IP stays banned. Not configurable on purpose: one knob
// fewer, and 24h is long enough to make a repeat attempt expensive without
// stranding a recycled address forever.
// ponytail: promote to config if an operator ever needs a different window.
const banTTL = 24 * time.Hour

// crashWindow is how recently a suspect must have connected to the beacon to be
// blamed for a fatal error. The observed attack crashes the server within a
// second of "Beacon Hello"; anything older is noise.
const crashWindow = 15 * time.Second

// Firewall is what the gate needs from the kernel side. Narrow on purpose: it
// keeps the ban/stall logic testable off-Linux, where nftables will not build.
type Firewall interface {
	Allow(netip.Addr) error
	Revoke(netip.Addr) error
	Block(netip.Addr) error
}

func New(fw Firewall, notif *notifier.Notifier, log *slog.Logger, enforce bool, ttl time.Duration, server string) *Gate {
	return &Gate{
		fw:       fw,
		notif:    notif,
		log:      log,
		enforce:  enforce,
		ttl:      ttl,
		server:   server,
		allowed:  make(map[netip.Addr]time.Time),
		eos:      make(map[netip.Addr]string),
		banned:   make(map[netip.Addr]time.Time),
		suspects: make(map[netip.Addr]*suspect),
		conns:    make(map[string]netip.Addr),
		stalled:  make(map[string]stall),
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

// SeedBans restores persisted bans on startup. The beacon crash kills the game
// server; guardian may be restarted alongside it, and a forgotten ban means the
// same address gets a free second shot.
func (g *Gate) SeedBans(bans map[netip.Addr]time.Time) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for ip, exp := range bans {
		if exp.Before(now) {
			continue
		}
		g.banned[ip] = exp
		if err := g.fw.Block(ip); err != nil {
			g.log.Warn("seed block failed", "ip", ip, "err", err)
		}
	}
}

// Bans returns the current non-expired bans for persistence.
func (g *Gate) Bans() map[netip.Addr]time.Time {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[netip.Addr]time.Time, len(g.banned))
	for ip, exp := range g.banned {
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
		g.ban(ev.IP, "sent a payload the engine refused (LogSecurity close)", ev.At)
	case parser.KindBeaconUnauth:
		g.noteSuspect(ev.IP, ev.At)
	case parser.KindCrash:
		g.blameCrash(ev.At)
	case parser.KindBeaconConn:
		g.bindConn(ev.Conn, ev.IP)
	case parser.KindBeaconHello:
		g.noteHello(ev.Conn, g.clock(ev.At))
	case parser.KindBeaconSpoke:
		g.noteSpoke(ev.Conn)
	}
	// Every event is a clock tick. The stall check has to run off the log stream
	// because that is the only thing that moves during an attack — and a stalled
	// connection with no further log traffic behind it is a server that already
	// died, which blameCrash covers.
	g.sweepStalls(g.clock(ev.At), time.Now())
}

// clock returns the log's own timestamp when the line carried one, falling back
// to wall time. Never mix the two in a comparison: see Event.At.
func (g *Gate) clock(at time.Time) time.Time {
	if at.IsZero() {
		return time.Now()
	}
	return at
}

func (g *Gate) bindConn(conn string, ip netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.conns) >= connsMax {
		for k := range g.conns { // drop an arbitrary entry, the map is a cache
			delete(g.conns, k)
			if len(g.conns) < connsMax {
				break
			}
		}
	}
	g.conns[conn] = ip
}

// noteHello starts the clock on a connection that finished the ENGINE handshake.
// Normal so far: every real client passes through here too.
func (g *Gate) noteHello(conn string, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ip, ok := g.conns[conn]
	if !ok {
		return // no binding (log gap, or backfill) — nothing to attribute
	}
	g.stalled[conn] = stall{ip: ip, seen: at, wall: time.Now()}
}

// noteSpoke clears a connection: it said something in the beacon protocol, so it
// is a real client whatever else it does later.
func (g *Gate) noteSpoke(conn string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.stalled, conn)
}

// sweepStalls bans every connection still silent stallWindow after Beacon Hello.
//
// This is the one detector that fires BEFORE the crash: in the 15:59 capture the
// attacker stalled once at :29.079, was silent, and killed the server at :32.699
// from the same address — 3.6s of warning. It does not help when the attacker
// rotates address between the probe and the kill, and it cannot help against a
// first-ever single shot: the payload lands in the same 81ms as the Hello.
// SweepStalls is the wall-clock entry point. Call it on a short ticker: the
// event-driven sweep cannot fire while the attacker is silent, which is exactly
// when it needs to.
func (g *Gate) SweepStalls() { g.sweepStalls(time.Time{}, time.Now()) }

func (g *Gate) sweepStalls(logNow, wallNow time.Time) {
	var hits []struct {
		conn string
		ip   netip.Addr
	}
	g.mu.Lock()
	for conn, st := range g.stalled {
		byLog := !logNow.IsZero() && logNow.Sub(st.seen) >= stallWindow
		byWall := wallNow.Sub(st.wall) >= stallWindow
		if !byLog && !byWall {
			continue
		}
		delete(g.stalled, conn)
		hits = append(hits, struct {
			conn string
			ip   netip.Addr
		}{conn, st.ip})
	}
	g.mu.Unlock()

	for _, h := range hits {
		g.ban(h.ip, "completed the engine handshake and never spoke the beacon protocol ("+
			h.conn+" stalled at Beacon Hello for "+stallWindow.String()+")", logNow)
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
	if exp, ok := g.banned[ip]; ok && exp.After(time.Now()) {
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

// noteSuspect records an unauthenticated beacon connection. Harmless on its own
// — every joining player produces one — so this NEVER bans. It only keeps a name
// ready for blameCrash.
func (g *Gate) noteSuspect(ip netip.Addr, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	sp := g.suspects[ip]
	if sp == nil {
		sp = &suspect{}
		g.suspects[ip] = sp
	}
	sp.last, sp.count = at, sp.count+1
	// bounded: drop anything outside the window while we are here
	for k, v := range g.suspects {
		if at.Sub(v.last) > crashWindow {
			delete(g.suspects, k)
		}
	}
}

// blameCrash reacts to a fatal server error. The beacon port cannot be gated by
// the allow-list, so a crash delivered through the beacon handshake is invisible
// to the firewall until someone names the source. The only evidence is which
// unauthenticated peer was mid-handshake when the process died.
//
// It does NOT ban. Replaying four real crash logs showed why: in two of them the
// most recent unauthenticated beacon peer was an ordinary player who happened to
// be joining, because the payload had actually arrived on the GAME driver. A
// 24h ban on a bystander is worse than no ban. The stall detector (sweepStalls)
// is the path allowed to ban — it was right 4 times out of 4 on the same data.
func (g *Gate) blameCrash(at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	g.mu.Lock()
	var pick netip.Addr
	var best time.Time
	others := 0
	for ip, sp := range g.suspects {
		if at.Sub(sp.last) > crashWindow || sp.last.After(at) {
			continue
		}
		others++
		if sp.last.After(best) {
			pick, best = ip, sp.last
		}
	}
	n := 0
	if sp := g.suspects[pick]; sp != nil {
		n = sp.count
	}
	g.mu.Unlock()

	if !pick.IsValid() {
		g.log.Error("server crashed, no unauthenticated beacon peer in window to blame")
		g.notif.Health("Server crashed ["+g.server+"]", "Fatal error with no beacon suspect in the last "+crashWindow.String()+". Not a beacon-side attack, or the log lines were missed.")
		return
	}
	g.log.Error("server crashed", "suspect", pick, "connections", n, "other_candidates", others-1)
	g.notif.Incident(pick, "Server crashed ["+g.server+"]",
		"Fatal error. Nearest unauthenticated beacon peer: "+pick.String()+" ("+itoa(n)+
			" connections, "+itoa(others-1)+" other candidate(s) in the window). NOT banned — this is a guess, "+
			"and the payload may have arrived on the game driver instead. Check the log around the crash.")
}

// ban revokes an IP, blocks it in the kernel (beacon port included) and alerts.
// reason goes into the alert so a human can judge a heuristic ban.
func (g *Gate) ban(ip netip.Addr, reason string, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	g.mu.Lock()
	if exp, ok := g.banned[ip]; ok && exp.After(time.Now()) {
		g.mu.Unlock()
		g.log.Info("already banned", "ip", ip, "reason", reason)
		return
	}
	id := g.eos[ip]
	delete(g.allowed, ip)
	g.banned[ip] = time.Now().Add(banTTL)
	g.mu.Unlock()

	if err := g.fw.Revoke(ip); err != nil {
		g.log.Error("revoke failed", "ip", ip, "err", err)
	}
	if err := g.fw.Block(ip); err != nil {
		g.log.Error("block failed", "ip", ip, "err", err)
		g.notif.Health("Block failed ["+g.server+"]", ip.String()+": "+err.Error())
	}
	if id == "" {
		id = "unknown (never completed a beacon auth here)"
	}
	g.log.Warn("banned", "ip", ip, "eos", id, "reason", reason)
	g.notif.Incident(ip, "Banned 24h ["+g.server+"]",
		ip.String()+" "+reason+". Revoked and dropped on the beacon and game ports. EOS id: "+id)
}

func itoa(i int) string { return strconv.Itoa(i) }

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
