// Package parser turns raw Squad log lines into typed events.
//
// The two lines that matter:
//
//   - Beacon close carrying an EOS id. This is proof an IP authenticated. It is
//     what puts an IP on the allow-list. Example:
//     LogNet: UNetConnection::Close: [UNetConnection] RemoteAddr: 1.2.3.4:43965,
//     ... Def:BeaconNetDriver ... UniqueId: RedpointEOS:00022f92c00c4537b96cd84fbe3d4bae
//
//   - Game-driver connection accepted. Only used in log-only mode to decide
//     whether a connection WOULD have been dropped (i.e. its IP is not allowed).
//     In enforce mode the kernel already dropped it, so this never appears.
//     Example:
//     LogNet: NotifyAcceptedConnection: Name: Gorodok_RAAS_v2, ... RemoteAddr:
//     1.2.3.4:43993, ... Def:GameNetDriver ...
//
// NOTE: these patterns are transcribed from the sample logs. Re-confirm against
// a live capture from YOUR build before enforcing — a plugin/engine version bump
// can reword them. This is the validated match logic from squad_crash_triage.py,
// ported.
package parser

import (
	"net/netip"
	"regexp"
	"time"
)

type Kind int

const (
	KindOther        Kind = iota
	KindBeaconAuthed      // an IP completed the beacon handshake (allow it)
	KindGameAccepted      // a game-driver connection was accepted (log-only interest)
	KindExploit           // the crash exploit's own footprint (revoke the IP)
	KindBeaconUnauth      // a beacon connection accepted with an unresolved id (suspect)
	KindCrash             // the server hit a fatal error (blame the last suspect)
	KindBeaconConn        // a beacon connection object was created (binds conn name -> IP)
	KindBeaconHello       // that connection reached "Beacon Hello"
	KindBeaconSpoke       // that connection then spoke the beacon protocol (it is a client)
)

type Event struct {
	Kind  Kind
	IP    netip.Addr
	EOSID string // populated for KindBeaconAuthed
	// Conn is the UNetConnection object name, e.g. RedpointEOSIpNetConnection_21.
	// Set on the three beacon-progress kinds. The LogBeacon lines identify a
	// connection ONLY by this name — no address — so the conn->IP binding from
	// KindBeaconConn is the only way to attribute them.
	Conn string
	Raw  string

	// At is the timestamp from the line's own [YYYY.MM.DD-HH.MM.SS:mmm] prefix,
	// zero if the line has none. Startup backfill needs it to age replayed
	// events; live tailing ignores it. It carries NO timezone — Squad writes
	// local time with no offset — so only DIFFERENCES between two At values
	// from the same log are meaningful. Never compare one to time.Now().
	At time.Time
}

// Unreal's line prefix, e.g. "[2026.08.30-12.24.09:123][ 45]LogNet: ...".
var reStamp = regexp.MustCompile(`^\[(\d{4})\.(\d{2})\.(\d{2})-(\d{2})\.(\d{2})\.(\d{2}):(\d{3})\]`)

// stampOf extracts the line's timestamp as a wall time in UTC. The zone is a
// lie (see Event.At) and deliberately so: it makes subtraction correct, which
// is all any caller is allowed to do with it.
func stampOf(line string) time.Time {
	m := reStamp.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}
	}
	n := func(s string) int {
		v := 0
		for _, c := range s {
			v = v*10 + int(c-'0')
		}
		return v
	}
	return time.Date(n(m[1]), time.Month(n(m[2])), n(m[3]), n(m[4]), n(m[5]), n(m[6]), n(m[7])*int(time.Millisecond), time.UTC)
}

// logNet anchors a pattern to a real LogNet line: Unreal's [stamp][frame] prefix
// followed by the category. Without this anchor the patterns match ANYWHERE in a
// line, and the exploit puts attacker-controlled text (team names, layer names)
// into LogSquadGameEvents lines — a crafted name containing a fake beacon-close
// would allow-list an arbitrary IP.
const logNet = `^\[[0-9.\-:]+\]\[[ 0-9]+\]LogNet: `

// A game-driver connection line. Matches only GameNetDriver acceptances.
var reGameAccepted = regexp.MustCompile(
	logNet + `NotifyAcceptedConnection:.*RemoteAddr:\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+.*Def:GameNetDriver`,
)

// The exploit's footprint: the engine closing a connection with a security
// reason. "poc" is what the current crash tool leaves behind, but any
// LogSecurity close is a peer sending something the engine refused — no
// legitimate client produces one. Matched on the category, not the reason
// string, so a renamed payload still trips it.
var reExploit = regexp.MustCompile(
	`^\[[0-9.\-:]+\]\[[ 0-9]+\]LogSecurity: Warning: (\d{1,3}(?:\.\d{1,3}){3}):\d+: Closed:`,
)

// A beacon-driver connection ACCEPTED with an unresolved id. On its own this is
// completely normal — every player looks like this until the EOS handshake
// resolves, which is why it can never ban by itself. It is recorded only so a
// fatal error seconds later has a suspect: the beacon port cannot be gated by
// the allow-list (it is where you go to GET allow-listed), so an attacker
// crashing the server through it is invisible to the firewall until named.
var reBeaconUnauth = regexp.MustCompile(
	logNet + `NotifyAcceptedConnection:.*RemoteAddr:\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+.*Def:BeaconNetDriver.*UniqueId:\s*INVALID`,
)

// The server dying. Unreal writes this immediately before the callstack.
var reCrash = regexp.MustCompile(`LogCore: (=== Critical error:|Fatal error!)`)

// The three lines that track how far a beacon connection got. The observed
// attack completes the engine's transport handshake and then never speaks the
// beacon protocol at all: it reaches "Beacon Hello" and stops. Across four crash
// logs, 1020 beacon handshakes produced exactly 4 connections that stalled
// there, and all 4 were the attacker — every real client, including ones that
// drop out moments later, sends "Client netspeed" first.
//
// LogBeacon lines carry the connection object name and no address, hence the
// separate binding line.
var reBeaconConn = regexp.MustCompile(
	logNet + `AddClientConnection:.*RemoteAddr:\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+,\s*Name:\s*(\w+),.*Def:BeaconNetDriver`,
)

var reBeaconHello = regexp.MustCompile(`LogBeacon: .*\[(\w+)\]: Beacon Hello`)

// Client netspeed is the FIRST thing a real beacon client sends. Anything later
// in the sequence (Beacon Join, Handshake complete) also proves it, but netspeed
// is the earliest, so it is the one worth waiting for.
var reBeaconSpoke = regexp.MustCompile(`LogBeacon: .*\[(\w+)\]: (Client netspeed|Beacon Join|Handshake complete)`)

// A beacon-driver close that carries a resolved EOS id. The EOS id proves the
// connection authenticated; INVALID lines are deliberately NOT matched.
var reBeaconAuthed = regexp.MustCompile(
	logNet + `UNetConnection::Close:.*RemoteAddr:\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+.*Def:BeaconNetDriver.*UniqueId:\s*RedpointEOS:([0-9a-fA-F]{32})`,
)

// Parse classifies a single log line. Returns (Event, true) on a match.
func Parse(line string) (Event, bool) {
	if m := reBeaconAuthed.FindStringSubmatch(line); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			return Event{Kind: KindBeaconAuthed, IP: ip, EOSID: m[2], Raw: line, At: stampOf(line)}, true
		}
	}
	if m := reExploit.FindStringSubmatch(line); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			return Event{Kind: KindExploit, IP: ip, Raw: line, At: stampOf(line)}, true
		}
	}
	if m := reBeaconSpoke.FindStringSubmatch(line); m != nil {
		return Event{Kind: KindBeaconSpoke, Conn: m[1], Raw: line, At: stampOf(line)}, true
	}
	if m := reBeaconHello.FindStringSubmatch(line); m != nil {
		return Event{Kind: KindBeaconHello, Conn: m[1], Raw: line, At: stampOf(line)}, true
	}
	if m := reBeaconConn.FindStringSubmatch(line); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			return Event{Kind: KindBeaconConn, IP: ip, Conn: m[2], Raw: line, At: stampOf(line)}, true
		}
	}
	if reCrash.MatchString(line) {
		return Event{Kind: KindCrash, Raw: line, At: stampOf(line)}, true
	}
	if m := reBeaconUnauth.FindStringSubmatch(line); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			return Event{Kind: KindBeaconUnauth, IP: ip, Raw: line, At: stampOf(line)}, true
		}
	}
	if m := reGameAccepted.FindStringSubmatch(line); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			return Event{Kind: KindGameAccepted, IP: ip, Raw: line, At: stampOf(line)}, true
		}
	}
	return Event{}, false
}
