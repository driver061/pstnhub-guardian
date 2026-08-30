// Package parser turns raw Squad log lines into typed events.
//
// The two lines that matter:
//
//   - Beacon close carrying an EOS id. This is proof an IP authenticated. It is
//     what puts an IP on the allow-list. Example:
//     LogNet: UNetConnection::Close: [UNetConnection] RemoteAddr: 1.2.3.4:43965,
//        ... Def:BeaconNetDriver ... UniqueId: RedpointEOS:00022f92c00c4537b96cd84fbe3d4bae
//
//   - Game-driver connection accepted. Only used in log-only mode to decide
//     whether a connection WOULD have been dropped (i.e. its IP is not allowed).
//     In enforce mode the kernel already dropped it, so this never appears.
//     Example:
//     LogNet: NotifyAcceptedConnection: Name: Gorodok_RAAS_v2, ... RemoteAddr:
//        1.2.3.4:43993, ... Def:GameNetDriver ...
//
// NOTE: these patterns are transcribed from the sample logs. Re-confirm against
// a live capture from YOUR build before enforcing — a plugin/engine version bump
// can reword them. This is the validated match logic from squad_crash_triage.py,
// ported.
package parser

import (
	"net/netip"
	"regexp"
)

type Kind int

const (
	KindOther Kind = iota
	KindBeaconAuthed // an IP completed the beacon handshake (allow it)
	KindGameAccepted // a game-driver connection was accepted (log-only interest)
)

type Event struct {
	Kind  Kind
	IP    netip.Addr
	EOSID string // populated for KindBeaconAuthed
	Raw   string
}

// A game-driver connection line. Matches only GameNetDriver acceptances.
var reGameAccepted = regexp.MustCompile(
	`NotifyAcceptedConnection:.*RemoteAddr:\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+.*Def:GameNetDriver`,
)

// A beacon-driver close that carries a resolved EOS id. The EOS id proves the
// connection authenticated; INVALID lines are deliberately NOT matched.
var reBeaconAuthed = regexp.MustCompile(
	`UNetConnection::Close:.*RemoteAddr:\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+.*Def:BeaconNetDriver.*UniqueId:\s*RedpointEOS:([0-9a-fA-F]{32})`,
)

// Parse classifies a single log line. Returns (Event, true) on a match.
func Parse(line string) (Event, bool) {
	if m := reBeaconAuthed.FindStringSubmatch(line); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			return Event{Kind: KindBeaconAuthed, IP: ip, EOSID: m[2], Raw: line}, true
		}
	}
	if m := reGameAccepted.FindStringSubmatch(line); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			return Event{Kind: KindGameAccepted, IP: ip, Raw: line}, true
		}
	}
	return Event{}, false
}
