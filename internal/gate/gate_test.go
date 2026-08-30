package gate

import (
	"bufio"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/pstnhub/pstnhub-guardian/internal/notifier"
	"github.com/pstnhub/pstnhub-guardian/internal/parser"
)

type fakeFW struct{ allowed, revoked, blocked []netip.Addr }

func (f *fakeFW) Allow(ip netip.Addr) error  { f.allowed = append(f.allowed, ip); return nil }
func (f *fakeFW) Revoke(ip netip.Addr) error { f.revoked = append(f.revoked, ip); return nil }
func (f *fakeFW) Block(ip netip.Addr) error  { f.blocked = append(f.blocked, ip); return nil }

func newTestGate() (*Gate, *fakeFW) {
	fw := &fakeFW{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(fw, notifier.New("", time.Minute, log), log, true, time.Hour, "test"), fw
}

func blocked(fw *fakeFW, ip string) bool {
	for _, b := range fw.blocked {
		if b.String() == ip {
			return true
		}
	}
	return false
}

// The attack signature: engine handshake completes, client never speaks.
func TestStalledBeaconIsBanned(t *testing.T) {
	g, fw := newTestGate()
	t0 := time.Date(2026, 8, 30, 15, 59, 29, 0, time.UTC)
	ip := netip.MustParseAddr("85.203.39.233")

	g.Handle(parser.Event{Kind: parser.KindBeaconConn, IP: ip, Conn: "c1", At: t0})
	g.Handle(parser.Event{Kind: parser.KindBeaconHello, Conn: "c1", At: t0})
	// still inside the window: no ban yet
	g.Handle(parser.Event{Kind: parser.KindOther, At: t0.Add(time.Second)})
	if blocked(fw, ip.String()) {
		t.Fatal("banned inside the stall window")
	}
	// window elapsed with no beacon protocol from c1
	g.Handle(parser.Event{Kind: parser.KindOther, At: t0.Add(3 * time.Second)})
	if !blocked(fw, ip.String()) {
		t.Fatal("stalled beacon connection was not banned")
	}
}

// A real client speaks immediately, and must never be banned — including one
// that reconnects repeatedly, which is what a player on a bad line looks like.
func TestSpeakingBeaconIsNotBanned(t *testing.T) {
	g, fw := newTestGate()
	t0 := time.Date(2026, 8, 30, 15, 39, 25, 0, time.UTC)
	ip := netip.MustParseAddr("79.135.105.52")

	for i := 0; i < 14; i++ {
		at := t0.Add(time.Duration(i) * 3 * time.Second)
		conn := "c" + string(rune('a'+i))
		g.Handle(parser.Event{Kind: parser.KindBeaconConn, IP: ip, Conn: conn, At: at})
		g.Handle(parser.Event{Kind: parser.KindBeaconHello, Conn: conn, At: at})
		g.Handle(parser.Event{Kind: parser.KindBeaconSpoke, Conn: conn, At: at})
	}
	g.Handle(parser.Event{Kind: parser.KindOther, At: t0.Add(time.Minute)})
	if blocked(fw, ip.String()) {
		t.Fatal("a client that spoke the beacon protocol was banned")
	}
}

// The wall-clock path is what actually fires in production: the attacker goes
// silent, so no log line arrives to drive the event-clock sweep.
func TestStallSweepOnWallClock(t *testing.T) {
	g, fw := newTestGate()
	ip := netip.MustParseAddr("85.203.39.233")
	g.stalled["c1"] = stall{ip: ip, wall: time.Now().Add(-3 * time.Second)}

	g.SweepStalls()
	if !blocked(fw, ip.String()) {
		t.Fatal("wall-clock sweep did not ban a silent stalled connection")
	}
}

// A banned IP must not get back on the allow-list by beaconing again.
func TestBannedIPCannotReallow(t *testing.T) {
	g, fw := newTestGate()
	ip := netip.MustParseAddr("1.2.3.4")
	g.Handle(parser.Event{Kind: parser.KindExploit, IP: ip, At: time.Now()})
	g.Handle(parser.Event{Kind: parser.KindBeaconAuthed, IP: ip, EOSID: "deadbeef", At: time.Now()})
	for _, a := range fw.allowed {
		if a == ip {
			t.Fatal("banned IP was re-allowed")
		}
	}
}

// TestReplay runs a real Squad log through the parser and the gate with a fake
// firewall, and prints what would have been banned. Skipped unless pointed at a
// log: GUARDIAN_REPLAY_LOG=/path/to/SquadGame.log go test ./internal/gate -run Replay -v
func TestReplay(t *testing.T) {
	path := os.Getenv("GUARDIAN_REPLAY_LOG")
	if path == "" {
		t.Skip("set GUARDIAN_REPLAY_LOG to replay a capture")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	g, fw := newTestGate()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lines, events := 0, 0
	for sc.Scan() {
		lines++
		if ev, ok := parser.Parse(sc.Text()); ok {
			events++
			before := len(fw.blocked)
			g.Handle(ev)
			for _, ip := range fw.blocked[before:] {
				t.Logf("  BLOCK %s at log time %s", ip, ev.At.Format("15:04:05.000"))
			}
			if ev.Kind == parser.KindCrash {
				t.Logf("  CRASH at log time %s", ev.At.Format("15:04:05.000"))
			}
		}
	}
	t.Logf("%d lines, %d events, %d blocked", lines, events, len(fw.blocked))
	for _, ip := range fw.blocked {
		t.Logf("  BLOCKED %s", ip)
	}
}
