package tailer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yourorg/squad-gatekeeper/internal/parser"
)

func beacon(ts, ip, eos string) string {
	return "[" + ts + "][ 45]LogNet: UNetConnection::Close: [UNetConnection] RemoteAddr: " +
		ip + ":43965, Name: EOSIpNetConnection_1, Def:BeaconNetDriver, UniqueId: RedpointEOS:" + eos + "\n"
}

func TestBackfill(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "SquadGame.log")

	// Timestamps are deliberately in a zone that is NOT the test machine's, and
	// dated in the past: Backfill must age them off the log's own last line, not
	// off time.Now(). Last line is 13.00.00, so 11.00.00 is 2h stale.
	body := beacon("2026.08.30-11.00.00:000", "1.1.1.1", "00022f92c00c4537b96cd84fbe3d4bae") +
		"[2026.08.30-12.00.00:000][ 45]LogNet: NotifyAcceptedConnection: Name: Gorodok_RAAS_v2, RemoteAddr: 9.9.9.9:43993, Def:GameNetDriver\n" +
		beacon("2026.08.30-12.30.00:000", "2.2.2.2", "10022f92c00c4537b96cd84fbe3d4bae") +
		beacon("2026.08.30-13.00.00:000", "3.3.3.3", "20022f92c00c4537b96cd84fbe3d4bae")
	if err := os.WriteFile(live, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	evs, err := New(live).Backfill(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]time.Duration{}
	for _, ev := range evs {
		if ev.Kind != parser.KindBeaconAuthed {
			t.Fatalf("replayed a non-beacon event: %v — would flood Discord with historical would-drops", ev.Kind)
		}
		got[ev.IP.String()] = time.Since(ev.At).Round(time.Minute)
	}

	if _, ok := got["1.1.1.1"]; ok {
		t.Error("kept a beacon older than the TTL")
	}
	if _, ok := got["9.9.9.9"]; ok {
		t.Error("kept a game-accepted line")
	}
	if d := got["2.2.2.2"]; d != 30*time.Minute {
		t.Errorf("2.2.2.2 aged %v, want 30m (rebased on the log's last line)", d)
	}
	if d := got["3.3.3.3"]; d != 0 {
		t.Errorf("3.3.3.3 aged %v, want 0 (it is the last line)", d)
	}
}
