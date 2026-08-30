package tailer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, s string, mod time.Time) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if !mod.IsZero() {
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
}

// The whole point of this package: SquadGame_2.log may be the live file, or it
// may be the stale one. Newest mtime wins in both directions.
func TestNewestPicksLiveSibling(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "SquadGame.log")
	b := filepath.Join(dir, "SquadGame_2.log")
	old := time.Now().Add(-time.Hour)

	tl := New(a)
	write(t, a, "x\n", old)
	write(t, b, "x\n", time.Now())
	if got := tl.newest(""); got != b {
		t.Fatalf("live sibling: got %s want %s", got, b)
	}

	// flip: SquadGame.log is now the newer one
	write(t, b, "x\n", old)
	write(t, a, "x\n", time.Now())
	if got := tl.newest(""); got != a {
		t.Fatalf("live primary: got %s want %s", got, a)
	}
	// and a stale sibling must not steal us away from the file we are on
	if got := tl.newest(a); got != a {
		t.Fatalf("stale steal: got %s want %s", got, a)
	}
}

// End to end: start on one file, then a newer sibling appears mid-run and its
// lines must reach the channel from the top of that file.
func TestFollowSwitchesToNewSibling(t *testing.T) {
	pollInterval = 20 * time.Millisecond
	defer func() { pollInterval = 5 * time.Second }()

	dir := t.TempDir()
	a := filepath.Join(dir, "SquadGame.log")
	b := filepath.Join(dir, "SquadGame_2.log")
	write(t, a, "old-history\n", time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lines := make(chan string, 64)
	go New(a).Follow(ctx, lines)

	time.Sleep(200 * time.Millisecond) // let it attach at EOF
	write(t, a, "from-a\n", time.Time{})
	if got := recv(t, lines); got != "from-a" {
		t.Fatalf("first file: got %q", got)
	}

	write(t, b, "from-b\n", time.Time{}) // newer sibling, read from the start
	if got := recv(t, lines); got != "from-b" {
		t.Fatalf("after switch: got %q", got)
	}
}

func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for line")
		return ""
	}
}

// Squad drops rotated and CRC logs next to the live one, stamped at the rotation
// instant — newer than the empty log it just created. Following one of those
// replays hours of history from SEEK_SET and re-allows departed IPs.
func TestNewestIgnoresRotatedAndCRCLogs(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "SquadGame.log")

	old := time.Now().Add(-time.Minute)
	for name, mod := range map[string]time.Time{
		"SquadGame.log":   old,
		"SquadGame_2.log": old,
		"SquadGame-backup-2026.08.30-13.00.36.log":     time.Now(),
		"SquadGame-CRC.log":                            time.Now(),
		"SquadGame-CRC-backup-2026.08.30-12.56.07.log": time.Now(),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}

	// The decoys are the newest files in the directory; neither may be chosen.
	if got := New(live).newest(""); got != live && got != filepath.Join(dir, "SquadGame_2.log") {
		t.Fatalf("newest picked a rotated/CRC log: %s", got)
	}
}
