package logging

import (
	"bytes"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

func TestFormat(t *testing.T) {
	var buf bytes.Buffer
	base := New(&buf, slog.LevelInfo)

	For(base, "Gate", "main").Info("allowed player",
		KeyIP, "1.2.3.4", KeyEOS, "00022f92c00c4537b96cd84fbe3d4bae")
	For(base, "Firewall", "main").Warn("enforce mode active", "port", 7787)
	base.Info("startup backfill complete", "allowed", 12)
	base.Debug("this must not appear")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (debug should be filtered):\n%s", len(lines), buf.String())
	}

	stamp := regexp.MustCompile(`^\[\d{2}\.\d{2}\.\d{4}-\d{2}:\d{2}:\d{2}\.\d{3}\] `)
	for _, l := range lines {
		if !stamp.MatchString(l) {
			t.Errorf("bad timestamp prefix: %s", l)
		}
	}

	if want := "[Gate:main] Allowed player. [1.2.3.4 | 00022f92c00c4537b96cd84fbe3d4bae]"; !strings.HasSuffix(lines[0], want) {
		t.Errorf("line 0 = %q, want suffix %q", lines[0], want)
	}
	if want := "[Firewall:main WARN] Enforce mode active. [port=7787]"; !strings.HasSuffix(lines[1], want) {
		t.Errorf("line 1 = %q, want suffix %q", lines[1], want)
	}
	if want := "[Guardian] Startup backfill complete. [allowed=12]"; !strings.HasSuffix(lines[2], want) {
		t.Errorf("line 2 = %q, want suffix %q", lines[2], want)
	}

	// The address must stay extractable — this is the README's journal grep.
	if got := regexp.MustCompile(`\[([0-9.]+) \|`).FindStringSubmatch(lines[0]); got == nil || got[1] != "1.2.3.4" {
		t.Errorf("IP not extractable from %q", lines[0])
	}
}
