package tailer

import (
	"bufio"
	"io"
	"os"
	"time"

	"github.com/yourorg/squad-gatekeeper/internal/parser"
)

// maxBackfill caps how much of the log we replay. A 35MB log is normal here and
// scanning it costs well under a second, but the cap keeps a pathological file
// from stalling startup before the live tailer is useful.
const maxBackfill = 128 << 20

// Backfill reads the current live log from the start and returns the
// beacon-authed events still within ttl, with At rewritten to real clock time.
//
// Why it exists: the tailer opens at END, so on a cold start (or after the state
// file is lost) every player already in the server looks unauthenticated. In
// enforce mode that drops a full server on restart — exactly when a crash has
// just happened.
//
// Two things it deliberately does NOT do:
//
//   - It returns only KindBeaconAuthed. Replaying KindGameAccepted would emit a
//     would-drop incident per historical connection and flood Discord at every
//     start.
//   - It never trusts a log timestamp as an absolute time. Squad writes local
//     time with no zone; parsing it as UTC on a UTC+3 box would make every entry
//     look 3h old (backfill silently does nothing) or 3h in the future (entries
//     outlive their TTL). Instead the LAST timestamp in the file is taken as
//     "now" — the file was being written a moment ago — and each event is placed
//     at now-(last-At). Only differences are used, so the zone cancels out.
func (t *Tailer) Backfill(ttl time.Duration) ([]parser.Event, error) {
	path := t.newest("")
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		evs  []parser.Event
		last time.Time
	)
	sc := bufio.NewScanner(&io.LimitedReader{R: f, N: maxBackfill})
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // Squad lines can be long
	for sc.Scan() {
		ev, ok := parser.Parse(sc.Text())
		if !ok || ev.At.IsZero() {
			continue
		}
		if ev.At.After(last) {
			last = ev.At
		}
		if ev.Kind == parser.KindBeaconAuthed {
			evs = append(evs, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// Re-base onto the real clock and drop anything already past its TTL.
	now := time.Now()
	out := evs[:0]
	for _, ev := range evs {
		age := last.Sub(ev.At)
		if age >= ttl {
			continue
		}
		ev.At = now.Add(-age)
		out = append(out, ev)
	}
	return out, nil
}
