// Package tailer follows the Squad log, surviving both in-place rotation and
// Squad's habit of starting a *differently named* file.
//
// Two distinct problems, both handled here:
//
//   - In-place rotation/truncation of one path (inode swap). nxadm/tail handles
//     this for us via ReOpen.
//
//   - Squad writing to a sibling file: SquadGame.log and SquadGame_2.log both
//     exist and either one may be the live one, depending on how the server was
//     restarted. A tailer pinned to a single path silently goes deaf here, which
//     is the classic way one of these daemons quietly stops working.
//
// So we do not pin a path. We poll the directory for the newest-mtime file
// matching the pattern and follow that one, switching when a newer sibling
// starts being written.
package tailer

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nxadm/tail"
)

// pollInterval is how often we look for a newer sibling log. The switch costs a
// stat per candidate; 5s is far below the time it takes an attacker to matter.
var pollInterval = 5 * time.Second

type Tailer struct {
	dir  string
	name *regexp.Regexp // matches live logs only, never rotated ones
}

// New builds a tailer from the configured log path. The path is treated as a
// *representative* name, not a fixed target: /x/SquadGame.log also matches
// /x/SquadGame_2.log, /x/SquadGame_3.log, etc.
//
// It deliberately does NOT match everything under SquadGame*.log. Squad drops
// two other families into the same directory:
//
//	SquadGame-backup-2026.08.30-13.00.36.log   the previous log, at rotation
//	SquadGame-CRC.log / SquadGame-CRC-backup-*.log
//
// Both get an mtime at the rotation instant, i.e. newer than the empty log Squad
// has just created. A glob that matches them makes newest() pick a dead file and
// — because switched-to files open at SEEK_SET — replay its whole history,
// re-allowing IPs that left hours ago. Only stem and stem_N are live.
func New(path string) *Tailer {
	dir, base := filepath.Split(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if dir == "" {
		dir = "."
	}
	return &Tailer{
		dir:  dir,
		name: regexp.MustCompile(`^` + regexp.QuoteMeta(stem) + `(_\d+)?` + regexp.QuoteMeta(ext) + `$`),
	}
}

// Follow tails the newest matching log and sends each line to out, switching
// files when a newer one appears. Returns when ctx is cancelled.
//
// The FIRST file is opened at END so a daemon restart does not replay history
// (replaying old beacon lines would re-allow long-gone IPs). Every file we switch
// to afterwards is read from the START, because it came into existence while we
// were running and its whole content is news to us.
func (t *Tailer) Follow(ctx context.Context, out chan<- string) error {
	var (
		curPath string
		stopCur = func() {}   // stops the follower we are currently running
		whence  = os.SEEK_END // first file only
	)
	defer func() { stopCur() }()

	poll := time.NewTicker(pollInterval)
	defer poll.Stop()

	for {
		if next := t.newest(curPath); next != "" && next != curPath {
			stopCur()
			fctx, cancel := context.WithCancel(ctx)
			stopCur = cancel
			go func(path string, whence int) {
				defer cancel()
				t.follow1(fctx, path, whence, out)
			}(next, whence)
			curPath, whence = next, os.SEEK_SET
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
		}
	}
}

// newest returns the matching file with the latest mtime, or "" if none. cur is
// the file we are already on: a candidate only wins if it is strictly newer, so
// a stale sibling can never steal us away from the live log.
func (t *Tailer) newest(cur string) string {
	ents, err := os.ReadDir(t.dir)
	if err != nil {
		return ""
	}
	var matches []string
	for _, e := range ents {
		if t.name.MatchString(e.Name()) {
			matches = append(matches, filepath.Join(t.dir, e.Name()))
		}
	}
	if len(matches) == 0 {
		return ""
	}
	best, bestMod := "", time.Time{}
	if cur != "" {
		if fi, err := os.Stat(cur); err == nil {
			best, bestMod = cur, fi.ModTime()
		}
	}
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if fi.ModTime().After(bestMod) {
			best, bestMod = m, fi.ModTime()
		}
	}
	return best
}

// follow1 tails exactly one path until ctx is cancelled. Errors are logged by the
// caller's absence of lines, not returned: a single bad file must not kill the
// daemon while a sibling may still be live.
func (t *Tailer) follow1(ctx context.Context, path string, whence int, out chan<- string) {
	tf, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    true, // in-place rotation of this same path
		MustExist: false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: whence},
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return
	}
	defer tf.Cleanup()

	for {
		select {
		case <-ctx.Done():
			_ = tf.Stop()
			return
		case line, ok := <-tf.Lines:
			if !ok {
				return
			}
			if line.Err != nil {
				// A read error on one line should not kill the tailer; skip it.
				continue
			}
			select {
			case out <- line.Text:
			case <-ctx.Done():
				_ = tf.Stop()
				return
			}
		}
	}
}
