// Package logging renders logs in the same shape as Squad's own server log, so
// an admin reading both is not switching formats mid-incident:
//
//	[30.08.2026-16:02:11.123] [Gate:main] Allowed player. [1.2.3.4 | 00022f92c00c4537b96cd84fbe3d4bae]
//	[30.08.2026-16:02:14.007] [Firewall:main] Enforce mode active, game port default-drop. [7787]
//	[30.08.2026-16:05:02.881] [Guardian] Startup backfill complete. [12 allowed]
//
// The trailing bracket is the subject of the line — the IP and EOS id when the
// event is about a player, otherwise whatever identifies it. It is always last
// so `grep -oP '\[\K[0-9.]+(?= \|)'` pulls addresses out of any line.
//
// Category is "<Component>" or "<Component>:<server>" and comes from With(),
// so call sites never repeat it.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// Attribute keys the handler treats specially. Everything else is rendered as
// key=value inside the trailing bracket.
const (
	KeyCategory = "cat" // component, e.g. "Gate"
	KeyServer   = "srv" // server name, appended to the category
	KeyIP       = "ip"
	KeyEOS      = "eos"
)

type handler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Level
	attrs []slog.Attr
}

// New returns a logger writing the Squad-style format to w. Levels below level
// are discarded. Writes are serialized: two servers logging at once must not
// interleave halves of a line.
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(&handler{mu: &sync.Mutex{}, w: w, level: level})
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr{}, h.attrs...), as...)
	return &n
}

// WithGroup is unused here; grouping has no meaning in a flat one-line format.
func (h *handler) WithGroup(string) slog.Handler { return h }

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	var (
		cat, srv, ip, eos string
		extra             []string
	)
	take := func(a slog.Attr) {
		v := a.Value.Resolve().String()
		switch a.Key {
		case KeyCategory:
			cat = v
		case KeyServer:
			srv = v
		case KeyIP:
			ip = v
		case KeyEOS:
			eos = v
		default:
			extra = append(extra, a.Key+"="+v)
		}
	}
	for _, a := range h.attrs {
		take(a)
	}
	r.Attrs(func(a slog.Attr) bool { take(a); return true })

	if cat == "" {
		cat = "Guardian"
	}
	if srv != "" {
		cat += ":" + srv
	}
	// WARN and ERROR are marked; INFO is the unmarked default, as in Squad's log.
	switch {
	case r.Level >= slog.LevelError:
		cat += " ERROR"
	case r.Level >= slog.LevelWarn:
		cat += " WARN"
	}

	// Squad's lines read as sentences: capitalised, full stop. Call sites stay
	// lowercase Go style ("allowed player") and the handler does the shaping.
	msg := strings.TrimSpace(r.Message)
	if msg != "" {
		msg = strings.ToUpper(msg[:1]) + msg[1:]
		if !strings.ContainsAny(msg[len(msg)-1:], ".!?:") {
			msg += "."
		}
	}

	// Subject bracket: "ip | eos", "ip", or the leftover key=value pairs.
	var subject string
	switch {
	case ip != "" && eos != "":
		subject = ip + " | " + eos
	case ip != "":
		subject = ip
	}
	if len(extra) > 0 {
		if subject != "" {
			subject += " | "
		}
		subject += strings.Join(extra, " ")
	}

	line := fmt.Sprintf("[%s] [%s] %s", r.Time.Format("02.01.2006-15:04:05.000"), cat, msg)
	if subject != "" {
		line += " [" + subject + "]"
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line+"\n")
	return err
}

// For returns a logger tagged with a component and, when non-empty, a server —
// the pair that becomes "[Gate:main]".
func For(base *slog.Logger, component, server string) *slog.Logger {
	l := base.With(KeyCategory, component)
	if server != "" {
		l = l.With(KeyServer, server)
	}
	return l
}
