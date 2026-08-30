// Package notifier posts alerts to a Discord webhook. It is deliberately OFF the
// firewall critical path: alerts flow through a buffered channel drained by one
// goroutine, and if the buffer fills we DROP ALERTS, never block the caller.
// Discord being slow, rate-limited, or down must degrade to "no alerts", never to
// "the guardian stalled".
//
// Aggregation: the attacker opens connections in bursts. One webhook per dropped
// connection would flood the channel and trip Discord's ~30/min limit exactly when
// you need the channel. So drops are aggregated per source IP over a cooldown
// window: the first drop from an IP fires immediately, then further drops from that
// IP are counted and flushed as one summary when the window closes.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type Level int

const (
	// Health events are about the daemon itself and are never aggregated or
	// dropped-silently in a way that hides them — these are the ones you can't
	// learn any other way (fail-open fired, enforce toggled, daemon restarted).
	LevelHealth Level = iota
	LevelIncident
)

type Alert struct {
	Level Level
	Title string
	Body  string
	IP    netip.Addr // zero value if not IP-specific
}

type Notifier struct {
	url      string
	cooldown time.Duration
	log      *slog.Logger
	client   *http.Client

	in chan Alert

	mu  sync.Mutex
	agg map[netip.Addr]*aggState // per-IP incident aggregation
}

type aggState struct {
	first    time.Time
	last     time.Time
	count    int
	deadline time.Time
}

// New returns a notifier. If url is empty the notifier is a no-op (all sends are
// silently discarded), so wiring it in is always safe even without Discord set up.
func New(url string, cooldown time.Duration, log *slog.Logger) *Notifier {
	return &Notifier{
		url:      url,
		cooldown: cooldown,
		log:      log,
		client:   &http.Client{Timeout: 10 * time.Second},
		in:       make(chan Alert, 256), // bounded: full buffer -> drop, never block
		agg:      make(map[netip.Addr]*aggState),
	}
}

// Run drains the queue and flushes aggregation windows until ctx is cancelled.
func (n *Notifier) Run(ctx context.Context) {
	if n.url == "" {
		// no-op mode: still drain so senders never block on a full buffer
		for {
			select {
			case <-ctx.Done():
				return
			case <-n.in:
			}
		}
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			n.flushAll()
			return
		case a := <-n.in:
			n.handle(a)
		case <-ticker.C:
			n.flushExpired()
		}
	}
}

// Health sends a daemon-health alert. Never aggregated; posted promptly.
func (n *Notifier) Health(title, body string) {
	n.enqueue(Alert{Level: LevelHealth, Title: title, Body: body})
}

// Incident reports something about a source IP (e.g. a would-be / actual drop).
// Aggregated per IP over the cooldown window.
func (n *Notifier) Incident(ip netip.Addr, title, body string) {
	n.enqueue(Alert{Level: LevelIncident, Title: title, Body: body, IP: ip})
}

// enqueue is non-blocking. A full buffer means we are already flooded with alerts;
// dropping additional ones is the correct behaviour and is logged locally.
func (n *Notifier) enqueue(a Alert) {
	select {
	case n.in <- a:
	default:
		n.log.Warn("notifier buffer full, dropping alert", "title", a.Title)
	}
}

func (n *Notifier) handle(a Alert) {
	if a.Level == LevelHealth || !a.IP.IsValid() {
		n.post(a.Title, a.Body)
		return
	}
	n.mu.Lock()
	st, ok := n.agg[a.IP]
	now := time.Now()
	if !ok {
		// first drop from this IP -> alert immediately, open a window
		n.agg[a.IP] = &aggState{first: now, last: now, count: 1, deadline: now.Add(n.cooldown)}
		n.mu.Unlock()
		n.post(a.Title, a.Body)
		return
	}
	st.count++
	st.last = now
	n.mu.Unlock()
}

func (n *Notifier) flushExpired() {
	now := time.Now()
	n.mu.Lock()
	var due []struct {
		ip netip.Addr
		st aggState
	}
	for ip, st := range n.agg {
		if now.After(st.deadline) {
			due = append(due, struct {
				ip netip.Addr
				st aggState
			}{ip, *st})
			delete(n.agg, ip)
		}
	}
	n.mu.Unlock()

	for _, d := range due {
		if d.st.count <= 1 {
			continue // the single first-drop was already sent
		}
		n.post(
			"Incident summary",
			formatSummary(d.ip, d.st),
		)
	}
}

func (n *Notifier) flushAll() {
	n.mu.Lock()
	all := n.agg
	n.agg = make(map[netip.Addr]*aggState)
	n.mu.Unlock()
	for ip, st := range all {
		if st.count <= 1 {
			continue
		}
		n.post("Incident summary (shutdown)", formatSummary(ip, *st))
	}
}

func formatSummary(ip netip.Addr, st aggState) string {
	return ip.String() + ": " + itoa(st.count) + " events in " +
		st.last.Sub(st.first).Round(time.Second).String()
}

// post does the actual webhook call. Failures are logged and forgotten — never
// retried in a way that could stall the drain loop.
func (n *Notifier) post(title, body string) {
	payload := map[string]any{
		"embeds": []map[string]any{{
			"title":       title,
			"description": body,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		n.log.Warn("notifier marshal failed", "err", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, n.url, bytes.NewReader(buf))
	if err != nil {
		n.log.Warn("notifier request build failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("notifier post failed", "err", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		n.log.Warn("notifier non-2xx", "status", resp.StatusCode)
	}
}

// small dependency-free itoa to avoid strconv churn in hot-ish path
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
