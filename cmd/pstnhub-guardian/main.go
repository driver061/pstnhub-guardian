// Command pstnhub-guardian gates Squad game ports by beacon authentication.
//
// For each configured server it tails the Squad log, allow-lists the source IP of
// every player that completes the beacon (EOS) handshake, and — in enforce mode —
// default-drops the game port for everyone else. The crash exploit this defends
// against never completes a beacon, so it is never allow-listed, so its packets
// are dropped before the vulnerable connection object is created.
//
// One process gates every server in the config. Each server gets its own nftables
// table, its own tailer, and its own allow-list; they share only the notifier and
// the process lifetime.
//
// SAFETY INVARIANT: if this daemon is not healthy, no drop rule may be installed.
// Enforced three ways:
//   - a deferred Disable() per server runs on every exit path (panic, signal, error)
//   - systemd WatchdogSec + Restart, plus ExecStopPost flushing the tables, covers
//     death without defers (SIGKILL, OOM)
//   - the chain policy is ACCEPT, so even a half-built chain passes traffic
//
// Run log-only first. Only set enforce = true after a week of clean would-drop logs.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"

	"github.com/pstnhub/pstnhub-guardian/internal/config"
	"github.com/pstnhub/pstnhub-guardian/internal/firewall"
	"github.com/pstnhub/pstnhub-guardian/internal/gate"
	"github.com/pstnhub/pstnhub-guardian/internal/logging"
	"github.com/pstnhub/pstnhub-guardian/internal/notifier"
	"github.com/pstnhub/pstnhub-guardian/internal/parser"
	"github.com/pstnhub/pstnhub-guardian/internal/tailer"
)

func main() {
	cfgPath := "guardian.toml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	// Bootstrap logger: the real level comes from the config we have not read yet.
	log := logging.New(os.Stdout, slog.LevelInfo)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logging.For(log, "Config", "").Error("load failed", "err", err)
		os.Exit(2)
	}
	log = logging.New(os.Stdout, parseLevel(cfg.LogLevel))

	if err := run(cfg, log); err != nil {
		logging.For(log, "Guardian", "").Error("fatal", "err", err)
		os.Exit(1)
	}
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

func run(cfg *config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	glog := logging.For(log, "Guardian", "")

	notif := notifier.New(cfg.WebhookURL, cfg.NotifyCooldown.Duration, logging.For(log, "Notify", ""))
	go notif.Run(ctx)
	if cfg.WebhookURL == "" {
		glog.Warn("no DISCORD_WEBHOOK_URL set, notifications are off")
	}

	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}

	// Bring each server up. A failure here aborts everything: servers already
	// started are torn down by their deferred teardown, reverting to accept-all.
	var (
		wg       sync.WaitGroup
		started  []string
		teardown []func()
	)
	defer func() {
		for _, fn := range teardown {
			fn()
		}
	}()

	for _, srv := range cfg.Servers {
		s := srv
		log := logging.For(log, "Server", s.Name)
		flog := logging.For(log, "Firewall", s.Name)
		enforce := cfg.Enforcing(s)

		fw, err := firewall.New(firewall.Config{
			Table:      s.NFTable,
			Set:        s.NFSet,
			BlockSet:   s.NFSet + "_blocked",
			GamePort:   s.GamePort,
			BeaconPort: s.BeaconPort,
			QueryPort:  s.QueryPort,
			AllowTTL:   cfg.AllowTTL.Duration,
			LogDropped: cfg.LogDroppedIPs,
			LogRate:    cfg.LogDropRate,
		})
		if err != nil {
			return fmt.Errorf("server %s: %w", s.Name, err)
		}
		if err := fw.EnsureTableAndSet(); err != nil {
			return fmt.Errorf("server %s: %w", s.Name, err)
		}

		// Registered BEFORE Enable, so the drop rule can never outlive us.
		teardown = append(teardown, func() {
			if err := fw.Disable(); err != nil {
				flog.Error("fail-open could not remove drop rule", "err", err)
				return
			}
			flog.Info("fail-open complete, game port open to all")
		})

		statePath := filepath.Join(cfg.StateDir, s.Name+".json")
		g := gate.New(fw, notif, logging.For(log, "Gate", s.Name), enforce, cfg.AllowTTL.Duration, s.Name)
		if seeded, err := gate.LoadState(statePath); err != nil {
			log.Warn("could not load persisted state", "err", err)
		} else {
			g.Seed(seeded)
			log.Info("seeded allow-list from state", "count", len(seeded))
		}
		if bans, err := gate.LoadState(banPath(cfg.StateDir, s.Name)); err != nil {
			log.Warn("could not load persisted bans", "err", err)
		} else if len(bans) > 0 {
			g.SeedBans(bans)
			log.Warn("restored bans from state", "count", len(bans))
		}

		if enforce {
			if err := fw.Enable(); err != nil {
				return fmt.Errorf("server %s: %w", s.Name, err)
			}
			flog.Warn("enforce mode active, game port is default-drop", "port", s.GamePort)
			notif.Health("Guardian enforcing ["+s.Name+"]", fmt.Sprintf("Game port %d is default-drop", s.GamePort))
		} else {
			flog.Info("log-only mode, no packets dropped", "port", s.GamePort)
			notif.Health("Guardian started log-only ["+s.Name+"]", "Validating would-drop list, no enforcement")
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			runServer(ctx, stop, s, cfg, g, fw, notif, log)
		}()
		started = append(started, s.Name)
	}

	glog.Info("all servers running", "servers", len(started))

	go heartbeat(ctx, cfg.HeartbeatInterval.Duration, logging.For(log, "Watchdog", ""))
	_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)

	<-ctx.Done()
	glog.Info("shutting down")
	wg.Wait()
	return nil
}

// runServer owns one tail -> parse -> gate pipeline for the process lifetime,
// plus that server's state saving and drop-counter watch.
func runServer(ctx context.Context, stop context.CancelFunc, s config.Server, cfg *config.Config,
	g *gate.Gate, fw *firewall.Firewall, notif *notifier.Notifier, log *slog.Logger) {

	statePath := filepath.Join(cfg.StateDir, s.Name+".json")
	bans := banPath(cfg.StateDir, s.Name)

	lines := make(chan string, 1024)
	tl := tailer.New(s.LogPath)
	go func() {
		if err := tl.Follow(ctx, lines); err != nil && ctx.Err() == nil {
			log.Error("tailer stopped", "err", err)
			stop() // a deaf gate is a broken gate: take the daemon down -> fail-open
		}
	}()

	// Startup backfill: the tailer opens at END, so without this every player
	// already connected looks unauthenticated — and in enforce mode gets dropped
	// on restart, which is exactly when the server has just crashed with a full
	// player list. Concurrent with the tail so it never delays reaching the live
	// edge of the log.
	go func() {
		evs, err := tl.Backfill(cfg.AllowTTL.Duration)
		if err != nil {
			log.Warn("startup backfill failed, allow-list starts from state only", "err", err)
			return
		}
		for _, ev := range evs {
			g.Handle(ev)
		}
		log.Info("startup backfill complete", "allowed", len(evs))
	}()

	if cfg.Enforcing(s) {
		go watchDrops(ctx, fw, notif, log, cfg.NotifyCooldown.Duration, s.Name, cfg.LogDroppedIPs)
	}

	saveTicker := time.NewTicker(30 * time.Second)
	defer saveTicker.Stop()

	// The stall detector is the one check that has to run on OUR clock: it fires
	// on a beacon connection that has gone silent, so waiting for the next log
	// line to drive it defeats the point. 500ms keeps the detection lag well
	// inside the 2s window.
	stallTicker := time.NewTicker(500 * time.Millisecond)
	defer stallTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := gate.SaveState(statePath, g.Snapshot()); err != nil {
				log.Warn("final state save failed", "err", err)
			}
			if err := gate.SaveState(bans, g.Bans()); err != nil {
				log.Warn("final ban save failed", "err", err)
			}
			return
		case <-saveTicker.C:
			if err := gate.SaveState(statePath, g.Snapshot()); err != nil {
				log.Warn("state save failed", "err", err)
			}
			if err := gate.SaveState(bans, g.Bans()); err != nil {
				log.Warn("ban save failed", "err", err)
			}
		case <-stallTicker.C:
			g.SweepStalls()
		case line := <-lines:
			if ev, ok := parser.Parse(line); ok {
				g.Handle(ev)
			}
		}
	}
}

// watchDrops polls the drop-rule counter and reports rising counts. In enforce
// mode the kernel drops silently — no Squad log line, so no event, so no alert.
// The counter is the only evidence an attack happened at all. Source addresses
// are not here: they go to the kernel log via the rate-limited log rule.
func watchDrops(ctx context.Context, fw *firewall.Firewall, notif *notifier.Notifier,
	log *slog.Logger, cooldown time.Duration, server string, ipsLogged bool) {

	// Only point at the kernel log when addresses are actually being written there.
	ipHint := " Source IPs are not being recorded (log_dropped_ips = false)."
	if ipsLogged {
		ipHint = " Source IPs: journalctl -k | grep pstnhub-guardian"
	}

	const interval = 30 * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()

	var (
		last      uint64
		haveLast  bool
		lastAlert time.Time
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pkts, _, ok := fw.DropCount()
			if !ok {
				continue
			}
			// First reading sets the baseline. A restart resets the kernel counter,
			// so a decrease re-baselines instead of reporting a nonsense delta.
			if !haveLast || pkts < last {
				last, haveLast = pkts, true
				continue
			}
			delta := pkts - last
			last = pkts
			if delta == 0 {
				continue
			}
			log.Warn("dropped packets on game port", "packets", delta, "total", pkts)
			if time.Since(lastAlert) >= cooldown {
				lastAlert = time.Now()
				notif.Health("Game port under load ["+server+"]",
					fmt.Sprintf("%d packets dropped in the last %s (%d total).%s",
						delta, interval, pkts, ipHint))
			}
		}
	}
}

func heartbeat(ctx context.Context, interval time.Duration, log *slog.Logger) {
	// If systemd is not managing us this is a harmless no-op beyond the ticker.
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
				log.Warn("watchdog notify failed", "err", err)
			}
		}
	}
}

// banPath is the ban file for a server. Separate from the allow-list file: bans
// must survive the crash that caused them, and mixing them into the same file
// risks one bad write losing both.
func banPath(dir, name string) string { return filepath.Join(dir, name+".bans.json") }
