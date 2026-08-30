// Command gatekeeper is the Squad game-port gatekeeper daemon.
//
// It tails the Squad server log, allow-lists the source IP of every player that
// completes the beacon (EOS) handshake, and — in enforce mode — default-drops the
// game port for everyone else. The crash exploit we defend against never touches
// the beacon, so it never gets allow-listed, so its packets are dropped before the
// vulnerable connection object is ever created.
//
// SAFETY INVARIANT: if this daemon is not healthy, the drop rule must not be
// installed. That is enforced two ways:
//   - a deferred firewall.Disable() runs on every exit path (panic, signal, error)
//   - systemd WatchdogSec + Restart, plus ExecStopPost that flushes the table,
//     covers the case where the process dies without running defers (SIGKILL, OOM)
//
// Run log-only first (default). Only pass -enforce after a week of clean would-drop
// logs.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"

	"github.com/yourorg/squad-gatekeeper/internal/config"
	"github.com/yourorg/squad-gatekeeper/internal/firewall"
	"github.com/yourorg/squad-gatekeeper/internal/gate"
	"github.com/yourorg/squad-gatekeeper/internal/notifier"
	"github.com/yourorg/squad-gatekeeper/internal/parser"
	"github.com/yourorg/squad-gatekeeper/internal/tailer"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.FromFlagsAndEnv()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}

	if err := run(cfg, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- firewall setup -------------------------------------------------------
	fw, err := firewall.New(firewall.Config{
		Table:      cfg.NFTable,
		Set:        cfg.NFSet,
		GamePort:   cfg.GamePort,
		BeaconPort: cfg.BeaconPort,
		QueryPort:  cfg.QueryPort,
		AllowTTL:   cfg.AllowTTL,
	})
	if err != nil {
		return err
	}
	if err := fw.EnsureTableAndSet(); err != nil {
		return err
	}

	// FAIL-OPEN GUARANTEE: no matter how we leave run(), the drop rule comes out.
	// This covers panics and clean signals. SIGKILL/OOM is covered by the systemd
	// unit's ExecStopPost. Registered BEFORE Enable so it always fires.
	defer func() {
		if err := fw.Disable(); err != nil {
			log.Error("fail-open: could not remove drop rule", "err", err)
		} else {
			log.Info("fail-open: drop rule removed, game port open to all")
		}
	}()

	// --- notifier -------------------------------------------------------------
	notif := notifier.New(cfg.WebhookURL, cfg.NotifyCooldown, log)
	go notif.Run(ctx)

	// --- gate + seeded state --------------------------------------------------
	g := gate.New(fw, notif, log, cfg.Enforce, cfg.AllowTTL)
	if seeded, err := gate.LoadState(cfg.StatePath); err != nil {
		log.Warn("could not load persisted state", "err", err)
	} else {
		g.Seed(seeded)
		log.Info("seeded allow-list", "count", len(seeded))
	}

	// --- enforce (or not) -----------------------------------------------------
	if cfg.Enforce {
		if err := fw.Enable(); err != nil {
			return err
		}
		log.Warn("ENFORCE MODE: game port is now default-drop", "game_port", cfg.GamePort)
		notif.Health("Gatekeeper enforcing", "Game port default-drop is active")
	} else {
		log.Info("LOG-ONLY MODE: no packets dropped; logging would-be drops", "game_port", cfg.GamePort)
		notif.Health("Gatekeeper started (log-only)", "Validating would-drop list; no enforcement")
	}

	// --- periodic state save --------------------------------------------------
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := gate.SaveState(cfg.StatePath, g.Snapshot()); err != nil {
					log.Warn("state save failed", "err", err)
				}
			}
		}
	}()

	// --- systemd watchdog heartbeat -------------------------------------------
	// sd_notify WATCHDOG=1 at an interval below the unit's WatchdogSec. If this
	// loop stops (daemon wedged), systemd kills and restarts us, and ExecStopPost
	// flushes the table — fail-open even when defers don't run.
	go heartbeat(ctx, cfg.HeartbeatInterval, log)
	_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)

	// --- main loop: tail -> parse -> gate -------------------------------------
	lines := make(chan string, 1024)
	go func() {
		if err := tailer.New(cfg.LogPath).Follow(ctx, lines); err != nil && ctx.Err() == nil {
			log.Error("tailer stopped", "err", err)
			stop() // treat a dead tailer as fatal -> triggers fail-open
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			_ = gate.SaveState(cfg.StatePath, g.Snapshot())
			return nil
		case line := <-lines:
			if ev, ok := parser.Parse(line); ok {
				g.Handle(ev)
			}
		}
	}
}

func heartbeat(ctx context.Context, interval time.Duration, log *slog.Logger) {
	// If systemd isn't managing us (interval unset or no watchdog), this is a
	// harmless no-op beyond the ticker.
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
				log.Debug("sd_notify watchdog failed (not under systemd?)", "err", err)
			}
		}
	}
}
