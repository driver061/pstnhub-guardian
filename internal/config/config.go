// Package config holds all runtime configuration for the gatekeeper.
//
// Everything here is set from flags or environment at startup and then treated
// as read-only. The webhook URL is the one secret; it comes from the
// environment, never a flag (flags show up in `ps`).
package config

import (
	"errors"
	"flag"
	"os"
	"time"
)

type Config struct {
	// LogPath is the Squad server log to tail.
	LogPath string

	// GamePort / BeaconPort / QueryPort are the UDP ports this server actually
	// binds. THESE ARE PLACEHOLDERS — confirm with `ss -ulpn` before enforcing.
	// The beacon and query ports are never gated; only the game port is
	// default-drop.
	GamePort   uint16
	BeaconPort uint16
	QueryPort  uint16

	// Enforce controls whether the drop rule is actually installed.
	//   false (default) -> log-only: everything runs, would-be drops are logged,
	//                      but the game port stays open to all. Run like this for
	//                      at least a week and confirm the would-drop list is
	//                      all attacker before flipping.
	//   true            -> the game port is default-drop; only allow-listed IPs pass.
	Enforce bool

	// AllowTTL is how long an authenticated IP stays on the allow-list before the
	// KERNEL expires it. Measured beacon->game gap maxed at ~30 min across 804
	// real players; 60 min is a safe margin. The daemon does not manage expiry
	// itself — nftables does.
	AllowTTL time.Duration

	// NFTable / NFSet name the nftables objects. Kept configurable so you can run
	// a second instance without collision.
	NFTable string
	NFSet   string

	// StatePath persists the allow-list across daemon restarts. The crash ->
	// restart -> crash window is exactly when an empty set locks out reconnecting
	// players, so this is not optional in enforce mode.
	StatePath string

	// WebhookURL is the Discord webhook. Empty disables notifications entirely.
	// From env DISCORD_WEBHOOK_URL only.
	WebhookURL string

	// NotifyCooldown is the per-source mute window: one alert when a source
	// starts getting dropped, then a summary when the window closes. Keeps an
	// attack from becoming an alert flood.
	NotifyCooldown time.Duration

	// HeartbeatInterval is how often we notify the systemd watchdog. Must be
	// comfortably below the unit's WatchdogSec.
	HeartbeatInterval time.Duration
}

func FromFlagsAndEnv() (*Config, error) {
	c := &Config{}

	flag.StringVar(&c.LogPath, "log", "/home/squad/SquadGame/Saved/Logs/SquadGame.log", "path to the Squad server log")
	var game, beacon, query uint
	flag.UintVar(&game, "game-port", 7787, "UDP game port (default-drop when enforcing)")
	flag.UintVar(&beacon, "beacon-port", 15000, "UDP beacon port (never gated)")
	flag.UintVar(&query, "query-port", 27165, "UDP query port (never gated)")
	flag.BoolVar(&c.Enforce, "enforce", false, "install the drop rule; default false = log-only")
	flag.DurationVar(&c.AllowTTL, "allow-ttl", 60*time.Minute, "how long an authed IP stays allowed (kernel-managed)")
	flag.StringVar(&c.NFTable, "nft-table", "squad", "nftables table name")
	flag.StringVar(&c.NFSet, "nft-set", "allowed", "nftables set name")
	flag.StringVar(&c.StatePath, "state", "/var/lib/squad-gatekeeper/allow.json", "allow-list persistence file")
	flag.DurationVar(&c.NotifyCooldown, "notify-cooldown", 5*time.Minute, "per-source alert aggregation window")
	flag.DurationVar(&c.HeartbeatInterval, "heartbeat", 10*time.Second, "systemd watchdog heartbeat interval")
	flag.Parse()

	c.GamePort = uint16(game)
	c.BeaconPort = uint16(beacon)
	c.QueryPort = uint16(query)
	c.WebhookURL = os.Getenv("DISCORD_WEBHOOK_URL") // secret: env only

	if c.LogPath == "" {
		return nil, errors.New("log path is required")
	}
	if c.GamePort == 0 {
		return nil, errors.New("game port is required")
	}
	return c, nil
}
