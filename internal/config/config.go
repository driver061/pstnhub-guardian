// Package config loads the one file that describes every server this daemon
// gates. See deploy/example.toml for an annotated copy.
//
// Two rules the loader enforces, because getting either wrong is silent and
// expensive:
//
//   - Every server needs its OWN nftables table. Two servers sharing a table
//     fight over the same chain, and one ends up gating the other's port.
//   - The webhook is read from the environment, never from the file and never
//     from a flag. Flags are visible in `ps` to every user on the box.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the whole daemon: global defaults plus one entry per server.
type Config struct {
	// Enforce is the global kill-switch. Servers may opt out individually, but
	// nothing enforces while this is false — so a single edit reverts the whole
	// box to log-only.
	Enforce bool `toml:"enforce"`

	// AllowTTL is how long an authenticated IP stays allowed (kernel-managed).
	AllowTTL duration `toml:"allow_ttl"`
	// NotifyCooldown is the per-source alert aggregation window.
	NotifyCooldown duration `toml:"notify_cooldown"`
	// HeartbeatInterval is the systemd watchdog ping. Keep well under WatchdogSec.
	HeartbeatInterval duration `toml:"heartbeat_interval"`
	// StateDir holds one allow-list file per server.
	StateDir string `toml:"state_dir"`
	// LogLevel is debug, info, warn or error.
	LogLevel string `toml:"log_level"`

	// LogDroppedIPs writes the source address of every dropped packet to the
	// KERNEL log (journalctl -k), for cross-referencing attackers with other
	// hosts. Off by default: this is the only path where an attacker controls how
	// much you write to disk. LogDropRate caps it, and the rule is separate from
	// the drop rule so exceeding the rate stops the logging and never the drop —
	// but the safest volume is still none.
	LogDroppedIPs bool `toml:"log_dropped_ips"`
	// LogDropRate is the per-second ceiling on those lines.
	LogDropRate uint64 `toml:"log_drop_rate"`

	Servers []Server `toml:"server"`

	// WebhookURL comes from DISCORD_WEBHOOK_URL. Empty disables notifications and
	// nothing else. Never present in the file.
	WebhookURL string `toml:"-"`
}

// Server is one Squad server: its log, its ports, its nftables table.
type Server struct {
	// Name identifies the server in logs, alerts and its state file. Must be
	// unique and filesystem-safe.
	Name string `toml:"name"`
	// LogPath is a pattern SEED, not a fixed file: .../SquadGame.log also follows
	// SquadGame_2.log. Rotated (-backup-) and CRC logs are never followed.
	LogPath string `toml:"log_path"`

	GamePort   uint16 `toml:"game_port"`
	BeaconPort uint16 `toml:"beacon_port"`
	QueryPort  uint16 `toml:"query_port"`

	// NFTable must be unique across servers. See the package doc.
	NFTable string `toml:"nft_table"`
	NFSet   string `toml:"nft_set"`

	// Enforce opts this server out of enforcement when the global switch is on.
	// Pointer so "unset" is distinguishable from "false": unset inherits global.
	Enforce *bool `toml:"enforce"`
}

// duration lets the file say allow_ttl = "60m" instead of a nanosecond count.
type duration struct{ time.Duration }

func (d *duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// Load reads path, applies defaults, and validates. A config that fails here
// must abort startup: a half-valid firewall config is worse than none.
func Load(path string) (*Config, error) {
	c := &Config{
		AllowTTL:          duration{60 * time.Minute},
		NotifyCooldown:    duration{5 * time.Minute},
		HeartbeatInterval: duration{10 * time.Second},
		StateDir:          "state",
		LogLevel:          "info",
		LogDropRate:       10,
	}
	if _, err := toml.DecodeFile(path, c); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	c.WebhookURL = os.Getenv("DISCORD_WEBHOOK_URL")

	if len(c.Servers) == 0 {
		return nil, errors.New("no [[server]] entries: nothing to gate")
	}

	seenName := map[string]bool{}
	seenTable := map[string]bool{}
	seenPort := map[uint16]string{}
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.Name == "" {
			return nil, fmt.Errorf("server #%d: name is required", i+1)
		}
		if seenName[s.Name] {
			return nil, fmt.Errorf("duplicate server name %q", s.Name)
		}
		seenName[s.Name] = true

		if s.LogPath == "" {
			return nil, fmt.Errorf("server %q: log_path is required", s.Name)
		}
		if s.GamePort == 0 {
			return nil, fmt.Errorf("server %q: game_port is required", s.Name)
		}
		if s.NFSet == "" {
			s.NFSet = "allowed"
		}
		if s.NFTable == "" {
			s.NFTable = "squad_" + s.Name
		}
		// Both of these are silent-failure modes at runtime, so they are fatal here.
		if seenTable[s.NFTable] {
			return nil, fmt.Errorf("server %q: nft_table %q already used by another server; each server needs its own table", s.Name, s.NFTable)
		}
		seenTable[s.NFTable] = true
		if other, dup := seenPort[s.GamePort]; dup {
			return nil, fmt.Errorf("server %q: game_port %d already used by %q", s.Name, s.GamePort, other)
		}
		seenPort[s.GamePort] = s.Name

		if s.Enforce == nil {
			s.Enforce = &c.Enforce
		}
	}
	return c, nil
}

// Enforcing reports whether this server should install the drop rule.
func (c *Config) Enforcing(s Server) bool { return c.Enforce && *s.Enforce }
