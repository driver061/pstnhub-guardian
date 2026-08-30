package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

const twoServers = `
enforce = true
allow_ttl = "30m"

[[server]]
name = "main"
log_path = "/srv/1/SquadGame.log"
game_port = 7787

[[server]]
name = "second"
log_path = "/srv/2/SquadGame.log"
game_port = 7797
enforce = false
`

func TestLoadDefaultsAndPerServerEnforce(t *testing.T) {
	c, err := load(t, twoServers)
	if err != nil {
		t.Fatal(err)
	}
	if c.AllowTTL.Duration.Minutes() != 30 {
		t.Errorf("allow_ttl = %v, want 30m", c.AllowTTL.Duration)
	}
	// Tables must be auto-derived per server, or they collide in the kernel.
	if c.Servers[0].NFTable == c.Servers[1].NFTable {
		t.Fatalf("servers share nft_table %q", c.Servers[0].NFTable)
	}
	if !c.Enforcing(c.Servers[0]) {
		t.Error("main should enforce (global on, unset locally)")
	}
	if c.Enforcing(c.Servers[1]) {
		t.Error("second opted out with enforce = false and must not enforce")
	}
}

func TestGlobalSwitchOverridesLocalTrue(t *testing.T) {
	c, err := load(t, strings.Replace(twoServers, "enforce = true", "enforce = false", 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range c.Servers {
		if c.Enforcing(s) {
			t.Errorf("%s enforces despite the global switch being off", s.Name)
		}
	}
}

// The two collisions that fail silently at runtime must fail loudly at load.
func TestRejectsCollisions(t *testing.T) {
	for name, body := range map[string]string{
		"same table": `
[[server]]
name = "a"
log_path = "/a/SquadGame.log"
game_port = 7787
nft_table = "shared"
[[server]]
name = "b"
log_path = "/b/SquadGame.log"
game_port = 7797
nft_table = "shared"
`,
		"same game port": `
[[server]]
name = "a"
log_path = "/a/SquadGame.log"
game_port = 7787
[[server]]
name = "b"
log_path = "/b/SquadGame.log"
game_port = 7787
`,
		"duplicate name": `
[[server]]
name = "a"
log_path = "/a/SquadGame.log"
game_port = 7787
[[server]]
name = "a"
log_path = "/b/SquadGame.log"
game_port = 7797
`,
		"no servers": `enforce = true`,
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: loaded without error, want rejection", name)
		}
	}
}
