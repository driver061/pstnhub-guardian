package gate

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// persisted is the on-disk form of the allow-list. Stored as ip -> unix expiry.
type persisted map[string]int64

// LoadState reads the allow-list from disk. Missing file is not an error (first
// run). Expired entries are dropped on load.
func LoadState(path string) (map[netip.Addr]time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[netip.Addr]time.Time{}, nil
		}
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	now := time.Now()
	out := make(map[netip.Addr]time.Time)
	for s, unix := range p {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		exp := time.Unix(unix, 0)
		if exp.After(now) {
			out[ip] = exp
		}
	}
	return out, nil
}

// SaveState atomically writes the allow-list to disk (temp file + rename).
func SaveState(path string, m map[netip.Addr]time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	p := make(persisted, len(m))
	for ip, exp := range m {
		p[ip.String()] = exp.Unix()
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
