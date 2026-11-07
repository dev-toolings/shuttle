package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadOverlay writes a base file and an environment overlay beside it, the way
// `shuttle deploy -e <env>` finds them.
func loadOverlay(t *testing.T, base string, env string, overlay string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if overlay != "" {
		if err := os.WriteFile(filepath.Join(dir, "config."+env+".json"), []byte(overlay), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Load(path, env)
}

// An overlay used to be merged as a decoded struct, and a Go struct cannot tell
// "absent" from "zero": every field the overlay did not restate was marshalled
// as its zero value and overwrote a good one. Declaring a domain and a host —
// the whole point of an overlay — reset version to 0 and stopped the deploy.
// The fields with no such guard, app and deploy.retain among them, were blanked
// in silence.
func TestOverlayReplacesOnlyTheKeysItDeclares(t *testing.T) {
	cfg, err := loadOverlay(t, validConfig, "preprod", `domain: preprod.example.com
server:
  host: 203.0.113.20
`)
	if err != nil {
		t.Fatalf("an overlay must not invalidate the base it layers onto: %v", err)
	}
	if cfg.Domain != "preprod.example.com" {
		t.Fatalf("the overlay must win where it speaks, got %v", cfg.Domain)
	}
	if cfg.Version != 2 {
		t.Fatalf("version must survive an overlay that says nothing about it, got %d", cfg.Version)
	}
	if cfg.App == "" {
		t.Fatal("app must survive an overlay that says nothing about it")
	}
	if cfg.Deploy.Strategy != "swarm" {
		t.Fatalf("deploy.strategy must survive, got %q", cfg.Deploy.Strategy)
	}
	if cfg.Server.Host != "203.0.113.20" {
		t.Fatalf("a nested key must be replaced without dropping its siblings, got %q", cfg.Server.Host)
	}
	if cfg.Server.User != "deploy" {
		t.Fatalf("server.user must survive an overlay that only sets server.host, got %q", cfg.Server.User)
	}
	if cfg.Server.Port != 22 {
		t.Fatalf("server.port must survive too, got %d", cfg.Server.Port)
	}
}

// An unknown field is still an error under an overlay, and the file that holds
// it is the file the operator has to open.
func TestOverlayStillRefusesAnUnknownField(t *testing.T) {
	_, err := loadOverlay(t, validConfig, "preprod", "not_a_field: 1\n")
	if err == nil || !strings.Contains(err.Error(), "not_a_field") {
		t.Fatalf("an unknown field in an overlay must be refused by name, got %v", err)
	}
}

// A named environment with no file beside the base is not an error: it is a
// project that has not needed one yet.
func TestMissingOverlayLeavesTheBaseAlone(t *testing.T) {
	cfg, err := loadOverlay(t, validConfig, "preprod", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 {
		t.Fatalf("the base must load untouched, got version %d", cfg.Version)
	}
}
