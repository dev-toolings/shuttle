package readiness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigMapsSingleSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shuttle.yml")
	body := `version: 2
app: demo
domain: demo.example.com
server: {host: 203.0.113.10, user: deploy, port: 2222}
setup: {slo_seconds: 600}
deploy: {strategy: swarm, total_slo_seconds: 30, retain: 2, swarm: {mode: single-node}}
services: {web: {port: 3000, healthcheck: {type: http, path: /health}}}
retention: {registry_cache: 5GB, postgres_backups: 7, min_free_percent: 20}
readiness: {preset: node-api, healthcheck_path: /health}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, resolved, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ContainerizedApplication {
		t.Fatal("validated Swarm config must describe containerized application runtimes")
	}
	if resolved != path || cfg.Version != 2 || cfg.Access.Host != "203.0.113.10" || cfg.Access.SSHPort != 2222 || cfg.App.Domain != "demo.example.com" {
		t.Fatalf("unexpected mapping: %#v", cfg)
	}
}

func TestLoadConfigCarriesTheOptionalOperatorIntoSSHPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
  "version": 2,
  "app": "demo",
  "domain": "demo.example.com",
  "server": {"host": "203.0.113.10", "user": "deploy", "port": 22},
  "setup": {"slo_seconds": 600, "operator_user": "ops", "operator_public_key": "keys/ops.pub"},
  "deploy": {"strategy": "swarm", "total_slo_seconds": 30, "retain": 2, "swarm": {"mode": "single-node"}},
  "services": {"web": {"port": 3000, "healthcheck": {"type": "http", "path": "/health"}}},
  "retention": {"registry_cache": "5GB", "postgres_backups": 7, "min_free_percent": 20},
  "readiness": {"preset": "node-api", "healthcheck_path": "/health"}
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Access.AllowedSSHUsers, " "); got != "deploy ops" {
		t.Fatalf("AllowedSSHUsers = %q, want deploy ops", got)
	}
}
