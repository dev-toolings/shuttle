package cli

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// A Mercure hub keeps its state in a BoltDB file on a mounted volume, and BoltDB
// is single-writer. Under start-first the replacement task starts while the
// outgoing one still owns the file, times out acquiring the lock and exits 1 —
// Swarm then rolls the entire stack back. Measured on demo api on
// 04-09-2026: `provision http.handlers.mercure.bolt: "": invalid transport:
// timeout`, with the outgoing task still logging health checks 25s after its
// replacement had started.
func TestSecureStackHonoursAPerServiceUpdateOrder(t *testing.T) {
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
  mercure:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
`
	cfg := &config.Config{
		Version: 2,
		App:     "demo",
		Domain:  "demo.example.com",
		Services: map[string]config.Service{
			"mercure": {UpdateOrder: config.UpdateOrderStopFirst},
		},
	}
	out, err := secureStack(body, cfg, "8080")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	services, _ := doc["services"].(map[string]any)

	for name, want := range map[string]string{"web": "start-first", "mercure": "stop-first"} {
		service, _ := services[name].(map[string]any)
		deploy, _ := service["deploy"].(map[string]any)
		update, _ := deploy["update_config"].(map[string]any)
		if update["order"] != want {
			t.Fatalf("%s update_config.order = %v, want %s", name, update["order"], want)
		}
		// A rollback that reverses the order would recreate the very overlap the
		// override exists to prevent, at the worst possible moment.
		rollback, _ := deploy["rollback_config"].(map[string]any)
		if rollback["order"] != want {
			t.Fatalf("%s rollback_config.order = %v, want %s", name, rollback["order"], want)
		}
	}
}

// The override is an exception, not a knob. Left unset, every service keeps the
// zero-downtime default.
func TestUpdateOrderDefaultsToStartFirst(t *testing.T) {
	var cfg *config.Config
	if got := cfg.UpdateOrder("anything"); got != config.UpdateOrderStartFirst {
		t.Fatalf("nil config resolved %q", got)
	}
	cfg = &config.Config{Services: map[string]config.Service{"web": {Port: 3000}}}
	if got := cfg.UpdateOrder("web"); got != config.UpdateOrderStartFirst {
		t.Fatalf("unset update_order resolved %q", got)
	}
	if got := cfg.UpdateOrder("absent"); got != config.UpdateOrderStartFirst {
		t.Fatalf("undeclared service resolved %q", got)
	}
}
