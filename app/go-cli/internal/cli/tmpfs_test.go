package cli

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// Declared sizes must survive the real Compose-to-Swarm transformation,
// including an override of the mandatory /tmp mount.
func TestSecureStackPreservesDeclaredTmpfsSizes(t *testing.T) {
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
    tmpfs: ["/tmp:size=256M", "/data:rw,noexec,size=134217728", "/app/var"]
`
	out, err := secureStack(body, &config.Config{Version: 2, App: "demo", Domain: "demo.example.com"}, "8080")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out), &document); err != nil {
		t.Fatal(err)
	}
	services := document["services"].(map[string]any)
	web := services["web"].(map[string]any)
	sizes := map[string]int{}
	for _, raw := range web["volumes"].([]any) {
		mount := raw.(map[string]any)
		if err := validateRootTmpfsMount("web", mount); err != nil {
			t.Fatalf("generated mount violates the existing root policy: %v", err)
		}
		sizes[mount["target"].(string)] = mount["tmpfs"].(map[string]any)["size"].(int)
	}
	for path, expected := range map[string]int{"/tmp": 256 << 20, "/data": 128 << 20, "/app/var": 64 << 20} {
		if sizes[path] != expected {
			t.Errorf("%s size = %d, want %d", path, sizes[path], expected)
		}
	}
}

func TestServiceTmpfsRejectsInvalidDeclaredSizes(t *testing.T) {
	for _, declaration := range []string{"/tmp:size=", "/tmp:size=0", "/tmp:size=-1", "/tmp:size=513M", "/tmp:size=invalid", "/tmp:size=999999999999999999999TB"} {
		t.Run(declaration, func(t *testing.T) {
			if _, err := serviceTmpfs([]any{declaration}); err == nil {
				t.Fatalf("invalid size silently accepted: %s", declaration)
			}
		})
	}
}

// A FrankenPHP image writes its Caddy PKI to /data before serving anything, so
// under read_only: true it crash-loops unless that path is a real Swarm mount.
// docker stack deploy silently drops the short `tmpfs:` key, so only the long
// type: tmpfs volume form reaches the service spec.
func TestSecureStackTurnsTmpfsIntoSwarmMounts(t *testing.T) {
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
    tmpfs:
      - /data:rw,noexec,nosuid,size=64m
      - /app/var
`
	cfg := &config.Config{Version: 2, App: "demo", Domain: "demo.example.com"}
	out, err := secureStack(body, cfg, "8080")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "\n    tmpfs:") {
		t.Fatalf("the short tmpfs key must not survive; Swarm ignores it:\n%s", out)
	}
	for _, target := range []string{"target: /tmp", "target: /data", "target: /app/var"} {
		if !strings.Contains(out, target) {
			t.Fatalf("missing writable mount %q:\n%s", target, out)
		}
	}
	if !strings.Contains(out, "type: tmpfs") {
		t.Fatalf("writable mounts must use the long form:\n%s", out)
	}
}

func TestSecureStackRejectsUnsafeTmpfs(t *testing.T) {
	for name, path := range map[string]string{
		"system directory": "/etc",
		"traversal":        "/app/../etc",
		"relative":         "app/var",
	} {
		body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
    tmpfs: ["` + path + `"]
`
		cfg := &config.Config{Version: 2, App: "demo", Domain: "demo.example.com"}
		if _, err := secureStack(body, cfg, "8080"); err == nil {
			t.Fatalf("%s (%s) must be rejected", name, path)
		}
	}
}

// Shuttle targets a single node, where a second web replica buys no failure
// domain but costs a second health-gated cold start: update_config uses
// parallelism 1 with start-first, so replicas are converged one after another.
// On a PHP stack that sequential boot is what pushed promotion past the
// convergence deadline. start-first alone already gives zero downtime.
func TestSecureStackRunsASingleWebReplica(t *testing.T) {
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
`
	cfg := &config.Config{Version: 2, App: "demo", Domain: "demo.example.com"}
	out, err := secureStack(body, cfg, "8080")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	services, _ := doc["services"].(map[string]any)
	web, _ := services["web"].(map[string]any)
	deploy, _ := web["deploy"].(map[string]any)
	if deploy["replicas"] != 1 {
		t.Fatalf("web must run a single replica on a single node, got %v", deploy["replicas"])
	}
	update, _ := deploy["update_config"].(map[string]any)
	if update["order"] != "start-first" {
		t.Fatalf("zero downtime relies on start-first, got %v", update["order"])
	}
}
