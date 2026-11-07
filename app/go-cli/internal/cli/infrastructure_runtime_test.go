package cli

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func infrastructureStack(t *testing.T, production config.ProductionConfig) map[string]any {
	t.Helper()
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
`
	cfg := &config.Config{Version: 2, App: "demo", Domain: "demo.example.com", Production: production}
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, false); err != nil {
		t.Fatal(err)
	}
	out, err := secureStack(body, cfg, "8080")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// Every service is generated with cap_drop: ALL, so uid 0 keeps no
// CAP_DAC_OVERRIDE. Both images seed their data directory owned by their own
// account, and the root helper chowns the named volume to that account too, so
// a service left running as root cannot open its own data directory and exits
// on the first write. Redis reports it as `Can't open or create append-only dir
// appendonlydir: Permission denied` and never becomes healthy, which fails every
// deployment of an application that enables it.
func TestInfrastructureServicesRunAsTheAccountOwningTheirData(t *testing.T) {
	doc := infrastructureStack(t, config.ProductionConfig{Redis: true, RabbitMQ: true})
	services, _ := doc["services"].(map[string]any)
	for _, runtime := range infrastructureRuntimes {
		service, ok := services[runtime.service].(map[string]any)
		if !ok {
			t.Fatalf("%s must be generated", runtime.service)
		}
		if service["user"] != runtime.user() {
			t.Fatalf("%s must run as %s, got %v", runtime.service, runtime.user(), service["user"])
		}
	}
}

func TestRedisUsesTheConfiguredRetainedImage(t *testing.T) {
	legacy := "redis:7.4.5-alpine@sha256:" + strings.Repeat("b", 64)
	doc := infrastructureStack(t, config.ProductionConfig{Redis: true, RedisImage: legacy})
	service := generatedService(t, doc, "redis")
	if service["image"] != legacy {
		t.Fatalf("configured Redis pin was not rendered: got %v", service["image"])
	}
}

// A Swarm secret is owned by root unless the reference says otherwise, so a 0400
// password is unreadable by the unprivileged account the service now runs as.
// The failure is quiet: the `cat` in the command yields nothing and the server
// comes up with an empty password instead of refusing to start.
func TestInfrastructurePasswordsAreReadableByTheirService(t *testing.T) {
	doc := infrastructureStack(t, config.ProductionConfig{Redis: true, RabbitMQ: true})
	services, _ := doc["services"].(map[string]any)
	for _, runtime := range infrastructureRuntimes {
		service, _ := services[runtime.service].(map[string]any)
		secrets, _ := service["secrets"].([]any)
		if len(secrets) != 1 {
			t.Fatalf("%s must mount exactly its password, got %v", runtime.service, secrets)
		}
		reference, _ := secrets[0].(map[string]any)
		if reference["uid"] != strconv.Itoa(runtime.uid) || reference["gid"] != strconv.Itoa(runtime.gid) {
			t.Fatalf("%s password must be owned by %s, got uid=%v gid=%v", runtime.service, runtime.user(), reference["uid"], reference["gid"])
		}
	}
}

// Invariant: adding the account leaves every application service byte-identical.
// It is a property of the two services Shuttle generates itself, not of
// hardening, so a compose file that declares none must produce what it always
// produced.
func TestApplicationServicesDeclareNoUser(t *testing.T) {
	doc := infrastructureStack(t, config.ProductionConfig{})
	services, _ := doc["services"].(map[string]any)
	if len(services) != 1 {
		t.Fatalf("no infrastructure was requested, got %v", services)
	}
	web, _ := services["web"].(map[string]any)
	if _, exists := web["user"]; exists {
		t.Fatalf("an application service must keep the user its image declares, got %v", web["user"])
	}
}
