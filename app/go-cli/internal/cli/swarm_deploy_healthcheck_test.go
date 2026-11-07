package cli

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// Swarm receives the compose healthcheck unchanged. Shuttle must not inject a
// language-specific fallback into the raw stack document.
func TestSwarmDoesNotInjectHealthchecks(t *testing.T) {
	cf := &composeFile{Services: map[string]composeService{
		"searxng": {Image: "searxng/searxng", Expose: []string{"8080"}, Build: map[string]any{"context": "."}},
		"web":     {Expose: []string{"8080"}, Build: map[string]any{"context": "."}},
	}}
	cfg := &config.Config{App: "demo", Caddy: config.Caddy{Network: "edge"}}

	out, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{"searxng": "127.0.0.1:5000/demo-searxng@sha256:" + strings.Repeat("a", 64), "web": "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out, "php") {
		t.Error("default healthcheck must not assume PHP")
	}
	var stack swarmStackFile
	if err := yaml.Unmarshal([]byte(out), &stack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if hc := stack.Services["searxng"].Healthcheck; hc != nil {
		t.Errorf("non-web build service must get no default healthcheck, got %v", hc)
	}
	if stack.Services["web"].Healthcheck != nil {
		t.Error("web service must not receive a generated healthcheck")
	}
}

// A compose healthcheck is the source of truth for raw Swarm generation.
func TestSwarmPreservesComposeHealthcheck(t *testing.T) {
	cf := &composeFile{Services: map[string]composeService{
		"searxng": {Image: "searxng/searxng", Expose: []string{"8080"}, Build: map[string]any{"context": "."}, Healthcheck: map[string]any{"test": []any{"CMD", "true"}}},
	}}
	cfg := &config.Config{
		App:      "demo",
		Caddy:    config.Caddy{Network: "edge"},
		Services: map[string]config.Service{},
	}

	out, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{"searxng": "127.0.0.1:5000/demo-searxng@sha256:" + strings.Repeat("a", 64)}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "true") {
		t.Errorf("compose healthcheck must be preserved, got:\n%s", out)
	}
}

func TestSwarmStackPreservesRawComposeAndOnlyRewritesBuiltImage(t *testing.T) {
	cf := parseComposeString(t, `
services:
  web:
    build: .
    image: local/web
    entrypoint: ["/entrypoint.sh"]
    secrets: [app_secret]
    networks: [private]
    volumes: [app_data:/data]
    deploy:
      replicas: 3
      update_config: {order: start-first}
    healthcheck: {test: ["CMD", "true"]}
  redis:
    image: redis:7
    networks: [private]
secrets:
  app_secret: {external: true}
networks:
  private: {external: true}
volumes:
  app_data: {}
`)
	out, err := generateSwarmStackWithSecrets(cf, &config.Config{App: "demo"}, map[string]string{"web": "127.0.0.1:51234/demo-runtime:abc123"}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	web := generatedService(t, doc, "web")
	if _, ok := web["build"]; ok {
		t.Fatal("build must be removed from the remote stack")
	}
	if web["image"] != "127.0.0.1:51234/demo-runtime:abc123" {
		t.Fatalf("unexpected rewritten image: %v", web["image"])
	}
	for _, field := range []string{"entrypoint", "secrets", "networks", "volumes", "deploy", "healthcheck"} {
		if web[field] == nil {
			t.Errorf("raw compose field %q was lost", field)
		}
	}
	if generatedService(t, doc, "redis")["image"] != "redis:7" {
		t.Fatal("non-built service image changed")
	}
}
