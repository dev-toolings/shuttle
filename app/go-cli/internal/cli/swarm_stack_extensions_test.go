package cli

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// A compose file keeps its shared build block under an x-* key and references
// it by anchor. The anchor is resolved into the service, whose build block the
// stack removes; the x-* key kept the unexpanded ${VAR:-default} verbatim, and
// the root helper refused the whole signed payload for it.
func TestGeneratedStackDropsExtensionKeys(t *testing.T) {
	cf := parseComposeString(t, `
x-api-build: &api-build
  context: .
  args:
    VITE_REVERB_HOST: ${VITE_REVERB_HOST:-bo.domebao.com}
services:
  web:
    build: *api-build
    healthcheck: {test: ["CMD", "true"]}
`)
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com",
		Deploy:   config.Deploy{PrimaryService: "web"},
		Services: map[string]config.Service{"web": {Port: 3000}},
	}
	images := map[string]string{"web": "registry.invalid/demo@sha256:" + strings.Repeat("a", 64)}
	generated, err := generateSwarmStackWithSecrets(cf, cfg, images, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "3000")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(secured, "${") {
		t.Fatalf("the generated stack must not carry an unresolved variable:\n%s", secured)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}
	for key := range root {
		if strings.HasPrefix(key, "x-") {
			t.Fatalf("the generated stack must not carry the extension key %q:\n%s", key, secured)
		}
	}
	if _, present := generatedService(t, root, "web")["build"]; present {
		t.Fatalf("the service's own build block must be gone:\n%s", secured)
	}
	if err := validateRootStack([]byte(secured)); err != nil {
		t.Fatalf("the root helper must accept a stack whose extension keys were dropped: %v\n%s", err, secured)
	}
}
