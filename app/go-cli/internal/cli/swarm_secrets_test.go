package cli

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func TestGenerateSwarmStackScopesVersionedSecretsByService(t *testing.T) {
	cf := parseComposeString(t, `
services:
  web:
    build: .
    secrets: [preexisting]
    environment:
      SHUTTLE_ENV_SECRETS: DB_PASSWORD
  queue:
    build: .
  public:
    image: nginx:alpine
  file-only:
    image: nginx:alpine
    environment:
      - SHUTTLE_ENV_SECRETS
secrets:
  preexisting: {external: true}
`)
	cfg := &config.Config{
		App: "demo",
		Secrets: config.Secrets{Backend: "swarm", Items: map[string]config.SecretItem{
			"APP_KEY":     {Services: []string{"web", "queue"}, Expose: "env"},
			"DB_PASSWORD": {Services: []string{"web", "file-only"}, Expose: "file"},
			"SIGNING_KEY": {Services: []string{"web"}, Expose: "env"},
		}},
	}
	manifest := secretManifest{Version: 1, Secrets: map[string]secretManifestEntry{
		"APP_KEY":     {Name: "demo_app_key_a1", Version: "a1"},
		"DB_PASSWORD": {Name: "demo_db_password_b2", Version: "b2"},
		"SIGNING_KEY": {Name: "demo_signing_key_c3", Version: "c3"},
	}}

	out, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{"web": "registry/web:sha"}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(out), &root); err != nil {
		t.Fatal(err)
	}
	services := root["services"].(map[string]any)
	web := services["web"].(map[string]any)
	queue := services["queue"].(map[string]any)
	public := services["public"].(map[string]any)
	fileOnly := services["file-only"].(map[string]any)
	webYAML, _ := yaml.Marshal(web)
	queueYAML, _ := yaml.Marshal(queue)
	publicYAML, _ := yaml.Marshal(public)
	fileOnlyYAML, _ := yaml.Marshal(fileOnly)
	if !strings.Contains(string(webYAML), "demo_app_key_a1") || !strings.Contains(string(webYAML), "demo_db_password_b2") || !strings.Contains(string(webYAML), "preexisting") {
		t.Fatalf("web secret scope is incomplete:\n%s", webYAML)
	}
	if !strings.Contains(string(queueYAML), "demo_app_key_a1") || strings.Contains(string(queueYAML), "demo_db_password_b2") {
		t.Fatalf("queue received wrong secrets:\n%s", queueYAML)
	}
	if strings.Contains(string(publicYAML), "demo_") {
		t.Fatalf("unlisted service received managed secrets:\n%s", publicYAML)
	}
	if strings.Contains(string(fileOnlyYAML), "SHUTTLE_ENV_SECRETS") {
		t.Fatalf("bare source allowlist exposed a file-only secret:\n%s", fileOnlyYAML)
	}
	if !strings.Contains(string(webYAML), "SHUTTLE_ENV_SECRETS") || !strings.Contains(string(webYAML), "APP_KEY,SIGNING_KEY") || !strings.Contains(string(queueYAML), "APP_KEY") {
		t.Fatalf("env exposure allowlist missing: web=%s queue=%s", webYAML, queueYAML)
	}
	if strings.Contains(string(webYAML), "DB_PASSWORD,APP_KEY") || strings.Contains(string(webYAML), "APP_KEY,SIGNING_KEY,DB_PASSWORD") {
		t.Fatalf("source compose expanded canonical env allowlist:\n%s", webYAML)
	}
}

func TestValidateConfiguredSecretServicesRejectsLegacySecretsFileBeforeDeploy(t *testing.T) {
	for _, ref := range []string{".env.secrets", "./.env.secrets", "secrets/.env.secrets"} {
		cf := parseComposeString(t, "services:\n  web:\n    image: demo\n    env_file: ["+ref+"]\n")
		found := false
		for _, candidate := range collectComposeEnvFiles(cf) {
			found = found || isLegacySecretsEnvFile(candidate)
		}
		if !found {
			t.Fatalf("legacy plaintext secrets file %q was not detected during preflight", ref)
		}
	}
}

func TestGenerateSwarmStackRejectsMissingManifestAndUnknownServices(t *testing.T) {
	cf := parseComposeString(t, "services:\n  web: {image: demo}\n")
	tests := []struct {
		name     string
		items    map[string]config.SecretItem
		manifest secretManifest
		want     string
	}{
		{name: "missing manifest", items: map[string]config.SecretItem{"APP_KEY": {Services: []string{"web"}, Expose: "file"}}, manifest: secretManifest{}, want: "not been pushed"},
		{name: "unknown service", items: map[string]config.SecretItem{"APP_KEY": {Services: []string{"worker"}, Expose: "file"}}, manifest: secretManifest{Secrets: map[string]secretManifestEntry{"APP_KEY": {Name: "demo_app_key_a1"}}}, want: "unknown service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{App: "demo", Secrets: config.Secrets{Backend: "swarm", Items: tt.items}}
			if _, err := generateSwarmStackWithSecrets(cf, cfg, nil, tt.manifest); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}

// docker stack deploy rejects the Compose Spec top-level "name" property, and
// Docker 29.7 turned that into a hard error: "(root) Additional property name
// is not allowed". A single compose file has to stay usable by both docker
// compose and docker stack deploy, so the generator drops the key.
func TestGenerateSwarmStackDropsTopLevelName(t *testing.T) {
	cf := parseComposeString(t, `
name: demo-audit-tracker
services:
  web:
    image: nginx:alpine
`)
	cfg := &config.Config{App: "demo-audit-tracker"}

	out, err := generateSwarmStackWithSecrets(cf, cfg, nil, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(out), &root); err != nil {
		t.Fatal(err)
	}
	if _, present := root["name"]; present {
		t.Fatalf("the generated stack must not carry a top-level name:\n%s", out)
	}
	if _, present := root["services"].(map[string]any)["web"]; !present {
		t.Fatalf("dropping name must not disturb the services:\n%s", out)
	}
}

// A service reachable through a generated Caddy route has to sit on the proxy
// network. Without it the edge resolves the service name to nothing and answers
// 502, and docker stack deploy drops any attachment added by hand.
func TestGenerateSwarmStackAttachesCaddyNetworkToRoutedServices(t *testing.T) {
	cf := parseComposeString(t, `
services:
  web:
    image: nginx:alpine
  api:
    image: nginx:alpine
`)
	cfg := &config.Config{App: "demo"}
	cfg.Caddy.Network = "edge"
	cfg.Caddy.Routes = map[string]string{"demo.example.com": "web:8080"}

	out, err := generateSwarmStackWithSecrets(cf, cfg, nil, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(out), &root); err != nil {
		t.Fatal(err)
	}
	networks, _ := root["networks"].(map[string]any)
	edge, _ := networks["edge"].(map[string]any)
	if edge == nil || edge["external"] != true {
		t.Fatalf("edge must be declared external:\n%s", out)
	}
	services := root["services"].(map[string]any)
	web := services["web"].(map[string]any)
	webNetworks, _ := web["networks"].([]any)
	if len(webNetworks) != 2 || webNetworks[0] != "edge" || webNetworks[1] != "default" {
		t.Fatalf("the routed service must join edge and keep default, got %#v:\n%s", web["networks"], out)
	}
	api := services["api"].(map[string]any)
	if _, present := api["networks"]; present {
		t.Fatalf("a service with no route must stay off the proxy network:\n%s", out)
	}
}

func TestAppendComposeNetworkKeepsExistingEntries(t *testing.T) {
	list, _ := appendComposeNetwork([]any{"internal"}, "edge", "default").([]any)
	if len(list) != 3 || list[0] != "internal" || list[1] != "edge" || list[2] != "default" {
		t.Fatalf("existing networks must be preserved, got %#v", list)
	}
	if again, _ := appendComposeNetwork([]any{"edge"}, "edge", "default").([]any); len(again) != 2 {
		t.Fatalf("an already attached network must not be duplicated, got %#v", again)
	}
	long, _ := appendComposeNetwork(map[string]any{"edge": map[string]any{"aliases": []any{"web"}}}, "edge", "default").(map[string]any)
	if long["edge"] == nil {
		t.Fatalf("the long form must keep its aliases, got %#v", long)
	}
	if _, present := long["default"]; !present {
		t.Fatalf("the long form must gain the default network, got %#v", long)
	}
}
