package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// primaryServiceConfig is the shape an existing application adopts: its own
// service name, kept, plus deploy.primary_service telling Shuttle which one to
// publish. "web" never appears anywhere.
func primaryServiceConfig() *config.Config {
	return &config.Config{
		App:    "demo-core",
		Domain: "api.example.com",
		Deploy: config.Deploy{PrimaryService: "api"},
		Services: map[string]config.Service{
			"api": {Port: 8000},
		},
	}
}

func TestPrimaryServiceDefaultsToWeb(t *testing.T) {
	if name := (&config.Config{}).PrimaryServiceName(); name != "web" {
		t.Fatalf("an unset deploy.primary_service must stay %q, got %q", "web", name)
	}
	if name := (*config.Config)(nil).PrimaryServiceName(); name != "web" {
		t.Fatalf("a nil config must resolve to %q, got %q", "web", name)
	}
	if name := (&config.Config{Deploy: config.Deploy{PrimaryService: "  api  "}}).PrimaryServiceName(); name != "api" {
		t.Fatalf("surrounding whitespace must be trimmed, got %q", name)
	}
}

func TestDetectWebPortFollowsPrimaryService(t *testing.T) {
	cf := parseComposeString(t, `
services:
  api:
    build: .
    expose: ["8000"]
  web:
    image: nginx:alpine
    expose: ["3000"]
`)
	// The decoy service really is called "web": if anything still keys off that
	// literal it will return 3000 and this test fails loudly.
	if port := detectWebPort(cf, primaryServiceConfig()); port != "8000" {
		t.Fatalf("expected the published service port 8000, got %q", port)
	}
}

func TestDetectWebPortFallsBackToConfiguredPrimaryPort(t *testing.T) {
	cf := parseComposeString(t, "services:\n  api:\n    build: .\n")
	if port := detectWebPort(cf, primaryServiceConfig()); port != "8000" {
		t.Fatalf("expected the configured port 8000, got %q", port)
	}
}

func TestSecureStackLabelsThePrimaryServiceOnly(t *testing.T) {
	cf := parseComposeString(t, `
services:
  api:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  worker-high:
    build: .
    healthcheck: {test: ["CMD", "true"]}
`)
	cfg := primaryServiceConfig()
	images := map[string]string{
		"api":         "registry/app@sha256:" + strings.Repeat("a", 64),
		"worker-high": "registry/app@sha256:" + strings.Repeat("a", 64),
	}
	generated, err := generateSwarmStackWithSecrets(cf, cfg, images, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "8000")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}

	api := generatedService(t, root, "api")
	apiDeploy := api["deploy"].(map[string]any)
	labels, ok := apiDeploy["labels"].(map[string]any)
	if !ok {
		t.Fatalf("the published service carries no labels: %#v", apiDeploy)
	}
	if labels["dev.shuttle.domain"] != "api.example.com" || labels["dev.shuttle.port"] != "8000" {
		t.Fatalf("unexpected routing labels: %#v", labels)
	}
	if apiDeploy["replicas"] != 1 {
		t.Fatalf("the published service must run one replica, got %#v", apiDeploy["replicas"])
	}

	worker := generatedService(t, root, "worker-high")
	workerDeploy := worker["deploy"].(map[string]any)
	if _, present := workerDeploy["labels"]; present {
		t.Fatalf("a non-published service must carry no routing labels: %#v", workerDeploy)
	}
	if _, present := workerDeploy["replicas"]; present {
		t.Fatalf("a non-published service must not have its replica count forced: %#v", workerDeploy)
	}
}

// The generated stack must carry the configured limits, and keep the shipped
// defaults for every service that does not set them.
func TestSecureStackAppliesConfiguredResourceLimits(t *testing.T) {
	cf := parseComposeString(t, `
services:
  api:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  worker-high:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  mercure:
    build: .
    healthcheck: {test: ["CMD", "true"]}
`)
	cfg := primaryServiceConfig()
	cfg.Services["api"] = config.Service{Port: 8000, Resources: config.Resources{CPUs: "1.5", Memory: "1G"}}
	cfg.Services["worker-high"] = config.Service{Resources: config.Resources{Memory: "384M"}}

	digest := "registry/app@sha256:" + strings.Repeat("a", 64)
	generated, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{
		"api": digest, "worker-high": digest, "mercure": digest,
	}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "8000")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string][2]string{
		"api":         {"1.5", "1G"},
		"worker-high": {config.DefaultServiceCPUs, "384M"},
		"mercure":     {config.DefaultServiceCPUs, config.DefaultServiceMemory},
	} {
		deploy := generatedService(t, root, name)["deploy"].(map[string]any)
		limits := deploy["resources"].(map[string]any)["limits"].(map[string]any)
		if limits["cpus"] != want[0] || limits["memory"] != want[1] {
			t.Fatalf("%s: expected cpus=%s memory=%s, got %#v", name, want[0], want[1], limits)
		}
	}
}

// An internal stack must publish nothing. The proof is that the signed payload
// carries no routing label at all: the root helper derives the Caddy fragment
// from that label, so its absence is what makes "no route" enforceable rather
// than merely intended.
func TestSecureStackPublishesNothingForAnInternalApplication(t *testing.T) {
	cf := parseComposeString(t, "services:\n  agent-next:\n    build: .\n    healthcheck: {test: [\"CMD\", \"true\"]}\n")
	cfg := &config.Config{
		App:      "demo-agent",
		Expose:   config.ExposeInternal,
		Deploy:   config.Deploy{PrimaryService: "agent-next"},
		Services: map[string]config.Service{"agent-next": {Port: 3300}},
	}
	generated, err := generateSwarmStackWithSecrets(cf, cfg,
		map[string]string{"agent-next": "registry/agent@sha256:" + strings.Repeat("a", 64)}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "3300")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(secured, "dev.shuttle.domain") || strings.Contains(secured, "dev.shuttle.port") {
		t.Fatalf("an internal stack must carry no routing label:\n%s", secured)
	}

	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}
	deploy := generatedService(t, root, "agent-next")["deploy"].(map[string]any)
	if _, present := deploy["labels"]; present {
		t.Fatalf("an internal service with no managed database needs no labels at all: %#v", deploy)
	}
	// The rest of the hardening still applies: internal is not a way out of it.
	if deploy["replicas"] != 1 {
		t.Fatalf("the published service still runs one replica, got %#v", deploy["replicas"])
	}
	if generatedService(t, root, "agent-next")["read_only"] != true {
		t.Fatal("an internal service is still read-only")
	}
}

func TestOriginProofIsSkippedForAnInternalApplication(t *testing.T) {
	cfg := &config.Config{App: "demo-agent", Expose: config.ExposeInternal}
	// 203.0.113.10 is TEST-NET-3: any real proof attempt would have to reach the
	// network and fail, so returning nil here can only mean the check was skipped.
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err != nil {
		t.Fatalf("an internal application has no origin to prove, got %v", err)
	}
}

// The operations an operator declares must reach the signed stack, because that
// is where the privileged helper reads them from. A `shuttle run` that had to
// send the command line would be a remote shell with extra steps.
func TestSecureStackCarriesDeclaredOperations(t *testing.T) {
	cf := parseComposeString(t, "services:\n  api:\n    build: .\n    healthcheck: {test: [\"CMD\", \"true\"]}\n")
	cfg := primaryServiceConfig()
	cfg.Operations = map[string]config.Operation{
		"reindex": {Service: "api", Command: []string{"php", "bin/console", "app:search:reindex-listings"}},
	}
	generated, err := generateSwarmStackWithSecrets(cf, cfg,
		map[string]string{"api": "registry/app@sha256:" + strings.Repeat("a", 64)}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "8000")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}
	labels := generatedService(t, root, "api")["deploy"].(map[string]any)["labels"].(map[string]any)
	encoded, ok := labels["dev.shuttle.operations"].(string)
	if !ok {
		t.Fatalf("the published service must carry the operations label: %#v", labels)
	}
	var declared map[string]config.Operation
	if err := json.Unmarshal([]byte(encoded), &declared); err != nil {
		t.Fatalf("the label must be readable JSON: %v", err)
	}
	if declared["reindex"].Service != "api" || len(declared["reindex"].Command) != 3 {
		t.Fatalf("unexpected declared operation: %#v", declared)
	}
}

// An internal application has no route, so it takes the other branch of the
// label code. It still needs migrations.
func TestInternalStackAlsoCarriesDeclaredOperations(t *testing.T) {
	cf := parseComposeString(t, "services:\n  agent-next:\n    build: .\n    healthcheck: {test: [\"CMD\", \"true\"]}\n")
	cfg := &config.Config{
		App:      "demo-agent",
		Expose:   config.ExposeInternal,
		Deploy:   config.Deploy{PrimaryService: "agent-next"},
		Services: map[string]config.Service{"agent-next": {Port: 3300}},
		Operations: map[string]config.Operation{
			"warm": {Service: "agent-next", Command: []string{"python", "-m", "app.warm"}},
		},
	}
	generated, err := generateSwarmStackWithSecrets(cf, cfg,
		map[string]string{"agent-next": "registry/agent@sha256:" + strings.Repeat("a", 64)}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "3300")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(secured, "dev.shuttle.operations") {
		t.Fatalf("an internal stack must still declare its operations:\n%s", secured)
	}
	if strings.Contains(secured, "dev.shuttle.domain") {
		t.Fatal("declaring operations must not give an internal stack a public route")
	}
}
