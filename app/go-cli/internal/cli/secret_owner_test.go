package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func secretReference(t *testing.T, item config.SecretItem) map[string]any {
	t.Helper()
	body := `services:
  api:
    image: demo
    healthcheck: {test: ["CMD", "true"]}
`
	var parsed composeFile
	if err := yaml.Unmarshal([]byte(body), &parsed.Raw); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com",
		Deploy:  config.Deploy{PrimaryService: "api"},
		Secrets: config.Secrets{Items: map[string]config.SecretItem{"APP_KEY": item}},
	}
	images := map[string]string{"api": "demo@sha256:" + strings.Repeat("a", 64)}
	manifest := secretManifest{Version: applicationSecretPayloadVersion, Secrets: map[string]secretManifestEntry{
		"APP_KEY": {Name: "demo_app_key_v1", Version: "v1"},
	}}
	out, err := generateSwarmStackWithSecrets(&parsed, cfg, images, manifest)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	services, _ := doc["services"].(map[string]any)
	api, _ := services["api"].(map[string]any)
	list, _ := api["secrets"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected exactly one secret reference, got %v", list)
	}
	reference, _ := list[0].(map[string]any)
	return reference
}

// A Swarm secret belongs to root. An image that drops privileges therefore
// cannot read it at a restrictive mode, and the usual workaround, copying it in a
// root entrypoint and chowning it, cannot work either, because Shuttle drops
// CAP_CHOWN from every service. Declaring the account is what makes the file
// arrive readable by the service and by nobody else.
func TestDeclaredSecretOwnerReachesTheStack(t *testing.T) {
	uid := 10001
	reference := secretReference(t, config.SecretItem{Services: []string{"api"}, UID: &uid})
	if reference["uid"] != "10001" || reference["gid"] != "10001" {
		t.Fatalf("the declared account must own the mounted file, got uid=%v gid=%v", reference["uid"], reference["gid"])
	}
	if reference["mode"] != 0o400 {
		t.Fatalf("an owned secret must be readable only by its owner, got mode %v", reference["mode"])
	}
}

func TestDeclaredSecretGroupOverridesTheDefault(t *testing.T) {
	uid, gid := 10001, 2000
	reference := secretReference(t, config.SecretItem{Services: []string{"api"}, UID: &uid, GID: &gid})
	if reference["gid"] != "2000" {
		t.Fatalf("a declared gid must win over the uid, got %v", reference["gid"])
	}
}

// Invariant: a configuration that declares no account produces the reference it
// always produced. The historical mode is world-readable inside the container
// precisely because the file is root-owned, so tightening it without an owner
// would lock out the service.
func TestSecretWithoutOwnerIsUnchanged(t *testing.T) {
	reference := secretReference(t, config.SecretItem{Services: []string{"api"}})
	if reference["mode"] != 0o444 {
		t.Fatalf("an unowned secret must keep mode 0444, got %v", reference["mode"])
	}
	for _, key := range []string{"uid", "gid"} {
		if _, exists := reference[key]; exists {
			t.Fatalf("an unowned secret must declare no %s, got %v", key, reference[key])
		}
	}
}

// The passphrase had exactly one source, an environment variable, so every
// non-interactive deploy invented its own storage for it and none was
// documented. A file Shuttle can name in its error message is the point.
func TestPassphraseComesFromTheApplicationFile(t *testing.T) {
	home := t.TempDir()
	// os.UserConfigDir reads HOME on macOS and XDG_CONFIG_HOME on Linux.
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("SHUTTLE_SECRETS_PASSPHRASE", "")
	t.Setenv("SHUTTLE_SECRETS_PASSPHRASE_FILE", "")
	dir := filepath.Join(home, "shuttle")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Written with the trailing newline a shell leaves behind, so the value
	// must match what `$(cat file)` yields today.
	if err := os.WriteFile(filepath.Join(dir, "demo.passphrase"), []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := openSecretStore(".shuttle/secrets.enc", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if store.Passphrase != "correct horse" {
		t.Fatalf("expected the file's passphrase without its trailing newline, got %q", store.Passphrase)
	}
}

// A passphrase anyone on the machine can read is not a passphrase. Refused
// rather than used, so the failure happens before it protects anything.
func TestPassphraseFileRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo.passphrase")
	if err := writeTestFile(path, []byte("correct horse\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassphraseFile(path); err == nil {
		t.Fatal("a group- or world-readable passphrase file must be refused")
	}
}

// Named explicitly, so a missing file is an error rather than a fall-through to
// a prompt that would hang a Makefile target or a CI job.
func TestNamedPassphraseFileMustExist(t *testing.T) {
	t.Setenv("SHUTTLE_SECRETS_PASSPHRASE", "")
	t.Setenv("SHUTTLE_SECRETS_PASSPHRASE_FILE", filepath.Join(t.TempDir(), "absent"))
	if _, err := openSecretStore(".shuttle/secrets.enc", "demo"); err == nil {
		t.Fatal("a named passphrase file that does not exist must fail")
	}
}

// managedStack generates a stack for an application whose services declare the
// credentials of the backing services Shuttle provisions.
func managedStack(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, false); err != nil {
		t.Fatal(err)
	}
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
  api:
    image: demo@sha256:` + strings.Repeat("b", 64) + `
    healthcheck: {test: ["CMD", "true"]}
`
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

func serviceSecretTargets(doc map[string]any, service string) []string {
	services, _ := doc["services"].(map[string]any)
	entry, _ := services[service].(map[string]any)
	list, _ := entry["secrets"].([]any)
	targets := []string{}
	for _, raw := range list {
		if reference, ok := raw.(map[string]any); ok {
			targets = append(targets, fmt.Sprint(reference["target"]))
		}
	}
	return targets
}

// Shuttle runs a password-protected Redis and mounted the password on the Redis
// container and nowhere else, so no application service could open a connection
// to the service Shuttle provisioned for it.
func TestManagedRedisPasswordReachesTheDeclaredService(t *testing.T) {
	uid := 10001
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com",
		Deploy:     config.Deploy{PrimaryService: "web"},
		Production: config.ProductionConfig{Redis: true},
		Secrets: config.Secrets{Items: map[string]config.SecretItem{
			"REDIS_PASSWORD": {Services: []string{"api"}, UID: &uid},
		}},
	}
	doc := managedStack(t, cfg)
	if targets := serviceSecretTargets(doc, "api"); len(targets) != 1 || targets[0] != "REDIS_PASSWORD" {
		t.Fatalf("api must mount the managed Redis password, got %v", targets)
	}
	if targets := serviceSecretTargets(doc, "web"); len(targets) != 0 {
		t.Fatalf("a service that did not ask for it must not receive it, got %v", targets)
	}
	services, _ := doc["services"].(map[string]any)
	api, _ := services["api"].(map[string]any)
	list, _ := api["secrets"].([]any)
	reference, _ := list[0].(map[string]any)
	if reference["uid"] != "10001" || reference["mode"] != 0o400 {
		t.Fatalf("the credential must be readable by the declared account alone, got %v", reference)
	}
}

// The database password did travel, but only to the published service. On a
// stack whose web tier talks to an API, that is the service that never opens
// a connection.
func TestManagedDatabasePasswordFollowsTheDeclaration(t *testing.T) {
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com",
		Deploy:   config.Deploy{PrimaryService: "web"},
		Database: config.DatabaseConfig{Version: 16},
		Secrets: config.Secrets{Items: map[string]config.SecretItem{
			"POSTGRES_PASSWORD": {Services: []string{"api"}},
		}},
	}
	doc := managedStack(t, cfg)
	if targets := serviceSecretTargets(doc, "api"); len(targets) != 1 || targets[0] != "POSTGRES_PASSWORD" {
		t.Fatalf("api must mount the managed database password, got %v", targets)
	}
	if targets := serviceSecretTargets(doc, "web"); len(targets) != 0 {
		t.Fatalf("naming the services replaces the published-service default, got %v", targets)
	}
}

// Invariant: a configuration that declares nothing keeps the mount it had, on
// the published service.
func TestManagedDatabasePasswordDefaultIsUnchanged(t *testing.T) {
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com",
		Deploy:   config.Deploy{PrimaryService: "web"},
		Database: config.DatabaseConfig{Version: 16},
	}
	doc := managedStack(t, cfg)
	if targets := serviceSecretTargets(doc, "web"); len(targets) != 1 || targets[0] != "POSTGRES_PASSWORD" {
		t.Fatalf("the published service must keep its historical mount, got %v", targets)
	}
	if targets := serviceSecretTargets(doc, "api"); len(targets) != 0 {
		t.Fatalf("no other service may gain a mount, got %v", targets)
	}
}

// A second application in the same stack runs on its own database role. Its
// password went to the published service alone, so the services that use that
// role had the address of a database they had no password for.
func TestPerRoleDatabasePasswordFollowsTheDeclaration(t *testing.T) {
	uid := 10001
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com",
		Deploy: config.Deploy{PrimaryService: "web"},
		Database: config.DatabaseConfig{
			Version:   16,
			Roles:     []config.DatabaseRole{{Name: "demo"}, {Name: "demo_agents"}},
			Databases: []config.DatabaseDatabase{{Name: "demo", Owner: "demo"}, {Name: "demo_agents", Owner: "demo_agents"}},
		},
		Secrets: config.Secrets{Items: map[string]config.SecretItem{
			"POSTGRES_PASSWORD_DEMO_AGENTS": {Services: []string{"api"}, UID: &uid},
		}},
	}
	doc := managedStack(t, cfg)
	targets := serviceSecretTargets(doc, "api")
	if len(targets) != 1 || targets[0] != "POSTGRES_PASSWORD_DEMO_AGENTS" {
		t.Fatalf("api must mount the role password it declared, got %v", targets)
	}
	// The published service keeps POSTGRES_PASSWORD, which nothing named, and
	// loses only the role password the operator routed elsewhere.
	web := serviceSecretTargets(doc, "web")
	if len(web) != 1 || web[0] != "POSTGRES_PASSWORD" {
		t.Fatalf("the published service must keep only what nothing else claimed, got %v", web)
	}
}

// The edge reaches an application by Swarm DNS name, which only works from a
// network they share. Attachment depended on the legacy caddy.routes list, so
// an application that published a domain and declared path routes joined
// nothing: the helper wrote the route, Caddy loaded it, and every request came
// back a bad gateway against a name the edge could not resolve.
func TestPublishedAndRoutedServicesJoinTheEdgeNetwork(t *testing.T) {
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com",
		Deploy: config.Deploy{PrimaryService: "web"},
		Caddy: config.Caddy{
			Network:    "caddy_network",
			PathRoutes: []config.CaddyPathRoute{{Path: "/api/*", Service: "api", Port: 8000}},
		},
	}
	doc := generatedStack(t, cfg)
	services, _ := doc["services"].(map[string]any)
	for _, name := range []string{"web", "api"} {
		service, _ := services[name].(map[string]any)
		networks := fmt.Sprint(service["networks"])
		if !strings.Contains(networks, "caddy_network") {
			t.Fatalf("%s must reach the shared edge, got networks=%v", name, service["networks"])
		}
		// Naming a network drops Compose's implicit default, which would cut the
		// service off from its own siblings.
		if !strings.Contains(networks, "default") {
			t.Fatalf("%s must keep the stack's default network, got %v", name, service["networks"])
		}
	}
	networks, _ := doc["networks"].(map[string]any)
	entry, _ := networks["caddy_network"].(map[string]any)
	if entry["external"] != true {
		t.Fatalf("the edge network is created by setup, so the stack must adopt it: %v", networks)
	}
}

// An internal application publishes nothing, so it joins nothing: the edge is
// never told to proxy it.
func TestInternalApplicationStaysOffTheEdgeNetwork(t *testing.T) {
	cfg := &config.Config{
		Version: 2, App: "demo", Domain: "demo.example.com", Expose: config.ExposeInternal,
		Deploy: config.Deploy{PrimaryService: "web"},
		Caddy:  config.Caddy{Network: "caddy_network"},
	}
	doc := generatedStack(t, cfg)
	services, _ := doc["services"].(map[string]any)
	web, _ := services["web"].(map[string]any)
	if _, exists := web["networks"]; exists {
		t.Fatalf("an internal application must not join the edge network, got %v", web["networks"])
	}
}

// generatedStack runs the compose-to-stack conversion, which is where network
// attachment happens: secureStack only hardens what that produced.
func generatedStack(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	body := `services:
  web:
    image: demo
    healthcheck: {test: ["CMD", "true"]}
  api:
    image: demo
    healthcheck: {test: ["CMD", "true"]}
`
	var parsed composeFile
	if err := yaml.Unmarshal([]byte(body), &parsed.Raw); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	images := map[string]string{
		"web": "demo@sha256:" + strings.Repeat("a", 64),
		"api": "demo@sha256:" + strings.Repeat("b", 64),
	}
	out, err := generateSwarmStackWithSecrets(&parsed, cfg, images, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
