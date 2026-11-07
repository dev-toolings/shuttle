package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/secrets"
	"gopkg.in/yaml.v3"
)

// The real case: an Ed25519 keypair in PEM, which is multi-line and must arrive
// byte for byte.
const signingKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHqvQnQ6ChW3M0RtcQhBTAnQPQKjQwXWFVQhDLPmVWXt
-----END PRIVATE KEY-----
`

func applicationSecretStoreWith(t *testing.T, values map[string]string) secrets.Store {
	t.Helper()
	store := secrets.Store{Path: filepath.Join(t.TempDir(), "secrets.enc"), Passphrase: "test-passphrase"}
	for key, value := range values {
		if err := store.Set(key, value); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func applicationSecretConfig(items map[string]config.SecretItem) *config.Config {
	cfg := &config.Config{App: "demo"}
	cfg.Domain = "demo.example.com"
	cfg.Secrets.Backend = "swarm"
	cfg.Secrets.Items = items
	return cfg
}

func applicationSecretStack(t *testing.T, cfg *config.Config, manifest secretManifest) (string, map[string]any) {
	t.Helper()
	cf := parseComposeString(t, `
services:
  web:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  worker:
    build: .
    healthcheck: {test: ["CMD", "true"]}
`)
	digest := "registry/app@sha256:" + strings.Repeat("a", 64)
	stackConfig := *cfg
	stackConfig.Secrets.Items = applicationSecretItems(cfg)
	generated, err := generateSwarmStackWithSecrets(cf, &stackConfig, map[string]string{"web": digest, "worker": digest}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	assertRootGlobalSectionsAccept(t, generated)
	secured, err := secureStack(generated, cfg, "8000")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}
	return secured, root
}

// An application secret is mounted as a file under /run/secrets, on the services
// that declared it and on no other, without being exported to the environment.
func TestApplicationSecretIsMountedAsAFileByDefault(t *testing.T) {
	cfg := applicationSecretConfig(map[string]config.SecretItem{
		"SIGNING_KEY": {Services: []string{"web"}},
	})
	store := applicationSecretStoreWith(t, map[string]string{"SIGNING_KEY": signingKeyPEM})
	manifest, payload, err := resolveApplicationSecrets(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("the material must travel to the host")
	}
	name := manifest.Secrets["SIGNING_KEY"].Name
	if !strings.HasPrefix(name, "demo_signing_key_v") {
		t.Fatalf("the Swarm secret name must be derived and versioned, got %q", name)
	}

	_, root := applicationSecretStack(t, cfg, manifest)
	web := generatedService(t, root, "web")
	references, _ := web["secrets"].([]any)
	if len(references) != 1 {
		t.Fatalf("the declaring service must mount exactly one secret: %#v", references)
	}
	reference := references[0].(map[string]any)
	if reference["source"] != name || reference["target"] != "SIGNING_KEY" {
		t.Fatalf("unexpected mount: %#v", reference)
	}
	environment, _ := web["environment"].(map[string]any)
	if _, present := environment["SHUTTLE_ENV_SECRETS"]; present {
		t.Fatalf("expose defaults to file, so nothing is exported: %#v", environment)
	}
	worker := generatedService(t, root, "worker")
	if _, present := worker["secrets"]; present {
		t.Fatalf("a service that did not declare the secret must not receive it: %#v", worker)
	}
	topLevel, _ := root["secrets"].(map[string]any)
	if external, _ := topLevel[name].(map[string]any); external["external"] != true {
		t.Fatalf("the secret must be declared external: %#v", topLevel)
	}
}

// The proof asked for: the value appears in no artifact, no plan, and no error
// message. The signed payload is its one intended carrier, and even there it is
// base64, never the literal text.
func TestApplicationSecretValueLeaksIntoNothing(t *testing.T) {
	cfg := applicationSecretConfig(map[string]config.SecretItem{
		"SIGNING_KEY": {Services: []string{"web"}, Expose: "file"},
	})
	store := applicationSecretStoreWith(t, map[string]string{"SIGNING_KEY": signingKeyPEM})
	manifest, payload, err := resolveApplicationSecrets(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "SHA256:" + strings.Repeat("a", 43)
	plan, err := rootplan.NewSecretsAction(cfg.App, rootplan.PayloadDigest(payload), fingerprint, fingerprint, time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = rootplan.Sign(plan, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := rootplan.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	stack, _ := applicationSecretStack(t, cfg, manifest)
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// A failure the operator will actually hit: the store is missing an entry.
	_, _, missingErr := resolveApplicationSecrets(applicationSecretConfig(map[string]config.SecretItem{
		"SIGNING_KEY": {Services: []string{"web"}},
		"OTHER_KEY":   {Services: []string{"web"}},
	}), store)
	if missingErr == nil {
		t.Fatal("a declared secret that is not stored must stop the deploy")
	}

	secret := strings.TrimSpace(strings.Split(signingKeyPEM, "\n")[1])
	for name, artifact := range map[string]string{
		"stack":         stack,
		"plan":          string(planJSON),
		"manifest":      string(manifestJSON),
		"error message": missingErr.Error(),
	} {
		if strings.Contains(artifact, secret) || strings.Contains(artifact, signingKeyPEM) {
			t.Fatalf("the secret value appears in the %s:\n%s", name, artifact)
		}
	}
	if strings.Contains(string(payload), secret) {
		t.Fatalf("even its own carrier must not hold the literal value:\n%s", payload)
	}
	// And it does travel: the helper gets back exactly what was stored.
	resolved, err := parseApplicationSecretPayload(cfg.App, payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved[manifest.Secrets["SIGNING_KEY"].Name]) != signingKeyPEM {
		t.Fatalf("the PEM key must arrive byte for byte, got %q", resolved[manifest.Secrets["SIGNING_KEY"].Name])
	}
}

// §4: a configuration that declares no application secret produces exactly the
// stack it produced before application secrets existed.
func TestApplicationSecretDefaultsAreUnchanged(t *testing.T) {
	cfg := applicationSecretConfig(nil)
	manifest, payload, err := resolveDeployApplicationSecrets(cfg)
	if err != nil || payload != nil || len(manifest.Secrets) != 0 {
		t.Fatalf("nothing declared, nothing resolved: %#v, %#v, %v", manifest, payload, err)
	}
	if items := applicationSecretItems(cfg); items != nil {
		t.Fatalf("nothing declared, nothing carried: %#v", items)
	}
	withSecrets, root := applicationSecretStack(t, cfg, manifest)
	if _, present := root["secrets"]; present {
		t.Fatalf("no secrets section belongs in the stack:\n%s", withSecrets)
	}
	if _, present := generatedService(t, root, "web")["secrets"]; present {
		t.Fatalf("no service mounts a secret:\n%s", withSecrets)
	}

	// Infrastructure credentials keep their own path: declared in the items, they
	// are still generated on the host and never read from the local store.
	infra := applicationSecretConfig(map[string]config.SecretItem{"REDIS_PASSWORD": {Services: []string{"redis"}, Expose: "file"}})
	manifest, payload, err = resolveDeployApplicationSecrets(infra)
	if err != nil || payload != nil || len(manifest.Secrets) != 0 {
		t.Fatalf("an infrastructure secret must not be carried from the store: %#v, %#v, %v", manifest, payload, err)
	}
}

// Cleaning the internal allowlist used to assign a nil interface back to every
// service, which YAML encoded as `environment: null`. Compose accepts an absent
// environment, while `docker stack deploy` rejects null before promotion.
func TestApplicationSecretsDoNotCreateNullEnvironment(t *testing.T) {
	cfg := applicationSecretConfig(map[string]config.SecretItem{
		"SIGNING_KEY": {Services: []string{"web"}},
	})
	manifest := secretManifest{Secrets: map[string]secretManifestEntry{
		"SIGNING_KEY": {Name: "demo_signing_key_v1"},
	}}
	cf := parseComposeString(t, `
services:
  web:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  worker:
    build: .
    healthcheck: {test: ["CMD", "true"]}
`)
	digest := "registry/app@sha256:" + strings.Repeat("a", 64)
	generated, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{"web": digest, "worker": digest}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(generated), &root); err != nil {
		t.Fatal(err)
	}
	worker := generatedService(t, root, "worker")
	if environment, present := worker["environment"]; present {
		t.Fatalf("a service without environment must not acquire a null value: %#v\n%s", environment, generated)
	}
}

func TestResolveApplicationSecretsRefusesUnusableMaterial(t *testing.T) {
	store := applicationSecretStoreWith(t, map[string]string{
		"SIGNING_KEY": signingKeyPEM,
		"EMPTY_KEY":   "",
	})
	cases := []struct {
		name  string
		items map[string]config.SecretItem
		want  string
	}{
		{"missing from the store", map[string]config.SecretItem{"ABSENT_KEY": {Services: []string{"web"}}}, "is not in the local secret store"},
		{"empty value", map[string]config.SecretItem{"EMPTY_KEY": {Services: []string{"web"}}}, "is empty in the local secret store"},
		{"multi-line in the environment", map[string]config.SecretItem{"SIGNING_KEY": {Services: []string{"web"}, Expose: "env"}}, "multi-line and cannot be exposed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := resolveApplicationSecrets(applicationSecretConfig(tc.items), store)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

// The helper re-validates the material it is handed, whatever the client claims.
func TestParseApplicationSecretPayloadRefusesForeignAndReservedNames(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"another application", `{"version":1,"app":"demo","secrets":{"other_signing_key_v1":"YQ=="}}`, "is not derived from demo"},
		{"infrastructure name", `{"version":1,"app":"demo","secrets":{"demo_postgres_password_v1":"YQ=="}}`, "infrastructure credential name"},
		{"wrong application", `{"version":1,"app":"other","secrets":{"demo_a_v1":"YQ=="}}`, "names another application"},
		{"not base64", `{"version":1,"app":"demo","secrets":{"demo_a_v1":"not base64"}}`, "not valid base64"},
		{"empty value", `{"version":1,"app":"demo","secrets":{"demo_a_v1":""}}`, "empty or oversized"},
		{"no secrets", `{"version":1,"app":"demo","secrets":{}}`, "between 1 and 32 secrets"},
		{"unknown field", `{"version":1,"app":"demo","secrets":{"demo_a_v1":"YQ=="},"extra":1}`, "not valid JSON"},
		{"two documents", `{"version":1,"app":"demo","secrets":{"demo_a_v1":"YQ=="}} {}`, "exactly one JSON document"},
		{"unsupported version", `{"version":2,"app":"demo","secrets":{"demo_a_v1":"YQ=="}}`, "unsupported application secret payload version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseApplicationSecretPayload("demo", []byte(tc.payload)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

// Rotating a value gives a new object name, which is what makes Swarm replace
// the mount; storing the same value again does not.
func TestApplicationSecretNameFollowsTheStoredVersion(t *testing.T) {
	store := applicationSecretStoreWith(t, map[string]string{"SIGNING_KEY": signingKeyPEM})
	cfg := applicationSecretConfig(map[string]config.SecretItem{"SIGNING_KEY": {Services: []string{"web"}}})
	first, _, err := resolveApplicationSecrets(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("SIGNING_KEY", signingKeyPEM); err != nil {
		t.Fatal(err)
	}
	same, _, err := resolveApplicationSecrets(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if same.Secrets["SIGNING_KEY"].Name != first.Secrets["SIGNING_KEY"].Name {
		t.Fatalf("an unchanged secret must keep its name: %q then %q", first.Secrets["SIGNING_KEY"].Name, same.Secrets["SIGNING_KEY"].Name)
	}
	if err := store.Set("SIGNING_KEY", signingKeyPEM+"# rotated\n"); err != nil {
		t.Fatal(err)
	}
	rotated, _, err := resolveApplicationSecrets(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Secrets["SIGNING_KEY"].Name == first.Secrets["SIGNING_KEY"].Name {
		t.Fatalf("a rotated secret must get a new name, got %q twice", rotated.Secrets["SIGNING_KEY"].Name)
	}
}
