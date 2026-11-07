package cli

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func hostSecretConfig(items map[string]config.SecretItem) *config.Config {
	cfg := &config.Config{App: "demo"}
	cfg.Domain = "demo.example.com"
	cfg.Secrets.Backend = config.SecretsBackendHost
	cfg.Secrets.Host.EnvFile = "/opt/demo/.env"
	cfg.Secrets.Items = items
	return cfg
}

// The file on a real server holds far more than the secrets an application
// declares. Reading it wholesale would publish as a credential every line
// somebody ever added to it, including the ones that are not secret and the
// ones that belong to something else entirely.
func TestHostSecretsReadOnlyTheDeclaredKeys(t *testing.T) {
	body := []byte(`
# a comment
DATABASE_HOST=203.0.113.4
JWT_SECRET_KEY=jwt-value
export HMAC_SECRET_KEY='hmac-value'
STRIPE_SECRET_KEY="stripe-value"
UNRELATED=not-a-secret
malformed line without an equals sign
`)
	found, missing := parseHostSecretEnvFile(body, []string{"HMAC_SECRET_KEY", "JWT_SECRET_KEY", "STRIPE_SECRET_KEY"})
	if len(found) != 3 {
		t.Fatalf("expected the three declared keys, got %d: %v", len(found), found)
	}
	if found["JWT_SECRET_KEY"] != "jwt-value" {
		t.Fatalf("a bare value must survive unchanged, got %q", found["JWT_SECRET_KEY"])
	}
	if found["HMAC_SECRET_KEY"] != "hmac-value" {
		t.Fatalf("an export prefix and single quotes must be stripped, got %q", found["HMAC_SECRET_KEY"])
	}
	if found["STRIPE_SECRET_KEY"] != "stripe-value" {
		t.Fatalf("double quotes must be stripped, got %q", found["STRIPE_SECRET_KEY"])
	}
	if _, ok := found["DATABASE_HOST"]; ok {
		t.Fatal("an undeclared key must never be read out of the file")
	}
	if len(missing) != 0 {
		t.Fatalf("nothing was missing, got %v", missing)
	}
}

// An empty credential produces a container that starts, authenticates against
// nothing and fails later, which is worse than not deploying. A key present but
// blank is therefore not a key that is present.
func TestHostSecretsTreatAnEmptyValueAsMissing(t *testing.T) {
	found, missing := parseHostSecretEnvFile([]byte("JWT_SECRET_KEY=\nHMAC_SECRET_KEY=set\n"), []string{"HMAC_SECRET_KEY", "JWT_SECRET_KEY"})
	if _, ok := found["JWT_SECRET_KEY"]; ok {
		t.Fatal("a blank value must not be published as a credential")
	}
	if len(missing) != 1 || missing[0] != "JWT_SECRET_KEY" {
		t.Fatalf("the blank key must be reported missing, got %v", missing)
	}
}

// The operator has to learn which key their server does not set, and learn it
// from the name of the key rather than from a service that never converges.
func TestHostSecretsResponseNamesTheKeysTheServerDoesNotSet(t *testing.T) {
	_, err := parseHostSecretsResponse("demo", []string{"JWT_SECRET_KEY"}, []byte(`{"version":1,"app":"demo","secrets":{},"missing":["JWT_SECRET_KEY"]}`))
	if err == nil || !strings.Contains(err.Error(), "JWT_SECRET_KEY") {
		t.Fatalf("the error must name the missing key, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "secrets.host.env_file") {
		t.Fatalf("the error must name the file to fix, got %v", err)
	}
}

// A response that names another application would publish, into this stack, a
// secret object belonging to something else.
func TestHostSecretsResponseMustNameThisApplication(t *testing.T) {
	_, err := parseHostSecretsResponse("demo", []string{"JWT_SECRET_KEY"}, []byte(`{"version":1,"app":"other","secrets":{"JWT_SECRET_KEY":"0123456789ab"}}`))
	if err == nil || !strings.Contains(err.Error(), "another application") {
		t.Fatalf("expected the response to be refused, got %v", err)
	}
}

// The fragment is concatenated into a Docker object name, so it is checked
// before the name is built rather than after Docker refuses it.
func TestHostSecretsResponseRefusesAnUnusableVersionFragment(t *testing.T) {
	_, err := parseHostSecretsResponse("demo", []string{"JWT_SECRET_KEY"}, []byte(`{"version":1,"app":"demo","secrets":{"JWT_SECRET_KEY":"NOT-HEX"}}`))
	if err == nil || !strings.Contains(err.Error(), "version fragment") {
		t.Fatalf("expected an invalid fragment to be refused, got %v", err)
	}
}

// Both backends derive the object name the same way, from an application, a key
// and a version fragment. A client that derived one spelling and a helper that
// derived another would publish a secret nothing mounts.
func TestHostSecretsDeriveTheSameObjectNameAsTheLocalStore(t *testing.T) {
	manifest, err := parseHostSecretsResponse("demo", []string{"JWT_SECRET_KEY"}, []byte(`{"version":1,"app":"demo","secrets":{"JWT_SECRET_KEY":"0123456789ab"}}`))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := swarmSecretObjectName("demo", "JWT_SECRET_KEY", "0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Secrets["JWT_SECRET_KEY"].Name != expected {
		t.Fatalf("expected %q, got %q", expected, manifest.Secrets["JWT_SECRET_KEY"].Name)
	}
	if !strings.HasPrefix(expected, "demo_jwt_secret_key_v") {
		t.Fatalf("the object name must be derived from the application and the key, got %q", expected)
	}
}

// Editing the file is the only rotation signal the host backend gets: there is
// nowhere beside a plain environment file to keep a version identifier that
// somebody editing that file would remember to update.
func TestHostSecretsVersionChangesWithTheValue(t *testing.T) {
	if hostSecretVersionFragment("before") == hostSecretVersionFragment("after") {
		t.Fatal("two different values must produce two different versions, or Swarm never rolls the service")
	}
	if hostSecretVersionFragment("same") != hostSecretVersionFragment("same") {
		t.Fatal("the same value must produce the same version, or every deploy republishes every secret")
	}
}

// The point of the backend is that the workstation holds no credential, so the
// deploy path must not reach for a local store it would then have to find.
func TestHostSecretsDeployResolutionNeverOpensTheLocalStore(t *testing.T) {
	cfg := hostSecretConfig(map[string]config.SecretItem{"JWT_SECRET_KEY": {Services: []string{"web"}, Expose: "env"}})
	cfg.Secrets.File = "/nonexistent/secrets.enc"
	t.Setenv("SHUTTLE_SECRETS_PASSPHRASE", "")
	manifest, payload, err := resolveDeployApplicationSecrets(cfg)
	if err != nil {
		t.Fatalf("the host backend must not need a local store: %v", err)
	}
	if len(payload) != 0 {
		t.Fatalf("no material may travel from this machine, got %d bytes", len(payload))
	}
	if len(manifest.Secrets) != 0 {
		t.Fatal("names are resolved against the host later, not here")
	}
}

// A helper that cannot read secrets on the host would apply a stack mounting
// objects nobody created, and the services would wait for them until the
// promotion budget ran out without ever saying why.
func TestHostSecretsRequireTheHelperCapability(t *testing.T) {
	cfg := hostSecretConfig(map[string]config.SecretItem{"JWT_SECRET_KEY": {Services: []string{"web"}, Expose: "env"}})
	required := requiredRootHelperCapabilities(cfg)
	found := false
	for _, capability := range required {
		if capability == capabilitySecretsHost {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s to be required, got %v", capabilitySecretsHost, required)
	}
	swarmCfg := applicationSecretConfig(map[string]config.SecretItem{"JWT_SECRET_KEY": {Services: []string{"web"}, Expose: "env"}})
	for _, capability := range requiredRootHelperCapabilities(swarmCfg) {
		if capability == capabilitySecretsHost {
			t.Fatal("the local-store backend must not demand a helper feature it does not use")
		}
	}
}

// The stack is written to disk on the VPS and printed by --dry-run, so it must
// carry the object name and never the value — exactly as the local-store
// backend already does.
func TestHostSecretsReachTheStackAsNamesOnly(t *testing.T) {
	cfg := hostSecretConfig(map[string]config.SecretItem{"JWT_SECRET_KEY": {Services: []string{"web"}, Expose: "env"}})
	manifest, err := parseHostSecretsResponse("demo", []string{"JWT_SECRET_KEY"}, []byte(`{"version":1,"app":"demo","secrets":{"JWT_SECRET_KEY":"0123456789ab"}}`))
	if err != nil {
		t.Fatal(err)
	}
	stack, root := applicationSecretStack(t, cfg, manifest)
	name := manifest.Secrets["JWT_SECRET_KEY"].Name
	if !strings.Contains(stack, name) {
		t.Fatalf("the stack must reference %q", name)
	}
	topLevel, ok := root["secrets"].(map[string]any)
	if !ok {
		t.Fatal("the stack must declare its secrets")
	}
	object, ok := topLevel[name].(map[string]any)
	if !ok || object["external"] != true {
		t.Fatalf("the object must be declared external, got %v", topLevel[name])
	}
}

// A dry run is read-only, so it may not go and ask the host what it holds; it
// must still print a stack that passes the same hardening checks a real one does.
func TestHostSecretsDryRunNamesObjectsWithoutReadingTheHost(t *testing.T) {
	cfg := hostSecretConfig(map[string]config.SecretItem{"JWT_SECRET_KEY": {Services: []string{"web"}, Expose: "env"}})
	manifest, err := dryRunHostSecretManifest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := manifest.Secrets["JWT_SECRET_KEY"]
	if !ok || !strings.HasPrefix(entry.Name, "demo_jwt_secret_key_v") {
		t.Fatalf("expected a placeholder object name, got %v", manifest.Secrets)
	}
	again, err := dryRunHostSecretManifest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again.Secrets["JWT_SECRET_KEY"].Name != entry.Name {
		t.Fatal("the placeholder must be deterministic, or two dry runs print two different stacks")
	}
}

// The helper prints a receipt after every root operation. Decoding the receipt
// as part of the answer would fail on a response the helper produced correctly.
func TestHostSecretsResponseIsReadWithoutTheOperationReceipt(t *testing.T) {
	body, err := hostSecretsResponseBody("{\"version\":1,\"app\":\"demo\",\"secrets\":{}}\noperation=secrets-host digest=sha256:abc\n")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"version":1,"app":"demo","secrets":{}}` {
		t.Fatalf("the receipt must be stripped, got %q", body)
	}
	if _, err := hostSecretsResponseBody("no receipt here"); err == nil {
		t.Fatal("a reply without a receipt is not an answer from the helper")
	}
}

// The store flag used to default to the literal path, so a project that moved
// its store with secrets.file was read at the declared path by every deploy and
// at the default path by every `shuttle secrets`: list showed an empty store for
// secrets that were there, and set wrote a second one no deploy ever opened.
func TestSecretsCommandFollowsTheConfiguredStorePath(t *testing.T) {
	command := newSecretsCommand()
	flag := command.PersistentFlags().Lookup("file")
	if flag == nil {
		t.Fatal("the store path must stay overridable")
	}
	if flag.DefValue != "" {
		t.Fatalf("an empty default is what lets secrets.file be consulted, got %q", flag.DefValue)
	}
	if !strings.Contains(flag.Usage, defaultSecretStorePath) {
		t.Fatalf("the help must still name the fallback path, got %q", flag.Usage)
	}
}
