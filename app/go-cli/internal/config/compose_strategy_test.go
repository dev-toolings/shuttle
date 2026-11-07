package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testHostKey = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"

// composeConfig is validConfig turned into the strategy that deploys as an
// existing account with no setup: the host key travels in the file, the user
// is whoever may run docker, and the swarm block is gone.
func composeConfig() string {
	body := strings.Replace(validConfig, "strategy: swarm", "strategy: compose", 1)
	body = strings.Replace(body, "  swarm:\n    mode: single-node\n", "", 1)
	body = strings.Replace(body, "user: deploy", "user: bob", 1)
	body = strings.Replace(body, "  port: 22\n", "  port: 22\n  host_key: "+testHostKey+"\n", 1)
	return body
}

// withDeploy adds keys under the deploy block, which sits mid-document.
func withDeploy(body, extra string) string {
	return strings.Replace(body, "  retain: 2\n", "  retain: 2\n"+extra, 1)
}

func TestComposeStrategyDeploysAsAnExistingAccountWithAPinnedHostKey(t *testing.T) {
	cfg, err := loadYAML(t, composeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UsesCompose() {
		t.Fatal("strategy compose not recognised")
	}
	group := cfg.Servers["default"]
	if group.User != "bob" || group.HostKey != testHostKey || group.Port != 22 {
		t.Fatalf("server group not carried over: %+v", group)
	}
	if got := cfg.ComposeProjectName(); got != "shuttle-demo" {
		t.Fatalf("default project = %q, want shuttle-demo", got)
	}
	named, err := loadYAML(t, withDeploy(composeConfig(), "  compose:\n    project: demo_preprod\n"))
	if err == nil && named.ComposeProjectName() != "demo_preprod" {
		t.Fatalf("declared project not read: %q", named.ComposeProjectName())
	}
	if err != nil {
		t.Fatal(err)
	}

	// Secrets: the host file is the only backend without Swarm, and it is the
	// default rather than a value to remember.
	withSecrets, err := loadYAML(t, composeConfig()+"secrets:\n  host:\n    env_file: /opt/app/.env\n  items:\n    JWT_SECRET_KEY:\n      services: [web]\n      expose: env\n")
	if err != nil {
		t.Fatal(err)
	}
	if withSecrets.Secrets.Backend != SecretsBackendHost {
		t.Fatalf("compose secrets default backend = %q, want host", withSecrets.Secrets.Backend)
	}
}

// Every refusal names the key and says why the strategy cannot honour it.
func TestComposeStrategyRefusesWhatItCannotDeliver(t *testing.T) {
	base := composeConfig()
	for name, tc := range map[string]struct{ body, want string }{
		"no host key":        {strings.Replace(base, "  host_key: "+testHostKey+"\n", "", 1), "requires server.host_key"},
		"malformed host key": {strings.Replace(base, testHostKey, "SHA256:short", 1), "not an ED25519 SHA256 fingerprint"},
		"padded host key":    {strings.Replace(base, "host_key: "+testHostKey, "host_key: ' "+testHostKey+"'", 1), "not an ED25519 SHA256 fingerprint"},
		"root":               {strings.Replace(base, "user: bob", "user: root", 1), "non-root account"},
		"bad account":        {strings.Replace(base, "user: bob", "user: Bob", 1), "non-root account"},
		"swarm block":        {withDeploy(base, "  swarm:\n    mode: single-node\n"), "deploy.swarm does not apply"},
		"bad project":        {withDeploy(base, "  compose:\n    project: Demo Preprod\n"), "invalid deploy.compose.project"},
		"bad build":          {withDeploy(base, "  compose:\n    build: remote\n"), "invalid deploy.compose.build"},
		"redis":              {base + "production:\n  redis: true\n", "production.redis and production.rabbitmq do not apply"},
		"database":           {base + "database:\n  version: 16\n", "database does not apply"},
		"swarm secrets":      {base + "secrets:\n  backend: swarm\n  items:\n    JWT_SECRET_KEY:\n      services: [web]\n", "requires secrets.backend: host"},
		"managed credential": {base + "secrets:\n  host:\n    env_file: /opt/app/.env\n  items:\n    REDIS_PASSWORD:\n      services: [web]\n", "credential the root helper generates"},
		"secret owner":       {base + "secrets:\n  host:\n    env_file: /opt/app/.env\n  items:\n    JWT_SECRET_KEY:\n      services: [web]\n      uid: 1000\n", "declares uid/gid"},
		"caddy routes":       {base + "caddy:\n  routes:\n    demo.example.com: web:3000\n", "caddy.routes does not apply"},
		"host routes":        {base + "caddy:\n  host_routes:\n    - host: api.example.com\n      service: web\n      port: 3000\n", "caddy.host_routes does not apply"},
		"basic auth":         {base + "caddy:\n  basic_auth:\n    users:\n      - username: demo\n        hash: $2a$14$k3Z7GEBmEg8Go2bSKa6pHeI6zP6Y2kYq6E3gYsO4Q0ZK0KZ6mQ9pW\n", "caddy.basic_auth does not apply"},
		"headers":            {base + "caddy:\n  headers:\n    X-Robots-Tag: noindex\n", "caddy.headers does not apply"},
		"trusted cidrs":      {base + "caddy:\n  trusted_cidrs: [172.16.0.0/12]\n", "caddy.trusted_cidrs does not apply"},
		"caddy image":        {base + "caddy:\n  image: caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d\n", "caddy.image does not apply"},
		"operator":           {strings.Replace(base, "setup:\n  slo_seconds: 600", "setup:\n  slo_seconds: 600\n  operator_user: ops\n  operator_public_key: keys/ops.pub", 1), "setup.operator_user and setup.retained_users do not apply"},
		"retained":           {strings.Replace(base, "setup:\n  slo_seconds: 600", "setup:\n  slo_seconds: 600\n  retained_users: [alice]", 1), "setup.operator_user and setup.retained_users do not apply"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, tc.body)
			if err == nil {
				t.Fatal("accepted a configuration the compose strategy cannot honour")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not say %q", err, tc.want)
			}
		})
	}

	// tls_mode stays: it is what the origin proof dials with.
	if _, err := loadYAML(t, base+"caddy:\n  tls_mode: \"off\"\n"); err != nil {
		t.Fatalf("caddy.tls_mode must stay accepted under compose: %v", err)
	}
}

// Rule 4, both directions: a swarm configuration cannot start carrying the
// compose keys, and a configuration that never mentions them is marshalled
// exactly as it was.
func TestSwarmConfigurationsAreUnchangedByTheComposeStrategy(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"host key under swarm": {strings.Replace(validConfig, "  port: 22\n", "  port: 22\n  host_key: "+testHostKey+"\n", 1), "only deploy.strategy: compose reads"},
		"project under swarm":  {withDeploy(validConfig, "  compose:\n    project: demo\n"), "only applies to deploy.strategy: compose"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
	cfg, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"host_key", "\"compose\""} {
		if strings.Contains(string(encoded), absent) {
			t.Fatalf("a swarm configuration now carries %q:\n%s", absent, encoded)
		}
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "valid-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(golden) != string(encoded)+"\n" {
		t.Fatalf("the loaded swarm configuration moved:\n--- want\n%s\n--- got\n%s", golden, encoded)
	}
	if cfg.Secrets.Backend != "" {
		t.Fatalf("a swarm configuration without secrets must keep an empty backend, got %q", cfg.Secrets.Backend)
	}
}
