package config

import (
	"strings"
	"testing"
)

// An application may now declare its own secrets. The value never appears in
// config.json: only the name, the services that mount it, and how.
func TestLoadAcceptsApplicationSecrets(t *testing.T) {
	cfg, err := loadYAML(t, validConfig+`secrets:
  backend: swarm
  items:
    SIGNING_PRIVATE_KEY:
      services: [web]
    SIGNING_PUBLIC_KEY:
      services: [web]
      expose: file
`)
	if err != nil {
		t.Fatalf("application secrets must be accepted: %v", err)
	}
	// expose: file is the default, so a secret nobody asked to see in the
	// environment stays under /run/secrets.
	if mode := cfg.Secrets.Items["SIGNING_PRIVATE_KEY"].ExposeMode(); mode != "file" {
		t.Fatalf("expose must default to file, got %q", mode)
	}
	if keys := cfg.ApplicationSecretKeys(); strings.Join(keys, ",") != "SIGNING_PRIVATE_KEY,SIGNING_PUBLIC_KEY" {
		t.Fatalf("application secrets must be listed in a stable order, got %#v", keys)
	}
}

// Infrastructure credentials keep exactly the treatment they had: they are
// generated on the host, and their scope is still pinned.
func TestLoadKeepsInfrastructureSecretsPinned(t *testing.T) {
	// Still refused when the service it belongs to is off: a credential for a
	// Redis nobody runs names nothing.
	if _, err := loadYAML(t, validConfig+`secrets:
  backend: swarm
  items:
    REDIS_PASSWORD:
      services: [web]
      expose: file
`); err == nil || !strings.Contains(err.Error(), "the service it belongs to is not enabled") {
		t.Fatalf("REDIS_PASSWORD must be refused while Redis is off, got %v", err)
	}
	// Accepted once it is on. Shuttle runs a password-protected Redis, so the
	// application services that connect to it have to be able to read the
	// password — mounting it on the Redis container alone made the service
	// Shuttle provisions unusable by the stack it provisions it for.
	if _, err := loadYAML(t, validConfig+`production:
  redis: true
secrets:
  backend: swarm
  items:
    REDIS_PASSWORD:
      services: [web]
      expose: file
      uid: 10001
`); err != nil {
		t.Fatalf("an application service must be allowed to read the managed Redis password: %v", err)
	}
	// The value is generated on the host and mounted, never carried as an
	// environment variable where `docker inspect` would show it.
	if _, err := loadYAML(t, validConfig+`production:
  redis: true
secrets:
  backend: swarm
  items:
    REDIS_PASSWORD:
      services: [web]
      expose: env
`); err == nil || !strings.Contains(err.Error(), "must be exposed as a file") {
		t.Fatalf("a managed credential must not travel as an environment variable, got %v", err)
	}
	// Outside the Laravel preset APP_KEY is an application secret like any
	// other: a TanStack primary with Laravel as a secondary service still has
	// one, and the operator names where it goes.
	appKeyConfig, err := loadYAML(t, validConfig+`secrets:
  backend: swarm
  items:
    APP_KEY:
      services: [api]
      expose: env
`)
	if err != nil {
		t.Fatalf("APP_KEY on a non-Laravel preset must be an ordinary application secret, got %v", err)
	}
	if keys := appKeyConfig.ApplicationSecretKeys(); strings.Join(keys, ",") != "APP_KEY" {
		t.Fatalf("APP_KEY must be carried from the local secret store, got %v", keys)
	}
	cfg, err := loadYAML(t, validConfig+`production:
  redis: true
secrets:
  backend: swarm
  items:
    REDIS_PASSWORD:
      services: [redis]
      expose: file
`)
	if err != nil {
		t.Fatalf("the infrastructure declaration must keep validating: %v", err)
	}
	if keys := cfg.ApplicationSecretKeys(); len(keys) != 0 {
		t.Fatalf("an infrastructure credential is not an application secret, got %#v", keys)
	}
}

func TestLoadRefusesUnusableApplicationSecrets(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"lowercase key", "    signing_key:\n      services: [web]\n", "invalid secret key"},
		{"no service", "    SIGNING_KEY:\n      services: []\n", "services must not be empty"},
		{"unknown exposure", "    SIGNING_KEY:\n      services: [web]\n      expose: stdout\n", "expose must be file or env"},
		{"repeated service", "    SIGNING_KEY:\n      services: [web, web]\n", "more than once"},
		{"name too long", "    " + strings.Repeat("A", 41) + ":\n      services: [web]\n", "above the 40"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, validConfig+"secrets:\n  backend: swarm\n  items:\n"+tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

// §4: a configuration that declares no secrets at all is unaffected.
func TestLoadWithoutSecretsIsUnchanged(t *testing.T) {
	cfg, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secrets.Items) != 0 || len(cfg.ApplicationSecretKeys()) != 0 {
		t.Fatalf("nothing declared, nothing carried: %#v", cfg.Secrets)
	}
}

// A per-role database password is generated on the host, like every other
// managed credential. Counting it as an application secret stopped the deploy
// with an instruction to store a value Shuttle is the one that creates:
//
//	secret POSTGRES_PASSWORD_DEMO_AGENTS is declared in secrets.items but is
//	not in the local secret store; run `shuttle secrets set …`
func TestPerRoleDatabasePasswordIsNotAnApplicationSecret(t *testing.T) {
	cfg, err := loadYAML(t, validConfig+`database:
  version: 16
  roles:
    - name: demo
    - name: demo_agents
  databases:
    - name: demo
      owner: demo
    - name: demo_agents
      owner: demo_agents
secrets:
  backend: swarm
  items:
    POSTGRES_PASSWORD_DEMO_AGENTS:
      services: [web]
      expose: file
      uid: 10001
`)
	if err != nil {
		t.Fatalf("a per-role password must be declarable: %v", err)
	}
	if keys := cfg.ApplicationSecretKeys(); len(keys) != 0 {
		t.Fatalf("it must not be looked for in the local store, got %v", keys)
	}
}

// The Laravel rule is unchanged: APP_KEY reaches the primary service as an
// environment variable, because that is the only form the framework boots
// with, and anything else is refused.
func TestAppKeyStaysTiedToThePrimaryUnderTheLaravelPreset(t *testing.T) {
	// The Laravel preset defaults to a 45 s promotion budget, which the shared
	// fixture's 30 s total would not hold.
	laravel := strings.NewReplacer("preset: node-api", "preset: laravel", "total_slo_seconds: 30", "total_slo_seconds: 120").Replace(validConfig)
	cfg, err := loadYAML(t, laravel+`secrets:
  backend: swarm
  items:
    APP_KEY:
      services: [web]
      expose: env
`)
	if err != nil {
		t.Fatalf("APP_KEY as env on the Laravel primary must be accepted, got %v", err)
	}
	if keys := cfg.ApplicationSecretKeys(); strings.Join(keys, ",") != "APP_KEY" {
		t.Fatalf("Laravel APP_KEY must be carried from the local secret store, got %v", keys)
	}
	for name, item := range map[string]string{
		"another service": "      services: [api]\n      expose: env\n",
		"a file mount":    "      services: [web]\n      expose: file\n",
	} {
		if _, err := loadYAML(t, laravel+"secrets:\n  backend: swarm\n  items:\n    APP_KEY:\n"+item); err == nil || !strings.Contains(err.Error(), "secret APP_KEY must target only enabled service web as env") {
			t.Fatalf("APP_KEY targeting %s under the Laravel preset must be refused, got %v", name, err)
		}
	}
}

// Outside the Laravel preset the ordinary application-secret rules apply, so
// a malformed APP_KEY is still refused — just for the same reasons as any
// other secret.
func TestAppKeyIsAnOrdinarySecretOutsideTheLaravelPreset(t *testing.T) {
	if _, err := loadYAML(t, validConfig+`secrets:
  backend: swarm
  items:
    APP_KEY:
      services: [api]
      expose: socket
`); err == nil || !strings.Contains(err.Error(), "secret APP_KEY expose must be file or env") {
		t.Fatalf("an ordinary secret rule must still apply to APP_KEY, got %v", err)
	}
}
