package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func withTempDir(t *testing.T, fn func(string)) {
	t.Helper()
	dir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)
	fn(dir)
}

func TestInitWritesOnlyValidConfig(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "nextjs", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, ".shuttle.yml")); !os.IsNotExist(err) {
			t.Fatalf("legacy .shuttle.yml must not exist: %v", err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Version != 2 || cfg.Readiness.Preset != "nextjs" || cfg.Setup.SLOSeconds != 600 || cfg.Deploy.TotalSLOSeconds != 30 {
			t.Fatalf("unexpected config: %#v", cfg)
		}
		var document map[string]any
		body, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatal(err)
		}
		caddy, _ := document["caddy"].(map[string]any)
		if _, exists := caddy["image"]; exists {
			t.Fatalf("init must leave caddy.image unset for runtime resolution, got %v", caddy["image"])
		}
	})
}

func TestInitPublicOutputIsUnchangedWhenExposeIsOmitted(t *testing.T) {
	var outputs []string
	for _, exposeArgs := range [][]string{nil, {"--expose", "public"}} {
		withTempDir(t, func(dir string) {
			args := []string{"--preset", "nextjs", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"}
			args = append(args, exposeArgs...)
			cmd := newInitCommand()
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, string(body))
		})
	}
	if outputs[0] != outputs[1] {
		t.Fatal("omitting --expose must produce byte-identical config to --expose public")
	}
}

func TestInitInternalConfigLoadsWithoutPublicRoute(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "nextjs", "--app", "demo", "--host", "203.0.113.10", "--expose", "internal", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatalf("load generated internal config: %v", err)
		}
		if cfg.Expose != config.ExposeInternal || cfg.Deploy.PrimaryService != "web" {
			t.Fatalf("unexpected internal config: expose=%q primary_service=%q", cfg.Expose, cfg.Deploy.PrimaryService)
		}
		body, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatal(err)
		}
		caddy, _ := document["caddy"].(map[string]any)
		if _, exists := document["domain"]; exists || len(cfg.Caddy.Routes) != 0 || cfg.Deploy.AvailabilityURL != "" || caddy["routes"] != nil {
			t.Fatalf("internal config declares a public route: domain=%q routes=%v availability_url=%q", cfg.Domain, cfg.Caddy.Routes, cfg.Deploy.AvailabilityURL)
		}
	})
}

func TestInitInternalRejectsDomainFlag(t *testing.T) {
	withTempDir(t, func(_ string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--expose", "internal", "--domain", "demo.example.com"})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with --domain") {
			t.Fatalf("expected clear --domain rejection, got %v", err)
		}
	})
}

func TestInitRejectsRemovedDatabaseAndUnknownPreset(t *testing.T) {
	for _, args := range [][]string{
		{"--with-db", "mysql", "--domain", "demo.example.com"},
		{"--preset", "rails", "--domain", "demo.example.com"},
	} {
		withTempDir(t, func(_ string) {
			cmd := newInitCommand()
			cmd.SetArgs(args)
			err := cmd.Execute()
			if err == nil || (!strings.Contains(err.Error(), "PostgreSQL") && !strings.Contains(err.Error(), "unknown preset")) {
				t.Fatalf("expected clear rejection, got %v", err)
			}
		})
	}
}

func TestInitMapsApplicationSlugToValidPostgresIdentifier(t *testing.T) {
	for _, test := range []struct {
		app  string
		want string
	}{
		{app: "shuttle-smoke", want: "shuttle_smoke"},
		{app: "2026-api", want: "app_2026_api"},
		{app: strings.Repeat("a", 63), want: strings.Repeat("a", 63)},
		{app: "1" + strings.Repeat("a", 62), want: "app_1" + strings.Repeat("a", 58)},
	} {
		withTempDir(t, func(dir string) {
			cmd := newInitCommand()
			cmd.SetArgs([]string{"--preset", "node-api", "--app", test.app, "--domain", "demo.example.com", "--host", "203.0.113.10", "--with-db", "postgres", "--force"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("init %q: %v", test.app, err)
			}
			cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
			if err != nil {
				t.Fatalf("load %q config: %v", test.app, err)
			}
			if got := cfg.Database.Roles[0].Name; got != test.want {
				t.Fatalf("database role for %q = %q, want %q", test.app, got, test.want)
			}
			if got := cfg.Database.Databases[0]; got.Name != test.want || got.Owner != test.want {
				t.Fatalf("database for %q = %#v, want name and owner %q", test.app, got, test.want)
			}
		})
	}
}

// `init` must write the budget the chosen framework can actually meet. One
// hard-coded 30 guaranteed that every generated PHP project shipped a budget its
// own runtime cannot hold.
func TestInitWritesThePresetDeployBudget(t *testing.T) {
	for preset, want := range map[string]int{
		"laravel":  45,
		"symfony":  45,
		"hono":     30,
		"nextjs":   30,
		"fastapi":  30,
		"fastify":  30,
		"node-api": 30,
	} {
		withTempDir(t, func(dir string) {
			cmd := newInitCommand()
			cmd.SetArgs([]string{"--preset", preset, "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("preset %s: %v", preset, err)
			}
			cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
			if err != nil {
				t.Fatalf("preset %s: %v", preset, err)
			}
			if cfg.Deploy.TotalSLOSeconds != want || cfg.Deploy.PromotionSLOSeconds != want {
				t.Errorf("preset %s: init wrote %d/%d, want %d", preset, cfg.Deploy.TotalSLOSeconds, cfg.Deploy.PromotionSLOSeconds, want)
			}
		})
	}
}

func TestInitLeavesCaddyMajorSelectionToSetup(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "hono", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Caddy.Image != "" || strings.Contains(string(body), `"image": "caddy:`) {
			t.Fatalf("init should leave Caddy major selection to setup: config=%q", cfg.Caddy.Image)
		}
	})
}

// `shuttle init` writes retention.registry_cache into every config.json, so the
// generated value has to survive the whole chain it promises: parsed into bytes
// by the loader, accepted by the signed root-operation contract, and therefore
// enforceable by the helper that owns the registry volume. It used to be dead
// configuration: defaulted, validated, generated, and read by nothing.
func TestInitWritesAnEnforceableRegistryCacheBudget(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "laravel", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "\"registry_cache\"") {
			t.Fatalf("the generated config must still declare the retention budget:\n%s", body)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatal(err)
		}
		budget := cfg.Retention.RegistryCacheBytes()
		if budget != 5<<30 {
			t.Fatalf("the generated budget must resolve to bytes, got %d", budget)
		}
		fingerprint := "SHA256:" + strings.Repeat("A", 43)
		plan, err := rootplan.NewStackAction("stack-apply", cfg.App, rootplan.PayloadDigest(body), cfg.Deploy.PromotionSLOSeconds, budget, fingerprint, fingerprint, time.Now(), time.Minute)
		if err != nil {
			t.Fatalf("the generated budget must be transportable to the root helper: %v", err)
		}
		if plan.Stack.RegistryCacheBudgetBytes != budget {
			t.Fatalf("the budget must reach the helper unchanged, got %d", plan.Stack.RegistryCacheBudgetBytes)
		}
	})
}

func TestInitWritesHostBackedAppKeyForLaravel(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "laravel", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--with-redis", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.UsesHostSecrets() {
			t.Fatalf("laravel init must use the host backend, got %#v", cfg.Secrets)
		}
		if cfg.Secrets.Host.EnvFile != "/opt/demo/.env" {
			t.Fatalf("host env_file = %q", cfg.Secrets.Host.EnvFile)
		}
		if _, ok := cfg.Secrets.Items["APP_KEY"]; !ok {
			t.Fatal("APP_KEY must still be declared")
		}
		if _, ok := cfg.Secrets.Items["REDIS_PASSWORD"]; !ok {
			t.Fatal("REDIS_PASSWORD stays declared; Shuttle still generates it on the host")
		}
	})
}

func TestInitRedisOnlyKeepsTheLocalStoreBecauseThereIsNoApplicationSecret(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "hono", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--with-redis", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.UsesHostSecrets() {
			t.Fatal("host backend requires an application secret; Redis-only must keep the swarm default")
		}
		if cfg.Secrets.Backend != config.SecretsBackendSwarm {
			t.Fatalf("backend = %q, want swarm", cfg.Secrets.Backend)
		}
	})
}

func TestInitInstallsTheHostEnvSkillAndKeepsEnvOutOfGit(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "nextjs", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		skill := filepath.Join(dir, ".claude", "skills", "shuttle-host-env", "SKILL.md")
		body, err := os.ReadFile(skill)
		if err != nil {
			t.Fatalf("init must drop the skill into the project: %v", err)
		}
		if !strings.Contains(string(body), "secrets.backend: host") {
			t.Fatalf("installed skill is not the bundled host-env text:\n%s", body)
		}
		ignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(ignore)
		for _, line := range []string{".env", ".env.*", "!.env.example"} {
			if !strings.Contains(text, line) {
				t.Fatalf(".gitignore missing %q:\n%s", line, text)
			}
		}
		example, err := os.ReadFile(filepath.Join(dir, ".env.example"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(example), "Copy to .env") {
			t.Fatal(".env.example must not tell anyone to copy production values onto a workstation")
		}
	})
}

func TestInitComposeLaravelWritesHostSecrets(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{
			"--preset", "laravel", "--app", "demo", "--domain", "demo.example.com",
			"--host", "203.0.113.10", "--strategy", "compose", "--user", "bob",
			"--host-key", "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA", "--force",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.UsesHostSecrets() || cfg.Secrets.Host.EnvFile != "/opt/demo/.env" {
			t.Fatalf("compose laravel must use the host backend, got %#v", cfg.Secrets)
		}
	})
}

// Symfony boots without APP_SECRET and fails later, on CSRF or a signed URL, so
// init declares it exactly like Laravel's APP_KEY: host-backed, in the env.
func TestInitDeclaresHostBackedAppSecretForSymfony(t *testing.T) {
	withTempDir(t, func(dir string) {
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "symfony", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"), "")
		if err != nil {
			t.Fatal(err)
		}
		item, ok := cfg.Secrets.Items["APP_SECRET"]
		if !ok || !cfg.UsesHostSecrets() || item.ExposeMode() != "env" {
			t.Fatalf("symfony init must declare a host-backed APP_SECRET in the env, got %#v", cfg.Secrets)
		}
		if _, ok := cfg.Secrets.Items["APP_KEY"]; ok {
			t.Fatal("APP_KEY is Laravel's, not Symfony's")
		}
	})
}
