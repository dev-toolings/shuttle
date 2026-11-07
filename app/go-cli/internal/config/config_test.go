package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const validConfig = `version: 2
app: demo
domain: demo.example.com
server:
  host: 203.0.113.10
  user: deploy
  port: 22
deploy:
  strategy: swarm
  total_slo_seconds: 30
  retain: 2
  swarm:
    mode: single-node
services:
  web:
    port: 3000
    healthcheck:
      type: http
      path: /health
setup:
  slo_seconds: 600
retention:
  registry_cache: 5GB
  postgres_backups: 7
  min_free_percent: 20
readiness:
  preset: node-api
  healthcheck_path: /health
`

func loadYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "shuttle.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path, "")
}

func TestLoadSingleNodeDefaults(t *testing.T) {
	cfg, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 || cfg.Setup.SLOSeconds != 600 || cfg.Deploy.TotalSLOSeconds != 30 || cfg.Deploy.Retain != 2 {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestPostgresBackupRetentionDefaultsAndBounds(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"omitted", strings.Replace(validConfig, "  postgres_backups: 7\n", "", 1), 7},
		{"default", strings.Replace(validConfig, "postgres_backups: 7", "postgres_backups: 0", 1), 7},
		{"one", strings.Replace(validConfig, "postgres_backups: 7", "postgres_backups: 1", 1), 1},
		{"seven", validConfig, 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := loadYAML(t, test.body)
			if err != nil {
				t.Fatalf("valid retention rejected: %v", err)
			}
			if cfg.Retention.Backups != test.want {
				t.Fatalf("got postgres_backups=%d, want %d", cfg.Retention.Backups, test.want)
			}
		})
	}

	for _, value := range []string{"8", "-1"} {
		t.Run("reject "+value, func(t *testing.T) {
			body := strings.Replace(validConfig, "postgres_backups: 7", "postgres_backups: "+value, 1)
			_, err := loadYAML(t, body)
			if err == nil || err.Error() != "retention.postgres_backups must be between 1 and 7" {
				t.Fatalf("got error %v, want exact postgres_backups range error", err)
			}
		})
	}

	body := strings.Replace(validConfig, "min_free_percent: 20", "min_free_percent: 19", 1)
	if _, err := loadYAML(t, body); err == nil || err.Error() != "retention.min_free_percent must be 20" {
		t.Fatalf("got error %v, want exact min_free_percent refusal", err)
	}
}

func TestProductionRedisImageAcceptsAnOfficialMajorTagOrDigest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := validConfig + "\nproduction:\n  redis: true\n  redis_image: redis:7.4.5-alpine@sha256:" + digest + "\n"
	cfg, err := loadYAML(t, valid)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Production.RedisImage == "" {
		t.Fatal("the retained Redis image pin was lost")
	}

	for name, body := range map[string]string{
		"without redis":  validConfig + "\nproduction:\n  redis_image: redis:7.4.5-alpine@sha256:" + digest + "\n",
		"official tag":   validConfig + "\nproduction:\n  redis: true\n  redis_image: redis:7-alpine\n",
		"other registry": validConfig + "\nproduction:\n  redis: true\n  redis_image: registry.example/redis:7.4.5-alpine@sha256:" + digest + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, body)
			if name == "official tag" {
				if err != nil {
					t.Fatalf("official Redis tag rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe Redis image configuration was accepted")
			}
		})
	}
}

func TestRejectsV1ComposeAndMultiNode(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"v1", strings.Replace(validConfig, "version: 2", "version: 1", 1), "requires version: 2"},
		// compose is a strategy now, and the first thing it asks for is the
		// host key nothing else would have recorded.
		{"compose", strings.Replace(validConfig, "strategy: swarm", "strategy: compose", 1), "requires server.host_key"},
		{"unknown strategy", strings.Replace(validConfig, "strategy: swarm", "strategy: kubernetes", 1), "swarm or compose"},
		{"multi-node", strings.Replace(validConfig, "mode: single-node", "mode: multi-node", 1), "at least two nodes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadYAML(t, test.body)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

func TestRejectsMultipleVPSAndNonDeployUser(t *testing.T) {
	for _, mutation := range []struct{ old, new, want string }{
		{"host: 203.0.113.10", "host: ''", "non-empty VPS"},
		{"user: deploy", "user: root", "least-privilege deploy user"},
	} {
		_, err := loadYAML(t, strings.Replace(validConfig, mutation.old, mutation.new, 1))
		if err == nil || !strings.Contains(err.Error(), mutation.want) {
			t.Fatalf("expected %q, got %v", mutation.want, err)
		}
	}
}

func TestRejectsUnknownLegacyKeys(t *testing.T) {
	_, err := loadYAML(t, validConfig+"\nlegacy_operator_profile: enabled\n")
	if err == nil || !strings.Contains(err.Error(), "field legacy_operator_profile not found") {
		t.Fatalf("expected unknown v1 key rejection, got %v", err)
	}
}

func TestDefaultConfigPrefersConfigJSON(t *testing.T) {
	dir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)
	if err := os.WriteFile("config.json", []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("shuttle.yml", []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("", ""); err == nil || !strings.Contains(err.Error(), "requires version: 2") {
		t.Fatalf("config.json was not preferred over shuttle.yml: %v", err)
	}
}

func TestDefaultConfigPrefersNearestProjectBeforeFormat(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "project")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "shuttle.yml"), []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(child); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)
	cfg, err := Load("", "")
	if err != nil || cfg.App != "demo" {
		t.Fatalf("nearest project configuration was not selected: cfg=%#v err=%v", cfg, err)
	}
}

// The budget follows the framework. Pinning deploy.total_slo_seconds to exactly
// 30 rejected the only value a PHP application can honestly declare, so the
// preset now picks the default and the operator may override it inside sane
// bounds instead of matching one hard-coded number.
func TestDeployBudgetDefaultsFollowThePreset(t *testing.T) {
	for preset, want := range map[string]int{
		"laravel":        45,
		"symfony":        45,
		"hono":           30,
		"node-api":       30,
		"fastify":        30,
		"nextjs":         30,
		"tanstack-start": 30,
		"fastapi":        30,
		"docker-swarm":   30,
	} {
		if got := DefaultDeploySLOSeconds(preset); got != want {
			t.Errorf("preset %s: default budget %d, want %d", preset, got, want)
		}
		body := strings.Replace(strings.Replace(validConfig, "  total_slo_seconds: 30\n", "", 1), "preset: node-api", "preset: "+preset, 1)
		cfg, err := loadYAML(t, body)
		if err != nil {
			t.Fatalf("preset %s: %v", preset, err)
		}
		if cfg.Deploy.TotalSLOSeconds != want || cfg.Deploy.PromotionSLOSeconds != want {
			t.Errorf("preset %s: loaded budgets %d/%d, want %d", preset, cfg.Deploy.TotalSLOSeconds, cfg.Deploy.PromotionSLOSeconds, want)
		}
	}
}

func TestDeployBudgetAcceptsAPHPOverrideAndRefusesOutOfRangeValues(t *testing.T) {
	php := strings.Replace(strings.Replace(validConfig, "total_slo_seconds: 30", "total_slo_seconds: 45\n  promotion_slo_seconds: 45", 1), "preset: node-api", "preset: symfony", 1)
	cfg, err := loadYAML(t, php)
	if err != nil {
		t.Fatalf("a PHP preset must be allowed to declare a 45 s budget: %v", err)
	}
	if cfg.Deploy.TotalSLOSeconds != 45 || cfg.Deploy.PromotionSLOSeconds != 45 {
		t.Fatalf("unexpected budgets: %d/%d", cfg.Deploy.TotalSLOSeconds, cfg.Deploy.PromotionSLOSeconds)
	}
	for name, body := range map[string]string{
		"below the floor":   strings.Replace(validConfig, "total_slo_seconds: 30", "total_slo_seconds: 5", 1),
		"above the ceiling": strings.Replace(validConfig, "total_slo_seconds: 30", "total_slo_seconds: 3600", 1),
		"promotion above total": strings.Replace(validConfig, "total_slo_seconds: 30",
			"total_slo_seconds: 30\n  promotion_slo_seconds: 120", 1),
	} {
		if _, err := loadYAML(t, body); err == nil && name != "official tag" {
			t.Errorf("%s must be rejected", name)
		}
	}
}

// The waits a promotion performs one after another are shares of the budget it
// is measured against, so they can never sum above it.
func TestDeployWaitsNeverOutlastTheBudget(t *testing.T) {
	for _, seconds := range []int{MinDeploySLOSeconds, 30, 45, MaxDeploySLOSeconds} {
		waits := DeployWaits(seconds)
		if waits.Total() > time.Duration(seconds)*time.Second {
			t.Errorf("%d s budget authorises %s of waiting: %+v", seconds, waits.Total(), waits)
		}
	}
	// Out-of-range input is clamped rather than trusted: the root helper derives
	// its privileged waits from a value that travels in a signed plan.
	if DeployWaits(0).Total() > MinDeploySLOSeconds*time.Second {
		t.Error("a zero budget must clamp to the floor")
	}
	if DeployWaits(100000).Total() > MaxDeploySLOSeconds*time.Second {
		t.Error("an oversized budget must clamp to the ceiling")
	}
}

// retention.registry_cache used to be dead configuration: it was defaulted,
// pinned to "5GB" by validation, written into every generated file, and never
// read by anything that applied it. It is now parsed into the budget the root
// helper enforces on the VPS after each promotion, so a value that cannot be
// turned into bytes has to be refused, and a value that can must survive the
// round trip through the loader.
func TestRegistryCacheBudgetIsParsedAndBounded(t *testing.T) {
	cfg, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Retention.RegistryCacheBytes(); got != 5<<30 {
		t.Fatalf("the shipped 5GB budget must resolve to %d bytes, got %d", int64(5)<<30, got)
	}
	// The cap has to follow the disk the operator bought, so a larger VPS may
	// state a larger budget instead of being rejected for not saying "5GB".
	larger := strings.Replace(validConfig, "registry_cache: 5GB", "registry_cache: 20GB", 1)
	cfg, err = loadYAML(t, larger)
	if err != nil {
		t.Fatalf("a 20GB registry cache budget must be accepted: %v", err)
	}
	if got := cfg.Retention.RegistryCacheBytes(); got != 20<<30 {
		t.Fatalf("unexpected parsed budget %d", got)
	}
	for name, value := range map[string]string{
		"no unit":           "5",
		"not a number":      "manyGB",
		"below the floor":   "1GB",
		"above the ceiling": "4096GB",
		"zero":              "0GB",
	} {
		body := strings.Replace(validConfig, "registry_cache: 5GB", "registry_cache: "+value, 1)
		if _, err := loadYAML(t, body); err == nil {
			t.Errorf("%s (%q) must be rejected", name, value)
		}
	}
}

// Sizes are read as binary multiples so that build_cache_keep and
// registry_cache, both written "5GB" in the same file, mean the same number of
// bytes.
func TestParseByteSizeReadsBinaryMultiples(t *testing.T) {
	for value, want := range map[string]int64{
		"5GB": 5 << 30, "5gb": 5 << 30, " 5 GB ": 5 << 30,
		"512MB": 512 << 20, "2G": 2 << 30, "1024B": 1024, "1TB": 1 << 40,
	} {
		got, err := ParseByteSize(value)
		if err != nil || got != want {
			t.Errorf("ParseByteSize(%q) = %d, %v; want %d", value, got, err, want)
		}
	}
	for _, value := range []string{"", "GB", "-1GB", "5PB", "5.5GB", "0"} {
		if _, err := ParseByteSize(value); err == nil {
			t.Errorf("ParseByteSize(%q) must fail", value)
		}
	}
}

// setup.slo_seconds was validated as having to be exactly 600 while setup.go
// ignored it and used a hard-coded ten minutes, so the only setting the file
// offered about setup regulated nothing. It is now the budget setup measures
// itself against, which means an operator on a slow provider mirror must be
// able to raise it.
func TestSetupBudgetIsConfigurableWithinBounds(t *testing.T) {
	for _, seconds := range []int{MinSetupSLOSeconds, 600, 1800, MaxSetupSLOSeconds} {
		body := strings.Replace(validConfig, "slo_seconds: 600", "slo_seconds: "+strconv.Itoa(seconds), 1)
		cfg, err := loadYAML(t, body)
		if err != nil {
			t.Fatalf("a %d s setup budget must be accepted: %v", seconds, err)
		}
		if cfg.Setup.SLOSeconds != seconds {
			t.Errorf("loaded setup budget %d, want %d", cfg.Setup.SLOSeconds, seconds)
		}
	}
	for _, seconds := range []int{1, MinSetupSLOSeconds - 1, MaxSetupSLOSeconds + 1} {
		body := strings.Replace(validConfig, "slo_seconds: 600", "slo_seconds: "+strconv.Itoa(seconds), 1)
		if _, err := loadYAML(t, body); err == nil {
			t.Errorf("a %d s setup budget must be rejected", seconds)
		}
	}
}

// The empty default used to be re-derived by every reader on its own — the
// validator, the label emitted onto the published service, the scheme the root
// helper renders — and the origin proof never asked at all. One helper is what
// makes those readers incapable of disagreeing.
func TestEffectiveTLSModeCollapsesTheDefaultToACME(t *testing.T) {
	// The last entry is a value validation refuses at load: reaching here with
	// it would be a configuration nobody accepted, and answering "acme" for it
	// keeps the helper total rather than making every caller handle a third
	// case that cannot occur.
	for _, mode := range []string{"", "acme", "  acme  ", "unknown"} {
		cfg := &Config{Caddy: Caddy{TLSMode: mode}}
		if got := cfg.EffectiveTLSMode(); got != TLSModeACME {
			t.Errorf("tls_mode %q must serve %s, got %s", mode, TLSModeACME, got)
		}
	}
	for _, mode := range []string{"off", "  off  "} {
		cfg := &Config{Caddy: Caddy{TLSMode: mode}}
		if got := cfg.EffectiveTLSMode(); got != TLSModeOff {
			t.Errorf("tls_mode %q must serve %s, got %s", mode, TLSModeOff, got)
		}
	}
}
