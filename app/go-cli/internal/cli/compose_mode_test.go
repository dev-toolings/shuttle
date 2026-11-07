package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// demoLikeCompose is the shape of the archived Demo project: two built
// services, a pinned third-party image, a sidecar sharing the API image, host
// ports on the front end, an env_file, tmpfs and healthchecks everywhere.
const demoLikeCompose = `services:
  api:
    build:
      context: ./apps/api
    env_file: env/preprod.env
    environment:
      REDIS_URL: redis://redis:6379/0
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      MOTD: hello $$USER
    volumes:
      - uploads:/app/uploads
    healthcheck:
      test: ["CMD", "python", "-c", "import sys"]
      interval: 15s
    depends_on:
      - redis
  web:
    build:
      context: ./apps/web
      args:
        VITE_SUPPORT_URL: ${VITE_SUPPORT_URL:-https://support.example}
    ports:
      - "80:80"
      - "3000:80"
    tmpfs:
      - /config
      - /data
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:80/"]
    depends_on:
      - api
  redis:
    image: redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
  crm-poller:
    build:
      context: ./apps/api
    entrypoint: ["/bin/bash", "/app/poll.sh"]
    networks:
      - demo
    healthcheck:
      test:
        - CMD-SHELL
        - test -f /tmp/heartbeat && [ $$(( $$(date +%s) - 1 )) -lt 600 ]
volumes:
  uploads:
networks:
  demo:
    driver: overlay
`

func composeTestConfig(t *testing.T) *config.Config {
	t.Helper()
	body := `version: 2
app: demo
domain: app.staging.example.com
server:
  host: 203.0.113.3
  user: bob
  port: 22
  host_key: SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA
deploy:
  strategy: compose
  primary_service: web
  edge_proxy: true
  total_slo_seconds: 120
  promotion_slo_seconds: 120
  retain: 2
services:
  web:
    port: 80
    healthcheck:
      type: http
      path: /health
  api:
    port: 8000
    healthcheck:
      type: http
      path: /health
    resources:
      cpus: "2.0"
      memory: 3G
caddy:
  tls_mode: "off"
secrets:
  host:
    env_file: /opt/demo/.env
  items:
    JWT_SECRET_KEY:
      services: [api]
      expose: env
    S3_SECRET_ACCESS_KEY:
      services: [api, crm-poller]
      expose: file
readiness:
  preset: fastapi
  healthcheck_path: /health
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, "")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func composeTestProject(t *testing.T) (*composeFile, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "env"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env", "preprod.env"), []byte("APP_MODE=preproduction\nDATABASE_HOST=203.0.113.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	return parseComposeString(t, demoLikeCompose), dir
}

// The rendered project is what runs. Every service is hardened, built ones
// carry their tag and the rest their digest, host ports and depends_on stay,
// no Swarm-only key survives, and no variable is left for the host.
func TestComposeProjectRendersHardenedServicesWithoutHostInterpolation(t *testing.T) {
	cfg := composeTestConfig(t)
	parsed, _ := composeTestProject(t)
	t.Setenv("JWT_SECRET_KEY", "desk-value")
	t.Setenv("USER", "kevin")
	images := map[string]string{"api": "shuttle/demo-api:v1", "web": "shuttle/demo-web:v1", "crm-poller": "shuttle/demo-api:v1"}
	rendered, err := generateComposeProject(parsed, cfg, images, planComposeSecrets(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "${") {
		t.Fatalf("a variable was left for the host to interpolate:\n%s", rendered)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &root); err != nil {
		t.Fatal(err)
	}
	services := root["services"].(map[string]any)
	for _, name := range []string{"api", "web", "redis", "crm-poller"} {
		service := services[name].(map[string]any)
		if service["read_only"] != true || service["restart"] != "unless-stopped" {
			t.Fatalf("service %s is not hardened: %v", name, service)
		}
		if capDrop, _ := service["cap_drop"].([]any); len(capDrop) != 1 || capDrop[0] != "ALL" {
			t.Fatalf("service %s keeps capabilities: %v", name, service["cap_drop"])
		}
		if _, has := service["build"]; has {
			t.Fatalf("service %s still declares a build", name)
		}
		deploy := service["deploy"].(map[string]any)
		if _, has := deploy["update_config"]; has {
			t.Fatalf("service %s carries a Swarm update_config Compose would ignore", name)
		}
		if _, has := deploy["resources"]; !has {
			t.Fatalf("service %s has no resource limits", name)
		}
	}
	api := services["api"].(map[string]any)
	if api["image"] != "shuttle/demo-api:v1" {
		t.Fatalf("built image not applied: %v", api["image"])
	}
	environment := api["environment"].(map[string]any)
	if environment["APP_MODE"] != "preproduction" {
		t.Fatalf("env_file was not inlined: %v", environment)
	}
	if _, shadowed := environment["JWT_SECRET_KEY"]; shadowed {
		t.Fatalf("a secret delivered by env file is shadowed by the compose environment: %v", environment)
	}
	// YAML does not interpret `$$`; Compose on the host does, and reads it as
	// one literal dollar — so the file must carry the doubled form.
	if environment["MOTD"] != "hello $$USER" {
		t.Fatalf("a literal $$ must stay escaped for the host: %v", environment["MOTD"])
	}
	if envFiles, _ := api["env_file"].([]any); len(envFiles) != 1 || envFiles[0] != "secrets.env" {
		t.Fatalf("api must read its env secrets from the release directory: %v", api["env_file"])
	}
	poller := services["crm-poller"].(map[string]any)
	references, _ := poller["secrets"].([]any)
	if len(references) != 1 || references[0].(map[string]any)["source"] != "S3_SECRET_ACCESS_KEY" {
		t.Fatalf("file secret not mounted on crm-poller: %v", poller["secrets"])
	}
	topSecrets := root["secrets"].(map[string]any)
	if topSecrets["S3_SECRET_ACCESS_KEY"].(map[string]any)["file"] != "./secrets/S3_SECRET_ACCESS_KEY" {
		t.Fatalf("file secret source is not the release directory: %v", topSecrets)
	}
	web := services["web"].(map[string]any)
	if ports, _ := web["ports"].([]any); len(ports) != 2 {
		t.Fatalf("host ports must survive under compose: %v", web["ports"])
	}
	if _, has := web["depends_on"]; !has {
		t.Fatal("depends_on must survive under compose")
	}
	volumes, _ := web["volumes"].([]any)
	targets := []string{}
	for _, volume := range volumes {
		targets = append(targets, volume.(map[string]any)["target"].(string))
	}
	if strings.Join(targets, ",") != "/tmp,/config,/data" {
		t.Fatalf("tmpfs mounts = %v", targets)
	}
	// A Swarm overlay network cannot be created by a plain daemon: the driver
	// goes, the network stays.
	networks := root["networks"].(map[string]any)
	if network, _ := networks["demo"].(map[string]any); network != nil && network["driver"] == "overlay" {
		t.Fatalf("an overlay network must not survive under compose: %v", networks)
	}
	if _, declared := networks["demo"]; !declared {
		t.Fatal("the network must stay declared under its name")
	}
	if volumes, _ := root["volumes"].(map[string]any); volumes == nil || len(volumes) != 1 {
		t.Fatalf("named volumes declared with no options must survive: %v", root["volumes"])
	}
	// The raw text carries the escaped form: that is what the host reads.
	if !strings.Contains(rendered, "hello $$USER") || !strings.Contains(rendered, "$$(( $$(date") {
		t.Fatalf("dollar signs must be doubled in the file:\n%s", rendered)
	}
	if rendered != mustRenderAgain(t, parsed, cfg, images) {
		t.Fatal("the rendered project is not deterministic")
	}

	// A non-built image without a digest is refused, as is a missing
	// healthcheck: the same bar the Swarm stack sets.
	unpinned := parseComposeString(t, strings.Replace(demoLikeCompose, "redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf", "redis:7-alpine", 1))
	if _, err := generateComposeProject(unpinned, cfg, images, planComposeSecrets(cfg)); err == nil || !strings.Contains(err.Error(), "pinned by digest") {
		t.Fatalf("an unpinned third-party image must be refused: %v", err)
	}
	if _, err := generateComposeProject(parsed, cfg, map[string]string{"api": "x", "web": "y"}, planComposeSecrets(cfg)); err == nil || !strings.Contains(err.Error(), "no image was planned") {
		t.Fatalf("a built service with no planned image must be refused: %v", err)
	}
}

func mustRenderAgain(t *testing.T, parsed *composeFile, cfg *config.Config, images map[string]string) string {
	t.Helper()
	again := parseComposeString(t, demoLikeCompose)
	rendered, err := generateComposeProject(again, cfg, images, planComposeSecrets(cfg))
	if err != nil {
		t.Fatal(err)
	}
	_ = parsed
	return rendered
}

// Interpolation: resolved here, escaped for there, and `:?` finally means
// what the operator wrote.
func TestComposeValueExpansionResolvesLocallyAndEscapesForTheHost(t *testing.T) {
	t.Setenv("PASS", "a$b")
	t.Setenv("HOST_NAME", "db")
	os.Unsetenv("UNSET_VAR")
	for source, want := range map[string]string{
		"plain":                  "plain",
		"${PASS}":                "a$$b",
		"pg://${HOST_NAME}:5432": "pg://db:5432",
		"${UNSET_VAR:-fallback}": "fallback",
		"${UNSET_VAR-fallback}":  "fallback",
		"${HOST_NAME:-x}":        "db",
		"$HOST_NAME/$UNSET_VAR":  "db/",
		"$$HOME":                 "$$HOME",
		"cost $5":                "cost $$5",
		"${PASS:?must be set}":   "a$$b",
	} {
		got, err := expandComposeValue(source)
		if err != nil {
			t.Fatalf("%q: %v", source, err)
		}
		if got != want {
			t.Fatalf("%q expanded to %q, want %q", source, got, want)
		}
	}
	for _, source := range []string{"${UNSET_VAR:?database host is required}", "${UNSET_VAR?required}", "${UNSET"} {
		if _, err := expandComposeValue(source); err == nil {
			t.Fatalf("%q must be an error", source)
		}
	}
	if _, err := expandComposeValue("${UNSET_VAR:?database host is required}"); err == nil || !strings.Contains(err.Error(), "UNSET_VAR is required") {
		t.Fatalf("a :? guard must name the variable: %v", err)
	}
}

func TestComposePrimaryServiceMustPublishTheProvenPort(t *testing.T) {
	parsed := parseComposeString(t, demoLikeCompose)
	if !composePrimaryPublishesPort(parsed, "web", 80) {
		t.Fatal("web publishes 80:80")
	}
	if composePrimaryPublishesPort(parsed, "web", 443) || composePrimaryPublishesPort(parsed, "api", 80) {
		t.Fatal("ports that are not published must not be reported as published")
	}
	for entry, want := range map[string]int{"80:80": 80, "0.0.0.0:80:80": 80, "[::]:8080:80/tcp": 8080, "80": 0, "8000-8001:8000-8001": 8000} {
		if got := composePublishedHostPort(entry); got != want {
			t.Fatalf("%q → %d, want %d", entry, got, want)
		}
	}
}

// The host script reads only the declared keys, writes only under the
// release, and stops on a missing or empty key with the key named.
func TestComposeSecretsScriptMaterialisesDeclaredKeysOnly(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "host.env")
	if err := os.WriteFile(source, []byte("# host env\nexport JWT_SECRET_KEY=\"jwt-value\"\nS3_SECRET_ACCESS_KEY='s3 value'\nOTHER=not-declared\nEMPTY=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	releases := filepath.Join(dir, "releases")
	if err := os.MkdirAll(releases, 0o700); err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(releases, "v1")
	script := composeSecretsScript(source, release, []string{"JWT_SECRET_KEY", "S3_SECRET_ACCESS_KEY"}, []string{"JWT_SECRET_KEY"}, []string{"S3_SECRET_ACCESS_KEY"})
	for _, forbidden := range []string{"sudo", "OTHER", "/etc/"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("the secrets script must not contain %q", forbidden)
		}
	}
	parse := exec.Command("sh", "-n")
	parse.Stdin = strings.NewReader(script)
	if out, err := parse.CombinedOutput(); err != nil {
		t.Fatalf("secrets script does not parse: %v\n%s", err, out)
	}
	run := exec.Command("sh", "-s")
	run.Stdin = strings.NewReader(script)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("secrets script failed: %v\n%s", err, out)
	}
	envFile, err := os.ReadFile(filepath.Join(release, composeSecretsEnvFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(envFile) != "JWT_SECRET_KEY=jwt-value\n" {
		t.Fatalf("env file = %q", envFile)
	}
	fileSecret, err := os.ReadFile(filepath.Join(release, composeSecretsDir, "S3_SECRET_ACCESS_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	if string(fileSecret) != "s3 value" {
		t.Fatalf("file secret = %q", fileSecret)
	}
	info, _ := os.Stat(filepath.Join(release, composeSecretsDir, "S3_SECRET_ACCESS_KEY"))
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("file secret mode = %o, want 0444", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(filepath.Join(release, composeSecretsDir)); len(entries) != 1 {
		t.Fatalf("only the declared file secret must be written, found %d entries", len(entries))
	}

	// Missing and empty keys stop the run by name, and nothing is left behind.
	failing := composeSecretsScript(source, filepath.Join(releases, "v2"), []string{"JWT_SECRET_KEY", "EMPTY", "ABSENT"}, []string{"JWT_SECRET_KEY", "EMPTY", "ABSENT"}, nil)
	run = exec.Command("sh", "-s")
	run.Stdin = strings.NewReader(failing)
	out, err := run.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "EMPTY") || !strings.Contains(string(out), "ABSENT") || strings.Contains(string(out), "jwt-value") {
		t.Fatalf("missing keys must be named and values never printed: err=%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(releases, "v2", composeSecretsEnvFile)); !os.IsNotExist(err) {
		t.Fatal("a failed materialisation must leave no partial file")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(releases, "v2.secrets.*")); len(leftovers) != 0 {
		t.Fatalf("temporary directory left behind: %v", leftovers)
	}
}

// Remote commands are text: exact, always scoped by the project, never a
// bare prune.
func TestComposeRemoteCommandsAreScopedAndBounded(t *testing.T) {
	up := composeUpCommand("shuttle-demo", "/home/bob/.shuttle/demo/releases/v1/docker-compose.yml", 66*time.Second)
	if up != "docker compose -p 'shuttle-demo' -f '/home/bob/.shuttle/demo/releases/v1/docker-compose.yml' up -d --wait --wait-timeout 66 --remove-orphans" {
		t.Fatalf("up = %q", up)
	}
	if got := composeExecCommand("shuttle-demo", "api", []string{"alembic", "upgrade", "head", "it's"}); got != `docker compose -p 'shuttle-demo' exec -T 'api' 'alembic' 'upgrade' 'head' 'it'"'"'s'` {
		t.Fatalf("exec = %q", got)
	}
	if got := composeDownCommand("shuttle-demo", false); strings.Contains(got, "--volumes") {
		t.Fatalf("down must not remove volumes unless asked: %q", got)
	}
	if got := composeDownCommand("shuttle-demo", true); !strings.Contains(got, "--volumes") {
		t.Fatalf("down --volumes must be honoured: %q", got)
	}
	for name, program := range map[string]string{
		"retain":          composeRetainCommand("/home/bob/.shuttle/demo/releases", "demo"),
		"rotate":          composeRotateCommand("/home/bob/.shuttle/demo/releases", "v2", "v2"),
		"swap":            composeSwapCommand("/home/bob/.shuttle/demo/releases"),
		"load-recovery":   composeLoadRecoveryCommand("demo", []string{"shuttle/demo-api:v1"}),
		"load-recovery-0": composeLoadRecoveryCommand("demo", nil),
		"containers":      composeContainerImagesCommand("shuttle-demo"),
		"preflight":       composePreflightCommand,
		"secrets":         composeSecretsScript("/opt/demo/.env", "/home/bob/.shuttle/demo/releases/v1", []string{"A"}, []string{"A"}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			command := exec.Command("sh", "-n")
			command.Stdin = strings.NewReader(program)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("%s does not parse: %v\n%s\n%s", name, err, out, program)
			}
			for _, forbidden := range []string{"docker system prune", "prune -a", "sudo "} {
				if strings.Contains(program, forbidden) {
					t.Fatalf("%s contains %q", name, forbidden)
				}
			}
		})
	}
	retain := composeRetainCommand("/root", "demo")
	if !strings.Contains(retain, "--filter 'label=dev.shuttle.app=demo'") {
		t.Fatalf("the remote prune must be scoped by the application label:\n%s", retain)
	}
	if !strings.Contains(retain, `[ -L "$dir" ] && continue`) {
		t.Fatalf("the retention loop must never remove the current and previous links:\n%s", retain)
	}
	// Executed for real on a release root: the links survive, an old release
	// goes, the two retained stay. Docker calls are stubbed by an empty PATH.
	root := t.TempDir()
	for _, version := range []string{"v1", "v2", "v3"} {
		if err := os.MkdirAll(filepath.Join(root, version), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, version, "docker-compose.yml"), []byte("services:\n  web:\n    image: shuttle/demo-web:"+version+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("v3", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("v2", filepath.Join(root, "previous")); err != nil {
		t.Fatal(err)
	}
	stub := t.TempDir()
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := exec.Command("sh", "-s")
	run.Env = append(os.Environ(), "PATH="+stub+":/usr/bin:/bin")
	run.Stdin = strings.NewReader(composeRetainCommand(root, "demo"))
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("retention failed: %v\n%s", err, out)
	}
	for _, kept := range []string{"current", "previous", "v2", "v3"} {
		if _, err := os.Lstat(filepath.Join(root, kept)); err != nil {
			t.Fatalf("%s must survive retention: %v", kept, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "v1")); !os.IsNotExist(err) {
		t.Fatal("the release neither link points at must be removed")
	}
	for _, mutation := range []string{"apt-get", "install ", ">/etc", "docker "} {
		if strings.Contains(composePreflightCommand, mutation) && mutation != "docker " {
			t.Fatalf("the preflight must be read-only, found %q", mutation)
		}
	}
	if composeTransferTimeout(0) != 2*time.Minute || composeTransferTimeout(600<<20) != 12*time.Minute || composeTransferTimeout(100<<30) != 30*time.Minute {
		t.Fatalf("transfer timeout sizing is wrong: %v %v %v", composeTransferTimeout(0), composeTransferTimeout(600<<20), composeTransferTimeout(100<<30))
	}
}

func TestComposePreflightRefusesWhatTheStrategyCannotWorkWith(t *testing.T) {
	cfg := composeTestConfig(t)
	root := "/home/bob/.shuttle/demo/releases"
	good := "user=bob\nhome=/home/bob\ndocker=28.1.1\ncompose=v2.35.1\ndriver=overlay2\narch=x86_64\nstore=Backing Filesystem=extfs;\ndisk_free_percent=37\nmeminfo=MemTotal: 8134208 kB;MemAvailable: 5340000 kB;\nprojects=[{\"Name\":\"demo-fastapi-backend\",\"Status\":\"running(6)\",\"ConfigFiles\":\"/opt/demo/docker-compose.yml\"}]\n"
	report, err := parseComposePreflight(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkComposePreflight(report, cfg, root); err != nil {
		t.Fatalf("a sound host must pass: %v", err)
	}
	for name, tc := range map[string]struct{ body, want string }{
		"no docker":    {strings.Replace(good, "docker=28.1.1", "docker=unreachable", 1), "docker group"},
		"old compose":  {strings.Replace(good, "compose=v2.35.1", "compose=v2.17.0", 1), "v2.20 or later"},
		"no compose":   {strings.Replace(good, "compose=v2.35.1", "compose=none", 1), "v2.20 or later"},
		"containerd":   {strings.Replace(good, "store=Backing Filesystem=extfs;", "store=driver-type=io.containerd.snapshotter.v1;", 1), ""},
		"compose 5":    {strings.Replace(good, "compose=v2.35.1", "compose=5.5.1", 1), ""},
		"name taken":   {strings.Replace(good, `"Name":"demo-fastapi-backend"`, `"Name":"shuttle-demo"`, 1), "already runs on the host from /opt/demo/docker-compose.yml"},
		"own project":  {strings.Replace(good, `"Name":"demo-fastapi-backend","Status":"running(6)","ConfigFiles":"/opt/demo/docker-compose.yml"`, `"Name":"shuttle-demo","Status":"running(6)","ConfigFiles":"`+root+`/v0/docker-compose.yml"`, 1), ""},
		"missing home": {strings.Replace(good, "home=/home/bob", "home=", 1), "deploy account and its home"},
		"unknown arch": {strings.Replace(good, "arch=x86_64", "arch=riscv64", 1), "does not know how to build for"},
		"disk":         {strings.Replace(good, "disk_free_percent=37", "disk_free_percent=14", 1), "14% disk free, minimum is 20%"},
		"disk unread":  {strings.Replace(good, "disk_free_percent=37", "disk_free_percent=", 1), "cannot verify remote free-disk policy"},
		"bad json":     {strings.Replace(good, "projects=[", "projects=[oops", 1), "compose project list"},
	} {
		t.Run(name, func(t *testing.T) {
			report, err := parseComposePreflight(tc.body)
			if err == nil {
				err = checkComposePreflight(report, cfg, root)
			}
			if tc.want == "" {
				if err != nil {
					t.Fatalf("must pass: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

// An image built for the workstation's architecture loads fine on a host of
// another and fails at exec: the platform is the host's, always.
// The preflight carries the memory figures, in the shape parseMemInfo reads.
func TestComposePreflightCarriesMemoryFigures(t *testing.T) {
	report, err := parseComposePreflight("user=k\nhome=/home/k\ndocker=1\ncompose=5.5.1\narch=x86_64\ndisk_free_percent=40\nmeminfo=MemTotal: 8134208 kB;MemAvailable: 5340000 kB;\nprojects=[]\n")
	if err != nil {
		t.Fatal(err)
	}
	total, available, err := parseMemInfo(report.MemInfo)
	if err != nil || total != 8134208*1024 || available != 5340000*1024 {
		t.Fatalf("meminfo not carried: total=%d available=%d err=%v", total, available, err)
	}
}

// --pull is skipped only where it could change nothing.
func TestBuildSkipsPullOnlyWhenEveryBaseIsPinned(t *testing.T) {
	dir := t.TempDir()
	pinned := filepath.Join(dir, "pinned.Dockerfile")
	unpinned := filepath.Join(dir, "unpinned.Dockerfile")
	if err := os.WriteFile(pinned, []byte("FROM python:3.14-slim@sha256:"+strings.Repeat("a", 64)+" AS builder\nRUN true\nFROM builder AS final\nFROM --platform=linux/amd64 caddy:2-alpine@sha256:"+strings.Repeat("b", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unpinned, []byte("FROM python:3.14-slim@sha256:"+strings.Repeat("a", 64)+" AS builder\nFROM caddy:2-alpine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !dockerfileBasesPinned(pinned) {
		t.Fatal("every base of the pinned Dockerfile carries a digest; stage references are not bases")
	}
	if dockerfileBasesPinned(unpinned) || dockerfileBasesPinned(filepath.Join(dir, "missing")) {
		t.Fatal("an unpinned base, or an unreadable Dockerfile, must keep --pull")
	}
	if got := withoutArg([]string{"build", "--pull", "-t", "x"}, "--pull"); strings.Join(got, " ") != "build -t x" {
		t.Fatalf("withoutArg = %v", got)
	}
}

func TestComposePlatformFollowsTheHost(t *testing.T) {
	for arch, want := range map[string]string{"x86_64": "linux/amd64", "amd64": "linux/amd64", "aarch64": "linux/arm64", "arm64": "linux/arm64"} {
		got, err := composePlatform(arch)
		if err != nil || got != want {
			t.Fatalf("%s → %q (%v), want %q", arch, got, err, want)
		}
	}
	if _, err := composePlatform(""); err == nil {
		t.Fatal("an unreported architecture must be refused")
	}
}

// Where the build runs follows the architectures unless the operator says.
func TestComposeBuildLocationFollowsTheArchitectures(t *testing.T) {
	if got := resolveComposeBuildLocation(config.ComposeBuildAuto, "linux/amd64", "linux/arm64"); got != config.ComposeBuildHost {
		t.Fatalf("auto with different architectures must build on the host, got %q", got)
	}
	if got := resolveComposeBuildLocation(config.ComposeBuildAuto, "linux/amd64", "linux/amd64"); got != config.ComposeBuildLocal {
		t.Fatalf("auto with one architecture must build locally, got %q", got)
	}
	if got := resolveComposeBuildLocation(config.ComposeBuildLocal, "linux/amd64", "linux/arm64"); got != config.ComposeBuildLocal {
		t.Fatalf("an explicit local must be honoured, got %q", got)
	}
	listing := "# Host 203.0.113.3 found: line 12 \n203.0.113.3 ED25519 SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA\n"
	if !knownHostsHoldsFingerprint(listing, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA") {
		t.Fatal("the pinned fingerprint is in known_hosts")
	}
	if knownHostsHoldsFingerprint(listing, "SHA256:"+strings.Repeat("A", 43)) || knownHostsHoldsFingerprint("203.0.113.3 RSA SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA\n", "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA") {
		t.Fatal("another fingerprint, or another key type, must not pass")
	}
}

func TestComposeReleaseIdentityComparesBuiltServicesOnly(t *testing.T) {
	wanted := map[string]string{"api": "sha256:aaaa", "web": "sha256:bbbb"}
	report := parseComposeContainerImages("api\trunning\tsha256:aaaa\tshuttle/demo-api:v1\tsha256:aaaa\nweb\trunning\tsha256:bbbb\tshuttle/demo-web:v1\tsha256:bbbb\nredis\trunning\tsha256:cccc\tredis@sha256:cccc\tsha256:cccc\n")
	if complaints := compareComposeRelease(wanted, report); complaints != nil {
		t.Fatalf("a matching release must pass: %v", complaints)
	}
	if len(report) != 3 || report[0].Reference != "shuttle/demo-api:v1" || report[0].ReferenceID != "sha256:aaaa" {
		t.Fatalf("the report must carry the reference and what it resolves to: %+v", report)
	}
	if rows := parseComposeContainerImages("api\trunning\tsha256:aaaa\n"); len(rows) != 0 {
		t.Fatalf("a row without the reference columns is not a report of this version: %+v", rows)
	}
	stale := parseComposeContainerImages("api\trunning\tsha256:0000\tshuttle/demo-api:v1\tsha256:0000\nweb\texited\tsha256:bbbb\tshuttle/demo-web:v1\tsha256:bbbb\n")
	complaints := compareComposeRelease(map[string]string{"api": "sha256:aaaa", "web": "sha256:bbbb", "worker": "sha256:dddd"}, stale)
	if len(complaints) != 3 || !strings.Contains(complaints[0], "api: running 0000") || !strings.Contains(complaints[1], "web: container is exited") || !strings.Contains(complaints[2], "worker: the project reports no container") {
		t.Fatalf("complaints = %v", complaints)
	}
	if images := composeReleaseImages("services:\n  api:\n    image: \"shuttle/demo-api:v1\"\n  redis:\n    image: redis@sha256:abc\n"); strings.Join(images, ",") != "redis@sha256:abc,shuttle/demo-api:v1" {
		t.Fatalf("release images = %v", images)
	}
}

// The identity record of a compose host is the host key alone, and it cannot
// be mistaken for, or replaced by, a setup record.
func TestComposeHostIdentityIsKeptApartFromSetup(t *testing.T) {
	// os.UserConfigDir reads HOME on macOS and XDG_CONFIG_HOME on Linux; both
	// are pointed at a scratch directory so no real record is read or written.
	scratch := t.TempDir()
	t.Setenv("HOME", scratch)
	t.Setenv("XDG_CONFIG_HOME", scratch)
	key := "SHA256:" + strings.Repeat("A", 43)
	if _, found, err := loadComposeHostIdentity("203.0.113.3", 22); err != nil || found {
		t.Fatalf("an absent record is not an error: found=%t err=%v", found, err)
	}
	if err := saveTrustedHostIdentity(trustedHostIdentity{Version: 2, Host: "203.0.113.3", Port: 22, HostKeyFingerprint: key, Mode: hostIdentityModeCompose}); err != nil {
		t.Fatal(err)
	}
	record, found, err := loadComposeHostIdentity("203.0.113.3", 22)
	if err != nil || !found || record.HostKeyFingerprint != key {
		t.Fatalf("compose record not read back: found=%t err=%v %+v", found, err, record)
	}
	if _, err := loadTrustedHostIdentity("203.0.113.3", 22); err == nil || !strings.Contains(err.Error(), "deploy.strategy: compose") {
		t.Fatalf("a signed operation must refuse a compose record by name: %v", err)
	}
	if err := saveTrustedHostIdentity(trustedHostIdentity{Version: 2, Host: "203.0.113.3", Port: 22, HostKeyFingerprint: key, OperatorKeyFingerprint: "SHA256:" + strings.Repeat("B", 43)}); err == nil || !strings.Contains(err.Error(), "must not set up") {
		t.Fatalf("setup must refuse to overwrite a compose record: %v", err)
	}

	setup := trustedHostIdentity{Version: 2, Host: "203.0.113.10", Port: 22, HostKeyFingerprint: key, OperatorKeyFingerprint: "SHA256:" + strings.Repeat("B", 43)}
	if err := saveTrustedHostIdentity(setup); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadComposeHostIdentity("203.0.113.10", 22); err == nil || !strings.Contains(err.Error(), "was set up by Shuttle") {
		t.Fatalf("a compose deploy must refuse a setup host: %v", err)
	}
	if err := saveTrustedHostIdentity(trustedHostIdentity{Version: 2, Host: "203.0.113.10", Port: 22, HostKeyFingerprint: key, Mode: hostIdentityModeCompose}); err == nil || !strings.Contains(err.Error(), "was set up by Shuttle") {
		t.Fatalf("a compose record must not replace a setup record: %v", err)
	}
	if loaded, err := loadTrustedHostIdentity("203.0.113.10", 22); err != nil || loaded.OperatorKeyFingerprint != setup.OperatorKeyFingerprint {
		t.Fatalf("the setup record must read as before: %v %+v", err, loaded)
	}
}

// The compose strategy is refused by every command that needs the helper,
// with the strategy named.
func TestComposeStrategyIsRefusedByCommandsThatNeedTheHelper(t *testing.T) {
	cfg := composeTestConfig(t)
	dir := filepath.Dir(cfgPathOf(t, cfg))
	for _, args := range [][]string{
		{"setup", "--target", "root@203.0.113.3:22", "--expected-host-key", "SHA256:" + strings.Repeat("A", 43), "--public-key", writeOperatorPublicKey(t), "--dry-run"},
	} {
		cmd := NewRootCommand()
		cmd.SetOut(&strings.Builder{})
		cmd.SetErr(&strings.Builder{})
		cmd.SetArgs(append(args, "--config", filepath.Join(dir, "config.json")))
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "deploy.strategy: compose") {
			t.Fatalf("%v must refuse a compose configuration by name, got %v", args[0], err)
		}
	}
}

// cfgPathOf rewrites the configuration next to a temporary directory so a
// command can be pointed at it.
func cfgPathOf(t *testing.T, cfg *config.Config) string {
	t.Helper()
	dir := t.TempDir()
	body := `{"version": 2, "app": "demo", "domain": "app.staging.example.com",
"server": {"host": "203.0.113.3", "user": "bob", "port": 22, "host_key": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"},
"deploy": {"strategy": "compose", "primary_service": "web", "retain": 2, "total_slo_seconds": 120, "promotion_slo_seconds": 120},
"services": {"web": {"port": 80, "healthcheck": {"type": "http", "path": "/health"}}},
"caddy": {"tls_mode": "off"},
"readiness": {"preset": "fastapi", "healthcheck_path": "/health"}}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = cfg
	return path
}

// A built service whose new tag is the image it already runs keeps the
// reference it runs, so the rendered service is the one Compose already has
// and the container is left alone. Anything the daemon does not confirm — a
// different image, a reference that no longer resolves to it, a container
// that is not there, a reference outside the repository this run built —
// gets the new tag, which is a recreation and nothing worse.
func TestComposeUnchangedImagesKeepTheReferenceAlreadyRunning(t *testing.T) {
	planned := map[string]string{
		"api":        "shuttle/demo-api:v2-20261105T120000000000002",
		"crm-poller": "shuttle/demo-api:v2-20261105T120000000000002",
		"web":        "shuttle/demo-web:v2-20261105T120000000000002",
		"backup":     "shuttle/demo-backup:v2-20261105T120000000000002",
		"worker":     "shuttle/demo-worker:v2-20261105T120000000000002",
		"stranger":   "shuttle/demo-stranger:v2-20261105T120000000000002",
	}
	built := map[string]string{
		"shuttle/demo-api:v2-20261105T120000000000002":      "sha256:aaaa",
		"shuttle/demo-web:v2-20261105T120000000000002":      "sha256:bbbb",
		"shuttle/demo-backup:v2-20261105T120000000000002":   "sha256:cccc",
		"shuttle/demo-worker:v2-20261105T120000000000002":   "sha256:dddd",
		"shuttle/demo-stranger:v2-20261105T120000000000002": "sha256:eeee",
	}
	running := parseComposeContainerImages(strings.Join([]string{
		// Same image under the previous tag: kept, for both services using it.
		"api\trunning\tsha256:aaaa\tshuttle/demo-api:v1-20261105T120000000000001\tsha256:aaaa",
		"crm-poller\trunning\tsha256:aaaa\tshuttle/demo-api:v1-20261105T120000000000001\tsha256:aaaa",
		// The code changed: the new tag.
		"web\trunning\tsha256:b000\tshuttle/demo-web:v1-20261105T120000000000001\tsha256:b000",
		// Same image, but the old tag was re-pointed since: the new tag.
		"backup\trunning\tsha256:cccc\tshuttle/demo-backup:v1-20261105T120000000000001\tsha256:c111",
		// Same image, started by hand from another repository: the new tag.
		"stranger\trunning\tsha256:eeee\tsomebody/stranger:latest\tsha256:eeee",
		// Not a built service: never considered.
		"redis\trunning\tsha256:ffff\tredis@sha256:ffff\tsha256:ffff",
	}, "\n"))
	images, reused := reuseRunningImages(planned, built, running)
	want := map[string]string{
		"api":        "shuttle/demo-api:v1-20261105T120000000000001",
		"crm-poller": "shuttle/demo-api:v1-20261105T120000000000001",
		"web":        "shuttle/demo-web:v2-20261105T120000000000002",
		"backup":     "shuttle/demo-backup:v2-20261105T120000000000002",
		"worker":     "shuttle/demo-worker:v2-20261105T120000000000002",
		"stranger":   "shuttle/demo-stranger:v2-20261105T120000000000002",
	}
	for service, image := range want {
		if images[service] != image {
			t.Fatalf("%s: rendered %q, want %q", service, images[service], image)
		}
	}
	if len(images) != len(want) {
		t.Fatalf("every planned service must be mapped: %v", images)
	}
	if strings.Join(reused, ",") != "api,crm-poller" {
		t.Fatalf("reused = %v", reused)
	}
	// A first deploy, or an unreadable report, changes nothing.
	images, reused = reuseRunningImages(planned, built, nil)
	if len(reused) != 0 || images["api"] != "shuttle/demo-api:v2-20261105T120000000000002" {
		t.Fatalf("with nothing running every service gets its tag: %v %v", images, reused)
	}
	// The same reference rendered twice is the same service hash for Compose:
	// what the previous release wrote is byte for byte what this one writes.
	cfg := composeTestConfig(t)
	parsed, _ := composeTestProject(t)
	secrets := planComposeSecrets(cfg)
	previous, err := generateComposeProject(parsed, cfg, map[string]string{"api": "shuttle/demo-api:v1-20261105T120000000000001", "crm-poller": "shuttle/demo-api:v1-20261105T120000000000001", "web": "shuttle/demo-web:v1-20261105T120000000000001"}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	next, err := generateComposeProject(parsed, cfg, map[string]string{"api": "shuttle/demo-api:v1-20261105T120000000000001", "crm-poller": "shuttle/demo-api:v1-20261105T120000000000001", "web": "shuttle/demo-web:v2-20261105T120000000000002"}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(next, "image: shuttle/demo-api:v1-20261105T120000000000001") || !strings.Contains(next, "image: shuttle/demo-web:v2-20261105T120000000000002") {
		t.Fatalf("the reused reference and the new tag must both be rendered:\n%s", next)
	}
	if strings.Count(previous, "shuttle/demo-api:v1-20261105T120000000000001") != strings.Count(next, "shuttle/demo-api:v1-20261105T120000000000001") {
		t.Fatalf("the reused service must be rendered exactly as before:\nprevious:\n%s\nnext:\n%s", previous, next)
	}
	// The report the host produces has the five columns the parser reads, on
	// a daemon stubbed to answer the three docker calls the script makes.
	stub := t.TempDir()
	script := `#!/bin/sh
case "$1 $2" in
  "compose -p") printf 'c1\nc2\n' ;;
  "inspect --format")
    case "$3" in
      *Config.Image*) if [ "$4" = c1 ]; then printf 'api\trunning\tsha256:aaaa\tshuttle/demo-api:v1-20261105T120000000000001\n'; else printf 'redis\trunning\tsha256:ffff\tredis@sha256:ffff\n'; fi ;;
    esac ;;
  "image inspect") if [ "$5" = shuttle/demo-api:v1-20261105T120000000000001 ]; then printf 'sha256:aaaa\n'; else exit 1; fi ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	run := exec.Command("sh", "-s")
	run.Env = append(os.Environ(), "PATH="+stub+":/usr/bin:/bin")
	run.Stdin = strings.NewReader(composeContainerImagesCommand("shuttle-demo"))
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("container report failed: %v\n%s", err, out)
	}
	rows := parseComposeContainerImages(string(out))
	if len(rows) != 2 || rows[0] != (composeContainerImage{Service: "api", State: "running", ImageID: "sha256:aaaa", Reference: "shuttle/demo-api:v1-20261105T120000000000001", ReferenceID: "sha256:aaaa"}) || rows[1].ReferenceID != "" {
		t.Fatalf("report rows = %+v\n%s", rows, out)
	}
}
