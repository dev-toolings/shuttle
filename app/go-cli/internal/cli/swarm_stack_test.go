package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func TestStackPromotionErrorCarriesHelperRefusalReason(t *testing.T) {
	stderr := "setup diagnostics\n" + rootPreflightRefusalMarker + "Redis image has no retained source\n"
	err := stackPromotionError(stderr)
	var refusal *stackRefusedBeforeMutation
	if !errors.As(err, &refusal) {
		t.Fatalf("helper refusal was not typed: %T %v", err, err)
	}
	if refusal.reason != "Redis image has no retained source" {
		t.Fatalf("typed refusal reason=%q", refusal.reason)
	}
	if err.Error() != "signed stack promotion failed: "+strings.TrimSpace(stderr) {
		t.Fatalf("promotion error message changed: %q", err)
	}
	if got := stackPromotionError("docker transport closed"); got.Error() != "signed stack promotion failed: docker transport closed" {
		t.Fatalf("unmarked promotion error changed: %q", got)
	}
}

func TestPromoteResponseFirstReleaseIsOptional(t *testing.T) {
	if !firstReleaseFromPromoteResponse(`{"first_release":true}`) {
		t.Fatal("first release response was not recognized")
	}
	for _, oldResponse := range []string{"", "operation=stack-apply digest=sha256:abc", `{"ok":true}`} {
		if firstReleaseFromPromoteResponse(oldResponse) {
			t.Errorf("response without first_release was treated as a first release: %q", oldResponse)
		}
	}
}

func TestOperationLabelJSONKeepsBackupDefaultBytes(t *testing.T) {
	without := map[string]config.Operation{"migrate": {Service: "api", Command: []string{"php", "migrate"}}}
	body, err := json.Marshal(without)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"migrate":{"service":"api","command":["php","migrate"]}}`
	if string(body) != want {
		t.Fatalf("operation label default bytes changed: got %s want %s", body, want)
	}
	with := map[string]config.Operation{"migrate": {Service: "api", Command: []string{"php", "migrate"}, BackupBefore: true}}
	body, err = json.Marshal(with)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"migrate":{"service":"api","command":["php","migrate"],"backup_before":true}}`
	if string(body) != want {
		t.Fatalf("backup policy label bytes mismatch: got %s want %s", body, want)
	}
}

func TestRabbitMQStackUsesMountedSecretAndRemainsHardened(t *testing.T) {
	doc := infrastructureStack(t, config.ProductionConfig{RabbitMQ: true})
	service := generatedService(t, doc, "rabbitmq")
	runtime := infrastructureRuntimeFor("rabbitmq")
	image, _ := service["image"].(string)
	if !strings.HasPrefix(image, "rabbitmq:4-alpine@sha256:") || service["user"] != runtime.user() {
		t.Fatalf("RabbitMQ image or user changed: image=%v user=%v", service["image"], service["user"])
	}
	if _, ok := service["healthcheck"]; !ok {
		t.Fatal("RabbitMQ healthcheck is missing")
	}
	if service["read_only"] != true || service["cap_drop"].([]any)[0] != "ALL" || service["security_opt"].([]any)[0] != "no-new-privileges:true" {
		t.Fatalf("RabbitMQ hardening changed: %#v", service)
	}
	hasTmpfs := false
	for _, mount := range service["volumes"].([]any) {
		if volume, ok := mount.(map[string]any); ok && volume["target"] == mandatoryTmpfsPath && volume["type"] == "tmpfs" {
			hasTmpfs = true
		}
	}
	if !hasTmpfs {
		t.Fatal("RabbitMQ must retain the mandatory /tmp tmpfs")
	}
	if volumes := service["volumes"].([]any); volumes[0] != "demo_rabbitmq_data:/var/lib/rabbitmq" {
		t.Fatalf("RabbitMQ data volume changed: %#v", volumes)
	}

	command, ok := service["command"].([]any)
	if !ok || len(command) != 3 || command[0] != "/bin/sh" || command[1] != "-ec" {
		t.Fatalf("RabbitMQ must start through the shell wrapper, got %#v", service["command"])
	}
	stackScript, ok := command[2].(string)
	if !ok {
		t.Fatalf("RabbitMQ command script has type %T", command[2])
	}
	script := strings.ReplaceAll(stackScript, "$$", "$")
	scriptFile := filepath.Join(t.TempDir(), "rabbitmq-entrypoint.sh")
	if err := os.WriteFile(scriptFile, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", scriptFile).CombinedOutput(); err != nil {
		t.Fatalf("generated RabbitMQ command is not valid shell: %v\n%s\n%s", err, out, script)
	}
	if !strings.Contains(script, "'/run/secrets/RABBITMQ_PASSWORD'") || !strings.Contains(script, "'/etc/rabbitmq/conf.d'") || !strings.Contains(script, "'/tmp/shuttle-rabbitmq-conf.d'") {
		t.Fatalf("RabbitMQ script paths differ from the production contract:\n%s", script)
	}
	if environment, ok := service["environment"].(map[string]any); ok {
		for key := range environment {
			if strings.HasPrefix(key, "RABBITMQ_") {
				t.Fatalf("RabbitMQ must not set image environment variable %s", key)
			}
		}
	}

	secrets := service["secrets"].([]any)
	if len(secrets) != 1 {
		t.Fatalf("RabbitMQ must retain one mounted secret, got %#v", secrets)
	}
	secret := secrets[0].(map[string]any)
	if secret["source"] != "demo_rabbitmq_password_v1" || secret["target"] != "RABBITMQ_PASSWORD" || secret["uid"] != "100" || secret["gid"] != "101" || secret["mode"] != 0o400 {
		t.Fatalf("RabbitMQ secret reference changed: %#v", secret)
	}
}

// The root helper refuses any stack payload holding "${" (validateRootStack).
// Unit tests that only reverse the $$ escaping missed it, and the first VM
// deploy with production.rabbitmq failed on it (2026-10-27), so every managed
// infrastructure service is checked against the helper's own validator.
func TestManagedInfrastructureStackPassesRootHelperValidation(t *testing.T) {
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
`
	cfg := &config.Config{Version: 2, App: "demo", Domain: "demo.example.com", Production: config.ProductionConfig{Redis: true, RabbitMQ: true}}
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, false); err != nil {
		t.Fatal(err)
	}
	out, err := secureStack(body, cfg, "8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRootStack([]byte(out)); err != nil {
		t.Fatalf("generated stack with Redis and RabbitMQ is refused by the root helper: %v", err)
	}
}

func TestRabbitMQDefaultsRemainByteIdenticalWhenDisabled(t *testing.T) {
	body := `services:
  web:
    image: demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    healthcheck: {test: ["CMD", "true"]}
`
	got, err := secureStack(body, &config.Config{Version: 2, App: "demo", Domain: "demo.example.com"}, "8080")
	if err != nil {
		t.Fatal(err)
	}
	const want = `services:
    web:
        cap_drop:
            - ALL
        deploy:
            labels:
                dev.shuttle.domain: demo.example.com
                dev.shuttle.port: "8080"
            replicas: 1
            resources:
                limits:
                    cpus: "1.0"
                    memory: 768M
                reservations:
                    memory: 64M
            restart_policy:
                condition: any
                delay: 5s
                max_attempts: 0
            rollback_config:
                order: start-first
                parallelism: 1
            update_config:
                failure_action: rollback
                monitor: 5s
                order: start-first
                parallelism: 1
        healthcheck:
            test:
                - CMD
                - "true"
        image: demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        logging:
            driver: json-file
            options:
                max-file: "3"
                max-size: 10m
        read_only: true
        security_opt:
            - no-new-privileges:true
        volumes:
            - target: /tmp
              tmpfs:
                size: 67108864
              type: tmpfs
`
	if got != want {
		t.Fatalf("production.rabbitmq false changed the default stack bytes:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestSwarmRestartPolicy(t *testing.T) {
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
  worker:
    image: demo@sha256:` + strings.Repeat("b", 64) + `
    healthcheck: {test: ["CMD", "true"]}
`
	cfg := &config.Config{
		Version:    2,
		App:        "demo",
		Domain:     "demo.example.com",
		Production: config.ProductionConfig{Redis: true, RabbitMQ: true},
	}
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, false); err != nil {
		t.Fatal(err)
	}
	stack, err := secureStack(body, cfg, "8080")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(stack), &document); err != nil {
		t.Fatal(err)
	}
	services, ok := document["services"].(map[string]any)
	if !ok {
		t.Fatalf("generated stack has no services map: %#v", document)
	}
	wantServices := map[string]bool{"web": false, "worker": false, "redis": false, "rabbitmq": false}
	if len(services) != len(wantServices) {
		t.Fatalf("generated services = %v, want %v", services, wantServices)
	}
	for name, raw := range services {
		if _, expected := wantServices[name]; !expected {
			t.Errorf("unexpected generated service %q", name)
		}
		service, _ := raw.(map[string]any)
		deploy, _ := service["deploy"].(map[string]any)
		policy, _ := deploy["restart_policy"].(map[string]any)
		if policy["condition"] != "any" || policy["delay"] != "5s" || policy["max_attempts"] != 0 {
			t.Errorf("%s restart_policy = %#v, want condition any, delay 5s, max_attempts 0", name, policy)
		}
		wantServices[name] = true
	}
	for name, found := range wantServices {
		if !found {
			t.Errorf("expected service %q was not generated", name)
		}
	}

	for _, mode := range []string{"replicated-job", "global-job"} {
		policy := swarmRestartPolicy(map[string]any{"mode": mode})
		if policy["condition"] != "on-failure" {
			t.Errorf("%s restart condition = %v, want on-failure", mode, policy["condition"])
		}
	}
}

func TestRabbitMQEntrypointWritesValidatedConfigAndExecsImage(t *testing.T) {
	const password = "valid_ABC-123"
	h := newRabbitScriptHarness(t, []byte(password), true)
	h.writeDefaults(t)
	if out, err := h.run(); err != nil {
		t.Fatalf("valid RabbitMQ secret was refused: %v\n%s", err, out)
	}

	defaults, err := os.ReadFile(filepath.Join(h.generatedConfDir, "10-defaults.conf"))
	if err != nil {
		t.Fatal(err)
	}
	wantDefaults := "# retained default\nlog.console = true\nlog.file = false\n"
	if string(defaults) != wantDefaults {
		t.Fatalf("copied image defaults did not drop exactly the guest setting: got %q want %q", defaults, wantDefaults)
	}
	credentialPath := filepath.Join(h.generatedConfDir, "90-shuttle-credentials.conf")
	credentials, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	wantCredentials := "default_user = shuttle\ndefault_pass = " + password + "\n"
	if string(credentials) != wantCredentials {
		t.Fatalf("RabbitMQ credentials config mismatch: got %q want %q", credentials, wantCredentials)
	}
	info, err := os.Stat(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("RabbitMQ credentials config mode = %04o, want 0600", got)
	}

	args, err := os.ReadFile(h.argsCapture)
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "rabbitmq-server\n" {
		t.Fatalf("entrypoint argv = %q, want rabbitmq-server", args)
	}
	environment, err := os.ReadFile(h.envCapture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(environment), "RABBITMQ_CONFIG_FILES="+h.generatedConfDir+"\n") {
		t.Fatalf("entrypoint environment is missing the generated config path: %s", environment)
	}
	if strings.Contains(string(args), password) || strings.Contains(string(environment), password) {
		t.Fatal("RabbitMQ password reached entrypoint argv or environment")
	}
}

func TestRabbitMQEntrypointRejectsMalformedSecretsWithoutWritingConfig(t *testing.T) {
	cases := []struct {
		name   string
		secret []byte
		create bool
	}{
		{name: "missing"},
		{name: "empty", create: true},
		{name: "embedded newline", secret: []byte("first\nsecond"), create: true},
		{name: "trailing newline", secret: []byte("trailing\n"), create: true},
		{name: "space", secret: []byte("has space"), create: true},
		{name: "equals", secret: []byte("has=equals"), create: true},
		{name: "hash", secret: []byte("has#hash"), create: true},
		{name: "nul byte", secret: []byte{'a', 0, 'b'}, create: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRabbitScriptHarness(t, tc.secret, tc.create)
			out, err := h.run()
			if err == nil {
				t.Fatalf("malformed secret was accepted; output: %s", out)
			}
			if !strings.Contains(string(out), "RABBITMQ_PASSWORD") {
				t.Fatalf("failure must identify the secret without exposing it: %s", out)
			}
			if len(tc.secret) > 0 && strings.Contains(string(out), string(tc.secret)) {
				t.Fatalf("failure output contains secret bytes: %q", out)
			}
			if entries, readErr := os.ReadDir(h.generatedConfDir); readErr == nil && len(entries) != 0 {
				t.Fatalf("refused secret wrote configuration files: %#v", entries)
			} else if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatalf("could not inspect generated config directory: %v", readErr)
			}
		})
	}
}

type rabbitScriptHarness struct {
	secretPath       string
	defaultConfDir   string
	generatedConfDir string
	argsCapture      string
	envCapture       string
	stubDir          string
	path             string
	script           string
}

func newRabbitScriptHarness(t *testing.T, secret []byte, createSecret bool) rabbitScriptHarness {
	t.Helper()
	root := t.TempDir()
	h := rabbitScriptHarness{
		secretPath:       filepath.Join(root, "secrets", "RABBITMQ_PASSWORD"),
		defaultConfDir:   filepath.Join(root, "image", "conf.d"),
		generatedConfDir: filepath.Join(root, "tmp", "shuttle-rabbitmq-conf.d"),
		argsCapture:      filepath.Join(root, "entrypoint-args"),
		envCapture:       filepath.Join(root, "entrypoint-env"),
		stubDir:          filepath.Join(root, "bin"),
	}
	for _, dir := range []string{filepath.Dir(h.secretPath), h.defaultConfDir, h.stubDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if createSecret {
		if err := os.WriteFile(h.secretPath, secret, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGS_CAPTURE\"\nenv > \"$ENV_CAPTURE\"\n"
	if err := os.WriteFile(filepath.Join(h.stubDir, "docker-entrypoint.sh"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	path := h.stubDir + string(os.PathListSeparator) + os.Getenv("PATH")
	h.script = strings.ReplaceAll(rabbitEntrypointScript(h.secretPath, h.defaultConfDir, h.generatedConfDir), "$$", "$")
	h.path = path
	return h
}

func (h rabbitScriptHarness) writeDefaults(t *testing.T) {
	t.Helper()
	contents := "# retained default\nloopback_users.guest = true\nlog.console = true\nlog.file = false\n"
	if err := os.WriteFile(filepath.Join(h.defaultConfDir, "10-defaults.conf"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h rabbitScriptHarness) run() ([]byte, error) {
	cmd := exec.Command("sh", "-ec", h.script)
	cmd.Env = []string{
		"PATH=" + h.path,
		"ARGS_CAPTURE=" + h.argsCapture,
		"ENV_CAPTURE=" + h.envCapture,
	}
	return cmd.CombinedOutput()
}

// A deploy that fails before its signed plan leaves the client (here: no
// trusted host identity) never reached the helper, so it must not count as a
// promotion attempt; otherwise finish aborts it into recovery_required.
func TestDeploySwarmToHostMarksPromotionOnlyWhenThePlanIsSent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	operation := &remoteOperation{kind: "deploy", app: "demo"}
	cfg := &config.Config{Version: 2, App: "demo"}
	group := config.ServerGroup{User: "deploy", Port: 22}
	if _, err := deploySwarmToHost(cfg, group, "192.0.2.10", nil, nil, "8080", secretManifest{}, nil, "op", operation); err == nil {
		t.Fatal("deploy without a trusted host identity succeeded")
	}
	if operation.promotionAttempted {
		t.Fatal("a failure before the plan was sent was recorded as a promotion attempt")
	}
	if operation.promotionResult() != "not-started" {
		t.Fatalf("promotion result = %q, want not-started", operation.promotionResult())
	}
}
