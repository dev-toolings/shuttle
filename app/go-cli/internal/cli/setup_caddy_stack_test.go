package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func parseCaddyStack(t *testing.T, cfg config.Caddy) map[string]any {
	t.Helper()
	var root map[string]any
	stack := setupCaddyStack(caddyImageDefault, cfg)
	if err := yaml.Unmarshal([]byte(stack), &root); err != nil {
		t.Fatalf("generated stack is not valid YAML: %v\n%s", err, stack)
	}
	return root
}

func caddyService(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	return root["services"].(map[string]any)["caddy"].(map[string]any)
}

// The default must not move: an existing deployment that sets none of the new
// keys has to produce the stack it produced before they existed.
func TestCaddyStackDefaultsAreUnchanged(t *testing.T) {
	root := parseCaddyStack(t, config.Caddy{})
	service := caddyService(t, root)

	volumes := service["volumes"].([]any)
	if len(volumes) != 3 || volumes[1].(map[string]any)["source"] != "shuttle_caddy_data" {
		t.Fatalf("unexpected default volumes: %#v", volumes)
	}
	if data := root["volumes"].(map[string]any)["shuttle_caddy_data"]; len(data.(map[string]any)) != 0 {
		t.Fatalf("the default data volume must be Shuttle-owned, got %#v", data)
	}
	if _, present := service["environment"]; present {
		t.Fatal("no environment block without configured variables")
	}
	if _, present := service["secrets"]; present {
		t.Fatal("no secrets block without configured secrets")
	}
	entrypoint := service["entrypoint"].([]any)
	if len(entrypoint) != 1 || entrypoint[0] != "/usr/bin/caddy" {
		t.Fatalf("without secrets Caddy must be exec'd directly, got %#v", entrypoint)
	}
}

// Adopting an existing certificate store is the whole point: it must be
// declared external so Swarm attaches it instead of creating an empty one.
func TestCaddyStackAdoptsAnExistingDataVolume(t *testing.T) {
	root := parseCaddyStack(t, config.Caddy{DataVolume: "demo_caddy_data"})
	if got := caddyService(t, root)["volumes"].([]any)[1]; got.(map[string]any)["source"] != "demo_caddy_data" {
		t.Fatalf("expected the configured volume at /data, got %#v", got)
	}
	declared := root["volumes"].(map[string]any)["demo_caddy_data"].(map[string]any)
	if declared["external"] != true {
		t.Fatalf("an adopted volume must be declared external, got %#v", declared)
	}
	if _, present := root["volumes"].(map[string]any)["shuttle_caddy_data"]; present {
		t.Fatal("Shuttle must not also create its own data volume")
	}
}

func TestCaddyStackCarriesMountsEnvAndSecrets(t *testing.T) {
	readWrite := false
	cfg := config.Caddy{
		Mounts: []config.CaddyMount{
			{Source: "/opt/caddy/maintenance", Target: "/srv"},
			{Source: "/opt/caddy/logs", Target: "/var/log/caddy", ReadOnly: &readWrite},
		},
		Env:       map[string]string{"MAINTENANCE_MODE": "false"},
		SecretEnv: map[string]string{"CLOUDFLARE_API_TOKEN": "cloudflare_api_token"},
	}
	root := parseCaddyStack(t, cfg)
	service := caddyService(t, root)

	volumes := service["volumes"].([]any)
	joined := strings.Join([]string{volumes[3].(string), volumes[4].(string)}, " ")
	if !strings.Contains(joined, "/opt/caddy/maintenance:/srv:ro") {
		t.Fatalf("a mount defaults to read-only, got %q", joined)
	}
	if !strings.Contains(joined, "/opt/caddy/logs:/var/log/caddy ") && !strings.HasSuffix(joined, "/opt/caddy/logs:/var/log/caddy") {
		t.Fatalf("an explicit read-write mount must not be forced read-only, got %q", joined)
	}

	if env := service["environment"].(map[string]any); env["MAINTENANCE_MODE"] != "false" {
		t.Fatalf("unexpected environment: %#v", env)
	}
	if secrets := service["secrets"].([]any); len(secrets) != 1 {
		t.Fatalf("expected the mapped secret to be mounted, got %#v", secrets)
	}
	if declared := root["secrets"].(map[string]any)["cloudflare_api_token"].(map[string]any); declared["external"] != true {
		t.Fatalf("a mapped secret must be external, got %#v", declared)
	}
	entrypoint := service["entrypoint"].([]any)
	if len(entrypoint) != 2 || entrypoint[1] != "/etc/caddy/shuttle-edge-entrypoint" {
		t.Fatalf("secret exporting requires the generated entrypoint, got %#v", entrypoint)
	}
	if _, present := service["command"]; present {
		t.Fatal("the generated entrypoint carries its own arguments; command must be dropped")
	}
}

// The script is generated, so its shell syntax is Shuttle's responsibility.
func TestCaddyEntrypointScriptIsValidShellAndFailsClosed(t *testing.T) {
	script := caddyEntrypointScript(config.Caddy{SecretEnv: map[string]string{
		"CLOUDFLARE_API_TOKEN": "cloudflare_api_token",
		"ACME_EAB_KEY":         "acme_eab_key",
	}})

	file, err := os.CreateTemp(t.TempDir(), "entrypoint-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(script); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if out, err := exec.Command("sh", "-n", file.Name()).CombinedOutput(); err != nil {
		t.Fatalf("generated entrypoint is not valid shell: %v\n%s\n%s", err, out, script)
	}

	// A missing secret must stop the container, not start an edge whose DNS
	// challenge silently reads an empty credential.
	if !strings.Contains(script, "missing secret: cloudflare_api_token") {
		t.Fatalf("the script must fail closed on a missing secret:\n%s", script)
	}
	if !strings.HasSuffix(strings.TrimSpace(script), "exec /usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile") {
		t.Fatalf("the script must exec Caddy so no shell stays as PID 1:\n%s", script)
	}
	// Deterministic output: a map-ordered script would rewrite the config object
	// on every setup and restart the edge for nothing.
	if strings.Index(script, "ACME_EAB_KEY") > strings.Index(script, "CLOUDFLARE_API_TOKEN") {
		t.Fatalf("exports must be sorted for a stable config object:\n%s", script)
	}
}

func TestInfrastructureServicesRunWithoutRoot(t *testing.T) {
	service := caddyService(t, parseCaddyStack(t, config.Caddy{SecretEnv: map[string]string{"TOKEN": "dns_token"}}))
	for _, mount := range service["volumes"].([]any)[1:] {
		if mount.(map[string]any)["volume"].(map[string]any)["nocopy"] != true {
			t.Fatal("image copy-up must not reset prepared volume ownership")
		}
	}
	if service["user"] != "10001:10001" {
		t.Fatalf("edge must use the dedicated unprivileged identity: %#v", service["user"])
	}
	secret := service["secrets"].([]any)[0].(map[string]any)
	if secret["uid"] != "10001" || secret["gid"] != "10001" || secret["mode"] != 256 {
		t.Fatalf("secret must be readable only by the service identity: %#v", secret)
	}
	for _, want := range []string{"--user 10001:10001", "--cap-drop ALL", "--security-opt no-new-privileges=true"} {
		if !strings.Contains(setupRegistryCreateSource, want) {
			t.Fatalf("registry runtime missing %s", want)
		}
	}
}

func TestCaddyVolumePreparationPreservesExternalOwnership(t *testing.T) {
	for _, cfg := range []config.Caddy{{}, {DataVolume: "existing_certs"}} {
		program := caddyVolumePreparation(cfg)
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(program)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("invalid preparation script: %v %s", err, output)
		}
		for _, line := range strings.Split(program, "\n") {
			if strings.Contains(line, "existing_certs") && (strings.Contains(line, "chown") || strings.Contains(line, "volume create")) {
				t.Fatalf("must not mutate adopted ownership: %s", line)
			}
		}
		if !strings.Contains(program, "--user 10001:10001") || !strings.Contains(program, "test -w /data") {
			t.Fatal("must prove the service can write its certificate store")
		}
	}
}

func TestCaddyFreshHTTPListenerAndImmutableConfig(t *testing.T) {
	cfg := config.Caddy{Email: "acme@example.test"}
	content := caddyfileContent(cfg.Email)
	for _, required := range []string{":80 {\n    respond 404\n}", "email acme@example.test", "import /etc/caddy/conf.d/*.caddy"} {
		if !strings.Contains(content, required) {
			t.Fatalf("fresh edge missing %q: %s", required, content)
		}
	}
	root := parseCaddyStack(t, cfg)
	declared := root["configs"].(map[string]any)["shuttle_caddyfile"].(map[string]any)
	if declared["name"] != caddyfileConfigName(cfg.Email) || declared["file"] != "/tmp/shuttle-Caddyfile" {
		t.Fatalf("immutable config mismatch: %#v", declared)
	}
	if caddyfileConfigName(cfg.Email) == caddyfileConfigName("other@example.test") {
		t.Fatal("changed content must create new config")
	}
}

func TestCaddyCheckpointReconcilesMountedConfig(t *testing.T) {
	for _, tc := range []struct {
		name, user, mounted string
		keep                bool
	}{
		{"current", "10001:10001", caddyfileConfigName(""), true},
		{"old config", "10001:10001", "shuttle-edge_shuttle_caddyfile_v2", false},
		{"old user", "", caddyfileConfigName(""), false},
		{"missing service", "missing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			checkpointPath := dir + "/checkpoint"
			if err := os.WriteFile(checkpointPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			fake := `#!/bin/sh
if [ "$TEST_USER" = missing ]; then exit 1; fi
case "$*" in
 *ContainerSpec.User*) printf '%s\n' "$TEST_USER" ;;
 *ContainerSpec.Configs*) printf '%s\n' "$TEST_CONFIG" ;;
esac
`
			if err := os.WriteFile(dir+"/docker", []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			script := strings.ReplaceAll(caddyCheckpointReconcile(""), "/etc/shuttle/setup.d/50-caddy-direct", checkpointPath)
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_USER="+tc.user, "TEST_CONFIG="+tc.mounted)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("reconcile: %v %s", err, out)
			}
			_, err := os.Stat(checkpointPath)
			if (err == nil) != tc.keep {
				t.Fatalf("checkpoint retained=%v, want %v", err == nil, tc.keep)
			}
		})
	}
}

// The edge keeps HSTS unconditional and only defaults the other three, one
// directive each: a single block would fold the `?` fields into one condition
// and drop every default as soon as the app sends any of them.
func TestCaddySecuritySnippetDefersToTheApplication(t *testing.T) {
	content := caddyfileContent("")
	for _, line := range []string{
		"    header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n",
		"    header ?X-Content-Type-Options \"nosniff\"\n",
		"    header ?Referrer-Policy \"strict-origin-when-cross-origin\"\n",
		"    header ?X-Frame-Options \"SAMEORIGIN\"\n",
		"    header -Via\n",
	} {
		if !strings.Contains(content, line) {
			t.Fatalf("security snippet missing %q: %s", line, content)
		}
	}
	if strings.Contains(content, "    header {\n") {
		t.Fatalf("security snippet must not group its defaults in one header block: %s", content)
	}
}
