package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// A custom image may read files itself, so lack of an export proof must warn
// before host access without refusing a working application or changing it.
func TestSwarmEnvSecretsPreflightExplainsImageContract(t *testing.T) {
	for _, image := range []string{"custom/app:release", "shuttle-preset:release"} {
		t.Run(image, func(t *testing.T) {
			parsed := &composeFile{Services: map[string]composeService{"api": {Image: image}}}
			cfg := &config.Config{Secrets: config.Secrets{Items: map[string]config.SecretItem{
				"JWT_SECRET_KEY": {Services: []string{"api"}, Expose: "env"},
				"FILE_KEY":       {Services: []string{"api"}, Expose: "file"},
			}}}
			cfg.Secrets.Backend = config.SecretsBackendHost
			file := filepath.Join(t.TempDir(), "compose.yml")
			if err := os.WriteFile(file, []byte("services:\n  api:\n    image: "+image+"\n    build: .\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg.Deploy.ComposeFiles = []string{file}
			var err error
			warning := captureStderr(t, func() { _, err = checkDeployInputs(cfg) })
			if err != nil {
				t.Fatalf("unproven image contract must not refuse deploy: %v", err)
			}
			for _, want := range []string{"JWT_SECRET_KEY", "api", "expose: env", "/run/secrets/JWT_SECRET_KEY", "SHUTTLE_ENV_SECRETS", "entrypoint", "expose: file", "cannot verify"} {
				if !strings.Contains(warning, want) {
					t.Errorf("warning missing %q: %q", want, warning)
				}
			}
			if strings.Contains(warning, "FILE_KEY") {
				t.Fatalf("file-only secret must not warn: %q", warning)
			}
			if parsed.Services["api"].Image != image {
				t.Fatal("preflight changed the image")
			}
		})
	}
}
