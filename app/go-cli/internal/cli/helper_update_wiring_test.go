//go:build linux

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// Run the real command, signing and envelope path. The loopback endpoint only
// records requests: no command is executed and no host is updated.
func TestHelperUpdateProductionConsentWiring(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint(allow), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			privatePath, _, err := ensureRootOperationKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			key, err := rootplan.ReadPrivateKey(privatePath)
			if err != nil {
				t.Fatal(err)
			}
			observed := make(chan rootplan.Plan, 1)
			identity, fingerprint := administratorSSHFixture(t, func(user, command string, stdin []byte) shuttlessh.Result {
				plan, _, err := decodeRootHelperEnvelope(bytes.NewReader(stdin))
				if err != nil {
					return shuttlessh.Result{Code: 1, Stderr: err.Error()}
				}
				if err := rootplan.Verify(plan, key.Public().(ed25519.PublicKey), time.Now()); err != nil {
					return shuttlessh.Result{Code: 1, Stderr: err.Error()}
				}
				if plan.Action == "helper-update" {
					observed <- plan
					return shuttlessh.Result{Code: 1, Stderr: "fixture stopped after signed plan"}
				}
				// A legacy self-updating helper avoids unrelated reserve/finalize traffic.
				report := currentRootHelperCapabilities()
				report.Features = []string{capabilitySignedHelperUpdate}
				body, _ := json.Marshal(report)
				return shuttlessh.Result{Stdout: string(body)}
			})
			if err := saveTrustedHostIdentity(trustedHostIdentity{Version: 2, Host: identity.host, Port: identity.port, HostKeyFingerprint: fingerprint, OperatorKeyFingerprint: fingerprint}); err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(t.TempDir(), "config.json")
			cfg := fmt.Sprintf(`{"version":2,"app":"demo","domain":"demo.example.com","server":{"host":"%s","user":"deploy","port":%d},"services":{"web":{"port":80,"healthcheck":{"type":"http","path":"/health"}}},"caddy":{"tls_mode":"off"}}`, identity.host, identity.port)
			if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(t.TempDir(), "candidate")
			if err := os.WriteFile(binary, []byte("fixture payload"), 0600); err != nil {
				t.Fatal(err)
			}
			command := newHelperUpdateCommand()
			args := []string{"--config", cfgPath, "--binary", binary, "--yes"}
			if allow {
				args = append(args, "--allow-downgrade")
			}
			command.SetArgs(args)
			err = command.Execute()
			if err == nil || !strings.Contains(err.Error(), "fixture stopped after signed plan") {
				t.Fatalf("command did not reach signed apply: %v", err)
			}
			select {
			case plan := <-observed:
				if plan.Helper.AllowDowngrade != allow {
					t.Fatalf("signed rollback consent = %t, want %t", plan.Helper.AllowDowngrade, allow)
				}
			default:
				t.Fatal("no signed helper plan received")
			}
		})
	}
}
