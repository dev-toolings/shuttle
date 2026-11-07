package cli

import (
	"fmt"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The helper is the program that runs as root on the host. Freezing its
// installation behind the stage checkpoint meant a converged host could never
// receive a fix to it: `shuttle update` updates the operator's binary, and
// `setup` skipped the only step that ships the remote one.
func TestRuntimeStageAlwaysInstallsTheHelper(t *testing.T) {
	body := setupRuntimeCommand(22, defaultPublicTCPPorts(t), setupModeFresh)
	marker := "touch /etc/shuttle/setup.d/40-runtime"
	index := strings.Index(body, marker)
	if index < 0 {
		t.Fatalf("the stage must still checkpoint:\n%s", body)
	}
	after := body[index:]
	if !strings.Contains(after, "install -o root -g root -m 0755 /tmp/shuttle-root /usr/local/libexec/shuttle-root") {
		t.Errorf("the helper must be installed outside the checkpoint:\n%s", after)
	}
	if !strings.Contains(after, "/etc/shuttle/trusted-root-operations.pem") {
		t.Errorf("the trusted key must travel with it:\n%s", after)
	}
	// Generated shell is testable as shell.
	file, err := os.CreateTemp(t.TempDir(), "*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(body); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if out, err := exec.Command("sh", "-n", file.Name()).CombinedOutput(); err != nil {
		t.Fatalf("generated shell is not valid: %v\n%s", err, out)
	}
}

// Stop at the first real mutation, so both refusal and admission are tested
// against the complete generated program without running setup on the host.
func TestSetupHelperPendingDestroyGuard(t *testing.T) {
	// The guard runs on the Linux host and uses GNU stat -c. BSD stat on the
	// macOS CI runner rejects it, which says nothing about the host script.
	if runtime.GOOS != "linux" {
		t.Skip("generated setup script targets GNU coreutils on the Linux host")
	}
	for _, mode := range []setupMode{setupModeFresh, setupModeAdoption} {
		for _, tc := range []struct {
			name, entry, owner     string
			fileMode               os.FileMode
			installed, wantRefusal bool
		}{
			{name: "fresh host"},
			{name: "missing directory", installed: true},
			{name: "empty directory", entry: "empty", installed: true},
			{name: "journal", entry: "pending.json", fileMode: 0600, installed: true, wantRefusal: true},
			{name: "temporary", entry: ".shuttle-root-123456", fileMode: 0600, installed: true},
			{name: "wrong name", entry: ".shuttle-root-123x", fileMode: 0600, installed: true, wantRefusal: true},
			{name: "empty suffix", entry: ".shuttle-root-", fileMode: 0600, installed: true, wantRefusal: true},
			{name: "wrong mode", entry: ".shuttle-root-123", fileMode: 0644, installed: true, wantRefusal: true},
			{name: "wrong owner", entry: ".shuttle-root-123", fileMode: 0600, owner: "1000", installed: true, wantRefusal: true},
			{name: "directory", entry: ".shuttle-root-123", fileMode: os.ModeDir | 0700, installed: true, wantRefusal: true},
			{name: "symlink", entry: ".shuttle-root-123", fileMode: os.ModeSymlink | 0600, installed: true, wantRefusal: true},
		} {
			t.Run(fmt.Sprint(mode)+"/"+tc.name, func(t *testing.T) {
				root := t.TempDir()
				helper := root + "/helper"
				cleanup := root + "/destroy-cleanup"
				if tc.installed {
					if err := os.WriteFile(helper, []byte("installed"), 0755); err != nil {
						t.Fatal(err)
					}
				}
				if tc.entry != "" {
					if err := os.Mkdir(cleanup, 0700); err != nil {
						t.Fatal(err)
					}
				}
				path := cleanup + "/" + tc.entry
				if tc.entry != "" && tc.entry != "empty" {
					var err error
					switch {
					case tc.fileMode.IsDir():
						err = os.Mkdir(path, 0700)
					case tc.fileMode&os.ModeSymlink != 0:
						err = os.Symlink(helper, path)
					default:
						err = os.WriteFile(path, []byte("evidence"), tc.fileMode)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				var body string
				for _, stage := range setupStages(adoptionApplyConfig(t), 22, mode) {
					body += stage.command + "\n"
				}
				body = strings.ReplaceAll(body, "/usr/local/libexec/shuttle-root", helper)
				body = strings.ReplaceAll(body, "/var/lib/shuttle/operations/destroy-cleanup", cleanup)
				owner := tc.owner
				if owner == "" {
					owner = "0"
				}
				body = "install() { echo MUTATION; exit 91; }\nstat() { if [ \"$3\" = \"" + cleanup + "\" ]; then command stat -c '0:%a' \"$3\"; else command stat -c '" + owner + ":%a' \"$3\"; fi; }\n" + body
				command := exec.Command("sh")
				command.Stdin = strings.NewReader(body)
				out, err := command.CombinedOutput()
				if tc.wantRefusal {
					if err == nil || strings.Contains(string(out), "MUTATION") || !strings.Contains(string(out), "docs/operations-recovery.md") {
						t.Fatalf("setup did not refuse before mutation with recovery guidance: %v %s", err, out)
					}
				} else if !strings.Contains(string(out), "MUTATION") {
					t.Fatalf("safe setup never reached first mutation: %v %s", err, out)
				}
				if tc.entry != "" && tc.entry != "empty" && tc.fileMode.IsRegular() {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != "evidence" {
						t.Fatalf("setup changed evidence: %q %v", got, err)
					}
				}
			})
		}
	}
}

// The claim itself writes state and clears staging files. Exercise the real
// adoption entry point so moving safety back behind that claim is observable.
func TestAdoptionHelperSafetyPrecedesClaim(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	calls := make(chan string, 8)
	identity, fingerprint := administratorSSHFixture(t, func(user, command string, stdin []byte) shuttlessh.Result {
		calls <- command
		if command == setupHelperReplacementGuard {
			return shuttlessh.Result{Code: 1, Stderr: "helper replacement refused: docs/operations-recovery.md"}
		}
		return shuttlessh.Result{Code: 91, Stderr: "MUTATION"}
	})
	client, err := shuttlessh.NewClientExactWithFingerprint(identity.host, identity.user, identity.port, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	err = applyAdoption(io.Discard, adoptionApplyConfig(t), identity, setupOptions{}, adoptionSurvey{}, adoptionEdgePlan{}, client, time.Now())
	if err == nil || !strings.Contains(err.Error(), "helper replacement refused") {
		t.Fatalf("adoption did not refuse at safety stage: %v", err)
	}
	if len(calls) != 1 || <-calls != setupHelperReplacementGuard {
		t.Fatal("adoption reached a command before safety refusal")
	}
}

func TestFreshSetupHelperSafetyPrecedesUploads(t *testing.T) {
	calls := make(chan string, 8)
	identity, fingerprint := administratorSSHFixture(t, func(user, command string, stdin []byte) shuttlessh.Result {
		calls <- command
		if command == setupHelperReplacementGuard {
			return shuttlessh.Result{Code: 1, Stderr: "helper replacement refused: docs/operations-recovery.md"}
		}
		return shuttlessh.Result{Code: 91, Stderr: "MUTATION"}
	})
	client, err := shuttlessh.NewClientExactWithFingerprint(identity.host, identity.user, identity.port, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	err = installSetupHost(setupRunner{client: client}, io.Discard, adoptionApplyConfig(t), identity, nil, []byte("trust"), []byte("helper"))
	if err == nil || !strings.Contains(err.Error(), "helper replacement refused") {
		t.Fatalf("fresh setup did not refuse at safety stage: %v", err)
	}
	if len(calls) != 1 || <-calls != setupHelperReplacementGuard {
		t.Fatal("fresh setup reached a command before safety refusal")
	}
}
