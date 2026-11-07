package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Exercise real SSH sessions and signed envelopes against a loopback server.
// It records commands but never executes them or changes an operating-system user.
func administratorSSHFixture(t *testing.T, handle func(user, command string, stdin []byte) shuttlessh.Result) (setupIdentity, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	// Keep the Unix socket path under the platform length limit.
	agentDir, err := os.MkdirTemp("", "shuttle-test-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	socket := filepath.Join(agentDir, "agent")
	agentListener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", socket)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = agentListener.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connections []net.Conn
	track := func(connection net.Conn) {
		mu.Lock()
		connections = append(connections, connection)
		mu.Unlock()
	}
	var accepts sync.WaitGroup
	accepts.Add(2)
	t.Cleanup(func() {
		_ = listener.Close()
		_ = agentListener.Close()
		accepts.Wait()
		mu.Lock()
		defer mu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
	go func() {
		defer accepts.Done()
		for {
			connection, err := agentListener.Accept()
			if err != nil {
				return
			}
			track(connection)
			go func() { _ = agent.ServeAgent(keyring, connection) }()
		}
	}()
	serverConfig := &gossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)
	go func() {
		defer accepts.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			track(connection)
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				server, channels, requests, err := gossh.NewServerConn(connection, serverConfig)
				if err != nil {
					return
				}
				defer server.Close()
				go gossh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(gossh.UnknownChannelType, "only sessions are supported")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					defer channel.Close()
					for request := range requests {
						if request.Type != "exec" {
							_ = request.Reply(false, nil)
							continue
						}
						var payload struct{ Command string }
						if err := gossh.Unmarshal(request.Payload, &payload); err != nil {
							return
						}
						_ = request.Reply(true, nil)
						stdin, err := io.ReadAll(channel)
						if err != nil {
							return
						}
						result := handle(server.User(), payload.Command, stdin)
						_, _ = io.WriteString(channel, result.Stdout)
						_, _ = io.WriteString(channel.Stderr(), result.Stderr)
						// A negative code closes the channel without an exit status.
						if result.Code >= 0 {
							_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{uint32(result.Code)}))
						}
						return
					}
				}
			}()
		}
	}()
	fingerprint := gossh.FingerprintSHA256(signer.PublicKey())
	return setupIdentity{user: "root", host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, operatorKeyFingerprint: fingerprint}, fingerprint
}

func TestAdoptionAdministratorSSHFailureGatesHardeningAndRollsBack(t *testing.T) {
	for _, failure := range []string{"", "before-sudo", "before-login", "after-sudo"} {
		t.Run("failure="+failure, func(t *testing.T) {
			var mu sync.Mutex
			var events []string
			baseline := false
			fail := failure
			identity, fingerprint := administratorSSHFixture(t, func(user, command string, stdin []byte) shuttlessh.Result {
				mu.Lock()
				defer mu.Unlock()
				if strings.HasSuffix(command, "/usr/local/libexec/shuttle-root apply") {
					plan, _, err := decodeRootHelperEnvelope(bytes.NewReader(stdin))
					if err != nil {
						return shuttlessh.Result{Code: 1, Stderr: err.Error()}
					}
					events = append(events, user+":"+plan.Action)
					if plan.Action == "baseline" {
						if plan.Baseline == nil || strings.Join(plan.Baseline.AllowedSSHUsers, " ") != "deploy ops" {
							return shuttlessh.Result{Code: 1, Stderr: "baseline dropped the administrator"}
						}
						baseline = true
					}
					if plan.Action == "baseline-rollback" {
						baseline = false
					}
					return shuttlessh.Result{}
				}
				if user == "ops" {
					events = append(events, "ops:proof")
					if !strings.Contains(command, `test "$(sudo -n id -u)" = 0`) {
						return shuttlessh.Result{Code: 1, Stderr: "administrator proof omitted root sudo"}
					}
					if fail == "before-login" && !baseline {
						return shuttlessh.Result{Code: 255, Stderr: "login unavailable"}
					}
					if (fail == "before-sudo" && !baseline) || (fail == "after-sudo" && baseline) {
						return shuttlessh.Result{Code: 1, Stderr: "sudo: a password is required"}
					}
					return shuttlessh.Result{}
				}
				if user == "deploy" && command == deployLeastPrivilegeProofSource {
					events = append(events, "deploy:proof")
					return shuttlessh.Result{}
				}
				return shuttlessh.Result{Code: 1, Stderr: "unexpected command"}
			})
			options := setupOptions{adopt: true, expectedHostKey: fingerprint, operator: &setupOperatorAccess{user: "ops"}}
			client, err := shuttlessh.NewClientExactWithFingerprint(identity.host, identity.user, identity.port, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			signingDir := t.TempDir()
			privatePath := filepath.Join(signingDir, "private.pem")
			if err := rootplan.GenerateKeyPair(privatePath, filepath.Join(signingDir, "public.pem")); err != nil {
				t.Fatal(err)
			}
			apply := func() error {
				return hardenAdoptedHostSSH(io.Discard, identity, options, setupRunner{client: client}, privatePath)
			}
			err = apply()
			mu.Lock()
			observed := strings.Join(events, " ")
			mu.Unlock()
			if failure == "" {
				if err != nil || observed != "ops:proof deploy:proof root:baseline ops:proof deploy:audit deploy:baseline-commit" {
					t.Fatalf("hardening did not prove both sides before commit: %v; %s", err, observed)
				}
				return
			}
			if err == nil || strings.Contains(observed, "baseline-commit") {
				t.Fatalf("administrator failure was committed: %v; %s", err, observed)
			}
			if strings.HasPrefix(failure, "before-") && strings.Contains(observed, ":baseline") {
				t.Fatalf("pre-hardening failure changed SSH policy: %s", observed)
			}
			if failure == "after-sudo" && (!strings.HasSuffix(observed, "deploy:baseline-rollback") || !strings.Contains(err.Error(), "restored automatically")) {
				t.Fatalf("post-hardening failure did not roll back through deploy: %v; %s", err, observed)
			}
			// Once access is fixed, rerunning must reach commit normally.
			mu.Lock()
			fail = ""
			events = nil
			mu.Unlock()
			if err := apply(); err != nil {
				t.Fatalf("resume after administrator recovery failed: %v", err)
			}
		})
	}
}
