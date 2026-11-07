package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestClientEndpointSupportsIPv4DNSAndIPv6(t *testing.T) {
	for _, scenario := range []struct {
		host string
		port int
		want string
	}{
		{host: "192.0.2.10", port: 22, want: "192.0.2.10:22"},
		{host: "vps.example", port: 2202, want: "vps.example:2202"},
		{host: "2001:db8::10", port: 22, want: "[2001:db8::10]:22"},
	} {
		client := &Client{Host: scenario.host, Port: scenario.port}
		if got := client.endpoint(); got != scenario.want {
			t.Fatalf("endpoint(%q, %d)=%q, want %q", scenario.host, scenario.port, got, scenario.want)
		}
	}
}

func TestNewClientExactWithFingerprintAuthenticatesFirstContact(t *testing.T) {
	configureKnownHosts(t, "")
	server := newTestSSHServer(t, func(_ string, _ []byte, channel gossh.Channel) {
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{Status: 0}))
	})
	expected := gossh.FingerprintSHA256(server.hostKey)
	client, err := NewClientExactWithFingerprint(server.host, "test", server.port, expected)
	if err != nil {
		t.Fatal(err)
	}
	if result := client.Run("true"); result.Code != 0 {
		t.Fatalf("first-contact authentication failed: %s", result.Stderr)
	}
}

func TestNewClientExactWithFingerprintRejectsMismatchAndMalformedInput(t *testing.T) {
	configureKnownHosts(t, "")
	server := newTestSSHServer(t, func(string, []byte, gossh.Channel) {})
	for _, fingerprint := range []string{"", "SHA256:short", "MD5:00", "SHA256:" + strings.Repeat("A", 43)} {
		client, err := NewClientExactWithFingerprint(server.host, "test", server.port, fingerprint)
		if fingerprint == "SHA256:"+strings.Repeat("A", 43) {
			if err != nil {
				t.Fatal(err)
			}
			if result := client.Run("true"); result.Code == 0 || !strings.Contains(result.Stderr, "out-of-band attestation") {
				t.Fatalf("mismatched first-contact key was accepted: %+v", result)
			}
			continue
		}
		if err == nil {
			t.Fatalf("malformed fingerprint %q was accepted", fingerprint)
		}
	}
}

func TestResolveSSHConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := `Host prod
  HostName 203.0.113.10
  User deploy
  Port 7022
  IdentityFile ~/.ssh/id_shuttle
  IdentitiesOnly yes
`
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := resolveSSHConfig("prod", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HostName != "203.0.113.10" || cfg.User != "deploy" || cfg.Port != 7022 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if len(cfg.IdentityFiles) != 1 || cfg.IdentityFiles[0] != filepath.Join(sshDir, "id_shuttle") {
		t.Fatalf("unexpected identity files: %#v", cfg.IdentityFiles)
	}
	if !cfg.IdentitiesOnly {
		t.Fatal("IdentitiesOnly yes was ignored")
	}
}

func TestResolveSSHConfigRejectsInvalidIdentitiesOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte("Host prod\n  IdentitiesOnly maybe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSSHConfig("prod", ""); err == nil || !strings.Contains(err.Error(), "invalid IdentitiesOnly") {
		t.Fatalf("invalid IdentitiesOnly was accepted: %v", err)
	}
}

func TestResolveSSHConfigMatchHostAndUser(t *testing.T) {
	writeSSHConfig(t, "MATCH HoSt 198.51.100.30 UsEr ops\n  IdentityFile ~/.ssh/id_ed25519_demo_ops\n")

	cfg, err := resolveSSHConfig("198.51.100.30", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IdentityFiles) != 1 || filepath.Base(cfg.IdentityFiles[0]) != "id_ed25519_demo_ops" {
		t.Fatalf("Match host/user did not apply: %#v", cfg.IdentityFiles)
	}

	cfg, err = resolveSSHConfig("198.51.100.30", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IdentityFiles) != 0 {
		t.Fatalf("Match user applied to another user: %#v", cfg.IdentityFiles)
	}
}

func TestResolveSSHConfigUnsupportedMatchDoesNotLeak(t *testing.T) {
	writeSSHConfig(t, "Host prod\n  IdentityFile ~/.ssh/prod\nMatch exec true\n  IdentityFile ~/.ssh/unsupported\n")

	cfg, err := resolveSSHConfig("prod", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IdentityFiles) != 1 || filepath.Base(cfg.IdentityFiles[0]) != "prod" {
		t.Fatalf("unsupported Match leaked into the matching Host block: %#v", cfg.IdentityFiles)
	}
}

func TestResolveSSHConfigMatchAll(t *testing.T) {
	writeSSHConfig(t, "Match all\n  IdentityFile ~/.ssh/all\n")

	cfg, err := resolveSSHConfig("any-host", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IdentityFiles) != 1 || filepath.Base(cfg.IdentityFiles[0]) != "all" {
		t.Fatalf("Match all did not apply: %#v", cfg.IdentityFiles)
	}
}

func TestResolveSSHConfigMatchNegatedHostPattern(t *testing.T) {
	writeSSHConfig(t, "Match host *,!blocked.example\n  IdentityFile ~/.ssh/allowed\n")

	for _, scenario := range []struct {
		host string
		want bool
	}{
		{host: "prod.example", want: true},
		{host: "blocked.example", want: false},
	} {
		cfg, err := resolveSSHConfig(scenario.host, "ops")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(cfg.IdentityFiles) == 1; got != scenario.want {
			t.Fatalf("Match host for %q applied=%t, want %t", scenario.host, got, scenario.want)
		}
	}
}

func writeSSHConfig(t *testing.T, config string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveClientTargetRequiresOneIdentityWithIdentitiesOnly(t *testing.T) {
	for _, identities := range []string{"", "  IdentityFile ~/.ssh/one\n  IdentityFile ~/.ssh/two\n"} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		sshDir := filepath.Join(home, ".ssh")
		if err := os.MkdirAll(sshDir, 0o700); err != nil {
			t.Fatal(err)
		}
		config := "Host prod\n  IdentitiesOnly yes\n" + identities
		if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveClientTarget("prod", "deploy", 22); err == nil || !strings.Contains(err.Error(), "exactly one IdentityFile") {
			t.Fatalf("IdentitiesOnly accepted %q: %v", identities, err)
		}
	}
}

func TestAuthMethodsUsesDeployShuttleKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_shuttle"), testPrivateKey(t), 0o600); err != nil {
		t.Fatal(err)
	}

	methods, err := authMethods(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected one auth method, got %d", len(methods))
	}
}

func TestAuthMethodsIdentitiesOnlyUsesOnlyConfiguredFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "must-not-be-used")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(sshDir, "operator")
	if err := os.WriteFile(explicit, testPrivateKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), testPrivateKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	originalDial := dialSSHAgent
	t.Cleanup(func() { dialSSHAgent = originalDial })
	agentDials := 0
	dialSSHAgent = func(string, string) (net.Conn, error) {
		agentDials++
		return nil, errors.New("unexpected agent dial")
	}

	methods, err := authMethods([]string{explicit}, true)
	if err != nil {
		t.Fatal(err)
	}
	if agentDials != 0 {
		t.Fatalf("IdentitiesOnly dialed the SSH agent %d times", agentDials)
	}
	if len(methods) != 1 {
		t.Fatalf("IdentitiesOnly loaded %d auth methods, want only the explicit identity", len(methods))
	}

	if _, err := authMethods([]string{filepath.Join(sshDir, "missing")}, true); err == nil || !strings.Contains(err.Error(), "IdentitiesOnly yes") {
		t.Fatalf("IdentitiesOnly fell back after a missing configured key: %v", err)
	}
}

func TestAuthMethodsSupportsEncryptedKeysAndGuidesNonInteractiveUse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("correct horse battery staple")
	block, err := gossh.MarshalPrivateKeyWithPassphrase(privateKey, "encrypted-test", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	originalTerminal, originalReader := sshInputIsTerminal, readSSHKeyPassphrase
	t.Cleanup(func() {
		sshInputIsTerminal = originalTerminal
		readSSHKeyPassphrase = originalReader
	})
	sshInputIsTerminal = func() bool { return false }
	if _, err := authMethods(nil, false); err == nil || !strings.Contains(err.Error(), "load it into ssh-agent") {
		t.Fatalf("non-interactive encrypted key produced no actionable error: %v", err)
	}

	sshInputIsTerminal = func() bool { return true }
	readSSHKeyPassphrase = func(string) ([]byte, error) { return append([]byte(nil), passphrase...), nil }
	methods, err := authMethods(nil, false)
	if err != nil || len(methods) != 1 {
		t.Fatalf("interactive encrypted key methods=%d err=%v", len(methods), err)
	}
	provided := append([]byte(nil), passphrase...)
	readSSHKeyPassphrase = func(string) ([]byte, error) { return provided, nil }
	signers, err := decryptSSHIdentity(path, pem.EncodeToMemory(block))
	expectedPublicKey, publicKeyErr := gossh.NewPublicKey(publicKey)
	if publicKeyErr != nil {
		t.Fatal(publicKeyErr)
	}
	if err != nil || len(signers) != 1 || gossh.FingerprintSHA256(signers[0].PublicKey()) != gossh.FingerprintSHA256(expectedPublicKey) {
		t.Fatalf("encrypted key did not decrypt to expected signer: signers=%d err=%v", len(signers), err)
	}
	if !bytes.Equal(provided, make([]byte, len(provided))) {
		t.Fatal("SSH private-key passphrase was not cleared after parsing")
	}
}

func TestAuthMethodsKeepsAgentConnectionAliveForSigning(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	})
	go func() { _ = agent.ServeAgent(keyring, serverSide) }()
	originalDial := dialSSHAgent
	t.Cleanup(func() { dialSSHAgent = originalDial })
	dialSSHAgent = func(network, address string) (net.Conn, error) {
		if network != "unix" || address != "test-agent" {
			t.Fatalf("unexpected agent dial %s %s", network, address)
		}
		return clientSide, nil
	}
	t.Setenv("SSH_AUTH_SOCK", "test-agent")
	t.Setenv("HOME", t.TempDir())
	methods, err := authMethods(nil, false)
	if err != nil || len(methods) != 1 {
		t.Fatalf("agent auth methods=%d err=%v", len(methods), err)
	}

	host, port, hostKey := newPublicKeyAuthTestServer(t, allowed)
	connection, err := gossh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), &gossh.ClientConfig{
		User: "test", Auth: methods, HostKeyCallback: gossh.FixedHostKey(hostKey), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("agent-backed signer lost its socket before signing: %v", err)
	}
	_ = connection.Close()
}

func TestRunWithStdinSendsPayloadSeparateFromCommand(t *testing.T) {
	command := "docker secret create app_DB_PASSWORD -"
	payload := []byte("line one\nline two\x00")
	server := newTestSSHServer(t, func(commandGot string, stdin []byte, channel gossh.Channel) {
		if commandGot != command {
			t.Errorf("unexpected command: %q", commandGot)
		}
		if !bytes.Equal(stdin, payload) {
			t.Errorf("unexpected stdin: %q", stdin)
		}
		_, _ = channel.Write([]byte("created\n"))
		_, _ = channel.Stderr().Write([]byte("already exists\n"))
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{Status: 1}))
	})

	result := server.client.RunWithStdin(command, payload)
	if result.Code != 1 || result.Stdout != "created\n" || result.Stderr != "already exists\n" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

// A reader-backed payload arrives whole and in order, and it is larger than
// the output bound so the test proves the bound is on output alone.
func TestRunWithReaderStreamsAPayloadLargerThanTheOutputBound(t *testing.T) {
	command := "docker load"
	payload := bytes.Repeat([]byte("layer"), 100_000)
	server := newTestSSHServer(t, func(commandGot string, stdin []byte, channel gossh.Channel) {
		if commandGot != command {
			t.Errorf("unexpected command: %q", commandGot)
		}
		if !bytes.Equal(stdin, payload) {
			t.Errorf("stdin arrived altered: %d bytes, want %d", len(stdin), len(payload))
		}
		_, _ = channel.Write([]byte("Loaded image: shuttle/demo-web:v1\n"))
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{Status: 0}))
	})
	server.client.maxOutputBytes = 4096
	result := server.client.RunWithReader(command, bytes.NewReader(payload))
	if result.Code != 0 || result.Stdout != "Loaded image: shuttle/demo-web:v1\n" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRunBoundsRemoteOutputWithoutLeakingTheOverflow(t *testing.T) {
	server := newTestSSHServer(t, func(command string, stdin []byte, channel gossh.Channel) {
		// Exceed the SSH channel window as well as the default output cap.
		// Stopping either drain on overflow would block the remote writer
		// before it can send its exit status, ending only at the deadline.
		payload := bytes.Repeat([]byte("x"), defaultSSHMaxOutputBytes+32768)
		_, _ = channel.Write(payload)
		_, _ = channel.Stderr().Write(payload)
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{Status: 0}))
		_ = channel.CloseWrite()
	})
	server.client.maxOutputBytes = 64
	server.client.operationTimeout = 3 * time.Second
	result := server.client.Run("produce-output")
	if result.Code == 0 || len(result.Stdout) > 64 || result.Stderr != "SSH output exceeded the configured safe limit" {
		t.Fatalf("unbounded SSH output result=%+v stdout_len=%d", result, len(result.Stdout))
	}
}

func TestRunAndUploadHaveAWholeOperationDeadline(t *testing.T) {
	for _, operation := range []string{"run", "upload"} {
		t.Run(operation, func(t *testing.T) {
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			server := newTestSSHServer(t, func(command string, stdin []byte, channel gossh.Channel) {
				<-release
			})
			server.client.operationTimeout = 75 * time.Millisecond
			started := time.Now()
			var result Result
			if operation == "run" {
				result = server.client.Run("hang")
			} else {
				result = server.client.UploadContent("body", "/tmp/file", 0o600)
			}
			if result.Code != 124 || result.Stderr != "SSH operation timed out" || !result.OutcomeUnknown || time.Since(started) > time.Second {
				t.Fatalf("%s deadline result=%+v elapsed=%s", operation, result, time.Since(started))
			}
		})
	}
}

// A bounded status probe must use its own context without changing the timeout
// concurrently read by the client's long-running operation path.
func TestRunWithStdinContextHonorsDeadlineWithoutChangingOperationTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	server := newTestSSHServer(t, func(string, []byte, gossh.Channel) { <-release })
	server.client.operationTimeout = 3 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := server.client.RunWithStdinContext(ctx, "bounded", []byte("input"))
	if result.Code != 124 || result.Stderr != "SSH operation timed out" || time.Since(started) > time.Second {
		t.Fatalf("context deadline result=%+v elapsed=%s", result, time.Since(started))
	}
	if server.client.operationTimeout != 3*time.Minute {
		t.Fatalf("operation timeout changed to %s", server.client.operationTimeout)
	}
}

func TestUploadPublishesAtomicallyWithoutPuttingContentInCommand(t *testing.T) {
	const secretBody = "sensitive-body-that-must-stay-on-stdin"
	var observedCommand string
	var observedInput []byte
	server := newTestSSHServer(t, func(command string, stdin []byte, channel gossh.Channel) {
		observedCommand = command
		observedInput = append([]byte(nil), stdin...)
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{Status: 0}))
		_ = channel.CloseWrite()
	})
	result := server.client.UploadContent(secretBody, "/opt/shuttle/demo.next/release.env", 0o600)
	if result.Code != 0 {
		t.Fatalf("atomic upload failed: %+v", result)
	}
	for _, want := range []string{".shuttle-upload-", "set -C", "sync -f", "mv -f --", "trap 'rm -f"} {
		if !strings.Contains(observedCommand, want) {
			t.Fatalf("upload command missing %q: %s", want, observedCommand)
		}
	}
	if strings.Contains(observedCommand, secretBody) {
		t.Fatalf("upload body leaked into remote argv: %s", observedCommand)
	}
	if string(observedInput) != secretBody {
		t.Fatalf("upload body mismatch: %q", observedInput)
	}
}

type testSSHServer struct {
	client  *Client
	hostKey gossh.PublicKey
	host    string
	port    int
}

func newTestSSHServer(t *testing.T, handler func(command string, stdin []byte, channel gossh.Channel)) testSSHServer {
	t.Helper()
	signer := testED25519Signer(t)
	return newTestSSHServerWithSigners(t, []gossh.Signer{signer}, handler)
}

func newPublicKeyAuthTestServer(t *testing.T, allowed gossh.PublicKey) (string, int, gossh.PublicKey) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	hostSigner := testED25519Signer(t)
	serverConfig := &gossh.ServerConfig{PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, errors.New("untrusted test client key")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(hostSigner)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		serverConnection, channels, requests, err := gossh.NewServerConn(connection, serverConfig)
		if err != nil {
			_ = connection.Close()
			return
		}
		go gossh.DiscardRequests(requests)
		go func() {
			for channel := range channels {
				_ = channel.Reject(gossh.UnknownChannelType, "not used by test")
			}
		}()
		_ = serverConnection.Wait()
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port, hostSigner.PublicKey()
}

func newTestSSHServerWithSigners(t *testing.T, signers []gossh.Signer, handler func(command string, stdin []byte, channel gossh.Channel)) testSSHServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if len(signers) == 0 {
		t.Fatal("test SSH server needs a host signer")
	}
	serverConfig := &gossh.ServerConfig{NoClientAuth: true}
	for _, signer := range signers {
		serverConfig.AddHostKey(signer)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, channels, requests, err := gossh.NewServerConn(conn, serverConfig)
		if err != nil {
			return
		}
		go gossh.DiscardRequests(requests)
		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(gossh.UnknownChannelType, "unsupported channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return
			}
			for request := range requests {
				if request.Type != "exec" {
					_ = request.Reply(false, nil)
					continue
				}
				var requestPayload struct{ Command string }
				if err := gossh.Unmarshal(request.Payload, &requestPayload); err != nil {
					return
				}
				_ = request.Reply(true, nil)
				stdin, err := io.ReadAll(channel)
				if err != nil {
					return
				}
				handler(requestPayload.Command, stdin, channel)
				_ = channel.Close()
				return
			}
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return testSSHServer{
		client: &Client{
			Host: host,
			Port: parsedPort,
			cfg: &gossh.ClientConfig{
				User:            "test",
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			},
		},
		hostKey: signers[0].PublicKey(),
		host:    host,
		port:    parsedPort,
	}
}

func configureKnownHosts(t *testing.T, content string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_shuttle"), testPrivateKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = content
}

func testED25519Signer(t *testing.T) gossh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// forwardTestServer serves direct-tcpip channels and counts how many SSH
// transports it had to negotiate, which is the whole point of the forward: one
// handshake for the entire deploy, not one per pushed layer.
type forwardTestServer struct {
	client     *Client
	handshakes atomic.Int32
	channels   atomic.Int32
	destPort   int

	mu         sync.Mutex
	transports []net.Conn
}

func newForwardTestSSHServer(t *testing.T, destPort int) *forwardTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	signer := testED25519Signer(t)
	serverConfig := &gossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	server := &forwardTestServer{destPort: destPort}
	go func() {
		for {
			transport, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go server.serve(transport, serverConfig)
		}
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	server.client = &Client{
		Host: host,
		Port: port,
		cfg: &gossh.ClientConfig{
			User:            "test",
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		},
	}
	return server
}

func (s *forwardTestServer) serve(transport net.Conn, serverConfig *gossh.ServerConfig) {
	_, channels, requests, err := gossh.NewServerConn(transport, serverConfig)
	if err != nil {
		_ = transport.Close()
		return
	}
	s.handshakes.Add(1)
	s.mu.Lock()
	s.transports = append(s.transports, transport)
	s.mu.Unlock()
	go gossh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "only forwards are served")
			continue
		}
		var payload struct {
			DestAddr string
			DestPort uint32
			OrigAddr string
			OrigPort uint32
		}
		if gossh.Unmarshal(newChannel.ExtraData(), &payload) != nil || int(payload.DestPort) != s.destPort {
			_ = newChannel.Reject(gossh.ConnectionFailed, "refused destination")
			continue
		}
		channel, channelRequests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			return
		}
		s.channels.Add(1)
		go gossh.DiscardRequests(channelRequests)
		go func() {
			// Echo, then EOF: a registry answers the request whose body just
			// ended, which only works if the forward half-closes instead of
			// tearing the channel down.
			_, _ = io.Copy(channel, channel)
			_ = channel.Close()
		}()
	}
}

func (s *forwardTestServer) dropTransports() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, transport := range s.transports {
		_ = transport.Close()
	}
	s.transports = nil
}

func forwardRoundTrip(t *testing.T, address string, payload string) string {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write to forward: %v", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close forward: %v", err)
	}
	echoed, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read from forward: %v", err)
	}
	return string(echoed)
}

func TestStartLocalForwardSharesOneSSHTransportAcrossConnections(t *testing.T) {
	server := newForwardTestSSHServer(t, 5000)
	forward, err := server.client.StartLocalForward(0, 5000)
	if err != nil {
		t.Fatalf("start forward: %v", err)
	}
	t.Cleanup(func() { _ = forward.Close() })

	const connections = 8
	for index := 0; index < connections; index++ {
		payload := fmt.Sprintf("blob-%d", index)
		if echoed := forwardRoundTrip(t, forward.Addr(), payload); echoed != payload {
			t.Fatalf("forward %d returned %q, want %q", index, echoed, payload)
		}
	}

	// One handshake for eight connections. Re-dialling per connection is what
	// exhausted OpenSSH's default MaxSessions during a multi-layer push.
	if got := server.handshakes.Load(); got != 1 {
		t.Fatalf("forward negotiated %d SSH transports for %d connections, want 1", got, connections)
	}
	if got := server.channels.Load(); got != connections {
		t.Fatalf("forward opened %d channels, want %d", got, connections)
	}
	if err := forward.Close(); err != nil {
		t.Fatalf("clean close reported %v", err)
	}
}

func TestLocalForwardStopsAcceptingAndReportsADeadTransport(t *testing.T) {
	server := newForwardTestSSHServer(t, 5000)
	forward, err := server.client.StartLocalForward(0, 5000)
	if err != nil {
		t.Fatalf("start forward: %v", err)
	}
	t.Cleanup(func() { _ = forward.Close() })
	address := forward.Addr()
	if echoed := forwardRoundTrip(t, address, "alive"); echoed != "alive" {
		t.Fatalf("forward is not serving: %q", echoed)
	}

	server.dropTransports()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, dialErr := net.Dial("tcp", address)
		if dialErr != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("forward kept accepting connections after its SSH transport died")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if forward.Err() == nil {
		t.Fatal("a dead SSH transport must be recorded, not swallowed")
	}
	if err := forward.Close(); err == nil {
		t.Fatal("Close must report the transport failure instead of returning success")
	}
}

func TestLocalForwardReportsARefusedRemoteInsteadOfReturningSilently(t *testing.T) {
	server := newForwardTestSSHServer(t, 5000)
	// The remote port the forward asks for is not the one the server serves, so
	// every channel open is refused: the old code returned from that path in
	// silence and left the caller with an unexplained EOF.
	forward, err := server.client.StartLocalForward(0, 5001)
	if err != nil {
		t.Fatalf("start forward: %v", err)
	}
	t.Cleanup(func() { _ = forward.Close() })
	conn, err := net.Dial("tcp", forward.Addr())
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	_, _ = io.WriteString(conn, "ping")
	// The unanswered request is discarded when the forward drops the socket, so
	// the read here legitimately fails; what must not happen is a silent drop
	// with no recorded cause.
	_, _ = io.ReadAll(conn)
	_ = conn.Close()
	if forward.Err() == nil {
		t.Fatal("a refused forwarded channel must be recorded")
	}
	if err := forward.Close(); err == nil {
		t.Fatal("Close must report the refused forward")
	}
}
