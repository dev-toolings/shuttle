package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

type Client struct {
	Host             string
	User             string
	Port             int
	cfg              *gossh.ClientConfig
	operationTimeout time.Duration
	maxOutputBytes   int
	hostKeyMu        sync.RWMutex
	hostKey          gossh.PublicKey
}

// LocalForward exposes a remote loopback TCP service on a local loopback port.
// Both SSH authentication and the host-key check reuse this client's verified
// configuration; no separate ssh(1) process can silently select another host.
//
// The SSH transport is dialled once and shared by every accepted TCP
// connection. Dialling per connection made a parallel `docker push` pay a full
// TCP+SSH+auth handshake, and burn one more concurrent session, for every
// layer: pushing a 243 MB image died reproducibly with "read: connection reset
// by peer" until the server's MaxSessions was raised from OpenSSH's default 10
// to 60. Exporting a mode=max build cache multiplies that fan-out by hundreds
// of blob HEAD requests, so the handshake must happen exactly once.
type LocalForward struct {
	listener net.Listener
	client   *gossh.Client
	done     chan struct{}

	mu      sync.Mutex
	closing bool
	failure error
}

// forwardKeepaliveInterval keeps the now long-lived transport in front of the
// server's ClientAliveInterval. Per-connection dialling never idled, so an idle
// timeout could not reach it; a single connection held across a multi-minute
// build can.
const forwardKeepaliveInterval = 30 * time.Second

// Addr is the local endpoint clients must dial. Callers that let the kernel
// pick the port (localPort 0) have no other way to learn it.
func (forward *LocalForward) Addr() string {
	if forward == nil || forward.listener == nil {
		return ""
	}
	return forward.listener.Addr().String()
}

// Err reports the first transport failure observed while the forward was
// running, or nil. A forward whose SSH transport died has silently dropped
// registry traffic, so callers must not treat that as success.
func (forward *LocalForward) Err() error {
	if forward == nil {
		return nil
	}
	forward.mu.Lock()
	defer forward.mu.Unlock()
	return forward.failure
}

// fail records the first transport failure and stops accepting. Keeping the
// listener open would hand every later caller a socket that is accepted and
// then immediately dropped, which docker reports as an opaque EOF; refusing the
// TCP connect outright surfaces the real cause at the first attempt.
func (forward *LocalForward) fail(err error) {
	if err == nil {
		return
	}
	forward.mu.Lock()
	if forward.closing || forward.failure != nil {
		forward.mu.Unlock()
		return
	}
	forward.failure = err
	forward.mu.Unlock()
	_ = forward.listener.Close()
}

func (forward *LocalForward) Close() error {
	if forward == nil || forward.listener == nil {
		return nil
	}
	forward.mu.Lock()
	forward.closing = true
	failure := forward.failure
	forward.mu.Unlock()
	closeErr := forward.listener.Close()
	// Closing the shared transport also tears down every channel still in
	// flight, which is what unblocks the copy loops the accept goroutine waits
	// on below. Closing it after the listener keeps that order deadlock-free.
	if forward.client != nil {
		_ = forward.client.Close()
	}
	<-forward.done
	if failure != nil {
		return failure
	}
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

func (c *Client) StartLocalForward(localPort int, remotePort int) (*LocalForward, error) {
	connection, err := gossh.Dial("tcp", c.endpoint(), c.cfg)
	if err != nil {
		return nil, fmt.Errorf("open SSH transport for local forward: %w", err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	forward := &LocalForward{listener: listener, client: connection, done: make(chan struct{})}
	go func() {
		defer close(forward.done)
		var inFlight sync.WaitGroup
		for {
			local, acceptErr := listener.Accept()
			if acceptErr != nil {
				break
			}
			inFlight.Add(1)
			go func() {
				defer inFlight.Done()
				forward.forwardConnection(local, remotePort)
			}()
		}
		inFlight.Wait()
	}()
	go forward.watchTransport()
	return forward, nil
}

// watchTransport turns a dead SSH transport into a closed listener plus a
// recorded error instead of an endlessly accepting forward that drops
// everything it is handed.
func (forward *LocalForward) watchTransport() {
	waitDone := make(chan error, 1)
	go func() { waitDone <- forward.client.Wait() }()
	ticker := time.NewTicker(forwardKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-waitDone:
			forward.fail(fmt.Errorf("SSH transport for the local forward closed: %w", err))
			return
		case <-forward.done:
			return
		case <-ticker.C:
			// A refused keepalive (ok=false) is fine: only a transport-level
			// error means the connection is gone.
			if _, _, err := forward.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				forward.fail(fmt.Errorf("SSH transport for the local forward stopped answering: %w", err))
				return
			}
		}
	}
}

func (forward *LocalForward) forwardConnection(local net.Conn, remotePort int) {
	defer local.Close()
	remote, err := forward.client.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)))
	if err != nil {
		// Returning in silence here is what made a broken tunnel look like a
		// flaky registry: record the cause so Close reports it.
		forward.fail(fmt.Errorf("open forwarded channel to 127.0.0.1:%d: %w", remotePort, err))
		return
	}
	defer remote.Close()
	go func() {
		_, _ = io.Copy(remote, local)
		// Half-close rather than close: the registry still has to write the
		// response to the request body that just ended. Tearing the whole
		// channel down at that point is exactly what turns a completed upload
		// into "connection reset by peer".
		closeWriteSide(remote)
	}()
	// The remote side ending is the authoritative end of the exchange; the
	// deferred closes above then unblock the copy goroutine. Waiting on the
	// remote (an SSH channel) also keeps Close able to unblock this goroutine.
	_, _ = io.Copy(local, remote)
}

// closeWriteSide sends EOF in one direction when the connection supports it.
// Both *net.TCPConn and the SSH channel connection returned by Client.Dial do.
func closeWriteSide(conn net.Conn) {
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

const (
	defaultSSHOperationTimeout = 2 * time.Minute
	defaultSSHMaxOutputBytes   = 4 * 1024 * 1024
)

type Result struct {
	Stdout string
	Stderr string
	Code   int
	// OutcomeUnknown means the remote command may have started, but its exit
	// status was not received. Callers can safely retry only with an idempotent
	// request identity.
	OutcomeUnknown bool
	// ConnectRefused is set only when the TCP connect itself was refused,
	// before any SSH session existed: nothing ran on the host. Text in Stderr
	// cannot prove that, since a remote command may print the same words.
	ConnectRefused bool
}

// ManagedCommand keeps one SSH session in the foreground while a runner
// operation is active. The remote supervisor reads heartbeats from stdin, so
// an SSH disconnect reaches the runner without relying on a later reconnect.
type ManagedCommand struct {
	session    *gossh.Session
	stdin      io.WriteCloser
	connection *gossh.Client
	transport  net.Conn
	done       chan Result
	mu         sync.Mutex
	closed     bool
	writeGate  chan struct{}
	finished   chan struct{}
	ready      chan struct{}
	resultMu   sync.Mutex
	result     Result
	resultSet  bool
	closeDone  chan struct{}
	abortOnce  sync.Once
}

const (
	managedCommandMaxLifetime = 20 * time.Minute
	managedCommandWriteLimit  = 5 * time.Second
	managedCommandCloseLimit  = 10 * time.Second
)

// StartManaged starts a bounded foreground control command. Its input is
// reserved for control messages and is never combined with command text.
func (c *Client) StartManaged(command string) (*ManagedCommand, error) {
	return c.startManaged(command, "")
}

// StartManagedReady starts a managed command and exposes a readiness marker
// emitted by the remote supervisor. The marker is observed from stdout, so
// the caller does not need a second SSH command to prove the trap is active.
func (c *Client) StartManagedReady(command, marker string) (*ManagedCommand, error) {
	if strings.TrimSpace(marker) == "" {
		return nil, errors.New("managed SSH readiness marker is required")
	}
	return c.startManaged(command, marker)
}

func (c *Client) startManaged(command, marker string) (*ManagedCommand, error) {
	connection, transport, _, err := c.dialOperation()
	if err != nil {
		return nil, err
	}
	if err := transport.SetDeadline(time.Now().Add(managedCommandMaxLifetime)); err != nil {
		_ = connection.Close()
		_ = transport.Close()
		return nil, err
	}
	session, err := connection.NewSession()
	if err != nil {
		_ = connection.Close()
		_ = transport.Close()
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = connection.Close()
		_ = transport.Close()
		return nil, err
	}
	stdoutBuffer := newBoundedSSHBuffer(c.outputLimit())
	stderr := newBoundedSSHBuffer(c.outputLimit())
	ready := make(chan struct{})
	var stdout io.Writer = stdoutBuffer
	if marker != "" {
		stdout = &managedReadyWriter{buffer: stdoutBuffer, marker: marker, ready: ready}
	}
	session.Stdout = stdout
	session.Stderr = stderr
	if err := session.Start(command); err != nil {
		_ = stdin.Close()
		_ = session.Close()
		_ = connection.Close()
		_ = transport.Close()
		return nil, err
	}
	managed := &ManagedCommand{
		session: session, stdin: stdin, connection: connection,
		transport: transport, done: make(chan Result, 1), finished: make(chan struct{}),
		writeGate: make(chan struct{}, 1),
	}
	managed.writeGate <- struct{}{}
	if marker != "" {
		managed.ready = ready
	}
	go func() {
		err := session.Wait()
		result := boundedSSHResult(0, stdoutBuffer, stderr)
		if err != nil {
			if exit, ok := err.(*gossh.ExitError); ok {
				result.Code = exit.ExitStatus()
			} else {
				result.Code = 1
			}
			if result.Stderr == "" {
				result.Stderr = err.Error()
			}
		}
		_ = connection.Close()
		_ = transport.Close()
		managed.complete(result)
		managed.done <- result
	}()
	return managed, nil
}

// Write sends one control message to a managed remote supervisor.
func (m *ManagedCommand) Write(message string) error {
	if m == nil {
		return errors.New("managed SSH command is unavailable")
	}
	return m.write(message, false, time.Now().Add(managedCommandWriteLimit))
}

func (m *ManagedCommand) write(message string, allowClosed bool, deadline time.Time) error {
	if m.stdin == nil {
		return errors.New("managed SSH command is unavailable")
	}
	m.mu.Lock()
	if m.writeGate == nil {
		m.writeGate = make(chan struct{}, 1)
		m.writeGate <- struct{}{}
	}
	gate := m.writeGate
	closed := m.closed
	m.mu.Unlock()
	if closed && !allowClosed {
		return errors.New("managed SSH command is closed")
	}
	if err := waitForManagedGate(gate, deadline); err != nil {
		return err
	}
	defer func() { gate <- struct{}{} }()
	if !allowClosed {
		m.mu.Lock()
		closed = m.closed
		m.mu.Unlock()
		if closed {
			return errors.New("managed SSH command is closed")
		}
	}
	if setter, ok := m.stdin.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = setter.SetWriteDeadline(deadline)
	}
	result := make(chan error, 1)
	go func() {
		_, err := io.WriteString(m.stdin, message)
		result <- err
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		m.abortTransport()
		return errors.New("managed SSH control write timed out")
	}
}

func waitForManagedGate(gate chan struct{}, deadline time.Time) error {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return errors.New("managed SSH control lock timed out")
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-gate:
		return nil
	case <-timer.C:
		return errors.New("managed SSH control lock timed out")
	}
}

// Ready reports the marker channel for StartManagedReady. It is nil for an
// ordinary managed command.
func (m *ManagedCommand) Ready() <-chan struct{} {
	if m == nil {
		return nil
	}
	return m.ready
}

// WaitReady waits for effective remote supervision to be installed.
func (m *ManagedCommand) WaitReady(ctx context.Context) error {
	if m == nil || m.ready == nil {
		return errors.New("managed SSH readiness is unavailable")
	}
	select {
	case <-m.ready:
		return nil
	case <-m.finished:
		result := m.resultValue()
		return fmt.Errorf("managed SSH command exited before readiness: %s", boundedDiagnostic(result.Stderr, result.Stdout))
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done reports the supervisor result once its foreground command exits.
func (m *ManagedCommand) Done() <-chan Result {
	if m == nil {
		return nil
	}
	return m.done
}

// Close asks the remote supervisor to clean up, then bounds the local wait.
func (m *ManagedCommand) Close() Result {
	if m == nil {
		return Result{}
	}
	m.mu.Lock()
	if m.closeDone == nil {
		m.closeDone = make(chan struct{})
		m.closed = true
		closeDone := m.closeDone
		m.mu.Unlock()
		result := m.closeInternal()
		m.resultMu.Lock()
		m.result = result
		m.resultSet = true
		m.resultMu.Unlock()
		close(closeDone)
		return result
	}
	closeDone := m.closeDone
	m.mu.Unlock()
	<-closeDone
	return m.resultValue()
}

func (m *ManagedCommand) closeInternal() Result {
	deadline := time.Now().Add(managedCommandCloseLimit)
	_ = m.write("close\n", true, deadline)
	_ = m.stdin.Close()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		m.abortTransport()
		return Result{Code: 124, Stderr: "managed SSH cleanup timed out"}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-m.finished:
		return m.resultValue()
	case <-timer.C:
		m.abortTransport()
		return Result{Code: 124, Stderr: "managed SSH cleanup timed out"}
	}
}

func (m *ManagedCommand) complete(result Result) {
	m.resultMu.Lock()
	if !m.resultSet {
		m.result = result
		m.resultSet = true
	}
	m.resultMu.Unlock()
	if m.finished != nil {
		close(m.finished)
	}
}

func (m *ManagedCommand) resultValue() Result {
	m.resultMu.Lock()
	defer m.resultMu.Unlock()
	return m.result
}

func (m *ManagedCommand) abortTransport() {
	m.abortOnce.Do(func() {
		if m.stdin != nil {
			_ = m.stdin.Close()
		}
		if m.session != nil {
			_ = m.session.Close()
		}
		if m.connection != nil {
			_ = m.connection.Close()
		}
		if m.transport != nil {
			_ = m.transport.Close()
		}
	})
}

type managedReadyWriter struct {
	buffer *boundedSSHBuffer
	marker string
	ready  chan struct{}
	mu     sync.Mutex
	scan   string
	once   sync.Once
}

func (w *managedReadyWriter) Write(value []byte) (int, error) {
	n, err := w.buffer.Write(value)
	w.mu.Lock()
	w.scan += string(value[:n])
	if len(w.scan) > len(w.marker)+1 {
		w.scan = w.scan[len(w.scan)-len(w.marker)-1:]
	}
	if strings.Contains(w.scan, w.marker+"\n") || strings.TrimSpace(w.scan) == w.marker {
		w.once.Do(func() { close(w.ready) })
	}
	w.mu.Unlock()
	return n, err
}

type clientTarget struct {
	Host           string
	User           string
	Port           int
	IdentityFiles  []string
	IdentitiesOnly bool
}

// resolveSSHConfigSnapshot is test-injectable so guarded callers can prove
// their target is resolved exactly once before it is validated and used.
var resolveSSHConfigSnapshot = resolveSSHConfig

var sshInputIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

var readSSHKeyPassphrase = func(path string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "Passphrase for SSH key %s: ", path)
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return passphrase, err
}

var dialSSHAgent = func(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func resolveClientTarget(host string, username string, port int) (clientTarget, error) {
	return resolveClientTargetWithPolicy(host, username, port, true)
}

func resolveClientTargetExplicit(host string, username string, port int) (clientTarget, error) {
	return resolveClientTargetWithPolicy(host, username, port, false)
}

func resolveClientTargetWithPolicy(host string, username string, port int, enforceConfiguredIdentities bool) (clientTarget, error) {
	resolved, err := resolveSSHConfigSnapshot(host, username)
	if err != nil {
		return clientTarget{}, err
	}
	if enforceConfiguredIdentities && resolved.IdentitiesOnly && len(resolved.IdentityFiles) != 1 {
		return clientTarget{}, fmt.Errorf("IdentitiesOnly yes requires exactly one IdentityFile for %s", host)
	}
	target := clientTarget{Host: host, User: username, Port: port, IdentityFiles: append([]string(nil), resolved.IdentityFiles...), IdentitiesOnly: resolved.IdentitiesOnly}
	if resolved.HostName != "" {
		target.Host = resolved.HostName
	}
	if target.User == "" && resolved.User != "" {
		target.User = resolved.User
	}
	if target.Port == 0 || target.Port == 22 && resolved.Port != 0 {
		target.Port = resolved.Port
	}
	if target.User == "" {
		current, err := user.Current()
		if err == nil {
			target.User = current.Username
		}
	}
	if target.Port == 0 {
		target.Port = 22
	}
	return target, nil
}

// NewClientExactWithFingerprint binds a literal endpoint to an independently
// supplied OpenSSH SHA256 host-key fingerprint. It is intended for first
// contact after an out-of-band attestation, where known_hosts cannot yet be
// the source of trust. The observed key is never returned or persisted.
func NewClientExactWithFingerprint(host string, username string, port int, expectedFingerprint string) (*Client, error) {
	return newClientExact(host, username, port, expectedFingerprint, nil, false, false)
}

// NewClientExactWithIdentity creates a client whose only authentication method
// is the explicitly named private key. It is used for a build runner identity:
// the deploy account key and the local SSH agent must never be reused for that
// connection.
func NewClientExactWithIdentity(host string, username string, port int, expectedFingerprint string, identityFile string) (*Client, error) {
	if strings.TrimSpace(identityFile) == "" {
		return nil, errors.New("an explicit SSH identity file is required")
	}
	return newClientExact(host, username, port, expectedFingerprint, []string{identityFile}, true, false)
}

// NewClientExactWithResolvedIdentity permits an SSH config alias to resolve
// the hostname while keeping the explicit user, port and fingerprint pinned.
// The resolved endpoint is then reused by Docker's SSH transport.
func NewClientExactWithResolvedIdentity(host string, username string, port int, expectedFingerprint string, identityFile string) (*Client, error) {
	if strings.TrimSpace(identityFile) == "" {
		return nil, errors.New("an explicit SSH identity file is required")
	}
	return newClientExact(host, username, port, expectedFingerprint, []string{identityFile}, true, true)
}

func newClientExact(host string, username string, port int, expectedFingerprint string, identityFiles []string, identitiesOnly, allowHostRewrite bool) (*Client, error) {
	if !validSHA256Fingerprint(expectedFingerprint) {
		return nil, fmt.Errorf("expected SSH host-key fingerprint must use OpenSSH SHA256 format")
	}
	var target clientTarget
	var err error
	if identitiesOnly {
		target, err = resolveClientTargetExplicit(host, username, port)
	} else {
		target, err = resolveClientTarget(host, username, port)
	}
	if err != nil {
		return nil, err
	}
	expectedPort := port
	if expectedPort == 0 {
		expectedPort = 22
	}
	if target.User != username || target.Port != expectedPort || (!allowHostRewrite && target.Host != host) {
		return nil, fmt.Errorf("SSH config rewrites guarded target %s@%s:%d to %s@%s:%d; refusing identity-unsafe transition", username, host, expectedPort, target.User, target.Host, target.Port)
	}
	if identitiesOnly {
		target.IdentityFiles = append([]string(nil), identityFiles...)
		target.IdentitiesOnly = true
	}
	auth, err := authMethods(target.IdentityFiles, target.IdentitiesOnly || identitiesOnly)
	if err != nil {
		return nil, err
	}
	client := &Client{
		Host: target.Host, User: target.User, Port: target.Port,
		operationTimeout: defaultSSHOperationTimeout,
		maxOutputBytes:   defaultSSHMaxOutputBytes,
	}
	callback := func(_ string, _ net.Addr, key gossh.PublicKey) error {
		if key.Type() != gossh.KeyAlgoED25519 {
			return errors.New("SSH host key must be ED25519 for first contact")
		}
		actual := gossh.FingerprintSHA256(key)
		if len(actual) != len(expectedFingerprint) || subtle.ConstantTimeCompare([]byte(actual), []byte(expectedFingerprint)) != 1 {
			return errors.New("SSH host key does not match the out-of-band attestation")
		}
		client.hostKeyMu.Lock()
		client.hostKey = key
		client.hostKeyMu.Unlock()
		return nil
	}
	client.cfg = &gossh.ClientConfig{
		User: target.User, Auth: auth, HostKeyCallback: callback, Timeout: 20 * time.Second,
		HostKeyAlgorithms: []string{gossh.KeyAlgoED25519},
	}
	return client, nil
}

// VerifyHostKey performs the exact SSH handshake and closes it immediately.
// It returns no remote command result, so it is suitable for preparing a
// strict known_hosts file for a second SSH client without using keyscan.
func (c *Client) VerifyHostKey() error {
	connection, transport, _, err := c.dialOperation()
	if err != nil {
		return err
	}
	_ = connection.Close()
	_ = transport.Close()
	return nil
}

// FreezeResolvedEndpoint resolves a hostname once and makes the selected
// address the endpoint for subsequent SSH operations. Callers that compare a
// target before a remote tunnel must not validate one DNS answer and dial a
// later answer.
func (c *Client) FreezeResolvedEndpoint() error {
	if c == nil {
		return errors.New("SSH client is nil")
	}
	host := strings.Trim(strings.TrimSpace(c.Host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		c.Host = ip.String()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve SSH endpoint %s: %w", host, err)
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, address.IP)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve SSH endpoint %s: no IPv4 or IPv6 address", host)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
	c.Host = ips[0].String()
	return nil
}

// KnownHostsLine returns the observed ED25519 key in OpenSSH known_hosts form.
// The key must have been observed by VerifyHostKey or a successful operation.
func (c *Client) KnownHostsLine(host string, port int) (string, error) {
	if c == nil {
		return "", errors.New("SSH client is nil")
	}
	c.hostKeyMu.RLock()
	key := c.hostKey
	c.hostKeyMu.RUnlock()
	if key == nil {
		return "", errors.New("SSH host key has not been observed")
	}
	if port == 0 {
		port = 22
	}
	name := host
	if port != 22 {
		name = "[" + strings.Trim(host, "[]") + "]:" + strconv.Itoa(port)
	}
	return name + " " + key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()), nil
}

func validSHA256Fingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") || len(value) != len("SHA256:")+43 {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(decoded) == sha256.Size
}

func (c *Client) endpoint() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

type sshConfig struct {
	HostName          string
	User              string
	Port              int
	IdentityFiles     []string
	IdentitiesOnly    bool
	identitiesOnlySet bool
}

func resolveSSHConfig(host string, user string) (sshConfig, error) {
	path := filepath.Join(homeDir(), ".ssh", "config")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sshConfig{}, nil
		}
		return sshConfig{}, err
	}
	cfg := sshConfig{}
	applies := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			key, value, ok = strings.Cut(line, "\t")
		}
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "host":
			applies = hostMatches(host, strings.Fields(value))
		case "match":
			// Match replaces the previous Host decision. On 2026-10-28,
			// setup --adopt ignored Match host/user and failed to load the
			// operator's key; unknown criteria must also stay false so their
			// IdentityFile values cannot leak from a matching Host block.
			applies = matchSSHConfig(host, user, strings.Fields(value))
		case "hostname":
			if applies && cfg.HostName == "" {
				cfg.HostName = value
			}
		case "user":
			if applies && cfg.User == "" {
				cfg.User = value
			}
		case "port":
			if applies && cfg.Port == 0 {
				parsed, err := strconv.Atoi(value)
				if err != nil || parsed < 1 || parsed > 65535 {
					return sshConfig{}, fmt.Errorf("invalid Port %q in %s", value, path)
				}
				cfg.Port = parsed
			}
		case "identityfile":
			if applies {
				cfg.IdentityFiles = append(cfg.IdentityFiles, expandPath(value))
			}
		case "identitiesonly":
			if applies && !cfg.identitiesOnlySet {
				switch strings.ToLower(value) {
				case "yes":
					cfg.IdentitiesOnly = true
				case "no":
					cfg.IdentitiesOnly = false
				default:
					return sshConfig{}, fmt.Errorf("invalid IdentitiesOnly %q in %s", value, path)
				}
				cfg.identitiesOnlySet = true
			}
		}
	}
	return cfg, nil
}

func matchSSHConfig(host string, user string, criteria []string) bool {
	if len(criteria) == 0 {
		return false
	}

	matched := true
	for i := 0; i < len(criteria); {
		criterion := strings.ToLower(criteria[i])
		i++
		switch criterion {
		case "all":
		case "host", "originalhost":
			if i >= len(criteria) {
				return false
			}
			matched = matched && hostMatches(host, []string{criteria[i]})
			i++
		case "user":
			if i >= len(criteria) {
				return false
			}
			matched = matched && hostMatches(user, []string{criteria[i]})
			i++
		default:
			return false
		}
	}
	return matched
}

func hostMatches(host string, patterns []string) bool {
	matched := false
	for _, patternList := range patterns {
		for _, pattern := range strings.Split(patternList, ",") {
			negated := strings.HasPrefix(pattern, "!")
			pattern = strings.TrimPrefix(pattern, "!")
			ok, err := filepath.Match(pattern, host)
			if err != nil {
				ok = pattern == host
			}
			if ok && negated {
				return false
			}
			if ok {
				matched = true
			}
		}
	}
	return matched
}

func authMethods(identityFiles []string, identitiesOnly bool) ([]gossh.AuthMethod, error) {
	methods := []gossh.AuthMethod{}
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" && !identitiesOnly {
		conn, err := dialSSHAgent("unix", socket)
		if err == nil {
			agentClient := agent.NewClient(conn)
			signers, signerErr := agentClient.Signers()
			if signerErr == nil && len(signers) > 0 {
				// Agent-backed signers still use this connection when the SSH
				// handshake requests a signature. Keep it alive for the client
				// lifetime; an empty or broken agent has nothing to retain.
				methods = append(methods, gossh.PublicKeysCallback(agentClient.Signers))
			} else {
				_ = conn.Close()
			}
		}
	}
	type encryptedIdentity struct {
		path string
		body []byte
	}
	encrypted := []encryptedIdentity{}
	signers := []gossh.Signer{}
	seen := map[string]bool{}
	candidates := append([]string{}, identityFiles...)
	if !identitiesOnly {
		candidates = append(candidates,
			filepath.Join(homeDir(), ".ssh", "id_shuttle"),
			filepath.Join(homeDir(), ".ssh", "id_ed25519"),
			filepath.Join(homeDir(), ".ssh", "id_rsa"),
		)
	}
	for _, path := range candidates {
		path = expandPath(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		key, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		signer, err := gossh.ParsePrivateKey(key)
		if err != nil {
			var missing *gossh.PassphraseMissingError
			if errors.As(err, &missing) {
				encrypted = append(encrypted, encryptedIdentity{path: path, body: key})
				continue
			}
			return nil, fmt.Errorf("parse SSH private key %s: %w", path, err)
		}
		signers = append(signers, signer)
	}
	// Every identity travels in ONE publickey method, in configuration order.
	// The SSH client marks an authentication method as tried by its name, so a
	// second gossh.PublicKeys is never attempted once the first has failed: two
	// IdentityFile lines meant only the first key was ever offered, and the
	// account the second key belongs to could not be reached at all. OpenSSH
	// offers them in turn on the same method, and so do we.
	if len(signers) > 0 {
		methods = append(methods, gossh.PublicKeys(signers...))
	}
	if sshInputIsTerminal() {
		for _, identity := range encrypted {
			candidate := identity
			methods = append(methods, gossh.PublicKeysCallback(func() ([]gossh.Signer, error) {
				return decryptSSHIdentity(candidate.path, candidate.body)
			}))
		}
	}
	if len(methods) == 0 {
		if len(encrypted) > 0 {
			if identitiesOnly {
				return nil, fmt.Errorf("encrypted SSH private key found at %s; run Shuttle interactively because IdentitiesOnly yes excludes the SSH agent", encrypted[0].path)
			}
			return nil, fmt.Errorf("encrypted SSH private key found at %s; run interactively or load it into ssh-agent", encrypted[0].path)
		}
		if identitiesOnly && len(identityFiles) > 0 {
			return nil, errors.New("no configured IdentityFile could be loaded with IdentitiesOnly yes")
		}
		return nil, fmt.Errorf("no SSH auth method found; load ssh-agent or add ~/.ssh/id_shuttle, ~/.ssh/id_ed25519, or ~/.ssh/id_rsa")
	}
	return methods, nil
}

func decryptSSHIdentity(path string, body []byte) ([]gossh.Signer, error) {
	passphrase, err := readSSHKeyPassphrase(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH private-key passphrase: %w", err)
	}
	defer func() {
		for index := range passphrase {
			passphrase[index] = 0
		}
	}()
	signer, err := gossh.ParsePrivateKeyWithPassphrase(body, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt SSH private key %s: %w", path, err)
	}
	return []gossh.Signer{signer}, nil
}

func expandPath(path string) string {
	if path == "~" {
		return homeDir()
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(homeDir(), strings.TrimPrefix(path, "~/"))
	}
	return os.ExpandEnv(path)
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// SetOperationTimeout raises the transport deadline this client puts on one
// remote operation.
//
// It only ever raises it, never lowers it, so no existing caller can be given
// less time than the two-minute default by a configuration mistake. It exists
// because one caller genuinely needs more: the signed stack promotion now waits
// on the host until the release is actually running, and that wait is sized
// from deploy.promotion_slo_seconds, which may legally reach 600. A flat
// two-minute deadline would cut the session mid-wait and report a failed
// promotion for a deploy that was in fact still converging, while the helper
// kept running as root, holding its operation lock, so the operator's retry
// would queue behind it.
func (c *Client) SetOperationTimeout(timeout time.Duration) {
	if timeout > c.operationTimeout {
		c.operationTimeout = timeout
	}
}

func (c *Client) Run(command string) Result {
	return c.run(command, nil)
}

// RunWithStdin executes command while streaming input over the SSH session's
// standard input. The input is never appended to or interpreted as command text.
func (c *Client) RunWithStdin(command string, input []byte) Result {
	return c.run(command, bytes.NewReader(input))
}

// RunWithStdinContext runs one stdin command with a caller-owned deadline.
// Recovery status probes share clients with keepalives, so changing the shared
// operation timeout here would race its concurrent, unguarded read.
func (c *Client) RunWithStdinContext(ctx context.Context, command string, input []byte) Result {
	return c.runContext(ctx, command, bytes.NewReader(input))
}

// RunWithReader executes command while streaming input from a reader over the
// SSH session's standard input. It exists for payloads that must not be held
// in memory, an image archive of several hundred megabytes, and, like
// RunWithStdin, never lets the input near the command text. The operation
// deadline still applies: size it with SetOperationTimeout before streaming.
func (c *Client) RunWithReader(command string, input io.Reader) Result {
	return c.run(command, input)
}

func (c *Client) run(command string, input io.Reader) Result {
	return c.runContext(context.Background(), command, input)
}

func (c *Client) runContext(ctx context.Context, command string, input io.Reader) Result {
	return c.runContextOutput(ctx, command, input, nil)
}

// RunWithStreams transfers archives without buffering them in memory or placing
// binary data in diagnostics. Stderr and the operation deadline remain bounded.
func (c *Client) RunWithStreams(command string, input io.Reader, output io.Writer) Result {
	return c.runContextOutput(context.Background(), command, input, output)
}

func (c *Client) runContextOutput(ctx context.Context, command string, input io.Reader, output io.Writer) Result {
	if err := ctx.Err(); err != nil {
		return sshContextResult(err)
	}
	conn, transport, deadline, err := c.dialOperationContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return sshContextResult(ctx.Err())
		}
		result := sshOperationError(err, 255)
		result.ConnectRefused = errors.Is(err, syscall.ECONNREFUSED)
		return result
	}
	defer conn.Close()
	defer transport.Close()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = transport.SetDeadline(time.Now())
		case <-watchDone:
		}
	}()

	session, err := conn.NewSession()
	if err != nil {
		return Result{Code: 255, Stderr: err.Error()}
	}
	defer session.Close()

	stdout := newBoundedSSHBuffer(c.outputLimit())
	stderr := newBoundedSSHBuffer(c.outputLimit())
	session.Stdout = stdout
	if output != nil {
		session.Stdout = output
	}
	session.Stderr = stderr
	if input != nil {
		session.Stdin = input
	}

	err = session.Run(command)
	if err != nil {
		if ctx.Err() != nil {
			result := sshContextResult(ctx.Err())
			_, exitStatusReceived := err.(*gossh.ExitError)
			result.OutcomeUnknown = !exitStatusReceived
			return result
		}
		if exit, ok := err.(*gossh.ExitError); ok {
			return boundedSSHResult(exit.ExitStatus(), stdout, stderr)
		}
		result := boundedSSHResult(1, stdout, stderr)
		result.OutcomeUnknown = true
		if isTimeoutError(err) || !time.Now().Before(deadline) {
			result.Code, result.Stderr = 124, "SSH operation timed out"
		} else if result.Stderr == "" {
			result.Stderr = err.Error()
		}
		return result
	}

	return boundedSSHResult(0, stdout, stderr)
}

func (c *Client) UploadContent(content string, remotePath string, mode os.FileMode) Result {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Result{Code: 1, Stderr: "could not create an upload transaction identifier"}
	}
	temporaryPath := remotePath + ".shuttle-upload-" + hex.EncodeToString(nonce)
	conn, transport, deadline, err := c.dialOperation()
	if err != nil {
		return sshOperationError(err, 255)
	}
	defer conn.Close()
	defer transport.Close()

	session, err := conn.NewSession()
	if err != nil {
		return Result{Code: 255, Stderr: err.Error()}
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return Result{Code: 255, Stderr: err.Error()}
	}

	stdout := newBoundedSSHBuffer(c.outputLimit())
	stderr := newBoundedSSHBuffer(c.outputLimit())
	session.Stdout = stdout
	session.Stderr = stderr

	command := fmt.Sprintf("set -eu; umask 077; temporary=%s; trap 'rm -f -- \"$temporary\"' EXIT HUP INT TERM; (set -C; cat > \"$temporary\"); chmod %04o \"$temporary\"; sync -f \"$temporary\" 2>/dev/null || sync; mv -f -- \"$temporary\" %s; sync -f %s 2>/dev/null || sync; trap - EXIT HUP INT TERM", shellQuote(temporaryPath), mode.Perm(), shellQuote(remotePath), shellQuote(path.Dir(remotePath)))
	if err := session.Start(command); err != nil {
		return Result{Code: 1, Stderr: err.Error(), OutcomeUnknown: true}
	}
	if _, err := io.WriteString(stdin, content); err != nil {
		_ = stdin.Close()
		if isTimeoutError(err) || !time.Now().Before(deadline) {
			return Result{Code: 124, Stderr: "SSH operation timed out", OutcomeUnknown: true}
		}
		result := boundedSSHResult(1, stdout, stderr)
		result.OutcomeUnknown = true
		if result.Stderr == "" {
			result.Stderr = err.Error()
		}
		return result
	}
	_ = stdin.Close()
	err = session.Wait()
	if err != nil {
		if exit, ok := err.(*gossh.ExitError); ok {
			return boundedSSHResult(exit.ExitStatus(), stdout, stderr)
		}
		if isTimeoutError(err) || !time.Now().Before(deadline) {
			return Result{Code: 124, Stderr: "SSH operation timed out", OutcomeUnknown: true}
		}
		result := boundedSSHResult(1, stdout, stderr)
		result.OutcomeUnknown = true
		if result.Stderr == "" {
			result.Stderr = err.Error()
		}
		return result
	}
	return boundedSSHResult(0, stdout, stderr)
}

func (c *Client) dialOperation() (*gossh.Client, net.Conn, time.Time, error) {
	return c.dialOperationContext(context.Background())
}

func (c *Client) dialOperationContext(ctx context.Context) (*gossh.Client, net.Conn, time.Time, error) {
	timeout := c.operationTimeout
	if timeout <= 0 {
		timeout = defaultSSHOperationTimeout
	}
	dialer := net.Dialer{Timeout: c.cfg.Timeout}
	transport, err := dialer.DialContext(ctx, "tcp", c.endpoint())
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := transport.SetDeadline(deadline); err != nil {
		_ = transport.Close()
		return nil, nil, time.Time{}, err
	}
	connection, channels, requests, err := gossh.NewClientConn(transport, c.endpoint(), c.cfg)
	if err != nil {
		_ = transport.Close()
		return nil, nil, time.Time{}, err
	}
	return gossh.NewClient(connection, channels, requests), transport, deadline, nil
}

func sshContextResult(err error) Result {
	if errors.Is(err, context.Canceled) {
		return Result{Code: 130, Stderr: "SSH operation cancelled"}
	}
	return Result{Code: 124, Stderr: "SSH operation timed out"}
}

func (c *Client) outputLimit() int {
	if c.maxOutputBytes <= 0 {
		return defaultSSHMaxOutputBytes
	}
	return c.maxOutputBytes
}

type boundedSSHBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func newBoundedSSHBuffer(limit int) *boundedSSHBuffer {
	return &boundedSSHBuffer{remaining: limit}
}

func (buffer *boundedSSHBuffer) Write(value []byte) (int, error) {
	original := len(value)
	written := 0
	if buffer.remaining > 0 {
		count := len(value)
		if count > buffer.remaining {
			count = buffer.remaining
		}
		_, _ = buffer.buffer.Write(value[:count])
		buffer.remaining -= count
		written = count
	}
	if written < original {
		buffer.truncated = true
	}
	return original, nil
}

func (buffer *boundedSSHBuffer) String() string { return buffer.buffer.String() }

func boundedSSHResult(code int, stdout, stderr *boundedSSHBuffer) Result {
	result := Result{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	if stdout.truncated || stderr.truncated {
		result.Code = 1
		result.Stderr = "SSH output exceeded the configured safe limit"
	}
	return result
}

func sshOperationError(err error, defaultCode int) Result {
	if isTimeoutError(err) {
		return Result{Code: 124, Stderr: "SSH operation timed out"}
	}
	return Result{Code: defaultCode, Stderr: err.Error()}
}

func isTimeoutError(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func shellQuote(value string) string {
	var out bytes.Buffer
	out.WriteByte('\'')
	for _, r := range value {
		if r == '\'' {
			out.WriteString("'\\''")
			continue
		}
		out.WriteRune(r)
	}
	out.WriteByte('\'')
	return out.String()
}
