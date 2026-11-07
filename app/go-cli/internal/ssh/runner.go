package ssh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/images"
)

const (
	RemoteRegistryPort   = 5000
	remoteTunnelStateDir = "$HOME/.shuttle/build-runners"

	runnerLeaseTTL          = 20 * time.Minute
	runnerHeartbeatInterval = 10 * time.Second
)

// lookupBuildRunnerIPs is injectable so endpoint comparison tests can model
// IPv4, IPv6 and aliases without changing the host resolver.
var lookupBuildRunnerIPs = func(host string) ([]net.IP, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		ip := address.IP
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, append(net.IP(nil), ip...))
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("host %q has no IPv4 or IPv6 address", host)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

// ProductionEndpoint describes one already configured production SSH target.
// BuildRunner validates every endpoint before it can stop a builder or bind a
// registry port on the runner.
type ProductionEndpoint struct {
	Host    string
	User    string
	Port    int
	HostKey string
}

// BuildRunnerConfig contains the credentials for the dedicated BuildKit
// machine. RegistryIdentityFile is intentionally a path on that machine. It
// is never opened or copied by the client.
type BuildRunnerConfig struct {
	Host                 string
	User                 string
	Port                 int
	HostKey              string
	IdentityFile         string
	RegistryIdentityFile string
}

// BuildRunner manages one persistent docker-container BuildKit builder on a
// dedicated guest. The builder cache is a Docker volume and survives Stop.
type BuildRunner struct {
	Config          BuildRunnerConfig
	client          *Client
	builderName     string
	builderImage    string
	resolveBuildKit func(context.Context) (string, error)

	mu            sync.Mutex
	prepareMu     sync.Mutex
	leaseMu       sync.Mutex
	prepared      bool
	knownHosts    string
	transportDir  string
	sshPath       string
	dockerPath    string
	runnerID      string
	runnerIPs     []net.IP
	production    *ProductionEndpoint
	tunnel        *RegistryTunnel
	lease         *runnerLease
	closed        bool
	remoteRun     func(string) Result
	dockerRun     func([]string) ([]byte, error)
	dockerExec    func([]string) error
	active        map[*exec.Cmd]struct{}
	runContext    context.Context
	leaseStarting bool
	closeErr      error
	closeDone     chan struct{}
	fenceResults  map[string]FenceResult
	fenceMu       sync.Mutex
}

type runnerLease struct {
	token              string
	app                string
	supervisor         *ManagedCommand
	stop               chan struct{}
	done               chan struct{}
	ctx                context.Context
	cancel             context.CancelFunc
	heartbeatErr       chan error
	supervisorResult   Result
	startedAt          time.Time
	revoked            bool
	admission          string
	bootID             string
	namespace          string
	tunnelIdentity     string
	actualContainerIDs []string
	mutationPending    bool
	finishOnce         sync.Once
}

// NewBuildRunner validates and prepares the authenticated client. Network
// access starts only when Prepare is called, which keeps dry-run planning
// read-only.
func NewBuildRunner(cfg BuildRunnerConfig) (*BuildRunner, error) {
	if strings.TrimSpace(cfg.Host) == "" || strings.TrimSpace(cfg.User) == "" {
		return nil, errors.New("build runner requires host and user")
	}
	if cfg.User == "root" {
		return nil, errors.New("build runner requires a dedicated non-root Unix account")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("build runner port must be between 1 and 65535, got %d", cfg.Port)
	}
	if strings.TrimSpace(cfg.RegistryIdentityFile) == "" {
		return nil, errors.New("build runner requires an independent registry identity file on the runner")
	}
	client, err := NewClientExactWithResolvedIdentity(cfg.Host, cfg.User, cfg.Port, cfg.HostKey, cfg.IdentityFile)
	if err != nil {
		return nil, fmt.Errorf("build runner %s@%s: %w", cfg.User, cfg.Host, err)
	}
	cfg.IdentityFile = expandPath(cfg.IdentityFile)
	runner := &BuildRunner{Config: cfg, client: client, active: make(map[*exec.Cmd]struct{}), fenceResults: make(map[string]FenceResult)}
	runner.runnerID = runnerIdentity(client.Host, client.User, client.Port, cfg.HostKey)
	runner.remoteRun = client.Run
	runner.dockerRun = runner.defaultDockerOutput
	runner.dockerExec = runner.defaultDocker
	return runner, nil
}

func runnerIdentity(host, user string, port int, hostKey string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{host, user, strconv.Itoa(port), hostKey}, "\x00")))
	return hex.EncodeToString(digest[:8])
}

// SetProductionTarget checks one production endpoint. It is retained as the
// small compatibility API for callers that have one VPS.
func (r *BuildRunner) SetProductionTarget(host, user string, port int, hostKey string) error {
	return r.ValidateProductionTargets([]ProductionEndpoint{{Host: host, User: user, Port: port, HostKey: hostKey}})
}

// ValidateProductionTarget rejects both a literal production host and an SSH
// config alias that resolves to any production address.
func (r *BuildRunner) ValidateProductionTarget(host, user string, port int) error {
	return r.ValidateProductionTargets([]ProductionEndpoint{{Host: host, User: user, Port: port}})
}

// ValidateProductionTargets compares all resolved production addresses and
// host-key pins before any Docker operation. A shared address or fingerprint
// is a refusal even when the configured names differ.
func (r *BuildRunner) ValidateProductionTargets(endpoints []ProductionEndpoint) error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	if len(endpoints) == 0 {
		return errors.New("at least one production endpoint is required")
	}
	runnerHost, runnerUser, runnerPort := r.endpoint()
	if r.client == nil {
		resolvedRunner, resolveErr := resolveClientTargetExplicit(r.Config.Host, r.Config.User, r.Config.Port)
		if resolveErr != nil {
			return fmt.Errorf("resolve build runner endpoint %s: %w", r.Config.Host, resolveErr)
		}
		runnerHost, runnerUser, runnerPort = resolvedRunner.Host, resolvedRunner.User, resolvedRunner.Port
	}
	runnerIPs, err := lookupBuildRunnerIPs(runnerHost)
	if err != nil {
		return fmt.Errorf("resolve build runner endpoint %s: %w", runnerHost, err)
	}
	var verifiedProduction *ProductionEndpoint
	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint.Host) == "" || strings.TrimSpace(endpoint.User) == "" {
			return errors.New("production endpoint requires host and user")
		}
		if endpoint.Port == 0 {
			endpoint.Port = 22
		}
		production, err := resolveClientTargetExplicit(endpoint.Host, endpoint.User, endpoint.Port)
		if err != nil {
			return fmt.Errorf("resolve production endpoint %s@%s: %w", endpoint.User, endpoint.Host, err)
		}
		productionIPs, err := lookupBuildRunnerIPs(production.Host)
		if err != nil {
			return fmt.Errorf("resolve production endpoint %s: %w", production.Host, err)
		}
		for _, runnerIP := range runnerIPs {
			for _, productionIP := range productionIPs {
				if runnerIP.Equal(productionIP) {
					return fmt.Errorf("build runner %s@%s:%d resolves to the production target %s@%s:%d; use a dedicated build guest", runnerUser, runnerHost, runnerPort, endpoint.User, endpoint.Host, endpoint.Port)
				}
			}
		}
		if endpoint.HostKey != "" && endpoint.HostKey == r.Config.HostKey {
			return fmt.Errorf("build runner host key is also pinned for production endpoint %s; use a dedicated build guest", endpoint.Host)
		}
		if sameSSHHost(runnerHost, production.Host) || sameSSHHost(r.Config.Host, endpoint.Host) {
			return fmt.Errorf("build runner %s@%s:%d is the production target %s@%s:%d; use a dedicated build guest", r.Config.User, r.Config.Host, r.Config.Port, endpoint.User, endpoint.Host, endpoint.Port)
		}
		if verifiedProduction == nil {
			verifiedProduction = &ProductionEndpoint{
				Host: productionIPs[0].String(), User: production.User,
				Port: production.Port, HostKey: endpoint.HostKey,
			}
		}
	}
	r.mu.Lock()
	r.runnerIPs = cloneIPs(runnerIPs)
	r.runnerID = runnerIdentity(runnerIPs[0].String(), runnerUser, runnerPort, r.Config.HostKey)
	r.production = verifiedProduction
	r.mu.Unlock()
	return nil
}

func cloneIPs(value []net.IP) []net.IP {
	result := make([]net.IP, 0, len(value))
	for _, ip := range value {
		result = append(result, append(net.IP(nil), ip...))
	}
	return result
}

func (r *BuildRunner) endpoint() (host, user string, port int) {
	if r != nil && r.client != nil {
		host, user, port = r.client.Host, r.client.User, r.client.Port
	}
	if host == "" && r != nil {
		host, user, port = r.Config.Host, r.Config.User, r.Config.Port
	}
	if port == 0 {
		port = 22
	}
	return host, user, port
}

func sameSSHHost(left, right string) bool {
	normalize := func(value string) string {
		value = strings.Trim(strings.TrimSpace(value), "[]")
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
		return strings.ToLower(strings.TrimSuffix(value, "."))
	}
	return normalize(left) == normalize(right)
}

func (r *BuildRunner) BuilderName() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.builderName
}

func (r *BuildRunner) SetBuilderName(name string) error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	if name == "" || strings.ContainsAny(name, "\r\n\x00 /'") {
		return errors.New("build runner name is invalid")
	}
	r.mu.Lock()
	r.builderName = name
	r.mu.Unlock()
	return nil
}

// SetBuilderIdentity adds the verified runner, target VPS and application to
// the persistent Buildx identity. The resulting name is stable for the tuple,
// while two VPS targets cannot reuse one another's cache or node.
func (r *BuildRunner) SetBuilderIdentity(app, targetHost string, targetPort int) error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	if !validRunnerComponent(app) || strings.TrimSpace(targetHost) == "" {
		return errors.New("build runner identity requires a valid application and target")
	}
	if targetPort == 0 {
		targetPort = 22
	}
	production, err := resolveClientTargetExplicit(targetHost, r.Config.User, targetPort)
	if err != nil {
		return fmt.Errorf("resolve production target for build runner identity: %w", err)
	}
	targetKey := ""
	if r.production != nil {
		targetKey = r.production.HostKey
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{r.runnerID, production.Host, strconv.Itoa(production.Port), targetKey, app}, "\x00")))
	return r.SetBuilderName("shuttle-" + app + "-remote-" + hex.EncodeToString(digest[:6]))
}

func validRunnerComponent(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func (r *BuildRunner) DockerHost() string {
	if r == nil {
		return ""
	}
	host, user, port := r.endpoint()
	return "ssh://" + user + "@" + net.JoinHostPort(host, strconv.Itoa(port))
}

// VerifiedProductionHost returns the concrete production address selected
// during endpoint comparison. It lets callers reuse the checked DNS answer
// for the production SSH client and the runner-side tunnel.
func (r *BuildRunner) VerifiedProductionHost() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.production == nil {
		return ""
	}
	return r.production.Host
}

// DockerSSHCommand returns the prepared wrapper path for diagnostics and
// compatibility. Docker is invoked with a child-scoped PATH, so this value is
// never passed through DOCKER_SSH_COMMAND.
func (r *BuildRunner) DockerSSHCommand() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.transportDir == "" {
		return ""
	}
	return filepath.Join(r.transportDir, "ssh")
}

// RegistryAddress is the loopback endpoint the remote BuildKit host sees.
func (r *BuildRunner) RegistryAddress() string {
	return "127.0.0.1:" + strconv.Itoa(RemoteRegistryPort)
}

// Prepare performs the verified runner handshake, freezes one resolved
// address, and writes the strict files Docker's SSH helper actually invokes.
func (r *BuildRunner) Prepare() error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	r.prepareMu.Lock()
	defer r.prepareMu.Unlock()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("build runner is already closed")
	}
	if r.prepared {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if r.client == nil {
		return errors.New("build runner SSH client is unavailable")
	}
	if err := r.freezeRunnerEndpoint(); err != nil {
		return err
	}
	sshPath, err := resolveExecutable("ssh")
	if err != nil {
		return fmt.Errorf("resolve OpenSSH for build runner: %w", err)
	}
	if err := r.client.VerifyHostKey(); err != nil {
		return fmt.Errorf("verify build runner host key for %s: %w", r.Config.Host, err)
	}
	line, err := r.client.KnownHostsLine(r.client.Host, r.client.Port)
	if err != nil {
		return fmt.Errorf("record verified build runner host key: %w", err)
	}
	directory, err := os.MkdirTemp("", "shuttle-build-runner-")
	if err != nil {
		return fmt.Errorf("create private build runner transport directory: %w", err)
	}
	removeDirectory := true
	defer func() {
		if removeDirectory {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect build runner transport directory: %w", err)
	}
	knownPath := filepath.Join(directory, "known_hosts")
	if err := writePrivateFile(knownPath, []byte(line+"\n"), 0o600); err != nil {
		return fmt.Errorf("write strict build runner known_hosts: %w", err)
	}
	wrapperPath := filepath.Join(directory, "ssh")
	if err := writePrivateFile(wrapperPath, []byte(r.sshWrapperScript(sshPath, knownPath)), 0o700); err != nil {
		return fmt.Errorf("write private build runner SSH wrapper: %w", err)
	}
	r.mu.Lock()
	r.sshPath = sshPath
	r.transportDir = directory
	r.knownHosts = knownPath
	r.prepared = true
	r.mu.Unlock()
	removeDirectory = false
	return nil
}

func (r *BuildRunner) freezeRunnerEndpoint() error {
	r.mu.Lock()
	host := r.client.Host
	ips := cloneIPs(r.runnerIPs)
	r.mu.Unlock()
	if len(ips) == 0 {
		resolved, err := lookupBuildRunnerIPs(host)
		if err != nil {
			return fmt.Errorf("resolve build runner endpoint %s: %w", host, err)
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return errors.New("build runner endpoint resolved to no address")
	}
	r.client.Host = ips[0].String()
	r.mu.Lock()
	r.runnerIPs = cloneIPs(ips)
	r.runnerID = runnerIdentity(ips[0].String(), r.client.User, r.client.Port, r.Config.HostKey)
	r.mu.Unlock()
	return nil
}

func resolveExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s is not an executable regular file", name)
	}
	return resolved, nil
}

func writePrivateFile(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		return err
	}
	return file.Sync()
}

func (r *BuildRunner) sshWrapperScript(realSSH, knownHosts string) string {
	host, user, port := r.endpoint()
	return strings.Join([]string{
		"#!/bin/sh",
		"set -eu",
		"fail() { echo 'shuttle: rejected Docker SSH transport request' >&2; exit 64; }",
		"expected_user=" + shellQuote(user),
		"expected_port=" + shellQuote(strconv.Itoa(port)),
		"expected_host=" + shellQuote(host),
		"seen_user=0; seen_port=0; seen_t=0; seen_timeout=0; seen_command=0",
		"while [ \"$#\" -gt 0 ]; do",
		"  case \"$1\" in",
		"    '-o ConnectTimeout=30') seen_timeout=$((seen_timeout + 1)); [ \"$seen_timeout\" -eq 1 ] || fail; shift;;",
		"    -o) [ \"$#\" -ge 2 ] || fail; [ \"$2\" = ConnectTimeout=30 ] || fail; seen_timeout=$((seen_timeout + 1)); [ \"$seen_timeout\" -eq 1 ] || fail; shift 2;;",
		"    -oConnectTimeout=30) seen_timeout=$((seen_timeout + 1)); [ \"$seen_timeout\" -eq 1 ] || fail; shift;;",
		"    -l) [ \"$#\" -ge 2 ] || fail; [ \"$seen_user\" -eq 0 ] || fail; [ \"$2\" = \"$expected_user\" ] || fail; seen_user=1; shift 2;;",
		"    -p) [ \"$#\" -ge 2 ] || fail; [ \"$seen_port\" -eq 0 ] || fail; [ \"$2\" = \"$expected_port\" ] || fail; seen_port=1; shift 2;;",
		"    -T) [ \"$seen_t\" -eq 0 ] || fail; seen_t=1; shift;;",
		"    --) shift; [ \"$#\" -ge 2 ] || fail; [ \"$1\" = \"$expected_host\" ] || fail; if [ \"$#\" -eq 2 ]; then [ \"$2\" = 'docker system dial-stdio' ] || fail; elif [ \"$#\" -eq 4 ]; then [ \"$2\" = docker ] && [ \"$3\" = system ] && [ \"$4\" = dial-stdio ] || fail; else fail; fi; seen_command=1; set --; break;;",
		"    *) fail;;",
		"  esac",
		"done",
		"[ \"$seen_user\" -eq 1 ] && [ \"$seen_t\" -eq 1 ] && [ \"$seen_timeout\" -eq 1 ] && [ \"$seen_command\" -eq 1 ] || fail",
		"exec " + shellQuote(realSSH) + " -F /dev/null -i " + shellQuote(r.Config.IdentityFile) + " -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o BatchMode=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=" + shellQuote(knownHosts) + " -o HostKeyAlgorithms=ssh-ed25519 -o ControlMaster=no -o ControlPath=none -o ControlPersist=no -o ConnectTimeout=30 -l " + shellQuote(user) + " -p " + shellQuote(strconv.Itoa(port)) + " -T -- " + shellQuote(host) + " " + shellQuote("docker system dial-stdio"),
	}, "\n") + "\n"
}

func (r *BuildRunner) childEnvironment() []string {
	r.mu.Lock()
	directory := r.transportDir
	r.mu.Unlock()
	blocked := func(key string) bool {
		if key == "PATH" || strings.HasPrefix(key, "DOCKER_") || strings.HasPrefix(key, "BUILDX_") || strings.HasPrefix(key, "BUILDKIT_") {
			return true
		}
		switch key {
		case "GIT_SSH", "GIT_SSH_COMMAND", "SSH_AUTH_SOCK", "SSH_CONFIG", "SSH_OPTIONS":
			return true
		default:
			return false
		}
	}
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok && !blocked(key) {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "PATH="+directory)
	return environment
}

func (r *BuildRunner) dockerCommand(args []string) (*exec.Cmd, error) {
	r.mu.Lock()
	dockerPath := r.dockerPath
	r.mu.Unlock()
	if dockerPath == "" {
		var err error
		dockerPath, err = resolveExecutable("docker")
		if err != nil {
			return nil, err
		}
	}
	command := exec.CommandContext(r.commandContext(), dockerPath, append([]string{"--host", r.DockerHost()}, args...)...)
	command.Env = r.childEnvironment()
	return command, nil
}

func (r *BuildRunner) defaultDockerOutput(args []string) ([]byte, error) {
	command, err := r.dockerCommand(args)
	if err != nil {
		return nil, err
	}
	r.trackCommand(command)
	defer r.untrackCommand(command)
	return command.CombinedOutput()
}

func (r *BuildRunner) defaultDocker(args []string) error {
	command, err := r.dockerCommand(args)
	if err != nil {
		return err
	}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	r.trackCommand(command)
	defer r.untrackCommand(command)
	return command.Run()
}

func (r *BuildRunner) runDocker(args ...string) ([]byte, error) {
	if err := r.Prepare(); err != nil {
		return nil, err
	}
	if err := r.admitDockerOperation(); err != nil {
		return nil, err
	}
	out, err := r.dockerRun(args)
	if admissionErr := r.admitDockerOperation(); admissionErr != nil {
		return out, admissionErr
	}
	return out, err
}

// RunDocker executes one Docker or Buildx command against the runner. Every
// child uses the prepared wrapper and sanitized environment.
func (r *BuildRunner) RunDocker(args []string) error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	if err := r.Prepare(); err != nil {
		return err
	}
	if err := r.admitDockerOperation(); err != nil {
		return err
	}
	if err := r.dockerExec(args); err != nil {
		return fmt.Errorf("docker operation failed on build runner %s@%s", r.Config.User, r.Config.Host)
	}
	if err := r.admitDockerOperation(); err != nil {
		return err
	}
	return nil
}

// StopBuilder stops only the app-scoped BuildKit daemon after validating the
// stored node. It retains the builder definition and cache volume.
func (r *BuildRunner) StopBuilder(name string) error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	if name == "" {
		return errors.New("remote BuildKit builder name is required")
	}
	out, err := r.runDocker("buildx", "inspect", name)
	if err != nil {
		if isMissingBuilder(string(out), err) {
			return nil
		}
		return r.dockerError("inspect remote BuildKit builder", name)
	}
	if err := r.validateStoredBuilder(name, out); err != nil {
		return err
	}
	if err := r.validateRuntimeBuilder(name, false); err != nil {
		return err
	}
	managed := r.managedLeaseActive()
	if managed {
		if err := r.recordBuilderContainer(name); err != nil {
			return err
		}
		if err := r.beginMutation("stop", name); err != nil {
			return err
		}
	}
	out, err = r.runDocker("buildx", "stop", name)
	if err != nil {
		return r.dockerError("stop remote BuildKit builder", name)
	}
	if managed {
		if err := r.verifyBuilderStopped(name); err != nil {
			return err
		}
		if err := r.clearMutation("stop", name); err != nil {
			return err
		}
	}
	return nil
}

// EnsureBuilder starts or creates the remote docker-container builder with a
// host network namespace. An existing pinned builder keeps its cache and image.
func (r *BuildRunner) EnsureBuilder(name string) error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	if err := r.SetBuilderName(name); err != nil {
		return err
	}
	out, err := r.runDocker("buildx", "inspect", name)
	exists := err == nil
	if err != nil && !isMissingBuilder(string(out), err) {
		return r.dockerError("inspect remote BuildKit builder", name)
	}
	if exists {
		if err := r.validateStoredBuilder(name, out); err != nil {
			return err
		}
		if err := r.validateRuntimeBuilder(name, false); err != nil {
			return err
		}
		managed := r.managedLeaseActive()
		if managed {
			if err := r.recordBuilderContainer(name); err != nil {
				return err
			}
			if err := r.beginMutation("stop", name); err != nil {
				return err
			}
		}
		if out, err = r.runDocker("buildx", "stop", name); err != nil {
			return r.dockerError("stop previous remote BuildKit builder", name)
		}
		if managed {
			if err := r.verifyBuilderStopped(name); err != nil {
				return err
			}
			if err := r.clearMutation("stop", name); err != nil {
				return err
			}
		}
	} else {
		resolve := r.resolveBuildKit
		if resolve == nil {
			resolve = func(ctx context.Context) (string, error) {
				return (images.Resolver{}).Resolve(ctx, "moby/buildkit", "", "")
			}
		}
		r.builderImage, err = resolve(context.Background())
		if err != nil {
			return err
		}
		if !images.ValidPinned("moby/buildkit", r.builderImage) {
			return errors.New("resolved BuildKit image is invalid")
		}
		fmt.Printf("BuildKit image: %s\n", r.builderImage)
		if r.managedLeaseActive() {
			if err := r.beginMutation("create", name); err != nil {
				return err
			}
		}
		if out, err = r.runDocker("buildx", "create", "--name", name, "--driver", "docker-container", "--driver-opt", "network=host", "--driver-opt", "image="+r.builderImage); err != nil {
			return r.dockerError("create remote BuildKit builder", name)
		}
	}
	if r.managedLeaseActive() {
		if err := r.beginMutation("bootstrap", name); err != nil {
			return err
		}
	}
	if out, err = r.runDocker("buildx", "inspect", "--bootstrap", name); err != nil {
		return r.dockerError("bootstrap remote BuildKit builder", name)
	}
	if err := r.validateRuntimeBuilder(name, true); err != nil {
		return err
	}
	if r.managedLeaseActive() {
		if err := r.recordBuilderContainer(name); err != nil {
			return err
		}
		if err := r.verifyBuilderRunning(name); err != nil {
			return err
		}
		if err := r.clearMutation("bootstrap", name); err != nil {
			return err
		}
	}
	return nil
}

func (r *BuildRunner) validateRuntimeBuilder(name string, required bool) error {
	runtime, err := r.runDocker("inspect", buildkitContainerName(name), "--format", "{{.Config.Image}}|{{.HostConfig.NetworkMode}}")
	if err != nil {
		if !required && isMissingBuilder(string(runtime), err) {
			return nil
		}
		return r.dockerError("inspect remote BuildKit runtime", name)
	}
	if err := validateRuntimeBuilderIdentity(runtime); err != nil {
		return fmt.Errorf("stored BuildKit runtime for %s on build runner %s is incompatible: %w", name, r.Config.Host, err)
	}
	if strings.SplitN(strings.TrimSpace(string(runtime)), "|", 2)[0] != r.builderImage {
		return fmt.Errorf("stored BuildKit runtime for %s does not match builder metadata", name)
	}
	return nil
}

func (r *BuildRunner) validateStoredBuilder(name string, inspected []byte) error {
	driver, nodes, err := parseBuildxInspect(string(inspected))
	if err != nil {
		return fmt.Errorf("stored BuildKit builder %s on build runner %s has invalid inspect metadata: %w", name, r.Config.Host, err)
	}
	if driver != "docker-container" {
		return fmt.Errorf("stored BuildKit builder %s on build runner %s has an unexpected driver", name, r.Config.Host)
	}
	if len(nodes) != 1 {
		return fmt.Errorf("stored BuildKit builder %s on build runner %s has %d nodes, want exactly one", name, r.Config.Host, len(nodes))
	}
	node := nodes[0]
	if node.name != name+"0" {
		return fmt.Errorf("stored BuildKit builder %s on build runner %s has unexpected node %q", name, r.Config.Host, node.name)
	}
	if !r.acceptedBuilderEndpoint(node.endpoint) {
		return fmt.Errorf("stored BuildKit builder %s on build runner %s has an unexpected node endpoint", name, r.Config.Host)
	}
	if node.options["network"] != "host" {
		return fmt.Errorf("stored BuildKit builder %s on build runner %s is not network=host", name, r.Config.Host)
	}
	// Comparing with the binary release rejected older builders on every deploy.
	// Keep their identity and compare it with the running container instead.
	if !images.ValidPinned("moby/buildkit", node.options["image"]) {
		return fmt.Errorf("stored BuildKit builder %s on build runner %s does not use a pinned official BuildKit image", name, r.Config.Host)
	}
	r.builderImage = node.options["image"]
	fmt.Printf("BuildKit image: %s\n", r.builderImage)
	return nil
}

type buildxNode struct {
	name     string
	endpoint string
	options  map[string]string
}

// parseBuildxInspect parses the human-readable output of `buildx inspect`.
// The node section is authoritative: builder-wide substrings can otherwise
// make a stale secondary node look valid and allow the wrong Docker endpoint
// to be stopped or bootstrapped.
func parseBuildxInspect(body string) (string, []buildxNode, error) {
	var driver string
	inNodes := false
	var nodes []buildxNode
	var current *buildxNode
	var pendingOptions bool
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "Nodes:" {
			inNodes = true
			pendingOptions = false
			continue
		}
		if !inNodes {
			if value, ok := buildxLabelValue(line, "Driver:"); ok {
				driver = value
			}
			continue
		}
		if value, ok := buildxLabelValue(line, "Name:"); ok {
			if current != nil {
				nodes = append(nodes, *current)
			}
			current = &buildxNode{name: value, options: make(map[string]string)}
			pendingOptions = false
			continue
		}
		if current == nil {
			continue
		}
		if value, ok := buildxLabelValue(line, "Endpoint:"); ok {
			current.endpoint = value
			pendingOptions = false
			continue
		}
		if value, ok := buildxLabelValue(line, "Driver Options:"); ok {
			if err := addBuildxOptions(current.options, value); err != nil {
				return "", nil, err
			}
			pendingOptions = true
			continue
		}
		if pendingOptions {
			if isBuildxMetadataLine(line) || !strings.Contains(line, "=") {
				pendingOptions = false
				continue
			}
			if err := addBuildxOptions(current.options, line); err != nil {
				return "", nil, err
			}
		}
	}
	if current != nil {
		nodes = append(nodes, *current)
	}
	if driver == "" {
		return "", nil, errors.New("missing Driver field")
	}
	if !inNodes {
		return "", nil, errors.New("missing Nodes section")
	}
	for _, node := range nodes {
		if node.name == "" || node.endpoint == "" {
			return "", nil, errors.New("node is missing Name or Endpoint")
		}
	}
	return driver, nodes, nil
}

func isBuildxMetadataLine(line string) bool {
	for _, label := range []string{"Name:", "Endpoint:", "Status:", "Buildkit:", "Platforms:", "Driver Options:", "Last Activity:"} {
		if strings.HasPrefix(line, label) {
			return true
		}
	}
	return false
}

func buildxLabelValue(line, label string) (string, bool) {
	if !strings.HasPrefix(line, label) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(line, label)), true
}

func addBuildxOptions(options map[string]string, text string) error {
	for len(strings.TrimSpace(text)) > 0 {
		text = strings.TrimSpace(strings.TrimLeft(text, ","))
		equal := strings.IndexByte(text, '=')
		if equal <= 0 {
			return fmt.Errorf("invalid driver option %q", text)
		}
		key := strings.TrimSpace(text[:equal])
		text = strings.TrimSpace(text[equal+1:])
		if key == "" {
			return errors.New("driver option has an empty key")
		}
		var value string
		if strings.HasPrefix(text, "\"") {
			end := 1
			escaped := false
			for end < len(text) {
				if text[end] == '"' && !escaped {
					break
				}
				if text[end] == '\\' && !escaped {
					escaped = true
				} else {
					escaped = false
				}
				end++
			}
			if end >= len(text) {
				return fmt.Errorf("unterminated driver option %q", key)
			}
			quoted := text[:end+1]
			unquoted, err := strconv.Unquote(quoted)
			if err != nil {
				return fmt.Errorf("decode driver option %q: %w", key, err)
			}
			value = unquoted
			text = text[end+1:]
		} else {
			end := strings.IndexAny(text, " \t")
			if end < 0 {
				value, text = text, ""
			} else {
				value, text = text[:end], text[end:]
			}
		}
		if _, exists := options[key]; exists {
			return fmt.Errorf("duplicate driver option %q", key)
		}
		options[key] = value
	}
	return nil
}

func hasDriverLine(body, expected string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Driver:") && strings.TrimSpace(strings.TrimPrefix(line, "Driver:")) == expected {
			return true
		}
	}
	return false
}

func hasBuildxOption(body, key, expected string) bool {
	for _, field := range strings.Fields(strings.ReplaceAll(body, ",", " ")) {
		field = strings.TrimSpace(field)
		prefix := key + "="
		if !strings.HasPrefix(field, prefix) {
			continue
		}
		value := strings.Trim(strings.TrimPrefix(field, prefix), "\"")
		if value == expected {
			return true
		}
	}
	return false
}

func buildxEndpoint(body string) (string, bool) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Endpoint:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "Endpoint:"))
			return value, value != ""
		}
	}
	return "", false
}

func (r *BuildRunner) acceptedBuilderEndpoint(endpoint string) bool {
	if r == nil {
		return false
	}
	expected, err := url.Parse(r.DockerHost())
	if err != nil || expected.Scheme != "ssh" || expected.User == nil {
		return false
	}
	candidate, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || candidate.Scheme != "ssh" || candidate.User == nil {
		return false
	}
	if candidate.User.String() != expected.User.String() || candidate.Hostname() != expected.Hostname() || candidate.Port() != expected.Port() {
		return false
	}
	return candidate.Path == "" && candidate.RawQuery == "" && candidate.Fragment == "" && candidate.Opaque == ""
}

func (r *BuildRunner) remoteBuilderUsesHostNetwork(name string, inspected []byte) bool {
	return r.validateStoredBuilder(name, inspected) == nil
}

func validateRuntimeBuilderIdentity(output []byte) error {
	value := strings.TrimSpace(string(output))
	parts := strings.SplitN(value, "|", 2)
	if len(parts) != 2 || !images.ValidPinned("moby/buildkit", parts[0]) || strings.TrimSpace(parts[1]) != "host" {
		return errors.New("image or network identity does not match the approved runner")
	}
	return nil
}

func buildkitContainerName(name string) string {
	return "buildx_buildkit_" + name + "0"
}

func isMissingBuilder(output string, err error) bool {
	message := strings.ToLower(output + " " + err.Error())
	for _, marker := range []string{"no builder", "does not exist", "no such object", "no such builder", "builder not found", "no such container"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (r *BuildRunner) dockerError(action, name string, _ ...any) error {
	return fmt.Errorf("%s %s on build runner %s@%s failed", action, name, r.Config.User, r.Config.Host)
}

func runnerLeaseAcquireCommand(r *BuildRunner, app, targetHost string, targetPort int, token string) string {
	lock := shellPath(remoteTunnelStateDir + "/leases/" + r.runnerID)
	owner := lock + "/owner"
	return strings.Join([]string{
		"set -eu",
		"umask 077",
		"state=" + shellPath(remoteTunnelStateDir+"/leases"),
		"lock=" + lock,
		"mkdir -p -- \"$state\"",
		"if ! mkdir -- \"$lock\" 2>/dev/null; then echo 'runner lease busy' >&2; sed -n '1,12p' \"" + owner + "\" >&2 2>/dev/null || true; exit 75; fi",
		"trap 'rm -rf -- \"$lock\"' EXIT",
		"boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf unknown)",
		"birth=$(awk '{print $22}' /proc/$$/stat 2>/dev/null || printf unknown)",
		"printf '%s\\n' " + shellQuote("run_token="+token) + " " + shellQuote("app="+app) + " " + shellQuote("runner="+r.Config.Host) + " " + shellQuote("target="+targetHost+":"+strconv.Itoa(targetPort)) + " \"started_unix=$(date +%s)\" \"lease_seconds=" + strconv.Itoa(int(runnerLeaseTTL/time.Second)) + "\" \"boot_id=$boot_id\" \"process_birth=$$:$birth\" > \"$lock/owner\"",
		"printf '%s\\n' \"$(date +%s)\" > \"$lock/heartbeat\"",
		"trap - EXIT",
		"printf 'runner-lease-acquired\\n'",
	}, "\n")
}

func runnerLeaseReleaseCommand(r *BuildRunner, token string) string {
	lock := shellPath(remoteTunnelStateDir + "/leases/" + r.runnerID)
	return strings.Join([]string{
		"set -eu",
		"lock=" + lock,
		"if [ -r \"$lock/owner\" ] && grep -F -- " + shellQuote("run_token="+token) + " \"$lock/owner\" >/dev/null; then rm -rf -- \"$lock\"; fi",
	}, "\n")
}

// StartRegistryTunnel starts an independent OpenSSH process on the build
// runner. The target host key line comes from a successful trusted handshake,
// and the dedicated runner-side identity is never opened by this client.
func (r *BuildRunner) StartRegistryTunnel(target *Client, targetHost, targetUser string, targetPort int, app string) error {
	if r == nil || target == nil {
		return errors.New("build runner and verified production client are required")
	}
	if !validRunnerComponent(app) {
		return errors.New("build runner application name is invalid")
	}
	if err := r.admitDockerOperation(); err != nil {
		return err
	}
	if targetPort == 0 {
		targetPort = 22
	}
	if target.Host != targetHost || target.User != targetUser || target.Port != targetPort {
		return errors.New("registry tunnel target is not the verified production endpoint")
	}
	if err := r.Prepare(); err != nil {
		return err
	}
	r.leaseMu.Lock()
	lease := r.lease
	r.leaseMu.Unlock()
	if lease == nil {
		return errors.New("runner lease is required before opening the registry tunnel")
	}
	line, err := target.KnownHostsLine(target.Host, target.Port)
	if err != nil {
		return fmt.Errorf("obtain verified production host key for runner tunnel: %w", err)
	}
	tunnel := &RegistryTunnel{
		runner: r, stateDir: remoteTunnelStateDir + "/" + app, id: lease.token,
		address: r.RegistryAddress(), targetHost: targetHost, targetUser: targetUser, targetPort: targetPort,
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("build runner is already closed")
	}
	if r.tunnel != nil {
		r.mu.Unlock()
		return errors.New("a registry tunnel is already active on the build runner")
	}
	r.tunnel = tunnel
	r.mu.Unlock()
	r.leaseMu.Lock()
	lease.tunnelIdentity = lease.token + ":" + targetUser + "@" + targetHost + ":" + strconv.Itoa(targetPort)
	r.leaseMu.Unlock()
	result := r.runRemote(registryTunnelStartCommand(tunnel, line, targetHost, targetUser, targetPort))
	if result.Code != 0 {
		_ = tunnel.Close()
		r.mu.Lock()
		r.tunnel = nil
		r.mu.Unlock()
		return fmt.Errorf("start registry tunnel on build runner %s: %s", r.Config.Host, boundedDiagnostic(result.Stderr, result.Stdout))
	}
	if err := r.admitDockerOperation(); err != nil {
		return err
	}
	return nil
}

type RegistryTunnel struct {
	runner     *BuildRunner
	stateDir   string
	id         string
	address    string
	targetHost string
	targetUser string
	targetPort int

	mu     sync.Mutex
	closed bool
}

func (t *RegistryTunnel) Address() string {
	if t == nil {
		return ""
	}
	return t.address
}

func (t *RegistryTunnel) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	if t.runner == nil || !t.runner.tunnelAdmission(t.id) {
		return nil
	}
	result := t.runner.runRemote(registryTunnelCleanupCommand(t))
	if result.Code != 0 {
		return fmt.Errorf("cleanup registry tunnel on build runner %s: %s", t.runner.Config.Host, boundedDiagnostic(result.Stderr, result.Stdout))
	}
	return nil
}

func (r *BuildRunner) runRemote(command string) Result {
	if r == nil || r.remoteRun == nil {
		return Result{Code: 1, Stderr: "build runner remote command is unavailable"}
	}
	return r.remoteRun(command)
}

func randomToken() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func registryTunnelPaths(t *RegistryTunnel) (pid, known, log string) {
	base := t.stateDir + "/" + t.id
	return base + ".pid", base + ".known_hosts", base + ".log"
}

func sshTarget(user, host string) string {
	if strings.Contains(strings.Trim(host, "[]"), ":") && net.ParseIP(strings.Trim(host, "[]")) != nil {
		return user + "@[" + strings.Trim(host, "[]") + "]"
	}
	return user + "@" + host
}

func registryTunnelStartCommand(t *RegistryTunnel, hostKeyLine, targetHost, targetUser string, targetPort int) string {
	pid, known, log := registryTunnelPaths(t)
	portHex := fmt.Sprintf("%04X", RemoteRegistryPort)
	target := sshTarget(targetUser, targetHost)
	return strings.Join([]string{
		"set -eu",
		"umask 077",
		"dir=" + shellPath(t.stateDir),
		"mkdir -p -- \"$dir\"",
		"known=" + shellPath(known),
		"pidfile=" + shellPath(pid),
		"log=" + shellPath(log),
		"target_marker=" + shellQuote(target),
		"printf '%s\\n' " + shellQuote(hostKeyLine) + " > \"$known\"",
		"rm -f -- \"$pidfile\"",
		"socket_inode() { awk -v p=':" + portHex + "' '$2 ~ \"^0100007F\" p \"$\" && $4 == \"0A\" { print $10; exit }' /proc/net/tcp; }",
		"if [ -n \"$(socket_inode)\" ]; then echo 'registry port 5000 is already occupied' >&2; exit 73; fi",
		"nohup ssh -F /dev/null -N -T -o BatchMode=yes -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=\"$known\" -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ControlMaster=no -o ControlPath=none -o ControlPersist=no -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -i " + shellQuote(t.runner.Config.RegistryIdentityFile) + " -p " + strconv.Itoa(targetPort) + " -L 127.0.0.1:" + strconv.Itoa(RemoteRegistryPort) + ":127.0.0.1:5000 -- " + shellQuote(target) + " >>\"$log\" 2>&1 < /dev/null &",
		"pid=$!",
		"birth=$(awk '{print $22}' /proc/\"$pid\"/stat)",
		"printf '%s %s\\n' \"$pid\" \"$birth\" > \"$pidfile\"",
		"process_owned() { [ -r \"$pidfile\" ] || return 1; read pid birth < \"$pidfile\" || return 1; case \"$pid:$birth\" in ''|*[!0-9:]*) return 1;; esac; [ -r /proc/\"$pid\"/cmdline ] || return 1; [ \"$(awk '{print $22}' /proc/\"$pid\"/stat 2>/dev/null)\" = \"$birth\" ] || return 1; tr '\\000' ' ' < /proc/\"$pid\"/cmdline | grep -F -- \"$known\" >/dev/null 2>&1 || return 1; tr '\\000' ' ' < /proc/\"$pid\"/cmdline | grep -F -- \"$target_marker\" >/dev/null 2>&1; }",
		"bound_by_pid() { inode=$(socket_inode); [ -n \"$inode\" ] || return 1; for fd in /proc/\"$pid\"/fd/*; do [ \"$(readlink \"$fd\" 2>/dev/null)\" = \"socket:[$inode]\" ] && return 0; done; return 1; }",
		"kill_owned() { if process_owned; then kill \"$pid\" 2>/dev/null || true; for n in $(seq 1 50); do kill -0 \"$pid\" 2>/dev/null || break; sleep 0.1; done; kill -9 \"$pid\" 2>/dev/null || true; fi; }",
		"deadline=$(($(date +%s) + 10))",
		"while kill -0 \"$pid\" 2>/dev/null && ! bound_by_pid; do [ \"$(date +%s)\" -lt \"$deadline\" ] || break; sleep 0.1; done",
		"if ! process_owned || ! bound_by_pid; then kill_owned; sed -n '1,40p' \"$log\" >&2 || true; rm -f -- \"$pidfile\" \"$known\" \"$log\"; exit 1; fi",
		"printf 'registry-tunnel-ready\\n'",
	}, "\n")
}

func registryTunnelCleanupCommand(t *RegistryTunnel) string {
	pid, known, log := registryTunnelPaths(t)
	targetMarker := ""
	if t.targetHost != "" {
		targetMarker = sshTarget(t.targetUser, t.targetHost)
	}
	targetPortMarker := ""
	if t.targetPort > 0 {
		targetPortMarker = "-p " + strconv.Itoa(t.targetPort)
	}
	return strings.Join([]string{
		"set -eu",
		"pidfile=" + shellPath(pid),
		"known=" + shellPath(known),
		"log=" + shellPath(log),
		"target_marker=" + shellQuote(targetMarker),
		"target_port_marker=" + shellQuote(targetPortMarker),
		"process_owned() { [ -r \"$pidfile\" ] || return 1; read pid birth < \"$pidfile\" || return 1; case \"$pid:$birth\" in ''|*[!0-9:]*) return 1;; esac; [ -r /proc/\"$pid\"/cmdline ] || return 1; [ \"$(awk '{print $22}' /proc/\"$pid\"/stat 2>/dev/null)\" = \"$birth\" ] || return 1; tr '\\000' ' ' < /proc/\"$pid\"/cmdline | grep -F -- \"$known\" >/dev/null 2>&1 || return 1; [ -z \"$target_marker\" ] || tr '\\000' ' ' < /proc/\"$pid\"/cmdline | grep -F -- \"$target_marker\" >/dev/null 2>&1; [ -z \"$target_port_marker\" ] || tr '\\000' ' ' < /proc/\"$pid\"/cmdline | grep -F -- \"$target_port_marker\" >/dev/null 2>&1; }",
		"if process_owned; then kill \"$pid\" 2>/dev/null || true; for n in $(seq 1 50); do kill -0 \"$pid\" 2>/dev/null || break; sleep 0.1; done; kill -9 \"$pid\" 2>/dev/null || true; fi",
		"rm -f -- \"$pidfile\" \"$known\" \"$log\"",
	}, "\n")
}

func shellPath(value string) string {
	if strings.HasPrefix(value, "$HOME/") {
		return `"$HOME/` + strings.TrimPrefix(value, "$HOME/") + `"`
	}
	return shellQuote(value)
}

func boundedDiagnostic(stderr, stdout string) string {
	value := strings.TrimSpace(stderr)
	if value == "" {
		value = strings.TrimSpace(stdout)
	}
	if len(value) > 4096 {
		value = value[:4096]
	}
	if value == "" {
		return "remote command failed without a diagnostic"
	}
	return value
}
