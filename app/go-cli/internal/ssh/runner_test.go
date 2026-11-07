package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildRunnerRejectsMissingDedicatedRegistryIdentity(t *testing.T) {
	_, err := NewBuildRunner(BuildRunnerConfig{
		Host:         "builder.example",
		User:         "build",
		Port:         22,
		HostKey:      "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
		IdentityFile: filepath.Join(t.TempDir(), "build"),
	})
	if err == nil || !strings.Contains(err.Error(), "independent registry identity") {
		t.Fatalf("missing runner-side registry identity was accepted: %v", err)
	}
}

func TestBuildRunnerRejectsProductionAliasAfterSSHConfigResolution(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte("Host builder-alias\n  HostName 203.0.113.10\n  Port 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "builder-alias", User: "build", Port: 2222}}
	if err := runner.ValidateProductionTarget("203.0.113.10", "deploy", 2222); err == nil || !strings.Contains(err.Error(), "production target") {
		t.Fatalf("resolved production runner alias was accepted: %v", err)
	}
}

func TestResolvedRunnerIdentityPinsResolvedHostForDockerTransport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte("Host builder-alias\n  HostName 192.0.2.40\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(sshDir, "builder")
	if err := os.WriteFile(identity, testPrivateKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClientExactWithResolvedIdentity("builder-alias", "build", 22, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA", identity)
	if err != nil {
		t.Fatal(err)
	}
	if client.Host != "192.0.2.40" || client.Port != 22 {
		t.Fatalf("resolved runner endpoint = %s:%d", client.Host, client.Port)
	}
}

func TestRegistryTunnelCommandUsesIndependentCredentialAndStrictForward(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "builder.example", User: "build", Port: 22, RegistryIdentityFile: "/home/build/.ssh/registry"}}
	tunnel := &RegistryTunnel{runner: runner, stateDir: "$HOME/.shuttle/build-runners/demo", id: "0123456789abcdef", address: "127.0.0.1:5000"}
	command := registryTunnelStartCommand(tunnel, "[203.0.113.10]:2222 ssh-ed25519 AAAA", "203.0.113.10", "deploy", 2222)
	for _, want := range []string{
		"-o BatchMode=yes",
		"-o ExitOnForwardFailure=yes",
		"-o StrictHostKeyChecking=yes",
		"-o GlobalKnownHostsFile=/dev/null",
		"-o UserKnownHostsFile=\"$known\"",
		"-o IdentitiesOnly=yes",
		"-o IdentityAgent=none",
		"-o ForwardAgent=no",
		"-i '/home/build/.ssh/registry'",
		"-L 127.0.0.1:5000:127.0.0.1:5000",
		"registry-tunnel-ready",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("registry tunnel command lacks %q:\n%s", want, command)
		}
	}
	if strings.Contains(command, "-----BEGIN") || strings.Contains(command, "deploy-private-key") {
		t.Fatal("registry tunnel command contains private-key content or the deploy key")
	}
}

func TestRegistryTunnelCleanupChecksItsOwnProcessMarker(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "builder.example", User: "build", Port: 22}}
	tunnel := &RegistryTunnel{runner: runner, stateDir: "$HOME/.shuttle/build-runners/demo", id: "fedcba9876543210", address: "127.0.0.1:5000"}
	command := registryTunnelCleanupCommand(tunnel)
	if !strings.Contains(command, "tr '\\000' ' ' < /proc/\"$pid\"/cmdline | grep -F") {
		t.Fatalf("cleanup does not verify the process command line:\n%s", command)
	}
	if !strings.Contains(command, "$HOME/.shuttle/build-runners/demo/fedcba9876543210.known_hosts") {
		t.Fatalf("cleanup marker is not scoped to this tunnel:\n%s", command)
	}
}

func TestEnsureBuilderStopsBeforeBootstrapAndKeepsTheCache(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "builder.example", User: "build", Port: 22}, prepared: true}
	oldImage := "moby/buildkit:v0.32.0@sha256:" + strings.Repeat("b", 64)
	runner.resolveBuildKit = func(context.Context) (string, error) { return "", errors.New("must not resolve existing builder") }
	var calls []string
	runner.dockerRun = func(args []string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if strings.HasPrefix(strings.Join(args, " "), "inspect buildx_buildkit_") {
			return []byte(oldImage + "|host\n"), nil
		}
		if strings.Contains(strings.Join(args, " "), "buildx inspect") {
			return []byte("Name: shuttle-demo-remote\nDriver: docker-container\nNodes:\nName: shuttle-demo-remote0\nEndpoint: " + runner.DockerHost() + "\nStatus: running\nDriver Options: network=\"host\" image=\"" + oldImage + "\"\n"), nil
		}
		return []byte("Name: shuttle-demo-remote\n"), nil
	}
	if err := runner.EnsureBuilder("shuttle-demo-remote"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"buildx inspect shuttle-demo-remote",
		"inspect buildx_buildkit_shuttle-demo-remote0 --format {{.Config.Image}}|{{.HostConfig.NetworkMode}}",
		"buildx stop shuttle-demo-remote",
		"buildx inspect --bootstrap shuttle-demo-remote",
		"inspect buildx_buildkit_shuttle-demo-remote0 --format {{.Config.Image}}|{{.HostConfig.NetworkMode}}",
	}
	if len(calls) != len(want) {
		t.Fatalf("unexpected remote builder lifecycle: %#v", calls)
	}
	for index := range want {
		if calls[index] != want[index] {
			t.Fatalf("builder call %d = %q, want %q", index, calls[index], want[index])
		}
	}
}

func TestEnsureBuilderCreatesOnlyThePinnedStableBuildKitIdentity(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22}, prepared: true, resolveBuildKit: func(context.Context) (string, error) { return RemoteBuildKitImage, nil }}
	var calls []string
	runner.dockerRun = func(args []string) ([]byte, error) {
		call := strings.Join(args, " ")
		calls = append(calls, call)
		switch {
		case call == "buildx inspect shuttle-demo-remote":
			return []byte("no such builder"), errors.New("exit status 1")
		case call == "buildx create --name shuttle-demo-remote --driver docker-container --driver-opt network=host --driver-opt image="+RemoteBuildKitImage:
			return nil, nil
		case call == "buildx inspect --bootstrap shuttle-demo-remote":
			return nil, nil
		case strings.HasPrefix(call, "inspect buildx_buildkit_"):
			return []byte(RemoteBuildKitImage + "|host\n"), nil
		default:
			return nil, errors.New("unexpected Docker operation")
		}
	}
	if err := runner.EnsureBuilder("shuttle-demo-remote"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 || !strings.Contains(calls[1], "image="+RemoteBuildKitImage) {
		t.Fatalf("remote builder was not created with the pinned image: %#v", calls)
	}
}

func TestStopBuilderTreatsOnlyBuilderNotFoundAsAnAbsentBuilder(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "builder.example", User: "build", Port: 22}, prepared: true}
	runner.dockerRun = func([]string) ([]byte, error) {
		return []byte("docker: command not found"), errors.New("exit status 127")
	}
	if err := runner.StopBuilder("shuttle-demo-remote"); err == nil || !strings.Contains(err.Error(), "build runner") {
		t.Fatalf("an unavailable Docker command was mistaken for an absent builder: %v", err)
	}
}

func TestDockerSSHWrapperValidatesAndReconstructsTheExactTransport(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "builder-key")
	knownHosts := filepath.Join(dir, "known_hosts")
	observed := filepath.Join(dir, "ssh-argv")
	fakeSSH := filepath.Join(dir, "real-ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+shellQuote(observed)+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22, IdentityFile: identity}}
	wrapper := filepath.Join(dir, "ssh-wrapper")
	if err := os.WriteFile(wrapper, []byte(runner.sshWrapperScript(fakeSSH, knownHosts)), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-n", wrapper).CombinedOutput(); err != nil {
		t.Fatalf("generated wrapper is not valid shell: %v: %s", err, output)
	}
	command := exec.Command(wrapper, "-o ConnectTimeout=30", "-l", "build", "-p", "22", "-T", "--", "192.0.2.40", "docker system dial-stdio")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("valid Docker SSH argv was rejected: %v: %s", err, output)
	}
	body, err := os.ReadFile(observed)
	if err != nil {
		t.Fatal(err)
	}
	args := string(body)
	for _, want := range []string{"-F\n/dev/null", "-i\n" + identity, "-o\nUserKnownHostsFile=" + knownHosts, "-l\nbuild", "-p\n22", "-T\n--\n192.0.2.40\ndocker system dial-stdio"} {
		if !strings.Contains(args, want) {
			t.Fatalf("reconstructed SSH argv lacks %q: %s", want, args)
		}
	}
	if strings.Contains(args, "-n\n") {
		t.Fatal("Docker transport used -n and would lose stdin")
	}
	bad := exec.Command(wrapper, "-o ProxyCommand=evil", "-l", "build", "-p", "22", "-T", "--", "192.0.2.40", "docker system dial-stdio")
	if err := bad.Run(); err == nil {
		t.Fatal("wrapper accepted an unknown SSH option")
	}
}

func TestDockerChildUsesThePrivateWrapperInsteadOfAmbientSSHCommand(t *testing.T) {
	dir := t.TempDir()
	transport := filepath.Join(dir, "transport")
	if err := os.Mkdir(transport, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "builder-key")
	knownHosts := filepath.Join(transport, "known_hosts")
	observed := filepath.Join(dir, "ssh-argv")
	realSSH := filepath.Join(dir, "real-ssh")
	if err := os.WriteFile(realSSH, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+shellQuote(observed)+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(transport, "ssh")
	runner := &BuildRunner{
		Config:       BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22, IdentityFile: identity},
		prepared:     true,
		transportDir: transport,
		knownHosts:   knownHosts,
		dockerPath:   filepath.Join(dir, "docker"),
	}
	if err := os.WriteFile(wrapper, []byte(runner.sshWrapperScript(realSSH, knownHosts)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runner.dockerPath, []byte("#!/bin/sh\n[ \"$1\" = --host ] || exit 1\nshift 2\nexec ssh '-o ConnectTimeout=30' -l build -p 22 -T -- 192.0.2.40 'docker system dial-stdio'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_SSH_COMMAND", "ssh -o ProxyCommand=ambient")
	if _, err := runner.defaultDockerOutput([]string{"version"}); err != nil {
		t.Fatalf("fake Docker could not use the prepared wrapper: %v", err)
	}
	body, err := os.ReadFile(observed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "ambient") || !strings.Contains(string(body), "UserKnownHostsFile="+knownHosts) {
		t.Fatalf("Docker child did not use the private wrapper transport: %s", body)
	}
}

func TestProductionEndpointComparisonRejectsAliasesAndSharedHostKeys(t *testing.T) {
	previous := lookupBuildRunnerIPs
	lookupBuildRunnerIPs = func(host string) ([]net.IP, error) {
		switch host {
		case "runner.example", "runner-key.example":
			return []net.IP{net.ParseIP("192.0.2.40")}, nil
		case "production.example":
			return []net.IP{net.ParseIP("192.0.2.40")}, nil
		case "production-key.example":
			return []net.IP{net.ParseIP("192.0.2.41")}, nil
		default:
			return nil, errors.New("unexpected host")
		}
	}
	t.Cleanup(func() { lookupBuildRunnerIPs = previous })
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "runner.example", User: "build", Port: 22, HostKey: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}}
	if err := runner.ValidateProductionTarget("production.example", "deploy", 22); err == nil || !strings.Contains(err.Error(), "production target") {
		t.Fatalf("shared DNS endpoint was accepted: %v", err)
	}
	runner.Config.Host = "runner-key.example"
	if err := runner.ValidateProductionTargets([]ProductionEndpoint{{Host: "production-key.example", User: "deploy", Port: 22, HostKey: runner.Config.HostKey}}); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("shared host-key identity was accepted: %v", err)
	}
}

func TestGeneratedRunnerScriptsPassShellSyntaxCheck(t *testing.T) {
	runner := &BuildRunner{
		Config:      BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22, RegistryIdentityFile: "/home/build/.ssh/registry"},
		runnerID:    "0123456789abcdef",
		builderName: "shuttle-demo-remote-012345",
	}
	tunnel := &RegistryTunnel{runner: runner, stateDir: "$HOME/.shuttle/build-runners/demo", id: "0123456789abcdef"}
	scripts := []string{
		registryTunnelStartCommand(tunnel, "[203.0.113.10]:2222 ssh-ed25519 AAAA", "203.0.113.10", "deploy", 2222),
		registryTunnelCleanupCommand(tunnel),
		runnerLeaseAcquireCommand(runner, "demo", "203.0.113.10", 2222, "0123456789abcdef"),
		runnerSupervisorCommand(runner, "demo", "203.0.113.10", 2222, "0123456789abcdef"),
	}
	for index, script := range scripts {
		path := filepath.Join(t.TempDir(), "script")
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("generated runner script %d is invalid shell: %v: %s\n%s", index, err, output, script)
		}
	}
}

func TestRunnerSupervisorCleansItsLeaseAfterControlDisconnect(t *testing.T) {
	home := t.TempDir()
	fakeBin := t.TempDir()
	dockerCalls := filepath.Join(fakeBin, "docker-calls")
	containerID := strings.Repeat("a", 64)
	dockerScript := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(dockerCalls) + "\ncase \"$1 $2\" in\n  'inspect " + containerID + "') case \"$4\" in *Config.Image*) printf '%s\\n' '" + containerID + "|" + RemoteBuildKitImage + "|host';; *) printf '%s\\n' '" + containerID + "|exited';; esac;;\nesac\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "docker"), []byte(dockerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(home, ".shuttle", "build-runners", "leases", "0123456789abcdef")
	if err := os.MkdirAll(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lock, "owner"), []byte("run_token=0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lock, "heartbeat"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, ".shuttle", "build-runners", "demo", "runs", "0123456789abcdef")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "containers"), []byte(containerID+"|"+RemoteBuildKitImage+"|host|shuttle-demo-remote-012345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &BuildRunner{
		Config:      BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22},
		runnerID:    "0123456789abcdef",
		builderName: "shuttle-demo-remote-012345",
		production:  &ProductionEndpoint{User: "deploy"},
	}
	command := exec.Command("sh", "-c", runnerSupervisorCommand(runner, "demo", "192.0.2.41", 22, "0123456789abcdef"))
	command.Env = []string{"HOME=" + home, "PATH=" + fakeBin + ":/usr/bin:/bin"}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stdin, "heartbeat 0123456789abcdef\n"); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("supervisor did not clean up after control disconnect: %v", err)
	}
	if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runner lease survived supervisor cleanup: %v", err)
	}
	if _, err := os.Stat(dockerCalls); err != nil {
		t.Fatalf("supervisor did not inspect its owned builder: %v", err)
	}
}

func TestRunnerLeaseSerializesClientsBeforeBuilderStop(t *testing.T) {
	home := t.TempDir()
	runner := &BuildRunner{
		Config:   BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22},
		runnerID: "0123456789abcdef",
	}
	acquire := runnerLeaseAcquireCommand(runner, "demo", "192.0.2.41", 22, "first-token")
	command := exec.Command("sh", "-c", acquire)
	command.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("first runner client could not acquire its lease: %v: %s", err, output)
	}
	second := exec.Command("sh", "-c", runnerLeaseAcquireCommand(runner, "other", "192.0.2.42", 22, "second-token"))
	second.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	output, err := second.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "runner lease busy") {
		t.Fatalf("second client was allowed past the runner lease: %v: %s", err, output)
	}
}

// The watch loop reads the heartbeat every second while the reader rewrites
// it. An in-place `>` write truncates first, so a read in between saw an empty
// value and exited 124 (CI, 2026-10-08). The heartbeat must only be replaced.
func TestRunnerSupervisorReplacesHeartbeatAtomically(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22}, runnerID: "0123456789abcdef"}
	script := runnerSupervisorCommand(runner, "demo", "192.0.2.41", 22, "0123456789abcdef")
	if strings.Contains(script, `> "$heartbeat"`) {
		t.Fatal("supervisor rewrites the heartbeat in place; a concurrent read can see it empty")
	}
	if !strings.Contains(script, `mv -f -- "$heartbeat.next" "$heartbeat"`) {
		t.Fatal("supervisor no longer replaces the heartbeat by rename")
	}
}
