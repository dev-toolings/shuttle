package ssh

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func retainedBuildxInspectFixture(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("testdata/buildx-inspect.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(body)); got != "b7fcbc4136ae1ed61e23f180e462929a37e8de9fb8ff36d6d1b97dea252db92d" {
		t.Fatalf("retained Buildx inspect fixture changed: %s", got)
	}
	return string(body)
}

func buildxInspectFixture(name, endpoint string, nodes ...string) string {
	var builder strings.Builder
	builder.WriteString("Name:          " + name + "\nDriver:        docker-container\nLast Activity: 2026-09-13 14:00:00 +0000 UTC\nNodes:\n")
	for _, node := range nodes {
		builder.WriteString("Name:             " + node + "\nEndpoint:         " + endpoint + "\nStatus:           running\nBuildkit:         v0.33.0\nPlatforms:        linux/amd64\nDriver Options:\n network=\"host\"\n image=\"" + RemoteBuildKitImage + "\"\n")
	}
	return builder.String()
}

func TestValidateStoredBuilderRequiresOneExactSSHNode(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "203.0.113.62", User: "build", Port: 22}}
	name := "shuttle-shuttle-build-recette-remote-a37dd252a66a"
	valid := retainedBuildxInspectFixture(t)
	if err := runner.validateStoredBuilder(name, []byte(valid)); err != nil {
		t.Fatalf("normal buildx inspect fixture was rejected: %v", err)
	}

	cases := map[string]string{
		"local socket":     strings.Replace(valid, "ssh://build@203.0.113.62:22", "unix:///var/run/docker.sock", 1),
		"stale SSH target": strings.Replace(valid, "ssh://build@203.0.113.62:22", "ssh://build@203.0.113.63:22", 1),
		"wrong driver":     strings.Replace(valid, "Driver:        docker-container", "Driver:        docker", 1),
		"wrong image":      strings.Replace(valid, RemoteBuildKitImage, "moby/buildkit:v0.32.0", 1),
		"wrong network":    strings.Replace(valid, `network="host"`, `network="bridge"`, 1),
		"multiple nodes":   valid + "\nName:                  foreign-node\nEndpoint:              ssh://build@203.0.113.63:22\nDriver Options:        image=\"" + RemoteBuildKitImage + "\" network=\"host\"\nStatus:                stopped\n",
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			if err := runner.validateStoredBuilder("shuttle-shuttle-build-recette-remote-a37dd252a66a", []byte(fixture)); err == nil {
				t.Fatal("invalid stored node metadata was accepted")
			}
		})
	}
}

func TestEnsureBuilderRefusesInvalidStoredNodesBeforeStopOrBootstrap(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22}, prepared: true}
	var calls []string
	runner.dockerRun = func(args []string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		fixture := strings.Replace(retainedBuildxInspectFixture(t), "shuttle-shuttle-build-recette-remote-a37dd252a66a", "shuttle-demo-remote", -1)
		fixture += "\nName:                  foreign-node\nEndpoint:              ssh://build@192.0.2.41:22\nDriver Options:        image=\"" + RemoteBuildKitImage + "\" network=\"host\"\nStatus:                stopped\n"
		return []byte(fixture), nil
	}
	if err := runner.EnsureBuilder("shuttle-demo-remote"); err == nil {
		t.Fatal("multiple stored nodes were accepted")
	}
	if len(calls) != 1 || calls[0] != "buildx inspect shuttle-demo-remote" {
		t.Fatalf("invalid metadata was not refused before lifecycle mutation: %#v", calls)
	}
}

func TestDockerChildEnvironmentDropsAllRoutingOverrides(t *testing.T) {
	dir := t.TempDir()
	transport := filepath.Join(dir, "transport")
	if err := os.Mkdir(transport, 0o700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "environment")
	dockerPath := filepath.Join(dir, "docker")
	envReader, err := exec.LookPath("env")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerPath, []byte("#!/bin/sh\n"+shellQuote(envReader)+" > "+shellQuote(envFile)+"\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &BuildRunner{
		Config:       BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22},
		prepared:     true,
		transportDir: transport,
		dockerPath:   dockerPath,
	}
	for _, key := range []string{
		"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_SSH_COMMAND", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
		"BUILDX_BUILDER", "BUILDX_CONFIG", "BUILDKIT_HOST", "BUILDKIT_PROGRESS", "SSH_AUTH_SOCK", "GIT_SSH_COMMAND",
	} {
		t.Setenv(key, "ambient-route")
	}
	t.Setenv("SHU1_ENV_SENTINEL", "retained")
	if _, err := runner.defaultDockerOutput([]string{"version"}); err == nil {
		t.Fatal("fake Docker unexpectedly succeeded")
	}
	body, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "SHU1_ENV_SENTINEL=retained") {
		t.Fatalf("absolute environment capture did not retain its sentinel: %s", body)
	}
	for _, key := range []string{
		"DOCKER_HOST=", "DOCKER_CONTEXT=", "DOCKER_SSH_COMMAND=", "DOCKER_CONFIG=", "DOCKER_TLS_VERIFY=", "DOCKER_CERT_PATH=",
		"BUILDX_BUILDER=", "BUILDX_CONFIG=", "BUILDKIT_HOST=", "BUILDKIT_PROGRESS=", "SSH_AUTH_SOCK=", "GIT_SSH_COMMAND=",
	} {
		if strings.Contains(string(body), key) {
			t.Fatalf("child environment retained %s: %s", key, body)
		}
	}
}

func TestRealDockerCLIUsesStrictWrapperTransport(t *testing.T) {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Skipf("real Docker CLI unavailable, transport test skipped explicitly: %v", err)
	}
	dockerPath, err = filepath.Abs(dockerPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	identity := filepath.Join(dir, "builder-key")
	knownHosts := filepath.Join(dir, "known_hosts")
	observed := filepath.Join(dir, "real-docker-ssh-argv")
	fakeSSH := filepath.Join(dir, "fake-ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nfor arg do printf '%s\\n' \"$arg\"; done > "+shellQuote(observed)+"\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	transport := filepath.Join(dir, "transport")
	if err := os.Mkdir(transport, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "203.0.113.40", User: "probe", Port: 2222, IdentityFile: identity}, prepared: true, transportDir: transport, dockerPath: dockerPath, knownHosts: knownHosts}
	if err := os.WriteFile(filepath.Join(transport, "ssh"), []byte(runner.sshWrapperScript(fakeSSH, knownHosts)), 0o700); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"DOCKER_HOST":        "ssh://ambient@198.51.100.20:22",
		"DOCKER_CONTEXT":     "ambient",
		"DOCKER_SSH_COMMAND": "ssh -o ProxyCommand=ambient",
		"BUILDX_BUILDER":     "ambient",
		"BUILDX_CONFIG":      filepath.Join(dir, "ambient-buildx"),
		"BUILDKIT_HOST":      "tcp://ambient.invalid:1234",
		"SSH_AUTH_SOCK":      filepath.Join(dir, "ambient-agent"),
	} {
		t.Setenv(key, value)
	}
	_, err = runner.defaultDockerOutput([]string{"version"})
	if err == nil {
		t.Fatal("real Docker unexpectedly succeeded against the harmless fake SSH")
	}
	body, err := os.ReadFile(observed)
	if err != nil {
		t.Fatalf("real Docker did not traverse the wrapper: %v", err)
	}
	got := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	want := []string{
		"-F", "/dev/null", "-i", identity,
		"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "ForwardAgent=no",
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=" + knownHosts, "-o", "HostKeyAlgorithms=ssh-ed25519",
		"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ConnectTimeout=30",
		"-l", "probe", "-p", "2222", "-T", "--", "203.0.113.40", "docker system dial-stdio",
	}
	if len(got) != len(want) {
		t.Fatalf("real Docker transport argv length = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("real Docker transport argv[%d] = %q, want %q; full argv %#v", i, got[i], want[i], got)
		}
	}
}

func TestWrapperAuthAndHostPinFailuresRemainHardFailures(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "builder-key")
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(identity, []byte("wrong-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("wrong-fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeSSH := filepath.Join(dir, "fake-ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nset -eu\nkey=\nknown=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    -i) key=$2; shift 2;;\n    -o) case $2 in UserKnownHostsFile=*) known=${2#UserKnownHostsFile=};; esac; shift 2;;\n    *) shift;;\n  esac\ndone\n[ \"$(sed -n '1p' \"$key\")\" = correct-key ] || { echo wrong-key >&2; exit 77; }\n[ \"$(sed -n '1p' \"$known\")\" = correct-fingerprint ] || { echo wrong-fingerprint >&2; exit 78; }\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22, IdentityFile: identity}}
	wrapper := filepath.Join(dir, "ssh")
	if err := os.WriteFile(wrapper, []byte(runner.sshWrapperScript(fakeSSH, knownHosts)), 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"-o ConnectTimeout=30", "-l", "build", "-p", "22", "-T", "--", "192.0.2.40", "docker system dial-stdio"}
	if output, err := exec.Command(wrapper, args...).CombinedOutput(); err == nil || !strings.Contains(string(output), "wrong-key") {
		t.Fatalf("wrong builder key was not a hard failure: %v: %s", err, output)
	}
	if err := os.WriteFile(identity, []byte("correct-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(wrapper, args...).CombinedOutput(); err == nil || !strings.Contains(string(output), "wrong-fingerprint") {
		t.Fatalf("wrong runner fingerprint was not a hard failure: %v: %s", err, output)
	}
}

func TestWrapperRejectsExtraTargetAndShellPayload(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "builder-key")
	knownHosts := filepath.Join(dir, "known_hosts")
	observed := filepath.Join(dir, "observed")
	fakeSSH := filepath.Join(dir, "fake-ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nprintf ok > "+shellQuote(observed)+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22, IdentityFile: identity}}
	wrapper := filepath.Join(dir, "ssh")
	if err := os.WriteFile(wrapper, []byte(runner.sshWrapperScript(fakeSSH, knownHosts)), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"extra target":  {"-o ConnectTimeout=30", "-l", "build", "-T", "--", "192.0.2.40", "docker system dial-stdio", "extra"},
		"shell payload": {"-o ConnectTimeout=30", "-l", "build", "-T", "--", "192.0.2.40", "docker system dial-stdio; touch /tmp/shuttle-injected"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := exec.Command(wrapper, args...).Run(); err == nil {
				t.Fatal("wrapper accepted an invalid Docker target or command")
			}
		})
	}
	if _, err := os.Stat(observed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fake SSH was invoked by a rejected request: %v", err)
	}
}
