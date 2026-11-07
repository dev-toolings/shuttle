package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestSetupShellProgramsParse(t *testing.T) {
	programs := map[string]string{
		"base":              setupBaseCommand(setupModeFresh),
		"docker":            setupDockerCommand(setupModeFresh),
		"postgres":          setupPostgresCommand(config.DefaultDatabaseVersion),
		"postgres-17":       setupPostgresCommand(17),
		"postgres-resolved": setupPostgresCommand(0),
		"runtime":           setupRuntimeCommand(22, defaultPublicTCPPorts(t), setupModeFresh),
		"operator":          setupOperatorCommand("ops"),
		"caddy":             setupCaddyCommand(),
		"proof":             setupInfrastructureProofCommand(),
		"direct-ssh":        setupDirectSSHServiceCommand(),
	}
	for name, program := range programs {
		t.Run(name, func(t *testing.T) {
			command := exec.Command("sh", "-n")
			command.Stdin = strings.NewReader(program)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("generated shell does not parse: %v\n%s\n%s", err, output, program)
			}
		})
	}
}

func TestInfrastructureProofGatesRootHardening(t *testing.T) {
	program := setupInfrastructureProofCommand()
	for _, required := range []string{
		"docker container inspect shuttle-registry",
		"http://127.0.0.1:5000/v2/",
		"shuttle-edge_caddy 1/1",
		"caddy validate",
		"fail2ban-client status sshd",
		"ufw status",
		"DOCKER-USER",
		"/var/run/reboot-required",
		"systemctl --failed",
		"resolvectl status",
		"while [ \"$attempt\" -lt 30 ]",
		"sleep 2",
	} {
		if !strings.Contains(program, required) {
			t.Fatalf("pre-hardening infrastructure proof is missing %q", required)
		}
	}
}

func TestSetupRegistryConvergenceRefusesDowngradesAndPullsBeforeReplacement(t *testing.T) {
	program := setupDockerCommand(setupModeFresh, "registry:3.1.3@sha256:"+strings.Repeat("a", 64))
	for _, required := range []string{
		"registry major change $existing_major -> $desired_major requires an explicit migration",
		"planned registry version $desired_version is older than running version $existing_version",
		"docker pull --quiet \"$desired_image\"",
	} {
		if !strings.Contains(program, required) {
			t.Fatalf("setup registry convergence lacks %q", required)
		}
	}
	if strings.Index(program, "docker pull --quiet \"$desired_image\"") > strings.Index(program, "docker rm shuttle-registry") {
		t.Fatal("setup must pull the accepted registry candidate before removing the running container")
	}
}

func TestBaselineTransactionPrecomputesRecoveryEnvelopes(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	envelopes, err := prepareBaselineEnvelopes(setupIdentity{operatorKeyFingerprint: fingerprint}, fingerprint, privateKey, time.Now().UTC(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for expected, envelope := range map[string][]byte{
		"baseline":          envelopes.baseline,
		"audit":             envelopes.audit,
		"baseline-rollback": envelopes.rollback,
		"baseline-commit":   envelopes.commit,
	} {
		plan, payload, err := decodeRootHelperEnvelope(strings.NewReader(string(envelope)))
		if err != nil || len(payload) != 0 || plan.Action != expected {
			t.Fatalf("invalid precomputed %s envelope: action=%q payload=%d err=%v", expected, plan.Action, len(payload), err)
		}
	}
}

func TestSetupPreflightDoesNotCreateRemoteFiles(t *testing.T) {
	// The preflight is deliberately fingerprint-only. This protects the
	// read-only contract before explicit --yes confirmation.
	if strings.Contains(setupReadOnlyPreflightSource, "/tmp/") {
		t.Fatal("preflight source contains a temporary-file mutation")
	}
	if !strings.Contains(setupReadOnlyPreflightSource, "/etc/shuttle/setup.d/10-base") {
		t.Fatal("preflight must distinguish a checkpointed resume from foreign resources")
	}
}

func TestSharedCaddyUsesPinnedOfficialImageWithoutExternalDNSPlugin(t *testing.T) {
	image, err := resolveInfrastructureImage(context.Background(), infraResolverForRun, "caddy", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if matched, _ := regexp.MatchString(`^caddy:[0-9]+@sha256:[0-9a-f]{64}$`, image); !matched {
		t.Fatalf("shared Caddy image is not a resolved official digest: %q", image)
	}
	stack := setupCaddyStack(image, config.Caddy{})
	for _, forbidden := range []string{"DNS_TOKEN", "dns cloudflare", "docker secret"} {
		if strings.Contains(strings.ToLower(stack), strings.ToLower(forbidden)) {
			t.Fatalf("shared Caddy stack contains removed external DNS integration %q", forbidden)
		}
	}
	if !strings.Contains(stack, image) {
		t.Fatalf("shared Caddy stack does not use the resolved image %q", image)
	}
	if strings.Contains(setupCaddyCommand(), "docker build") {
		t.Fatal("shared Caddy setup must not build a custom proxy image")
	}
}

func TestRuntimeFirewallAllowsOnlyConfiguredPublicServices(t *testing.T) {
	program := setupRuntimeCommand(2222, defaultPublicTCPPorts(t), setupModeFresh)
	for _, rule := range []string{"ufw allow 2222/tcp", "ufw allow 80/tcp", "ufw allow 443/tcp", "ufw allow 443/udp"} {
		if !strings.Contains(program, rule) {
			t.Fatalf("runtime firewall is missing %q", rule)
		}
	}
	for _, rule := range []string{"shuttle-docker-user-firewall", "-A DOCKER-USER -j ufw-user-forward", "-A DOCKER-USER -d 172.16.0.0/12 -p tcp", "-A ufw-docker-logging-deny -j DROP", "/etc/ufw/after.init", "After=ufw.service docker.service"} {
		if !strings.Contains(program, rule) {
			t.Fatalf("runtime firewall is missing persistent Docker/UFW rule %q", rule)
		}
	}
	if strings.Contains(program, "cat >>/etc/ufw/after.rules") {
		t.Fatal("Docker rules must not reference ufw-user-forward during after.rules restoration")
	}
}

func TestRuntimeDisablesLinkLocalNameResolution(t *testing.T) {
	program := setupRuntimeCommand(22, defaultPublicTCPPorts(t), setupModeFresh)
	for _, setting := range []string{"LLMNR=no", "MulticastDNS=no", "systemctl restart systemd-resolved"} {
		if !strings.Contains(program, setting) {
			t.Fatalf("runtime baseline is missing %q", setting)
		}
	}
}

func TestBaseAppliesHeldKernelSecurityUpdates(t *testing.T) {
	if !strings.Contains(setupBaseCommand(setupModeFresh), "apt-get dist-upgrade -y") {
		t.Fatal("base setup must apply upgrades that require dependency changes")
	}
}

func TestBaseConvergesUnattendedPolicyOutsideCheckpoint(t *testing.T) {
	program := setupBaseCommand(setupModeFresh)
	checkpointEnd := strings.Index(program, "touch /etc/shuttle/setup.d/10-base")
	policyStart := strings.Index(program, "unattended_file=/etc/apt/apt.conf.d/52shuttle-unattended-upgrades")
	if checkpointEnd < 0 || policyStart < checkpointEnd {
		t.Fatalf("unattended policy must run after the 10-base checkpoint:\n%s", program)
	}
	for _, required := range []string{
		"ubuntu:24.04)", "debian:13)",
		`"${distro_id}:${distro_codename}-security"`,
		`"${distro_id}ESMApps:${distro_codename}-apps-security"`,
		`"${distro_id}ESM:${distro_codename}-infra-security"`,
		`origin=Debian,codename=${distro_codename}-security,label=Debian-Security`,
		`Unattended-Upgrade::Automatic-Reboot "false";`,
		`#clear Unattended-Upgrade::Allowed-Origins;`, `#clear Unattended-Upgrade::Origins-Pattern;`,
		"cmp -s", "mv -f", "chmod 0644",
	} {
		if !strings.Contains(program, required) {
			t.Errorf("base setup does not converge required unattended policy fragment %q", required)
		}
	}
	if !strings.Contains(program, "if ! cmp -s \"$unattended_tmp\" \"$unattended_file\"; then\n  mv -f \"$unattended_tmp\" \"$unattended_file\"\nelse\n  rm -f \"$unattended_tmp\"\nfi") {
		t.Fatal("an identical policy drop-in must be discarded without replacing the existing file")
	}
}

func TestDockerSetupDistinguishesRegistryVolumeFromContainer(t *testing.T) {
	program := setupDockerCommand(setupModeFresh)
	for _, required := range []string{"docker volume inspect shuttle-registry", "docker container inspect shuttle-registry", "http://127.0.0.1:5000/v2/", ".State.Health.Status"} {
		if !strings.Contains(program, required) {
			t.Fatalf("Docker setup is missing registry convergence proof %q", required)
		}
	}
	if strings.Contains(program, "docker inspect shuttle-registry") {
		t.Fatal("untyped docker inspect can mistake the registry volume for its container")
	}
}

func TestCaddySetupPersistsAuditSourceAndWaitsForValidation(t *testing.T) {
	program := setupCaddyCommand()
	for _, required := range []string{"/etc/shuttle/Caddyfile", "docker service ls", "docker exec \"$container\" caddy validate", "ready=1", "docker service ps --no-trunc"} {
		if !strings.Contains(program, required) {
			t.Fatalf("Caddy setup is missing convergence proof %q", required)
		}
	}
	if strings.Contains(program, "then\n    exit 0") {
		t.Fatal("Caddy readiness must not exit before the setup checkpoint is written")
	}
}

// The shared edge publishes 80/443 in host mode with a single replica. A
// start-first update asks the replacement task to bind ports the outgoing task
// still holds, which never resolves: the service stays unconverged, the caller
// waits forever while holding the root-operation lock, and the public endpoint
// stays down until the VPS is rebooted out of band.
func TestSharedCaddyNeverUpdatesStartFirstOnHostPorts(t *testing.T) {
	stack := setupCaddyStack(caddyImageDefault, config.Caddy{})
	if !strings.Contains(stack, "mode: host") {
		t.Fatal("this contract only matters while the edge publishes host-mode ports")
	}
	if strings.Contains(stack, "order: start-first") {
		t.Fatal("shared Caddy must not update start-first: host-mode ports cannot be bound twice")
	}
	if !strings.Contains(stack, "order: stop-first") {
		t.Fatalf("shared Caddy update order must be stop-first:\n%s", stack)
	}
}

// DEV-DEPL-64: a refused connect right after the SSH baseline reloaded sshd is
// retried (nothing ran), any other failure is returned at once.
func TestRunAfterSSHDReloadRetriesOnlyARefusedConnect(t *testing.T) {
	calls := 0
	result := runAfterSSHDReload(func() shuttlessh.Result {
		calls++
		if calls == 1 {
			return shuttlessh.Result{Code: 255, Stderr: "dial tcp 192.0.2.4:22: connect: connection refused", ConnectRefused: true}
		}
		return shuttlessh.Result{Code: 0}
	})
	if result.Code != 0 || calls != 2 {
		t.Fatalf("refused connect was not retried: code=%d calls=%d", result.Code, calls)
	}
	calls = 0
	result = runAfterSSHDReload(func() shuttlessh.Result {
		calls++
		return shuttlessh.Result{Code: 1, Stderr: "signed audit refused"}
	})
	if result.Code != 1 || calls != 1 {
		t.Fatalf("a real failure was retried: code=%d calls=%d", result.Code, calls)
	}
	// A remote command that ran and printed the same words is not retried.
	calls = 0
	result = runAfterSSHDReload(func() shuttlessh.Result {
		calls++
		return shuttlessh.Result{Code: 1, Stderr: "helper: upstream connect: connection refused"}
	})
	if calls != 1 {
		t.Fatalf("remote stderr text triggered a retry: calls=%d", calls)
	}
	// No attempt starts after the budget.
	calls = 0
	started := time.Now()
	runAfterSSHDReloadWithin(30*time.Millisecond, 20*time.Millisecond, func() shuttlessh.Result {
		calls++
		return shuttlessh.Result{Code: 255, ConnectRefused: true}
	})
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond || calls > 3 {
		t.Fatalf("retry ran past its budget: %s, %d calls", elapsed, calls)
	}
}
