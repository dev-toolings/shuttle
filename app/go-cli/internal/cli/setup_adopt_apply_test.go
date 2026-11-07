package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// defaultPublicTCPPorts is what a configuration that declares no extra public
// port produces. Tests take it from the configuration rather than restating
// {80, 443}, so a change to the default is a failing test here instead of a
// firewall that quietly stops matching the audit.
func defaultPublicTCPPorts(t *testing.T) []int {
	t.Helper()
	cfg := &config.Config{Servers: map[string]config.ServerGroup{"web": {Hosts: []string{"203.0.113.7"}, Port: 22}}}
	return cfg.AllowedPublicTCPPorts()
}

func adoptionApplyConfig(t *testing.T, extraPorts ...int) *config.Config {
	t.Helper()
	group := config.ServerGroup{Hosts: []string{"203.0.113.7"}, Port: 22}
	group.Access.AllowedPublicTCPPorts = append([]int{80, 443}, extraPorts...)
	return &config.Config{App: "demo", Servers: map[string]config.ServerGroup{"web": group}}
}

// Setup goldens use a fixed fake registry digest so the generated scripts stay
// deterministic without reaching Docker Hub.
func TestSetupStagesAreUnchangedWithoutAdoption(t *testing.T) {
	for name, generated := range map[string]string{
		"setup-helper-safety.sh":         setupHelperReplacementGuard,
		"setup-fresh-10-base.sh":         setupBaseCommand(setupModeFresh),
		"setup-fresh-20-docker.sh":       setupDockerCommand(setupModeFresh, "registry:3@sha256:"+strings.Repeat("a", 64)),
		"setup-fresh-40-runtime-22.sh":   setupRuntimeCommand(22, defaultPublicTCPPorts(t), setupModeFresh),
		"setup-fresh-40-runtime-2222.sh": setupRuntimeCommand(2222, defaultPublicTCPPorts(t), setupModeFresh),
	} {
		t.Run(name, func(t *testing.T) {
			expected, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			if generated != string(expected) {
				t.Fatalf("the fresh-setup program moved while adding adoption:\n--- want\n%s\n--- got\n%s", expected, generated)
			}
		})
	}
}

// On a host in service, dist-upgrade is an unrequested change to software the
// operator did not ask Shuttle to touch. The packages the baseline needs are
// still installed, and unattended-upgrades still enabled, so security updates
// keep arriving on the host's schedule.
func TestAdoptionInstallsTheBaselineWithoutUpgradingTheWholeHost(t *testing.T) {
	adopted := setupBaseCommand(setupModeAdoption)
	if strings.Contains(adopted, "dist-upgrade") {
		t.Fatalf("adoption must not dist-upgrade a host in service:\n%s", adopted)
	}
	for _, required := range []string{
		"apt-get update -y",
		"apt-get install -y ca-certificates curl gnupg sudo ufw fail2ban apparmor apparmor-utils unattended-upgrades openssh-server systemd-timesyncd",
		"systemctl enable --now apparmor fail2ban unattended-upgrades systemd-timesyncd",
		"/etc/shuttle/setup.d/10-base",
	} {
		if !strings.Contains(adopted, required) {
			t.Fatalf("the adopted baseline is missing %q:\n%s", required, adopted)
		}
	}
	if !strings.Contains(setupBaseCommand(setupModeFresh), "apt-get dist-upgrade -y") {
		t.Fatal("a fresh VPS must still be brought up to date")
	}
}

// The firewall is the one thing in this lot that can lock the operator out of a
// machine that is serving traffic: `ufw --force reset` clears every rule and
// `ufw --force enable` installs a default-deny policy. The rule for the port
// this run arrived on has to exist before the policy is enabled, never after.
func TestAdoptionOpensTheLiveSSHPortBeforeEnablingTheFirewall(t *testing.T) {
	program := setupRuntimeCommand(2222, defaultPublicTCPPorts(t), setupModeAdoption)
	guard := strings.Index(program, "ufw show added")
	enable := strings.Index(program, "ufw --force enable")
	reset := strings.Index(program, "ufw --force reset")
	if guard < 0 || enable < 0 || reset < 0 {
		t.Fatalf("the adopted runtime stage lost its firewall transaction:\n%s", program)
	}
	if !(reset < guard && guard < enable) {
		t.Fatalf("the SSH reachability guard must sit between the reset and the enable (reset=%d guard=%d enable=%d)", reset, guard, enable)
	}
	for _, required := range []string{
		"sshd -T 2>/dev/null | awk '$1 == \"port\" { print $2 }'",
		"systemctl show ssh.socket -p ListenStream",
		"ss -H -ltnp",
		"ufw allow \"$ssh_port\"/tcp",
		"grep -Fqx \"ufw allow 2222/tcp\"",
		"refusing to enable the firewall: no rule was added for SSH port 2222",
	} {
		if !strings.Contains(program, required) {
			t.Fatalf("the SSH reachability guard is missing %q:\n%s", required, program)
		}
	}
	if strings.Contains(setupRuntimeCommand(2222, defaultPublicTCPPorts(t), setupModeFresh), "ufw show added") {
		t.Fatal("the guard is adoption-only: a fresh VPS has no listener but the one this configuration declares")
	}
}

// A host in service can legitimately publish something beyond the edge — the
// analytics container on 3000 that forced this. The firewall Shuttle applies
// and the proof that checks it must both come from the declared list, or a
// reset closes a port nothing can reopen.
func TestDeclaredPublicPortsDriveBothTheFirewallAndItsProof(t *testing.T) {
	ports := adoptionApplyConfig(t, 3000).AllowedPublicTCPPorts()
	program := setupRuntimeCommand(22, ports, setupModeAdoption)
	for _, required := range []string{
		"ufw allow 80/tcp",
		"ufw allow 443/tcp",
		"ufw allow 3000/tcp",
		"ufw allow 443/udp",
		`"$iptables" -A DOCKER-USER -p tcp --dport 3000 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN`,
	} {
		if !strings.Contains(program, required) {
			t.Fatalf("a declared public port is missing from the firewall: %q\n%s", required, program)
		}
	}
	if strings.Index(program, "--dport 3000") > strings.Index(program, "-d 10.0.0.0/8 -p tcp") {
		t.Fatal("a published port must be returned before the private-range denies")
	}
	proof := setupAdoptionProofCommand(2222, ports)
	for _, required := range []string{"ufw status | grep -q '^2222/tcp'", "ufw status | grep -q '^80/tcp'", "ufw status | grep -q '^3000/tcp'"} {
		if !strings.Contains(proof, required) {
			t.Fatalf("the adoption proof does not check %q:\n%s", required, proof)
		}
	}
	undeclared := setupRuntimeCommand(22, defaultPublicTCPPorts(t), setupModeAdoption)
	if strings.Contains(undeclared, "3000") {
		t.Fatal("a port nobody declared must not be opened")
	}
}

// The fresh proof asserts the finished article and must never be weakened. The
// adoption proof asserts what stages 10-base to 40-runtime actually produce,
// which is a different set — not a shorter version of the same one.
func TestAdoptionProofProvesThisStageWithoutWeakeningTheFreshOne(t *testing.T) {
	fresh := setupInfrastructureProofCommand()
	for _, required := range []string{"shuttle-edge_caddy 1/1", "caddy validate", "test ! -e /var/run/reboot-required", "systemctl --failed"} {
		if !strings.Contains(fresh, required) {
			t.Fatalf("the fresh infrastructure proof lost %q", required)
		}
	}
	adopted := setupAdoptionProofCommand(22, defaultPublicTCPPorts(t))
	for _, required := range []string{
		"docker container inspect shuttle-registry",
		"http://127.0.0.1:5000/v2/",
		"{{.Swarm.LocalNodeState}}",
		"systemctl is-active --quiet docker postgresql fail2ban ssh",
		"test -x /usr/local/libexec/shuttle-root",
		"test -f /etc/shuttle/trusted-root-operations.pem",
		"test -f /etc/shuttle/setup-state",
		"id -nG deploy",
		"fail2ban-client status sshd",
		"ufw status | grep -qx 'Status: active'",
		"iptables -C DOCKER-USER -j ufw-user-forward",
		"resolvectl status",
	} {
		if !strings.Contains(adopted, required) {
			t.Fatalf("the adoption proof is missing %q:\n%s", required, adopted)
		}
	}
	// An adopted host has not taken the cutover, so proving the edge would be
	// proving something this run deliberately did not do.
	for _, absent := range []string{"shuttle-edge_caddy", "caddy validate", "/var/run/reboot-required", "systemctl --failed"} {
		if strings.Contains(adopted, absent) {
			t.Fatalf("the adoption proof asserts %q, which this stage does not produce", absent)
		}
	}
}

func TestAdoptionShellProgramsStillParse(t *testing.T) {
	ports := adoptionApplyConfig(t, 3000).AllowedPublicTCPPorts()
	for name, program := range map[string]string{
		"adopted-base":    setupBaseCommand(setupModeAdoption),
		"adopted-runtime": setupRuntimeCommand(2222, ports, setupModeAdoption),
		"adopted-proof":   setupAdoptionProofCommand(2222, ports),
		"adoption-claim":  adoptionClaimSource,
	} {
		t.Run(name, func(t *testing.T) {
			command := exec.Command("sh", "-n")
			command.Stdin = strings.NewReader(program)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("generated shell does not parse: %v\n%s\n%s", err, output, program)
			}
		})
	}
}

// The checkpoints are what make an adoption resumable, and the state file is
// what stops the next run from mistaking a half-converged host for a foreign
// machine. Both are asserted here because both are load-bearing on a host that
// is carrying production while it is being converged.
func TestAdoptionIsResumableWithSafetyBeforeCheckpointedStages(t *testing.T) {
	cfg := adoptionApplyConfig(t)
	stages := setupStages(cfg, 22, setupModeAdoption)
	names := make([]string, 0, len(stages))
	for _, stage := range stages {
		names = append(names, stage.name)
	}
	if strings.Join(names, ",") != "helper-safety,base,docker,postgres,runtime" {
		t.Fatalf("adoption must run the existing stages in the existing order, got %q", names)
	}
	for index, marker := range []string{"10-base", "20-docker", "30-postgres", "40-runtime"} {
		if !strings.Contains(stages[index+1].command, "if [ ! -f /etc/shuttle/setup.d/"+marker+" ]") {
			t.Fatalf("stage %s is not guarded by its checkpoint:\n%s", marker, stages[index+1].command)
		}
	}
	if !strings.Contains(adoptionClaimSource, "printf 'version=2\\n' >/etc/shuttle/setup-state") {
		t.Fatalf("the claim must write the setup state the exit-43 guard reads:\n%s", adoptionClaimSource)
	}
	if !strings.Contains(adoptionClaimSource, "rm -f /tmp/shuttle-operator.pub") {
		t.Fatalf("the claim must clear the staging paths the adoption user writes:\n%s", adoptionClaimSource)
	}
	// The same file 40-runtime writes: nothing downstream may tell them apart.
	if !strings.Contains(stages[4].command, "printf 'version=2\\n' >/etc/shuttle/setup-state") {
		t.Fatal("40-runtime and the adoption claim must write the same setup state")
	}
}

// The two refusals this lot adds, in the shape an operator meets them.
func TestAdoptionRefusesToApplyWithoutConfirmationOrOutsideARebootWindow(t *testing.T) {
	options := setupOptions{target: "ops@203.0.113.7:22", expectedHostKey: "SHA256:" + strings.Repeat("A", 43), adopt: true}
	err := runSetupAdoption(&strings.Builder{}, adoptionApplyConfig(t), setupIdentity{user: "ops", host: "203.0.113.7", port: 22}, options, time.Now())
	if err == nil || err.Error() != "adopting a host in service requires explicit --yes confirmation (run --adopt --dry-run first)" {
		t.Fatalf("an unconfirmed adoption must refuse before contacting the host, got %v", err)
	}

	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	pending := adoptionSurvey{RebootRequired: true}
	confirmed := setupOptions{adopt: true, yes: true}
	var warned strings.Builder
	warnAdoptionOnPendingReboot(&warned, identity, pending, confirmed)
	const expected = "WARNING: ops@203.0.113.7:22 has /var/run/reboot-required: its packages (often a kernel) wait for a reboot. This run does not reboot it; reboot in a maintenance window or pass --allow-reboot to let a run take it.\n"
	if warned.String() != expected {
		t.Fatalf("a pending reboot must be reported as a warning naming the flag, got:\n%s", warned.String())
	}
	for _, quiet := range []struct {
		survey  adoptionSurvey
		options setupOptions
	}{
		{pending, setupOptions{adopt: true, yes: true, allowReboot: true}},
		{adoptionSurvey{}, confirmed},
	} {
		var out strings.Builder
		warnAdoptionOnPendingReboot(&out, identity, quiet.survey, quiet.options)
		if out.Len() != 0 {
			t.Fatalf("no warning expected for %+v, got %q", quiet, out.String())
		}
	}

	flag := newSetupCommand().Flags().Lookup("allow-reboot")
	if flag == nil || flag.DefValue != "false" {
		t.Fatalf("rebooting a host in service must be opt-in; --allow-reboot is %v", flag)
	}
}

// The survey reports the pending reboot as its own typed field, and a value
// this build does not understand is never read as "nothing pending".
func TestAdoptionSurveyReportsThePendingReboot(t *testing.T) {
	for _, required := range []string{"/var/run/reboot-required", "reboot-required=present", "reboot-required=absent"} {
		if !strings.Contains(adoptionSurveySource, required) {
			t.Fatalf("the survey does not report the pending reboot: missing %q", required)
		}
	}
	present, err := parseAdoptionSurvey("reboot-required=present\n")
	if err != nil || !present.RebootRequired {
		t.Fatalf("a pending reboot must be parsed: %+v %v", present, err)
	}
	absent, err := parseAdoptionSurvey("reboot-required=absent\n")
	if err != nil || absent.RebootRequired {
		t.Fatalf("an absent reboot marker must be parsed: %+v %v", absent, err)
	}
	if _, err := parseAdoptionSurvey("reboot-required=maybe\n"); err == nil {
		t.Fatal("an unusable reboot state must stop the run")
	}
}

// adoptionOptions is the flag state of a plain `--adopt --yes`: no reboot, no
// cutover, the first-contact account preserved. Tests take it from one place so
// a new adoption flag whose default moves shows up as a failure here.
func adoptionOptions() setupOptions {
	return setupOptions{adopt: true, yes: true}
}

// What the plan promises and what the completion report restates come from one
// list, so an operator is told the same boundary before and after.
func TestAdoptionAnnouncesTheStopAfterRuntimeBeforeApplying(t *testing.T) {
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	survey, err := parseAdoptionSurvey(adoptionSurveySample + "reboot-required=present\n")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	options := adoptionOptions()
	edge := resolveAdoptionEdgePlan(identity, survey, options, nil, false)
	plan := adoptionPlan(identity, "demo", fingerprint, survey, options, edge, defaultPublicTCPPorts(t), true)
	for _, required := range []string{
		"pending reboot    yes, /var/run/reboot-required is present; warning only, adoption does not reboot without --allow-reboot",
		"stages this run applies, in order",
		"- 10-base (security baseline, unattended upgrades, swap), already satisfied so its checkpoint skips it",
		"- 30-postgres (PostgreSQL on loopback and the Docker gateway)",
		"- 40-runtime (deploy user, signed root helper, UFW and Docker forwarding policy)",
		"apt-get dist-upgrade is not run",
		"after the stages, the signed SSH hardening transaction runs: it is what grants deploy the sudoers rule for the root helper",
		"not attempted by this run",
		"50-caddy-direct: taking 80/443 from the incumbent listener",
		"migrating the adopted application's PostgreSQL database",
	} {
		if !strings.Contains(plan, required) {
			t.Fatalf("the applied plan is missing %q:\n%s", required, plan)
		}
	}
	if strings.Contains(plan, "50-caddy-direct (shared Caddy edge on 80/443)\n    - ") {
		t.Fatal("the cutover must never be listed as a stage this run applies")
	}
	for _, applied := range adoptionAppliedStages(survey, edge) {
		if strings.HasPrefix(applied, "50-caddy-direct") {
			t.Fatalf("50-caddy-direct is not applied without --cutover-edge, got %q", applied)
		}
	}
	if strings.Contains(plan, "the adoption survey is read-only") {
		t.Fatal("an applying run must not claim to be read-only")
	}
	if !strings.Contains(adoptionPlan(identity, "demo", fingerprint, survey, options, edge, defaultPublicTCPPorts(t), false), "the adoption survey is read-only") {
		t.Fatal("a dry run must still say it changed nothing")
	}
	if plan != adoptionPlan(identity, "demo", fingerprint, survey, options, edge, defaultPublicTCPPorts(t), true) {
		t.Fatal("the adoption plan is not deterministic")
	}
}

// A flag that grants nothing must not look like it grants something. A fresh
// setup already completes the reboot its own package installation requires, so
// --allow-reboot outside adoption is refused rather than quietly ignored — and
// it is refused before the first packet.
func TestAllowRebootIsRefusedOutsideAdoption(t *testing.T) {
	withTempDir(t, func(dir string) {
		initialise := newInitCommand()
		initialise.SetArgs([]string{"--preset", "nextjs", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
		if err := initialise.Execute(); err != nil {
			t.Fatal(err)
		}
		arguments := []string{
			"--config", filepath.Join(dir, "config.json"),
			"--target", "root@203.0.113.10:22",
			"--expected-host-key", "SHA256:" + strings.Repeat("A", 43),
			"--public-key", writeOperatorPublicKey(t),
			"--dry-run",
			"--allow-reboot",
		}
		cmd := newSetupCommand()
		cmd.SetOut(&strings.Builder{})
		cmd.SetErr(&strings.Builder{})
		cmd.SetArgs(arguments)
		err := cmd.Execute()
		if err == nil || err.Error() != "--allow-reboot only applies to --adopt; a fresh setup always completes the reboot its own package installation requires" {
			t.Fatalf("--allow-reboot without --adopt must be refused, got %v", err)
		}
	})
}
