package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

// ── Lot A: the hardening transaction preserves the account it arrived on ─────

// Adoption is the only reason AllowUsers became a signed value, and a fresh
// setup must not be able to tell. Passing no extra account has to produce the
// same four envelopes, byte for byte, that rootplan's own constructors produce.
func TestFreshBaselineEnvelopesAreUnchangedByTheAdoptionParameter(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	now := time.Now().UTC()
	identity := setupIdentity{operatorKeyFingerprint: fingerprint}
	envelopes, err := prepareBaselineEnvelopes(identity, fingerprint, privateKey, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := rootplan.NewBaseline(fingerprint, fingerprint, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if historical, err = rootplan.Sign(historical, privateKey); err != nil {
		t.Fatal(err)
	}
	expected, err := encodeRootHelperEnvelope(historical, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(envelopes.baseline) != string(expected) {
		t.Fatalf("a setup that names no extra account must sign the historical baseline:\n--- want\n%s\n--- got\n%s", expected, envelopes.baseline)
	}
	plan, _, err := decodeRootHelperEnvelope(strings.NewReader(string(envelopes.baseline)))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Baseline != nil {
		t.Fatalf("the historical baseline carries no account list, got %#v", plan.Baseline)
	}
}

// The first-contact account is what the operator is holding the session open
// with, and on a host adopted from a previous generation it is also what that
// generation's deployments still use. It travels in the signed list unless the
// operator explicitly asked for the strict one.
func TestAdoptionSignsTheFirstContactAccountIntoAllowUsers(t *testing.T) {
	for name, testCase := range map[string]struct {
		user     string
		lockOut  bool
		expected string
	}{
		"a sudo operator is preserved":   {user: "ops", expected: "ops"},
		"the strict flag drops it":       {user: "ops", lockOut: true, expected: ""},
		"root is never signed in":        {user: "root", expected: ""},
		"deploy is already in the list":  {user: "deploy", expected: ""},
		"another operator is preserved":  {user: "demo", expected: "demo"},
		"strict wins over any account":   {user: "demo", lockOut: true, expected: ""},
		"an underscore login is allowed": {user: "svc_ops", expected: "svc_ops"},
	} {
		t.Run(name, func(t *testing.T) {
			identity := setupIdentity{user: testCase.user, host: "203.0.113.7", port: 22}
			options := adoptionOptions()
			options.lockOutFirstContactUser = testCase.lockOut
			got := strings.Join(adoptionPreservedSSHUsers(identity, options), " ")
			if got != testCase.expected {
				t.Fatalf("preserved accounts = %q, want %q", got, testCase.expected)
			}
		})
	}

	// What is preserved has to survive sealing and the helper's own
	// re-validation, not merely be computed.
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	plan, err := rootplan.NewBaselineWithSSHUsers(fingerprint, fingerprint, adoptionPreservedSSHUsers(identity, adoptionOptions()), time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(plan.Baseline.AllowedSSHUsers, " "); got != "deploy ops" {
		t.Fatalf("the signed AllowUsers list is %q, want \"deploy ops\"", got)
	}
	if got := describeAdoptionAllowUsers(identity, adoptionOptions()); got != "AllowUsers deploy ops" {
		t.Fatalf("the plan and the directive disagree: %q", got)
	}
}

// The pre-signed rollback is only a recovery if it reaches the helper. On an
// adopted host it cannot travel through deploy before the baseline has applied:
// /etc/sudoers.d/90-shuttle-root is written by that very operation, so `sudo -n`
// would be refused by sudo itself and the rollback would report a failure it
// never even attempted. The channel is the first-contact account, whose
// non-interactive root was proven before any mutation, and it moves to deploy
// once deploy is privileged — which is also when the strict flag has closed the
// first-contact account.
func TestSignedOperationsNameTheChannelTheyTravelOn(t *testing.T) {
	if got := rootHelperApplyCommand(false); got != "/usr/local/libexec/shuttle-root apply" {
		t.Fatalf("a root channel must invoke the helper directly, got %q", got)
	}
	if got := rootHelperApplyCommand(true); got != "sudo -n /usr/local/libexec/shuttle-root apply" {
		t.Fatalf("an unprivileged channel must become root non-interactively, got %q", got)
	}
	// The sudoers rule the deploy channel depends on has exactly one writer,
	// and it is the operation the rollback exists to undo.
	helper, err := os.ReadFile("root_helper_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(helper), `"/etc/sudoers.d/90-shuttle-root"`) != 2 {
		t.Fatal("90-shuttle-root is expected to be written and validated by applyRootBaseline alone; if that moved, the adoption rollback channel must be revisited")
	}
	if !strings.Contains(string(helper), "func applyRootBaseline(") {
		t.Fatal("applyRootBaseline is the operation that grants deploy its privilege")
	}
}

// A flag that grants nothing must not look like it grants something, and the
// default must be the safe one: an adoption that preserves the account it
// arrived on.
func TestAdoptionHardeningFlagsAreOptInAndAdoptionOnly(t *testing.T) {
	flags := newSetupCommand().Flags()
	for name, usage := range map[string]string{
		"lock-out-first-contact-user": "loses SSH access",
		"cutover-edge":                "restarted if the edge does not become healthy",
	} {
		flag := flags.Lookup(name)
		if flag == nil {
			t.Fatalf("--%s does not exist", name)
		}
		if flag.DefValue != "false" {
			t.Fatalf("--%s must be opt-in, default is %q", name, flag.DefValue)
		}
		if !strings.Contains(flag.Usage, usage) {
			t.Fatalf("--%s must say what it costs, usage is %q", name, flag.Usage)
		}
	}

	for flag, expected := range map[string]string{
		"--cutover-edge":                "--cutover-edge only applies to --adopt; a fresh setup deploys the shared edge because nothing else on that host is listening on 80/443",
		"--lock-out-first-contact-user": "--lock-out-first-contact-user only applies to --adopt; a fresh setup requires a separate administrator",
	} {
		withTempDir(t, func(dir string) {
			initialise := newInitCommand()
			initialise.SetArgs([]string{"--preset", "nextjs", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
			if err := initialise.Execute(); err != nil {
				t.Fatal(err)
			}
			cmd := newSetupCommand()
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})
			cmd.SetArgs([]string{
				"--config", filepath.Join(dir, "config.json"),
				"--target", "root@203.0.113.10:22",
				"--expected-host-key", "SHA256:" + strings.Repeat("A", 43),
				"--public-key", writeOperatorPublicKey(t),
				"--dry-run",
				flag,
			})
			err := cmd.Execute()
			if err == nil || err.Error() != expected {
				t.Fatalf("%s without --adopt must be refused with the reason, got %v", flag, err)
			}
		})
	}
}

// The plan says what hardening does to the account the operator is reading it
// from, before anything is applied.
func TestAdoptionPlanNamesWhatHardeningDoesToTheFirstContactAccount(t *testing.T) {
	survey, err := parseAdoptionSurvey(adoptionSurveySample)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	ops := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}

	preserved := adoptionPlan(ops, "demo", fingerprint, survey, adoptionOptions(), adoptionEdgePlan{}, defaultPublicTCPPorts(t), true)
	if !strings.Contains(preserved, "ssh baseline      root, password and keyboard-interactive logins are closed; signs AllowUsers deploy ops, so ops keeps the access this run is using (--lock-out-first-contact-user drops it)") {
		t.Fatalf("the plan does not say the account is preserved:\n%s", preserved)
	}

	strict := adoptionOptions()
	strict.lockOutFirstContactUser = true
	locked := adoptionPlan(ops, "demo", fingerprint, survey, strict, adoptionEdgePlan{}, defaultPublicTCPPorts(t), true)
	if !strings.Contains(locked, "signs AllowUsers deploy alone, so ops loses SSH access to this host (--lock-out-first-contact-user)") {
		t.Fatalf("the plan does not say the account is dropped:\n%s", locked)
	}

	asRoot := adoptionPlan(setupIdentity{user: "root", host: "203.0.113.7", port: 22}, "demo", fingerprint, survey, adoptionOptions(), adoptionEdgePlan{}, defaultPublicTCPPorts(t), true)
	if !strings.Contains(asRoot, "root — the account this run arrived on — is closed with them") {
		t.Fatalf("adopting as root must say root SSH is what gets closed:\n%s", asRoot)
	}
}

// ── Lot B: the 80/443 cutover ───────────────────────────────────────────────

// The fresh stage is the reference. It predates the cutover and must not have
// moved a byte while the cutover was added beside it.
func TestSharedEdgeStageIsUnchangedWithoutAdoption(t *testing.T) {
	expected, err := os.ReadFile(filepath.Join("testdata", "setup-fresh-50-caddy-direct.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if setupCaddyCommand() != string(expected) {
		t.Fatalf("the fresh shared-edge stage moved:\n--- want\n%s\n--- got\n%s", expected, setupCaddyCommand())
	}
}

// Taking ports that are serving requests is an outage. It happens because an
// operator asked for it, never because a convergence run reached that line.
func TestEdgeCutoverNeedsTheOperatorToAskForIt(t *testing.T) {
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	survey, err := parseAdoptionSurvey("port-held=80 by published container demo-app-caddy-1\n")
	if err != nil {
		t.Fatal(err)
	}
	silent := resolveAdoptionEdgePlan(identity, survey, adoptionOptions(), nil, false)
	if silent.applies() || silent.Incumbent != "" || silent.Refusal != nil {
		t.Fatalf("without --cutover-edge nothing about the incumbent is decided: %#v", silent)
	}
	deferred := strings.Join(adoptionDeferredWork(silent, true), "\n")
	if !strings.Contains(deferred, "50-caddy-direct: taking 80/443 from the incumbent listener") || !strings.Contains(deferred, "--cutover-edge") {
		t.Fatalf("a deferred cutover must be named along with the flag that schedules it:\n%s", deferred)
	}
	if !strings.Contains(describeAdoptionEdgePlan(silent), "not scheduled") {
		t.Fatalf("the plan must say the ports are left alone: %q", describeAdoptionEdgePlan(silent))
	}

	options := adoptionOptions()
	options.cutoverEdge = true
	asked := resolveAdoptionEdgePlan(identity, survey, options, nil, false)
	if !asked.applies() || asked.Incumbent != "demo-app-caddy-1" {
		t.Fatalf("--cutover-edge must name the incumbent from the survey: %#v", asked)
	}
	if strings.Contains(strings.Join(adoptionDeferredWork(asked, true), "\n"), "50-caddy-direct") {
		t.Fatal("a cutover this run performs must not also be reported as deferred")
	}
}

// The survey already reports who holds 80/443. Adoption reads it and refuses
// every case in which it would either have to choose a victim or would not be
// able to give the ports back.
func TestEdgeCutoverRefusesEveryHolderItCouldNotRestore(t *testing.T) {
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	options := adoptionOptions()
	options.cutoverEdge = true

	for name, testCase := range map[string]struct {
		lines     string
		incumbent string
		refusal   string
	}{
		"one container, seen on both ports": {
			lines:     "port-held=80 by published container demo-app-caddy-1\nport-held=443 by published container demo-app-caddy-1\nport-held=80/tcp by process docker-proxy\n",
			incumbent: "demo-app-caddy-1",
		},
		"two containers": {
			lines:   "port-held=80 by published container legacy-web\nport-held=443 by published container other-edge\n",
			refusal: "held by more than one container (legacy-web, other-edge)",
		},
		"a process with no container": {
			lines:   "port-held=80/tcp by process nginx\nport-held=443/tcp by process nginx\n",
			refusal: "held by nginx, which is not a container this run can stop and start again",
		},
		"an unidentified process": {
			lines:   "port-held=80/tcp by process an unidentified process\n",
			refusal: "held by an unidentified process",
		},
		"Shuttle's own edge is not an incumbent": {
			lines:     "port-held=80 by published container shuttle-edge_caddy.1.abc\n",
			incumbent: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			survey, err := parseAdoptionSurvey(testCase.lines)
			if err != nil {
				t.Fatal(err)
			}
			plan := resolveAdoptionEdgePlan(identity, survey, options, nil, false)
			if testCase.refusal == "" {
				if plan.Refusal != nil {
					t.Fatalf("unexpected refusal: %v", plan.Refusal)
				}
				if plan.Incumbent != testCase.incumbent {
					t.Fatalf("incumbent = %q, want %q", plan.Incumbent, testCase.incumbent)
				}
				return
			}
			if plan.Refusal == nil {
				t.Fatalf("this holder must be refused, got incumbent %q", plan.Incumbent)
			}
			if !strings.Contains(plan.Refusal.Error(), testCase.refusal) {
				t.Fatalf("the refusal does not name the cause: %v", plan.Refusal)
			}
			if plan.applies() {
				t.Fatal("a refused cutover must not apply")
			}
			if !strings.Contains(describeAdoptionEdgePlan(plan), "refused") {
				t.Fatalf("a dry run must print the refusal: %q", describeAdoptionEdgePlan(plan))
			}
		})
	}

	// A line this build cannot read is not an empty result. Reading "nginx is
	// listening" as "nothing is listening" is how a cutover walks into the
	// outage it was warned about.
	unreadable := adoptionSurvey{PortsHeld: []string{"8080 by published container something"}}
	plan := resolveAdoptionEdgePlan(identity, unreadable, options, nil, false)
	if plan.Refusal == nil {
		t.Fatal("a port-holder line outside the protocol must refuse the cutover")
	}
}

// The order is the whole point: pull before stopping, stop only what was named,
// and give the ports back when the edge does not come up.
func TestEdgeCutoverPullsFirstAndRestoresTheIncumbentOnFailure(t *testing.T) {
	program := setupCaddyCutoverCommand("demo-app-caddy-1", caddyImageDefault)

	pull := strings.Index(program, "docker pull")
	stop := strings.Index(program, "docker stop --time 20")
	deploy := strings.Index(program, "docker stack deploy")
	wait := strings.Index(program, `while [ "$attempt" -lt 24 ]`)
	failure := strings.Index(program, `if [ "$ready" != 1 ]`)
	remove := strings.Index(program, "docker stack rm shuttle-edge")
	start := strings.Index(program, "docker start")
	for label, index := range map[string]int{"pull": pull, "stop": stop, "deploy": deploy, "wait": wait, "failure": failure, "remove": remove, "start": start} {
		if index < 0 {
			t.Fatalf("the cutover has no %s step:\n%s", label, program)
		}
	}
	if !(pull < stop && stop < deploy && deploy < wait && wait < failure && failure < remove && remove < start) {
		t.Fatalf("the cutover order is wrong (pull=%d stop=%d deploy=%d wait=%d failure=%d remove=%d start=%d):\n%s", pull, stop, deploy, wait, failure, remove, start, program)
	}
	for _, required := range []string{
		// Named in the plan, confirmed on the host, and the only container
		// this program may touch.
		"incumbent='demo-app-caddy-1'",
		`docker container inspect "$incumbent" >/dev/null`,
		`docker stop --time 20 "$incumbent"`,
		// Healthy means replicated and able to validate its own config, which
		// is the same bar the fresh stage sets.
		`docker service ls --filter name=shuttle-edge_caddy --format '{{.Replicas}}'`,
		"caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile",
		// A task that is still shutting down still owns the port.
		`docker ps -aq --filter label=com.docker.swarm.service.name=shuttle-edge_caddy`,
		`docker start "$incumbent"`,
		"CRITICAL: $incumbent could not be restarted, so nothing is listening on 80/443",
		"exit 1",
		// Resumable exactly like every other stage.
		"if [ ! -f /etc/shuttle/setup.d/50-caddy-direct ]",
		"touch /etc/shuttle/setup.d/50-caddy-direct",
	} {
		if !strings.Contains(program, required) {
			t.Fatalf("the cutover is missing %q:\n%s", required, program)
		}
	}
	if strings.Count(program, "docker stop") != 1 || strings.Count(program, "docker start") != 1 {
		t.Fatalf("the cutover must stop and start exactly one container:\n%s", program)
	}
	if strings.Contains(program, "docker rm ") {
		t.Fatalf("the incumbent is stopped, never removed — restoring it must stay one verb:\n%s", program)
	}

	// With nothing holding the ports there is no incumbent, so neither the
	// stop nor the restore is generated at all rather than generated and
	// skipped: a branch that cannot run cannot run wrong.
	free := setupCaddyCutoverCommand("", caddyImageDefault)
	for _, absent := range []string{"docker stop", "docker start", "incumbent=", "docker stack rm"} {
		if strings.Contains(free, absent) {
			t.Fatalf("with no incumbent the cutover must not contain %q:\n%s", absent, free)
		}
	}
	if !strings.Contains(free, "docker pull") || !strings.Contains(free, "docker stack deploy") {
		t.Fatalf("with no incumbent the edge is still deployed:\n%s", free)
	}
}

func TestRootInfraSweepCaddyStackIsCopiedBeforeVolumeAndPull(t *testing.T) {
	program := setupCaddyCutoverCommand("incumbent", caddyImageDefault)
	copyAt := strings.Index(program, "cp /tmp/shuttle-caddy-stack.yml /etc/shuttle/caddy-stack.yml")
	volumesAt := strings.Index(program, "sh /tmp/shuttle-caddy-volumes.sh")
	pullAt := strings.Index(program, "docker pull")
	if copyAt < 0 || volumesAt < 0 || pullAt < 0 || !(copyAt < volumesAt && volumesAt < pullAt) {
		t.Fatalf("Caddy retained stack must exist before volume preparation and pull (copy=%d volumes=%d pull=%d):\n%s", copyAt, volumesAt, pullAt, program)
	}
}

// The completion report tells the operator what state the incumbent is in and
// how to go back, because a stopped container nobody mentioned is a surprise.
func TestAdoptionReportExplainsHowToRevertTheCutover(t *testing.T) {
	applied := adoptionEdgePlan{Requested: true, Incumbent: "demo-app-caddy-1"}
	report := describeAdoptionRemainingWork(applied, true, false)
	for _, required := range []string{
		"80/443 now belong to the shared edge",
		"demo-app-caddy-1 is stopped, not removed",
		"stopping shuttle-edge first",
		"docker start demo-app-caddy-1",
	} {
		if !strings.Contains(report, required) {
			t.Fatalf("the completion report is missing %q:\n%s", required, report)
		}
	}
	if strings.Contains(describeAdoptionRemainingWork(adoptionEdgePlan{}, true, false), "now belong to the shared edge") {
		t.Fatal("a run that did not cut over must not claim it did")
	}
}

// Every generated program is text, and text is testable as text.
func TestAdoptionCutoverShellPrograms(t *testing.T) {
	for name, program := range map[string]string{
		"cutover-with-incumbent": setupCaddyCutoverCommand("demo-app-caddy-1", caddyImageDefault),
		"cutover-no-incumbent":   setupCaddyCutoverCommand("", caddyImageDefault),
		// A container name is host-controlled text until it is quoted.
		"cutover-hostile-name": setupCaddyCutoverCommand("weird'; rm -rf /", caddyImageDefault),
		"fresh-edge":           setupCaddyCommand(),
	} {
		t.Run(name, func(t *testing.T) {
			command := exec.Command("sh", "-n")
			command.Stdin = strings.NewReader(program)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("generated shell does not parse: %v\n%s\n%s", err, output, program)
			}
		})
	}
	hostile := setupCaddyCutoverCommand("weird'; rm -rf /", caddyImageDefault)
	if strings.Contains(hostile, "; rm -rf /\n") {
		t.Fatalf("a container name must be escaped, not interpolated:\n%s", hostile)
	}
}

// The staging paths the edge assets are uploaded to are cleared before the
// upload, for the same reason the helper's are: /tmp is sticky, and a file left
// there by an earlier run as root cannot be replaced by the adoption user.
func TestAdoptionClaimClearsTheEdgeStagingPaths(t *testing.T) {
	for _, path := range []string{"/tmp/shuttle-Caddyfile", "/tmp/shuttle-caddy-stack.yml", "/tmp/shuttle-edge-entrypoint"} {
		if !strings.Contains(adoptionClaimSource, path) {
			t.Fatalf("the adoption claim does not clear %s:\n%s", path, adoptionClaimSource)
		}
	}
}

// The production survey of 2026-10-12: the only holder is this stack's own
// edge, published through docker-proxy. That is the idempotent redeploy, not a
// foreign listener; a docker-proxy with no published container stays refused.
func TestEdgeCutoverReadsDockerProxyAsTheContainersOwnPublication(t *testing.T) {
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	options := setupOptions{adopt: true, yes: true, cutoverEdge: true}
	own := adoptionSurvey{PortsHeld: []string{
		"443 by published container shuttle-edge_caddy.1.zg5opdunufi3y1pcbegx8bzhc",
		"443/tcp by process docker-proxy",
		"443/udp by process docker-proxy",
		"80 by published container shuttle-edge_caddy.1.zg5opdunufi3y1pcbegx8bzhc",
		"80/tcp by process docker-proxy",
	}}
	plan := resolveAdoptionEdgePlan(identity, own, options, nil, false)
	if plan.Refusal != nil || plan.Incumbent != "" || !plan.applies() {
		t.Fatalf("the stack's own edge behind docker-proxy must redeploy in place, got %+v", plan)
	}
	orphan := adoptionSurvey{PortsHeld: []string{"443/tcp by process docker-proxy"}}
	if plan := resolveAdoptionEdgePlan(identity, orphan, options, nil, false); plan.Refusal == nil {
		t.Fatal("a docker-proxy with no published container on its port must stay refused")
	}
}
