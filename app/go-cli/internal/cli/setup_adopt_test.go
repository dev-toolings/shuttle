package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// setupPreflightSourceBeforeAdoption is the verbatim first-contact preflight as
// it shipped before --adopt existed. Invariant: adding a flag must leave the
// configurations that do not set it byte-identical, and this script is the
// artifact that decides whether a busy host is refused. If a change to
// adoption edits it, this test fails and the change is deliberate.
const setupPreflightSourceBeforeAdoption = `set -eu
. /etc/os-release
printf 'os=%s version=%s\n' "$ID" "$VERSION_ID"
case "$ID:$VERSION_ID" in ubuntu:24.04|debian:13) ;; *) exit 42;; esac
test "$(id -u)" = 0
ssh-keygen -lf /root/.ssh/authorized_keys -E sha256 | awk '{print $2}' | grep -Fx "$1" >/dev/null
if [ ! -f /etc/shuttle/setup-state ] && [ ! -f /etc/shuttle/setup.d/10-base ]; then
  if command -v docker >/dev/null 2>&1 && { [ -n "$(docker ps -aq 2>/dev/null)" ] || [ -n "$(docker service ls -q 2>/dev/null)" ]; }; then exit 43; fi
  if command -v psql >/dev/null 2>&1 && [ -n "$(runuser -u postgres -- psql -Atqc "select datname from pg_database where datistemplate=false and datname <> 'postgres'" 2>/dev/null)" ]; then exit 43; fi
fi
`

func adoptionTestConfig() *config.Config {
	return &config.Config{
		App:     "demo",
		Servers: map[string]config.ServerGroup{"web": {Hosts: []string{"203.0.113.7"}, Port: 22}},
	}
}

// writeOperatorPublicKey produces the one-key file --public-key demands.
func writeOperatorPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gossh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(path, gossh.MarshalAuthorizedKey(key), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func adoptionTestOptions(t *testing.T, target string, adopt bool) setupOptions {
	t.Helper()
	return setupOptions{
		target:          target,
		expectedHostKey: "SHA256:" + strings.Repeat("A", 43),
		publicKeyPath:   writeOperatorPublicKey(t),
		adopt:           adopt,
	}
}

// A new flag must leave every configuration that does not set it exactly where
// it was. These are the two refusals --adopt exists to lift, asserted in the
// shape a caller sees them: the same text, from the same inputs, with the flag
// absent.
func TestSetupWithoutAdoptRefusesBusyHostsAndNonRootExactlyAsBefore(t *testing.T) {
	if setupReadOnlyPreflightSource != setupPreflightSourceBeforeAdoption {
		t.Fatalf("the first-contact preflight moved while adding --adopt:\n%s", setupReadOnlyPreflightSource)
	}
	foreign := interpretSetupPreflight(shuttlessh.Result{Code: 43})
	if foreign == nil || foreign.Error() != "VPS contains foreign Docker or PostgreSQL resources; refusing setup" {
		t.Fatalf("the foreign-resource refusal changed: %v", foreign)
	}
	unsupported := interpretSetupPreflight(shuttlessh.Result{Code: 42, Stdout: "os=ubuntu version=22.04\n"})
	if unsupported == nil || unsupported.Error() != "unsupported VPS OS: os=ubuntu version=22.04" {
		t.Fatalf("the unsupported-OS refusal changed: %v", unsupported)
	}
	if err := interpretSetupPreflight(shuttlessh.Result{Code: 0}); err != nil {
		t.Fatalf("a passing preflight must stay a pass: %v", err)
	}

	_, err := validateSetupIdentity(adoptionTestConfig(), adoptionTestOptions(t, "ops@203.0.113.7:22", false))
	if err == nil || err.Error() != "setup first contact must use --target root@IP[:port]" {
		t.Fatalf("without --adopt a sudo user must be refused with the original message, got %v", err)
	}
	identity, err := validateSetupIdentity(adoptionTestConfig(), adoptionTestOptions(t, "root@203.0.113.7:22", false))
	if err != nil || identity.user != "root" {
		t.Fatalf("root first contact must keep working: user=%q err=%v", identity.user, err)
	}

	flag := newSetupCommand().Flags().Lookup("adopt")
	if flag == nil || flag.DefValue != "false" {
		t.Fatalf("adoption must be opt-in; --adopt default is %v", flag)
	}
}

func TestKnownSetupRootAuthenticationFailurePrintsAdoptionCommand(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("HOME", configHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	trusted := trustedHostIdentity{
		Version: 2, Host: "203.0.113.7", Port: 22,
		HostKeyFingerprint: fingerprint, OperatorKeyFingerprint: "SHA256:" + strings.Repeat("B", 43),
		AllowedSSHUsers: []string{"deploy", "ops"},
	}
	if err := saveTrustedHostIdentity(trusted); err != nil {
		t.Fatal(err)
	}

	cfg := adoptionTestConfig()
	cfg.Setup.OperatorUser = "ops"
	cfg.Setup.OperatorPublicKey = "keys/ops.pub"
	options := setupOptions{
		config:          configFlags{path: "/tmp/project config.json", env: "production"},
		expectedHostKey: fingerprint,
		publicKeyPath:   "/tmp/deploy key.pub",
	}
	identity := setupIdentity{user: "root", host: trusted.Host, port: trusted.Port}
	result := shuttlessh.Result{
		Code:   255,
		Stderr: "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain",
	}
	err := interpretSetupPreflightForHost(result, cfg, identity, options)
	if err == nil {
		t.Fatal("the root authentication failure must explain how to adopt this known host")
	}
	want := "this host was already set up by Shuttle, which intentionally closes root SSH access. Use the configured operator account instead:\n" +
		"  shuttle setup --adopt --config '/tmp/project config.json' --env 'production' --target 'ops@203.0.113.7' --expected-host-key '" + fingerprint + "' --public-key '/tmp/deploy key.pub'"
	if err.Error() != want {
		t.Fatalf("unexpected setup hint:\n got: %s\nwant: %s", err, want)
	}

	nonAuthentication := interpretSetupPreflightForHost(shuttlessh.Result{Code: 1, Stderr: "permission denied by remote preflight"}, cfg, identity, options)
	if nonAuthentication == nil || !strings.Contains(nonAuthentication.Error(), "verified setup preflight failed") {
		t.Fatalf("a remote preflight failure must not be reported as root SSH closure: %v", nonAuthentication)
	}
	unknownHome := t.TempDir()
	t.Setenv("HOME", unknownHome)
	t.Setenv("XDG_CONFIG_HOME", unknownHome)
	unknown := interpretSetupPreflightForHost(result, cfg, identity, setupOptions{publicKeyPath: "/tmp/deploy.pub"})
	if unknown == nil || !strings.Contains(unknown.Error(), "verified setup preflight failed") {
		t.Fatalf("without a trusted host identity, keep the ordinary preflight error: %v", unknown)
	}
}

// Adoption relaxes who connects. It never relaxes which host answers: the
// out-of-band fingerprint stays mandatory, and the login is validated as the
// exact string handed to the SSH client and to the remote survey.
func TestAdoptAcceptsASudoUserButKeepsTheOutOfBandFingerprint(t *testing.T) {
	identity, err := validateSetupIdentity(adoptionTestConfig(), adoptionTestOptions(t, "ops@203.0.113.7:22", true))
	if err != nil {
		t.Fatalf("--adopt must accept a sudo user at first contact: %v", err)
	}
	if identity.user != "ops" || identity.host != "203.0.113.7" || identity.port != 22 {
		t.Fatalf("unexpected adopted identity: %+v", identity)
	}
	if got := adoptionEndpoint(identity); got != "ops@203.0.113.7:22" {
		t.Fatalf("adoption endpoint = %q", got)
	}

	withoutKey := adoptionTestOptions(t, "ops@203.0.113.7:22", true)
	withoutKey.expectedHostKey = ""
	if _, err := validateSetupIdentity(adoptionTestConfig(), withoutKey); err == nil || !strings.Contains(err.Error(), "--expected-host-key is required") {
		t.Fatalf("--adopt must still require the out-of-band host fingerprint, got %v", err)
	}

	elsewhere := adoptionTestOptions(t, "ops@198.51.100.9:22", true)
	if _, err := validateSetupIdentity(adoptionTestConfig(), elsewhere); err == nil || !strings.Contains(err.Error(), "must match the literal VPS endpoint") {
		t.Fatalf("--adopt must still refuse a host the configuration does not declare, got %v", err)
	}

	for _, target := range []string{"203.0.113.7:22", "Ops@203.0.113.7:22", "-ops@203.0.113.7:22"} {
		if _, err := validateSetupIdentity(adoptionTestConfig(), adoptionTestOptions(t, target, true)); err == nil {
			t.Fatalf("--adopt accepted an unusable login in %q", target)
		}
	}
}

func TestAdoptionShellProgramsParse(t *testing.T) {
	for name, program := range map[string]string{
		"survey":     adoptionSurveySource,
		"sudo-proof": adoptionSudoProofSource,
		"root-proof": adoptionRootProofSource,
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

// The survey runs as root on a host the operator has not yet decided to change.
// It must read and report, nothing else.
func TestAdoptionSurveyIsReadOnly(t *testing.T) {
	for _, mutation := range []string{"/tmp/", "apt-get", "install ", "docker run", "docker stack deploy", "systemctl start", "systemctl restart", "systemctl enable", "rm ", "touch ", ">/etc", ">/opt"} {
		if strings.Contains(adoptionSurveySource, mutation) {
			t.Fatalf("the adoption survey contains the mutation %q", mutation)
		}
	}
	for _, required := range []string{
		"/opt/shuttle/$app/state.json",
		"exit 44",
		"exit 45",
		"authorized_keys",
		"foreign-container=",
		"legacy-app=",
		"port-held=",
		"satisfied=",
		"pending=",
	} {
		if !strings.Contains(adoptionSurveySource, required) {
			t.Fatalf("the adoption survey is missing %q", required)
		}
	}
}

// Privilege is proven through sudo only when the login needs sudo, and every
// argument crosses the wire escaped; the script itself travels on stdin.
func TestAdoptionSurveyCommandEscapesArgumentsAndElevatesOnlyWhenNeeded(t *testing.T) {
	asOperator := adoptionSurveyCommand("ops", "SHA256:abc", "demo", false)
	if asOperator != "sudo -n sh -s -- 'ops' 'SHA256:abc' 'demo' 0" {
		t.Fatalf("unexpected adoption survey command: %q", asOperator)
	}
	if got := adoptionSurveyCommand("root", "SHA256:abc", "demo", true); got != "sh -s -- 'root' 'SHA256:abc' 'demo' 1" {
		t.Fatalf("root needs no sudo, got %q", got)
	}
	if got := adoptionSurveyCommand("ops", "SHA256:abc", "it's", false); !strings.Contains(got, `'it'"'"'s'`) {
		t.Fatalf("survey arguments must be shell-escaped, got %q", got)
	}
}

// Adoption must prove it is adopting something it installed, and say precisely
// what is missing when it is not.
func TestAdoptionRefusalsNameWhatIsMissing(t *testing.T) {
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22, operatorKeyFingerprint: "SHA256:" + strings.Repeat("A", 43)}

	_, err := interpretAdoptionSurvey(shuttlessh.Result{Code: adoptionExitLegacyMarkerAbsent}, identity, "demo")
	if err == nil || !strings.Contains(err.Error(), "/opt/shuttle/demo/state.json is absent") {
		t.Fatalf("a missing legacy marker must be named exactly, got %v", err)
	}
	_, err = interpretAdoptionSurvey(shuttlessh.Result{Code: adoptionExitKeyNotAuthorized}, identity, "demo")
	if err == nil || !strings.Contains(err.Error(), identity.operatorKeyFingerprint) || !strings.Contains(err.Error(), "not authorized for ops") {
		t.Fatalf("an unauthorized operator key must be named exactly, got %v", err)
	}
	_, err = interpretAdoptionSurvey(shuttlessh.Result{Code: adoptionExitUnsupportedOS, Stdout: "os=ubuntu\nos-version=22.04\n"}, identity, "demo")
	if err == nil || err.Error() != "unsupported VPS OS: os=ubuntu os-version=22.04" {
		t.Fatalf("an unsupported OS must be reported, got %v", err)
	}
	_, err = interpretAdoptionSurvey(shuttlessh.Result{Code: 1, Stderr: "sudo: a password is required\n"}, identity, "demo")
	if err == nil || !strings.Contains(err.Error(), "sudo: a password is required") {
		t.Fatalf("an opaque survey failure must surface its stderr, got %v", err)
	}
}

const adoptionSurveySample = `os=ubuntu
os-version=24.04
legacy-marker=present
live-restore=false
setup-state=absent
foreign-container=legacy-web
shuttle-container=shuttle-registry
foreign-container=legacy-worker
swarm-service=shuttle-edge_caddy
legacy-app=demo
port-held=80/tcp by process nginx
port-held=443/tcp by process nginx
satisfied=20-docker
pending=50-caddy-direct
satisfied=10-base
`

// A survey the CLI cannot fully understand is a survey the operator must not
// read as complete. Unknown keys and out-of-charset values stop the run.
func TestAdoptionSurveyParsesDeterministicallyAndFailsClosed(t *testing.T) {
	survey, err := parseAdoptionSurvey(adoptionSurveySample)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(survey.ForeignContainers, ","); got != "legacy-web,legacy-worker" {
		t.Fatalf("foreign containers are not sorted: %q", got)
	}
	if len(survey.LegacyApps) != 1 || survey.LegacyApps[0] != "demo" {
		t.Fatalf("unexpected legacy applications: %#v", survey.LegacyApps)
	}
	if got := strings.Join(survey.Satisfied, ","); got != "10-base,20-docker" {
		t.Fatalf("satisfied steps are not sorted: %q", got)
	}
	duplicated, err := parseAdoptionSurvey(adoptionSurveySample + "foreign-container=legacy-web\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(duplicated.ForeignContainers, ",") != strings.Join(survey.ForeignContainers, ",") {
		t.Fatalf("a repeated container must not appear twice: %#v", duplicated.ForeignContainers)
	}
	for name, body := range map[string]string{
		"unknown key":   "os=ubuntu\nexec=rm -rf /\n",
		"no separator":  "os=ubuntu\nnot a pair\n",
		"hostile value": "foreign-container=$(id)\n",
	} {
		if _, err := parseAdoptionSurvey(body); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// The plan is the feature: an operator has to be able to read what is on the
// host, what adoption would skip, and what it deliberately does not do.
func TestAdoptionPlanEnumeratesTheHostAndTheWork(t *testing.T) {
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	survey, err := parseAdoptionSurvey(adoptionSurveySample)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	plan := adoptionPlan(identity, "demo", fingerprint, survey, adoptionOptions(), adoptionEdgePlan{}, defaultPublicTCPPorts(t), false)
	for _, required := range []string{
		"Shuttle adoption plan for ops@203.0.113.7:22",
		"/opt/shuttle/demo/state.json found",
		"ubuntu 24.04, attested by " + fingerprint,
		"ops, non-interactive sudo proven",
		"- legacy-web",
		"- legacy-worker",
		"- shuttle-registry",
		"- demo",
		"- 80/tcp by process nginx",
		"- 443/tcp by process nginx",
		"steps observed satisfied by the survey",
		"- 10-base (security baseline, unattended upgrades, swap)",
		"- 20-docker (Docker CE and one-node Swarm)",
		"steps this host still needs",
		"- 50-caddy-direct (shared Caddy edge on 80/443)",
		"not attempted by this run",
		"taking 80/443 from the incumbent listener",
		"migrating the adopted application's PostgreSQL database",
		"read-only",
	} {
		if !strings.Contains(plan, required) {
			t.Fatalf("the adoption plan is missing %q:\n%s", required, plan)
		}
	}
	if plan != adoptionPlan(identity, "demo", fingerprint, survey, adoptionOptions(), adoptionEdgePlan{}, defaultPublicTCPPorts(t), false) {
		t.Fatal("the adoption plan is not deterministic")
	}
	empty := adoptionPlan(identity, "demo", fingerprint, adoptionSurvey{}, adoptionOptions(), adoptionEdgePlan{}, defaultPublicTCPPorts(t), false)
	if !strings.Contains(empty, "- none") {
		t.Fatalf("an empty inventory must say so explicitly:\n%s", empty)
	}
}

func TestConvergedAdoptionOwnsShuttleStacksAndReportsForeignContainers(t *testing.T) {
	for _, required := range []string{
		`{{.Label "com.docker.stack.namespace"}}`,
		`classify_adoption_container "$name" "$owner" "$service" "$namespace" /var/lib/shuttle/apps`,
	} {
		if !strings.Contains(adoptionSurveySource, required) {
			t.Fatalf("the adoption survey is not using stack ownership classification %q", required)
		}
	}
	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "a2zsmoke")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	classifier := adoptionContainerClassificationSource + `
classify_adoption_container 'a2zsmoke_web.1.abc' '' 'a2zsmoke_web' 'a2zsmoke' "$1"
classify_adoption_container 'a2zsmoke_redis.1.def' '' 'a2zsmoke_redis' 'a2zsmoke' "$1"
classify_adoption_container 'a2zsmoke_rabbitmq.1.ghi' '' 'a2zsmoke_rabbitmq' 'a2zsmoke' "$1"
classify_adoption_container 'shuttle-edge_caddy.1.jkl' '' 'shuttle-edge_caddy' 'shuttle-edge' "$1"
classify_adoption_container 'outside-nginx' '' 'outside_nginx' 'outside' "$1"
`
	command := exec.Command("sh", "-c", classifier, "adoption-container-classifier", stateRoot)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("container classifier failed: %v\n%s", err, output)
	}
	wantContainers := "shuttle-container=a2zsmoke_web.1.abc\n" +
		"shuttle-container=a2zsmoke_redis.1.def\n" +
		"shuttle-container=a2zsmoke_rabbitmq.1.ghi\n" +
		"shuttle-container=shuttle-edge_caddy.1.jkl\n" +
		"foreign-container=outside-nginx\n"
	if string(output) != wantContainers {
		t.Fatalf("container ownership report:\n got: %s\nwant: %s", output, wantContainers)
	}

	lines := string(output) + "legacy-marker=absent\nsetup-state=present\nlive-restore=false\nreboot-required=absent\n" +
		"swarm-service=shuttle-edge_caddy\n" +
		"port-held=80 by published container shuttle-edge_caddy.1.jkl\n" +
		"port-held=443 by published container shuttle-edge_caddy.1.jkl\n" +
		"port-held=80/tcp by process docker-proxy\n" +
		"port-held=443/tcp by process docker-proxy\n" +
		"satisfied=10-base\nsatisfied=20-docker\nsatisfied=30-postgres\nsatisfied=40-runtime\nsatisfied=50-caddy-direct\n"
	survey, err := parseAdoptionSurvey(lines)
	if err != nil {
		t.Fatal(err)
	}
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	edge := resolveAdoptionEdgePlan(identity, survey, adoptionOptions(), nil, false)
	if !edge.AlreadyServing || edge.applies() {
		t.Fatalf("the existing Shuttle Caddy must need no takeover: %+v", edge)
	}
	requestedCutover := adoptionOptions()
	requestedCutover.cutoverEdge = true
	requestedEdge := resolveAdoptionEdgePlan(identity, survey, requestedCutover, nil, false)
	if !requestedEdge.AlreadyServing || requestedEdge.applies() || requestedEdge.Incumbent != "" {
		t.Fatalf("--cutover-edge must not take ports back from Shuttle's own Caddy: %+v", requestedEdge)
	}
	plan := adoptionPlan(identity, "a2zsmoke", "SHA256:"+strings.Repeat("A", 43), survey, adoptionOptions(), edge, []int{80, 443}, false)
	for _, required := range []string{
		"already served by Shuttle's Caddy on 80/443; no takeover is needed",
		"foreign containers:\n    - outside-nginx",
		"Shuttle-owned containers:\n    - a2zsmoke_rabbitmq.1.ghi\n    - a2zsmoke_redis.1.def\n    - a2zsmoke_web.1.abc\n    - shuttle-edge_caddy.1.jkl",
	} {
		if !strings.Contains(plan, required) {
			t.Fatalf("the converged adoption plan is missing %q:\n%s", required, plan)
		}
	}
	if strings.Contains(plan, "50-caddy-direct: taking 80/443") || strings.Contains(plan, "still to do, deliberately not part of this run") {
		t.Fatalf("a converged host must not report an edge takeover or remaining work:\n%s", plan)
	}
	report := describeAdoptionRemainingWork(edge, false, false)
	if !strings.Contains(report, "Host is already converged.") || strings.Contains(report, "still to do, deliberately not part of this run") {
		t.Fatalf("the completion report must omit an empty still-to-do section: %s", report)
	}
}

// An adoption that would mutate is refused before the first packet when the
// operator has not confirmed it. Confirmation is the only thing that lifts
// this: what an adoption then applies, and what it still refuses to touch, is
// covered by TestAdoptionRefusesToApplyWithoutConfirmationOrOutsideARebootWindow.
func TestAdoptionRefusesToMutateBeforeContactingTheHost(t *testing.T) {
	var out bytes.Buffer
	options := setupOptions{target: "ops@203.0.113.7:22", expectedHostKey: "SHA256:" + strings.Repeat("A", 43), adopt: true}
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	err := runSetupAdoption(&out, adoptionTestConfig(), identity, options, time.Now())
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("--adopt without --yes must refuse and say so, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("a refused adoption must print no plan, got %q", out.String())
	}
}

// Every fixed /tmp/shuttle-* path uploaded by setup or adoption must be removed
// by the adoption claim: a copy left by an earlier root setup in sticky /tmp
// cannot be replaced by the sudo adoption user (30-10-2026 e2e, VM 246).
func TestAdoptionClaimRemovesEveryStagedUpload(t *testing.T) {
	staged := regexp.MustCompile(`"(/tmp/shuttle-[A-Za-z0-9._-]+)"`)
	seen := map[string]bool{}
	for _, file := range []string{"setup.go", "setup_adopt.go"} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range staged.FindAllStringSubmatch(string(body), -1) {
			seen[match[1]] = true
		}
	}
	if len(seen) < 8 {
		t.Fatalf("expected the staged uploads of setup and adoption, found %v", seen)
	}
	removed := map[string]bool{}
	for _, line := range strings.Split(adoptionClaimSource, "\n") {
		if strings.HasPrefix(line, "rm -f ") {
			for _, path := range strings.Fields(strings.TrimPrefix(line, "rm -f ")) {
				removed[path] = true
			}
		}
	}
	for path := range seen {
		if !removed[path] {
			t.Errorf("staged upload %s is not removed by adoptionClaimSource", path)
		}
	}
}
