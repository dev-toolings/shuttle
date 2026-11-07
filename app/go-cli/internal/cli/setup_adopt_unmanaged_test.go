package cli

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// ── --unmanaged: claiming a host Shuttle never installed ────────────────────

// The gate moves from "the marker exists" to "the marker exists, or this
// generation already claimed the host, or the operator said --unmanaged". It is
// decided on the host, from what is on the host, and the refusal text for the
// default case does not move a character.
func TestUnmanagedSurveyGateAndReporting(t *testing.T) {
	for _, required := range []string{
		"unmanaged=$4",
		"legacy-marker=present",
		"legacy-marker=absent",
		`if [ ! -f "/opt/shuttle/$app/state.json" ] && [ ! -f /etc/shuttle/setup-state ] && [ "$unmanaged" != 1 ]; then`,
		"live-restore=%s",
		"live-restore=unknown",
		"{{.LiveRestoreEnabled}}",
		"published-bind=",
		"incumbent-restart=%s %s",
		"{{.HostConfig.RestartPolicy.Name}}",
	} {
		if !strings.Contains(adoptionSurveySource, required) {
			t.Fatalf("the adoption survey is missing %q", required)
		}
	}
	if strings.Contains(adoptionSurveySource, "published-port=") {
		t.Fatal("the adoption survey must retain the bind address with each published port")
	}
	// The marker verdict is printed before the gate can fire, so a refused
	// survey and an accepted one report it the same way.
	if strings.Index(adoptionSurveySource, "legacy-marker=present") > strings.Index(adoptionSurveySource, "exit 44") {
		t.Fatal("the legacy marker must be reported before the gate")
	}
	if strings.Index(adoptionSurveySource, "setup-state=present") > strings.Index(adoptionSurveySource, "exit 44") {
		t.Fatal("the setup state must be probed before the gate reads it")
	}

	identity := setupIdentity{user: "alice", host: "203.0.113.3", port: 22}
	_, err := interpretAdoptionSurvey(shuttlessh.Result{Code: adoptionExitLegacyMarkerAbsent}, identity, "demo")
	if err == nil || err.Error() != "refusing to adopt alice@203.0.113.3:22: /opt/shuttle/demo/state.json is absent, so this host holds no previous-generation Shuttle deployment of \"demo\". Adoption converges a host Shuttle already installed; it never claims an unrelated machine" {
		t.Fatalf("the default refusal moved: %v", err)
	}
}

func TestUnmanagedSurveyKeysParseAndFailClosed(t *testing.T) {
	survey, err := parseAdoptionSurvey("legacy-marker=absent\nlive-restore=true\nsetup-state=absent\npublished-port=8001\npublished-port=80\npublished-port=3000\npublished-port=80\nincumbent-restart=demo-web-1 unless-stopped\nincumbent-restart=bare \nport-held=80 by published container demo-web-1\n")
	if err != nil {
		t.Fatal(err)
	}
	if survey.LegacyMarker != "absent" || survey.LiveRestore != "true" {
		t.Fatalf("verdicts not parsed: %+v", survey)
	}
	if got := survey.PublishedPorts; len(got) != 3 || got[0] != 80 || got[1] != 3000 || got[2] != 8001 {
		t.Fatalf("published ports must be numeric, sorted and deduplicated, got %v", got)
	}
	if survey.ContainerRestart["demo-web-1"] != "unless-stopped" {
		t.Fatalf("restart policy not parsed: %v", survey.ContainerRestart)
	}
	// A container with no policy set reports an empty name; Docker's own
	// default for it is "no", and that is what the cutover must restore.
	if survey.ContainerRestart["bare"] != "no" {
		t.Fatalf("an unset restart policy must read as no, got %q", survey.ContainerRestart["bare"])
	}
	for name, body := range map[string]string{
		"marker":     "legacy-marker=maybe\n",
		"live":       "live-restore=yes\n",
		"port text":  "published-port=http\n",
		"port range": "published-port=70000\n",
		"port zero":  "published-port=0\n",
	} {
		if _, err := parseAdoptionSurvey(body); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}

	// Closed ports: what is published today minus SSH and the declared public
	// ports, in ascending order, as strings the plan prints.
	closed := adoptionClosedPorts(adoptionSurvey{PublishedPorts: []int{80, 3000, 5433, 8001, 22, 443}}, 22, []int{80, 443})
	if got := strings.Join(closed, ","); got != "3000,5433,8001" {
		t.Fatalf("closed ports = %q", got)
	}
}

func TestAdoptionSurveyPublishedBindsExcludeLoopback(t *testing.T) {
	survey, err := parseAdoptionSurvey("published-bind=127.0.0.1:5000\npublished-bind=[::1]:6000\npublished-bind=0.0.0.0:80\npublished-bind=[::]:80\npublished-bind=10.0.0.5:8080\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := survey.PublishedPorts; len(got) != 2 || got[0] != 80 || got[1] != 8080 {
		t.Fatalf("published ports must exclude loopback binds, be sorted and deduplicated, got %v", got)
	}
}

func TestAdoptionSurveyRejectsInvalidPublishedBinds(t *testing.T) {
	for _, value := range []string{"nohostport", "0.0.0.0:70000"} {
		if _, err := parseAdoptionSurvey("published-bind=" + value + "\n"); err == nil {
			t.Fatalf("published bind %q must be refused", value)
		}
	}
}

// The plan is written from the survey, never from the flag: the same options
// against two hosts describe two different runs.
func TestUnmanagedPlanSaysWhatClaimingChanges(t *testing.T) {
	identity := setupIdentity{user: "alice", host: "203.0.113.3", port: 22}
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	options := adoptionOptions()
	options.unmanaged = true
	options.cutoverEdge = true
	options.retained = []string{"bob"}

	survey, err := parseAdoptionSurvey("os=ubuntu\nos-version=24.04\nlegacy-marker=absent\nlive-restore=true\nsetup-state=absent\nreboot-required=absent\nforeign-container=demo-api-1\nforeign-container=demo-web-1\npublished-port=80\npublished-port=3000\npublished-port=8001\npublished-port=5433\nport-held=80 by published container demo-web-1\nport-held=80/tcp by process docker-proxy\nincumbent-restart=demo-web-1 unless-stopped\npending=10-base\npending=20-docker\npending=30-postgres\npending=40-runtime\npending=50-caddy-direct\n")
	if err != nil {
		t.Fatal(err)
	}
	edge := resolveAdoptionEdgePlan(identity, survey, options, nil, false)
	if edge.Refusal != nil || edge.Incumbent != "demo-web-1" || edge.IncumbentRestart != "unless-stopped" {
		t.Fatalf("unexpected edge plan: %+v", edge)
	}
	plan := adoptionPlan(identity, "demo", fingerprint, survey, options, edge, []int{80, 443}, false)
	for _, required := range []string{
		"application       demo (never set up by Shuttle: no /opt/shuttle/demo/state.json; --unmanaged claims it)",
		"live-restore      enabled; 20-docker turns it off in /etc/docker/daemon.json",
		"no container restarts now; afterwards a dockerd restart or the deferred reboot restarts every container",
		"demo-web-1 (restart policy unless-stopped) is stopped and set to restart: no",
		"until the first `shuttle deploy`, the edge serves no site on those ports",
		"ports published today that 40-runtime closes (declare them in access.allowed_public_tcp_ports to keep them):\n    - 3000\n    - 5433\n    - 8001\n",
		"30-postgres installs a PostgreSQL server on this host whether or not the application uses one",
		"signs AllowUsers alice bob deploy",
		"- demo-api-1",
	} {
		if !strings.Contains(plan, required) {
			t.Fatalf("the unmanaged plan is missing %q:\n%s", required, plan)
		}
	}
	if strings.Contains(plan, "migrating the adopted application's PostgreSQL database") {
		t.Fatalf("a host Shuttle never installed has no adopted database to migrate:\n%s", plan)
	}
	if plan != adoptionPlan(identity, "demo", fingerprint, survey, options, edge, []int{80, 443}, false) {
		t.Fatal("the unmanaged plan is not deterministic")
	}

	// The same flag against a host the previous generation installed is a
	// convergence, and says so.
	legacy, err := parseAdoptionSurvey("legacy-marker=present\nlive-restore=false\nsetup-state=absent\n")
	if err != nil {
		t.Fatal(err)
	}
	converge := adoptionPlan(identity, "demo", fingerprint, legacy, options, adoptionEdgePlan{}, []int{80, 443}, false)
	for _, required := range []string{
		"application       demo (marker /opt/shuttle/demo/state.json found)",
		"live-restore      off, as Swarm requires",
		"migrating the adopted application's PostgreSQL database",
	} {
		if !strings.Contains(converge, required) {
			t.Fatalf("the legacy plan is missing %q:\n%s", required, converge)
		}
	}
	// A claim interrupted after its first stage resumes without the flag, and
	// the plan says which of the two it is doing.
	resumed, err := parseAdoptionSurvey("legacy-marker=absent\nlive-restore=false\nsetup-state=present\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := describeAdoptionApplication("demo", resumed); !strings.Contains(got, "already claimed the host, resuming") {
		t.Fatalf("a claimed host must be described as resuming, got %q", got)
	}
	if got := describeAdoptionApplication("demo", adoptionSurvey{}); !strings.Contains(got, "not reported by the survey") {
		t.Fatalf("a survey silent on the marker must not be read as either verdict, got %q", got)
	}

	// The completion report restates the revert recipe with the policy to put
	// back, and drops the database line on a host that has no adopted one.
	report := describeAdoptionRemainingWork(edge, false, false)
	for _, required := range []string{
		"demo-web-1 is stopped, not removed, and set to restart: no",
		"`docker update --restart unless-stopped demo-web-1`",
		"`docker start demo-web-1`",
	} {
		if !strings.Contains(report, required) {
			t.Fatalf("the completion report is missing %q:\n%s", required, report)
		}
	}
	if strings.Contains(report, "PostgreSQL database") {
		t.Fatalf("no adopted database on an unmanaged host:\n%s", report)
	}
}

func TestUnmanagedFlagIsAdoptionOnly(t *testing.T) {
	flag := newSetupCommand().Flags().Lookup("unmanaged")
	if flag == nil || flag.DefValue != "false" || !strings.Contains(flag.Usage, "no Shuttle generation ever set up") {
		t.Fatalf("--unmanaged must exist, default to false and say what it claims: %v", flag)
	}
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
			"--dry-run", "--unmanaged",
		})
		err := cmd.Execute()
		if err == nil || err.Error() != "--unmanaged only applies to --adopt; a fresh setup already expects a host nothing has set up, and refuses one that is in service" {
			t.Fatalf("--unmanaged without --adopt must be refused with the reason, got %v", err)
		}
	})
}

// ── 20-docker on an adopted host ────────────────────────────────────────────

// The fresh stage is pinned by its golden file; this is the adopted one, which
// must turn live-restore off with the file's other keys intact, prove it did
// before `swarm init`, and name the address it advertises.
func TestAdoptedDockerStageTurnsLiveRestoreOffBeforeSwarmInit(t *testing.T) {
	adopted := setupDockerCommand(setupModeAdoption)
	fresh := setupDockerCommand(setupModeFresh)
	for _, required := range []string{
		"daemon_json=/etc/docker/daemon.json",
		`jq -e . "$daemon_json"`,
		`is not valid JSON; it was written by hand, so fix it by hand`,
		`cp -p "$daemon_json" "$daemon_json.shuttle-previous"`,
		`jq '.["live-restore"] = false' "$daemon_json" >"$daemon_json.shuttle-next"`,
		`mv -f "$daemon_json.shuttle-next" "$daemon_json"`,
		"systemctl reload docker",
		`if [ "$(docker info --format '{{.LiveRestoreEnabled}}')" != false ]; then`,
		`advertise_if=$(ip -o -4 route show default | awk '{print $5; exit}')`,
		`docker swarm init --advertise-addr "$advertise"`,
		`test "$(docker info --format '{{.LiveRestoreEnabled}}')" = false`,
	} {
		if !strings.Contains(adopted, required) {
			t.Fatalf("the adopted docker stage is missing %q:\n%s", required, adopted)
		}
		if strings.Contains(fresh, required) {
			t.Fatalf("the fresh docker stage must not contain %q:\n%s", required, fresh)
		}
	}
	// Still the same checkpoint: a resumed adoption does not edit daemon.json
	// a second time.
	if !strings.Contains(adopted, "if [ ! -f /etc/shuttle/setup.d/20-docker ]") {
		t.Fatal("the adopted docker stage must stay under its checkpoint")
	}
	if strings.Contains(adopted, "systemctl restart docker") {
		t.Fatal("live-restore is reloadable; a restart would stop every container on a host in service")
	}
	if strings.Index(adopted, "systemctl reload docker") > strings.Index(adopted, "docker swarm init") {
		t.Fatal("live-restore must be off before swarm init, not after")
	}
	if !strings.Contains(fresh, "|| docker swarm init\n") {
		t.Fatalf("the fresh stage must keep its bare swarm init:\n%s", fresh)
	}

	// jq travels with the baseline on an adopted host only.
	if !strings.Contains(setupBaseCommand(setupModeAdoption), "systemd-timesyncd jq\n") {
		t.Fatalf("the adopted baseline must install jq:\n%s", setupBaseCommand(setupModeAdoption))
	}
	if strings.Contains(setupBaseCommand(setupModeFresh), "jq") {
		t.Fatal("the fresh baseline must not change")
	}

	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(adopted)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("adopted docker stage does not parse: %v\n%s", err, output)
	}
}

// ── the cutover and the incumbent's restart policy ──────────────────────────

func TestEdgeCutoverNeutralisesAndRestoresTheIncumbentRestartPolicy(t *testing.T) {
	program := setupCaddyCutoverCommand("demo-web-1", caddyImageDefault)
	read := strings.Index(program, `incumbent_restart=$(docker container inspect "$incumbent" --format '{{.HostConfig.RestartPolicy.Name}}')`)
	stop := strings.Index(program, `docker stop --time 20 "$incumbent"`)
	neutralise := strings.Index(program, `docker update --restart no "$incumbent"`)
	restore := strings.Index(program, `docker update --restart "$incumbent_restart" "$incumbent"`)
	start := strings.Index(program, `docker start "$incumbent"`)
	for label, index := range map[string]int{"read": read, "stop": stop, "neutralise": neutralise, "restore": restore, "start": start} {
		if index < 0 {
			t.Fatalf("the cutover has no %s step:\n%s", label, program)
		}
	}
	if !(read < stop && stop < neutralise && neutralise < restore && restore < start) {
		t.Fatalf("the cutover must read the policy, stop, set no, and restore before starting again (read=%d stop=%d neutralise=%d restore=%d start=%d)", read, stop, neutralise, restore, start)
	}
	if !strings.Contains(program, `[ -n "$incumbent_restart" ] || incumbent_restart=no`) {
		t.Fatal("an unset policy must be restored as no, which is what Docker meant by it")
	}
	if strings.Contains(setupCaddyCutoverCommand("", caddyImageDefault), "docker update") {
		t.Fatal("with no incumbent there is no policy to touch")
	}
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(program)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cutover does not parse: %v\n%s", err, output)
	}
}

// The prerequisite an operator meets first on a host that never ran Shuttle,
// with the one line that resolves it.
func TestAdoptionSudoRefusalNamesTheSudoersLine(t *testing.T) {
	identity := setupIdentity{user: "alice", host: "203.0.113.3", port: 22}
	err := interpretAdoptionSudoProof(shuttlessh.Result{Code: adoptionExitNoPasswordlessSudo}, identity)
	if err == nil || !strings.Contains(err.Error(), "'alice ALL=(ALL:ALL) NOPASSWD: ALL' >/etc/sudoers.d/90-alice") {
		t.Fatalf("the sudo refusal must give the sudoers line to write, got %v", err)
	}
}
