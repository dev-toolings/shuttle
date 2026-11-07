package cli

import (
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func adoptionPrerequisiteFixture(t *testing.T) adoptionSurvey {
	t.Helper()
	listen := base64.StdEncoding.EncodeToString([]byte("127.0.0.1, 172.18.0.1"))
	survey, err := parseAdoptionSurvey("satisfied=20-docker\nsatisfied=30-postgres\nlive-restore=false\nregistry=absent\ngateway=172.18.0.1\ngateway-subnet=172.18.0.0/16\ngateway-mtu=1500-1500\nedge-network=overlay\npostgres-cluster=18-main\npostgres-listen=" + listen + "\n")
	if err != nil {
		t.Fatal(err)
	}
	return survey
}

func TestAdoptionPrerequisiteSurveyAndRefusals(t *testing.T) {
	good := adoptionPrerequisiteFixture(t)
	if err := adoptionPrerequisiteError(good); err != nil {
		t.Fatalf("valid fixture refused: %v", err)
	}
	encoded := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		name, message string
		change        func(*adoptionSurvey)
	}{
		{"live restore", "live-restore", func(s *adoptionSurvey) { s.LiveRestore = "true" }},
		{"edge network", "caddy_network", func(s *adoptionSurvey) { s.EdgeNetwork = "bridge" }},
		{"gateway MTU", "MTU", func(s *adoptionSurvey) { s.GatewayMTU = "1450-1500" }},
		{"missing gateway", "docker_gwbridge", func(s *adoptionSurvey) { s.Gateway = "" }},
		{"missing subnet", "docker_gwbridge", func(s *adoptionSurvey) { s.GatewaySubnet = "" }},
		{"missing cluster", "cluster", func(s *adoptionSurvey) { s.PostgresCluster = "" }},
		{"unreadable listen", "cannot read PostgreSQL listen_addresses", func(s *adoptionSurvey) { s.PostgresListen = encoded("unavailable") }},
		{"gateway not listening", "listen_addresses does not contain", func(s *adoptionSurvey) { s.PostgresListen = encoded("127.0.0.1") }},
		{"foreign script", "backup-script", func(s *adoptionSurvey) { s.PrerequisiteIssues = []string{"backup-script"} }},
		{"foreign service", "backup-service", func(s *adoptionSurvey) { s.PrerequisiteIssues = []string{"backup-service"} }},
		{"foreign timer", "backup-timer", func(s *adoptionSurvey) { s.PrerequisiteIssues = []string{"backup-timer"} }},
		{"foreign boot dropin", "boot-dropin", func(s *adoptionSurvey) { s.PrerequisiteIssues = []string{"boot-dropin"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := good
			tc.change(&s)
			if err := adoptionPrerequisiteError(s); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("got %v, want %q", err, tc.message)
			}
		})
	}
	good.PostgresListen = encoded("*")
	if err := adoptionPrerequisiteError(good); err != nil {
		t.Fatalf("wildcard listener refused: %v", err)
	}
}

func TestAdoptionMissingRegistryIsPlannedAndGeneratedSeparately(t *testing.T) {
	survey := adoptionPrerequisiteFixture(t)
	plan := strings.Join(adoptionAppliedStages(survey, adoptionEdgePlan{}), "\n")
	if !strings.Contains(plan, "21-registry-nonroot") {
		t.Fatal("missing registry is not planned")
	}
	var registry string
	for _, stage := range adoptionSetupStages(adoptionApplyConfig(t), 22, survey) {
		if stage.name == "21-registry-nonroot" {
			registry = stage.command
		}
		if strings.Contains(stage.command, "apt-get install -y docker-ce") {
			t.Fatal("20-docker body was generated")
		}
	}
	if !strings.Contains(registry, "docker run -d --user 10001:10001") || !strings.Contains(registry, "shuttle-registry") {
		t.Fatal("registry creation is missing")
	}
}

func TestAdoptionExistingPostgresNamesOwnedStepsWithoutRestart(t *testing.T) {
	survey := adoptionPrerequisiteFixture(t)
	plan := strings.Join(adoptionAppliedStages(survey, adoptionEdgePlan{}), "\n")
	stages := adoptionSetupStages(adoptionApplyConfig(t), 22, survey)
	for _, name := range []string{"31-postgres-backup-script", "31-postgres-backup-timer", "32-postgres-boot-order"} {
		if !strings.Contains(plan, name) {
			t.Fatalf("plan omits %s", name)
		}
		found := false
		for _, stage := range stages {
			if stage.name == name {
				found = true
				if strings.Contains(stage.command, "systemctl restart postgresql") || strings.Contains(stage.command, "listen_addresses = '") || strings.Contains(stage.command, "pg_hba.conf") {
					t.Fatalf("%s changes PostgreSQL configuration or restarts it", name)
				}
			}
		}
		if !found {
			t.Fatalf("command omits %s", name)
		}
	}
	if !strings.Contains(plan, "next PostgreSQL or host restart") {
		t.Fatal("plan omits deferred boot ordering")
	}
}

func TestAdoptionGeneratedSurveyAndSelectedStagesParseAsShell(t *testing.T) {
	programs := []string{adoptionSurveySource + adoptionOwnedFilesSurvey()}
	fixture := adoptionPrerequisiteFixture(t)
	for _, stage := range adoptionSetupStages(adoptionApplyConfig(t), 22, fixture) {
		programs = append(programs, stage.command)
	}
	fixture.SetupState, fixture.DockerCheckpoint, fixture.EdgeNetwork = "present", "absent", ""
	fixture.Satisfied = []string{"20-docker"}
	for _, stage := range adoptionSetupStages(adoptionApplyConfig(t), 22, fixture) {
		programs = append(programs, stage.command)
	}
	for i, program := range programs {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(program)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("program %d does not parse: %v: %s", i, err, output)
		}
	}
}

func TestAdoptionBackupOwnershipSurveyRefusesForeignFiles(t *testing.T) {
	dir := t.TempDir()
	replacements := strings.NewReplacer(
		"/usr/local/sbin/shuttle-postgres-backup", dir+"/backup",
		"/etc/systemd/system/shuttle-postgres-backup.service", dir+"/backup.service",
		"/etc/systemd/system/shuttle-postgres-backup.timer", dir+"/backup.timer",
		"/etc/systemd/system/postgresql@$cluster.service.d/10-shuttle-after-docker.conf", dir+"/boot.conf",
	)
	program := "set -eu\napp=demo\ncluster=18-main\nhave_postgres() { return 0; }\n" + replacements.Replace(adoptionOwnedFilesSurvey())
	paths := []struct{ name, path, known string }{
		{"backup-script", dir + "/backup", postgresBackupScript},
		{"backup-service", dir + "/backup.service", strings.ReplaceAll(adoptionBackupService, "/usr/local/sbin/shuttle-postgres-backup", dir+"/backup")},
		{"backup-timer", dir + "/backup.timer", adoptionBackupTimer},
		{"boot-dropin", dir + "/boot.conf", adoptionBootDropin},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(tc.path, []byte("foreign\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", program)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("survey: %v %s", err, out)
			}
			if !strings.Contains(string(out), "prerequisite-issue="+tc.name) {
				t.Fatalf("foreign file accepted: %s", out)
			}
			if err := os.WriteFile(tc.path, []byte(tc.known), 0600); err != nil {
				t.Fatal(err)
			}
			cmd = exec.Command("sh", "-c", program)
			out, err = cmd.CombinedOutput()
			if err != nil || strings.Contains(string(out), "prerequisite-issue="+tc.name) {
				t.Fatalf("known file refused: %v %s", err, out)
			}
		})
	}
}

func TestAdoptionPlanAndGeneratedStagesHaveTheSameOrder(t *testing.T) {
	survey := adoptionPrerequisiteFixture(t)
	plan := strings.Join(adoptionAppliedStages(survey, adoptionEdgePlan{}), "\n")
	stages := adoptionSetupStages(adoptionApplyConfig(t), 22, survey)
	want := []string{"helper-safety", "base", "21-registry-nonroot", "31-postgres-backup-script", "31-postgres-backup-timer", "32-postgres-boot-order", "runtime"}
	var names []string
	for _, stage := range stages {
		names = append(names, stage.name)
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("generated stage order = %v", names)
	}
	previous := -1
	for _, name := range []string{"10-base", "20-docker", "21-registry-nonroot", "30-postgres", "31-postgres-backup-script", "31-postgres-backup-timer", "32-postgres-boot-order", "40-runtime"} {
		index := strings.Index(plan, name)
		if index <= previous {
			t.Fatalf("plan is missing or misorders %s:\n%s", name, plan)
		}
		previous = index
	}
	if !strings.Contains(plan, "20-docker (Docker CE and one-node Swarm), already satisfied so adoption skips its body") || !strings.Contains(plan, "30-postgres (PostgreSQL on loopback and the Docker gateway), already satisfied so adoption skips its body") {
		t.Fatal("plan does not identify both skipped bodies")
	}
}

func TestAdoptionRegistryStartsOwnedStoppedContainerAndWaitsForReadiness(t *testing.T) {
	var script string
	for _, stage := range adoptionSetupStages(adoptionApplyConfig(t), 22, adoptionPrerequisiteFixture(t)) {
		if stage.name == "21-registry-nonroot" {
			script = stage.command
		}
	}
	for _, required := range []string{"docker start shuttle-registry", "{{.State.Running}}", "{{.State.Health.Status}}", "http://127.0.0.1:5000/v2/", `{{index .Config.Labels "dev.shuttle.owner"}}`} {
		if !strings.Contains(script, required) {
			t.Fatalf("registry stage lacks %q", required)
		}
	}
}

func TestAdoptionResumesClaimedHostBeforeCaddyNetworkCheckpoint(t *testing.T) {
	s := adoptionPrerequisiteFixture(t)
	s.SetupState = "present"
	s.DockerCheckpoint = "absent"
	s.EdgeNetwork = ""
	if err := adoptionPrerequisiteError(s); err != nil {
		t.Fatalf("claimed incomplete setup should create the missing network: %v", err)
	}
	plan := strings.Join(adoptionAppliedStages(s, adoptionEdgePlan{}), "\n")
	if !strings.Contains(plan, "20-caddy-network") {
		t.Fatal("network creation missing from plan")
	}
	found := false
	for _, stage := range adoptionSetupStages(adoptionApplyConfig(t), 22, s) {
		if stage.name == "20-caddy-network" && strings.Contains(stage.command, "docker network create --driver overlay --attachable caddy_network") {
			found = true
		}
	}
	if !found {
		t.Fatal("network creation command missing")
	}
	s.DockerCheckpoint = "present"
	if err := adoptionPrerequisiteError(s); err == nil {
		t.Fatal("completed checkpoint must not authorize network recreation")
	}
	s.DockerCheckpoint = "absent"
	s.SetupState = "absent"
	if err := adoptionPrerequisiteError(s); err == nil {
		t.Fatal("unclaimed host must not authorize network creation")
	}
}

func TestAdoptionRefusesForeignPostgresRetentionFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/demo.conf", []byte("foreign policy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	program := "set -eu\napp=demo\ncluster=18-main\nhave_postgres() { return 0; }\n" + strings.ReplaceAll(adoptionOwnedFilesSurvey(), "/etc/shuttle/postgres-backup.d", dir)
	cmd := exec.Command("sh", "-c", program)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("survey: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "prerequisite-issue=backup-retention") {
		t.Fatalf("foreign retention was accepted: %s", out)
	}
	if err := os.WriteFile(dir+"/demo.conf", []byte("keep=7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("sh", "-c", program)
	out, err = cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "prerequisite-issue=backup-retention") {
		t.Fatalf("matching retention refused: %v %s", err, out)
	}
	for _, stage := range adoptionSetupStages(adoptionApplyConfig(t), 22, adoptionPrerequisiteFixture(t)) {
		if stage.name == "31-postgres-backup-script" && (!strings.Contains(stage.command, "foreign PostgreSQL retention configuration") || strings.Count(stage.command, "retention_owned ") < 2) {
			t.Fatal("retention write is not guarded")
		}
	}
}

func TestAdoptionChecksRetentionEvenWhenPostgresIsNotRunning(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/demo.conf", []byte("foreign\n"), 0600); err != nil {
		t.Fatal(err)
	}
	program := "set -eu\napp=demo\ncluster=\nhave_postgres() { return 1; }\n" + strings.ReplaceAll(adoptionOwnedFilesSurvey(), "/etc/shuttle/postgres-backup.d", dir)
	cmd := exec.Command("sh", "-c", program)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("survey: %v %s", err, out)
	}
	if !strings.Contains(string(out), "prerequisite-issue=backup-retention") {
		t.Fatalf("foreign file was ignored while PostgreSQL is stopped: %s", out)
	}
	s := adoptionPrerequisiteFixture(t)
	s.Satisfied = []string{"20-docker"}
	for _, stage := range adoptionSetupStages(adoptionApplyConfig(t), 22, s) {
		if stage.name == "postgres" && !strings.Contains(stage.command, "foreign PostgreSQL retention configuration") {
			t.Fatal("pending PostgreSQL stage has no retention guard")
		}
	}
}

func TestAdoptionRegistryStageHandlesStoppedForeignAndUnhealthyContainers(t *testing.T) {
	dir := t.TempDir()
	state := dir + "/state"
	docker := `#!/bin/sh
case "$*" in
  *'.Config.Labels'*) printf '%s\n' "$FAKE_OWNER" ;;
  *'.Config.User'*) echo 10001:10001 ;;
  *'.Config.Image'*) echo 'registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
  *'.Mounts'*) echo volume:shuttle-registry ;;
  *'.State.Running'*) cat "$FAKE_STATE" ;;
  *'.State.Health.Status'*) printf '%s\n' "$FAKE_HEALTH" ;;
  'start shuttle-registry') echo true >"$FAKE_STATE" ;;
  *) : ;;
esac
`
	for name, body := range map[string]string{"docker": docker, "curl": "#!/bin/sh\nexit 0\n", "sleep": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(dir+"/"+name, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := adoptionApplyConfig(t)
	cfg.ResolvedInfrastructure = map[string]string{"registry": "registry:3@sha256:" + strings.Repeat("a", 64)}
	var program string
	for _, stage := range adoptionSetupStages(cfg, 22, adoptionPrerequisiteFixture(t)) {
		if stage.name == "21-registry-nonroot" {
			program = stage.command
		}
	}
	for _, tc := range []struct {
		name, owner, health string
		wantOK, wantStarted bool
	}{{"stopped", "system", "healthy", true, true}, {"foreign", "other", "healthy", false, false}, {"unhealthy", "system", "unhealthy", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(state, []byte("false\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", program)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_OWNER="+tc.owner, "FAKE_HEALTH="+tc.health, "FAKE_STATE="+state)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("result %v: %s", err, out)
			}
			got, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			if (strings.TrimSpace(string(got)) == "true") != tc.wantStarted {
				t.Fatalf("running state = %q", got)
			}
		})
	}
}

func TestAdoptionUpdatesValidRetentionWithoutOverwritingForeignFiles(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/demo.conf"
	if err := os.WriteFile(path, []byte("keep=7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	surveyScript := "set -eu\napp=demo\ncluster=18-main\nhave_postgres() { return 0; }\n" + strings.ReplaceAll(adoptionOwnedFilesSurvey(3), "/etc/shuttle/postgres-backup.d", dir)
	cmd := exec.Command("sh", "-c", surveyScript)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "prerequisite-issue=backup-retention") {
		t.Fatalf("valid previous retention refused: %v %s", err, out)
	}
	survey, err := parseAdoptionSurvey(string(out))
	if err != nil {
		t.Fatal(err)
	}
	plan := adoptionPlan(setupIdentity{}, "demo", "fingerprint", survey, setupOptions{}, adoptionEdgePlan{}, nil, false, 3)
	if !strings.Contains(plan, "PostgreSQL backup retention: 7 -> 3 backups") {
		t.Fatalf("plan omitted retention change: %s", plan)
	}
	cfg := adoptionApplyConfig(t)
	cfg.Retention.Backups = 3
	var program string
	for _, stage := range adoptionSetupStages(cfg, 22, adoptionPrerequisiteFixture(t)) {
		if stage.name == "31-postgres-backup-script" {
			program = stage.command
		}
	}
	program = strings.NewReplacer("/etc/shuttle/postgres-backup.d", dir, "/usr/local/sbin/shuttle-postgres-backup", dir+"/backup", "/var/backups/shuttle-postgres", dir+"/backups").Replace(program)
	bin := dir + "/bin"
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"install": "#!/bin/sh\nlast=\nfor arg do last=$arg; done\ncase \"$1\" in -d) mkdir -p \"$last\" ;; *) cp /dev/null \"$last\" ;; esac\n", "chown": "#!/bin/sh\nexit 0\n", "chmod": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(bin+"/"+name, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	run := func() error {
		cmd := exec.Command("sh", "-c", program)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("stage: %s", out)
		}
		return err
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "keep=3\n" {
		t.Fatalf("retention = %q, %v", value, err)
	}
	if err := os.WriteFile(path, []byte("foreign\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("foreign retention was overwritten")
	}
	value, _ = os.ReadFile(path)
	if string(value) != "foreign\n" {
		t.Fatalf("foreign content changed: %q", value)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := dir + "/external"
	if err := os.WriteFile(target, []byte("keep=7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("retention symlink was accepted")
	}
	value, _ = os.ReadFile(target)
	if string(value) != "keep=7\n" {
		t.Fatalf("symlink target changed: %q", value)
	}
}
