package readiness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func TestPostgresHBAViolationsAcceptsPrivateRanges(t *testing.T) {
	// Verbatim pg_hba_file_rules output from a provisioned VPS: loopback plus
	// two Docker bridges, every host rule authenticated with scram-sha-256.
	raw := strings.Join([]string{
		"local|||peer|",
		"host|127.0.0.1|255.255.255.255|scram-sha-256|",
		"host|::1|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|scram-sha-256|",
		"host|172.17.0.0|255.255.0.0|scram-sha-256|",
		"host|172.18.0.0|255.255.0.0|scram-sha-256|",
	}, "\n")
	if violations := postgresHBAViolations(raw); len(violations) != 0 {
		t.Fatalf("private HBA rules reported as violations: %v", violations)
	}
}

// A catch-all reject rule closes access; demo prod (2026-10-28) was flagged
// as permissive for exactly these lines.
func TestPostgresHBAViolationsIgnoresRejectRules(t *testing.T) {
	raw := strings.Join([]string{
		"host|172.18.0.0|255.255.0.0|scram-sha-256|",
		"host|0.0.0.0|0.0.0.0|reject|",
		"host|::|::|reject|",
		"local|||reject|",
	}, "\n")
	if violations := postgresHBAViolations(raw); len(violations) != 0 {
		t.Fatalf("reject rules reported as violations: %v", violations)
	}
	if violations := postgresHBAViolations(raw + "\nhost|0.0.0.0|0.0.0.0|scram-sha-256|"); len(violations) != 1 {
		t.Fatalf("public scram rule must stay a violation: %v", violations)
	}
}

func TestPostgresHBAViolationsRejectsPublicRules(t *testing.T) {
	cases := map[string]string{
		"world readable trust":   "host|0.0.0.0|0.0.0.0|trust|",
		"world readable scram":   "host|0.0.0.0|0.0.0.0|scram-sha-256|",
		"mask spans public":      "host|172.16.0.0|255.0.0.0|scram-sha-256|",
		"weak auth on private":   "host|192.168.1.0|255.255.255.0|md5|",
		"parse error reported":   "host|172.17.0.0|255.255.0.0|scram-sha-256|invalid connection type",
		"local without peer":     "local|||md5|",
		"cidr world readable":    "host all all 0.0.0.0/0 trust",
		"cidr mask spans public": "host all all 172.16.0.0/8 scram-sha-256",
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if violations := postgresHBAViolations(rule); len(violations) != 1 {
				t.Fatalf("rule %q produced %d violations, want 1", rule, len(violations))
			}
		})
	}
}

func TestPostgresHBAViolationsAcceptsCIDRPrivateRules(t *testing.T) {
	raw := strings.Join([]string{
		"local all postgres peer",
		"host all all 127.0.0.1/32 scram-sha-256",
		"host all all ::1/128 scram-sha-256",
		"host all all 172.17.0.0/16 scram-sha-256",
		"host all all 10.0.0.0/8 scram-sha-256",
	}, "\n")
	if violations := postgresHBAViolations(raw); len(violations) != 0 {
		t.Fatalf("private CIDR rules reported as violations: %v", violations)
	}
}

func TestHBARangeIsPrivate(t *testing.T) {
	private := [][2]string{
		{"127.0.0.1", "255.255.255.255"},
		{"::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"172.17.0.0", "255.255.0.0"},
		{"192.168.0.0", "255.255.0.0"},
		{"10.0.0.0/8", ""},
		{"localhost", ""},
	}
	for _, item := range private {
		if !hbaRangeIsPrivate(item[0], item[1]) {
			t.Errorf("hbaRangeIsPrivate(%q, %q) = false, want true", item[0], item[1])
		}
	}
	public := [][2]string{
		{"0.0.0.0", "0.0.0.0"},
		{"0.0.0.0/0", ""},
		{"::/0", ""},
		{"172.16.0.0", "255.0.0.0"},
		{"8.8.8.8", "255.255.255.255"},
		{"all", ""},
		{"", ""},
	}
	for _, item := range public {
		if hbaRangeIsPrivate(item[0], item[1]) {
			t.Errorf("hbaRangeIsPrivate(%q, %q) = true, want false", item[0], item[1])
		}
	}
}

func TestDockerRunningAsRootUsesResolvedUser(t *testing.T) {
	// The probe pipeline fills the user in from the image config, so the check
	// only sees rows whose user is genuinely empty or root.
	output := "__shuttle_runtime=swarm\n" +
		"caddy_caddy\t\n" +
		"search-demo_postgres\troot\n" +
		"search-demo_web\tnextjs\n" +
		"sample-app_web\tnode\n" +
		"deployshuttle_web\t1000:1000\n"
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: output}
	}}
	got := checkDockerRunningAsRoot(adapter)
	if got.Status != Failed {
		t.Fatalf("expected the two root workloads to fail the check, got %+v", got)
	}
	workloads, ok := evidenceStringSlice(got.Evidence["workloads"])
	if !ok {
		t.Fatalf("expected workload evidence, got %#v", got.Evidence["workloads"])
	}
	if len(workloads) != 2 {
		t.Fatalf("expected exactly the 2 root workloads, got %v", workloads)
	}
	for _, name := range workloads {
		if name == "search-demo_web" || name == "sample-app_web" || name == "deployshuttle_web" {
			t.Fatalf("workload %q runs as a non-root user and must not be reported", name)
		}
	}
}

func TestResolveImageUserPipelineIsValidShell(t *testing.T) {
	command := dockerRuntimeCommand("echo swarm | "+resolveImageUserPipeline, "echo classic | "+resolveImageUserPipeline)
	if output, err := exec.Command("sh", "-n", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("root-user probe shell syntax: %v: %s", err, output)
	}
	if strings.Contains(resolveImageUserPipeline, "docker rm") || strings.Contains(resolveImageUserPipeline, "docker run") {
		t.Fatalf("the root-user probe must stay read-only: %s", resolveImageUserPipeline)
	}
}

func TestDockerClassicChecksUsePortableEmptyInputHandling(t *testing.T) {
	commands := []string{}
	adapter := scriptedAdapter{respond: func(command string) execx.Result {
		commands = append(commands, command)
		return execx.Result{ExitCode: 0, Stdout: "__shuttle_runtime=classic\n"}
	}}
	checkDockerRestartPolicies(adapter)
	checkDockerHealthchecks(adapter)
	checkDockerRunningAsRoot(adapter)
	checkDockerSockExposed(adapter)
	if len(commands) != 4 {
		t.Fatalf("captured %d Docker checks, want 4", len(commands))
	}
	for _, command := range commands {
		if strings.Contains(command, "xargs -r") || !strings.Contains(command, "while IFS= read -r id") {
			t.Fatalf("Docker classic probe is not portable to macOS: %s", command)
		}
		if output, err := exec.Command("sh", "-n", "-c", command).CombinedOutput(); err != nil {
			t.Fatalf("Docker classic probe shell syntax: %v: %s", err, output)
		}
	}
}

// TestResolveImageUserPipelineRunsAgainstStubbedDocker executes the real shell
// pipeline. A row whose user column is empty must keep its name and pick the
// user up from the image, never shift the image into the user column.
func TestResolveImageUserPipelineRunsAgainstStubbedDocker(t *testing.T) {
	dir := t.TempDir()
	stub := "#!/bin/sh\n" +
		"# argv: image inspect --format <template> <ref>\n" +
		"case \"$5\" in\n" +
		"  *search-demo-web*) echo nextjs ;;\n" +
		"  *caddy*) echo \"\" ;;\n" +
		"  *) echo \"\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	rows := "caddy_caddy||caddy:2.10.2\n" +
		"search-demo_web||127.0.0.1:5080/search-demo-web:latest@sha256:abc\n" +
		"deployshuttle_web|1000:1000|deployshuttle-web:tag\n"
	command := "printf '%s' " + shellSingleQuote(rows) + " | " + resolveImageUserPipeline
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pipeline failed: %v: %s", err, output)
	}
	want := "caddy_caddy\t\nsearch-demo_web\tnextjs\ndeployshuttle_web\t1000:1000\n"
	if string(output) != want {
		t.Fatalf("pipeline output\n got: %q\nwant: %q", output, want)
	}
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
