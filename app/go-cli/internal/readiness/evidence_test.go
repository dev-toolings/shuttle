package readiness

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func TestUnavailableCollectionNeverPasses(t *testing.T) {
	for _, code := range []int{1, 124, 127} {
		adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: code} }}
		report := RunWithConfig(adapter, "test", []string{"all"}, EmptyConfig(), "")
		if report.Validated || report.Level == "production-ready" {
			t.Fatal("unavailable host was certified")
		}
		for _, check := range report.Checks {
			if check.Status == Passed {
				t.Errorf("exit %d: %s passed without evidence", code, check.ID)
			}
			if check.Status == Skipped && check.SkipReason == "" {
				t.Errorf("%s: missing reason", check.ID)
			}
		}
	}
}

func TestEvidenceVerdictRequiresCompleteApplicableChecks(t *testing.T) {
	for _, check := range []CheckResult{
		{Status: Failed, Severity: High}, {Status: Skipped, Severity: Critical},
		{Status: Unknown}, {Status: Passed, Ignored: true},
	} {
		checks := []CheckResult{{Status: Passed}, check}
		if ChecksValidated(checks) || EvidenceLevel(checks) == "production-ready" {
			t.Fatalf("certified %+v", check)
		}
	}
	checks := []CheckResult{{Status: Passed}, {Status: Skipped, SkipReason: NotApplicable}}
	if !ChecksValidated(checks) {
		t.Fatal("proven inapplicability must not block")
	}
	if ChecksValidated(nil) {
		t.Fatal("empty audit must not validate")
	}
}

func TestMalformedEvidenceAndSpecificPublicListeners(t *testing.T) {
	a := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{Stdout: "broken output"} }}
	for _, check := range []Check{checkDiskSpace, checkDatabasePorts, checkCaddyAdminExposed, checkRebootRequired, checkResolvedLinkLocalProtocols} {
		if result := check(a); result.Status != Skipped {
			t.Errorf("%s accepted malformed evidence: %s", result.ID, result.Status)
		}
	}
	for _, host := range []string{"203.0.113.10", "[2001:db8::10]", "0.0.0.0", "[::]"} {
		if len(publicDatabaseListeners("LISTEN 0 128 "+host+":5432 *:*")) != 1 {
			t.Errorf("missed public bind %s", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "[::1]", "172.18.0.1"} {
		if len(publicDatabaseListeners("LISTEN 0 128 "+host+":5432 *:*")) != 0 {
			t.Errorf("private bind %s reported public", host)
		}
	}
}

func TestUnavailableEvidenceRemainsVisible(t *testing.T) {
	report := Report{Score: 100, Checks: []CheckResult{{Status: Skipped, Severity: High, Title: "collection unavailable"}}}
	output := ConsoleWithOptions(report, false, false)
	if !strings.Contains(output, "collection unavailable") || strings.Contains(output, "- Production Ready") {
		t.Fatal(output)
	}
}

func TestOptionalFallbackSuppliesCompleteEvidence(t *testing.T) {
	a := scriptedAdapter{respond: func(command string) execx.Result {
		if strings.Contains(command, "command -v systemctl") || strings.Contains(command, "is-active chrony") {
			return execx.Result{}
		}
		return execx.Result{ExitCode: 3}
	}}
	if got := evaluateCheck(a, checkTimeSync); got.Status != Passed {
		t.Fatalf("working chrony fallback rejected: %+v", got)
	}
	a = scriptedAdapter{respond: func(command string) execx.Result {
		switch {
		case strings.Contains(command, "command -v dig"):
			return execx.Result{}
		case strings.Contains(command, "@1.1.1.1"), strings.Contains(command, "ipify"):
			return execx.Result{Stdout: "203.0.113.10"}
		default:
			return execx.Result{ExitCode: 9}
		}
	}}
	if got := evaluateCheck(a, checkDNSPointsToServer("example.com")); got.Status != Passed {
		t.Fatalf("working DNS fallback rejected: %+v", got)
	}
}

func TestDockerEvidenceParsersRejectIncompleteRows(t *testing.T) {
	for _, body := range []string{"broken", "__shuttle_runtime=unknown\n", "__shuttle_runtime=classic\ncontainer broken\n"} {
		a := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{Stdout: body} }}
		for _, check := range []Check{checkDockerRestartPolicies, checkDockerHealthchecks, checkDockerRunningAsRoot, checkDockerSockExposed} {
			if got := check(a); got.Status != Skipped || got.SkipReason != EvidenceUnavailable {
				t.Errorf("%s accepted %q: %+v", got.ID, body, got)
			}
		}
	}
}

func TestDockerRuntimePoliciesInspectEffectiveFields(t *testing.T) {
	a := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{Stdout: "__shuttle_runtime=classic\nweb\t0:1000\n"} }}
	if got := checkDockerRunningAsRoot(a); got.Status != Failed {
		t.Fatalf("UID 0 with non-root group passed: %+v", got)
	}
	a = scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{Stdout: "__shuttle_runtime=classic\nweb\t[{\"Source\":\"/data\",\"RW\":false},{\"Source\":\"/run/docker.sock\",\"RW\":true}]\n"}
	}}
	if got := checkDockerSockExposed(a); got.Status != Failed || got.Severity != Critical {
		t.Fatalf("writable socket hidden by another read-only mount: %+v", got)
	}
	a = scriptedAdapter{respond: func(string) execx.Result { return execx.Result{Stdout: "web\t203.0.113.10:5432->5432/tcp\n"} }}
	if got := checkDockerPublishedSensitivePorts(a); got.Status != Failed {
		t.Fatalf("specific public Docker bind missed: %+v", got)
	}
	if publicListenerPort("LISTEN 0 128 127.0.0.1:8080 203.0.113.1:2019", "2019") {
		t.Fatal("remote endpoint confused with local bind")
	}
}

func TestUnavailableCoverageAndExceptionsRemainDistinct(t *testing.T) {
	checks := []CheckResult{{Status: Passed}, {Status: Failed}, {Status: Skipped, SkipReason: EvidenceUnavailable}, {Status: Skipped, SkipReason: NotApplicable}, {Status: Passed, Ignored: true}}
	got := SummarizeCoverage(checks)
	if got.Total != 5 || got.Passed != 1 || got.Failed != 1 || got.Unavailable != 1 || got.NotApplicable != 1 || got.Exceptions != 1 {
		t.Fatalf("incorrect coverage: %+v", got)
	}
	if ChecksValidated(checks) {
		t.Fatal("incomplete evidence certified")
	}
}

func TestContainerizedRuntimeApplicabilityDoesNotWaiveDockerChecks(t *testing.T) {
	for _, containerized := range []bool{false, true} {
		cfg := EmptyConfig()
		cfg.ContainerizedApplication = containerized
		calls := []string{}
		adapter := scriptedAdapter{respond: func(command string) execx.Result {
			calls = append(calls, command)
			return execx.Result{ExitCode: 127}
		}}
		report := RunWithConfig(adapter, "test", []string{"node", "php", "docker"}, cfg, "")
		hostChecks, dockerChecks := 0, 0
		for _, result := range report.Checks {
			if strings.HasPrefix(result.ID, "runtime.") {
				hostChecks++
				if containerized {
					if result.Status != Skipped || result.SkipReason != NotApplicable || result.Ignored || result.Evidence["applicationRuntime"] != "container" {
						t.Fatalf("missing explicit container applicability: %+v", result)
					}
				} else if result.SkipReason == NotApplicable || result.Status == Passed {
					t.Fatalf("standalone host-runtime audit was waived: %+v", result)
				}
			}
			if strings.HasPrefix(result.ID, "docker.") {
				dockerChecks++
				if result.SkipReason == NotApplicable || result.Status == Passed {
					t.Fatalf("Docker workload check was waived: %+v", result)
				}
			}
		}
		if hostChecks != 4 || dockerChecks != 9 {
			t.Fatalf("unexpected check coverage: host=%d docker=%d", hostChecks, dockerChecks)
		}
		if report.Validated || report.Coverage.Exceptions != 0 {
			t.Fatalf("scope adjustment certified missing Docker evidence: %+v", report.Coverage)
		}
		if containerized {
			for _, command := range calls {
				if strings.Contains(command, "php") || strings.Contains(command, "node --version") {
					t.Fatalf("queried irrelevant host runtime: %s", command)
				}
			}
		}
	}
}
