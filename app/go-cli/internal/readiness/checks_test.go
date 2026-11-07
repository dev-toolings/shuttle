package readiness

import (
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

type unavailableAdapter struct{}

func (unavailableAdapter) Run(string, time.Duration) execx.Result {
	return execx.Result{ExitCode: 1}
}

func TestFullProfileContainsExactly73Checks(t *testing.T) {
	report := RunWithConfig(unavailableAdapter{}, "test", []string{"all"}, EmptyConfig(), "")
	if len(report.Checks) != 73 {
		t.Fatalf("check catalog requires exactly 73 active checks, got %d", len(report.Checks))
	}
	seen := make(map[string]struct{}, len(report.Checks))
	for _, check := range report.Checks {
		if _, exists := seen[check.ID]; exists {
			t.Fatalf("duplicate check ID %q", check.ID)
		}
		seen[check.ID] = struct{}{}
	}
}

func TestRunWithConfigProgressReportsEveryCheck(t *testing.T) {
	count := 0
	lastDone, lastTotal := 0, 0
	RunWithConfigProgress(unavailableAdapter{}, "test", []string{"all"}, EmptyConfig(), "", func(done, total int) {
		count++
		lastDone, lastTotal = done, total
	})
	if count != 73 || lastDone != 73 || lastTotal != 73 {
		t.Fatalf("progress = count %d, last %d/%d; want 73 callbacks ending at 73/73", count, lastDone, lastTotal)
	}
}

func TestConsoleWithColorAddsANSIOnlyWhenRequested(t *testing.T) {
	report := Report{Target: "test", Profile: []string{"all"}, Score: 100, Level: "production-ready", Checks: []CheckResult{{Severity: High, Status: Passed, Title: "ok", Summary: "fine"}}}
	plain := ConsoleWithOptions(report, false, false)
	if strings.Contains(plain, "\033[") {
		t.Fatal("plain console output must not contain ANSI escapes")
	}
	colored := ConsoleWithOptions(report, true, false)
	if !strings.Contains(colored, "\033[32m") {
		t.Fatal("colored console output must contain ANSI status color")
	}
}

func TestConsoleHidesSkippedChecksUnlessRequested(t *testing.T) {
	report := Report{Target: "test", Profile: []string{"all"}, Score: 100, Level: "production-ready", Checks: []CheckResult{
		{Severity: High, Status: Skipped, SkipReason: NotApplicable, Title: "optional workload", Summary: "not installed"},
		{Severity: High, Status: Passed, Title: "ok", Summary: "fine"},
	}}
	plain := ConsoleWithOptions(report, false, false)
	if strings.Contains(plain, "optional workload") {
		t.Fatal("skipped checks must be hidden by default")
	}
	shown := ConsoleWithOptions(report, false, true)
	if !strings.Contains(shown, "optional workload") {
		t.Fatal("--show-skipped output must include skipped checks")
	}
}

func TestProfileCategoriesKeepsStandbyPrivateTailscalePresetInactive(t *testing.T) {
	categories := profileCategories([]string{"private-tailscale"})
	if categoryEnabled("tailscale", categories) || categoryEnabled("access", categories) {
		t.Fatal("standby private-tailscale profile must not enable Tailscale or private-access checks")
	}
}

func TestDebian13IsSupported(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "ID=debian\nVERSION_ID=\"13\"\n"}
	}}
	if got := checkOSSupported(adapter); got.Status != Passed {
		t.Fatalf("expected Debian 13 support after PVE validation, got %+v", got)
	}
}

func TestSSHPortMatchesConfiguredPort(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "port 22\n"}
	}}
	if got := checkSSHPortForAccess(adapter, AccessConfig{SSHPort: 22}); got.Status != Passed {
		t.Fatalf("expected configured port to pass, got %+v", got)
	}
}

func TestProfileCategoriesAvoidsImplicitCrossCategoryExpansion(t *testing.T) {
	categories := profileCategories([]string{"docker", "caddy"})
	for _, category := range []string{"docker", "reverse-proxy"} {
		if !categories[category] {
			t.Fatalf("expected exact category %q to be enabled", category)
		}
	}
	for _, category := range []string{"system", "compose", "caddy", "tls"} {
		if categories[category] {
			t.Fatalf("category %q was unexpectedly enabled", category)
		}
	}
}

func TestProfileCategoriesAllowsExplicitCategoryFilter(t *testing.T) {
	categories := profileCategories([]string{"tls"})
	if !categoryEnabled("tls", categories) {
		t.Fatal("expected tls to be enabled")
	}
	if categoryEnabled("docker", categories) {
		t.Fatal("expected docker to be disabled")
	}
}

func TestDatabaseListenersPublicButFirewallRestricted(t *testing.T) {
	output := `LISTEN 0 200 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=2701933,fd=7))
LISTEN 0 200 [::]:5432 [::]:* users:(("postgres",pid=2701933,fd=8))`
	listeners := publicDatabaseListeners(output)
	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(listeners))
	}
	ports := uniqueListenerPorts(listeners)
	if len(ports) != 1 || ports[0] != "5432" {
		t.Fatalf("expected only 5432, got %#v", ports)
	}
	firewall := `Status: active
Default: deny (incoming), allow (outgoing), deny (routed)

To                         Action      From
--                         ------      ----
5432/tcp                   ALLOW IN    127.0.0.1
5432/tcp                   ALLOW IN    172.20.0.0/16`
	if !databasePortsFirewallRestricted(firewall, ports) {
		t.Fatal("expected UFW rules to restrict public database access")
	}
}

func TestDatabaseFirewallDetectsPublicAllow(t *testing.T) {
	firewall := `Status: active
Default: deny (incoming), allow (outgoing), deny (routed)

To                         Action      From
--                         ------      ----
5432/tcp                   ALLOW IN    Anywhere`
	if databasePortsFirewallRestricted(firewall, []string{"5432"}) {
		t.Fatal("expected public allow to be treated as unrestricted")
	}
}

func TestSplitRuntimeOutput(t *testing.T) {
	mode, body := splitRuntimeOutput("__shuttle_runtime=swarm\nservice-a\ton-failure\n__shuttle_runtime=classic\n/container\tunless-stopped\n")
	if mode != "mixed" {
		t.Fatalf("expected mixed mode, got %q", mode)
	}
	if body != "service-a\ton-failure\n/container\tunless-stopped\n" {
		t.Fatalf("unexpected body %q", body)
	}
}

func TestHealthMissing(t *testing.T) {
	if !healthMissing("null") {
		t.Fatal("expected null healthcheck to be missing")
	}
	if !healthMissing(`{"Test":["NONE"]}`) {
		t.Fatal("expected NONE healthcheck to be missing")
	}
	if healthMissing(`{"Test":["CMD","curl","-f","http://localhost/health"]}`) {
		t.Fatal("expected CMD healthcheck to be present")
	}
}

func TestSplitTab2(t *testing.T) {
	left, right := splitTab2("service\tvalue")
	if left != "service" || right != "value" {
		t.Fatalf("unexpected split: %q %q", left, right)
	}
	left, right = splitTab2("service-only")
	if left != "service-only" || right != "" {
		t.Fatalf("unexpected split without tab: %q %q", left, right)
	}
}

func TestApplyConfigIgnoresCheckID(t *testing.T) {
	result := applyConfig(CheckResult{
		ID:       "docker.sock_exposed",
		Severity: High,
		Status:   Failed,
		Evidence: map[string]any{"workloads": []string{"dozzle"}},
	}, Config{Checks: CheckConfig{Ignore: []string{"docker.sock_exposed"}}})

	if !result.Ignored {
		t.Fatal("expected result to be ignored")
	}
	if result.Status != Passed {
		t.Fatalf("expected passed status for an explicit allowlist, got %s", result.Status)
	}
}

func TestApplyConfigAllowsSomeDockerSocketWorkloads(t *testing.T) {
	result := applyConfig(CheckResult{
		ID:       "docker.sock_exposed",
		Severity: High,
		Status:   Failed,
		Summary:  "2 Docker workload(s) mount /var/run/docker.sock.",
		Evidence: map[string]any{"workloads": []string{"caddy_dozzle", "shared_uptime-kuma"}},
	}, Config{Docker: DockerConfig{AllowDockerSocket: []string{"caddy_dozzle"}}})

	if result.Ignored {
		t.Fatal("expected one remaining workload, not full ignore")
	}
	workloads, ok := result.Evidence["workloads"].([]string)
	if !ok {
		t.Fatalf("expected workloads evidence as []string")
	}
	if len(workloads) != 1 || workloads[0] != "shared_uptime-kuma" {
		t.Fatalf("unexpected remaining workloads %#v", workloads)
	}
}

func TestApplyConfigAllowsAllWorkerHealthcheckFindings(t *testing.T) {
	result := applyConfig(CheckResult{
		ID:       "docker.containers_without_healthcheck",
		Severity: Medium,
		Status:   Failed,
		Evidence: map[string]any{"workloads": []string{"prod_worker-high-priority", "prod_worker-low-priority"}},
	}, Config{Docker: DockerConfig{WorkerServices: []string{"prod_worker-*"}}})

	if !result.Ignored {
		t.Fatal("expected worker healthcheck finding to be ignored")
	}
}
