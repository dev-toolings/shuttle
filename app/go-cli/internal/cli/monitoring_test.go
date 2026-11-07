package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/monitoring"
)

func TestMonitoringCommandIsAvailableThroughStatusAliasWithoutChangingRootSurface(t *testing.T) {
	root := NewRootCommand()
	status, _, err := root.Find([]string{"monitoring", "run"})
	if err != nil || status == nil || status.Name() != "run" {
		t.Fatalf("monitoring alias did not resolve its run command: %v %#v", err, status)
	}
	if len(root.Commands()) != 17 {
		t.Fatalf("monitoring should be exposed through the status alias without changing the root command count: %d", len(root.Commands()))
	}
}

func TestConfigMonitoringMaterializesOpsDeployAndPublicPortsFromProjectSettings(t *testing.T) {
	cfg := &config.Config{
		App: "demo",
		Servers: map[string]config.ServerGroup{
			"default": {Hosts: []string{"203.0.113.10"}, User: "deploy", Port: 22},
		},
		Setup:      config.SetupConfig{OperatorUser: "ops"},
		Monitoring: &config.MonitoringConfig{Enabled: true, Notifications: config.MonitoringNotifications{WebhookEnv: "SHUTTLE_MONITOR_WEBHOOK"}},
	}
	got := configMonitoring(cfg)
	if strings.Join(got.Security.ExpectedSSHUsers, " ") != "deploy ops" {
		t.Fatalf("installed config did not materialize ops and deploy: %#v", got.Security)
	}
	ports := map[string]bool{}
	for _, port := range got.Security.AllowedTCPPorts {
		ports[port] = true
	}
	if len(got.Security.AllowedTCPPorts) != 3 || !ports["22"] || !ports["80"] || !ports["443"] {
		t.Fatalf("installed config did not materialize SSH and HTTPS ports: %#v", got.Security.AllowedTCPPorts)
	}
	if got.Security.SSHListenAddress != "203.0.113.10" || got.Security.SSHPeerAddress != "" {
		t.Fatalf("listen address must be the host-group IP and peer must stay unobserved: %#v", got.Security)
	}
	cfg.Monitoring.Security.ExpectedSSHUsers = []string{"alice"}
	cfg.Monitoring.Security.AllowedTCPPorts = []string{"443"}
	got = configMonitoring(cfg)
	if strings.Join(got.Security.ExpectedSSHUsers, " ") != "alice" || strings.Join(got.Security.AllowedTCPPorts, ",") != "443" {
		t.Fatalf("explicit monitoring access settings were overwritten: %#v", got.Security)
	}
}

func TestMonitoringDisabledLocalCommandIsExplicitlyNotApplicable(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	config := []byte(`{"version":2,"app":"demo","domain":"demo.example.com","server":{"host":"203.0.113.10","user":"deploy"},"deploy":{"strategy":"swarm","total_slo_seconds":30,"promotion_slo_seconds":30,"retain":2},"services":{"web":{"port":3000,"healthcheck":{"type":"http","path":"/health"}}},"setup":{"slo_seconds":600},"retention":{"registry_cache":"5GB","postgres_backups":7,"min_free_percent":20},"readiness":{"preset":"node-api","healthcheck_path":"/health"}}`)
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	command := newMonitoringStatusCommand()
	buffer := new(bytes.Buffer)
	command.SetOut(buffer)
	command.SetArgs([]string{"--config", path, "--local"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "not_applicable") {
		t.Fatalf("disabled monitoring did not expose its state: %s", buffer.String())
	}
}

func TestMonitoringReportFailurePolicyRejectsUnavailableAndDegraded(t *testing.T) {
	for _, state := range []string{monitoring.StateDegraded, monitoring.StateUnavailable} {
		if monitoringReportError(monitoring.Report{State: state}) == nil {
			t.Fatalf("%s report must fail the CLI policy", state)
		}
	}
	if monitoringReportError(monitoring.Report{State: monitoring.StateHealthy}) != nil {
		t.Fatal("healthy report must pass the CLI policy")
	}
}

func TestStripRootOperationFooterKeepsOnlyReport(t *testing.T) {
	body := "{\"schema\":\"shuttle.monitoring/v1\"}\noperation=monitor-run digest=sha256:abc\n"
	if got := stripRootOperationFooter(body); got != "{\"schema\":\"shuttle.monitoring/v1\"}" {
		t.Fatalf("unexpected helper report: %q", got)
	}
}

func monitoringRecetteConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"version":2,"app":"demo","domain":"demo.example.com","server":{"host":"203.0.113.10","user":"deploy"},"deploy":{"strategy":"swarm","total_slo_seconds":30,"promotion_slo_seconds":30,"retain":2},"services":{"web":{"port":3000,"healthcheck":{"type":"http","path":"/health"}}},"setup":{"slo_seconds":600},"retention":{"registry_cache":"5GB","postgres_backups":7,"min_free_percent":20},"readiness":{"preset":"node-api","healthcheck_path":"/health"},"monitoring":{"enabled":true,"notifications":{"webhook_env":"SHUTTLE_RECETTE_WEBHOOK"},"external":{"url":"https://demo.example.com"}}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMonitoringStatusReadsSignedVPSReportByDefault(t *testing.T) {
	old := monitoringRemoteOperation
	t.Cleanup(func() { monitoringRemoteOperation = old })
	calls := 0
	monitoringRemoteOperation = func(cfg *config.Config, action string, payload []byte, until time.Time) (string, error) {
		calls++
		if cfg.App != "demo" || action != "status" {
			t.Fatalf("wrong remote request: app=%s action=%s", cfg.App, action)
		}
		return monitoring.JSON(monitoring.Report{Schema: monitoring.Schema, App: cfg.App, Scope: monitoring.ScopeLocal, State: monitoring.StateDegraded, CheckedAt: "2026-09-13T12:00:00Z"}), nil
	}
	cmd := newMonitoringStatusCommand()
	cmd.SilenceUsage = true
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--config", monitoringRecetteConfig(t), "--format", "json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("degraded VPS report must fail policy")
	}
	var report monitoring.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || report.CheckedAt != "2026-09-13T12:00:00Z" || report.State != monitoring.StateDegraded {
		t.Fatalf("local state replaced VPS evidence: calls=%d report=%#v", calls, report)
	}
}

func TestMonitoringEmptyHelperOutputStillEmitsJSON(t *testing.T) {
	old := monitoringRemoteOperation
	t.Cleanup(func() { monitoringRemoteOperation = old })
	helperErr := errors.New("signed monitoring operation failed: timeout")
	monitoringRemoteOperation = func(*config.Config, string, []byte, time.Time) (string, error) {
		return "", helperErr
	}
	cmd := newMonitoringRunCommand()
	cmd.SilenceUsage = true
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--config", monitoringRecetteConfig(t), "--format", "json"})
	if err := cmd.Execute(); !errors.Is(err, helperErr) {
		t.Fatalf("helper timeout hidden: %v", err)
	}
	var report monitoring.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("missing JSON on empty helper output: %s (%v)", output.String(), err)
	}
	if report.State != monitoring.StateUnavailable || report.Freshness == monitoring.Fresh && report.State == monitoring.StateHealthy {
		t.Fatalf("empty helper output was treated as healthy: %#v", report)
	}
}

func TestMonitoringExternalKeepsJSONWhenNotificationFails(t *testing.T) {
	old := monitoringExternalRun
	t.Cleanup(func() { monitoringExternalRun = old })
	deliveryErr := errors.New("notification endpoint returned HTTP 500")
	monitoringExternalRun = func(_ context.Context, installed monitoring.InstalledConfig, _ monitoring.Adapters) (monitoring.Report, error) {
		return monitoring.Report{Schema: monitoring.Schema, App: installed.App, Scope: monitoring.ScopeExternal, State: monitoring.StateDegraded, CheckedAt: "2026-09-13T12:00:00Z"}, deliveryErr
	}
	cmd := newMonitoringExternalCommand()
	cmd.SilenceUsage = true
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--config", monitoringRecetteConfig(t), "--format", "json"})
	if err := cmd.Execute(); !errors.Is(err, deliveryErr) {
		t.Fatalf("delivery failure hidden: %v", err)
	}
	var report monitoring.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("missing JSON when webhook fails: %s (%v)", output.String(), err)
	}
	if report.Scope != monitoring.ScopeExternal || report.State != monitoring.StateDegraded {
		t.Fatalf("external evidence lost: %#v", report)
	}
}

// An operator created by `setup --operator-user` exists on the host and in the
// recorded identity even when the config does not name it (VM e2e, 2026-10-28).
func TestMonitoringDefaultUsersIncludeTheRecordedIdentity(t *testing.T) {
	original := monitoringRecordedSSHUsers
	t.Cleanup(func() { monitoringRecordedSSHUsers = original })
	monitoringRecordedSSHUsers = func(*config.Config) []string { return []string{"deploy", "ops"} }
	cfg := &config.Config{App: "demo", Setup: config.SetupConfig{RetainedUsers: []string{"legacy"}}, Servers: map[string]config.ServerGroup{"default": {Hosts: []string{"203.0.113.10"}, User: "deploy", Port: 22}}}
	got := trustedMonitoringAccess(cfg).Users
	if strings.Join(got, ",") != "deploy,legacy,ops" {
		t.Fatalf("default users = %v, want deploy, legacy (declared) and ops (recorded)", got)
	}
}
