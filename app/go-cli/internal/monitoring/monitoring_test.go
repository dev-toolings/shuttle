package monitoring

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func privateRuntimeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime fixture is not private after explicit chmod: %v", info.Mode())
	}
	return dir
}

func enabledMonitoringConfig(t *testing.T) config.MonitoringConfig {
	t.Helper()
	value := config.MonitoringConfig{Enabled: true}
	value.NormalizeMonitoring()
	value.Disk.Data.Path = "/data"
	value.Disk.ImagesRegistry.Path = "/images"
	value.Disk.Cache.Path = "/cache"
	value.Disk.Backups.Path = "/backups"
	value.Backup.Expected = false
	value.Security.CheckSSH = false
	value.Security.CheckUFW = false
	value.Security.CheckDockerUser = false
	value.Security.CheckFail2ban = false
	value.Security.ExpectedSSHPort = 22
	value.Security.ExpectedSSHUsers = []string{"deploy"}
	value.Security.PrivateInterface = "tailscale0"
	value.Security.AllowedTCPPorts = []string{"80", "443"}
	return value
}

const retainedMonitoringStack = `services:
  web:
    image: demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    deploy:
      replicas: 1
    healthcheck:
      test: ["CMD", "true"]
`

func readRetainedMonitoringStack(path string) ([]byte, error) {
	expected := filepath.Join(rootApplicationState, "demo", "current.yml")
	if path != expected {
		return nil, errors.New("unexpected retained inventory path: " + path)
	}
	return []byte(retainedMonitoringStack), nil
}

func isolatedOperationsDir(t *testing.T) (string, DirectoryReader) {
	t.Helper()
	dir := t.TempDir()
	return dir, func(path string) ([]os.DirEntry, error) {
		if path != dir {
			return nil, errors.New("unexpected operations directory: " + path)
		}
		return os.ReadDir(path)
	}
}

func healthyRunner(_ context.Context, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "stack services"):
		return []byte("demo_web\t1/1\n"), nil
	case strings.Contains(joined, "docker info") && strings.Contains(joined, "DockerRootDir"):
		return []byte("/var/lib/docker"), nil
	case strings.Contains(joined, "docker info"):
		return []byte("28.0"), nil
	case strings.Contains(joined, "service inspect shuttle-edge_caddy"):
		return []byte(`{"Condition":"any"}`), nil
	case strings.Contains(joined, "service ls") && strings.Contains(joined, "shuttle-edge_caddy"):
		return []byte("shuttle-edge_caddy\t1/1\n"), nil
	case strings.Contains(joined, "service ps shuttle-edge_caddy"):
		return []byte("caddytask1\tRunning 5 seconds ago\tRunning\t\n"), nil
	case strings.Contains(joined, "service inspect demo_web"):
		return []byte("demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t1"), nil
	case strings.Contains(joined, "service ps demo_web"):
		return []byte("taskweb1\tRunning 5 seconds ago\tRunning\t\n"), nil
	case strings.Contains(joined, "docker inspect taskweb1") && strings.Contains(joined, "ContainerSpec.Image"):
		return []byte(`"demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`), nil
	case strings.Contains(joined, "docker ps") && strings.Contains(joined, "service.name=shuttle-edge_caddy"):
		return []byte("caddy-task\n"), nil
	case strings.Contains(joined, "docker ps") && strings.Contains(joined, "service.name=demo_web"):
		return []byte("web-task\n"), nil
	case strings.Contains(joined, "docker inspect caddy-task") || strings.Contains(joined, "docker inspect web-task"):
		return []byte(`{"Status":"healthy"}`), nil
	case strings.Contains(joined, "inspect shuttle-registry") && strings.Contains(joined, ".State"):
		return []byte(`{"Running":true,"Health":{"Status":"healthy"}}`), nil
	case strings.Contains(joined, "inspect shuttle-registry") && strings.Contains(joined, "HostConfig"):
		return []byte(`{"RestartPolicy":{"Name":"always"},"PortBindings":{"5000/tcp":[{"HostIp":"127.0.0.1","HostPort":"5000"}]}}`), nil
	case strings.Contains(joined, "ss -lnt"):
		return []byte("LISTEN 0 4096 127.0.0.1:5000 0.0.0.0:*\n"), nil
	case strings.Contains(joined, "__shuttle_docker_ipv6"):
		return []byte("__shuttle_docker_ipv6=1\n__shuttle_family=ipv4\n__shuttle_privilege=direct\n-N DOCKER-USER\n-A DOCKER-USER -j ufw-before-forward\n-A DOCKER-USER -j ufw-skip-to-policy-forward\n-A DOCKER-USER -j RETURN\n__shuttle_family=ipv6\n__shuttle_privilege=direct\n-N DOCKER-USER\n-A DOCKER-USER -j ufw6-before-forward\n-A DOCKER-USER -j ufw6-skip-to-policy-forward\n-A DOCKER-USER -j RETURN\n"), nil
	case strings.Contains(joined, "systemctl is-active"):
		return []byte("active\n"), nil
	case strings.Contains(joined, "pg_lsclusters"):
		return []byte("18 main 5432 online postgres /var/lib/postgresql/18/main /var/log/postgresql/postgresql-18-main.log\n"), nil
	case strings.Contains(joined, "pg_isready"):
		return []byte("accepting connections\n"), nil
	case strings.Contains(joined, "sshd -T"):
		return []byte("permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 22\nallowusers deploy\n"), nil
	case strings.Contains(joined, "ufw status"):
		return []byte("Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n22/tcp on tailscale0 ALLOW IN Anywhere\n80/tcp ALLOW IN Anywhere\n443/tcp ALLOW IN Anywhere\n"), nil
	case strings.Contains(joined, "jail.d/shuttle-sshd.local"):
		return []byte("22\n"), nil
	case strings.Contains(joined, "fail2ban-client status sshd"):
		return []byte("Status for the jail: sshd\n"), nil
	case strings.Contains(joined, "command -v fail2ban-client"):
		return []byte(""), nil
	default:
		return nil, errors.New("unexpected monitoring command: " + joined)
	}
}

func healthyStatfs(string) (DiskStats, error) {
	return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
}

func TestRunProducesDatedScopedResultsAndDoesNotTreatExternalAsLocal(t *testing.T) {
	cfg := enabledMonitoringConfig(t)
	opsDir, readDir := isolatedOperationsDir(t)
	cfg.OperationsStateDir = opsDir
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	engine := New("demo", cfg, Adapters{Run: healthyRunner, Read: readRetainedMonitoringStack, ReadDir: readDir, Statfs: healthyStatfs, Now: func() time.Time { return now }})
	engine.PostgresVersion = 18
	engine.PostgresCluster = "main"
	report := engine.Run(context.Background())
	if report.Schema != Schema || report.Scope != ScopeLocal || report.State != StateHealthy {
		t.Fatalf("unexpected report: %#v", report)
	}
	expectedStates := map[string]string{
		"services.application": StateHealthy,
		"services.docker":      StateHealthy,
		"services.caddy":       StateHealthy,
		"services.registry":    StateHealthy,
		"services.postgresql":  StateHealthy,
		"services.redis":       StateNotApplicable,
		"services.rabbitmq":    StateNotApplicable,
		"security.ssh":         StateHealthy,
		"security.ufw":         StateHealthy,
		"security.docker_user": StateHealthy,
		"security.fail2ban":    StateHealthy,
	}
	seen := map[string]bool{}
	for _, check := range report.Checks {
		if check.CheckedAt == "" || check.FreshUntil == "" || check.Scope != ScopeLocal {
			t.Fatalf("check lacks dated local freshness evidence: %#v", check)
		}
		if want, ok := expectedStates[check.ID]; ok {
			seen[check.ID] = true
			if check.State != want {
				t.Fatalf("collector %s returned %s, want %s: %#v", check.ID, check.State, want, check)
			}
		}
		if check.ID == "external.https" && check.State != StateNotApplicable {
			t.Fatal("local execution must not claim external availability")
		}
	}
	for id := range expectedStates {
		if !seen[id] {
			t.Fatalf("expected collector %s did not execute", id)
		}
	}
	body, err := MarshalReport(report)
	if err != nil || !strings.Contains(string(body), `"freshness"`) {
		t.Fatalf("JSON report did not expose freshness: %v %s", err, body)
	}
}

func TestDiskAndInodeThresholdsAreIndependent(t *testing.T) {
	cfg := enabledMonitoringConfig(t)
	cfg.Disk.Data.MinFreePercent = 50
	cfg.Disk.Data.MinFreeInodesPercent = 10
	engine := New("demo", cfg, Adapters{Run: healthyRunner, Statfs: healthyStatfs})
	checks := engine.diskChecks(context.Background())
	if checks[0].State != StateDegraded || checks[0].Evidence["free_inodes_percent"] != uint64(40) {
		t.Fatalf("disk threshold did not report the block/inode distinction: %#v", checks[0])
	}
	if checks[1].State != StateHealthy {
		t.Fatalf("images disk should be healthy: %#v", checks[1])
	}
}

type responseDoer struct {
	response *http.Response
	err      error
}

func (d responseDoer) Do(*http.Request) (*http.Response, error) { return d.response, d.err }

func TestHTTPSAndTLSChecksRefuseTimeoutAndNearExpiry(t *testing.T) {
	cfg := enabledMonitoringConfig(t)
	cfg.TLS.URL = "https://service.example/health"
	cfg.TLS.MinDays = 14
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	engine := New("demo", cfg, Adapters{Run: healthyRunner, Statfs: healthyStatfs, Now: func() time.Time { return now }, HTTP: responseDoer{response: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: now.Add(2 * 24 * time.Hour)}}}}}})
	result := engine.Run(context.Background())
	var expiry Result
	for _, check := range result.Checks {
		if check.ID == "tls.expiry" {
			expiry = check
		}
	}
	if expiry.State != StateDegraded {
		t.Fatalf("near-expiry certificate was not degraded: %#v", expiry)
	}
}

func TestTimeoutAndStaleEvidenceCannotBeHealthy(t *testing.T) {
	cfg := enabledMonitoringConfig(t)
	runner := func(ctx context.Context, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "docker info") {
			return nil, context.DeadlineExceeded
		}
		return healthyRunner(ctx, args...)
	}
	engine := New("demo", cfg, Adapters{Run: runner, Statfs: healthyStatfs})
	report := engine.Run(context.Background())
	for _, check := range report.Checks {
		if check.ID == "services.docker" && check.State == StateHealthy {
			t.Fatal("a timed out Docker check was reported healthy")
		}
	}
	now := time.Now().UTC()
	stale := Result{State: StateHealthy, FreshUntil: now.Add(-time.Second).Format(time.RFC3339Nano), Freshness: Fresh}
	if stale.WithFreshness(now).State == StateHealthy {
		t.Fatal("stale evidence was reported healthy")
	}
}

type recordingNotifier struct {
	mu     sync.Mutex
	events []Notification
	fails  int
}

func (n *recordingNotifier) Notify(ctx context.Context, event Notification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	if n.fails > 0 {
		n.fails--
		return errors.New("synthetic delivery failure")
	}
	return nil
}

func (n *recordingNotifier) Events() []Notification {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Notification(nil), n.events...)
}

func reportFor(state string, now time.Time) Report {
	return Report{Schema: Schema, App: "demo", Scope: ScopeLocal, State: state, CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: now.Add(time.Hour).Format(time.RFC3339Nano), Freshness: Fresh, Checks: []Result{{ID: "services.application", Title: "Application", Category: "services", Scope: ScopeLocal, State: state, Summary: "application state", CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: now.Add(time.Hour).Format(time.RFC3339Nano), Freshness: Fresh}}}
}

func TestIncidentDeliveryFailurePersistsAndRecoveryFollowsIncident(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	notifier := &recordingNotifier{fails: 3}
	store := &MemoryStore{}
	manager := AlertManager{Store: store, Notifier: notifier, Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	state, err := manager.Process(context.Background(), reportFor(StateDegraded, now))
	if err != nil || len(state.Pending) != 1 {
		t.Fatalf("failed incident was not retained: %#v %v", state, err)
	}
	notifier.fails = 0
	now = now.Add(time.Minute)
	state, err = manager.Process(context.Background(), reportFor(StateHealthy, now))
	if err != nil || len(state.Pending) != 0 || len(notifier.events) != 3 || notifier.events[1].Kind != "incident" || notifier.events[2].Kind != "recovery" {
		t.Fatalf("recovery was not ordered after the pending incident: state=%#v events=%#v err=%v", state, notifier.events, err)
	}
}

func TestMaintenanceSuppressesDeliveryButNotIncidentHistory(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	notifier := &recordingNotifier{}
	store := &MemoryStore{}
	manager := AlertManager{Store: store, Notifier: notifier, Retries: 1, Debounce: 0, MaintenanceUntil: now.Add(time.Hour).Format(time.RFC3339Nano), Now: func() time.Time { return now }}
	state, err := manager.Process(context.Background(), reportFor(StateDegraded, now))
	if err != nil || len(notifier.events) != 0 || state.Incidents["services.application"].State != StateActive {
		t.Fatalf("maintenance hid history or delivered unexpectedly: %#v events=%#v err=%v", state, notifier.events, err)
	}
	now = now.Add(2 * time.Hour)
	state, err = manager.Process(context.Background(), reportFor(StateDegraded, now))
	if err != nil || len(notifier.events) != 1 || len(state.Pending) != 0 {
		t.Fatalf("incident was not delivered after maintenance expired: %#v events=%#v err=%v", state, notifier.events, err)
	}
}

func TestExternalRunUsesIndependentScope(t *testing.T) {
	cfg := enabledMonitoringConfig(t)
	cfg.External.URL = "https://public.example/health"
	cfg.NormalizeMonitoring()
	now := time.Now().UTC()
	engine := New("demo", cfg, Adapters{Now: func() time.Time { return now }, HTTP: responseDoer{response: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}}})
	report := engine.RunExternal(context.Background())
	if report.Scope != ScopeExternal || report.State != StateHealthy || len(report.Checks) != 1 || report.Checks[0].Scope != ScopeExternal {
		t.Fatalf("external result did not retain independent scope: %#v", report)
	}
}

func TestFileStoreUsesPrivateAtomicStateAndKeepsLastReport(t *testing.T) {
	path := filepath.Join(privateRuntimeDir(t), "incidents.json")
	store := FileStore{Path: path}
	now := time.Now().UTC()
	state := emptyIncidentState()
	lastReport := reportFor(StateHealthy, now)
	state.LastReport = &lastReport
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("incident state is not private: %v %#v", err, info)
	}
	loaded, err := store.Load(context.Background())
	if err != nil || loaded.LastReport == nil || loaded.LastReport.State != StateHealthy {
		t.Fatalf("stored dated report was not recovered: %#v %v", loaded, err)
	}
	if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
		t.Fatal("partial state file leaked")
	}
	var decoded IncidentState
	if body, err := os.ReadFile(path); err != nil || json.Unmarshal(body, &decoded) != nil {
		t.Fatal("state is not valid JSON")
	}
}

func TestReadLatestUsesPersistedEvidenceWithoutRunningCollectors(t *testing.T) {
	stateDir := privateRuntimeDir(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	store := FileStore{Path: filepath.Join(stateDir, "incidents.json")}
	last := reportFor(StateHealthy, now)
	if err := store.Save(context.Background(), IncidentState{Schema: incidentSchema, Incidents: map[string]Incident{}, Pending: []AlertEvent{}, LastReport: &last}); err != nil {
		t.Fatal(err)
	}
	called := false
	installed := InstalledConfig{App: "demo", Monitoring: config.MonitoringConfig{Enabled: true, StateDir: stateDir, StaleAfterSeconds: 300}}
	report, err := ReadLatest(installed, func(string) ([]byte, error) {
		called = true
		body, readErr := os.ReadFile(store.Path)
		return body, readErr
	}, now.Add(time.Minute))
	if err != nil || !called || report.State != StateHealthy || report.Checks[0].State != StateHealthy {
		t.Fatalf("persisted report was not read without probes: report=%#v err=%v called=%v", report, err, called)
	}
}

func TestFreshFailureCancelsQueuedRecoveryAndStartsNewEpisode(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	notifier := &recordingNotifier{}
	store := &MemoryStore{}
	manager := AlertManager{Store: store, Notifier: notifier, Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	if _, err := manager.Process(context.Background(), reportFor(StateDegraded, now)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := manager.Process(context.Background(), reportFor(StateHealthy, now)); err != nil {
		t.Fatal(err)
	}
	if len(store.State.Pending) != 0 || !store.State.Incidents["services.application"].RecoverySent {
		t.Fatalf("recovery was not delivered before the next episode: %#v", store.State)
	}
	now = now.Add(time.Minute)
	incident := store.State.Incidents["services.application"]
	incident.RecoveryPending = true
	store.State.Incidents["services.application"] = incident
	store.State.Pending = []AlertEvent{{ID: "old-recovery", Kind: "recovery", CheckID: "services.application", App: "demo"}}
	if _, err := manager.Process(context.Background(), reportFor(StateDegraded, now)); err != nil {
		t.Fatal(err)
	}
	if len(store.State.Pending) != 0 || len(notifier.events) != 3 || notifier.events[2].Kind != "incident" || notifier.events[2].ID == notifier.events[0].ID {
		t.Fatalf("fresh failure replayed obsolete recovery or reused the episode ID: state=%#v events=%#v", store.State, notifier.events)
	}
}
