package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func alertReport(checks ...Result) Report {
	return Report{Schema: Schema, App: "demo", Scope: ScopeLocal, State: StateDegraded, CheckedAt: checks[0].CheckedAt, FreshUntil: checks[0].FreshUntil, Freshness: Fresh, Checks: checks}
}

func alertCheck(id, state string, now time.Time) Result {
	return Result{ID: id, Title: id, Category: "services", Scope: ScopeLocal, State: state, Summary: "observed " + state, CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: now.Add(time.Hour).Format(time.RFC3339Nano), Freshness: Fresh}
}

func TestRecoveryDebounceSurvivesHealthyCycles(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	notifier := &recordingNotifier{}
	manager := AlertManager{Store: &MemoryStore{}, Notifier: notifier, Retries: 1, Debounce: 2 * time.Minute, Now: func() time.Time { return now }}

	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err != nil {
		t.Fatal(err)
	}
	// The failure is observed for the whole 2 minute debounce (three samples),
	// so it is an incident; see TestSingleBadSampleBetweenHealthyOnesNeverPages.
	for range 2 {
		now = now.Add(time.Minute)
		if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(90 * time.Second)
	state, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now)))
	if err != nil || len(notifier.events) != 1 || notifier.events[0].Kind != "incident" || !state.Incidents["services.application"].RecoveryPending {
		t.Fatalf("matured recovery transition was not retained: state=%#v events=%#v err=%v", state, notifier.events, err)
	}
	firstRecoveryID := eventID("demo", "services.application", "recovery", state.Incidents["services.application"].FirstSeen)
	now = now.Add(2 * time.Minute)
	state, err = manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now)))
	if err != nil || len(notifier.events) != 2 || notifier.events[1].Kind != "recovery" || notifier.events[1].ID != firstRecoveryID || len(state.Pending) != 0 {
		t.Fatalf("recovery did not survive subsequent healthy cycles: state=%#v events=%#v err=%v", state, notifier.events, err)
	}
}

func TestMaintenanceClearDeliversExpectedRecovery(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	notifier := &recordingNotifier{}
	store := &MemoryStore{}
	manager := AlertManager{Store: store, Notifier: notifier, Retries: 1, Debounce: 0, MaintenanceUntil: now.Add(time.Hour).Format(time.RFC3339Nano), Now: func() time.Time { return now }}
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Minute)
	state, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now)))
	if err != nil || len(notifier.events) != 0 || !state.Incidents["services.application"].RecoveryPending {
		t.Fatalf("maintenance did not retain the expected recovery: state=%#v events=%#v err=%v", state, notifier.events, err)
	}
	now = now.Add(time.Minute)
	manager.MaintenanceUntil = ""
	state, err = manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now)))
	if err != nil || len(notifier.events) != 2 || notifier.events[0].Kind != "incident" || notifier.events[1].Kind != "recovery" || len(state.Pending) != 0 {
		t.Fatalf("clearing maintenance lost the recovery: state=%#v events=%#v err=%v", state, notifier.events, err)
	}
}

func TestDeliveryProgressSurvivesRestartAfterNextEventFails(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	dir := privateRuntimeDir(t)
	store := FileStore{Path: filepath.Join(dir, "incidents.json")}
	first := &failOnCallNotifier{failCall: 2}
	manager := AlertManager{Store: store, Notifier: first, FailureLog: filepath.Join(dir, "delivery-failures.jsonl"), Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	report := alertReport(alertCheck("services.application", StateDegraded, now), alertCheck("services.docker", StateDegraded, now))
	state, err := manager.Process(context.Background(), report)
	if err == nil || len(state.Pending) != 1 || len(first.events) != 2 {
		t.Fatalf("failed batch did not retain only the unacknowledged event: state=%#v events=%#v err=%v", state, first.events, err)
	}
	restartedNotifier := &recordingNotifier{}
	restarted := AlertManager{Store: FileStore{Path: store.Path}, Notifier: restartedNotifier, FailureLog: manager.FailureLog, Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	if _, err := restarted.Process(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	if len(restartedNotifier.events) != 1 || restartedNotifier.events[0].CheckID != "services.docker" {
		t.Fatalf("restart replayed a previously acknowledged event: %#v", restartedNotifier.events)
	}
}

func TestInvalidNotifierIsUnavailableWithoutPendingIncident(t *testing.T) {
	store := &MemoryStore{}
	notifierErr := errors.New("invalid notifier configuration")
	manager := AlertManager{Store: store, FailureLog: filepath.Join(privateRuntimeDir(t), "delivery-failures.jsonl"), NotifierErr: notifierErr, Retries: 1, Now: time.Now}
	now := time.Now().UTC()
	state, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now)))
	if !errors.Is(err, notifierErr) || len(state.Pending) != 0 || state.LastReport == nil {
		t.Fatalf("invalid notifier was ignored without a pending incident: state=%#v err=%v", state, err)
	}
	for _, check := range state.LastReport.Checks {
		if check.ID == "notifications.delivery" && check.State == StateUnavailable {
			return
		}
	}
	t.Fatal("unavailable notification check was not persisted")
}

func TestDeliveryLogFailureIsJoinedWithDeliveryError(t *testing.T) {
	root := privateRuntimeDir(t)
	badParent := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(badParent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	deliveryErr := errors.New("channel down")
	notifier := &sentinelNotifier{err: deliveryErr}
	manager := AlertManager{Store: &MemoryStore{}, Notifier: notifier, FailureLog: filepath.Join(badParent, "delivery-failures.jsonl"), Retries: 1, Debounce: 0, Now: time.Now}
	now := time.Now().UTC()
	_, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now)))
	if !errors.Is(err, deliveryErr) || !strings.Contains(err.Error(), "persist notification failure") {
		t.Fatalf("delivery and log errors were not joined: %v", err)
	}
}

func TestFileStoreRejectsUnsafeRuntimePathsAndReservesStateNames(t *testing.T) {
	root := privateRuntimeDir(t)
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := (FileStore{Path: filepath.Join(private, "incidents.json")}).Lock(context.Background())
	if err != nil {
		t.Fatalf("private runtime directory was rejected: %v", err)
	}
	unlock()

	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Path: filepath.Join(writable, "incidents.json")}).Lock(context.Background()); err == nil {
		t.Fatal("group/world-writable runtime ancestor was accepted")
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(root, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Path: filepath.Join(symlink, "incidents.json")}).Lock(context.Background()); err == nil {
		t.Fatal("symlinked runtime ancestor was accepted")
	}
	if err := appendDeliveryFailure(filepath.Join(root, "incidents.json"), AlertEvent{ID: "event"}, errors.New("failed"), time.Now); err == nil {
		t.Fatal("failure log collided with incident state")
	}
}

func TestFileStoreLockIsExclusiveAcrossProcesses(t *testing.T) {
	if os.Getenv("SHUTTLE_FILESTORE_LOCK_HELPER") == "1" {
		store := FileStore{Path: os.Getenv("SHUTTLE_FILESTORE_LOCK_PATH")}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		unlock, err := store.Lock(ctx)
		if err == nil {
			unlock()
			os.Exit(2)
		}
		return
	}

	store := FileStore{Path: filepath.Join(privateRuntimeDir(t), "incidents.json")}
	unlock, err := store.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	command := exec.Command(os.Args[0], "-test.run=TestFileStoreLockIsExclusiveAcrossProcesses", "-test.v")
	command.Env = append(os.Environ(), "SHUTTLE_FILESTORE_LOCK_HELPER=1", "SHUTTLE_FILESTORE_LOCK_PATH="+store.Path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("lock helper unexpectedly acquired the state lock: %v\n%s", err, output)
	}
}

func TestSlowCollectorAndNotifierAreBounded(t *testing.T) {
	cfg := enabledMonitoringConfig(t)
	cfg.TimeoutSeconds = 1
	engine := New("demo", cfg, Adapters{Now: time.Now})
	started := time.Now()
	result := engine.runCheck(context.Background(), "slow", "Slow", "test", func(context.Context) (string, string, map[string]any) {
		time.Sleep(2 * time.Second)
		return StateHealthy, "late", nil
	})
	if elapsed := time.Since(started); elapsed >= 1500*time.Millisecond || result.State != StateUnavailable {
		t.Fatalf("slow collector exceeded its bound: elapsed=%s result=%#v", elapsed, result)
	}

	now := time.Now().UTC()
	manager := AlertManager{Store: &MemoryStore{}, Notifier: &slowNotifier{}, FailureLog: filepath.Join(privateRuntimeDir(t), "delivery-failures.jsonl"), Retries: 1, Debounce: 0, NotifyTimeout: 30 * time.Millisecond, Now: func() time.Time { return now }}
	started = time.Now()
	state, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now)))
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond || err == nil || len(state.Pending) != 1 {
		t.Fatalf("slow notifier exceeded its bound or lost pending state: elapsed=%s state=%#v err=%v", elapsed, state, err)
	}
}

func TestInstalledCyclePersistsPartialReportWithinOneBudget(t *testing.T) {
	stateDir := privateRuntimeDir(t)
	cfg := enabledMonitoringConfig(t)
	cfg.StateDir = stateDir
	cfg.IntervalSeconds = 1
	cfg.TimeoutSeconds = 1
	cfg.Notifications.WebhookEnv = "SHUTTLE_MONITORING_TEST_WEBHOOK"
	cfg.Notifications.Retries = 3
	cfg.Notifications.RetryDelaySeconds = 1
	cfg.Notifications.DebounceSeconds = 1
	t.Setenv("SHUTTLE_MONITORING_TEST_WEBHOOK", "https://notify.example.test/alerts")
	incidentTime := time.Now().UTC().Add(-2 * time.Minute)
	incidentID := incidentTime.Format(time.RFC3339Nano)
	if err := (FileStore{Path: filepath.Join(stateDir, "incidents.json")}).Save(context.Background(), IncidentState{
		Schema: incidentSchema,
		Incidents: map[string]Incident{"services.application": {
			CheckID: "services.application", EpisodeID: incidentID, State: StateActive,
			FirstSeen: incidentID, LastSeen: incidentID, PendingSince: incidentID,
			LastFailureState: StateDegraded, LastFailureSummary: "stored failure",
		}},
		Episodes: map[string]Incident{}, Pending: []AlertEvent{},
	}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	report, err := RunInstalled(context.Background(), InstalledConfig{App: "demo", Monitoring: cfg}, Adapters{
		Run: func(ctx context.Context, _ ...string) ([]byte, error) {
			select {
			case <-time.After(100 * time.Millisecond):
				return nil, errors.New("synthetic collector failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		HTTP: blockingHTTPDoer{},
		Read: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Statfs: func(string) (DiskStats, error) {
			return DiskStats{Blocks: 100, Bavail: 100, Files: 100, Ffree: 100}, nil
		},
		Now: time.Now,
	})
	if report.Schema != Schema || report.CheckedAt == "" || err == nil {
		t.Fatalf("installed cycle did not return a dated report and delivery error: report=%#v err=%v", report, err)
	}
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Fatalf("installed cycle exceeded its total budget: %s", elapsed)
	}
	state, loadErr := (FileStore{Path: filepath.Join(stateDir, "incidents.json")}).Load(context.Background())
	if loadErr != nil || state.LastReport == nil || state.LastReport.CheckedAt != report.CheckedAt {
		t.Fatalf("partial report was not durably retained: state=%#v err=%v", state, loadErr)
	}
}

func TestMissingWebhookFailsRunAndStatusReportsDeliveryIncident(t *testing.T) {
	cfg := enabledMonitoringConfig(t)
	cfg.Notifications.WebhookEnv = "SHUTTLE_MONITORING_TEST_MISSING_WEBHOOK"
	t.Setenv(cfg.Notifications.WebhookEnv, "")
	installed := InstalledConfig{App: "demo", Monitoring: cfg}
	now := time.Now().UTC()
	manager := AlertManager{Store: &MemoryStore{}, Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	manager.NotifierFactory = func() (Notifier, error) { return ConfiguredNotifier(cfg, nil) }
	state, runErr := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now)))
	if runErr == nil || state.LastReport == nil {
		t.Fatalf("missing runtime channel did not fail the run with a report: state=%#v err=%v", state, runErr)
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	status, statusErr := ReadLatest(installed, func(string) ([]byte, error) { return body, nil }, time.Now().UTC())
	if statusErr != nil {
		t.Fatalf("status could not read the persisted incident report: %v", statusErr)
	}
	for _, check := range status.Checks {
		if check.ID == "notifications.delivery" && check.State == StateUnavailable {
			return
		}
	}
	t.Fatalf("status omitted the unavailable notification incident: %#v", status)
}

func TestInstalledCycleFinalizesReportAfterCallerDeadline(t *testing.T) {
	stateDir := privateRuntimeDir(t)
	cfg := enabledMonitoringConfig(t)
	cfg.StateDir = stateDir
	cfg.IntervalSeconds = 1
	cfg.TimeoutSeconds = 1
	cfg.Notifications.WebhookEnv = "SHUTTLE_MONITORING_TEST_DEADLINE_WEBHOOK"
	cfg.Notifications.Retries = 1
	cfg.Notifications.DebounceSeconds = 0
	t.Setenv("SHUTTLE_MONITORING_TEST_DEADLINE_WEBHOOK", "https://notify.example.test/deadline")
	incidentTime := time.Now().UTC().Add(-2 * time.Minute)
	incidentID := incidentTime.Format(time.RFC3339Nano)
	if err := (FileStore{Path: filepath.Join(stateDir, "incidents.json")}).Save(context.Background(), IncidentState{
		Schema: incidentSchema,
		Incidents: map[string]Incident{"services.application": {
			CheckID: "services.application", EpisodeID: incidentID, State: StateActive,
			FirstSeen: incidentID, LastSeen: incidentID, PendingSince: incidentID,
			LastFailureState: StateDegraded, LastFailureSummary: "stored failure",
		}},
		Episodes: map[string]Incident{}, Pending: []AlertEvent{},
	}); err != nil {
		t.Fatal(err)
	}
	var notifies atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	report, err := RunInstalled(ctx, InstalledConfig{App: "demo", Monitoring: cfg}, Adapters{
		Run: func(context.Context, ...string) ([]byte, error) {
			time.Sleep(100 * time.Millisecond)
			return nil, errors.New("late collector failure")
		},
		Read: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Statfs: func(string) (DiskStats, error) {
			return DiskStats{Blocks: 100, Bavail: 100, Files: 100, Ffree: 100}, nil
		},
		HTTP: notifyCountingDoer{count: &notifies},
		Now:  time.Now,
	})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("caller deadline was not observed: %s", elapsed)
	}
	if report.Schema != Schema || report.CheckedAt == "" || err == nil {
		t.Fatalf("expired caller context lost the dated report: report=%#v err=%v", report, err)
	}
	if _, marshalErr := MarshalReport(report); marshalErr != nil {
		t.Fatalf("dated report was not framed as JSON: %v", marshalErr)
	}
	state, loadErr := (FileStore{Path: filepath.Join(stateDir, "incidents.json")}).Load(context.Background())
	if loadErr != nil || state.LastReport == nil || state.LastReport.CheckedAt != report.CheckedAt {
		t.Fatalf("expired caller context did not persist partial report: state=%#v err=%v", state, loadErr)
	}
	if notifies.Load() != 0 {
		t.Fatalf("notification was delivered after the caller deadline: %d", notifies.Load())
	}
}

func TestExternalInstalledCycleUsesTheSameDeadlineForDelivery(t *testing.T) {
	stateDir := privateRuntimeDir(t)
	cfg := enabledMonitoringConfig(t)
	cfg.IntervalSeconds = 1
	cfg.TimeoutSeconds = 1
	cfg.External.URL = "https://probe.example.test/health"
	cfg.External.StateDir = stateDir
	cfg.External.TimeoutSeconds = 1
	cfg.External.WebhookEnv = "SHUTTLE_MONITORING_TEST_EXTERNAL_WEBHOOK"
	cfg.Notifications.Retries = 2
	cfg.Notifications.RetryDelaySeconds = 1
	t.Setenv("SHUTTLE_MONITORING_TEST_EXTERNAL_WEBHOOK", "https://notify.example.test/external")
	incidentTime := time.Now().UTC().Add(-2 * time.Minute)
	incidentID := incidentTime.Format(time.RFC3339Nano)
	if err := (FileStore{Path: filepath.Join(stateDir, "incidents.json")}).Save(context.Background(), IncidentState{
		Schema: incidentSchema,
		Incidents: map[string]Incident{"external.https": {
			CheckID: "external.https", EpisodeID: incidentID, State: StateActive,
			FirstSeen: incidentID, LastSeen: incidentID, PendingSince: incidentID,
			LastFailureState: StateUnavailable, LastFailureSummary: "stored external failure",
		}},
		Episodes: map[string]Incident{}, Pending: []AlertEvent{},
	}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	report, err := RunExternalInstalled(context.Background(), InstalledConfig{App: "demo", Monitoring: cfg}, Adapters{
		HTTP: blockingHTTPDoer{},
		Now:  time.Now,
	})
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Fatalf("external cycle exceeded its delivery deadline: %s", elapsed)
	}
	if report.Schema != Schema || report.Scope != ScopeExternal || err == nil {
		t.Fatalf("external cycle did not retain its report and delivery error: report=%#v err=%v", report, err)
	}
	state, loadErr := (FileStore{Path: filepath.Join(stateDir, "incidents.json")}).Load(context.Background())
	if loadErr != nil || state.LastReport == nil || state.LastReport.CheckedAt != report.CheckedAt {
		t.Fatalf("external partial report was not durably retained: state=%#v err=%v", state, loadErr)
	}
}

type blockingHTTPDoer struct{}

func (blockingHTTPDoer) Do(request *http.Request) (*http.Response, error) {
	<-request.Context().Done()
	return nil, request.Context().Err()
}

type sentinelNotifier struct {
	err error
}

func (n *sentinelNotifier) Notify(context.Context, Notification) error { return n.err }

type failOnCallNotifier struct {
	events   []Notification
	failCall int
	call     int
}

func (n *failOnCallNotifier) Notify(ctx context.Context, event Notification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.call++
	n.events = append(n.events, event)
	if n.call == n.failCall {
		return errors.New("synthetic delivery failure")
	}
	return nil
}

type slowNotifier struct{}

func (*slowNotifier) Notify(ctx context.Context, _ Notification) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func TestWebhook500Then204IncidentRecoveryDedupsAcrossFileStoreRestart(t *testing.T) {
	var statuses []int
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("unexpected method %s", request.Method)
		}
		status := http.StatusNoContent
		if len(statuses) < 2 {
			status = http.StatusInternalServerError
		}
		statuses = append(statuses, status)
		writer.WriteHeader(status)
	}))
	t.Cleanup(server.Close)

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	dir := privateRuntimeDir(t)
	store := FileStore{Path: filepath.Join(dir, "incidents.json")}
	notifier := WebhookNotifier{URL: server.URL, Client: server.Client()}
	manager := AlertManager{Store: store, Notifier: notifier, FailureLog: filepath.Join(dir, "delivery-failures.jsonl"), Retries: 3, RetryDelay: time.Millisecond, Debounce: 0, Now: func() time.Time { return now }}
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 3 || statuses[0] != http.StatusInternalServerError || statuses[1] != http.StatusInternalServerError || statuses[2] != http.StatusNoContent {
		t.Fatalf("incident sequence was not 500/500/204: %v", statuses)
	}
	now = now.Add(time.Minute)
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now))); err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 4 || statuses[3] != http.StatusNoContent {
		t.Fatalf("recovery was not delivered as 204: %v", statuses)
	}
	restarted := AlertManager{Store: FileStore{Path: store.Path}, Notifier: notifier, FailureLog: manager.FailureLog, Retries: 3, Debounce: 0, Now: func() time.Time { return now }}
	state, err := restarted.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now)))
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 4 {
		t.Fatalf("restart replayed acknowledged webhook events: %v", statuses)
	}
	if !state.Incidents["services.application"].RecoverySent || state.Incidents["services.application"].RecoveryPending {
		t.Fatalf("rehydrated FileStore lost recovery acknowledgement: %#v", state)
	}
	if state.Incidents["services.application"].EpisodeID == "" {
		t.Fatal("episode identity was not rehydrated")
	}
}

func TestRuntimeLockIdentitySurvivesAncestorSwap(t *testing.T) {
	base := privateRuntimeDir(t)
	original := filepath.Join(base, "runtime")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(original, 0o700); err != nil {
		t.Fatal(err)
	}
	store := FileStore{Path: filepath.Join(original, "incidents.json")}
	session, err := store.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Save(context.Background(), emptyIncidentState()); err != nil {
		t.Fatal(err)
	}

	displaced := original + ".displaced"
	if err := os.Rename(original, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(original, 0o700); err != nil {
		t.Fatal(err)
	}

	replacement := FileStore{Path: filepath.Join(original, "incidents.json")}
	replacementUnlock, err := replacement.Lock(context.Background())
	if err != nil {
		t.Fatalf("replacement tree should have its own lock identity: %v", err)
	}
	replacementUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := (FileStore{Path: filepath.Join(displaced, "incidents.json")}).Lock(ctx); err == nil {
		t.Fatal("ancestor swap redirected another process onto the held lock")
	}

	updated := emptyIncidentState()
	updated.UpdatedAt = "after-swap"
	if err := session.Save(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(original, "incidents.json")); !os.IsNotExist(err) {
		t.Fatal("held session followed the swapped ancestor")
	}
	loaded, err := (FileStore{Path: filepath.Join(displaced, "incidents.json")}).Load(context.Background())
	if err != nil || loaded.UpdatedAt != "after-swap" {
		t.Fatalf("held session did not stay on the original directory: %#v %v", loaded, err)
	}
}

func TestCancelStopsFurtherNotifications(t *testing.T) {
	dir := privateRuntimeDir(t)
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	block := make(chan struct{})
	notifier := notifyFunc(func(ctx context.Context, event Notification) error {
		n := calls.Add(1)
		if n == 1 {
			close(firstStarted)
			select {
			case <-block:
			case <-ctx.Done():
				return ctx.Err()
			}
			return ctx.Err()
		}
		return errors.New("notification after cancel")
	})
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	manager := AlertManager{Store: FileStore{Path: filepath.Join(dir, "incidents.json")}, Notifier: notifier, FailureLog: filepath.Join(dir, "delivery-failures.jsonl"), Retries: 1, Debounce: 0, NotifyTimeout: time.Second, Now: func() time.Time { return now }}
	t.Cleanup(func() { joinRuntimeTransactionForTest(t, filepath.Join(dir, "incidents.json"), block) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := manager.Process(ctx, alertReport(alertCheck("services.application", StateDegraded, now), alertCheck("services.docker", StateDegraded, now)))
		done <- err
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first notification was never started")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled process returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled process did not return")
	}
	close(block)
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("cancelled process started further notifications: %d", calls.Load())
	}
}

// A caller can return on deadline while its filesystem worker is still
// finalizing. Tests must join that worker before restoring global hooks or
// deleting its private directory; acquiring flock does not synchronize Go memory.
func joinRuntimeTransactionForTest(t *testing.T, path string, release chan struct{}) {
	t.Helper()
	select {
	case <-release:
	default:
		close(release)
	}
	transactionMu.Lock()
	slot := inflightTransactions[filepath.Clean(path)]
	transactionMu.Unlock()
	if slot == nil {
		return
	}
	select {
	case <-slot.done:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime worker did not finish before fixture cleanup")
	}
}

func TestBlockedFsyncKeepsLockUntilWorkerCloses(t *testing.T) {
	dir := privateRuntimeDir(t)
	path := filepath.Join(dir, "incidents.json")
	store := FileStore{Path: path}
	if err := store.Save(context.Background(), emptyIncidentState()); err != nil {
		t.Fatal(err)
	}
	oldSync := runtimeSync
	release := make(chan struct{})
	inSync := make(chan struct{})
	var blockedFirst atomic.Bool
	runtimeSync = func(file *os.File) error {
		if blockedFirst.CompareAndSwap(false, true) {
			close(inSync)
			<-release
		}
		return oldSync(file)
	}
	t.Cleanup(func() {
		joinRuntimeTransactionForTest(t, path, release)
		runtimeSync = oldSync
	})

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	manager := AlertManager{Store: store, Notifier: &recordingNotifier{}, FailureLog: filepath.Join(dir, "delivery-failures.jsonl"), Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := manager.Process(ctx, alertReport(alertCheck("services.application", StateDegraded, now)))
		done <- err
	}()
	select {
	case <-inSync:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach fsync")
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrPersistenceUnconfirmed) && !errors.Is(err, ErrTransactionTimeout) {
			t.Fatalf("caller did not return a typed timeout: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller did not return while fsync was blocked")
	}

	busyCtx, busyCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer busyCancel()
	if err := (FileStore{Path: path}).Save(busyCtx, emptyIncidentState()); err == nil {
		t.Fatal("second FileStore wrote while the worker still held the flock")
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		lockCtx, lockCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		unlock, lockErr := (FileStore{Path: path}).Lock(lockCtx)
		lockCancel()
		if lockErr == nil {
			unlock()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not release the flock after fsync: %v", lockErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	loaded, err := (FileStore{Path: path}).Load(context.Background())
	if err != nil || loaded.Incidents["services.application"].State != StateActive {
		t.Fatalf("committed state was not visible after fsync released: %#v %v", loaded, err)
	}
}

func TestBlockedRenameDoesNotClaimDurableSuccess(t *testing.T) {
	dir := privateRuntimeDir(t)
	path := filepath.Join(dir, "incidents.json")
	store := FileStore{Path: path}
	if err := store.Save(context.Background(), emptyIncidentState()); err != nil {
		t.Fatal(err)
	}
	oldDirectorySync := runtimeDirectorySync
	release := make(chan struct{})
	inSync := make(chan struct{})
	var blockedFirst atomic.Bool
	runtimeDirectorySync = func(root *os.Root) error {
		if blockedFirst.CompareAndSwap(false, true) {
			close(inSync)
			<-release
		}
		return oldDirectorySync(root)
	}
	t.Cleanup(func() {
		joinRuntimeTransactionForTest(t, path, release)
		runtimeDirectorySync = oldDirectorySync
	})

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	manager := AlertManager{Store: store, Notifier: &recordingNotifier{}, FailureLog: filepath.Join(dir, "delivery-failures.jsonl"), Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := manager.Process(ctx, alertReport(alertCheck("services.application", StateDegraded, now)))
		done <- err
	}()
	select {
	case <-inSync:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach post-rename directory sync")
	}
	err := <-done
	if !errors.Is(err, ErrPersistenceUnconfirmed) {
		t.Fatalf("rename-in-flight timeout claimed durable success: %v", err)
	}
	close(release)
}

func TestRepeatedExpiredCallsDoNotSpawnExtraWorkers(t *testing.T) {
	dir := privateRuntimeDir(t)
	path := filepath.Join(dir, "incidents.json")
	store := FileStore{Path: path}
	if err := store.Save(context.Background(), emptyIncidentState()); err != nil {
		t.Fatal(err)
	}
	oldSync := runtimeSync
	release := make(chan struct{})
	inSync := make(chan struct{}, 1)
	var syncs atomic.Int32
	var blockedFirst atomic.Bool
	runtimeSync = func(file *os.File) error {
		syncs.Add(1)
		if blockedFirst.CompareAndSwap(false, true) {
			select {
			case inSync <- struct{}{}:
			default:
			}
			<-release
		}
		return oldSync(file)
	}
	t.Cleanup(func() {
		joinRuntimeTransactionForTest(t, path, release)
		runtimeSync = oldSync
	})

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	manager := AlertManager{Store: store, Notifier: &recordingNotifier{}, FailureLog: filepath.Join(dir, "delivery-failures.jsonl"), Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	firstDone := make(chan struct{})
	go func() {
		_, _ = manager.Process(ctx, alertReport(alertCheck("services.application", StateDegraded, now)))
		close(firstDone)
	}()
	select {
	case <-inSync:
	case <-time.After(time.Second):
		t.Fatal("first worker did not start")
	}
	expired, expire := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer expire()
	<-expired.Done()
	for range 8 {
		_, err := manager.Process(expired, alertReport(alertCheck("services.application", StateDegraded, now)))
		if !errors.Is(err, ErrTransactionTimeout) && !errors.Is(err, ErrPersistenceUnconfirmed) {
			t.Fatalf("expired call did not stay on the inflight worker: %v", err)
		}
	}
	if syncs.Load() != 1 {
		t.Fatalf("repeated expired calls spawned extra workers: %d", syncs.Load())
	}
	close(release)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first worker did not finish after fsync was released")
	}
}

func TestUnsafeMaintenanceReturnsReportWithoutNotifications(t *testing.T) {
	dir := privateRuntimeDir(t)
	cfg := enabledMonitoringConfig(t)
	cfg.StateDir = dir
	cfg.Notifications.WebhookEnv = "SHUTTLE_MONITORING_TEST_MAINT_WEBHOOK"
	t.Setenv("SHUTTLE_MONITORING_TEST_MAINT_WEBHOOK", "https://notify.example.test/alerts")
	if err := os.WriteFile(filepath.Join(dir, "maintenance.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "maintenance.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var notifies atomic.Int32
	report, err := RunInstalled(context.Background(), InstalledConfig{App: "demo", Monitoring: cfg}, Adapters{
		Run: healthyRunner,
		Statfs: func(string) (DiskStats, error) {
			return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
		},
		Read: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		HTTP: notifyCountingDoer{count: &notifies},
		Now:  time.Now,
	})
	if report.Schema != Schema || report.CheckedAt == "" || err == nil {
		t.Fatalf("corrupt maintenance did not keep the collected report: report=%#v err=%v", report, err)
	}
	if !errors.Is(err, errMaintenanceUnreadable) {
		t.Fatalf("corrupt maintenance was treated as absent: %v", err)
	}
	if notifies.Load() != 0 {
		t.Fatalf("notifications started despite unreadable maintenance: %d", notifies.Load())
	}

	if err := os.Remove(filepath.Join(dir, "maintenance.json")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "maintenance.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = RunInstalled(context.Background(), InstalledConfig{App: "demo", Monitoring: cfg}, Adapters{
		Run: healthyRunner,
		Statfs: func(string) (DiskStats, error) {
			return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
		},
		Read: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		HTTP: notifyCountingDoer{count: &notifies},
		Now:  time.Now,
	})
	if report.CheckedAt == "" || !errors.Is(err, errMaintenanceUnreadable) {
		t.Fatalf("FIFO maintenance was treated as absent: report=%#v err=%v", report, err)
	}
	state, loadErr := (FileStore{Path: filepath.Join(dir, "incidents.json")}).Load(context.Background())
	if loadErr != nil || state.LastReport == nil || state.LastReport.CheckedAt == "" {
		t.Fatalf("unreadable maintenance discarded the collected report: %#v %v", state, loadErr)
	}
}

func TestInvalidMaintenanceUntilDoesNotClearWindowOrNotify(t *testing.T) {
	dir := privateRuntimeDir(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	until := now.Add(time.Hour).Format(time.RFC3339Nano)
	store := FileStore{Path: filepath.Join(dir, "incidents.json")}
	if err := store.Save(context.Background(), IncidentState{Schema: incidentSchema, Incidents: map[string]Incident{}, Pending: []AlertEvent{}, MaintenanceUntil: until, LastReport: &Report{Schema: Schema, App: "demo", State: StateHealthy, CheckedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maintenance.json"), []byte(`{"until":"not-a-timestamp"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := enabledMonitoringConfig(t)
	cfg.StateDir = dir
	cfg.Notifications.WebhookEnv = "SHUTTLE_MONITORING_TEST_INVALID_MAINT"
	t.Setenv("SHUTTLE_MONITORING_TEST_INVALID_MAINT", "https://notify.example.test/alerts")
	var notifies atomic.Int32
	_, err := RunInstalled(context.Background(), InstalledConfig{App: "demo", Monitoring: cfg}, Adapters{
		Run: healthyRunner,
		Statfs: func(string) (DiskStats, error) {
			return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
		},
		Read: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		HTTP: notifyCountingDoer{count: &notifies},
		Now:  func() time.Time { return now },
	})
	if !errors.Is(err, errMaintenanceUnreadable) {
		t.Fatalf("invalid until was treated as cleared: %v", err)
	}
	if notifies.Load() != 0 {
		t.Fatalf("invalid until started notifications: %d", notifies.Load())
	}
	state, loadErr := store.Load(context.Background())
	if loadErr != nil || state.MaintenanceUntil != until {
		t.Fatalf("invalid until cleared the existing window: %#v %v", state, loadErr)
	}
}

func TestOlderCheckedAtDoesNotReplayNotifications(t *testing.T) {
	dir := privateRuntimeDir(t)
	newer := time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC)
	older := newer.Add(-time.Minute)
	path := filepath.Join(dir, "incidents.json")
	notifier := &recordingNotifier{}
	store := FileStore{Path: path}
	if _, err := (AlertManager{Store: store, Notifier: notifier, Debounce: 0, Now: func() time.Time { return newer }}).Process(context.Background(), alertReport(alertCheck("services.docker", StateDegraded, newer))); err != nil {
		t.Fatal(err)
	}
	first := len(notifier.Events())
	if first == 0 {
		t.Fatal("newer cycle did not enqueue an incident")
	}
	olderReport := alertReport(alertCheck("services.docker", StateHealthy, older))
	olderReport.CheckedAt = older.Format(time.RFC3339Nano)
	if _, err := (AlertManager{Store: store, Notifier: notifier, Debounce: 0, Now: func() time.Time { return older }}).Process(context.Background(), olderReport); err != nil {
		t.Fatal(err)
	}
	if len(notifier.Events()) != first {
		t.Fatalf("older cycle replayed notifications: %#v", notifier.Events())
	}
	state, err := store.Load(context.Background())
	if err != nil || state.LastReport == nil || state.LastReport.CheckedAt != newer.Format(time.RFC3339Nano) {
		t.Fatalf("older cycle overwrote the newer report: %#v %v", state, err)
	}
}

func TestAcknowledgedEpisodesAreArchivedWithoutDroppingPending(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	dir := privateRuntimeDir(t)
	path := filepath.Join(dir, "incidents.json")
	notifier := &recordingNotifier{}
	manager := AlertManager{Store: FileStore{Path: path}, Notifier: notifier, Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now))); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err != nil {
		t.Fatal(err)
	}
	state, err := (FileStore{Path: path}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Episodes) != 0 {
		t.Fatalf("acknowledged historical episode was not archived: %#v", state)
	}
	if state.Incidents["services.application"].State != StateActive || len(state.Pending) != 0 {
		t.Fatalf("current episode was not preserved: %#v", state)
	}
	archive, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil || !strings.Contains(string(archive), `"check_id":"services.application"`) {
		t.Fatalf("archive was not written: %s %v", archive, err)
	}
	firstArchive := string(archive)
	if err := manager.Store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil || string(second) != firstArchive {
		t.Fatalf("archive rewrite was not idempotent: %s", second)
	}

	failing := &alwaysFailNotifier{}
	now = now.Add(time.Minute)
	failed, err := AlertManager{Store: FileStore{Path: path}, Notifier: failing, FailureLog: filepath.Join(dir, "delivery-failures.jsonl"), Retries: 1, Debounce: 0, Now: func() time.Time { return now }}.Process(context.Background(), alertReport(alertCheck("services.docker", StateDegraded, now)))
	if err == nil || len(failed.Pending) != 1 {
		t.Fatalf("unacknowledged incident was not preserved: %#v %v", failed, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxIncidentStateBytes {
		t.Fatalf("active state exceeded the reader limit: %v %#v", err, info)
	}
}

func TestInstalledCycleRunsCollectionLockAndNotifierRetries(t *testing.T) {
	dir := privateRuntimeDir(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) < 2 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	cfg := enabledMonitoringConfig(t)
	cfg.StateDir = dir
	cfg.TimeoutSeconds = 2
	cfg.IntervalSeconds = 1
	cfg.Notifications.WebhookEnv = "SHUTTLE_MONITORING_TEST_CYCLE_WEBHOOK"
	cfg.Notifications.Retries = 2
	cfg.Notifications.RetryDelaySeconds = 0
	cfg.Notifications.DebounceSeconds = 0
	t.Setenv("SHUTTLE_MONITORING_TEST_CYCLE_WEBHOOK", server.URL)
	now := time.Now().UTC().Add(-2 * time.Minute)
	incidentID := now.Format(time.RFC3339Nano)
	if err := (FileStore{Path: filepath.Join(dir, "incidents.json")}).Save(context.Background(), IncidentState{
		Schema: incidentSchema,
		Incidents: map[string]Incident{"services.application": {
			CheckID: "services.application", EpisodeID: incidentID, State: StateActive,
			FirstSeen: incidentID, LastSeen: incidentID, PendingSince: incidentID,
			LastFailureState: StateDegraded, LastFailureSummary: "stored failure",
		}},
		Episodes: map[string]Incident{}, Pending: []AlertEvent{},
	}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	report, err := RunInstalled(context.Background(), InstalledConfig{App: "demo", Monitoring: cfg}, Adapters{
		Run:  healthyRunner,
		HTTP: server.Client(),
		Read: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Statfs: func(string) (DiskStats, error) {
			return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
		},
		Now: time.Now,
	})
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Fatalf("installed cycle exceeded elapsed bound: %s", elapsed)
	}
	if report.Schema != Schema || report.CheckedAt == "" {
		t.Fatalf("installed cycle lost its report: %#v", report)
	}
	if err != nil {
		t.Fatalf("installed cycle failed after notifier retry: %v", err)
	}
	if requests.Load() < 2 {
		t.Fatalf("notifier retries were not executed: %d", requests.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "incidents.json.lock")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

type notifyFunc func(context.Context, Notification) error

func (f notifyFunc) Notify(ctx context.Context, event Notification) error {
	return f(ctx, event)
}

type notifyCountingDoer struct {
	count *atomic.Int32
}

func (d notifyCountingDoer) Do(request *http.Request) (*http.Response, error) {
	d.count.Add(1)
	return nil, errors.New("notification should not have been attempted")
}

func TestOversizedIncidentStateIsRejectedBeforeCommit(t *testing.T) {
	dir := privateRuntimeDir(t)
	path := filepath.Join(dir, "incidents.json")
	store := FileStore{Path: path}
	if err := store.Save(context.Background(), emptyIncidentState()); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	state := emptyIncidentState()
	state.Pending = []AlertEvent{{ID: strings.Repeat("x", int(maxIncidentStateBytes)), Kind: "incident", CheckID: "services.application", App: "demo"}}
	if err := store.Save(context.Background(), state); err == nil {
		t.Fatal("oversized state was committed")
	}
	assertStateBytesUnchanged(t, path, original)
}

type capturingDoer struct{ body []byte }

func (c *capturingDoer) Do(request *http.Request) (*http.Response, error) {
	c.body, _ = io.ReadAll(request.Body)
	return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
}

// A Discord or Slack webhook needs a human line (content / text); the generic
// fields stay for any other receiver.
func TestWebhookPayloadCarriesChatLineAndNotificationFields(t *testing.T) {
	doer := &capturingDoer{}
	notifier := WebhookNotifier{URL: "https://hooks.example.test/x", Client: doer}
	note := Notification{ID: "n1", Kind: "incident", App: "api", CheckID: "disk.images_registry", EpisodeID: "2026-10-28T09:41:52.132606066Z", State: "critical", Summary: "12% free on /var/lib/docker", CreatedAt: "2026-10-28T09:42:51Z"}
	if err := notifier.Notify(context.Background(), note); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Content   *string `json:"content"`
		Text      string  `json:"text"`
		CheckID   string  `json:"check_id"`
		EpisodeID string  `json:"episode_id"`
		State     string  `json:"state"`
		Embeds    []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Color       int    `json:"color"`
			Timestamp   string `json:"timestamp"`
			Fields      []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(doer.body, &got); err != nil {
		t.Fatal(err)
	}
	// Discord shows the embed only: no duplicated headline in content.
	if got.Content != nil || got.Text != "api: image disk critical. 12% free on /var/lib/docker" {
		t.Fatalf("content = %v, text = %q", got.Content, got.Text)
	}
	if got.CheckID != "disk.images_registry" || got.EpisodeID != note.EpisodeID || got.State != "critical" {
		t.Fatalf("notification fields lost: %s", doer.body)
	}
	if len(got.Embeds) != 1 {
		t.Fatalf("embeds = %s", doer.body)
	}
	embed := got.Embeds[0]
	if embed.Title != "api: image disk critical" || embed.Description != note.Summary || embed.Color != colorDown || embed.Timestamp != "2026-10-28T09:42:51Z" {
		t.Fatalf("embed = %+v", embed)
	}
	if len(embed.Fields) != 3 || embed.Fields[1].Value != "`disk.images_registry`" || embed.Fields[2].Value != "<t:1793180512:R>" {
		t.Fatalf("embed fields = %+v", embed.Fields)
	}
	recovery := notificationEmbed(Notification{Kind: "recovery", App: "api", CheckID: "services.application", State: StateHealthy, EpisodeID: "2026-10-28T09:41:52Z", CreatedAt: "2026-10-28T09:43:04Z"})
	if recovery.Title != "api: application service recovered" || recovery.Description != "Healthy again after 1m12s." || recovery.Color != colorRecovered {
		t.Fatalf("recovery embed = %+v", recovery)
	}
	if degraded := notificationColor(Notification{Kind: "incident", State: StateDegraded}); degraded != colorDegraded {
		t.Fatalf("degraded color = %x", degraded)
	}
	long := chatLine(Notification{Summary: strings.Repeat("é", 3000)})
	if utf8.RuneCountInString(long) != chatMessageLimit || !utf8.ValidString(long) {
		t.Fatalf("long line not bounded on a rune boundary: %d runes", utf8.RuneCountInString(long))
	}
}

// One sample taken mid-rollout (demo prod, 2026-10-28 10:41:52, a new task
// still starting) between two healthy ones must never page, whatever the gap
// between samples. Two consecutive bad samples spanning the debounce do.
func TestSingleBadSampleBetweenHealthyOnesNeverPages(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 40, 50, 0, time.UTC)
	notifier := &recordingNotifier{}
	manager := AlertManager{Store: &MemoryStore{}, Notifier: notifier, Retries: 1, Debounce: 30 * time.Second, Now: func() time.Time { return now }}
	sample := func(state string) IncidentState {
		t.Helper()
		got, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", state, now)))
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
		return got
	}
	sample(StateHealthy)
	sample(StateDegraded)
	sample(StateHealthy)
	if len(notifier.events) != 0 {
		t.Fatalf("a single bad sample paged: %+v", notifier.events)
	}
	sample(StateHealthy) // a healthy baseline record, created before the failure
	baselineEpisode := now
	sample(StateDegraded)
	state := sample(StateDegraded)
	if len(notifier.events) != 1 || notifier.events[0].Kind != "incident" {
		t.Fatalf("a failure seen across the debounce did not page: %+v", notifier.events)
	}
	// The episode starts at the failure, not when the healthy record was made.
	if got := state.Incidents["services.application"].EpisodeID; got != baselineEpisode.Format(time.RFC3339Nano) {
		t.Fatalf("episode id = %s, want %s", got, baselineEpisode.Format(time.RFC3339Nano))
	}
}
