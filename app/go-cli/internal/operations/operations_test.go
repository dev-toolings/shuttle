package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testCoordinator(t *testing.T, now *time.Time, boot string) *Coordinator {
	t.Helper()
	root := t.TempDir()
	return New(Options{
		Root: root, LockPath: root + "/root.lock", LockWait: time.Second,
		Now: func() time.Time { return *now }, BootID: func() (string, error) { return boot, nil },
	})
}

func TestReserveSerializesApplicationAndGlobalMutations(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	boot := "boot-a"
	c := New(Options{Root: root, LockPath: root + "/root.lock", LockWait: time.Second, Now: func() time.Time { return now }, BootID: func() (string, error) { return boot, nil }})
	first, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator-a"})
	if err != nil {
		t.Fatal(err)
	}
	defer first.NeedsRecovery("test cleanup")
	if _, err := c.Reserve(context.Background(), Request{Kind: "backup", App: "other", Principal: "operator-b"}); err == nil || !strings.Contains(err.Error(), first.ID()) {
		t.Fatalf("global mutation should report the active operation, got %v", err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "rollback", App: "demo", Principal: "operator-b"}); err == nil || !strings.Contains(err.Error(), "target demo") {
		t.Fatalf("same application mutation should report its target, got %v", err)
	}
}

func TestConcurrentReservationsHaveOneWinner(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	makeCoordinator := func() *Coordinator {
		return New(Options{Root: root, LockPath: root + "/root.lock", LockWait: time.Second, Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := makeCoordinator().Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
			if err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
				_ = h.NeedsRecovery("test cleanup")
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("concurrent reservations had %d winners, want one", winners)
	}
}

func TestApplicationOperationsOfDifferentApplicationsReserveTogether(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	demo, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator-a"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "other", Principal: "operator-b"})
	if err != nil {
		t.Fatalf("a deploy of another application must not wait for demo: %v", err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "run", App: "other", Principal: "operator-b"}); err == nil || !strings.Contains(err.Error(), other.ID()) {
		t.Fatalf("same application mutation must stay exclusive, got %v", err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "backup", App: "third", Principal: "operator-c"}); err == nil || !strings.Contains(err.Error(), " is active for ") {
		t.Fatalf("a global operation must wait for every live deploy, got %v", err)
	}
	if err := demo.NeedsRecovery("test"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator-a"}); err == nil || !strings.Contains(err.Error(), "requires recovery for deploy") {
		t.Fatalf("an unrecovered operation must not read as one worth waiting for, got %v", err)
	}
	_ = other.Complete("test")
}

// A helper update is the remedy for a helper whose recovery is broken, so an
// operation awaiting recovery must not refuse it. A live operation still does.
func TestHelperUpdateWaitsForLiveOperationsButNotForRecovery(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	blocked, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := blocked.NeedsRecovery("memory guard refused the promotion"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "backup", Principal: "operator-a"}); err == nil || !strings.Contains(err.Error(), "requires recovery for deploy") {
		t.Fatalf("other global operations must still wait for the recovery, got %v", err)
	}
	update, err := c.Reserve(context.Background(), Request{Kind: "helper-update", Principal: "operator-a"})
	if err != nil {
		t.Fatalf("a recovery_required deploy refused the helper update meant to repair its recovery: %v", err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "other", Principal: "operator-b"}); err == nil || !strings.Contains(err.Error(), update.ID()) {
		t.Fatalf("the helper update must stay exclusive while it is live, got %v", err)
	}
	if err := update.Complete("helper replaced"); err != nil {
		t.Fatal(err)
	}
	if record, err := c.Get(context.Background(), blocked.ID()); err != nil || record.State != RecoveryRequired || !record.RecoveryRequired {
		t.Fatalf("the helper update must leave the blocked deploy to recovery: %+v %v", record, err)
	}

	live, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "other", Principal: "operator-b"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "helper-update", Principal: "operator-a"}); err == nil || !strings.Contains(err.Error(), " is active for ") {
		t.Fatalf("a helper update must still wait for a live operation, got %v", err)
	}
	_ = live.Complete("test")
}

func TestConcurrentPhasesOfTwoApplicationsOverlap(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	owner := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	demo, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	other, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "other", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	demoDone := make(chan error, 1)
	go func() {
		request := phaseRequestFor(demo, "stack-apply", host)
		request.Concurrent = true
		demoDone <- c.ExecutePhase(context.Background(), request, func(context.Context, Record) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	otherDone := make(chan error, 1)
	go func() {
		request := PhaseRequest{ID: other.ID(), Kind: "deploy", App: "other", Principal: "operator", OwnerKeyFingerprint: owner, Host: host, Name: "stack-apply", Concurrent: true}
		otherDone <- c.ExecutePhase(context.Background(), request, func(context.Context, Record) error { return nil })
	}()
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("second application's phase failed while the first was running: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second application's phase waited for the first one")
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "run", App: "third", Principal: "operator"}); err != nil {
		t.Fatalf("a concurrent phase must not hold the journal flock across its callback: %v", err)
	}
	close(release)
	if err := <-demoDone; err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{demo.ID(), other.ID()} {
		if record, err := c.Get(context.Background(), id); err != nil || len(record.Phases) != 1 || record.Phases[0].EndedAt == "" || record.State != "active" {
			t.Fatalf("phase outcome of %s was not durably recorded: %+v %v", id, record, err)
		}
	}
}

func TestConcurrentPhaseRefusesGlobalKindAndHeldExecutorLock(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	c := New(Options{Root: root, LockPath: root + "/root.lock", LockWait: 250 * time.Millisecond, Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	owner := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	backup, err := c.Reserve(context.Background(), Request{Kind: "backup", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	request := PhaseRequest{ID: backup.ID(), Kind: "backup", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host, Name: "dump", Concurrent: true}
	if err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error { called = true; return nil }); err == nil || called || !strings.Contains(err.Error(), "only an application-scoped") {
		t.Fatalf("a global phase ran concurrently: err=%v called=%v", err, called)
	}
	if err := backup.Complete("test"); err != nil {
		t.Fatal(err)
	}

	demo, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(c.applicationLockPath("demo"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	request = phaseRequestFor(demo, "stack-apply", host)
	request.Concurrent = true
	if err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error { called = true; return nil }); err == nil || called || !strings.Contains(err.Error(), "earlier executor of application demo") {
		t.Fatalf("a phase ran beside an executor still holding the application lock: err=%v called=%v", err, called)
	}
	if record, err := c.Get(context.Background(), demo.ID()); err != nil || len(record.Phases) != 0 {
		t.Fatalf("a refused phase left a phase-start behind: %+v %v", record, err)
	}
}

func TestSoleOperationDefersWhileAnotherOperationIsLive(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	demo, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := c.WithSoleOperation(context.Background(), demo.ID(), func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("a lone operation was refused its exclusive section: err=%v calls=%d", err, calls)
	}
	other, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "other", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WithSoleOperation(context.Background(), demo.ID(), func() error { calls++; return nil }); !errors.Is(err, ErrOtherOperationsActive) || calls != 1 || !strings.Contains(err.Error(), other.ID()) {
		t.Fatalf("exclusive section ran beside another live operation: err=%v calls=%d", err, calls)
	}
}

func TestLegacyGlobalScopedDeployRecordLoadsAndBlocksEveryApplication(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	c := New(Options{Root: root, LockPath: root + "/root.lock", LockWait: time.Second, Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	legacy, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	path := root + "/" + legacy.ID() + ".json"
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(body), `"scope": "application"`, `"scope": "global"`, 1)
	if rewritten == string(body) {
		t.Fatal("fixture did not contain an application scope to rewrite")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(context.Background()); err != nil {
		t.Fatalf("a journal written by an older helper became unreadable: %v", err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "other", Principal: "operator"}); err == nil || !strings.Contains(err.Error(), legacy.ID()) {
		t.Fatalf("a live legacy global deploy must still exclude other applications, got %v", err)
	}
}

func TestRecoveryWaitsForAnotherLiveOperation(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	broken, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := broken.NeedsRecovery("client disconnected"); err != nil {
		t.Fatal(err)
	}
	live, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "other", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	observer := func(context.Context, Record) (RecoveryObservation, error) { return completeSafeObservation(), nil }
	plan, err := c.RecoveryPlan(context.Background(), broken.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	applier := func(context.Context, Record, RecoveryObservation) error { called = true; return nil }
	if _, err := c.ApplyRecoveryWith(context.Background(), broken.ID(), plan.PlanDigest, observer, applier); err == nil || called || !strings.Contains(err.Error(), live.ID()) {
		t.Fatalf("recovery touched the host beside a live promotion: err=%v called=%v", err, called)
	}
	if err := live.Complete("test"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), broken.ID(), plan.PlanDigest, observer, applier); err != nil || !called {
		t.Fatalf("recovery stayed refused once the host was quiet: err=%v called=%v", err, called)
	}
}

func TestReserveRejectsUnsupportedKind(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	if _, err := c.Reserve(context.Background(), Request{Kind: "future-operation", App: "demo", Principal: "operator"}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported operation kind was accepted: %v", err)
	}
}

func TestGeneratedOperationIDsUseUUIDShape(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Fatalf("operation ID is not a UUID: %q", id)
	}
}

func TestBootChangeMarksActiveOperationForRecovery(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	boot := "boot-a"
	c := New(Options{Root: root, LockPath: root + "/root.lock", LockWait: time.Second, Now: func() time.Time { return now }, BootID: func() (string, error) { return boot, nil }})
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	boot = "boot-b"
	if _, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"}); err == nil || !strings.Contains(err.Error(), h.ID()) {
		t.Fatalf("boot change should block new work until recovery, got %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || !record.RecoveryRequired {
		t.Fatalf("boot change left active operation usable: %+v", record)
	}
}

func TestRecoveryRequiresObservedPlanAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("client disconnected", "reconcile current and previous release"); err != nil {
		t.Fatal(err)
	}
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		return completeSafeObservation(), nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil || !strings.HasPrefix(plan.PlanDigest, "sha256:") {
		t.Fatalf("recovery plan invalid: %+v %v", plan, err)
	}
	applier := func(context.Context, Record, RecoveryObservation) error { return nil }
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), "sha256:wrong", observer, applier); err == nil {
		t.Fatal("recovery accepted an unrelated confirmation")
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer, applier); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer, applier); err != nil {
		t.Fatalf("repeating a successful recovery must be a no-op: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("unexpected recovered record: %+v %v", record, err)
	}
}

func completeSafeObservation() RecoveryObservation {
	return RecoveryObservation{
		Safe: true, ObservedAt: "2026-09-13T12:00:00Z", ProcessVersion: "docker-27",
		BootVersion: "boot-a", PhaseVersion: "phase-1", ResourceVersion: "resource-1",
		ExecutorProof: "process-table:0", Freshness: "2026-09-13T12:00:00Z",
		ServiceState: "previous release healthy", RegistryState: "healthy", DataState: "witnesses match",
		ManifestProof: "manifest:current=previous", MarkerProof: "marker:current=previous",
		ResourceProof: "resource:stable", ActionProof: "actions:verified",
	}
}

func phaseRequestFor(handle *Handle, name string, host string) PhaseRequest {
	return PhaseRequest{ID: handle.ID(), Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: host, Name: name}
}

func boundaryCoordinator(t *testing.T) (*Coordinator, *Handle, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{
		Kind: "deploy", App: "demo", Principal: "operator",
		OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43),
		Host:                "SHA256:" + strings.Repeat("B", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, h, now
}

func seedEvents(t *testing.T, c *Coordinator, h *Handle, now time.Time, count int) Record {
	t.Helper()
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.Events = make([]Event, count)
	for i := range record.Events {
		record.Events[i] = Event{At: now.Format(time.RFC3339Nano), Kind: "seed", State: record.State}
	}
	if err := c.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	record, err = c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func applyBoundaryRecovery(t *testing.T, c *Coordinator, h *Handle) Record {
	t.Helper()
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
		return completeSafeObservation(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
		func(context.Context, Record) (RecoveryObservation, error) { return completeSafeObservation(), nil },
		func(context.Context, Record, RecoveryObservation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("boundary recovery was not fully recorded: %+v", record)
	}
	return record
}

func TestJournalTransitionBudgetsPreserveReadableRecords(t *testing.T) {
	t.Run("phase refuses without outcome capacity", func(t *testing.T) {
		c, h, now := boundaryCoordinator(t)
		before := seedEvents(t, c, h, now, MaxJournalItems-1)
		called := false
		err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "overflow", h.host), func(context.Context, Record) error {
			called = true
			return nil
		})
		if err == nil || called || !strings.Contains(err.Error(), "event history") {
			t.Fatalf("phase ran without a complete event budget: err=%v called=%v", err, called)
		}
		after, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if after.Revision != before.Revision || after.State != "active" || len(after.Phases) != 0 || len(after.Events) != len(before.Events) {
			t.Fatalf("phase refusal changed the persisted record: before=%+v after=%+v", before, after)
		}
	})

	t.Run("normal phase then terminal outcome", func(t *testing.T) {
		c, h, now := boundaryCoordinator(t)
		seedEvents(t, c, h, now, MaxJournalItems-executePhaseEventBudget)
		if err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "last", h.host), func(context.Context, Record) error { return nil }); err != nil {
			t.Fatal(err)
		}
		phaseRecord, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if phaseRecord.State != "active" || len(phaseRecord.Phases) != 1 || phaseRecord.Phases[0].EndedAt == "" || len(phaseRecord.Events) != MaxJournalItems-activeIdleEventBudget {
			t.Fatalf("normal phase boundary was not readable: %+v", phaseRecord)
		}
		if err := h.Complete("complete at boundary"); err != nil {
			t.Fatal(err)
		}
		terminal, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if terminal.State != "completed" || len(terminal.Events) != MaxJournalItems-activeIdleEventBudget+1 {
			t.Fatalf("terminal boundary was not recorded: %+v", terminal)
		}
	})

	t.Run("error outcome then recovery", func(t *testing.T) {
		c, h, now := boundaryCoordinator(t)
		seedEvents(t, c, h, now, MaxJournalItems-executePhaseEventBudget)
		err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "fails", h.host), func(context.Context, Record) error {
			return errors.New("phase failed at boundary")
		})
		if err == nil {
			t.Fatal("phase failure was unexpectedly hidden")
		}
		failed, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if failed.State != RecoveryRequired || !failed.RecoveryRequired || len(failed.Events) != MaxJournalItems-activeIdleEventBudget || len(failed.Phases) != 1 || failed.Phases[0].EndedAt == "" {
			t.Fatalf("failed phase boundary was not readable: %+v", failed)
		}
		applyBoundaryRecovery(t, c, h)
	})

	t.Run("watchdog outcome then recovery", func(t *testing.T) {
		c, h, now := boundaryCoordinator(t)
		seedEvents(t, c, h, now, MaxJournalItems-executePhaseEventBudget)
		request := phaseRequestFor(h, "watchdog", h.host)
		err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error {
			return c.MarkWatchdogRecoveryForPhase(request, "watchdog stopped phase", "inspect current release")
		})
		if err == nil || !strings.Contains(err.Error(), "recovery") {
			t.Fatalf("watchdog did not win at the event boundary: %v", err)
		}
		watchdog, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if watchdog.State != RecoveryRequired || !watchdog.RecoveryRequired || len(watchdog.Events) != MaxJournalItems-activeIdleEventBudget || len(watchdog.Phases) != 1 || watchdog.Phases[0].EndedAt != "" {
			t.Fatalf("watchdog boundary was not readable: %+v", watchdog)
		}
		applyBoundaryRecovery(t, c, h)
	})
}

func TestJournalWriterCountsNewlineAtExactLimit(t *testing.T) {
	c, h, now := boundaryCoordinator(t)
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.Events = []Event{{At: now.Format(time.RFC3339Nano), Kind: "x", State: record.State}}
	record.Revision++
	base, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	padding := MaxJournalBytes - len(base) - 1
	if padding < 0 {
		t.Fatalf("test record unexpectedly exceeds journal limit: %d", len(base)+1)
	}
	record.Events[0].Kind = strings.Repeat("x", 1+padding)
	record.Revision--
	if err := c.writeRecord(record); err != nil {
		t.Fatalf("exact full serialized record was refused: %v", err)
	}
	body, err := os.ReadFile(recordPath(c, h.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != MaxJournalBytes {
		t.Fatalf("persisted record has %d bytes, want exact limit %d", len(body), MaxJournalBytes)
	}
	if _, err := c.Get(context.Background(), h.ID()); err != nil {
		t.Fatalf("exact-limit record is not readable: %v", err)
	}
	tooLarge := record
	tooLarge.Events = append([]Event(nil), record.Events...)
	tooLarge.Events[0].Kind += "x"
	if err := c.writeRecord(tooLarge); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("one-over record was accepted: %v", err)
	}
	if _, err := c.Get(context.Background(), h.ID()); err != nil {
		t.Fatalf("one-over refusal damaged the exact-limit record: %v", err)
	}
}

func recordPath(c *Coordinator, id string) string { return c.root + "/" + id + ".json" }

func TestExecutePhaseKeepsOneFenceAcrossMutationAndOutcome(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	host := "SHA256:" + strings.Repeat("B", 43)
	c := New(Options{Root: root, LockPath: root + "/root.lock", LockWait: 250 * time.Millisecond, Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: host})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	phaseDone := make(chan error, 1)
	var phaseStartErr error
	go func() {
		phaseDone <- c.ExecutePhase(context.Background(), phaseRequestFor(h, "push", host), func(context.Context, Record) error {
			if record, readErr := c.readRecord(h.ID()); readErr != nil || len(record.Phases) != 1 || record.Phases[0].EndedAt != "" {
				phaseStartErr = errors.New("phase-start was not durable before the mutation callback")
			}
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	reserveDone := make(chan error, 1)
	go func() {
		_, reserveErr := c.Reserve(context.Background(), Request{Kind: "backup", App: "other", Principal: "operator-b", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("C", 43), Host: host})
		reserveDone <- reserveErr
	}()
	select {
	case reserveErr := <-reserveDone:
		if reserveErr == nil || !strings.Contains(reserveErr.Error(), h.ID()) {
			t.Fatalf("concurrent reservation escaped the phase fence: %v", reserveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent reservation did not observe the held phase fence")
	}
	close(release)
	if err := <-phaseDone; err != nil {
		t.Fatal(err)
	}
	if phaseStartErr != nil {
		t.Fatal(phaseStartErr)
	}
	if record, err := c.Get(context.Background(), h.ID()); err != nil || len(record.Phases) != 1 || record.Phases[0].EndedAt == "" {
		t.Fatalf("phase outcome was not durably recorded: %+v %v", record, err)
	}
}

func TestExecutePhaseRejectsExpiredBootAndPlanBeforeMutation(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	boot := "boot-a"
	host := "SHA256:" + strings.Repeat("B", 43)
	c := New(Options{Root: t.TempDir(), LockPath: t.TempDir() + "/root.lock", LockWait: time.Second, Now: func() time.Time { return now }, BootID: func() (string, error) { return boot, nil }})
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: host})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	request := phaseRequestFor(h, "push", host)
	request.PlanExpiresAt = now.Add(-time.Second)
	if err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error { called = true; return nil }); err == nil || called {
		t.Fatalf("expired signed plan reached mutation: err=%v called=%v", err, called)
	}
	boot = "boot-b"
	request.PlanExpiresAt = now.Add(time.Minute)
	if err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error { called = true; return nil }); err == nil || called {
		t.Fatalf("old boot reservation reached mutation: err=%v called=%v", err, called)
	}
}

func TestExecutePhaseRejectsThe129thPhaseBeforeMutation(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: "SHA256:" + strings.Repeat("B", 43)})
	if err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxJournalItems; i++ {
		record.Phases = append(record.Phases, Phase{Name: "phase-" + strings.Repeat("x", i%10+1), StartedAt: now.Format(time.RFC3339Nano), EndedAt: now.Format(time.RFC3339Nano)})
	}
	if err := c.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	called := false
	err = c.ExecutePhase(context.Background(), phaseRequestFor(h, "overflow", "SHA256:"+strings.Repeat("B", 43)), func(context.Context, Record) error {
		called = true
		return nil
	})
	if err == nil || called || !strings.Contains(err.Error(), "phase history is full") {
		t.Fatalf("129th phase was not rejected before mutation: err=%v called=%v", err, called)
	}
}

func TestApplyRecoveryReobservesAndRejectsChangedPlanBeforeAction(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: "SHA256:" + strings.Repeat("B", 43)})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("interrupted push"); err != nil {
		t.Fatal(err)
	}
	first, second := true, false
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		if first {
			first = false
			return completeSafeObservation(), nil
		}
		second = true
		observation := completeSafeObservation()
		observation.ResourceVersion = "changed-resource"
		return observation, nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer, func(context.Context, Record, RecoveryObservation) error { applied = true; return nil })
	if err == nil || applied || !second || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed dry-run plan was applied: err=%v applied=%v second=%v", err, applied, second)
	}
}

func TestPhaseStartFsyncFailurePreventsMutation(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	var syncs int
	c := New(Options{Root: t.TempDir(), LockPath: t.TempDir() + "/root.lock", Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }, Sync: func(*os.File) error {
		syncs++
		if syncs == 3 {
			return errors.New("simulated disk fsync failure")
		}
		return nil
	}})
	host := "SHA256:" + strings.Repeat("B", 43)
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: host})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "push", host), func(context.Context, Record) error { called = true; return nil }); err == nil || called {
		t.Fatalf("mutation ran after phase-start fsync failure: err=%v called=%v", err, called)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || len(record.Phases) != 0 {
		t.Fatalf("failed phase-start left an apparent phase: %+v %v", record, err)
	}
}

func TestRecoveryRefusesLiveExecutorAndWrongIdentity(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	owner := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Attach(context.Background(), h.ID(), "other", "deploy", "demo"); err == nil {
		t.Fatal("wrong principal attached to operation")
	}
	called := false
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), "sha256:"+strings.Repeat("a", 64), func(context.Context, Record) (RecoveryObservation, error) { return completeSafeObservation(), nil }, func(context.Context, Record, RecoveryObservation) error { called = true; return nil }); err == nil || called || !strings.Contains(err.Error(), "live unexpired") {
		t.Fatalf("recovery applied while executor was live: err=%v called=%v", err, called)
	}
}

func TestReserveAndAttachReuseRequireExactIdentity(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	owner := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	c := New(Options{Root: t.TempDir(), LockPath: t.TempDir() + "/root.lock", Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	h, err := c.Reserve(context.Background(), Request{ID: strings.Repeat("e", 32), Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	reused, err := c.Reserve(context.Background(), Request{ID: h.ID(), Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil || reused.ID() != h.ID() {
		t.Fatalf("exact active reservation was not reusable: handle=%v err=%v", reused, err)
	}
	if _, err := c.Attach(context.Background(), h.ID(), "operator", "deploy", "demo"); err == nil {
		t.Fatal("legacy attachment without key and host proof was accepted")
	}
	if _, err := c.Attach(context.Background(), h.ID(), "operator", owner, host, "deploy", "demo"); err != nil {
		t.Fatalf("exact attachment was refused: %v", err)
	}
}

func TestRecoveryAppliesPendingBackupReplicaEvidence(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "backup", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: "SHA256:" + strings.Repeat("B", 43)})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("backup interrupted while application was quiesced", "restore original backup replica counts"); err != nil {
		t.Fatal(err)
	}
	observation := completeSafeObservation()
	observation.PendingBackup = true
	observation.OriginalReplicas = 2
	observation.Actions = []string{"restore original backup replica counts"}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) { return observation, nil })
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	postObservation := observation
	postObservation.Actions = nil
	applyObservation := true
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, func(context.Context, Record) (RecoveryObservation, error) {
		if applyObservation {
			applyObservation = false
			return observation, nil
		}
		return postObservation, nil
	}, func(_ context.Context, record Record, observed RecoveryObservation) error {
		applied = observed.PendingBackup && record.App == "demo" && observed.OriginalReplicas == 2
		return nil
	})
	if err != nil || !applied {
		t.Fatalf("pending backup recovery was not applied: err=%v applied=%v", err, applied)
	}
}

func TestRecoveryFenceSerializesFinish(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: "SHA256:" + strings.Repeat("B", 43)})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("interrupted operation"); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) { return completeSafeObservation(), nil })
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	applyDone := make(chan error, 1)
	var enteredOnce sync.Once
	go func() {
		_, applyErr := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, func(context.Context, Record) (RecoveryObservation, error) {
			enteredOnce.Do(func() { close(entered); <-release })
			return completeSafeObservation(), nil
		}, func(context.Context, Record, RecoveryObservation) error { return nil })
		applyDone <- applyErr
	}()
	<-entered
	finishDone := make(chan error, 1)
	go func() { finishDone <- h.Complete("must not finish during recovery") }()
	select {
	case finishErr := <-finishDone:
		t.Fatalf("finish escaped the recovery fence: %v", finishErr)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-finishDone; err == nil || !strings.Contains(err.Error(), "already terminal") {
		t.Fatalf("finish did not observe the recovered terminal state: %v", err)
	}
}

func fillPublicPhasesUntilRefusal(t *testing.T, c *Coordinator, h *Handle, host string) Record {
	t.Helper()
	if err := h.Phase("documented", "recorded"); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for {
		name := "step-" + strings.Repeat("x", accepted%8+1)
		err := c.ExecutePhase(context.Background(), phaseRequestFor(h, name, host), func(context.Context, Record) error { return nil })
		if err != nil {
			if !strings.Contains(err.Error(), "event history") && !strings.Contains(err.Error(), "bytes") {
				t.Fatalf("phase refused for an unexpected reason: %v", err)
			}
			break
		}
		accepted++
		if accepted > MaxJournalItems {
			t.Fatal("public phase sequence never refused")
		}
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "active" || record.RecoveryRequired || len(record.Events) > MaxJournalItems-activeIdleEventBudget {
		t.Fatalf("refused sequence did not keep idle recovery capacity: %+v", record)
	}
	return record
}

func TestPublicPhaseSequenceLeavesAbandonmentAndRecoveryCapacity(t *testing.T) {
	host := "SHA256:" + strings.Repeat("B", 43)
	t.Run("close then recovery", func(t *testing.T) {
		c, h, _ := boundaryCoordinator(t)
		before := fillPublicPhasesUntilRefusal(t, c, h, host)
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		closed, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if closed.State != RecoveryRequired || !closed.RecoveryRequired || len(closed.Events) != len(before.Events)+1 {
			t.Fatalf("close after refusal was not recorded: %+v", closed)
		}
		recovered := applyBoundaryRecovery(t, c, h)
		if recovered.Revision == 0 || len(recovered.Events) != len(closed.Events)+2 {
			t.Fatalf("recovery after close did not record start and outcome: %+v", recovered)
		}
		revision, events := recovered.Revision, len(recovered.Events)
		if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), recovered.RecoveryPlanDigest,
			func(context.Context, Record) (RecoveryObservation, error) { return completeSafeObservation(), nil },
			func(context.Context, Record, RecoveryObservation) error {
				t.Fatal("idempotent recovery retry invoked the applier")
				return nil
			}); err != nil {
			t.Fatal(err)
		}
		again, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if again.Revision != revision || len(again.Events) != events || again.State != "recovered" {
			t.Fatalf("recovery retry was not idempotent: %+v", again)
		}
	})

	t.Run("needs recovery then recovery", func(t *testing.T) {
		c, h, _ := boundaryCoordinator(t)
		before := fillPublicPhasesUntilRefusal(t, c, h, host)
		actions := maxRecoveryActionList()
		if err := h.NeedsRecovery("abandoned at capacity", actions...); err != nil {
			t.Fatal(err)
		}
		marked, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if marked.State != RecoveryRequired || len(marked.Events) != len(before.Events)+1 || len(marked.RecoveryActions) != MaxEvidenceItems || marked.RecoveryActions[0] != maxJSONEscapedReason() {
			t.Fatalf("needs-recovery after refusal was not recorded: %+v", marked)
		}
		plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
			return completeSafeObservation(), nil
		})
		if err != nil || plan.PlanDigest == "" {
			t.Fatalf("dry-run after max needs-recovery was not recordable: %+v %v", plan, err)
		}
		applyBoundaryRecovery(t, c, h)
	})

	t.Run("stale then recovery", func(t *testing.T) {
		now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
		root := t.TempDir()
		boot := "boot-a"
		c := New(Options{Root: root, LockPath: root + "/root.lock", LockWait: time.Second, Now: func() time.Time { return now }, BootID: func() (string, error) { return boot, nil }})
		h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: host})
		if err != nil {
			t.Fatal(err)
		}
		before := fillPublicPhasesUntilRefusal(t, c, h, host)
		boot = "boot-b"
		if _, err := c.Reserve(context.Background(), Request{Kind: "backup", App: "other", Principal: "operator-b"}); err == nil || !strings.Contains(err.Error(), h.ID()) {
			t.Fatalf("stale boundary should block new work: %v", err)
		}
		staleRecord, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if staleRecord.State != RecoveryRequired || len(staleRecord.Events) != len(before.Events)+1 {
			t.Fatalf("stale recovery at the public boundary was not recorded: %+v", staleRecord)
		}
		applyBoundaryRecovery(t, c, h)
	})

	t.Run("watchdog then recovery", func(t *testing.T) {
		c, h, _ := boundaryCoordinator(t)
		before := fillPublicPhasesUntilRefusal(t, c, h, host)
		request := phaseRequestFor(h, "watchdog-last", host)
		err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error {
			t.Fatal("watchdog phase callback ran without event capacity")
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "event history") {
			t.Fatalf("watchdog phase should refuse at the idle boundary: %v", err)
		}
		if err := h.MarkWatchdogRecovery("watchdog at capacity", maxRecoveryActionList()...); err != nil {
			t.Fatal(err)
		}
		watchdog, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if watchdog.State != RecoveryRequired || len(watchdog.Events) != len(before.Events)+1 || len(watchdog.RecoveryActions) != MaxEvidenceItems {
			t.Fatalf("watchdog recovery at the public boundary was not recorded: %+v", watchdog)
		}
		revision := watchdog.Revision
		if err := h.MarkWatchdogRecovery("watchdog at capacity", maxRecoveryActionList()...); err != nil {
			t.Fatal(err)
		}
		again, err := c.Get(context.Background(), h.ID())
		if err != nil {
			t.Fatal(err)
		}
		if again.Revision != revision || len(again.Events) != len(watchdog.Events) {
			t.Fatalf("watchdog retry was not idempotent: %+v", again)
		}
		applyBoundaryRecovery(t, c, h)
	})
}

func TestTerminalAndRecoveryRetriesAreIdempotent(t *testing.T) {
	c, h, _ := boundaryCoordinator(t)
	if err := h.Complete("done"); err != nil {
		t.Fatal(err)
	}
	first, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Complete("done again"); err != nil {
		t.Fatal(err)
	}
	second, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if second.Revision != first.Revision || len(second.Events) != len(first.Events) || second.State != "completed" {
		t.Fatalf("completed retry was not idempotent: first=%+v second=%+v", first, second)
	}

	c, h, _ = boundaryCoordinator(t)
	if err := h.NeedsRecovery("disconnected", "inspect current release"); err != nil {
		t.Fatal(err)
	}
	marked, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("disconnected again", "inspect current release"); err != nil {
		t.Fatal(err)
	}
	again, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision != marked.Revision || len(again.Events) != len(marked.Events) {
		t.Fatalf("needs-recovery retry was not idempotent: %+v", again)
	}
}

func TestSaturatedActiveRecordFailsClosedWithoutTruncation(t *testing.T) {
	c, h, now := boundaryCoordinator(t)
	before := seedEvents(t, c, h, now, 126)
	called := false
	err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "overflow", h.host), func(context.Context, Record) error {
		called = true
		return nil
	})
	if err == nil || called || !strings.Contains(err.Error(), "event history") {
		t.Fatalf("saturated record reached a phase callback: err=%v called=%v", err, called)
	}
	if err := h.Close(); err == nil || !strings.Contains(err.Error(), "event history") {
		t.Fatalf("saturated close did not fail closed: %v", err)
	}
	if err := h.NeedsRecovery("too full", "inspect current release"); err == nil || !strings.Contains(err.Error(), "event history") {
		t.Fatalf("saturated needs-recovery did not fail closed: %v", err)
	}
	after, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision || after.State != "active" || len(after.Events) != 126 {
		t.Fatalf("fail-closed refusal truncated the saturated record: before=%+v after=%+v", before, after)
	}
}

func padJournalRemaining(t *testing.T, c *Coordinator, id string, remaining int) Record {
	t.Helper()
	record, err := c.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Events) == 0 {
		t.Fatal("cannot pad a record without events")
	}
	probe := record
	probe.Revision++
	base, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	padding := MaxJournalBytes - remaining - len(base) - 1
	if padding < 1 {
		t.Fatalf("cannot pad to remaining %d; base %d", remaining, len(base)+1)
	}
	record.Events[len(record.Events)-1].Kind += strings.Repeat("x", padding)
	if err := c.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	record, err = c.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestPhaseRefusesNearByteBoundBeforeCallback(t *testing.T) {
	for _, remaining := range []int{400, 8000} {
		remaining := remaining
		t.Run(strconv.Itoa(remaining), func(t *testing.T) {
			c, h, _ := boundaryCoordinator(t)
			before := padJournalRemaining(t, c, h.ID(), remaining)
			called := false
			err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "near-limit", h.host), func(context.Context, Record) error {
				called = true
				return nil
			})
			if err == nil || called || !strings.Contains(err.Error(), "bytes") {
				t.Fatalf("near-limit phase reached the callback: err=%v called=%v remaining=%d", err, called, remaining)
			}
			record, err := c.Get(context.Background(), h.ID())
			if err != nil {
				t.Fatal(err)
			}
			if record.State != "active" || len(record.Phases) != 0 || record.Revision != before.Revision || len(record.Events) != len(before.Events) {
				t.Fatalf("near-limit refusal mutated the journal: %+v", record)
			}
		})
	}
}

// TestPhaseRefusesWhenSecondMaxActionListDoesNotFit catches a preflight that
// budgets only the watchdog action list. Mutation would then run and the later
// recovery-intent list would make the journal unreadable.
func TestPhaseRefusesWhenSecondMaxActionListDoesNotFit(t *testing.T) {
	c, h, _ := boundaryCoordinator(t)
	remaining := remainingWhereSecondActionListOverflows(t)
	before := padJournalRemaining(t, c, h.ID(), remaining)
	start := phaseStartCapacityProbe(before, "second-list")
	abandoned := compactAbandonment(start, "watchdog")
	if err := ensureCapacityProbeFits(abandoned, "one maximum action list"); err != nil {
		t.Fatalf("fixture left less space than one maximum action list: remaining=%d err=%v", remaining, err)
	}
	if err := ensureCapacityProbeFits(futureRecoveryFailure(abandoned), "two maximum action lists"); err == nil {
		t.Fatalf("fixture still fit two maximum action lists: remaining=%d", remaining)
	}
	called := false
	err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "second-list", h.host), func(context.Context, Record) error {
		called = true
		return nil
	})
	if err == nil || called || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("omitting the second action list would accept this record: err=%v called=%v remaining=%d", err, called, remaining)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "active" || len(record.Phases) != 0 || record.Revision != before.Revision || len(record.Events) != len(before.Events) {
		t.Fatalf("second-list refusal mutated the journal: %+v", record)
	}
}

func remainingWhereSecondActionListOverflows(t *testing.T) int {
	t.Helper()
	lo, hi, found := 100000, 210000, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		tc, th, _ := boundaryCoordinator(t)
		before := padJournalRemaining(t, tc, th.ID(), mid)
		start := phaseStartCapacityProbe(before, "second-list")
		abandoned := compactAbandonment(start, "watchdog")
		one := ensureCapacityProbeFits(abandoned, "one")
		two := ensureCapacityProbeFits(futureRecoveryFailure(abandoned), "two")
		switch {
		case one == nil && two != nil:
			found = mid
			hi = mid - 1
		case two != nil:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	if found < 0 {
		t.Fatal("could not find a byte remainder where one maximum action list fits and two do not")
	}
	return found
}

func phaseStartCapacityProbe(record Record, name string) Record {
	start := copyRecord(record)
	start.Phases = append(start.Phases, Phase{Name: name, StartedAt: capacityProbeTime})
	start.UpdatedAt = capacityProbeTime
	start.Events = append(start.Events, Event{At: capacityProbeTime, Kind: "phase-start", State: start.State, Phase: name})
	return start
}

func TestWatchdogDuringCallbackRecordsMaxActions(t *testing.T) {
	c, h, _ := boundaryCoordinator(t)
	request := phaseRequestFor(h, "watchdog-max", h.host)
	actions := maxRecoveryActionList()
	err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error {
		return c.MarkWatchdogRecoveryForPhase(request, "watchdog during callback", actions...)
	})
	if err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("watchdog during callback was not preserved: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || len(record.RecoveryActions) != MaxEvidenceItems || record.RecoveryActions[0] != maxJSONEscapedReason() || len(record.Phases) != 1 || record.Phases[0].EndedAt != "" {
		t.Fatalf("watchdog during callback dropped max actions: %+v", record)
	}
	applyBoundaryRecovery(t, c, h)
}

// TestHeartbeatWritesCrossRevisionWidthsThenMaxFailure waits for real lease
// renewals to cross a decimal width. Direct writeRecord in the callback would
// still pass if preflight reserved only one extra revision digit.
func TestHeartbeatWritesCrossRevisionWidthsThenMaxFailure(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := New(Options{
		Root: t.TempDir(), LockPath: t.TempDir() + "/root.lock", Lease: 30 * time.Millisecond,
		LockWait: time.Second, Now: func() time.Time { return now },
		BootID: func() (string, error) { return "boot-a", nil },
	})
	h, err := c.Reserve(context.Background(), Request{
		Kind: "deploy", App: "demo", Principal: "operator",
		OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43),
		Host:                "SHA256:" + strings.Repeat("B", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.Revision = 8
	body, err := encodeJournalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath(c, h.ID()), body, 0o600); err != nil {
		t.Fatal(err)
	}
	err = c.ExecutePhase(context.Background(), phaseRequestFor(h, "heartbeat-width", h.host), func(context.Context, Record) error {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			latest, readErr := c.readRecord(h.ID())
			if readErr != nil {
				return readErr
			}
			if latest.Revision >= 10 {
				return errors.New(maxJSONEscapedReason())
			}
			time.Sleep(5 * time.Millisecond)
		}
		return errors.New("heartbeat did not renew across a revision digit width")
	})
	if err == nil || !strings.Contains(err.Error(), maxJSONEscapedReason()) {
		t.Fatalf("max escaped failure after synchronized heartbeat writes was hidden: %v", err)
	}
	record, err = c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || record.Result != maxJSONEscapedReason() || record.Revision < 10 || len(strconv.FormatUint(record.Revision, 10)) < 2 {
		t.Fatalf("synchronized heartbeat width crossing was not durable with max failure: %+v", record)
	}
}

func TestSaturatedRevisionRefusesWithoutWrapping(t *testing.T) {
	c, h, _ := boundaryCoordinator(t)
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.Revision = ^uint64(0)
	body, err := encodeJournalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath(c, h.ID()), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.Phase("saturated", "must refuse"); err == nil || !strings.Contains(err.Error(), "saturated") {
		t.Fatalf("saturated revision was not refused before effects: %v", err)
	}
	if err := c.writeRecord(record); err == nil || !strings.Contains(err.Error(), "saturated") {
		t.Fatalf("saturated write wrapped or succeeded: %v", err)
	}
	after, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != ^uint64(0) || after.State != "active" || len(after.Phases) != 0 {
		t.Fatalf("saturated refusal wrapped to zero or mutated history: %+v", after)
	}
}

func TestAlreadyOversizedRecordFailsClosedBeforeEffects(t *testing.T) {
	c, h, _ := boundaryCoordinator(t)
	record := padJournalRemaining(t, c, h.ID(), 0)
	body, err := os.ReadFile(recordPath(c, h.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != MaxJournalBytes {
		t.Fatalf("exact-limit fixture is %d bytes, want %d", len(body), MaxJournalBytes)
	}
	called := false
	err = c.ExecutePhase(context.Background(), phaseRequestFor(h, "oversized", h.host), func(context.Context, Record) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("exact-limit record reached the callback: err=%v called=%v", err, called)
	}
	after, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != record.Revision || after.State != "active" || len(after.Events) != len(record.Events) {
		t.Fatalf("exact-limit refusal mutated the journal: before=%+v after=%+v", record, after)
	}
	if err := os.WriteFile(recordPath(c, h.ID()), append(append([]byte{}, body...), 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), h.ID()); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("already oversized record was cleaned up or accepted: %v", err)
	}
	still, err := os.ReadFile(recordPath(c, h.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if len(still) != MaxJournalBytes+1 || still[len(still)-1] != 'x' {
		t.Fatalf("already oversized record was rewritten: %d bytes", len(still))
	}
}

func TestPhaseWarningCompletesPhaseOnlyWhenBare(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	host := "SHA256:" + strings.Repeat("B", 43)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: host})
	if err != nil {
		t.Fatal(err)
	}
	reset := errors.New("read tcp 127.0.0.1:37150->127.0.0.1:5000: read: connection reset by peer")
	if err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "stack-apply", host), func(context.Context, Record) error {
		return Warn(reset)
	}); err != nil {
		t.Fatalf("a bare warning failed the phase: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "active" || record.Phases[0].Error != "" || !strings.Contains(record.Phases[0].Warning, "connection reset by peer") {
		t.Fatalf("warning was not recorded on a completed phase: %+v %v", record, err)
	}
	// Joined with anything else, the coordinator cannot say the phase finished.
	err = c.ExecutePhase(context.Background(), phaseRequestFor(h, "stack-apply", host), func(context.Context, Record) error {
		return errors.Join(Warn(reset), errors.New("lease renewal failed"))
	})
	if err == nil {
		t.Fatal("a joined warning completed the phase")
	}
	if record, _ := c.Get(context.Background(), h.ID()); record.State != RecoveryRequired {
		t.Fatalf("joined warning state = %s, want %s", record.State, RecoveryRequired)
	}
}

func TestKnownOutcomeKeepsRunActiveAndRejectsFurtherMutation(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	host := "SHA256:" + strings.Repeat("B", 43)
	owner := "SHA256:" + strings.Repeat("A", 43)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "run", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	request := PhaseRequest{ID: h.ID(), Kind: "run", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host, Name: "run"}
	wantErr := errors.New("exit status 3")
	if err := c.ExecutePhase(context.Background(), request, func(context.Context, Record) error { return KnownOutcome(wantErr) }); !errors.Is(err, wantErr) {
		t.Fatalf("known phase did not return command error: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "active" || record.RecoveryRequired || record.LeaseUntil == "" || len(record.Phases) != 1 || !record.Phases[0].Known || record.Phases[0].Error != wantErr.Error() {
		t.Fatalf("known outcome did not leave an active known phase: %+v", record)
	}
	control := PhaseRequest{ID: h.ID(), Kind: "run", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host, HostIdentity: host, Name: "client-cleanup", PlanExpiresAt: now.Add(time.Minute)}
	if err := c.Control(context.Background(), control, "finish", "success"); err == nil {
		t.Fatal("finish completed a known failed run")
	}
	if err := c.Control(context.Background(), control, "renew", "client progress"); err == nil {
		t.Fatal("phase-bearing renew followed a known failed run")
	}
	control.Name = "client-renew"
	if err := c.Control(context.Background(), control, "renew", ""); err != nil {
		t.Fatalf("phase-less client renew was rejected: %v", err)
	}
	if err := h.ExecutePhase(context.Background(), "another-phase", func(context.Context, Record) error { return nil }); err == nil {
		t.Fatal("new coordinator phase followed a known failed run")
	}
	if err := h.Phase("client-phase", "progress"); err == nil {
		t.Fatal("Handle.Phase followed a known failed run")
	}
	if err := h.Complete("success"); err == nil {
		t.Fatal("local completion bypassed operation-refuse")
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "run", App: "demo", Principal: "operator-2", Host: host}); err == nil {
		t.Fatal("known failed run stopped blocking before the client refused it")
	}
}

func TestJournalRunTargetRequiresOpenRunPhaseAndSurvivesRead(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	host := "SHA256:" + strings.Repeat("B", 43)
	owner := "SHA256:" + strings.Repeat("A", 43)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "run", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	container := strings.Repeat("a", 64)
	if err := JournalRunTarget(context.Background(), "api", container); err == nil {
		t.Fatal("run target was journaled outside a phase")
	}
	request := PhaseRequest{ID: h.ID(), Kind: "run", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host, Name: "run"}
	if err := c.ExecutePhase(context.Background(), request, func(phase context.Context, _ Record) error {
		if err := JournalRunTarget(phase, "bad/service", container); err == nil {
			return errors.New("invalid service name was accepted")
		}
		if err := JournalRunTarget(phase, "api", "container-id"); err == nil {
			return errors.New("short container ID was accepted")
		}
		if err := JournalRunTarget(phase, "api", container); err != nil {
			return err
		}
		if err := JournalRunTarget(phase, "api", container); err != nil {
			return err
		}
		if err := JournalRunTarget(phase, "worker", container); err == nil {
			return errors.New("run target was changed after journaling")
		}
		record, err := c.readRecord(h.ID())
		if err != nil || record.RunTarget == nil || record.RunTarget.Service != "api" || record.RunTarget.Container != container {
			return fmt.Errorf("run target was not durably readable before action: %+v %v", record.RunTarget, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.RunTarget == nil || record.RunTarget.Container != container {
		t.Fatalf("run target did not survive phase completion and re-read: %+v %v", record.RunTarget, err)
	}
}

func TestJournalCurrentManifestIsBoundToTheOpenPhase(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	host := "SHA256:" + strings.Repeat("B", 43)
	c := testCoordinator(t, &now, "boot-a")
	digest := "sha256:" + strings.Repeat("c", 64)
	if err := JournalCurrentManifest(context.Background(), digest); err == nil {
		t.Fatal("a digest was journaled outside any phase")
	}
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "stack-apply", host), func(phase context.Context, _ Record) error {
		if err := JournalCurrentManifest(phase, "sha256:short"); err == nil {
			return errors.New("a truncated digest was journaled")
		}
		if err := JournalCurrentManifest(phase, digest); err != nil {
			return err
		}
		record, err := c.readRecord(h.ID())
		if err != nil || record.CurrentManifestSHA256 != digest {
			return fmt.Errorf("digest was not durable before the callback continued: %+v %v", record, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestJournalRecoveryCurrentManifestIsBoundToDeployRecovery(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	owner := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	currentDigest := "sha256:" + strings.Repeat("a", 64)
	recoveryDigest := "sha256:" + strings.Repeat("b", 64)
	if err := c.ExecutePhase(context.Background(), phaseRequestFor(h, "stack-apply", host), func(phase context.Context, _ Record) error {
		if err := JournalRecoveryCurrentManifest(phase, recoveryDigest); err == nil {
			return errors.New("recovery manifest was journaled from a normal phase")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("interrupted deploy"); err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.CurrentManifestSHA256 = currentDigest
	if err := c.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		return completeSafeObservation(), nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	if err := JournalRecoveryCurrentManifest(context.Background(), recoveryDigest); err == nil {
		t.Fatal("recovery manifest was journaled outside an applier")
	}
	shortDigest := "sha256:short"
	wrongPlan := "sha256:" + strings.Repeat("c", 64)
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, time.Time{}, "", nil, observer, func(ctx context.Context, started Record, _ RecoveryObservation) error {
		if err := JournalRecoveryCurrentManifest(ctx, shortDigest); err == nil {
			return errors.New("a truncated recovery manifest digest was accepted")
		}
		mismatched := context.WithValue(ctx, recoveryJournalKey{}, &recoveryJournal{c: c, id: started.ID, planDigest: wrongPlan, active: true})
		if err := JournalRecoveryCurrentManifest(mismatched, recoveryDigest); err == nil {
			return errors.New("a recovery journal with a mismatched plan digest was accepted")
		}
		if err := JournalRecoveryCurrentManifest(ctx, recoveryDigest); err != nil {
			return err
		}
		if err := JournalRecoveryCurrentManifest(ctx, recoveryDigest); err != nil {
			return fmt.Errorf("repeating the same digest was not a no-op: %w", err)
		}
		if err := JournalRecoveryCurrentManifest(ctx, currentDigest); err == nil {
			return errors.New("a second recovery digest replaced the first")
		}
		latest, err := c.readRecord(started.ID)
		if err != nil || latest.RecoveryCurrentManifestSHA256 != recoveryDigest || latest.CurrentManifestSHA256 != currentDigest {
			return fmt.Errorf("recovery digest was not durable without changing the deploy proof: %+v %v", latest, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	latest, err := c.Get(context.Background(), h.ID())
	if err != nil || latest.State != "recovered" || latest.RecoveryCurrentManifestSHA256 != recoveryDigest || latest.CurrentManifestSHA256 != currentDigest {
		t.Fatalf("fresh recovery journal did not preserve the binding: %+v %v", latest, err)
	}
}

func TestJournalRecoveryCurrentManifestRefusesNonDeployRecord(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "backup", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("interrupted backup"); err != nil {
		t.Fatal(err)
	}
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		return completeSafeObservation(), nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, time.Time{}, "", nil, observer, func(ctx context.Context, _ Record, _ RecoveryObservation) error {
		called = true
		if err := JournalRecoveryCurrentManifest(ctx, "sha256:"+strings.Repeat("d", 64)); err == nil {
			return errors.New("a non-deploy recovery journaled current.yml")
		}
		return nil
	}); err != nil || !called {
		t.Fatalf("non-deploy recovery did not reject the binding: called=%v err=%v", called, err)
	}
}

func TestApplyRecoveryDoesNotRestorePreApplierSnapshotWhenRereadFails(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("interrupted deploy"); err != nil {
		t.Fatal(err)
	}
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		return completeSafeObservation(), nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("{post-applier journal read must fail")
	_, err = c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, time.Time{}, "", nil, observer, func(context.Context, Record, RecoveryObservation) error {
		return os.WriteFile(filepath.Join(c.root, h.ID()+".json"), corrupt, 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "read operation journal after recovery actions") {
		t.Fatalf("post-applier journal reread failure was not returned: %v", err)
	}
	stored, readErr := os.ReadFile(filepath.Join(c.root, h.ID()+".json"))
	if readErr != nil || string(stored) != string(corrupt) {
		t.Fatalf("coordinator wrote its pre-applier snapshot over the failed reread: body=%q err=%v", stored, readErr)
	}
}

func TestRecoveryAttemptCapacityReservesRecoveryManifestDigest(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	plan := RecoveryPlan{PlanDigest: "sha256:" + strings.Repeat("a", 64)}
	observed := completeSafeObservation()
	makeRecord := func(totalNoteBytes int) Record {
		record := copyRecord(base)
		record.Events = make([]Event, MaxJournalItems-recoveryAttemptEventBudget)
		perEvent, remainder := totalNoteBytes/len(record.Events), totalNoteBytes%len(record.Events)
		for index := range record.Events {
			noteSize := perEvent
			if index < remainder {
				noteSize++
			}
			record.Events[index] = Event{At: capacityProbeTime, Kind: "test", State: RecoveryRequired, Note: strings.Repeat("x", noteSize)}
		}
		return record
	}
	withoutNewFieldFits := func(record Record) bool {
		start := copyRecord(record)
		start.State = RecoveryRequired
		start.RecoveryRequired = true
		start.RecoveryIntent = &RecoveryIntent{PlanDigest: plan.PlanDigest, StartedAt: capacityProbeTime, Actions: append([]string(nil), plan.Actions...)}
		start.UpdatedAt = capacityProbeTime
		start.LeaseUntil = ""
		c.appendCapacityEvent(&start, "recovery-start", "", true)
		if ensureCapacityProbeFits(start, "test recovery start without new field") != nil {
			return false
		}
		failed := copyRecord(start)
		failed.Result = maxJSONEscapedReason()
		failed.UpdatedAt = capacityProbeTime
		c.appendCapacityEvent(&failed, "recovery-failed", "", true)
		if ensureCapacityProbeFits(failed, "test recovery failure without new field") != nil {
			return false
		}
		recovered := copyRecord(start)
		recovered.State = "recovered"
		recovered.RecoveryRequired = false
		recovered.Result = "explicit recovery reconciled observed host state"
		recovered.UpdatedAt = capacityProbeTime
		recovered.LeaseUntil = ""
		recovered.RecoveryActions = append([]string(nil), plan.Actions...)
		recovered.RecoveryPlanDigest = plan.PlanDigest
		recovered.RecoveryObservation = copyObservation(observed)
		recovered.RecoveryIntent = nil
		c.appendCapacityEvent(&recovered, "recovered", "", false)
		return ensureCapacityProbeFits(recovered, "test recovered outcome without new field") == nil
	}
	low, high := 0, MaxJournalBytes
	for low < high {
		middle := low + (high-low)/2
		if c.ensureRecoveryAttemptCapacity(makeRecord(middle), plan, observed) == nil {
			low = middle + 1
		} else {
			high = middle
		}
	}
	nearLimit := makeRecord(low)
	if low == 0 || !withoutNewFieldFits(nearLimit) {
		t.Fatalf("test record did not isolate the new digest capacity reservation at total note size %d", low)
	}
	if err := c.ensureRecoveryAttemptCapacity(nearLimit, plan, observed); err == nil {
		t.Fatal("recovery capacity did not reserve the new digest before starting")
	}
}

func TestLoadedRecordValidatesRecoveryCurrentManifestDigest(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.RecoveryCurrentManifestSHA256 = "sha256:short"
	if err := validateLoadedRecord(record); err == nil || !strings.Contains(err.Error(), "recovery current manifest digest is invalid") {
		t.Fatalf("record accepted a non-full recovery manifest digest: %v", err)
	}
}

// A lost helper reply must not replay a non-idempotent command while its
// successful phase is durable but the client has not finished the operation.
func TestSuccessfulRunCannotReplayBeforeOperationFinish(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent=%t", concurrent), func(t *testing.T) {
			now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
			c := testCoordinator(t, &now, "boot-a")
			h, err := c.Reserve(context.Background(), Request{Kind: "run", App: "demo", Principal: "operator", Host: "host", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43)})
			if err != nil {
				t.Fatal(err)
			}
			request := PhaseRequest{ID: h.ID(), Kind: "run", App: "demo", Principal: "operator", Host: "host", OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Name: "run", Concurrent: concurrent}
			calls := 0
			mutate := func(context.Context, Record) error { calls++; return nil }
			if err := c.ExecutePhase(context.Background(), request, mutate); err != nil {
				t.Fatal(err)
			}
			if err := h.Phase("client-cleanup", "progress"); err != nil {
				t.Fatal(err)
			}
			if err := c.ExecutePhase(context.Background(), request, mutate); err == nil || !strings.Contains(err.Error(), "already completed successfully") {
				t.Errorf("successful run replay was not clearly refused: %v", err)
			}
			if calls != 1 {
				t.Fatalf("command executed %d times, want once", calls)
			}
			if err := h.Complete("success"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJournalRegistryReplacementRequiresOpenDeployAndKeepsLegacyRecords(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	c := testCoordinator(t, &now, "boot-a")
	owner := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := c.Get(context.Background(), h.ID())
	if err != nil || legacy.RegistryReplacement != nil {
		t.Fatalf("legacy record changed: %+v %v", legacy.RegistryReplacement, err)
	}
	body, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(body), "registry_replacement") {
		t.Fatalf("optional proof was emitted for a legacy record: %v", err)
	}
	intent := RegistryReplacement{Image: "registry:3@sha256:" + strings.Repeat("a", 64), VolumeSHA256: "sha256:" + strings.Repeat("b", 64)}
	if err := JournalRegistryReplacement(context.Background(), intent); err == nil {
		t.Fatal("replacement was journaled outside a phase")
	}
	request := PhaseRequest{ID: h.ID(), Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: owner, Host: host, Name: "stack-apply", Concurrent: true}
	if err := c.ExecutePhase(context.Background(), request, func(ctx context.Context, _ Record) error {
		invalid := intent
		invalid.Image = "registry:latest"
		if err := JournalRegistryReplacement(ctx, invalid); err == nil {
			return errors.New("mutable image accepted")
		}
		if err := JournalRegistryReplacement(ctx, intent); err != nil {
			return err
		}
		if err := JournalRegistryReplacement(ctx, intent); err != nil {
			return err
		}
		changed := intent
		changed.VolumeSHA256 = "sha256:" + strings.Repeat("c", 64)
		if err := JournalRegistryReplacement(ctx, changed); err == nil {
			return errors.New("journaled volume proof was replaced")
		}
		stored, err := c.readRecord(h.ID())
		if err != nil || stored.RegistryReplacement == nil || *stored.RegistryReplacement != intent {
			return fmt.Errorf("replacement is not durable before stop: %+v %v", stored.RegistryReplacement, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := c.Get(context.Background(), h.ID())
	if err != nil || stored.RegistryReplacement == nil || *stored.RegistryReplacement != intent {
		t.Fatalf("replacement proof did not survive phase completion: %+v %v", stored.RegistryReplacement, err)
	}
}
