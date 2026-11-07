package operations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func controlFixture(t *testing.T) (*Coordinator, PhaseRequest, string) {
	t.Helper()
	dir := t.TempDir()
	lock := filepath.Join(dir, "root.lock")
	// A fixed boot id, as the other fixtures use: the real one is read from
	// /proc, which the macOS CI job does not have.
	c := New(Options{Root: filepath.Join(dir, "records"), LockPath: lock, LockWait: time.Second, BootID: func() (string, error) { return "boot-a", nil }})
	owner := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	h, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	return c, PhaseRequest{ID: h.ID(), Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host, HostIdentity: host, Name: "client-renew", PlanExpiresAt: time.Now().Add(time.Minute)}, lock
}

func TestWriterClosureAfterFailureDoesNotReviveAdmission(t *testing.T) {
	c, request, _ := controlFixture(t)
	if err := c.Control(context.Background(), request, "abort", "promotion failed"); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := c.WithWriterInventory(context.Background(), request, true, func(Record) error { called = true; return nil }); err == nil || called {
		t.Fatal("failed operation admitted a writer")
	}
	request.Name = "operation-writers-close"
	if err := c.WithWriterInventory(context.Background(), request, false, func(record Record) error {
		called = true
		if record.State != RecoveryRequired {
			t.Fatal("closure revived the reservation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("failed operation could not close its writers")
	}
	record, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || record.LeaseUntil != "" {
		t.Fatal("writer closure claimed recovery completion")
	}
}

// A recovered operation must point clients at recovery, while completed rows
// retain the legacy inactive response; identity validation still comes first.
func TestRecoveryRequiredControlsKeepRecoveryState(t *testing.T) {
	c, request, _ := controlFixture(t)
	if err := c.Control(context.Background(), request, "abort", "failed deploy"); err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	handle := handleFor(c, record)
	if err := handle.Phase("client-renew", ""); !errors.Is(err, ErrOperationRequiresRecovery) {
		t.Fatalf("phase error = %v, want ErrOperationRequiresRecovery", err)
	}
	if err := c.Control(context.Background(), request, "renew", ""); !errors.Is(err, ErrOperationRequiresRecovery) {
		t.Fatalf("renew error = %v, want ErrOperationRequiresRecovery", err)
	}
	if err := c.Control(context.Background(), request, "refuse", "refused"); !errors.Is(err, ErrOperationRequiresRecovery) {
		t.Fatalf("refuse error = %v, want ErrOperationRequiresRecovery", err)
	}
	if err := c.Control(context.Background(), request, "finish", "finished"); !errors.Is(err, ErrOperationRequiresRecovery) {
		t.Fatalf("finish error = %v, want ErrOperationRequiresRecovery", err)
	}
	if err := c.Control(context.Background(), request, "abort", "again"); !errors.Is(err, ErrOperationRequiresRecovery) {
		t.Fatalf("abort error = %v, want ErrOperationRequiresRecovery", err)
	}
	wrongIdentity := request
	wrongIdentity.Host = "SHA256:" + strings.Repeat("d", 43)
	if err := c.Control(context.Background(), wrongIdentity, "renew", ""); err == nil || errors.Is(err, ErrOperationRequiresRecovery) || !strings.Contains(err.Error(), "identity does not match") {
		t.Fatalf("identity mismatch did not take precedence: %v", err)
	}
}

func TestCompletedOperationKeepsInactiveControlError(t *testing.T) {
	c, request, _ := controlFixture(t)
	if err := c.Control(context.Background(), request, "finish", "done"); err != nil {
		t.Fatal(err)
	}
	err := c.Control(context.Background(), request, "renew", "")
	if err == nil || errors.Is(err, ErrOperationRequiresRecovery) || !strings.Contains(err.Error(), "operation is not active for this phase") {
		t.Fatalf("completed row returned wrong control error: %v", err)
	}
	record, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := handleFor(c, record).Phase("client-renew", ""); err == nil || errors.Is(err, ErrOperationRequiresRecovery) || !strings.Contains(err.Error(), "operation is not active for this phase") {
		t.Fatalf("completed phase returned wrong error: %v", err)
	}
}

func TestCompletionHookRunsAfterDurableTerminalRecord(t *testing.T) {
	c, request, _ := controlFixture(t)
	called := false
	if err := c.ControlWithLockedCompletion(context.Background(), request, "finish", "replacement synced", func(record Record) error {
		called = true
		stored, err := c.readRecord(record.ID)
		if err != nil {
			return err
		}
		if stored.State != "completed" || stored.LeaseUntil != "" {
			t.Fatal("completion hook ran before terminal journal")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("completion hook was not called")
	}
}

func TestControlRechecksSignedExpiryAfterWaitingForLock(t *testing.T) {
	c, request, path := controlFixture(t)
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	request.PlanExpiresAt = time.Now().Add(30 * time.Millisecond)
	result := make(chan error, 1)
	go func() { result <- c.Control(context.Background(), request, "finish", "complete") }()
	time.Sleep(60 * time.Millisecond)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired signature completed after flock wait: %v", err)
	}
	record, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "active" {
		t.Fatalf("expired control changed state: %#v", record)
	}
}

func TestControlRejectsChangedOwnerAndCannotReviveExpiredLease(t *testing.T) {
	c, request, _ := controlFixture(t)
	wrong := request
	wrong.OwnerKeyFingerprint = "SHA256:" + strings.Repeat("c", 43)
	if err := c.Control(context.Background(), wrong, "finish", "complete"); err == nil {
		t.Fatal("different owner completed reservation")
	}
	now := time.Now().Add(time.Hour)
	c.now = func() time.Time { return now }
	request.PlanExpiresAt = now.Add(time.Minute)
	if err := c.Control(context.Background(), request, "renew", ""); err == nil {
		t.Fatal("expired lease was resurrected")
	}
	record, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || !record.RecoveryRequired {
		t.Fatalf("expired operation not marked recoverable: %#v", record)
	}
}

func TestRunRefuseAcceptsOnlyPreflightOrKnownCommandFailure(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		kind    string
		phases  []Phase
		allowed bool
	}{
		{name: "destroy without phase", kind: "destroy", phases: nil, allowed: false},
		{name: "destroy initialized only", kind: "destroy", phases: []Phase{Phase{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}}, allowed: false},
		{name: "destroy unknown failure", kind: "destroy", phases: []Phase{Phase{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "stack-apply", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z", Error: "drop refused"}}, allowed: false},
		{name: "destroy known failure", kind: "destroy", phases: []Phase{Phase{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "stack-apply", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z", Error: "drop refused", Known: true}}, allowed: true},
		{name: "destroy without writers", kind: "destroy", phases: []Phase{{Name: "stack-apply", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z", Error: "drop refused", Known: true}}, allowed: false},
		{name: "destroy successful phase", kind: "destroy", phases: []Phase{Phase{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "stack-apply", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z"}}, allowed: false},
		{name: "completed writers initialization", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}}, allowed: true},
		{name: "known failed run after writers", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "run", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z", Error: "exit status 3", Known: true}}, allowed: true},
		{name: "known writers initialization", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z", Known: true}}},
		{name: "no phase", kind: "run"},
		{name: "open phase", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z"}}},
		{name: "failed phase", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z", Error: "failed"}}},
		{name: "run phase", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "run", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z"}}},
		{name: "unknown failed run", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "run", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z", Error: "exit status 3"}}},
		{name: "two run phases", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "run", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z", Error: "first", Known: true}, {Name: "run", StartedAt: "2026-10-26T12:00:04Z", EndedAt: "2026-10-26T12:00:05Z", Error: "second", Known: true}}},
		{name: "open known run", kind: "run", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}, {Name: "run", StartedAt: "2026-10-26T12:00:02Z", Error: "exit status 3", Known: true}}},
		{name: "wrong kind", kind: "rollback", phases: []Phase{{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			owner := "SHA256:" + strings.Repeat("a", 43)
			host := "SHA256:" + strings.Repeat("b", 43)
			now := time.Now().UTC()
			c := New(Options{Root: filepath.Join(dir, "records"), LockPath: filepath.Join(dir, "root.lock"), LockWait: time.Second, BootID: func() (string, error) { return "boot-a", nil }})
			h, err := c.Reserve(context.Background(), Request{Kind: scenario.kind, App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
			if err != nil {
				t.Fatal(err)
			}
			if len(scenario.phases) > 0 {
				if err := c.withLock(context.Background(), func() error {
					record, err := c.readRecord(h.ID())
					if err != nil {
						return err
					}
					record.Phases = append([]Phase(nil), scenario.phases...)
					return c.writeRecord(record)
				}); err != nil {
					t.Fatal(err)
				}
			}
			request := PhaseRequest{ID: h.ID(), Kind: scenario.kind, App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host, HostIdentity: host, Name: "operation-refuse", PlanExpiresAt: now.Add(time.Minute)}
			before, err := c.Get(context.Background(), h.ID())
			if err != nil {
				t.Fatal(err)
			}
			err = c.Control(context.Background(), request, "refuse", "refused before any mutation: database probe failed")
			if scenario.allowed {
				if err != nil {
					t.Fatalf("completed initialization should be refusable: %v", err)
				}
				after, err := c.Get(context.Background(), h.ID())
				if err != nil {
					t.Fatal(err)
				}
				if after.State != "failed" || after.RecoveryRequired || after.LeaseUntil != "" || after.Result != "refused before any mutation: database probe failed" {
					t.Fatalf("unexpected refused terminal record: %+v", after)
				}
				if err := checkReserverRecordIsTerminal(t, c, owner, host); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid operation refusal was accepted")
			}
			after, getErr := c.Get(context.Background(), h.ID())
			if getErr != nil {
				t.Fatal(getErr)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected refusal changed the record:\nbefore=%+v\nafter=%+v", before, after)
			}
		})
	}
}

func TestDeployRefuseAcceptsOnlyJournaledNoMutationPhases(t *testing.T) {
	writers := Phase{Name: "writers-initialize", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z"}
	reclaim := Phase{Name: "stack-reclaim", StartedAt: "2026-10-26T12:00:02Z", EndedAt: "2026-10-26T12:00:03Z"}
	promotion := Phase{Name: "client-promotion", StartedAt: "2026-10-26T12:00:04Z", EndedAt: "2026-10-26T12:00:05Z", Result: "not-started"}
	cleanup := Phase{Name: "client-cleanup", StartedAt: "2026-10-26T12:00:06Z", EndedAt: "2026-10-26T12:00:07Z", Result: "completed"}
	for _, scenario := range []struct {
		name    string
		kind    string
		phases  []Phase
		allowed bool
	}{
		{name: "writers only", kind: "deploy", phases: []Phase{writers}, allowed: true},
		{name: "writers and reclaim", kind: "deploy", phases: []Phase{writers, reclaim}, allowed: true},
		{name: "client progress proves pre-promotion", kind: "deploy", phases: []Phase{writers, promotion, cleanup}, allowed: true},
		{name: "writers reclaim and client progress", kind: "deploy", phases: []Phase{writers, reclaim, promotion, cleanup}, allowed: true},
		{name: "no phase", kind: "deploy"},
		{name: "reclaim without writers", kind: "deploy", phases: []Phase{reclaim}},
		{name: "open reclaim", kind: "deploy", phases: []Phase{writers, {Name: "stack-reclaim", StartedAt: writers.EndedAt}}},
		{name: "failed reclaim", kind: "deploy", phases: []Phase{writers, {Name: "stack-reclaim", StartedAt: writers.EndedAt, EndedAt: reclaim.EndedAt, Error: "failed"}}},
		{name: "secret publication", kind: "deploy", phases: []Phase{writers, {Name: "secrets-apply", StartedAt: reclaim.StartedAt, EndedAt: reclaim.EndedAt}}},
		{name: "completed stack apply", kind: "deploy", phases: []Phase{writers, {Name: "stack-apply", StartedAt: reclaim.StartedAt, EndedAt: reclaim.EndedAt}}},
		{name: "failed stack apply", kind: "deploy", phases: []Phase{writers, {Name: "stack-apply", StartedAt: reclaim.StartedAt, EndedAt: reclaim.EndedAt, Error: "failed"}}},
		{name: "open stack apply", kind: "deploy", phases: []Phase{writers, {Name: "stack-apply", StartedAt: reclaim.StartedAt}}},
		{name: "promotion attempted", kind: "deploy", phases: []Phase{writers, {Name: "client-promotion", StartedAt: promotion.StartedAt, EndedAt: promotion.EndedAt, Result: "applied-unverified"}}},
		{name: "cleanup failed", kind: "deploy", phases: []Phase{writers, {Name: "client-cleanup", StartedAt: cleanup.StartedAt, EndedAt: cleanup.EndedAt, Result: "failed"}}},
		{name: "open writers", kind: "deploy", phases: []Phase{{Name: "writers-initialize", StartedAt: writers.StartedAt}}},
		{name: "failed writers", kind: "deploy", phases: []Phase{{Name: "writers-initialize", StartedAt: writers.StartedAt, EndedAt: writers.EndedAt, Error: "failed"}}},
		{name: "wrong kind", kind: "rollback", phases: []Phase{writers}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			owner := "SHA256:" + strings.Repeat("a", 43)
			host := "SHA256:" + strings.Repeat("b", 43)
			now := time.Now().UTC()
			c := New(Options{Root: filepath.Join(dir, "records"), LockPath: filepath.Join(dir, "root.lock"), LockWait: time.Second, BootID: func() (string, error) { return "boot-a", nil }})
			h, err := c.Reserve(context.Background(), Request{Kind: scenario.kind, App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
			if err != nil {
				t.Fatal(err)
			}
			if len(scenario.phases) > 0 {
				if err := c.withLock(context.Background(), func() error {
					record, err := c.readRecord(h.ID())
					if err != nil {
						return err
					}
					record.Phases = append([]Phase(nil), scenario.phases...)
					return c.writeRecord(record)
				}); err != nil {
					t.Fatal(err)
				}
			}
			request := PhaseRequest{ID: h.ID(), Kind: scenario.kind, App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host, HostIdentity: host, Name: "operation-refuse", PlanExpiresAt: now.Add(time.Minute)}
			before, err := c.Get(context.Background(), h.ID())
			if err != nil {
				t.Fatal(err)
			}
			err = c.Control(context.Background(), request, "refuse", "refused before any mutation: client failed before promotion")
			if scenario.allowed {
				if err != nil {
					t.Fatalf("valid no-mutation deploy refusal rejected: %v", err)
				}
				after, err := c.Get(context.Background(), h.ID())
				if err != nil {
					t.Fatal(err)
				}
				if after.State != "failed" || after.RecoveryRequired || after.LeaseUntil != "" {
					t.Fatalf("refused deploy was not terminal without recovery: %+v", after)
				}
				if err := checkReserverRecordIsTerminal(t, c, owner, host); err != nil {
					t.Fatalf("following application operation remained blocked: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid deploy refusal was accepted")
			}
			after, getErr := c.Get(context.Background(), h.ID())
			if getErr != nil {
				t.Fatal(getErr)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected refusal changed the record:\nbefore=%+v\nafter=%+v", before, after)
			}
		})
	}
}

func checkReserverRecordIsTerminal(t *testing.T, c *Coordinator, owner, host string) error {
	t.Helper()
	_, err := c.Reserve(context.Background(), Request{Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
	return err
}

func TestRequireLiveDoesNotMutateStaleReservation(t *testing.T) {
	c, request, _ := controlFixture(t)
	before, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := c.RequireLive(context.Background(), request.ID); err == nil {
		t.Fatal("expired reservation passed RequireLive")
	}
	after, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only liveness check changed reservation: before=%+v after=%+v", before, after)
	}
}

func TestControlRejectsChangedBootAndPreservesSeparateCleanupOutcome(t *testing.T) {
	c, request, _ := controlFixture(t)
	request.Name = "client-promotion"
	if err := c.Control(context.Background(), request, "renew", "verified"); err != nil {
		t.Fatal(err)
	}
	request.Name = "client-cleanup"
	if err := c.Control(context.Background(), request, "renew", "failed"); err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Phases) != 2 || record.Phases[0].Result != "verified" || record.Phases[1].Result != "failed" {
		t.Fatalf("promotion/cleanup outcomes conflated: %#v", record.Phases)
	}
	c.bootID = func() (string, error) { return "a-new-boot", nil }
	if err := c.Control(context.Background(), request, "finish", "complete"); err == nil {
		t.Fatal("old boot owner completed operation")
	}
}

func TestConcurrentControlDoesNotResurrectCompletedOperation(t *testing.T) {
	c, request, _ := controlFixture(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, action := range []string{"renew", "finish"} {
		wg.Add(1)
		go func(action string) {
			defer wg.Done()
			<-start
			err := c.Control(context.Background(), request, action, "complete")
			if action == "finish" && err != nil {
				t.Error(err)
			}
		}(action)
	}
	close(start)
	wg.Wait()
	record, err := c.Get(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "completed" || record.LeaseUntil != "" {
		t.Fatalf("completed reservation resurrected: %#v", record)
	}
}
