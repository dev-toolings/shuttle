package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func proofObservation(now time.Time) RecoveryObservation {
	observation := completeSafeObservation()
	stamp := now.UTC().Format(time.RFC3339Nano)
	observation.ObservedAt = stamp
	observation.Freshness = stamp
	return observation
}

func recoveryCoordinator(t *testing.T, now *time.Time, syncFile func(*os.File) error) *Coordinator {
	t.Helper()
	return New(Options{
		Root: t.TempDir(), LockPath: filepath.Join(t.TempDir(), "root.lock"), Lease: time.Second,
		LockWait: time.Second, Now: func() time.Time { return *now },
		BootID: func() (string, error) { return "boot-a", nil }, Sync: syncFile,
	})
}

func recoveryHandle(t *testing.T, c *Coordinator) *Handle {
	t.Helper()
	h, err := c.Reserve(context.Background(), Request{
		Kind: "deploy", App: "demo", Principal: "operator",
		OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43),
		Host:                "SHA256:" + strings.Repeat("B", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("interrupted phase", "verify release witnesses"); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRecoveryDigestIgnoresAdvancingObservationClock(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	observer := func(_ context.Context, _ Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	applied := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer,
		func(_ context.Context, _ Record, observed RecoveryObservation) error {
			applied = observed.ObservedAt == now.Format(time.RFC3339Nano)
			return nil
		})
	if err != nil || !applied {
		t.Fatalf("advancing observation clock changed a stable recovery proof: err=%v applied=%v", err, applied)
	}
}

func TestRecoveryDigestBindsRevisionAndResourceProof(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	}
	first, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.RecoveryActions = append(record.RecoveryActions, "retain journal markers")
	if err := c.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	second, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanDigest == second.PlanDigest || first.Observed.ResourceVersion != second.Observed.ResourceVersion {
		t.Fatalf("record revision change did not invalidate the confirmation: first=%+v second=%+v", first, second)
	}

	changed := proofObservation(now)
	changed.ResourceVersion = "resource-2"
	third, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) { return changed, nil })
	if err != nil {
		t.Fatal(err)
	}
	if second.PlanDigest == third.PlanDigest {
		t.Fatal("changed resource proof kept the same confirmation digest")
	}
}

func TestRecoveryApplyRejectsChangedSemanticEvidenceBeforeApplier(t *testing.T) {
	cases := []struct {
		name   string
		change func(*RecoveryObservation)
		want   string
	}{
		{name: "marker", change: func(observed *RecoveryObservation) { observed.MarkerProof = "marker:changed" }, want: "changed"},
		{name: "action", change: func(observed *RecoveryObservation) { observed.Actions = []string{"changed action"} }, want: "changed"},
		{name: "late action", change: func(observed *RecoveryObservation) { observed.Actions = append(observed.Actions, "late action") }, want: "too many entries"},
		{name: "long suffix", change: func(observed *RecoveryObservation) { observed.ActionProof += strings.Repeat("x", MaxReasonBytes+1) }, want: "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
			c := recoveryCoordinator(t, &now, nil)
			h := recoveryHandle(t, c)
			initial := proofObservation(now)
			if tc.name == "late action" {
				initial.Actions = make([]string, MaxEvidenceItems)
				for i := range initial.Actions {
					initial.Actions[i] = "action-" + strings.Repeat("x", i%8+1)
				}
			}
			changed := initial
			tc.change(&changed)
			observations := []RecoveryObservation{initial, changed}
			observer := func(context.Context, Record) (RecoveryObservation, error) {
				observed := observations[0]
				observations = observations[1:]
				return observed, nil
			}
			plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
			if err != nil {
				t.Fatal(err)
			}
			applied := false
			_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer, func(context.Context, Record, RecoveryObservation) error {
				applied = true
				return nil
			})
			if err == nil || applied || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("changed %s evidence reached applier: err=%v applied=%v", tc.name, err, applied)
			}
		})
	}
}

func TestRecoveryRejectsNegativeCountsBeforeApplier(t *testing.T) {
	cases := []struct {
		name   string
		change func(*RecoveryObservation)
	}{
		{name: "executor count", change: func(observed *RecoveryObservation) { observed.ExecutorCount = -1 }},
		{name: "original replicas", change: func(observed *RecoveryObservation) { observed.OriginalReplicas = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
			c := recoveryCoordinator(t, &now, nil)
			h := recoveryHandle(t, c)
			plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
				return proofObservation(now), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			bad := proofObservation(now)
			tc.change(&bad)
			applied := 0
			_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
				func(context.Context, Record) (RecoveryObservation, error) { return bad, nil },
				func(context.Context, Record, RecoveryObservation) error {
					applied++
					return nil
				})
			if err == nil || !strings.Contains(err.Error(), "negative count") || applied != 0 {
				t.Fatalf("invalid recovery count reached the applier: err=%v applied=%d", err, applied)
			}
			record, err := c.Get(context.Background(), h.ID())
			if err != nil {
				t.Fatal(err)
			}
			if record.State != RecoveryRequired || record.RecoveryIntent != nil {
				t.Fatalf("invalid recovery count changed the persisted record: %+v", record)
			}
		})
	}
}

func TestRecoveryApplyRejectsChangedJournalRevisionBeforeApplier(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.RecoveryActions = append(record.RecoveryActions, "revision changed")
	if err := c.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	applied := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer, func(context.Context, Record, RecoveryObservation) error {
		applied = true
		return nil
	})
	if err == nil || applied || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed journal revision reached applier: err=%v applied=%v", err, applied)
	}
}

func TestRecoveryStartIntentIsDurableBeforeApplier(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
		func(context.Context, Record) (RecoveryObservation, error) { return proofObservation(now), nil },
		func(context.Context, Record, RecoveryObservation) error {
			called = true
			record, readErr := c.readRecord(h.ID())
			if readErr != nil {
				return readErr
			}
			if record.RecoveryIntent == nil || record.RecoveryIntent.PlanDigest != plan.PlanDigest {
				return errors.New("recovery intent was not durable before applier")
			}
			return nil
		})
	if err != nil || !called {
		t.Fatalf("recovery applier did not observe durable recovery intent: err=%v called=%v", err, called)
	}
}

func TestRecoveryStartWriteFailurePreventsApplier(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	var syncs int
	fail := false
	c := recoveryCoordinator(t, &now, func(file *os.File) error {
		syncs++
		if fail {
			return errors.New("recovery-start disk failure")
		}
		return file.Sync()
	})
	h := recoveryHandle(t, c)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	called := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
		func(context.Context, Record) (RecoveryObservation, error) { return proofObservation(now), nil },
		func(context.Context, Record, RecoveryObservation) error { called = true; return nil })
	if err == nil || called || !strings.Contains(err.Error(), "recovery-start disk failure") {
		t.Fatalf("failed recovery-start write did not prevent mutation: syncs=%d err=%v called=%v", syncs, err, called)
	}
}

func TestRecoveryFailureJoinsApplierAndJournalErrors(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	failWrites := false
	c := recoveryCoordinator(t, &now, func(file *os.File) error {
		if failWrites {
			return errors.New("recovery-failure journal failure")
		}
		return file.Sync()
	})
	h := recoveryHandle(t, c)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
		func(context.Context, Record) (RecoveryObservation, error) { return proofObservation(now), nil },
		func(context.Context, Record, RecoveryObservation) error {
			failWrites = true
			return errors.New("applier failed")
		})
	if err == nil || !strings.Contains(err.Error(), "applier failed") || !strings.Contains(err.Error(), "recovery-failure journal failure") {
		t.Fatalf("applier and journal errors were not joined: %v", err)
	}
}

func TestRecoveryPostcheckRejectsRemainingActions(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The observer is called twice. The first call confirms the plan and the
	// second call is the postcheck, which must reject a Safe result with work.
	called := 0
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
		func(context.Context, Record) (RecoveryObservation, error) {
			called++
			if called == 1 {
				return proofObservation(now), nil
			}
			post := proofObservation(now)
			post.Actions = []string{"still required"}
			return post, nil
		},
		func(context.Context, Record, RecoveryObservation) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "required actions") {
		t.Fatalf("postcheck accepted remaining actions: %v", err)
	}
}

func TestMalformedHistoryFailsClosedAndLegacyPythonBlocksReservation(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	c := New(Options{Root: root, LockPath: filepath.Join(t.TempDir(), "root.lock"), Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	bad := Record{Schema: Schema, ID: strings.Repeat("a", 32), Revision: 1, Kind: "backup", Scope: "global", Principal: "backup-source", HostBootID: "boot-a", StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), LeaseUntil: now.Add(time.Hour).Format(time.RFC3339Nano), State: "unknown", Events: []Event{}}
	body, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, bad.ID+".json"), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(context.Background()); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown journal state did not fail closed: %v", err)
	}

	root = t.TempDir()
	c = New(Options{Root: root, LockPath: filepath.Join(t.TempDir(), "root.lock"), Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	legacy := bad
	legacy.ID = strings.Repeat("b", 32)
	legacy.State = "active"
	legacy.RecoveryRequired = false
	legacy.Events = []Event{{At: "2026-09-13T12:00:00.%fZ", Kind: "reserved", State: "active"}}
	body, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, legacy.ID+".json"), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(context.Background(), Request{Kind: "deploy", App: "demo", Principal: "operator"}); err == nil || !strings.Contains(err.Error(), legacy.ID) {
		t.Fatalf("valid legacy Python reservation did not block global work: %v", err)
	}

	root = t.TempDir()
	c = New(Options{Root: root, LockPath: filepath.Join(t.TempDir(), "root.lock"), Now: func() time.Time { return now }, BootID: func() (string, error) { return "boot-a", nil }})
	directoryID := strings.Repeat("c", 32)
	if err := os.Mkdir(filepath.Join(root, directoryID+".json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(context.Background()); err == nil || !strings.Contains(err.Error(), directoryID) {
		t.Fatalf("directory journal entry was skipped: %v", err)
	}
}

func TestWatchdogRecoveryWinsAgainstPhaseOutcome(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	var syncCalls atomic.Int32
	heartbeatSyncStarted := make(chan struct{})
	allowHeartbeatSync := make(chan struct{})
	watchdogLockAttempt := make(chan struct{}, 1)
	var heartbeatOnce sync.Once
	c := New(Options{
		Root: t.TempDir(), LockPath: filepath.Join(t.TempDir(), "root.lock"), Lease: 60 * time.Millisecond,
		LockWait: time.Second, Now: func() time.Time { return now },
		BootID: func() (string, error) { return "boot-a", nil },
		Sync: func(file *os.File) error {
			if syncCalls.Add(1) == 7 {
				heartbeatOnce.Do(func() { close(heartbeatSyncStarted) })
				<-allowHeartbeatSync
			}
			return file.Sync()
		},
	})
	c.journalLockHook = func(kind string) {
		if kind != "watchdog" {
			return
		}
		select {
		case watchdogLockAttempt <- struct{}{}:
		default:
		}
	}
	h, err := c.Reserve(context.Background(), Request{
		Kind: "deploy", App: "demo", Principal: "operator",
		OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), Host: "SHA256:" + strings.Repeat("B", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := phaseRequestFor(h, "push", "SHA256:"+strings.Repeat("B", 43))
	err = c.ExecutePhase(context.Background(), request, func(_ context.Context, phaseRecord Record) error {
		select {
		case <-heartbeatSyncStarted:
		case <-time.After(2 * time.Second):
			return errors.New("heartbeat did not reach its journal write")
		}
		watchdogDone := make(chan error, 1)
		go func() {
			watchdogDone <- c.MarkWatchdogRecoveryForPhase(request, "watchdog stopped phase", "inspect current release")
		}()
		select {
		case <-watchdogLockAttempt:
		case <-time.After(2 * time.Second):
			return errors.New("watchdog did not observe a failed journal TryLock")
		}
		close(allowHeartbeatSync)
		if err := <-watchdogDone; err != nil {
			return err
		}
		published, err := c.readRecord(h.ID())
		if err != nil {
			return err
		}
		if published.State != RecoveryRequired || !published.RecoveryRequired {
			return errors.New("watchdog publication was not durable before renewal")
		}
		renewalDone := make(chan error, 1)
		renewalStop := make(chan struct{})
		go c.renewPhaseLease(phaseRecord, request.Name, holdJournalAlready, renewalStop, renewalDone)
		select {
		case renewalErr := <-renewalDone:
			if renewalErr == nil || !strings.Contains(renewalErr.Error(), "recovery") {
				return fmt.Errorf("heartbeat revived the watchdog record: %v", renewalErr)
			}
		case <-time.After(2 * time.Second):
			close(renewalStop)
			return errors.New("heartbeat did not attempt renewal after watchdog publication")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("phase outcome overwrote watchdog recovery: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || !record.RecoveryRequired || len(record.Phases) != 1 || record.Phases[0].EndedAt != "" || len(record.RecoveryActions) != 1 {
		t.Fatalf("watchdog recovery was not preserved: %+v", record)
	}
}

func TestRecoveryRefusesNearByteBoundBeforeApplier(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	padJournalRemaining(t, c, h.ID(), 400)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
		func(context.Context, Record) (RecoveryObservation, error) { return proofObservation(now), nil },
		func(context.Context, Record, RecoveryObservation) error {
			applied = true
			return nil
		})
	if err == nil || applied || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("near-limit recovery reached the applier: err=%v applied=%v", err, applied)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || record.RecoveryIntent != nil {
		t.Fatalf("near-limit recovery mutated the journal: %+v", record)
	}
}

func TestFailedRecoveryKeepsDistinctOldAndNewActionLists(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h, err := c.Reserve(context.Background(), Request{
		Kind: "deploy", App: "demo", Principal: "operator",
		OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43),
		Host:                "SHA256:" + strings.Repeat("B", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldActions := []string{"retain previous release", "inspect current marker"}
	if err := h.NeedsRecovery("interrupted with prior actions", oldActions...); err != nil {
		t.Fatal(err)
	}
	newActions := []string{"reconcile executor fence", "restore previous digest", "verify backup witness"}
	observer := func(context.Context, Record) (RecoveryObservation, error) {
		observed := proofObservation(now)
		observed.Actions = append([]string(nil), newActions...)
		return observed, nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer, func(context.Context, Record, RecoveryObservation) error {
		applied = true
		return errors.New("applier refused distinct action lists")
	})
	if err == nil || !applied || !strings.Contains(err.Error(), "distinct action lists") {
		t.Fatalf("failed recovery did not invoke the applier: err=%v applied=%v", err, applied)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || record.RecoveryIntent == nil {
		t.Fatalf("failed recovery dropped intent: %+v", record)
	}
	if strings.Join(record.RecoveryActions, ",") != strings.Join(oldActions, ",") {
		t.Fatalf("failed recovery replaced old actions: %+v", record.RecoveryActions)
	}
	if strings.Join(record.RecoveryIntent.Actions, ",") != strings.Join(newActions, ",") {
		t.Fatalf("failed recovery dropped new intent actions: %+v", record.RecoveryIntent.Actions)
	}
}

func TestRecoveryFallsBackWhenPostProofExceedsJournalCapacity(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	padJournalRemaining(t, c, h.ID(), 8000)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), func(context.Context, Record) (RecoveryObservation, error) {
		return proofObservation(now), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest,
		func(context.Context, Record) (RecoveryObservation, error) {
			if !applied {
				return proofObservation(now), nil
			}
			rich := proofObservation(now)
			rich.ActionProof = maxJSONEscapedReason()
			rich.ResourceProof = maxJSONEscapedReason()
			rich.MarkerProof = maxJSONEscapedReason()
			rich.ManifestProof = maxJSONEscapedReason()
			return rich, nil
		},
		func(context.Context, Record, RecoveryObservation) error {
			applied = true
			return nil
		})
	if err == nil || !applied || !strings.Contains(err.Error(), unrecordableRecoveryProof) {
		t.Fatalf("rich post-proof did not use the capacity fallback: err=%v applied=%v", err, applied)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != RecoveryRequired || !record.RecoveryRequired || record.Result != unrecordableRecoveryProof {
		t.Fatalf("unrecordable success did not stay recovery-required: %+v", record)
	}
	if record.RecoveryIntent == nil || record.RecoveryIntent.PlanDigest != plan.PlanDigest {
		t.Fatalf("fallback dropped recovery intent: %+v", record)
	}
	if record.RecoveryObservation.ActionProof != "" || record.RecoveryPlanDigest != "" {
		t.Fatalf("fallback masqueraded post-action proof: %+v", record)
	}
	if len(record.Events) < 2 || record.Events[len(record.Events)-1].Kind != "recovery-failed" {
		t.Fatalf("fallback did not record the reserved outcome event: %+v", record)
	}
}

func TestRecoveryConfirmationBindsDisplayedInventory(t *testing.T) {
	now := time.Now().UTC()
	c := recoveryCoordinator(t, &now, nil)
	h := recoveryHandle(t, c)
	observed := proofObservation(now)
	observed.Details = []string{"drop PostgreSQL database first"}
	observer := func(context.Context, Record) (RecoveryObservation, error) { return observed, nil }
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), observer)
	if err != nil {
		t.Fatal(err)
	}
	observed.Details = []string{"drop PostgreSQL database second"}
	applied := false
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, observer, func(context.Context, Record, RecoveryObservation) error { applied = true; return nil })
	if err == nil || applied {
		t.Fatalf("changed displayed inventory reused consent: err=%v applied=%v", err, applied)
	}
}
