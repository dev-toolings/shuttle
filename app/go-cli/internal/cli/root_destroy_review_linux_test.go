//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"strings"
	"testing"
	"time"
)

func destroyReviewRecoveryRuntime(t *testing.T, now *time.Time) *rootRecoveryRuntime {
	oldSize := preRunDatabaseSize
	preRunDatabaseSize = func(context.Context, string) (int64, error) { return 100, nil }
	t.Cleanup(func() { preRunDatabaseSize = oldSize })
	docker := &fakeRecoveryDocker{version: "27.1.0"}
	rt := newTestRecoveryRuntimeAt(t, docker, now)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	oldJ, oldHost := rootDestroyCleanupRoot, rootDestroyHost
	rootDestroyCleanupRoot = rt.destroyJournalRoot
	runtime := oldHost()
	runtime.stateRoot, runtime.secretRoot, runtime.caddyRoot = rt.appStateRoot, t.TempDir(), rt.caddyDir
	runtime.reload = func(time.Time) error { return nil }
	rootDestroyHost = func() destroyHostRuntime { return runtime }
	t.Cleanup(func() { rootDestroyCleanupRoot, rootDestroyHost = oldJ, oldHost })
	fake := func(_ context.Context, args ...string) ([]byte, error) {
		return []byte("Error: No such secret"), errors.New("exit 1: No such secret: " + args[len(args)-1])
	}
	rt.completeDestroy = func(ctx context.Context, app string, out io.Writer) error {
		id, _ := ctx.Value(destroyOperationContextKey{}).(string)
		return removeRootStackAt(rt.appStateRoot, app, id, nil, out, fake)
	}
	return rt
}

// Interrupted default destroy, real removeRootStackAt, journal late in its life.
func TestDestroyKeptLedgerRecoveryCloses(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	rt := destroyReviewRecoveryRuntime(t, &now)
	if err := writePostgresLedger(rt.appStateRoot, "demo", postgresLedger{Version: 1, Databases: []string{"demo"}, Roles: []string{"demo"}}); err != nil {
		t.Fatal(err)
	}
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	j := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo", DrainBoundNanos: int64(30 * time.Second),
		Removal: postgresRemoval{Kept: []keptPostgresObject{{Kind: "database", Name: "demo", Reason: "x"}, {Kind: "role", Name: "demo", Reason: "x"}}},
		Progress: destroyCleanupProgress{ServicesRemoved: true, ContainersGone: true, StackRemoved: true, NetworksGone: true, SecretsPrepared: true, SecretsRemoved: true,
			VolumesPrepared: true, VolumesRemoved: true, RouteRemoved: true, RouteDirectorySynced: true, PostgresDropsPrepared: true, PostgresDropIntentsPrepared: true, CaddyReloaded: true}}
	if err := writeDestroyCleanupJournalAt(rt.destroyJournalRoot, j); err != nil {
		t.Fatal(err)
	}
	for pass := 1; pass <= 1; pass++ {
		plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
		if err != nil {
			t.Fatal(err)
		}
		_, applyErr := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply)
		rec, _ := c.Get(context.Background(), h.ID())
		_, statErr := os.Stat(filepath.Join(rt.appStateRoot, "demo", "postgres.json"))
		jr, _, _ := readDestroyCleanupJournalAt(rt.destroyJournalRoot, h.ID(), "demo")
		if applyErr != nil || rec.State != "recovered" || rec.RecoveryRequired || statErr != nil || jr != nil {
			t.Fatalf("pass %d: actions=%d applyErr=%v state=%s ledgerStat=%v journal=%v", pass, len(plan.Observed.Actions), applyErr, rec.State, statErr, jr != nil)
		}
	}
}

// Reservation done, helper never reached removeRootStackAt: no journal, live app.
func TestDestroyUnstartedRecoveryLeavesLiveApp(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	rt := destroyReviewRecoveryRuntime(t, &now)
	if err := os.MkdirAll(filepath.Join(rt.appStateRoot, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"), []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	_, applyErr := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply)
	rec, _ := c.Get(context.Background(), h.ID())
	if len(plan.Observed.Actions) != 0 || applyErr != nil || rec.State != "recovered" || rec.RecoveryRequired {
		t.Fatalf("actions=%v applyErr=%v state=%s", plan.Observed.Actions, applyErr, rec.State)
	}
	body, err := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
	if err != nil || string(body) != "live" {
		t.Fatal("unstarted destroy changed live state")
	}
}

func TestDestroyRecoveryPreviewNamesDatabaseRoleAndArchive(t *testing.T) {
	now := time.Now()
	rt := destroyReviewRecoveryRuntime(t, &now)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	j := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo", DropDatabases: true, DrainBoundNanos: int64(30 * time.Second), Removal: postgresRemoval{Databases: []string{"demo"}, Roles: []string{"demo_login"}}, PendingDatabases: []string{"demo"}, PendingRoles: []string{"demo_login"}}
	if err := writeDestroyCleanupJournalAt(rt.destroyJournalRoot, j); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	display := strings.Join(plan.Observed.Details, "\n")
	for _, part := range []string{"database demo", "role demo_login", planDestroyBackupPaths(&j)["demo"]} {
		if !strings.Contains(display, part) {
			t.Fatalf("recovery preview omits %s: %s", part, display)
		}
	}
}

func TestDestroyRecoveryReportIncludesPathsAndSettledFailure(t *testing.T) {
	root := setupPreRunBackupTest(t)
	oldBackups := destroyBackupRoot
	destroyBackupRoot = filepath.Join(root, "backups")
	t.Cleanup(func() { destroyBackupRoot = oldBackups })
	preRunTestBehavior = "fail-dump"
	now := time.Now()
	rt := destroyReviewRecoveryRuntime(t, &now)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	if err := writePostgresLedger(rt.appStateRoot, "demo", postgresLedger{Version: 1, Databases: []string{"demo"}, Roles: []string{"demo"}}); err != nil {
		t.Fatal(err)
	}
	j := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo", DropDatabases: true, DrainBoundNanos: int64(30 * time.Second), Removal: postgresRemoval{Databases: []string{"demo"}, Roles: []string{"demo"}}, PendingDatabases: []string{"demo"}, PendingRoles: []string{"demo"}, Progress: destroyCleanupProgress{ServicesRemoved: true, ContainersGone: true, StackRemoved: true, NetworksGone: true, SecretsPrepared: true, SecretsRemoved: true, VolumesPrepared: true, VolumesRemoved: true, RouteRemoved: true, RouteDirectorySynced: true, PostgresDropsPrepared: true, PostgresDropIntentsPrepared: true, CaddyReloaded: true}}
	if err := writeDestroyCleanupJournalAt(rt.destroyJournalRoot, j); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply)
	if err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("settled failure blocked recovery: %+v %v", record, err)
	}
	body, err := marshalRecoveryApplyReport(recovered, rt.completed, rt.remaining, rt.destroyFailure, rt.destroyDetails.String())
	if err == nil {
		t.Fatal("settled failure disappeared from report")
	}
	var report recoveryApplyReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(report.CompletedSteps, "\n"), "drop PostgreSQL") {
		t.Fatalf("report claims skipped drops completed: %s", body)
	}
	if len(report.Details) == 0 || !strings.Contains(strings.Join(report.Details, "\n"), "kept PostgreSQL database demo") {
		t.Fatalf("kept resources absent from report: %s", body)
	}
	path := filepath.Join(destroyBackupRoot, "demo", "archive.dump")
	body, err = marshalRecoveryApplyReport(recovered, nil, nil, nil, "backup PostgreSQL database demo -> "+path)
	if err != nil || !strings.Contains(string(body), path) {
		t.Fatalf("dump path absent from report: %s %v", body, err)
	}
}
