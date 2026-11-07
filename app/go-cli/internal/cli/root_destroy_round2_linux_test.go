//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDestroyRefusedDropSettlesAndAllowsNormalRetry(t *testing.T) {
	for _, binary := range []string{"/usr/bin/dropdb", "/usr/bin/dropuser"} {
		t.Run(binary, func(t *testing.T) {
			f := newDestroyFlow(t)
			drop := f.host.drop
			refuse := true
			f.host.drop = func(ctx context.Context, name string, args ...string) error {
				if refuse && args[3] == binary {
					return runDestroyFixed(ctx, "/bin/sh", "-c", "exit 1")
				}
				return drop(ctx, name, args...)
			}
			p, err := f.apply(true)
			var known *coord.KnownOutcomeError
			if !errors.As(err, &known) {
				t.Fatalf("refused drop left an unknown outcome: %v", err)
			}
			_ = f.finish(p, err)
			rec, e := f.coordinator.Get(context.Background(), p.OperationID)
			if e != nil || rec.State != "failed" || rec.RecoveryRequired {
				t.Fatalf("refused drop blocks host: %+v %v", rec, e)
			}
			j, _, e := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
			if e != nil || j != nil {
				t.Fatalf("settled failure left cleanup journal: %+v %v", j, e)
			}
			other, e := f.coordinator.Reserve(context.Background(), coord.Request{Kind: "deploy", App: "other", Principal: f.fingerprint, OwnerKeyFingerprint: f.fingerprint, Host: f.fingerprint})
			if e != nil {
				t.Fatal("other app remains blocked", e)
			}
			if e = other.Complete("test complete"); e != nil {
				t.Fatal(e)
			}
			refuse = false
			p, err = f.apply(true)
			if err != nil {
				t.Fatal("normal retry failed", err)
			}
			if err = f.finish(p, err); err != nil {
				t.Fatal(err)
			}
			if len(f.objects) != 0 {
				t.Fatalf("retry left objects: %v", f.objects)
			}
		})
	}
}

func TestDestroyRecoveryTakesFreshDumpWithoutDropIntent(t *testing.T) {
	f := newDestroyFlow(t)
	docker := f.host.docker
	fail := true
	f.host.docker = func(ctx context.Context, args ...string) ([]byte, error) {
		if fail && args[0] == "secret" && args[1] == "ls" {
			return nil, errors.New("daemon unavailable")
		}
		return docker(ctx, args...)
	}
	p, err := f.apply(true)
	if err == nil {
		t.Fatal("expected interrupted cleanup")
	}
	j, _, err := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
	if err != nil || j == nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(j.BackupPaths["demo"])
	if err != nil {
		t.Fatal(err)
	}
	fail = false
	f.events = append(f.events, "external-write")
	var out strings.Builder
	if err := removeRootStackWithConsent("demo", p.OperationID, nil, &out); err != nil {
		t.Fatal(err)
	}
	events := strings.Join(f.events, ",")
	write := strings.Index(events, "external-write")
	if !strings.Contains(events[write:], "dump") {
		t.Fatalf("recovery used stale dump: %v", f.events)
	}
	after, err := os.ReadFile(j.BackupPaths["demo"])
	if err != nil || string(before) != string(after) {
		t.Fatal("prior archive was overwritten", err)
	}
	if strings.Contains(out.String(), "verified archive retained") {
		t.Fatal("archive reused without matching drop intent")
	}
}

func TestDestroyRecoveryDetailsDoNotConsumeActionSlots(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(fmt.Sprint(drop), func(t *testing.T) {
			now := time.Now()
			rt := destroyReviewRecoveryRuntime(t, &now)
			c := newRecoveryCoordinator(t, &now)
			h := reserveRecovery(t, c, "destroy", "demo")
			var names []string
			for i := 0; i < 16; i++ {
				names = append(names, fmt.Sprintf("db_%02d", i))
			}
			j := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo", DropDatabases: drop, DrainBoundNanos: int64(30 * time.Second), Removal: postgresRemoval{Databases: names, Roles: names}, PendingDatabases: names, PendingRoles: names, Progress: destroyCleanupProgress{PostgresDropsPrepared: true, PostgresDropIntentsPrepared: true}}
			if err := writeDestroyCleanupJournalAt(rt.destroyJournalRoot, j); err != nil {
				t.Fatal(err)
			}
			plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
			if err != nil {
				t.Fatal("full inventory blocked recovery", err)
			}
			if len(plan.Actions) != 1 {
				t.Fatalf("inventory expanded executable actions: %v", plan.Actions)
			}
			for _, name := range names {
				details := strings.Join(plan.Observed.Details, "\n")
				if !strings.Contains(details, "database "+name) || !strings.Contains(details, "role "+name) {
					t.Fatalf("inventory omitted %s: %s", name, details)
				}
			}
			if drop && len(plan.Observed.Details) != 48 {
				t.Fatalf("missing dump targets: %v", plan.Observed.Details)
			}
		})
	}
}

func TestDestroyFailureSizeReportRemainsBounded(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestBehavior = "fail-dump"
	size := preRunDatabaseSize
	calls := 0
	preRunDatabaseSize = func(ctx context.Context, name string) (int64, error) {
		calls++
		if calls > 2 {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("post-failure size query has no deadline")
			}
			return 0, errors.New("database unavailable")
		}
		return size(ctx, name)
	}
	_, err := f.apply(true)
	if err == nil || calls < 3 {
		t.Fatalf("failure report not exercised: %v calls=%d", err, calls)
	}
}

func TestDestroyDropBoundaryRejectsFailedOrUnconfirmedDump(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			j := &destroyCleanupJournal{DropDatabases: true, PendingDatabases: []string{"demo"}, BackupPaths: map[string]string{"demo": "archive.dump"}}
			if failed {
				j.PostgresBackupFailure = "failed"
				j.PostgresBackupsComplete = true
			}
			dropped := false
			err := applyDestroyPostgresDrop(j, "database", "demo", func(string, string) (string, bool, error) { return "42", true, nil }, func() error { dropped = true; return nil }, func() error { return nil }, func(string) {})
			if err == nil || dropped {
				t.Fatalf("unsafe dump state allowed drop: %v dropped=%v", err, dropped)
			}
		})
	}
}

func TestDestroyFreshArchiveRequiresVerification(t *testing.T) {
	newDestroyFlow(t)
	paths := destroyDatabaseBackupPaths("demo", strings.Repeat("e", 32), []string{"demo"})
	preRunTestBehavior = "fail-restore"
	if err := backupDestroyDatabasesAt(context.Background(), "demo", []string{"demo"}, paths, io.Discard); err == nil {
		t.Fatal("fresh archive published without verification")
	}
	if _, err := os.Stat(paths["demo"]); !os.IsNotExist(err) {
		t.Fatalf("unverified archive published: %v", err)
	}
}

func TestDestroyBackupPlanAlwaysUsesFreshGeneration(t *testing.T) {
	old := destroyDatabaseBackupPaths("demo", strings.Repeat("e", 32), []string{"demo", "other"})
	j := destroyCleanupJournal{App: "demo", OperationID: strings.Repeat("e", 32), BackupPaths: old, PendingDatabases: []string{"demo", "other"}, PostgresDropIntent: &postgresDropIntent{Kind: "database", Name: "demo", OID: "42"}}
	paths := planDestroyBackupPaths(&j)
	if paths["demo"] == old["demo"] || paths["other"] == old["other"] {
		t.Fatalf("intent reused a stale database archive: %v", paths)
	}
}
