//go:build linux

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
)

func TestDestroyExitOneReconcilesOID(t *testing.T) {
	for _, outcome := range []string{"absent", "same", "recreated", "unreadable"} {
		t.Run(outcome, func(t *testing.T) {
			f := newDestroyFlow(t)
			attempted := false
			f.host.drop = func(context.Context, string, ...string) error {
				attempted = true
				if outcome == "absent" {
					delete(f.objects, "database:demo")
				}
				return runDestroyFixed(context.Background(), "/bin/sh", "-c", "exit 1")
			}
			f.host.oid = func(_ context.Context, kind, name string) (string, bool, error) {
				if attempted && kind == "database" {
					switch outcome {
					case "recreated":
						return "99", true, nil
					case "unreadable":
						return "", false, errors.New("connection lost")
					}
				}
				return "42", f.objects[kind+":"+name], nil
			}
			p, err := f.apply(true)
			j, _, readErr := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
			if readErr != nil {
				t.Fatal(readErr)
			}
			if outcome == "recreated" || outcome == "unreadable" {
				var known *coord.KnownOutcomeError
				if err == nil || errors.As(err, &known) || j == nil || j.PostgresDropIntent == nil || j.PostgresDropIntent.OID != "42" {
					t.Fatalf("uncertain exit lost intent: journal=%+v err=%v", j, err)
				}
				return
			}
			ledger, e := readPostgresLedger(f.host.stateRoot, "demo")
			if e != nil {
				t.Fatal(e)
			}
			if outcome == "absent" && len(ledger.Databases) != 0 {
				t.Fatalf("completed drop still owned: %+v", ledger)
			}
			if outcome == "same" && (j != nil || !reflect.DeepEqual(ledger.Databases, []string{"demo"})) {
				t.Fatalf("refusal not settled: %+v %+v %v", j, ledger, err)
			}
		})
	}
}

func TestDestroyRecoveryChecksCapacityForEveryGeneration(t *testing.T) {
	f := newDestroyFlow(t)
	docker := f.host.docker
	fail := true
	f.host.docker = func(ctx context.Context, args ...string) ([]byte, error) {
		if fail && args[0] == "secret" && args[1] == "ls" {
			return nil, errors.New("crash after dump")
		}
		return docker(ctx, args...)
	}
	p, err := f.apply(true)
	if err == nil {
		t.Fatal("missing interruption")
	}
	fail = false
	preRunTestAvailable, preRunTestTotal = 1, 1000
	n := len(f.events)
	err = removeRootStackWithConsent("demo", p.OperationID, nil, io.Discard)
	var known *coord.KnownOutcomeError
	if !errors.As(err, &known) || !strings.Contains(err.Error(), "not enough space") {
		t.Fatalf("capacity refusal not settled: %v", err)
	}
	for _, event := range f.events[n:] {
		if event == "dump" || strings.HasPrefix(event, "drop:") {
			t.Fatalf("insufficient capacity allowed %s", event)
		}
	}
	if !f.objects["database:demo"] || !f.objects["role:demo"] {
		t.Fatal("data lost")
	}
}

func TestDestroyDumpBudgetUsesSizeAndKeepsOversizedData(t *testing.T) {
	for _, size := range []int64{100, 400 << 20, 1 << 40} {
		t.Run(humanBytes(uint64(size)), func(t *testing.T) {
			f := newDestroyFlow(t)
			preRunTestSize, preRunTestAvailable, preRunTestTotal = size, 2<<40, 3<<40
			command := preRunCommand
			var budget time.Duration
			preRunCommand = func(ctx context.Context, pg bool, name string, args ...string) *exec.Cmd {
				if name == "pg_dump" {
					deadline, ok := ctx.Deadline()
					if !ok {
						t.Error("dump has no deadline")
					}
					budget = time.Until(deadline)
				}
				return command(ctx, pg, name, args...)
			}
			_, err := f.apply(true)
			if size == 1<<40 {
				var known *coord.KnownOutcomeError
				if !errors.As(err, &known) || !strings.Contains(err.Error(), "dump budget") || budget != 0 || !f.objects["database:demo"] {
					t.Fatalf("oversized dump not kept: budget=%s err=%v", budget, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if size == 100 && budget >= time.Minute {
					t.Fatalf("tiny dump still has fixed budget: %s", budget)
				}
				if size == 400<<20 && (budget <= 5*time.Minute || budget >= rootOperationBudget-rootHelperOperationMargin) {
					t.Fatalf("large dump budget not derived within watchdog: %s", budget)
				}
			}
		})
	}
}

func TestDestroyFailedRecoveryDumpReportsOnlyPendingObjects(t *testing.T) {
	for _, failure := range []string{"new-failure", "recorded-failure", "unpersisted-failure"} {
		t.Run(failure, func(t *testing.T) {
			f := newDestroyFlow(t)
			preRunTestExisting["second"], f.objects["database:second"] = true, true
			if err := writePostgresLedger(f.host.stateRoot, "demo", postgresLedger{Version: 1, Databases: []string{"demo", "second"}, Roles: []string{"demo"}}); err != nil {
				t.Fatal(err)
			}
			original := rootDestroyWriteJournal
			t.Cleanup(func() { rootDestroyWriteJournal = original })
			rootDestroyWriteJournal = func(root string, j destroyCleanupJournal) error {
				if err := original(root, j); err != nil {
					return err
				}
				if j.Progress.PostgresDropIntentsPrepared && len(j.PendingDatabases) == 1 && j.PendingDatabases[0] == "second" {
					return errors.New("crash after first drop")
				}
				return nil
			}
			p, err := f.apply(true)
			if err == nil {
				t.Fatal("missing crash")
			}
			rootDestroyWriteJournal = original
			j, _, err := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
			if err != nil || j == nil {
				t.Fatalf("journal: %v", err)
			}
			if failure == "recorded-failure" {
				j.PostgresBackupFailure = "final dump failed"
				if err := original(rootDestroyCleanupRoot, *j); err != nil {
					t.Fatal(err)
				}
			}
			preRunTestBehavior = "fail-db:second"
			if failure == "unpersisted-failure" {
				rootDestroyWriteJournal = func(root string, j destroyCleanupJournal) error {
					if j.PostgresBackupFailure != "" {
						return errors.New("dump failure record could not be persisted")
					}
					return original(root, j)
				}
				if err := removeRootStackWithConsent("demo", p.OperationID, nil, io.Discard); err == nil {
					t.Fatal("missing failure-record write error")
				}
				rootDestroyWriteJournal = original
				preRunTestBehavior = ""
			}
			var out strings.Builder
			err = removeRootStackWithConsent("demo", p.OperationID, nil, &out)
			if err == nil {
				t.Fatal("expected kept failure")
			}
			ledger, ledgerErr := readPostgresLedger(f.host.stateRoot, "demo")
			if ledgerErr != nil || !reflect.DeepEqual(ledger.Databases, []string{"second"}) || !reflect.DeepEqual(ledger.Roles, []string{"demo"}) {
				t.Fatalf("completed drop still owned or pending ownership lost: %+v err=%v", ledger, ledgerErr)
			}
			if f.objects["database:demo"] || !f.objects["database:second"] || !f.objects["role:demo"] {
				t.Fatalf("unexpected live objects: %v", f.objects)
			}
			if _, err := os.Stat(filepath.Join(f.host.secretRoot, "demo", "postgres.password")); err != nil {
				t.Fatal("pending credentials lost", err)
			}
			j, _, err = readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
			if err != nil || j != nil {
				t.Fatalf("settled failure left journal: %+v %v", j, err)
			}
			if strings.Contains(out.String(), "kept PostgreSQL database demo") || strings.Contains(out.String(), "--drop-databases was not requested") || !strings.Contains(out.String(), "kept PostgreSQL database second") {
				t.Fatalf("false kept report: %s", out.String())
			}
			// A replacement created outside Shuttle must not regain ownership
			// from the stale name on a later, freshly consented destroy.
			f.objects["database:demo"] = true
			stubRemovalPostgresProbes(t, true, func(name string) (bool, error) { return f.objects["database:"+name], nil }, func(name string) (bool, error) { return f.objects["role:"+name], nil })
			next, err := planPostgresRemovalWithContext(context.Background(), f.host.stateRoot, "demo")
			if err != nil || !reflect.DeepEqual(next.Databases, []string{"second"}) {
				t.Fatalf("fresh destroy would own the replacement: %+v %v", next, err)
			}
		})
	}
}

func TestDestroyDumpFailureIncludesSanitizedStderr(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestBehavior = "fail-dump"
	_, err := f.apply(true)
	if err == nil || !strings.Contains(err.Error(), "dump failed DETAIL: rejected") {
		t.Fatalf("pg_dump diagnostic lost: %v", err)
	}
}

func TestDestroyWithoutPostgresRemovesAppNamespace(t *testing.T) {
	f := newDestroyFlow(t)
	if err := os.Remove(filepath.Join(f.host.stateRoot, "demo", "postgres.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.host.stateRoot, "demo")); !os.IsNotExist(err) {
		t.Fatalf("empty app namespace retained: %v", err)
	}
}

func TestDestroyDumpBudgetReservesCleanupAfterSlowDrain(t *testing.T) {
	newDestroyFlow(t)
	// A five-minute drain leaves three minutes for all dumps and two for cleanup.
	remaining := rootOperationBudget - destroyDrainCeiling - rootHelperOperationMargin
	preRunTestSize = 400 << 20
	if _, err := destroyDumpBudget(context.Background(), []string{"demo"}, remaining); err == nil {
		t.Fatal("oversized dump consumed cleanup reserve after slow drain")
	}
	preRunTestSize = 60 << 20
	budget, err := destroyDumpBudget(context.Background(), []string{"demo"}, remaining)
	if err != nil || budget <= time.Minute || budget > remaining {
		t.Fatalf("small dump does not fit: %s %v", budget, err)
	}
	if _, err := destroyDumpBudget(context.Background(), []string{"demo", "second"}, remaining); err == nil {
		t.Fatal("per-database budgets exceed the shared deadline")
	}
}

func TestDestroyDumpIncludesTimeAlreadySpentInRecoveryObservation(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestSize = 100 << 20
	// The phase watchdog started before recovery observed the host. Model seven
	// minutes of observation/drain without sleeping or running a real watchdog.
	rootWatchdogState.Lock()
	saved := rootWatchdogState.deadline
	rootWatchdogState.deadline = time.Now().Add(3 * time.Minute)
	rootWatchdogState.Unlock()
	t.Cleanup(func() { rootWatchdogState.Lock(); rootWatchdogState.deadline = saved; rootWatchdogState.Unlock() })
	consent := true
	err := removeRootStackWithRuntime(f.host, "demo", strings.Repeat("c", 32), &consent, io.Discard)
	var known *coord.KnownOutcomeError
	if !errors.As(err, &known) || !strings.Contains(err.Error(), "dump budget") || !f.objects["database:demo"] {
		t.Fatalf("observation time excluded from budget: %v events=%v", err, f.events)
	}
}

func TestDestroyPruneKeepsJournalUntilLedgerDurable(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(map[bool]string{false: "unpersisted-failure", true: "recorded-failure"}[recorded], func(t *testing.T) {
			f := newDestroyFlow(t)
			id := strings.Repeat("d", 32)
			ledger := postgresLedger{Version: 1, Databases: []string{"alpha", "demo", "kept", "outside"}, Roles: []string{"completed_role", "demo", "kept_role"}}
			if err := writePostgresLedger(f.host.stateRoot, "demo", ledger); err != nil {
				t.Fatal(err)
			}
			j := destroyCleanupJournal{
				Schema: rootDestroyCleanupSchema, OperationID: id, App: "demo", DropDatabases: true, DrainBoundNanos: int64(30 * time.Second),
				Removal:          postgresRemoval{Databases: []string{"alpha", "demo", "kept"}, Roles: []string{"completed_role", "demo", "kept_role"}, Kept: []keptPostgresObject{{Kind: "database", Name: "kept", Reason: "kept explicitly"}, {Kind: "role", Name: "kept_role", Reason: "kept explicitly"}}},
				PendingDatabases: []string{"demo"}, PendingRoles: []string{"demo"},
				BackupPaths: destroyDatabaseBackupPaths("demo", id, []string{"demo"}),
				Progress:    destroyCleanupProgress{PostgresDropsPrepared: true, PostgresDropIntentsPrepared: true},
			}
			if recorded {
				j.PostgresBackupFailure = "final dump failed"
			}
			if err := rootDestroyWriteJournal(rootDestroyCleanupRoot, j); err != nil {
				t.Fatal(err)
			}
			originalSync := syncRootFileDirectory
			t.Cleanup(func() { syncRootFileDirectory = originalSync })
			syncRootFileDirectory = func(path string) error {
				if path == filepath.Join(f.host.stateRoot, "demo") {
					return errors.New("ledger directory sync failed")
				}
				return originalSync(path)
			}
			err := removeRootStackWithConsent("demo", id, nil, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "ledger directory sync failed") {
				t.Fatalf("ledger failure not returned: %v", err)
			}
			retained, _, readErr := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, id, "demo")
			if readErr != nil || retained == nil || !reflect.DeepEqual(retained.Removal.Databases, j.Removal.Databases) || !reflect.DeepEqual(retained.PendingDatabases, j.PendingDatabases) {
				t.Fatalf("ledger write failure lost completion proof: %+v %v", retained, readErr)
			}
			// Rename has succeeded; recovery must still make that pruning durable
			// before discarding its proof, even if no ledger entry now needs removal.
			if err := removeRootStackWithConsent("demo", id, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "ledger directory sync failed") {
				t.Fatalf("retry forgot unsynced ledger: %v", err)
			}
			syncRootFileDirectory = originalSync
			err = removeRootStackWithConsent("demo", id, nil, io.Discard)
			var known *coord.KnownOutcomeError
			if !errors.As(err, &known) {
				t.Fatalf("recovery did not settle kept data: %v", err)
			}
			actual, err := readPostgresLedger(f.host.stateRoot, "demo")
			if err != nil || !reflect.DeepEqual(actual.Databases, []string{"demo", "kept", "outside"}) || !reflect.DeepEqual(actual.Roles, []string{"demo", "kept_role"}) {
				t.Fatalf("prune removed pending, kept or unrelated ownership: %+v %v", actual, err)
			}
			retained, _, err = readDestroyCleanupJournalAt(rootDestroyCleanupRoot, id, "demo")
			if err != nil || retained != nil {
				t.Fatalf("durable settlement left journal: %+v %v", retained, err)
			}
			for _, event := range f.events {
				if strings.HasPrefix(event, "drop:") || event == "dump" {
					t.Fatalf("failed dump replayed PostgreSQL mutation: %s", event)
				}
			}
		})
	}
}
