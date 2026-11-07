//go:build linux

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
)

func TestDestroyRecoveryRefreshesDumpAfterDurableIntent(t *testing.T) {
	f := newDestroyFlow(t)
	original := rootDestroyWriteJournal
	t.Cleanup(func() { rootDestroyWriteJournal = original })
	rootDestroyWriteJournal = func(root string, j destroyCleanupJournal) error {
		if err := original(root, j); err != nil {
			return err
		}
		if j.PostgresDropIntent != nil {
			return errors.New("crash after durable intent, before drop")
		}
		return nil
	}
	p, err := f.apply(true)
	if !errors.Is(err, errDestroyJournalProgress) {
		t.Fatalf("missing crash: %v", err)
	}
	rootDestroyWriteJournal = original
	j, _, err := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
	if err != nil || j == nil || j.PostgresDropIntent == nil {
		t.Fatalf("intent: %+v %v", j, err)
	}
	oldPath := j.BackupPaths["demo"]
	oldBody, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	n := len(f.events)
	f.events = append(f.events, "external-write")
	var out strings.Builder
	if err := removeRootStackWithConsent("demo", p.OperationID, nil, &out); err != nil {
		t.Fatal(err)
	}
	events := strings.Join(f.events[n:], ",")
	if !strings.HasPrefix(events, "external-write,dump,drop:database:demo") {
		t.Fatalf("same-OID database dropped without fresh dump: %s", events)
	}
	paths, err := filepath.Glob(filepath.Join(destroyBackupRoot, "demo", "*.dump"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("expected two generations: %v %v", paths, err)
	}
	after, err := os.ReadFile(oldPath)
	if err != nil || string(after) != string(oldBody) {
		t.Fatal("prior snapshot changed", err)
	}
	if strings.Contains(out.String(), "verified archive retained") {
		t.Fatal("stale snapshot reused")
	}
}

func TestDestroyRecoveryAfterRefusedDropPreservesLedger(t *testing.T) {
	f := newDestroyFlow(t)
	f.host.drop = func(context.Context, string, ...string) error {
		return runDestroyFixed(context.Background(), "/bin/sh", "-c", "exit 1")
	}
	reload := f.host.reload
	fail := true
	f.host.reload = func(deadline time.Time) error {
		if fail {
			return errors.New("reload failed after refused drop")
		}
		return reload(deadline)
	}
	p, err := f.apply(true)
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("missing reload failure: %v", err)
	}
	before, err := readPostgresLedger(f.host.stateRoot, "demo")
	if err != nil || len(before.Databases) != 1 || len(before.Roles) != 1 {
		t.Fatalf("ledger before recovery: %+v %v", before, err)
	}
	j, _, err := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
	if err != nil || j == nil || j.PostgresRemovalFailure == "" {
		t.Fatalf("missing durable refusal: %+v %v", j, err)
	}
	fail = false
	n := len(f.events)
	err = removeRootStackWithConsent("demo", p.OperationID, nil, io.Discard)
	var known *coord.KnownOutcomeError
	if !errors.As(err, &known) {
		t.Fatalf("recovery did not settle refusal: %v", err)
	}
	after, err := readPostgresLedger(f.host.stateRoot, "demo")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("recovery lost kept ledger: before=%+v after=%+v err=%v", before, after, err)
	}
	if !f.objects["database:demo"] || !f.objects["role:demo"] {
		t.Fatal("kept objects lost")
	}
	if _, err := os.Stat(filepath.Join(f.host.secretRoot, "demo", "postgres.password")); err != nil {
		t.Fatal("credential lost", err)
	}
	if strings.Contains(strings.Join(f.events[n:], ","), "drop:") {
		t.Fatal("recovery retried refused objects")
	}
	j, _, err = readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
	if err != nil || j != nil {
		t.Fatalf("cleanup not settled: %+v %v", j, err)
	}
}

func TestDestroyRefusedDatabaseAllowsFollowingDatabase(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestExisting["second"] = true
	f.objects["database:second"] = true
	if err := writePostgresLedger(f.host.stateRoot, "demo", postgresLedger{Version: 1, Databases: []string{"demo", "second"}, Roles: []string{"demo"}}); err != nil {
		t.Fatal(err)
	}
	drop := f.host.drop
	f.host.drop = func(ctx context.Context, binary string, args ...string) error {
		if args[3] == "/usr/bin/dropdb" && args[len(args)-1] == "demo" {
			return runDestroyFixed(ctx, "/bin/sh", "-c", "exit 1")
		}
		return drop(ctx, binary, args...)
	}
	p, err := f.apply(true)
	var known *coord.KnownOutcomeError
	if !errors.As(err, &known) {
		t.Fatalf("refusal not settled: %v", err)
	}
	_ = f.finish(p, err)
	if f.objects["database:second"] {
		t.Fatal("first refusal blocked the second database")
	}
	ledger, err := readPostgresLedger(f.host.stateRoot, "demo")
	if err != nil || !reflect.DeepEqual(ledger.Databases, []string{"demo"}) || !reflect.DeepEqual(ledger.Roles, []string{"demo"}) {
		t.Fatalf("incorrect remainder: %+v %v", ledger, err)
	}
}

func TestDestroyUncertainDropPreservesIntent(t *testing.T) {
	for _, reason := range []string{"timeout", "cancel", "signal", "unknown"} {
		t.Run(reason, func(t *testing.T) {
			f := newDestroyFlow(t)
			f.host.drop = func(context.Context, string, ...string) error {
				switch reason {
				case "timeout":
					return context.DeadlineExceeded
				case "cancel":
					return context.Canceled
				case "signal":
					return runDestroyFixed(context.Background(), "/bin/sh", "-c", "kill -TERM $$")
				default:
					return errors.New("outcome not available")
				}
			}
			p, err := f.apply(true)
			var known *coord.KnownOutcomeError
			if err == nil || errors.As(err, &known) {
				t.Fatalf("uncertain drop settled: %v", err)
			}
			j, _, err := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
			if err != nil || j == nil || j.PostgresDropIntent == nil || j.PostgresDropIntent.OID != "42" {
				t.Fatalf("uncertain drop lost intent: %+v %v", j, err)
			}
		})
	}
}
