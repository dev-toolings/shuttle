//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type destroyFlow struct {
	stderr      string
	t           *testing.T
	host        destroyHostRuntime
	coordinator *coord.Coordinator
	private     ed25519.PrivateKey
	fingerprint string
	events      []string
	objects     map[string]bool
	alive       bool
}

func newDestroyFlow(t *testing.T) *destroyFlow {
	root := setupPreRunBackupTest(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	oldHost, oldJournal, oldBackup := rootDestroyHost, rootDestroyCleanupRoot, destroyBackupRoot
	oldCoordinator, oldIdentity, oldGuard, oldPhase := rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, rootStackPhase
	t.Cleanup(func() {
		rootDestroyHost, rootDestroyCleanupRoot, destroyBackupRoot = oldHost, oldJournal, oldBackup
		rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, rootStackPhase = oldCoordinator, oldIdentity, oldGuard, oldPhase
	})
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	f := &destroyFlow{t: t, private: private, fingerprint: "SHA256:" + strings.Repeat("a", 43), alive: true, objects: map[string]bool{"database:demo": true, "role:demo": true}}
	f.coordinator = coord.New(coord.Options{Root: filepath.Join(root, "operations"), LockPath: filepath.Join(root, "lock"), BootID: func() (string, error) { return "boot", nil }})
	rootOperationCoordinator = func() *coord.Coordinator { return f.coordinator }
	rootCoordinatedIdentityVerifier = func(p rootplan.Plan) error { return rootplan.Verify(p, public, time.Now()) }
	rootCoordinatedMutationGuard = func(string) error { return nil }
	rootStackPhase = withCoordinatedRootPhase
	rootDestroyCleanupRoot, destroyBackupRoot = filepath.Join(root, "journal"), filepath.Join(root, "backups")
	f.host = destroyHostRuntime{stateRoot: filepath.Join(root, "apps"), secretRoot: filepath.Join(root, "secrets"), caddyRoot: filepath.Join(root, "caddy")}
	for _, dir := range []string{f.host.caddyRoot, filepath.Join(f.host.secretRoot, "demo")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePostgresLedger(f.host.stateRoot, "demo", postgresLedger{Version: 1, Databases: []string{"demo"}, Roles: []string{"demo"}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.host.stateRoot, "demo", "current.yml"), []byte("live"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.host.secretRoot, "demo", "postgres.password"), []byte("test-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	f.host.docker = func(_ context.Context, args ...string) ([]byte, error) {
		switch {
		case args[0] == "service" && args[1] == "ls":
			if f.alive {
				return []byte("service1"), nil
			}
			return nil, nil
		case args[0] == "service" && args[1] == "inspect":
			return []byte("0"), nil
		case args[0] == "service" && args[1] == "rm":
			f.events = append(f.events, "drain")
			f.alive = false
			return nil, nil
		case args[0] == "ps" || args[0] == "network" && args[1] == "ls" || args[0] == "volume" && args[1] == "ls" || args[0] == "secret" && args[1] == "ls":
			return nil, nil
		case args[0] == "volume" && args[1] == "inspect":
			return nil, errors.New("No such volume: " + args[len(args)-1])
		case args[0] == "secret" && args[1] == "inspect":
			return nil, errors.New("No such secret: " + args[len(args)-1])
		case args[0] == "stack" && args[1] == "rm":
			f.events = append(f.events, "stack-rm")
			return nil, nil
		default:
			t.Fatalf("unexpected Docker command %v", args)
			return nil, nil
		}
	}
	f.host.oid = func(_ context.Context, kind, name string) (string, bool, error) {
		return "42", f.objects[kind+":"+name], nil
	}
	f.host.drop = func(_ context.Context, binary string, args ...string) error {
		kind := "database"
		if args[3] == "/usr/bin/dropuser" {
			kind = "role"
		}
		name := args[len(args)-1]
		f.events = append(f.events, "drop:"+kind+":"+name)
		delete(f.objects, kind+":"+name)
		return nil
	}
	f.host.reload = func(time.Time) error { f.events = append(f.events, "reload"); return nil }
	rootDestroyHost = func() destroyHostRuntime { return f.host }
	stubRemovalPostgresProbes(t, false, nil, nil)
	oldCommand := preRunCommand
	preRunCommand = func(ctx context.Context, pg bool, name string, args ...string) *exec.Cmd {
		if name == "pg_dump" {
			f.events = append(f.events, "dump")
		}
		return oldCommand(ctx, pg, name, args...)
	}
	return f
}

func (f *destroyFlow) apply(drop bool) (rootplan.Plan, error) {
	f.t.Helper()
	h, err := f.coordinator.Reserve(context.Background(), coord.Request{Kind: "destroy", App: "demo", Principal: f.fingerprint, OwnerKeyFingerprint: f.fingerprint, Host: f.fingerprint})
	if err != nil {
		f.t.Fatal(err)
	}
	req := coord.PhaseRequest{ID: h.ID(), Kind: "destroy", App: "demo", Principal: f.fingerprint, OwnerKeyFingerprint: f.fingerprint, Host: f.fingerprint, Name: "writers-initialize"}
	if err := f.coordinator.ExecutePhase(context.Background(), req, func(_ context.Context, record coord.Record) error {
		_, err := operationwriters.NewStore(f.coordinator.Root()).InitializeLocked(operationWriterBinding(record), operationwriters.Baseline{ConfiguredNativePGVersion: "not-configured", ConfiguredNativePGCluster: "not-configured"})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	p, err := rootplan.NewStackRemove("demo", f.fingerprint, f.fingerprint, time.Now(), time.Minute)
	if err == nil {
		p.Stack.DropDatabases = drop
		p, err = bindOperationPlan(p, h.ID(), "destroy", "demo")
	}
	if err == nil {
		p, err = rootplan.Sign(p, f.private)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		f.t.Fatal(err)
	}
	previous := os.Stderr
	defer func() { os.Stderr = previous; read.Close(); write.Close() }()
	os.Stderr = write
	applyErr := applyRootStack(p, nil)
	write.Close()
	os.Stderr = previous
	body, err := io.ReadAll(read)
	if err != nil {
		f.t.Fatal(err)
	}
	f.stderr = string(body)
	return p, applyErr
}

func TestDestroySignedConsentReachesJournalAndDrops(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "drop"}[drop], func(t *testing.T) {
			f := newDestroyFlow(t)
			_, err := f.apply(drop)
			if err != nil {
				t.Fatal(err)
			}
			if f.objects["database:demo"] == drop || f.objects["role:demo"] == drop {
				t.Fatalf("signed drop=%v objects=%v events=%v", drop, f.objects, f.events)
			}
			ledger, err := readPostgresLedger(f.host.stateRoot, "demo")
			if err != nil {
				t.Fatal(err)
			}
			if !drop && (!reflect.DeepEqual(ledger.Databases, []string{"demo"}) || !reflect.DeepEqual(ledger.Roles, []string{"demo"})) {
				t.Fatalf("kept ledger lost: %+v", ledger)
			}
			if !drop {
				if _, err := os.Stat(filepath.Join(f.host.secretRoot, "demo", "postgres.password")); err != nil {
					t.Fatal("kept credential removed", err)
				}
			}
		})
	}
}

func TestDestroyDumpsOnlyAfterDrain(t *testing.T) {
	f := newDestroyFlow(t)
	_, err := f.apply(true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.events, ",")
	if strings.Index(joined, "drain") > strings.Index(joined, "dump") {
		t.Fatalf("dump precedes drain: %v", f.events)
	}
}

func TestDestroyCapacityRefusalKeepsLiveApp(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestAvailable = 1
	p, err := f.apply(true)
	if err == nil || !f.alive || len(f.events) != 0 {
		t.Fatalf("capacity not refused before mutation: err=%v alive=%v events=%v", err, f.alive, f.events)
	}
	j, _, e := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
	if e != nil || j != nil {
		t.Fatalf("refusal left journal: %+v %v", j, e)
	}
	_ = f.finish(p, err)
	record, e := f.coordinator.Get(context.Background(), p.OperationID)
	if e != nil || record.RecoveryRequired || record.State != "failed" {
		t.Fatalf("refusal blocked host: %+v %v", record, e)
	}
}

func (f *destroyFlow) finish(p rootplan.Plan, operationErr error) error {
	oldRequest, oldControl := remoteOperationWriterRequest, remoteOperationControl
	defer func() { remoteOperationWriterRequest, remoteOperationControl = oldRequest, oldControl }()
	remoteOperationWriterRequest = func(_ *remoteOperation, envelope []byte) shuttlessh.Result {
		plan, _, err := decodeRootHelperEnvelope(bytes.NewReader(envelope))
		if err != nil {
			return shuttlessh.Result{Code: 1, Stderr: err.Error()}
		}
		body, err := controlRootOperationWriters(context.Background(), plan)
		if err != nil {
			return shuttlessh.Result{Code: 1, Stderr: err.Error()}
		}
		return shuttlessh.Result{Stdout: string(body)}
	}
	remoteOperationControl = func(o *remoteOperation, action, result string) error {
		plan, err := rootplan.NewOperationControl(action, o.id, o.kind, o.app, result, f.fingerprint, f.fingerprint, time.Now(), time.Minute)
		if err == nil {
			plan, err = rootplan.Sign(plan, f.private)
		}
		if err != nil {
			return err
		}
		_, err = controlRootOperationWith(context.Background(), f.coordinator, plan)
		return err
	}
	o := &remoteOperation{id: p.OperationID, kind: "destroy", app: "demo", key: f.private, identity: trustedHostIdentity{OperatorKeyFingerprint: f.fingerprint, HostKeyFingerprint: f.fingerprint}}
	if operationErr != nil {
		operationErr = reportDestroyResult(io.Discard, shuttlessh.Result{Code: 1, Stderr: f.stderr}, o)
	}
	o.finish(&operationErr)
	return operationErr
}

func TestDestroyDumpFailureFinishesAndNormalRetryDropsKeptLedger(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestBehavior = "fail-db:second"
	preRunTestExisting["second"] = true
	f.objects["database:second"] = true
	if err := writePostgresLedger(f.host.stateRoot, "demo", postgresLedger{Version: 1, Databases: []string{"demo", "second"}, Roles: []string{"demo"}}); err != nil {
		t.Fatal(err)
	}
	p, err := f.apply(true)
	var known *coord.KnownOutcomeError
	if !errors.As(err, &known) {
		t.Fatalf("dump failure is not a settled failure: %v events=%v", err, f.events)
	}
	if f.alive || !f.objects["database:demo"] || !f.objects["role:demo"] || !f.objects["database:second"] {
		t.Fatalf("wrong failure outcome: alive=%v objects=%v", f.alive, f.objects)
	}
	if !strings.Contains(err.Error(), "shuttle destroy --drop-databases --yes") {
		t.Fatal("missing retry command", err)
	}
	_ = f.finish(p, err)
	record, e := f.coordinator.Get(context.Background(), p.OperationID)
	if e != nil || record.RecoveryRequired || record.State != "failed" {
		t.Fatalf("failed dump blocked retry: %+v %v", record, e)
	}
	j, _, e := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, p.OperationID, "demo")
	if e != nil || j != nil {
		t.Fatalf("settled destroy left journal: %+v %v", j, e)
	}
	preRunTestBehavior = ""
	p, err = f.apply(true)
	if err != nil {
		t.Fatalf("normal retry failed with stack gone: %v", err)
	}
	if len(f.objects) != 0 {
		t.Fatalf("retry left objects: %v", f.objects)
	}
	if err := f.finish(p, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyKeepsLoginRoleWhileAnyDatabaseKept(t *testing.T) {
	drops := 0
	removal := postgresRemoval{Roles: []string{"demo_login"}, Kept: []keptPostgresObject{{Kind: "database", Name: "external", Reason: "not owned"}}}
	_, withheld, _ := applyPostgresRemoval("demo", removal, func(string, string) error { drops++; return nil })
	if drops != 0 || !reflect.DeepEqual(withheld, []string{"demo_login"}) {
		t.Fatalf("role used for login to a kept database was dropped: drops=%d withheld=%v", drops, withheld)
	}
}

func TestDestroySettledDumpFailureCannotReplaySignedConsent(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestBehavior = "fail-dump"
	p, err := f.apply(true)
	if err == nil {
		t.Fatal("expected dump failure")
	}
	preRunTestBehavior = ""
	before := len(f.events)
	if err := applyRootStack(p, nil); err == nil || len(f.events) != before {
		t.Fatalf("settled failed destroy replayed: err=%v events=%v", err, f.events)
	}
}

func TestDestroyRecoveryKeepsLegacyPendingObjectsAndLedger(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "replan", true: "prepared"}[prepared], func(t *testing.T) {
			f := newDestroyFlow(t)
			id := strings.Repeat("b", 32)
			j := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: id, App: "demo", DrainBoundNanos: int64(30 * time.Second), Removal: postgresRemoval{Databases: []string{"demo"}, Roles: []string{"demo"}}, PendingDatabases: []string{"demo"}, PendingRoles: []string{"demo"}, Progress: destroyCleanupProgress{PostgresDropsPrepared: prepared, PostgresDropIntentsPrepared: true}}
			if err := writeDestroyCleanupJournalAt(rootDestroyCleanupRoot, j); err != nil {
				t.Fatal(err)
			}
			if err := removeRootStackWithConsent("demo", id, nil, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !f.objects["database:demo"] || !f.objects["role:demo"] {
				t.Fatalf("legacy recovery dropped objects: %v", f.events)
			}
			ledger, err := readPostgresLedger(f.host.stateRoot, "demo")
			if err != nil || len(ledger.Databases) != 1 || len(ledger.Roles) != 1 {
				t.Fatalf("legacy recovery lost ownership: %+v %v", ledger, err)
			}
		})
	}
}

func TestDestroyRecoveryCannotChangeConsentOrInventJournal(t *testing.T) {
	f := newDestroyFlow(t)
	id := strings.Repeat("b", 32)
	if err := removeRootStackWithConsent("demo", id, nil, io.Discard); err == nil {
		t.Fatal("recovery invented consent without a journal")
	}
	j := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: id, App: "demo", DrainBoundNanos: int64(30 * time.Second)}
	if err := writeDestroyCleanupJournalAt(rootDestroyCleanupRoot, j); err != nil {
		t.Fatal(err)
	}
	yes := true
	if err := removeRootStackWithConsent("demo", id, &yes, io.Discard); err == nil || !strings.Contains(err.Error(), "consent differs") {
		t.Fatalf("changed consent accepted: %v", err)
	}
	if len(f.events) != 0 {
		t.Fatalf("refusal mutated host: %v", f.events)
	}
}

func TestDestroyRecoveryNeverRetriesDumpFailureDrops(t *testing.T) {
	f := newDestroyFlow(t)
	id := strings.Repeat("c", 32)
	j := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: id, App: "demo", DropDatabases: true, PostgresBackupFailure: "dump failed", DrainBoundNanos: int64(30 * time.Second), Removal: postgresRemoval{Databases: []string{"demo"}, Roles: []string{"demo"}}, PendingDatabases: []string{"demo"}, PendingRoles: []string{"demo"}, Progress: destroyCleanupProgress{PostgresDropsPrepared: true, PostgresDropIntentsPrepared: true}}
	if err := writeDestroyCleanupJournalAt(rootDestroyCleanupRoot, j); err != nil {
		t.Fatal(err)
	}
	err := removeRootStackWithConsent("demo", id, nil, io.Discard)
	var known *coord.KnownOutcomeError
	if !errors.As(err, &known) || !f.objects["database:demo"] || !f.objects["role:demo"] {
		t.Fatalf("failed dump retried deletion: %v events=%v", err, f.events)
	}
	for _, event := range f.events {
		if event == "dump" || strings.HasPrefix(event, "drop:") {
			t.Fatalf("recovery retried failed snapshot: %v", f.events)
		}
	}
}

func TestDestroyPublishesOnlyCompleteVerifiedArchives(t *testing.T) {
	f := newDestroyFlow(t)
	old := preRunCommand
	preRunCommand = func(ctx context.Context, pg bool, name string, args ...string) *exec.Cmd {
		if name == "pg_restore" {
			finals, _ := filepath.Glob(filepath.Join(destroyBackupRoot, "demo", "*.dump"))
			if len(finals) != 0 {
				t.Fatalf("unverified archive published: %v", finals)
			}
			temps, _ := filepath.Glob(filepath.Join(destroyBackupRoot, "demo", ".destroy-*"))
			if len(temps) != 1 {
				t.Fatalf("missing temporary archive: %v", temps)
			}
		}
		return old(ctx, pg, name, args...)
	}
	_, err := f.apply(true)
	if err != nil {
		t.Fatal(err)
	}
	finals, _ := filepath.Glob(filepath.Join(destroyBackupRoot, "demo", "*.dump"))
	if len(finals) != 1 {
		t.Fatalf("archive not published: %v", finals)
	}
	info, err := os.Stat(finals[0])
	if err != nil || info.Size() == 0 || info.Mode().Perm() != 0600 {
		t.Fatalf("invalid archive: %v", err)
	}
	temps, _ := filepath.Glob(filepath.Join(destroyBackupRoot, "demo", ".destroy-*"))
	if len(temps) != 0 {
		t.Fatalf("temporary file survived rename: %v", temps)
	}
}

func TestDestroyRecoveryDoesNotOverwritePublishedArchive(t *testing.T) {
	newDestroyFlow(t)
	paths := destroyDatabaseBackupPaths("demo", strings.Repeat("d", 32), []string{"demo"})
	if err := backupDestroyDatabasesAt(context.Background(), "demo", []string{"demo"}, paths, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(paths["demo"])
	if err != nil {
		t.Fatal(err)
	}
	old := preRunCommand
	preRunCommand = func(ctx context.Context, pg bool, name string, args ...string) *exec.Cmd {
		if name == "pg_dump" {
			t.Fatal("recovery overwrites original archive with a possibly recreated database")
		}
		return old(ctx, pg, name, args...)
	}
	if err := backupDestroyDatabasesAt(context.Background(), "demo", []string{"demo"}, paths, io.Discard); err == nil {
		t.Fatal("existing archive path must be refused")
	}
	after, err := os.ReadFile(paths["demo"])
	if err != nil || string(after) != string(before) {
		t.Fatal("published archive changed", err)
	}
}

func TestDestroyRecoveryKeepsDataWhenDumpFailureCannotBeJournaled(t *testing.T) {
	f := newDestroyFlow(t)
	preRunTestBehavior = "fail-dump"
	old := rootDestroyWriteJournal
	t.Cleanup(func() { rootDestroyWriteJournal = old })
	rootDestroyWriteJournal = func(root string, j destroyCleanupJournal) error {
		if j.PostgresBackupFailure != "" {
			return errors.New("simulated journal disk failure")
		}
		return old(root, j)
	}
	p, err := f.apply(true)
	if err == nil {
		t.Fatal("expected journal failure")
	}
	rootDestroyWriteJournal = old
	preRunTestBehavior = ""
	err = removeRootStackWithConsent("demo", p.OperationID, nil, io.Discard)
	var known *coord.KnownOutcomeError
	if !errors.As(err, &known) || !f.objects["database:demo"] || !f.objects["role:demo"] {
		t.Fatalf("recovery lost failed-dump keep decision: %v objects=%v events=%v", err, f.objects, f.events)
	}
}
