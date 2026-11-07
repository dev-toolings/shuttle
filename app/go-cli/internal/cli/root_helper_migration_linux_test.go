//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestRootHelperMigrationProbeRequiresExactParentAndFiles(t *testing.T) {
	staging := t.TempDir()
	if err := os.Chmod(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(staging, ".shuttle-root.next-candidate")
	if err := writeTestFile(candidate, []byte("candidate"), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		t.Fatal(err)
	}
	stageInfo, err := os.Lstat(staging)
	if err != nil {
		t.Fatal(err)
	}
	spec := helperMigrationProbeSpec{
		CandidatePath:            candidate,
		StagingDir:               staging,
		InstalledPath:            "/usr/local/libexec/shuttle-root",
		LockPath:                 "/run/shuttle-root.lock",
		ExpectedParentExecutable: "/usr/local/libexec/shuttle-root",
		ExpectedParentArgv:       []string{"/usr/local/libexec/shuttle-root", "apply"},
		ExpectedCandidateArgv:    []string{"shuttle-root", "--help"},
		ExpectedUID:              0,
	}
	valid := helperMigrationProbeObservation{
		CandidateInfo: info, StagingInfo: stageInfo, CandidateOwned: true, StagingOwned: true, CandidateArgv: []string{"shuttle-root", "--help"},
		ParentUID: 0, ParentExecutable: spec.ExpectedParentExecutable,
		ParentArgv: spec.ExpectedParentArgv, ParentHasLock: true, ParentLockInode: true,
	}
	if err := validateHelperMigrationProbe(spec, valid); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*helperMigrationProbeObservation){
		"wrong executable": func(observation *helperMigrationProbeObservation) { observation.ParentExecutable = "/tmp/fake-helper" },
		"wrong argv": func(observation *helperMigrationProbeObservation) {
			observation.ParentArgv = []string{"shuttle-root", "apply", "extra"}
		},
		"unlocked parent": func(observation *helperMigrationProbeObservation) { observation.ParentHasLock = false },
		"wrong uid":       func(observation *helperMigrationProbeObservation) { observation.ParentUID = 1000 },
		"candidate owner": func(observation *helperMigrationProbeObservation) { observation.CandidateOwned = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			observation := valid
			mutate(&observation)
			if err := validateHelperMigrationProbe(spec, observation); err == nil {
				t.Fatal("unsafe probe observation was accepted")
			}
		})
	}

	link := filepath.Join(staging, ".shuttle-root.next-link")
	if err := os.Symlink(candidate, link); err != nil {
		t.Fatal(err)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	unsafe := valid
	unsafe.CandidateInfo = linkInfo
	if err := validateHelperMigrationProbe(spec, unsafe); err == nil {
		t.Fatal("symlinked candidate was accepted")
	}
}

func TestHelperMigrationOwnHelperUpdateReservationIsAdmitted(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	paths := helperMigrationPaths{JournalPath: journal, IntentPath: filepath.Join(root, "migration", "intent.json")}
	proof := testHelperMigrationOwnReservationProof()
	writeJSONFile(t, filepath.Join(journal, proof.OperationID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: helperMigrationOwnReservationKind,
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	if err := inspectRootHelperMigrationStateWithOwnReservation(paths, fs, nil, proof); err != nil {
		t.Fatalf("matching helper-update own reservation was refused: %v", err)
	}
}

func TestHelperRollbackPendingDestroyRefused(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	cleanup := filepath.Join(journal, "destroy-cleanup")
	if err := os.MkdirAll(cleanup, 0o700); err != nil {
		t.Fatal(err)
	}
	proof := testHelperMigrationOwnReservationProof()
	writeJSONFile(t, filepath.Join(journal, proof.OperationID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: helperMigrationOwnReservationKind,
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	old := rootHelperUpdatePreflightRuntime
	t.Cleanup(func() { rootHelperUpdatePreflightRuntime = old })
	rootHelperUpdatePreflightRuntime = func() helperMigrationRuntime {
		return helperMigrationRuntime{paths: helperMigrationPaths{JournalPath: journal}, fs: testHelperMigrationFS()}
	}
	plan := rootplan.Plan{Helper: &rootplan.HelperOperation{PayloadSHA256: proof.CandidateSHA256}, Action: "helper-update", OperationID: proof.OperationID, OperationKind: proof.OperationKind, OperatorKeyFingerprint: proof.OwnerKeyFingerprint, RequiredHostFingerprint: proof.HostFingerprint}
	plan.Helper.AllowDowngrade = true
	record := coord.Record{HostBootID: proof.BootID}
	if err := rootHelperUpdatePreflight(plan, record); err != nil {
		t.Fatalf("empty destroy directory blocked rollback: %v", err)
	}
	pending := filepath.Join(cleanup, "pending.json")
	if err := os.WriteFile(pending, []byte("unreadable journal must also block rollback"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rootHelperUpdatePreflight(plan, record); err == nil || !strings.Contains(err.Error(), "pending destroy") {
		t.Fatalf("rollback with pending destroy admitted: %v", err)
	}
	if body, err := os.ReadFile(pending); err != nil || string(body) != "unreadable journal must also block rollback" {
		t.Fatal("rollback changed pending evidence")
	}
}

func TestHelperMigrationOtherActiveLeaseIsRejected(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	paths := helperMigrationPaths{JournalPath: journal, IntentPath: filepath.Join(root, "migration", "intent.json")}
	proof := testHelperMigrationOwnReservationProof()
	otherID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	writeJSONFile(t, filepath.Join(journal, proof.OperationID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: helperMigrationOwnReservationKind,
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	writeJSONFile(t, filepath.Join(journal, otherID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: otherID, Kind: "deploy",
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	if err := inspectRootHelperMigrationStateWithOwnReservation(paths, fs, nil, proof); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("a second active lease was ignored: %v", err)
	}

	otherOnly := helperMigrationPaths{JournalPath: journal + "-other", IntentPath: filepath.Join(root, "migration-other", "intent.json")}
	if err := os.Mkdir(otherOnly.JournalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(otherOnly.JournalPath, otherID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: otherID, Kind: helperMigrationOwnReservationKind,
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	if err := inspectRootHelperMigrationStateWithOwnReservation(otherOnly, fs, nil, proof); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("a different helper-update lease was admitted as own: %v", err)
	}
}

// An operation awaiting recovery has no executor left. Refusing it made the
// helper update impossible on the very host whose helper could not recover it
// (preprod VPS, 2026-10-15), so only its inconsistent forms are refused now.
func TestHelperMigrationAdmitsRecoveryRequiredRecordButNotInconsistentOne(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	paths := helperMigrationPaths{JournalPath: journal, IntentPath: filepath.Join(root, "migration", "intent.json")}
	proof := testHelperMigrationOwnReservationProof()
	otherID := "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
	writeJSONFile(t, filepath.Join(journal, proof.OperationID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: helperMigrationOwnReservationKind,
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	writeJSONFile(t, filepath.Join(journal, otherID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: otherID, Kind: "deploy",
		State: "recovery_required", RecoveryRequired: true, Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	if err := inspectRootHelperMigrationStateWithOwnReservation(paths, fs, nil, proof); err != nil {
		t.Fatalf("a recovery_required deploy refused the helper update meant to recover it: %v", err)
	}
	for name, record := range map[string]helperMigrationOperationRecord{
		"flag without state": {State: "failed", RecoveryRequired: true},
		"state without flag": {State: "recovery_required", RecoveryRequired: false},
	} {
		record.Schema, record.ID, record.Kind = helperMigrationOperationSchema, otherID, "deploy"
		writeJSONFile(t, filepath.Join(journal, otherID+".json"), record)
		if err := inspectRootHelperMigrationStateWithOwnReservation(paths, fs, nil, proof); err == nil || !strings.Contains(err.Error(), "requires recovery") {
			t.Fatalf("%s: inconsistent recovery record was admitted: %v", name, err)
		}
	}
}

func TestHelperMigrationWriterRecordTerminalAdmitsRecoveryRequired(t *testing.T) {
	id := "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
	binding := operationwriters.Binding{OperationID: id, Generation: 1, HostKey: "SHA256:" + strings.Repeat("B", 43), BootID: "boot-a"}
	base := helperMigrationOperationRecord{Schema: helperMigrationOperationSchema, ID: id, Kind: "deploy", Host: binding.HostKey, HostBootID: binding.BootID}
	cases := []struct {
		state    string
		recovery bool
		want     bool
	}{
		{"completed", false, true},
		{"failed", false, true},
		{"recovered", false, true},
		{"recovery_required", true, true},
		{"recovery_required", false, false},
		{"failed", true, false},
		{"active", false, false},
	}
	for _, tc := range cases {
		record := base
		record.State, record.RecoveryRequired = tc.state, tc.recovery
		if got := migrationWriterRecordTerminal(record, id, binding); got != tc.want {
			t.Fatalf("state=%s recovery_required=%v: terminal=%v, want %v", tc.state, tc.recovery, got, tc.want)
		}
	}
	other := base
	other.State, other.RecoveryRequired = "recovery_required", true
	other.HostBootID = "boot-b"
	if migrationWriterRecordTerminal(other, id, binding) {
		t.Fatal("a recovery_required record from another boot matched the writer binding")
	}
}

func TestHelperMigrationOwnReservationFailClosedOnMismatchedProof(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	paths := helperMigrationPaths{JournalPath: journal, IntentPath: filepath.Join(root, "migration", "intent.json")}
	proof := testHelperMigrationOwnReservationProof()
	record := helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: helperMigrationOwnReservationKind,
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	}
	writeJSONFile(t, filepath.Join(journal, proof.OperationID+".json"), record)

	cases := map[string]helperMigrationOwnReservationProof{
		"wrong owner": func() helperMigrationOwnReservationProof {
			p := proof
			p.OwnerKeyFingerprint = "SHA256:" + strings.Repeat("B", 43)
			return p
		}(),
		"wrong host": func() helperMigrationOwnReservationProof {
			p := proof
			p.HostFingerprint = "SHA256:" + strings.Repeat("B", 43)
			return p
		}(),
		"wrong boot": func() helperMigrationOwnReservationProof {
			p := proof
			p.BootID = "boot-b"
			return p
		}(),
		"wrong id": func() helperMigrationOwnReservationProof {
			p := proof
			p.OperationID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			return p
		}(),
		"wrong kind": func() helperMigrationOwnReservationProof {
			p := proof
			p.OperationKind = "deploy"
			return p
		}(),
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			err := inspectRootHelperMigrationStateWithOwnReservation(paths, fs, nil, invalid)
			if err == nil {
				t.Fatal("mismatched own reservation proof was accepted")
			}
		})
	}
	if err := inspectRootHelperMigrationState(paths, fs); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("legacy proof-free inspection admitted an active helper-update lease: %v", err)
	}
	if err := inspectRootHelperMigrationStateWithOwnReservation(paths, fs, nil, helperMigrationOwnReservationProof{}); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("zero proof admitted an active helper-update lease: %v", err)
	}
}

func TestHelperMigrationAdmitOwnReservationBindsCandidateDigest(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	migration := filepath.Join(root, "migration")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(migration, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("staged helper")
	candidate := filepath.Join(root, "shuttle-root-candidate")
	if err := writeTestFile(candidate, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	proof := testHelperMigrationOwnReservationProof()
	proof.CandidateSHA256 = digestBytes(payload)
	writeJSONFile(t, filepath.Join(journal, proof.OperationID+".json"), helperMigrationOperationRecord{
		Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: helperMigrationOwnReservationKind,
		State: "active", Principal: proof.OwnerKeyFingerprint, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID,
	})
	runtime := helperMigrationRuntime{
		fs: testHelperMigrationFS(),
		paths: helperMigrationPaths{
			JournalPath: journal, IntentPath: filepath.Join(migration, "intent.json"), BackupStagingPath: filepath.Join(root, "backups"),
		},
	}
	if err := admitHelperMigrationOwnReservationWithRuntime(proof, candidate, runtime); err != nil {
		t.Fatalf("parent receiving hook refused the matching own reservation: %v", err)
	}
	loaded, err := readHelperMigrationOwnReservationProof(runtime.fs, runtime.paths)
	if err != nil || loaded == nil || loaded.OperationID != proof.OperationID || loaded.CandidateSHA256 != proof.CandidateSHA256 {
		t.Fatalf("parent proof was not persisted for the candidate init: %+v %v", loaded, err)
	}
	wrong := proof
	wrong.CandidateSHA256 = "sha256:" + strings.Repeat("c", 64)
	if err := admitHelperMigrationOwnReservationWithRuntime(wrong, candidate, runtime); err == nil {
		t.Fatal("parent receiving hook accepted a mismatched candidate digest")
	}
}

func TestRootHelperMigrationJournalAndBackupStateFailClosed(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	backups := filepath.Join(root, "backups")
	for _, directory := range []string{journal, backups} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fs := testHelperMigrationFS()
	paths := helperMigrationPaths{JournalPath: journal, BackupStagingPath: backups}
	record := helperMigrationOperationRecord{Schema: helperMigrationOperationSchema, ID: "01234567-89ab-cdef-0123-456789abcdef", State: "active"}
	writeJSONFile(t, filepath.Join(journal, record.ID+".json"), record)
	if err := inspectRootHelperMigrationState(paths, fs); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("active journal record was not rejected: %v", err)
	}
	record.State, record.RecoveryRequired = "failed", false
	writeJSONFile(t, filepath.Join(journal, record.ID+".json"), record)
	if err := inspectRootHelperMigrationState(paths, fs); err != nil {
		t.Fatalf("terminal journal record should be readable: %v", err)
	}
	marker := helperMigrationBackupMarker{App: "demo", OperationID: record.ID, Replicas: map[string]int{"demo_web": 1}, Work: "quiesce"}
	writeJSONFile(t, filepath.Join(backups, "demo.pending.json"), marker)
	if err := inspectRootHelperMigrationState(paths, fs); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("pending backup marker was not rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backups, "demo.pending.json"), []byte(`{"app":"demo","operation_id":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := inspectRootHelperMigrationState(paths, fs); err == nil {
		t.Fatal("corrupt backup marker was accepted")
	}
}

func TestRootHelperMigrationProcessMatchingUsesBirthAndExecutableIdentity(t *testing.T) {
	intent := testHelperMigrationIntent()
	oldPath, oldDigest, err := helperMigrationSourceParts(intent.Source)
	if err != nil {
		t.Fatal(err)
	}
	process := helperMigrationProcess{PID: 41, Birth: "100", Executable: oldPath + " (deleted)", Argv: []string{oldPath, "apply"}, ExecutableSHA256: oldDigest}
	if !oldHelperMigrationProcess(process, intent, 99) {
		t.Fatal("exact old helper process was not recognized")
	}
	for name, altered := range map[string]helperMigrationProcess{
		"reused current pid": {PID: 99, Birth: "100", Executable: process.Executable, Argv: process.Argv, ExecutableSHA256: oldDigest},
		"missing birth":      {PID: 41, Executable: process.Executable, Argv: process.Argv, ExecutableSHA256: oldDigest},
		"wrong executable":   {PID: 41, Birth: "100", Executable: "/tmp/shuttle-root", Argv: process.Argv, ExecutableSHA256: oldDigest},
		"wrong digest":       {PID: 41, Birth: "100", Executable: process.Executable, Argv: process.Argv, ExecutableSHA256: "sha256:" + strings.Repeat("c", 64)},
		"broad argv":         {PID: 41, Birth: "100", Executable: process.Executable, Argv: []string{"/bin/sh", "shuttle-root apply"}, ExecutableSHA256: oldDigest},
	} {
		t.Run(name, func(t *testing.T) {
			if oldHelperMigrationProcess(altered, intent, 99) {
				t.Fatal("non-identical process was treated as an old helper executor")
			}
		})
	}
}

func TestRootHelperMigrationFinalizationIsDurableIdempotentAndRetryable(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "shuttle-root")
	payload := []byte("new helper")
	if err := writeTestFile(installed, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := helperMigrationPaths{
		IntentPath:  filepath.Join(root, "migration", "intent.json"),
		JournalPath: filepath.Join(root, "journal"), BackupStagingPath: filepath.Join(root, "backups"),
		LockPath: filepath.Join(root, "root.lock"), InstalledPath: installed, StagingDir: root,
	}
	fs := testHelperMigrationFS()
	intent := testHelperMigrationIntent()
	intent.Phase = helperMigrationPhaseReplaced
	intent.CandidateSHA256 = digestBytes(payload)
	if err := writeHelperMigrationIntent(fs, paths.IntentPath, intent); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	validationCalls := 0
	runtime := helperMigrationRuntime{
		fs: fs, paths: paths, now: func() time.Time { return now }, bootID: func() (string, error) { return intent.BootID, nil }, currentPID: 777,
		listProcess: func() ([]helperMigrationProcess, error) { return nil, nil },
		withLock:    func(_ context.Context, _ time.Duration, run func() error) error { return run() },
	}
	request := helperMigrationFinalizeRequest{CandidateSHA256: intent.CandidateSHA256, Host: intent.Host}
	request.Validate = func() error { validationCalls++; return nil }
	if err := finalizeRootHelperMigrationWithRuntime(context.Background(), requestWithExpiry(request, now.Add(time.Minute)), runtime); err != nil {
		t.Fatal(err)
	}
	loaded, err := readHelperMigrationIntent(fs, paths.IntentPath)
	if err != nil || loaded == nil || loaded.Phase != helperMigrationPhaseComplete {
		t.Fatalf("finalization was not durably completed: %+v %v", loaded, err)
	}
	if validationCalls != 1 {
		t.Fatalf("signed finalization was not revalidated exactly once, got %d calls", validationCalls)
	}
	if err := finalizeRootHelperMigrationWithRuntime(context.Background(), requestWithExpiry(request, now.Add(time.Minute)), runtime); err != nil {
		t.Fatalf("repeating finalization must be idempotent: %v", err)
	}
}

func TestRootHelperMigrationReadyIntentResumesAfterInterruptedCompletion(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "shuttle-root")
	payload := []byte("new helper")
	if err := writeTestFile(installed, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := helperMigrationPaths{IntentPath: filepath.Join(root, "migration", "intent.json"), JournalPath: filepath.Join(root, "journal"), BackupStagingPath: filepath.Join(root, "backups"), LockPath: filepath.Join(root, "lock"), InstalledPath: installed, StagingDir: root}
	fs := testHelperMigrationFS()
	intent := testHelperMigrationIntent()
	intent.Phase = helperMigrationPhaseReady
	intent.CandidateSHA256 = digestBytes(payload)
	if err := writeHelperMigrationIntent(fs, paths.IntentPath, intent); err != nil {
		t.Fatal(err)
	}
	fsyncCalls := 0
	fs.syncFile = func(file *os.File) error {
		fsyncCalls++
		if fsyncCalls >= 2 {
			return errors.New("injected completion fsync failure")
		}
		return file.Sync()
	}
	now := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	runtime := helperMigrationRuntime{fs: fs, paths: paths, now: func() time.Time { return now }, bootID: func() (string, error) { return intent.BootID, nil }, currentPID: 777, listProcess: func() ([]helperMigrationProcess, error) { return nil, nil }, withLock: func(_ context.Context, _ time.Duration, run func() error) error { return run() }}
	request := requestWithExpiry(helperMigrationFinalizeRequest{CandidateSHA256: intent.CandidateSHA256, Host: intent.Host}, now.Add(time.Minute))
	if err := finalizeRootHelperMigrationWithRuntime(context.Background(), request, runtime); err == nil {
		t.Fatal("completion fsync failure was reported as success")
	}
	loaded, err := readHelperMigrationIntent(fs, paths.IntentPath)
	if err != nil || loaded == nil || loaded.Phase != helperMigrationPhaseReplaced {
		t.Fatalf("interrupted completion must leave a resumable replaced intent: %+v %v", loaded, err)
	}
	runtime.fs.syncFile = func(file *os.File) error { return file.Sync() }
	if err := finalizeRootHelperMigrationWithRuntime(context.Background(), request, runtime); err != nil {
		t.Fatalf("retry did not resume the replaced intent: %v", err)
	}
}

func TestRootHelperMigrationFinalizationRechecksExpiryAndBoot(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "shuttle-root")
	payload := []byte("new helper")
	if err := writeTestFile(installed, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := helperMigrationPaths{IntentPath: filepath.Join(root, "migration", "intent.json"), JournalPath: filepath.Join(root, "journal"), BackupStagingPath: filepath.Join(root, "backups"), LockPath: filepath.Join(root, "lock"), InstalledPath: installed, StagingDir: root}
	fs := testHelperMigrationFS()
	intent := testHelperMigrationIntent()
	intent.CandidateSHA256 = digestBytes(payload)
	intent.Phase = helperMigrationPhaseReplaced
	if err := writeHelperMigrationIntent(fs, paths.IntentPath, intent); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	base := helperMigrationRuntime{fs: fs, paths: paths, now: func() time.Time { return now }, bootID: func() (string, error) { return "boot-b", nil }, currentPID: 1, listProcess: func() ([]helperMigrationProcess, error) { return nil, nil }, withLock: func(_ context.Context, _ time.Duration, run func() error) error { return run() }}
	request := requestWithExpiry(helperMigrationFinalizeRequest{CandidateSHA256: intent.CandidateSHA256, Host: intent.Host}, now.Add(time.Minute))
	if err := finalizeRootHelperMigrationWithRuntime(context.Background(), request, base); err == nil || !strings.Contains(err.Error(), "boot") {
		t.Fatalf("boot change was not rejected: %v", err)
	}
	base.bootID = func() (string, error) { return intent.BootID, nil }
	request = requestWithExpiry(request, now.Add(-time.Second))
	if err := finalizeRootHelperMigrationWithRuntime(context.Background(), request, base); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired signed finalization was not rejected: %v", err)
	}
}

func TestRootHelperMigrationReconcileRequiresSignedProofAndRecordsBootChange(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "shuttle-root")
	payload := []byte("new helper")
	if err := writeTestFile(installed, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := helperMigrationPaths{
		IntentPath:  filepath.Join(root, "migration", "intent.json"),
		JournalPath: filepath.Join(root, "journal"), BackupStagingPath: filepath.Join(root, "backups"),
		LockPath: filepath.Join(root, "lock"), InstalledPath: installed, StagingDir: root,
	}
	fs := testHelperMigrationFS()
	intent := testHelperMigrationIntent()
	intent.Phase = helperMigrationPhaseReplaced
	intent.CandidateSHA256 = digestBytes(payload)
	if err := writeHelperMigrationIntent(fs, paths.IntentPath, intent); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	validated := 0
	runtime := helperMigrationRuntime{
		fs: fs, paths: paths, now: func() time.Time { return now },
		bootID: func() (string, error) { return "boot-b", nil }, currentPID: 777,
		listProcess: func() ([]helperMigrationProcess, error) { return nil, nil },
		withLock:    func(_ context.Context, _ time.Duration, run func() error) error { return run() },
	}
	request := helperMigrationReconcileRequest{
		CandidateSHA256: intent.CandidateSHA256, Host: intent.Host,
		PlanExpiresAt: now.Add(time.Minute), Validate: func() error { validated++; return nil },
	}
	if err := reconcileRootHelperMigrationWithRuntime(context.Background(), request, runtime); err != nil {
		t.Fatal(err)
	}
	loaded, err := readHelperMigrationIntent(fs, paths.IntentPath)
	if err != nil || loaded == nil || loaded.Phase != helperMigrationPhaseComplete || loaded.BootID != "boot-b" {
		t.Fatalf("boot-change reconciliation did not complete durably: %+v %v", loaded, err)
	}
	if validated != 1 || len(loaded.History) != 1 || loaded.History[0].Action != "reconcile-boot-change" {
		t.Fatalf("reconciliation proof/history was not recorded: calls=%d history=%+v", validated, loaded.History)
	}
}

func TestRootHelperMigrationRefusesMutationsWhileIntentIsPending(t *testing.T) {
	root := t.TempDir()
	fs := testHelperMigrationFS()
	paths := helperMigrationPaths{IntentPath: filepath.Join(root, "migration", "intent.json")}
	intent := testHelperMigrationIntent()
	if err := writeHelperMigrationIntent(fs, paths.IntentPath, intent); err != nil {
		t.Fatal(err)
	}
	runtime := helperMigrationRuntime{fs: fs, paths: paths}
	if err := refuseRootHelperMutationDuringMigrationWithRuntime("stack-apply", runtime); err == nil {
		t.Fatal("mutation was allowed with a pending migration intent")
	}
	for _, action := range []string{"audit", "operations-status", "recovery-plan", "helper-migration-finalize", "helper-migration-reconcile"} {
		if err := refuseRootHelperMutationDuringMigrationWithRuntime(action, runtime); err != nil {
			t.Fatalf("signed read or migration action %q was blocked: %v", action, err)
		}
	}
	if err := refuseRootHelperMutationDuringMigrationWithRuntime("recovery-apply", runtime); err == nil {
		t.Fatal("recovery apply was allowed while migration was pending")
	}
}

func TestHelperMigrationLockWaitIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	holder, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = withHelperMigrationLock(context.Background(), path, 20*time.Millisecond, func() error { return nil })
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("lock wait was not bounded: err=%v elapsed=%s", err, time.Since(started))
	}
}

func TestProcEffectiveUIDUsesEffectiveColumn(t *testing.T) {
	uid, err := procEffectiveUID([]byte("Name:\tshuttle-root\nUid:\t1001\t0\t1001\t1001\n"))
	if err != nil || uid != 0 {
		t.Fatalf("effective UID was not read from /proc status: uid=%d err=%v", uid, err)
	}
}

func TestProcFlockProofRequiresTheParentOwnerAndExactLock(t *testing.T) {
	device := encodeLinuxDevice(8, 1)
	body := "lock: 1: FLOCK ADVISORY WRITE 42 08:01:99 0 EOF\n"
	if !procFlockProofMatches(body, 42, device, 99) {
		t.Fatal("exact parent FLOCK proof was rejected")
	}
	if procFlockProofMatches(body, 43, device, 99) {
		t.Fatal("another process was accepted as the flock owner")
	}
	if procFlockProofMatches(body, 42, device, 100) {
		t.Fatal("another lock inode was accepted")
	}
}

func TestOperationWritersRequireAClosedTypedProof(t *testing.T) {
	root := t.TempDir()
	writers := filepath.Join(root, "writers")
	if err := os.Mkdir(writers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(writers, "pending.json"), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	if err := inspectHelperMigrationWriters(writers, fs, nil); err == nil {
		t.Fatal("nonempty writers directory was accepted without its proof reader")
	}
	reader := func(string) (helperMigrationWriterProof, error) {
		return helperMigrationWriterProof{
			Schema:  helperMigrationWriterProofSchema,
			Writers: []helperMigrationWriterRecord{{OperationID: strings.Repeat("a", 32), State: "closed", Origin: "local-vps"}},
		}, nil
	}
	if err := inspectHelperMigrationWriters(writers, fs, reader); err != nil {
		t.Fatalf("closed writer proof was rejected: %v", err)
	}
	reader = func(string) (helperMigrationWriterProof, error) {
		return helperMigrationWriterProof{Schema: helperMigrationWriterProofSchema, Writers: []helperMigrationWriterRecord{{OperationID: strings.Repeat("a", 32), State: "open", Origin: "client-origin"}}}, nil
	}
	if err := inspectHelperMigrationWriters(writers, fs, reader); err == nil {
		t.Fatal("open writer proof was accepted")
	}
}

func TestHelperMigrationProcessCaptureFiltersBeforeHashingAndRechecksBirth(t *testing.T) {
	procRoot := t.TempDir()
	expected := filepath.Join(t.TempDir(), "shuttle-root")
	if err := writeTestFile(expected, []byte("helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		pid  string
		exe  string
		args []byte
	}{
		{pid: "100", exe: expected, args: []byte(expected + "\x00apply\x00")},
		{pid: "101", exe: "/missing/not-the-helper", args: []byte("other\x00")},
	} {
		base := filepath.Join(procRoot, item.pid)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(item.exe, filepath.Join(base, "exe")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "stat"), stat, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "cmdline"), item.args, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	processes, err := readHelperMigrationProcessesFromWithExpected(procRoot, expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 || processes[0].PID != 100 {
		t.Fatalf("filtered process capture returned %+v", processes)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestBytes(body []byte) string {
	return rootplan.PayloadDigest(body)
}

func requestWithExpiry(request helperMigrationFinalizeRequest, expiry time.Time) helperMigrationFinalizeRequest {
	request.PlanExpiresAt = expiry
	return request
}

func TestHelperMigrationRebootCompanionRetainedAndStrictlyLinked(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	id := strings.Repeat("a", 32)
	key := "SHA256:" + strings.Repeat("b", 43)
	record := helperMigrationOperationRecord{Schema: helperMigrationOperationSchema, ID: id, Kind: "reboot", State: "completed", Principal: key, OwnerKeyFingerprint: key, Host: key, HostBootID: "source-boot"}
	intent := map[string]any{"boot_before": "source-boot", "services": []any{}, "postgres": []any{}, "https_required": true}
	writeJSONFile(t, filepath.Join(directory, id+".json"), record)
	writeJSONFile(t, filepath.Join(directory, id+".reboot"), intent)
	if err := inspectHelperMigrationJournal(helperMigrationPaths{JournalPath: directory}, fs, nil, helperMigrationOwnReservationProof{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, id+".reboot")); err != nil {
		t.Fatal("idempotent reboot intent was removed", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"wrong boot":       func(v map[string]any) { v["boot_before"] = "other" },
		"wrong id":         func(v map[string]any) { v["id"] = strings.Repeat("c", 32) },
		"wrong host":       func(v map[string]any) { v["host"] = "SHA256:" + strings.Repeat("c", 43) },
		"unknown field":    func(v map[string]any) { v["unexpected"] = true },
		"missing services": func(v map[string]any) { delete(v, "services") },
	} {
		t.Run(name, func(t *testing.T) {
			altered := map[string]any{}
			for k, v := range intent {
				altered[k] = v
			}
			mutate(altered)
			writeJSONFile(t, filepath.Join(directory, id+".reboot"), altered)
			if err := inspectHelperMigrationRebootCompanion(directory, id+".reboot", fs); err == nil {
				t.Fatal("invalid companion accepted")
			}
		})
	}
	writeJSONFile(t, filepath.Join(directory, id+".reboot"), intent)
	record.State = "active"
	writeJSONFile(t, filepath.Join(directory, id+".json"), record)
	if err := inspectHelperMigrationRebootCompanion(directory, id+".reboot", fs); err == nil {
		t.Fatal("active reboot companion accepted")
	}
	record.State = "completed"
	writeJSONFile(t, filepath.Join(directory, id+".json"), record)
	if err := os.Chmod(filepath.Join(directory, id+".reboot"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := inspectHelperMigrationRebootCompanion(directory, id+".reboot", fs); err == nil {
		t.Fatal("unsafe companion permissions accepted")
	}
}

func TestHelperMigrationOwnReservationRejectsExpiredLeaseAndOtherPrincipal(t *testing.T) {
	proof := testHelperMigrationOwnReservationProof()
	record := helperMigrationOperationRecord{Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: proof.OperationKind, State: "active", Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}
	if err := admitHelperMigrationActiveRecord(record, proof); err != nil {
		t.Fatal(err)
	}
	record.Principal = "SHA256:" + strings.Repeat("z", 43)
	if err := admitHelperMigrationActiveRecord(record, proof); err == nil {
		t.Fatal("other principal accepted")
	}
	record.Principal = proof.OwnerKeyFingerprint
	for _, lease := range []string{"", "invalid", time.Now().Add(-time.Hour).Format(time.RFC3339Nano)} {
		record.LeaseUntil = lease
		if err := admitHelperMigrationActiveRecord(record, proof); err == nil {
			t.Fatal("stale lease accepted", lease)
		}
	}
}

func TestHelperMigrationParentCompletionRequiresPersistedExactProof(t *testing.T) {
	directory := t.TempDir()
	journal := filepath.Join(directory, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	proof := testHelperMigrationOwnReservationProof()
	runtime := helperMigrationRuntime{fs: testHelperMigrationFS(), paths: helperMigrationPaths{JournalPath: journal, IntentPath: filepath.Join(directory, "migration", "intent.json")}, bootID: func() (string, error) { return proof.BootID, nil }}
	writeJSONFile(t, filepath.Join(journal, proof.OperationID+".json"), helperMigrationOperationRecord{Schema: helperMigrationOperationSchema, ID: proof.OperationID, Kind: proof.OperationKind, State: "active", Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostBootID: proof.BootID, LeaseUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano)})
	if err := validateHelperMigrationOwnReservationWithRuntime(proof, runtime); err == nil {
		t.Fatal("missing proof accepted")
	}
	if err := writeHelperMigrationOwnReservationProof(runtime.fs, helperMigrationOwnReservationPath(runtime.paths), proof); err != nil {
		t.Fatal(err)
	}
	if err := validateHelperMigrationOwnReservationWithRuntime(proof, runtime); err != nil {
		t.Fatal(err)
	}
	altered := proof
	altered.CandidateSHA256 = "sha256:" + strings.Repeat("e", 64)
	if err := validateHelperMigrationOwnReservationWithRuntime(altered, runtime); err == nil {
		t.Fatal("another candidate accepted")
	}
	runtime.bootID = func() (string, error) { return "new-boot", nil }
	if err := validateHelperMigrationOwnReservationWithRuntime(proof, runtime); err == nil {
		t.Fatal("another boot accepted")
	}
}

// Security cases supplement the real-writer inventory test below, including
// interrupted temporaries that successful writer calls normally remove.
func TestHelperMigrationJournalKnownEntries(t *testing.T) {
	for _, name := range []string{"writers", rootOperationBaselineDirName, filepath.Base(rootDestroyCleanupRoot), ".operation-123456789.tmp", ".reboot-ab12_cd3"} {
		t.Run(name, func(t *testing.T) {
			for _, invalid := range []string{"", "mode", "owner", "symlink", "type"} {
				t.Run(invalid, func(t *testing.T) {
					root := t.TempDir()
					if err := os.Chmod(root, 0o700); err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(root, name)
					directory := !strings.HasPrefix(name, ".")
					if invalid == "type" {
						directory = !directory
					}
					if invalid == "symlink" {
						if err := os.Symlink(t.TempDir(), path); err != nil {
							t.Fatal(err)
						}
					} else if directory {
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(path, []byte("unfinished"), 0o600); err != nil {
						t.Fatal(err)
					}
					if invalid == "mode" {
						if err := os.Chmod(path, 0o755); err != nil {
							t.Fatal(err)
						}
					}
					fs := testHelperMigrationFS()
					if invalid == "owner" {
						fs.ownerOK = func(info os.FileInfo) bool { return info.Name() != name }
					}
					err := inspectHelperMigrationJournal(helperMigrationPaths{JournalPath: root}, fs, nil, helperMigrationOwnReservationProof{})
					if (err != nil) != (invalid != "") {
						t.Fatalf("entry=%s invalid=%s: %v", name, invalid, err)
					}
				})
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, "future-store"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := inspectHelperMigrationJournal(helperMigrationPaths{JournalPath: root}, testHelperMigrationFS(), nil, helperMigrationOwnReservationProof{}); err == nil {
			t.Fatal("unknown entry accepted")
		}
	})
}

func TestHelperUpdateScanRefusalLeavesNoRecovery(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	proof := testHelperMigrationOwnReservationProof()
	c := coord.New(coord.Options{Root: root, LockPath: filepath.Join(t.TempDir(), "lock"), BootID: func() (string, error) { return proof.BootID, nil }})
	_, err := c.Reserve(context.Background(), coord.Request{ID: proof.OperationID, Kind: proof.OperationKind, Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	oldC, oldI, oldG, oldP := rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, rootHelperUpdatePreflightRuntime
	t.Cleanup(func() {
		rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, rootHelperUpdatePreflightRuntime = oldC, oldI, oldG, oldP
	})
	rootOperationCoordinator = func() *coord.Coordinator { return c }
	rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return nil }
	rootCoordinatedMutationGuard = func(string) error { return nil }
	rootHelperUpdatePreflightRuntime = func() helperMigrationRuntime {
		return helperMigrationRuntime{paths: helperMigrationPaths{JournalPath: root, BackupStagingPath: filepath.Join(root, "absent-backup-staging")}, fs: testHelperMigrationFS(), writerProof: readMigrationWriterProof}
	}
	plan := rootplan.Plan{Helper: &rootplan.HelperOperation{PayloadSHA256: proof.CandidateSHA256}, Action: "helper-update", OperationID: proof.OperationID, OperationKind: proof.OperationKind, OperatorKeyFingerprint: proof.OwnerKeyFingerprint, RequiredHostFingerprint: proof.HostFingerprint, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	// Exercise the production proof construction with a real zero-phase lease.
	// Replacing the whole preflight hid both a missing boot ID and a no-op scan.
	record, err := c.Get(context.Background(), proof.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rootHelperUpdatePreflight(plan, record); err != nil {
		t.Fatalf("valid reservation refused by production preflight: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "unknown-store"), 0o700); err != nil {
		t.Fatal(err)
	}
	ran := false
	err = withCoordinatedRootOperation(plan, true, func() error { ran = true; return nil })
	if ran || err == nil || !strings.Contains(err.Error(), "unknown-store") {
		t.Fatalf("scan did not refuse before mutation: ran=%v err=%v", ran, err)
	}
	record, err = c.Get(context.Background(), proof.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "failed" || record.RecoveryRequired || record.LeaseUntil != "" || len(record.Phases) != 0 {
		t.Fatalf("refusal left a reservation requiring recovery: %+v", record)
	}
}

func TestHelperUpdateRefusalControlRequiresNoPhase(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(fmt.Sprint(started), func(t *testing.T) {
			proof := testHelperMigrationOwnReservationProof()
			c := coord.New(coord.Options{Root: filepath.Join(t.TempDir(), "records"), LockPath: filepath.Join(t.TempDir(), "lock"), BootID: func() (string, error) { return proof.BootID, nil }})
			_, err := c.Reserve(context.Background(), coord.Request{ID: proof.OperationID, Kind: proof.OperationKind, Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint})
			if err != nil {
				t.Fatal(err)
			}
			if started {
				err = c.ExecutePhase(context.Background(), coord.PhaseRequest{ID: proof.OperationID, Kind: proof.OperationKind, Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, Name: "helper-update"}, func(context.Context, coord.Record) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
			}
			if started {
				// The helper also invokes coordinator refusal locally after a scan
				// failure, without going through the signed control writer guard.
				err := c.Control(context.Background(), coord.PhaseRequest{ID: proof.OperationID, Kind: proof.OperationKind, Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, HostIdentity: proof.HostFingerprint, Name: "helper-update", PlanExpiresAt: time.Now().Add(time.Minute)}, "refuse", "scan refused")
				if err == nil || !strings.Contains(err.Error(), "no mutation phase") {
					t.Fatalf("coordinator released a started helper update: %v", err)
				}
			}
			oldI, oldG := rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard
			t.Cleanup(func() { rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard = oldI, oldG })
			rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return nil }
			rootCoordinatedMutationGuard = func(string) error { return nil }
			plan := rootplan.Plan{Action: "operation-refuse", OperationID: proof.OperationID, OperationKind: proof.OperationKind, OperatorKeyFingerprint: proof.OwnerKeyFingerprint, RequiredHostFingerprint: proof.HostFingerprint, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339), Control: &rootplan.OperationControl{Result: "helper-update refused"}}
			_, err = controlRootOperationWith(context.Background(), c, plan)
			if (err != nil) != started {
				t.Fatalf("started=%v refusal error=%v", started, err)
			}
			record, err := c.Get(context.Background(), proof.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			want := "failed"
			if started {
				want = "active"
			}
			if record.State != want || record.RecoveryRequired {
				t.Fatalf("unexpected state: %+v", record)
			}
		})
	}
}

// Run the actual producers, so adding a new directory in any of them without
// teaching migration its contract fails here instead of on the next VPS update.
func TestHelperMigrationJournalAcceptsRealWriters(t *testing.T) {
	root := t.TempDir()
	source := t.TempDir()
	proof := testHelperMigrationOwnReservationProof()
	c := coord.New(coord.Options{Root: root, LockPath: filepath.Join(t.TempDir(), "lock"), BootID: func() (string, error) { return proof.BootID, nil }})
	h, err := c.Reserve(context.Background(), coord.Request{Kind: "destroy", App: "demo", Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	baseline := operationwriters.Baseline{Current: writeBaselineSource(t, source, "demo", "current", []byte("services: {}\n")), ConfiguredNativePGVersion: "not-configured", ConfiguredNativePGCluster: "not-configured"}
	err = c.ExecutePhase(context.Background(), coord.PhaseRequest{ID: h.ID(), Kind: "destroy", App: "demo", Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint, Name: "destroy"}, func(_ context.Context, record coord.Record) error {
		if err := preserveRootOperationBaselineArtifactsAt(root, source, h.ID(), "demo", baseline); err != nil {
			return err
		}
		store := operationwriters.NewStore(root)
		binding := operationWriterBinding(record)
		if _, err := store.InitializeLocked(binding, baseline); err != nil {
			return err
		}
		if _, err := store.CloseAdmissionsLocked(binding); err != nil {
			return err
		}
		if _, err := store.CommitClosureLocked(binding, nil); err != nil {
			return err
		}
		cleanup := filepath.Join(root, filepath.Base(rootDestroyCleanupRoot))
		if err := writeDestroyCleanupJournalAt(cleanup, destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo", DrainBoundNanos: int64(30 * time.Second)}); err != nil {
			return err
		}
		return removeDestroyCleanupJournalAt(cleanup, h.ID())
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Complete("fixture destroy finished"); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	reader := func(path string) (helperMigrationWriterProof, error) { return readMigrationWriterProofWithFS(path, fs) }
	if err := inspectHelperMigrationJournal(helperMigrationPaths{JournalPath: root}, fs, reader, helperMigrationOwnReservationProof{}); err != nil {
		t.Fatalf("real writer layout refused: %v", err)
	}
}

func TestHelperMigrationJournalRetainsPendingDestroy(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	proof := testHelperMigrationOwnReservationProof()
	c := coord.New(coord.Options{Root: root, LockPath: filepath.Join(t.TempDir(), "lock"), BootID: func() (string, error) { return proof.BootID, nil }})
	h, err := c.Reserve(context.Background(), coord.Request{Kind: "destroy", App: "demo", Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	cleanup := filepath.Join(root, filepath.Base(rootDestroyCleanupRoot))
	journal := destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo", DrainBoundNanos: int64(30 * time.Second), PendingVolumes: []string{"demo_data"}}
	if err := writeDestroyCleanupJournalAt(cleanup, journal); err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("destroy interrupted"); err != nil {
		t.Fatal(err)
	}
	journalPath, err := destroyCleanupJournalPath(cleanup, h.ID())
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{journalPath, filepath.Join(root, h.ID()+".json")}
	before := make([][]byte, len(paths))
	for i, path := range paths {
		before[i], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	// A new helper may be the only way to recover this destroy. Migration must
	// preserve its evidence, unlike the empty-only old-helper bootstrap procedure.
	if err := inspectHelperMigrationJournal(helperMigrationPaths{JournalPath: root}, testHelperMigrationFS(), readMigrationWriterProof, helperMigrationOwnReservationProof{}); err != nil {
		t.Fatalf("pending destroy blocked helper migration: %v", err)
	}
	for i, path := range paths {
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(before[i]) {
			t.Fatalf("migration changed retained destroy evidence %s: %v", path, err)
		}
	}
}
