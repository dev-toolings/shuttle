//go:build linux

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func testHelperMigrationFS() helperMigrationFS {
	fs := newOSHelperMigrationFS()
	fs.ownerOK = func(os.FileInfo) bool { return true }
	return fs
}

func testHelperMigrationIntent() helperMigrationIntent {
	return helperMigrationIntent{
		Schema:          helperMigrationSchema,
		ID:              "01234567-89ab-cdef-0123-456789abcdef",
		Source:          "/usr/local/libexec/shuttle-root#sha256:" + strings.Repeat("a", 64),
		CandidateSHA256: "sha256:" + strings.Repeat("b", 64),
		Host:            "SHA256:" + strings.Repeat("A", 43),
		BootID:          "boot-a",
		Phase:           helperMigrationPhaseReady,
	}
}

func TestLegacyHelperUpdateRemainsStrictAndOperationFree(t *testing.T) {
	now := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	plan, err := rootplan.NewHelperUpdate("sha256:"+strings.Repeat("b", 64), 1024, fingerprint, fingerprint, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if plan.OperationID != "" || plan.OperationKind != "" || plan.OperationApp != "" {
		t.Fatalf("legacy helper update unexpectedly requires coordination: %+v", plan)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = rootplan.Sign(plan, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := rootplan.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := rootplan.Decode(strings.NewReader(string(body)))
	if err != nil || decoded.Helper == nil || decoded.OperationID != "" {
		t.Fatalf("legacy helper decoder did not preserve the operation-free plan: %+v %v", decoded, err)
	}
	unknown := strings.TrimSpace(string(body))[:len(strings.TrimSpace(string(body)))-1] + `,"unexpected":true}`
	if _, err := rootplan.Decode(strings.NewReader(unknown)); err == nil {
		t.Fatal("legacy root-operation decoder accepted an unknown field")
	}
}

func TestModernHelperUpdateBindsReservedOperationID(t *testing.T) {
	now := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	id := "01234567-89ab-cdef-0123-456789abcdef"
	plan, err := rootplan.NewHelperUpdate("sha256:"+strings.Repeat("b", 64), 1024, fingerprint, fingerprint, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = bindOperationPlan(plan, id, helperMigrationOwnReservationKind, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.OperationID != id || plan.OperationKind != helperMigrationOwnReservationKind || plan.OperationApp != "" || plan.Helper == nil {
		t.Fatalf("modern helper update was not bound to the reserved helper-update lease: %+v", plan)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = rootplan.Sign(plan, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := rootplan.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := rootplan.Decode(strings.NewReader(string(body)))
	if err != nil || decoded.Helper == nil || decoded.OperationID != id || decoded.OperationKind != helperMigrationOwnReservationKind {
		t.Fatalf("modern helper decoder lost the reserved operation identity: %+v %v", decoded, err)
	}
}

func TestHelperMigrationOwnReservationProofFailClosed(t *testing.T) {
	proof := testHelperMigrationOwnReservationProof()
	if err := proof.validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]helperMigrationOwnReservationProof{
		"missing operation id":  func() helperMigrationOwnReservationProof { p := proof; p.OperationID = ""; return p }(),
		"wrong kind":            func() helperMigrationOwnReservationProof { p := proof; p.OperationKind = "deploy"; return p }(),
		"missing owner":         func() helperMigrationOwnReservationProof { p := proof; p.OwnerKeyFingerprint = ""; return p }(),
		"missing host":          func() helperMigrationOwnReservationProof { p := proof; p.HostFingerprint = "host"; return p }(),
		"missing boot":          func() helperMigrationOwnReservationProof { p := proof; p.BootID = ""; return p }(),
		"missing digest":        func() helperMigrationOwnReservationProof { p := proof; p.CandidateSHA256 = "sha256:nope"; return p }(),
		"unknown schema":        func() helperMigrationOwnReservationProof { p := proof; p.Schema = "other/v1"; return p }(),
		"zero value is not own": {},
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			if err := invalid.validate(); err == nil {
				t.Fatal("invalid own reservation proof was accepted")
			}
		})
	}
}

func testHelperMigrationOwnReservationProof() helperMigrationOwnReservationProof {
	return canonicalHelperMigrationOwnReservationProof(helperMigrationOwnReservationProof{
		OperationID:         "01234567-89ab-cdef-0123-456789abcdef",
		OperationKind:       helperMigrationOwnReservationKind,
		OwnerKeyFingerprint: "SHA256:" + strings.Repeat("A", 43),
		HostFingerprint:     "SHA256:" + strings.Repeat("A", 43),
		BootID:              "boot-a",
		CandidateSHA256:     "sha256:" + strings.Repeat("b", 64),
	})
}

func TestHelperMigrationIntentUsesAtomicDurablePhaseTransitions(t *testing.T) {
	root := t.TempDir()
	intentPath := filepath.Join(root, "migration", "intent.json")
	fs := testHelperMigrationFS()
	intent := testHelperMigrationIntent()
	if err := writeHelperMigrationIntent(fs, intentPath, intent); err != nil {
		t.Fatal(err)
	}
	loaded, err := readHelperMigrationIntent(fs, intentPath)
	if err != nil || loaded == nil || !reflect.DeepEqual(*loaded, intent) {
		t.Fatalf("intent round trip failed: %+v %v", loaded, err)
	}
	if err := markHelperMigrationPhase(fs, intentPath, intent.CandidateSHA256, helperMigrationPhaseReplaced); err != nil {
		t.Fatal(err)
	}
	if err := markHelperMigrationPhase(fs, intentPath, intent.CandidateSHA256, helperMigrationPhaseComplete); err != nil {
		t.Fatal(err)
	}
	loaded, err = readHelperMigrationIntent(fs, intentPath)
	if err != nil || loaded == nil || loaded.Phase != helperMigrationPhaseComplete {
		t.Fatalf("completion was not durably recorded: %+v %v", loaded, err)
	}
	if err := markHelperMigrationPhase(fs, intentPath, "sha256:"+strings.Repeat("c", 64), helperMigrationPhaseComplete); err == nil {
		t.Fatal("phase transition accepted a changed candidate digest")
	}
	if err := markHelperMigrationPhase(fs, intentPath, intent.CandidateSHA256, helperMigrationPhaseReady); err == nil {
		t.Fatal("phase transition accepted a backwards transition")
	}
}

func TestHelperMigrationFailedFsyncNeverPublishesOrCompletes(t *testing.T) {
	root := t.TempDir()
	intentPath := filepath.Join(root, "migration", "intent.json")
	fs := testHelperMigrationFS()
	fs.syncFile = func(*os.File) error { return errors.New("injected fsync failure") }
	if err := writeHelperMigrationIntent(fs, intentPath, testHelperMigrationIntent()); err == nil {
		t.Fatal("intent write reported success after fsync failure")
	}
	if _, err := os.Lstat(intentPath); !os.IsNotExist(err) {
		t.Fatalf("failed intent write left a published file: %v", err)
	}
}

func TestHelperMigrationIntentRejectsCorruptionAndSymlinks(t *testing.T) {
	root := t.TempDir()
	intentPath := filepath.Join(root, "intent.json")
	fs := testHelperMigrationFS()
	if err := os.WriteFile(intentPath, []byte(`{"schema":"shuttle.helper-migration/v1","id":"01234567-89ab-cdef-0123-456789abcdef","source":"x","candidate_sha256":"sha256:`+strings.Repeat("b", 64)+`","host":"h","boot_id":"b","phase":"prepared","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHelperMigrationIntent(fs, intentPath); err == nil {
		t.Fatal("corrupt intent with an unknown field was accepted")
	}
	if err := os.Remove(intentPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("intent"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, intentPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readHelperMigrationIntent(fs, intentPath); err == nil {
		t.Fatal("symlinked migration intent was accepted")
	}
}

func TestHelperMigrationFinalizerIsExplicitWhenRootHookIsAbsent(t *testing.T) {
	if err := unavailableHelperMigrationFinalizer(nil, trustedHostIdentity{}, helperMigrationFinalizeRequest{}); !errors.Is(err, errHelperMigrationFinalizationUnavailable) {
		t.Fatalf("unexpected absent-hook error: %v", err)
	}
}

func TestCompletedHelperMigrationIsArchivedBeforeNextGeneration(t *testing.T) {
	root := t.TempDir()
	paths := helperMigrationPaths{
		IntentPath: filepath.Join(root, "migration", "intent.json"),
		HistoryDir: filepath.Join(root, "migration", "history"),
	}
	fs := testHelperMigrationFS()
	intent := testHelperMigrationIntent()
	intent.Phase = helperMigrationPhaseComplete
	if err := writeHelperMigrationIntent(fs, paths.IntentPath, intent); err != nil {
		t.Fatal(err)
	}
	if err := archiveCompletedHelperMigrationIntent(fs, paths, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(paths.IntentPath); !os.IsNotExist(err) {
		t.Fatalf("active completed intent was not removed: %v", err)
	}
	archived, err := readHelperMigrationIntent(fs, filepath.Join(paths.HistoryDir, intent.ID+".json"))
	if err != nil || archived == nil || !reflect.DeepEqual(*archived, intent) {
		t.Fatalf("completed intent was not archived immutably: %+v %v", archived, err)
	}
}

func TestHelperMigrationRetryRequiresTheOriginalProbeAndLockProof(t *testing.T) {
	proof := &helperMigrationProbeProof{
		CandidatePath:    "/var/lib/shuttle/.shuttle-root.next-candidate",
		CandidateArgv:    []string{"shuttle-root", "--help"},
		ParentUID:        0,
		ParentPID:        42,
		ParentExecutable: "/usr/local/libexec/shuttle-root",
		ParentArgv:       []string{"/usr/local/libexec/shuttle-root", "apply"},
		ParentBirth:      "100",
		LockDevice:       1,
		LockInode:        2,
	}
	current := testHelperMigrationIntent()
	current.Probe = proof
	desired := current
	if !helperMigrationIntentRetryMatches(current, desired) {
		t.Fatal("identical prepared intent was not retryable")
	}
	desired.Probe = &helperMigrationProbeProof{CandidatePath: proof.CandidatePath, CandidateArgv: proof.CandidateArgv, ParentUID: proof.ParentUID, ParentExecutable: proof.ParentExecutable, ParentArgv: proof.ParentArgv, ParentBirth: "101", LockDevice: proof.LockDevice, LockInode: proof.LockInode}
	if helperMigrationIntentRetryMatches(current, desired) {
		t.Fatal("retry with changed process birth was accepted")
	}
	desired = current
	desired.Host = "SHA256:" + strings.Repeat("B", 43)
	if helperMigrationIntentRetryMatches(current, desired) {
		t.Fatal("retry with changed host identity was accepted")
	}
}
