package operationwriters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Go's testing directories honor the process umask. The production writer
// store requires a private root, so its fixture must establish that invariant.
func privateTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func testBinding() Binding {
	return Binding{
		OperationID: "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b10",
		Generation:  7,
		HostKey:     "SHA256:" + strings.Repeat("a", 43),
		BootID:      "75cd8e98-536d-44a2-aed6-1bed269a8027",
	}
}

func testBaseline() Baseline {
	return Baseline{
		Current:                   BaselineArtifact{Present: true, FullSHA256: "sha256:" + strings.Repeat("1", 64)},
		Previous:                  BaselineArtifact{Present: false},
		ConfiguredNativePGVersion: "17.6",
		ConfiguredNativePGCluster: "main",
	}
}

func TestStoreTransitionsAreDurableAndIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	store, err := OpenStore(StoreOptions{Root: privateTestRoot(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	state, err := store.InitializeLocked(binding, testBaseline())
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 1 || state.Admissions != AdmissionsOpen {
		t.Fatalf("unexpected initial state: %+v", state)
	}
	group := LocalGroup{LeaderPID: 91, LeaderStartTicks: 123, PGID: 91, SID: 91}
	writer := Writer{ID: "local", Kind: WriterKindLocalGroup, Local: &group}
	state, err = store.RegisterLocked(binding, writer)
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 2 {
		t.Fatalf("registration revision = %d, want 2", state.Revision)
	}
	if repeated, err := store.RegisterLocked(binding, writer); err != nil || repeated.Revision != 2 {
		t.Fatalf("exact registration was not idempotent: %+v %v", repeated, err)
	}
	state, err = store.CloseAdmissionsLocked(binding)
	if err != nil {
		t.Fatal(err)
	}
	if state.Admissions != AdmissionsClosed || state.Revision != 3 {
		t.Fatalf("unexpected closed state: %+v", state)
	}
	if _, err := store.RegisterLocked(binding, Writer{ID: "late", Kind: WriterKindLocalGroup, Local: &LocalGroup{LeaderPID: 92, LeaderStartTicks: 124, PGID: 92, SID: 92}}); !errors.Is(err, ErrAdmissionsClosed) {
		t.Fatalf("late registration error = %v, want ErrAdmissionsClosed", err)
	}
	if _, err := store.Read(binding); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(store.Root(), "writers", binding.OperationID+".json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "configured_native_pg_version") || strings.Contains(string(contents), "password") {
		t.Fatalf("state did not contain the expected bounded baseline fields: %s", contents)
	}
}

func TestStoreRejectsUnknownAndTrailingJSON(t *testing.T) {
	root := privateTestRoot(t)
	store := NewStore(root)
	if _, err := store.InitializeLocked(testBinding(), testBaseline()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "writers", testBinding().OperationID+".json")
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"unknown":  append(append([]byte{}, valid[:len(valid)-2]...), []byte(",\n  \"unknown\":true\n}\n")...),
		"trailing": append(valid, []byte("{}\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Read(testBinding()); err == nil || !errors.Is(err, ErrInvalidState) {
				t.Fatalf("Read error = %v, want invalid state", err)
			}
		})
		if err := os.WriteFile(path, valid, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreAcceptsTheHistoricalNoteField(t *testing.T) {
	root := privateTestRoot(t)
	store := NewStore(root)
	if _, err := store.InitializeLocked(testBinding(), testBaseline()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "writers", testBinding().OperationID+".json")
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := append(append([]byte{}, valid[:len(valid)-2]...), []byte(",\n  \"note\":\"legacy writer state\"\n}\n")...)
	legacy = []byte(strings.Replace(string(legacy), "\n  \"binding\": {\n", "\n  \"binding\": {\n    \"note\": \"legacy nested note\",\n", 1))
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := store.Read(testBinding())
	if err != nil {
		t.Fatalf("historical note field was refused: %v", err)
	}
	if state.Note != "legacy writer state" {
		t.Fatalf("historical note field was not retained: %q", state.Note)
	}
}

func TestLocalFenceRequiresClosedAdmissions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local process-group fencing requires Linux /proc and pidfds")
	}
	group := LocalGroup{LeaderPID: 999999, LeaderStartTicks: 1, PGID: 999999, SID: 999999}
	_, err := FenceLocalGroups(context.Background(), LocalSnapshot{Generation: 1, Groups: []LocalGroup{group}})
	if !errors.Is(err, ErrAdmissionsClosed) {
		t.Fatalf("FenceLocalGroups error = %v, want ErrAdmissionsClosed", err)
	}
}

func TestInvalidSnapshotDoesNotBecomeAClosedProof(t *testing.T) {
	group := LocalGroup{LeaderPID: 999999, LeaderStartTicks: 1, PGID: 999999, SID: 999999}
	_, err := InspectLocalGroups(context.Background(), LocalSnapshot{Generation: 1, ProcRoot: filepath.Join(privateTestRoot(t), "missing"), Groups: []LocalGroup{group}})
	if errors.Is(err, ErrUnsupported) {
		return
	}
	if err == nil || !errors.Is(err, ErrProcessMissing) {
		t.Fatalf("InspectLocalGroups error = %v, want missing proc", err)
	}
	_, err = FenceLocalGroups(context.Background(), LocalSnapshot{Generation: 1, AdmissionsClosed: true, Groups: []LocalGroup{group}})
	if err == nil || !errors.Is(err, ErrProcessMissing) {
		t.Fatalf("FenceLocalGroups error = %v, want no false closed proof", err)
	}
}

func TestReceiptValidationRejectsBooleanOnlyProof(t *testing.T) {
	store := NewStore(privateTestRoot(t))
	binding := testBinding()
	if _, err := store.InitializeLocked(binding, testBaseline()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterLocked(binding, Writer{ID: "remote", Kind: WriterKindRemoteRunner, Remote: &RemoteRunner{HostKey: binding.HostKey, RunToken: "token"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CloseAdmissionsLocked(binding); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{WriterID: "remote", Kind: WriterKindRemoteRunner, Generation: binding.Generation, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), AdmissionsClosed: true, ResourcesClosed: true, EvidenceSHA256: "sha256:" + strings.Repeat("a", 64)}
	if _, err := store.CommitClosureLocked(binding, []Receipt{receipt}); err == nil || !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("boolean-only receipt error = %v, want invalid receipt", err)
	}
}

func TestRemoteClosureDigestExcludesObservationTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	store, err := OpenStore(StoreOptions{Root: privateTestRoot(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	if _, err := store.InitializeLocked(binding, testBaseline()); err != nil {
		t.Fatal(err)
	}
	runner := RemoteRunner{HostKey: binding.HostKey, RunToken: "run-token"}
	if _, err := store.RegisterLocked(binding, Writer{ID: "runner", Kind: WriterKindRemoteRunner, Remote: &runner}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CloseAdmissionsLocked(binding); err != nil {
		t.Fatal(err)
	}
	evidence := "sha256:" + strings.Repeat("a", 64)
	makeReceipt := func(observedAt string) Receipt {
		remote := &RemoteRunnerReceipt{HostKey: runner.HostKey, RunToken: runner.RunToken, Generation: binding.Generation, ObservedAt: observedAt, AdmissionsClosed: true, ResourcesClosed: true, ResourceIDs: []string{"buildkit:runner-1"}, TunnelID: "tunnel-1", EvidenceSHA256: evidence, AuthenticatedProof: "SHU1-Fence/v1"}
		return Receipt{WriterID: "runner", Kind: WriterKindRemoteRunner, Generation: binding.Generation, ObservedAt: observedAt, AdmissionsClosed: true, ResourcesClosed: true, EvidenceSHA256: evidence, Remote: remote}
	}
	first, err := store.CommitClosureLocked(binding, []Receipt{makeReceipt(formatTime(now))})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CommitClosureLocked(binding, []Receipt{makeReceipt(formatTime(now.Add(time.Second)))})
	if err != nil {
		t.Fatal(err)
	}
	if first.Closure == nil || second.Closure == nil || first.Closure.ProofHash != second.Closure.ProofHash || first.Revision != second.Revision {
		t.Fatalf("timestamp changed semantic closure: first=%+v second=%+v", first.Closure, second.Closure)
	}
}

func TestStateErrorsRemainActionable(t *testing.T) {
	if !strings.Contains(fmt.Sprint(ErrConflict), "conflicting") {
		t.Fatal("conflict error lost its actionable text")
	}
}
