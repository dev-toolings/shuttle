package backup

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
)

// requireHostBootID skips a Go/Python interop test where it cannot mean
// anything. Both sides read the real boot id from /proc, as they do on the VPS,
// and agreeing on it is part of what these tests prove; macOS has no /proc. The
// Python suite alone runs everywhere with a fixed id (operations_test.py).
func requireHostBootID(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/proc/sys/kernel/random/boot_id"); err != nil {
		t.Skip("host boot id is Linux-only; this interop runs on the Linux CI job")
	}
}

func TestNativeRestoreArchiveExtraction(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed for the embedded recovery program tests")
	}
	cmd := exec.Command(python, "-B", "-m", "unittest", "discover", "-s", ".", "-p", "*_test.py")
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if body, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("recovery archive tests: %v\n%s", err, body)
	}
}

func TestPythonSourceKeepsTheGoReservationUntilArchivePublication(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	directory := t.TempDir()
	root := filepath.Join(directory, "operations")
	lock := filepath.Join(directory, "root.lock")
	requireHostBootID(t)
	c := coord.New(coord.Options{Root: root, LockPath: lock, LockWait: time.Millisecond})
	key := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	h, err := c.Reserve(context.Background(), coord.Request{Kind: "backup", App: "demo", Principal: key, OwnerKeyFingerprint: key, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	provided, _ := json.Marshal(map[string]string{"id": h.ID(), "owner_key_fingerprint": key, "host": host})
	code := `import source,sys,json
source.OPERATIONS_ROOT=source.pathlib.Path(sys.argv[1])
source.OPERATIONS_LOCK=sys.argv[2]
id=source.reserve_operation("backup","demo",json.loads(sys.argv[3]))
source.transition_operation(id,"active","source streamed; publication pending",phase="source-capture")
print(id)
`
	cmd := exec.Command(python, "-B", "-c", code, root, lock, string(provided))
	body, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python attach/capture failed: %v %s", err, body)
	}
	if strings.TrimSpace(string(body)) != h.ID() {
		t.Fatalf("source created another reservation: %s", body)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "active" || record.OwnerKeyFingerprint != key || len(record.Phases) != 1 {
		t.Fatalf("source prematurely completed or lost owner: %#v", record)
	}
	for _, event := range record.Events {
		if _, err := time.Parse(time.RFC3339Nano, event.At); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Reserve(context.Background(), coord.Request{Kind: "deploy", App: "other", Principal: "another-client"}); err == nil {
		t.Fatal("deploy overlapped encrypted archive publication")
	}
	if err := h.Complete("encrypted archive and signed receipt committed"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(context.Background(), coord.Request{Kind: "deploy", App: "other", Principal: "another-client"}); err != nil {
		t.Fatalf("completed archive still blocked deploy: %v", err)
	}
}

func TestPythonSourceRejectsMismatchedReservationIdentity(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	directory := t.TempDir()
	root := filepath.Join(directory, "operations")
	lock := filepath.Join(directory, "root.lock")
	requireHostBootID(t)
	c := coord.New(coord.Options{Root: root, LockPath: lock, LockWait: time.Millisecond})
	key := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	h, err := c.Reserve(context.Background(), coord.Request{Kind: "backup", App: "demo", Principal: key, OwnerKeyFingerprint: key, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	wrong := "SHA256:" + strings.Repeat("c", 43)
	provided, _ := json.Marshal(map[string]string{"id": h.ID(), "principal": wrong, "owner_key_fingerprint": wrong, "host": host})
	code := `import source,sys,json
source.OPERATIONS_ROOT=source.pathlib.Path(sys.argv[1])
source.OPERATIONS_LOCK=sys.argv[2]
source.reserve_operation("backup","demo",json.loads(sys.argv[3]))
`
	cmd := exec.Command(python, "-B", "-c", code, root, lock, string(provided))
	if body, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("mismatched owner attached: %s", body)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "active" {
		t.Fatalf("wrong owner marked the live reservation: %#v", record)
	}
}

func TestPythonAttachMarksExpiredReservationForRecovery(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	directory := t.TempDir()
	root := filepath.Join(directory, "operations")
	lock := filepath.Join(directory, "root.lock")
	requireHostBootID(t)
	c := coord.New(coord.Options{Root: root, LockPath: lock, LockWait: time.Millisecond})
	key := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	h, err := c.Reserve(context.Background(), coord.Request{Kind: "backup", App: "demo", Principal: key, OwnerKeyFingerprint: key, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	record.LeaseUntil = "2000-01-01T00:00:00Z"
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, h.ID()+".json"), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	provided, _ := json.Marshal(map[string]string{"id": h.ID(), "principal": key, "owner_key_fingerprint": key, "host": host})
	code := `import source,sys,json
source.OPERATIONS_ROOT=source.pathlib.Path(sys.argv[1])
source.OPERATIONS_LOCK=sys.argv[2]
source.reserve_operation("backup","demo",json.loads(sys.argv[3]))
`
	cmd := exec.Command(python, "-B", "-c", code, root, lock, string(provided))
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expired reservation attached: %s", out)
	}
	record, err = c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != coord.RecoveryRequired || !record.RecoveryRequired {
		t.Fatalf("expired attach left the reservation live: %#v", record)
	}
}

func TestPythonCleanupFailureAfterStreamLeavesReservationUncompleted(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	directory := t.TempDir()
	root := filepath.Join(directory, "operations")
	lock := filepath.Join(directory, "root.lock")
	staging := filepath.Join(directory, "staging")
	if err := os.MkdirAll(filepath.Join(staging, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "work", "snap"), []byte("streamed"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireHostBootID(t)
	c := coord.New(coord.Options{Root: root, LockPath: lock, LockWait: time.Millisecond})
	key := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	h, err := c.Reserve(context.Background(), coord.Request{Kind: "backup", App: "demo", Principal: key, OwnerKeyFingerprint: key, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	provided, _ := json.Marshal(map[string]string{"id": h.ID(), "principal": key, "owner_key_fingerprint": key, "host": host})
	code := `import source,sys,json,os
source.OPERATIONS_ROOT=source.pathlib.Path(sys.argv[1])
source.OPERATIONS_LOCK=sys.argv[2]
source.STAGING_ROOT=source.pathlib.Path(sys.argv[3])
identity=json.loads(sys.argv[4])
source.reserve_operation("backup","demo",identity)
def boom(*args,**kwargs):
    raise OSError("directory busy")
source.shutil.rmtree=boom
try:
    source.commit_source_capture(identity["id"],identity,source.STAGING_ROOT/"work")
except OSError as error:
    print(error)
    raise SystemExit(2)
`
	cmd := exec.Command(python, "-B", "-c", code, root, lock, staging, string(provided))
	body, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("cleanup failure returned success: %s", body)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatalf("strict journal reload after cleanup failure: %v %s", err, body)
	}
	if record.State != "active" || record.RecoveryRequired {
		t.Fatalf("cleanup failure completed or recovered the reservation: %#v", record)
	}
	for _, event := range record.Events {
		if _, err := time.Parse(time.RFC3339Nano, event.At); err != nil {
			t.Fatal(err)
		}
	}
}
