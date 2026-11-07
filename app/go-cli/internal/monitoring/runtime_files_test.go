package monitoring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeFilesRejectSpecialFilesWithoutBlocking(t *testing.T) {
	directory := privateRuntimeDir(t)
	paths := []string{
		filepath.Join(directory, "incidents.json"),
		filepath.Join(directory, "maintenance.json"),
		filepath.Join(directory, "delivery-failures.jsonl"),
		filepath.Join(directory, "incidents.json.lock"),
		filepath.Join(directory, "webhook-url"),
	}
	for _, path := range paths {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now()
	if _, err := (FileStore{Path: paths[0]}).Load(context.Background()); err == nil {
		t.Fatal("FIFO state file was accepted")
	}
	if _, err := readRuntimePath(paths[1], maxMaintenanceBytes, runtimeUID(), false); err == nil {
		t.Fatal("FIFO maintenance file was accepted")
	}
	if err := appendDeliveryFailure(paths[2], AlertEvent{ID: "event"}, errors.New("hidden delivery error"), time.Now); err == nil {
		t.Fatal("FIFO failure log was accepted")
	}
	lockDir := privateRuntimeDir(t)
	if err := syscall.Mkfifo(filepath.Join(lockDir, "incidents.json.lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Path: filepath.Join(lockDir, "incidents.json")}).Lock(context.Background()); err == nil {
		t.Fatal("FIFO lock file was accepted")
	}
	if _, err := readRootSecret(paths[4], maxSecretBytes); err == nil {
		t.Fatal("FIFO secret file was accepted")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("special file checks were not bounded: %s", elapsed)
	}
}

func TestFileStoreWriteAndSyncFailuresRemainVisible(t *testing.T) {
	path := filepath.Join(privateRuntimeDir(t), "incidents.json")
	store := FileStore{Path: path}
	state := emptyIncidentState()
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	oldWrite := runtimeWrite
	oldSync := runtimeSync
	oldRename := runtimeRename
	oldDirectorySync := runtimeDirectorySync
	t.Cleanup(func() {
		runtimeWrite = oldWrite
		runtimeSync = oldSync
		runtimeRename = oldRename
		runtimeDirectorySync = oldDirectorySync
	})

	runtimeWrite = func(*os.File, []byte) (int, error) { return 0, errors.New("synthetic write failure") }
	if err := store.Save(context.Background(), state); err == nil {
		t.Fatal("write failure was hidden")
	}
	assertStateBytesUnchanged(t, path, original)

	runtimeWrite = oldWrite
	runtimeSync = func(*os.File) error { return errors.New("synthetic fsync failure") }
	if err := store.Save(context.Background(), state); err == nil {
		t.Fatal("fsync failure was hidden")
	}
	assertStateBytesUnchanged(t, path, original)

	runtimeSync = oldSync
	runtimeRename = func(*os.Root, string, string) error { return errors.New("synthetic rename failure") }
	if err := store.Save(context.Background(), state); err == nil {
		t.Fatal("rename failure was hidden")
	}
	assertStateBytesUnchanged(t, path, original)

	runtimeRename = oldRename
	runtimeDirectorySync = func(*os.Root) error { return errors.New("synthetic directory fsync failure") }
	if err := store.Save(context.Background(), state); err == nil {
		t.Fatal("directory fsync failure was hidden")
	}
}

func TestCollectorReadLeavesOrdinaryHostConfigUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sshd_config")
	original := []byte("PermitRootLogin no\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	beforeDir, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	beforeFile, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := readCollectorPath(path, maxRuntimeReadBytes)
	if err != nil || string(body) != string(original) {
		t.Fatalf("collector read failed: %v %q", err, body)
	}
	afterDir, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	afterFile, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if afterDir.Mode() != beforeDir.Mode() || afterFile.Mode() != beforeFile.Mode() {
		t.Fatalf("collector read mutated modes: dir %v->%v file %v->%v", beforeDir.Mode(), afterDir.Mode(), beforeFile.Mode(), afterFile.Mode())
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	body, err = defaultAdapters().Read(path)
	if err != nil || string(body) != string(original) {
		t.Fatalf("read-only collector read failed: %v %q", err, body)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing-host-config")
	if _, err := readCollectorPath(missing, maxRuntimeReadBytes); !os.IsNotExist(err) {
		t.Fatalf("missing collector path: %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("collector read created a missing host file")
	}
}

func TestTrustedIntermediateAncestorsDoNotNeedPrivateMode(t *testing.T) {
	root := privateRuntimeDir(t)
	mid := filepath.Join(root, "mid")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(mid, "runtime")
	if err := os.Mkdir(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := (FileStore{Path: filepath.Join(leaf, "incidents.json")}).Lock(context.Background())
	if err != nil {
		t.Fatalf("trusted 0755 intermediate ancestor was rejected: %v", err)
	}
	unlock()

	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o775); err != nil {
		t.Fatal(err)
	}
	privateLeaf := filepath.Join(writable, "runtime")
	if err := os.Mkdir(privateLeaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privateLeaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Path: filepath.Join(privateLeaf, "incidents.json")}).Lock(context.Background()); err == nil {
		t.Fatal("group-writable EUID ancestor was accepted")
	}

	sticky := filepath.Join(root, "sticky")
	if err := os.Mkdir(sticky, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, 0o1777); err != nil {
		t.Fatal(err)
	}
	stickyLeaf := filepath.Join(sticky, "runtime")
	if err := os.Mkdir(stickyLeaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stickyLeaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Path: filepath.Join(stickyLeaf, "incidents.json")}).Lock(context.Background()); err == nil {
		t.Fatal("non-root sticky ancestor was accepted")
	}
}

func assertStateBytesUnchanged(t *testing.T, path string, expected []byte) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(expected) {
		t.Fatalf("failed state write replaced durable state: got=%s want=%s", body, expected)
	}
}
