package backuplifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func isolatedStore(t *testing.T) Store {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return Store{Root: filepath.Join(parent, "backups")}
}

func applySequence(t *testing.T, store Store, statuses ...Status) {
	t.Helper()
	for _, status := range statuses {
		if err := store.Apply(status); err != nil {
			t.Fatalf("apply %s %s: %v", status.AttemptID, status.Phase, err)
		}
	}
}

func TestStoreKeepsLastSuccessAndRejectsOldOrConflictingAttempts(t *testing.T) {
	store := isolatedStore(t)
	pending := testStatus("backup-1", PhaseSource)
	if err := store.Apply(pending); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(pending); err != nil {
		t.Fatalf("identical phase was not idempotent: %v", err)
	}
	conflict := pending
	conflict.Error = "redacted failure"
	if err := store.Apply(conflict); err == nil {
		t.Fatal("conflicting duplicate phase was accepted")
	}
	applySequence(t, store, testStatus("backup-1", PhaseSourceDone), testStatus("backup-1", PhaseReceipt), testStatus("backup-1", PhaseComplete))
	secondBegin := testCloudStatus("backup-2", PhaseSource)
	secondBegin.CreatedAt = time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC).Format(time.RFC3339Nano)
	secondBegin.UpdatedAt = secondBegin.CreatedAt
	secondDone := testCloudStatus("backup-2", PhaseSourceDone)
	secondDone.CreatedAt = secondBegin.CreatedAt
	secondDone.UpdatedAt = secondBegin.CreatedAt
	secondReceipt := testCloudStatus("backup-2", PhaseReceipt)
	secondReceipt.CreatedAt = secondBegin.CreatedAt
	secondReceipt.UpdatedAt = secondBegin.CreatedAt
	failed := testCloudStatus("backup-2", PhaseCloudFailed)
	failed.CreatedAt = secondBegin.CreatedAt
	failed.UpdatedAt = secondBegin.CreatedAt
	applySequence(t, store, secondBegin, secondDone, secondReceipt, failed)
	journal, err := store.Load("demo")
	if err != nil {
		t.Fatal(err)
	}
	if journal.LatestAttempt == nil || journal.LatestAttempt.AttemptID != "backup-2" || journal.LatestAttempt.Phase != PhaseCloudFailed {
		t.Fatalf("latest attempt did not keep the cloud failure: %#v", journal.LatestAttempt)
	}
	if journal.LastSuccess == nil || journal.LastSuccess.AttemptID != "backup-2" || !LocalArtifactSuccess(*journal.LastSuccess) || journal.LastSuccess.State == StateFailed {
		t.Fatalf("new local receipt did not become last success: %#v", journal.LastSuccess)
	}
	if err := store.Apply(pending); err == nil {
		t.Fatal("superseded admitted attempt was replayed as a new begin")
	}
	skew := testStatus("backup-3", PhaseSource)
	skew.CreatedAt = time.Date(2026, 9, 13, 11, 59, 0, 0, time.UTC).Format(time.RFC3339Nano)
	skew.UpdatedAt = skew.CreatedAt
	if err := store.Apply(skew); err != nil {
		t.Fatalf("clock-skewed new begin was refused: %v", err)
	}
}

func TestStoreRejectsUnknownPhaseWithoutBegin(t *testing.T) {
	store := isolatedStore(t)
	if err := store.Apply(testStatus("backup-1", PhaseComplete)); err == nil {
		t.Fatal("complete without begin was accepted")
	}
	if err := store.Apply(testCloudStatus("backup-2", PhaseCloudFailed)); err == nil {
		t.Fatal("cloud failure without begin was accepted")
	}
}

func TestStoreRejectsWrongAppHostAndImmutableProgression(t *testing.T) {
	store := isolatedStore(t)
	applySequence(t, store, testStatus("backup-1", PhaseSource), testStatus("backup-1", PhaseSourceDone), testStatus("backup-1", PhaseReceipt))
	wrongApp := testStatus("backup-1", PhaseComplete)
	wrongApp.App = "other"
	if err := store.Apply(wrongApp); err == nil {
		t.Fatal("wrong application was accepted")
	}
	wrongHost := testStatus("backup-1", PhaseComplete)
	wrongHost.Host = "other.example"
	if err := store.Apply(wrongHost); err == nil {
		t.Fatal("wrong host was accepted")
	}
	digestB := testCloudStatus("backup-1", PhaseCloud)
	digestB.ArchiveSHA256 = strings.Repeat("c", 64)
	if err := store.Apply(digestB); err == nil {
		t.Fatal("cloud verification with a different digest was accepted")
	}
}

func TestStoreRejectsSymlinkAndSpecialJournal(t *testing.T) {
	store := isolatedStore(t)
	root := store.Root
	status := testStatus("backup-1", PhaseSource)
	if err := os.MkdirAll(filepath.Join(root, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), store.Path("demo")); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(status); err == nil {
		t.Fatal("symlink journal was accepted")
	}
	_ = os.Remove(store.Path("demo"))
	if err := os.MkdirAll(filepath.Join(root, "demo", "status.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(status); err == nil {
		t.Fatal("directory journal was accepted")
	}
}

func TestStoreRejectsSymlinkAncestorBeforeCreatingApplicationData(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	store := Store{Root: filepath.Join(link, "backups")}
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err == nil {
		t.Fatal("symlink ancestor was followed")
	}
	if _, err := os.Stat(filepath.Join(outside, "backups", "demo")); !os.IsNotExist(err) {
		t.Fatalf("unsafe ancestor was mutated: %v", err)
	}
}

func TestStoreRejectsWorldWritableAndStickyAncestors(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store := Store{Root: filepath.Join(parent, "backups")}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err == nil {
		t.Fatal("world-writable ancestor was accepted")
	}
	if err := os.Chmod(parent, 0o1777); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err == nil {
		t.Fatal("sticky world-writable ancestor was accepted")
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err != nil {
		t.Fatalf("trusted non-writable ancestor was refused: %v", err)
	}
}

func TestStorePreservesPreviousJournalWhenDirectorySyncFails(t *testing.T) {
	store := isolatedStore(t)
	previous := testStatus("backup-1", PhaseSource)
	if err := store.Apply(previous); err != nil {
		t.Fatal(err)
	}
	oldSyncDir := syncDirFile
	syncDirFile = func(*os.File) error { return errors.New("synthetic directory sync failure") }
	defer func() { syncDirFile = oldSyncDir }()
	next := testStatus("backup-1", PhaseSourceDone)
	if err := store.Apply(next); err == nil {
		t.Fatal("directory sync failure was hidden")
	}
	journal, err := store.Load("demo")
	if err != nil {
		t.Fatal(err)
	}
	if journal.LatestAttempt == nil || journal.LatestAttempt.Phase != PhaseSource {
		t.Fatalf("previous usable journal was not preserved: %#v", journal)
	}
}

func TestStoreAbortsWhenNewDirectoryParentSyncFails(t *testing.T) {
	store := isolatedStore(t)
	oldSyncDir := syncDirFile
	syncDirFile = func(*os.File) error { return errors.New("synthetic parent directory sync failure") }
	defer func() { syncDirFile = oldSyncDir }()
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err == nil {
		t.Fatal("new directory parent sync failure was hidden")
	}
	if _, err := os.Stat(store.Path("demo")); !os.IsNotExist(err) {
		t.Fatalf("journal was created despite parent sync failure: %v", err)
	}
}

func TestStoreApplyUnderActualFlockContention(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "journal.lock")
	holder, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	store := Store{Root: filepath.Join(dir, "backups")}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		waiter, openErr := os.OpenFile(lockPath, os.O_RDWR, 0)
		if openErr != nil {
			done <- openErr
			return
		}
		defer waiter.Close()
		close(started)
		if lockErr := syscall.Flock(int(waiter.Fd()), syscall.LOCK_EX); lockErr != nil {
			done <- lockErr
			return
		}
		defer syscall.Flock(int(waiter.Fd()), syscall.LOCK_UN)
		done <- store.Apply(testStatus("backup-1", PhaseSource))
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("waiter proceeded while the exclusive lock was held: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	journal, err := store.Load("demo")
	if err != nil || journal.LatestAttempt == nil || journal.LatestAttempt.AttemptID != "backup-1" {
		t.Fatalf("flock-protected begin was not readable: %#v %v", journal, err)
	}
}

func TestStoreValidatesAncestorsWhenDestinationAlreadyExists(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store := Store{Root: filepath.Join(parent, "backups")}
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	next := testStatus("backup-1", PhaseSourceDone)
	if err := store.Apply(next); err == nil {
		t.Fatal("existing destination under a world-writable ancestor was accepted")
	}
}

func TestStoreBeginRetryAfterDirectorySyncFailure(t *testing.T) {
	store := isolatedStore(t)
	pending := testStatus("backup-1", PhaseSource)
	if err := store.Apply(pending); err != nil {
		t.Fatal(err)
	}
	oldSyncDir := syncDirFile
	syncDirFile = func(*os.File) error { return errors.New("synthetic directory sync failure") }
	if err := store.Apply(pending); err == nil {
		syncDirFile = oldSyncDir
		t.Fatal("identical begin skipped durability after a failed directory sync")
	}
	syncDirFile = oldSyncDir
	if err := store.Apply(pending); err != nil {
		t.Fatalf("retry did not establish durability: %v", err)
	}
}

func TestStoreBeginRetryAfterParentSyncFailure(t *testing.T) {
	store := isolatedStore(t)
	oldSyncDir := syncDirFile
	syncDirFile = func(*os.File) error { return errors.New("synthetic parent directory sync failure") }
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err == nil {
		syncDirFile = oldSyncDir
		t.Fatal("new directory parent sync failure was hidden")
	}
	syncDirFile = oldSyncDir
	if err := store.Apply(testStatus("backup-1", PhaseSource)); err != nil {
		t.Fatalf("retry after parent sync failure did not establish the journal: %v", err)
	}
}

func TestStoreCompactsAdmittedAttemptsWithoutLosingReplayProtection(t *testing.T) {
	store := isolatedStore(t)
	first := testStatus("backup-01", PhaseSource)
	for i := 1; i <= maxAdmittedAttempts+1; i++ {
		begin := testStatus(fmt.Sprintf("backup-%02d", i), PhaseSource)
		if err := store.Apply(begin); err != nil {
			t.Fatalf("begin %s: %v", begin.AttemptID, err)
		}
		if i == 1 {
			first = begin
		}
	}
	journal, err := store.Load("demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.AdmittedAttempts) > maxRetainedAdmissions {
		t.Fatalf("admitted attempts were not compacted: %d", len(journal.AdmittedAttempts))
	}
	if len(journal.CompactedAttemptHashes) == 0 {
		t.Fatal("compacted identity hashes were not retained")
	}
	if err := store.Apply(first); err == nil {
		t.Fatal("compacted attempt was replayed as a new begin")
	}
}
