package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func heldLock(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shuttle-root.lock")
	holder, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("seed the lock: %v", err)
	}
	waiter, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { holder.Close(); waiter.Close() })
	return holder, waiter
}

// A host serving several applications has one shared edge and one shared
// registry, so promotions must not overlap. Queueing is the right answer to
// that; failing instantly turned it into a red build for whoever arrived second.
func TestRootOperationLockWaitsForTheHolder(t *testing.T) {
	holder, waiter := heldLock(t)

	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(150 * time.Millisecond)
		_ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
	}()

	started := time.Now()
	err := acquireRootOperationLock(waiter, 5*time.Second)
	// Join the releasing goroutine before the test cleanup closes holder. This
	// matters even on the failure path: FailNow would otherwise race the
	// cleanup against holder.Fd() under the race detector.
	<-released
	if err != nil {
		t.Fatalf("the lock should have been granted once released: %v", err)
	}
	defer syscall.Flock(int(waiter.Fd()), syscall.LOCK_UN)
	if waited := time.Since(started); waited < 100*time.Millisecond {
		t.Errorf("returned after %s: it cannot have waited for the holder", waited)
	}
}

// Waiting is bounded. Past the budget the holder would have been aborted by the
// watchdog anyway, so a longer wait could only outlive what it waits on.
func TestRootOperationLockGivesUpAndNamesTheWait(t *testing.T) {
	_, waiter := heldLock(t)

	err := acquireRootOperationLock(waiter, 300*time.Millisecond)
	if err == nil {
		t.Fatal("a lock held for the whole budget must not be granted")
	}
	if got := err.Error(); !strings.Contains(got, "after waiting") {
		t.Errorf("error %q does not say how long it waited, which is what tells the operator which failure they hit", got)
	}
}

// A real failure — a bad descriptor, a filesystem without locking — is not a
// busy lock, and must not be retried until the budget runs out.
func TestRootOperationLockSurfacesNonBusyErrors(t *testing.T) {
	closed, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()

	started := time.Now()
	if err := acquireRootOperationLock(closed, time.Minute); err == nil {
		t.Fatal("locking a closed descriptor must fail")
	} else if errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("a closed descriptor is not a busy lock: %v", err)
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Errorf("returned after %s: a hard error was retried instead of surfaced", waited)
	}
}
