//go:build linux

package operationwriters

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStoreUsesCallerOwnedExternalFlock(t *testing.T) {
	root := privateTestRoot(t)
	lock, err := os.OpenFile(filepath.Join(root, "coordination.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, err := NewStore(root).InitializeLocked(testBinding(), testBaseline()); err != nil {
		t.Fatal(err)
	}
}
