package monitoring

import (
	"os"
	"path/filepath"
	"testing"
)

// A webhook secret under setup's 0755 /etc/shuttle was refused on the live VPS
// because its parent was held to the private runtime-state rule.
func TestSecretParentAcceptsNonWritableSharedDirectoryOnly(t *testing.T) {
	// /tmp directly: TMPDIR may sit below a group-writable directory, which the
	// ancestor rule correctly refuses and would hide the behavior under test.
	base, err := os.MkdirTemp("/tmp", "shuttle-secret-parent-")
	if err != nil {
		t.Skipf("no /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if dir, err := openSecretParentDirectory(base); err != nil {
		t.Skipf("temporary directory ancestors are writable by others on this host: %v", err)
	} else {
		_ = dir.Close()
	}
	shared := filepath.Join(base, "etc-shuttle")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if dir, err := openRuntimeDirectory(shared, false); err == nil {
		_ = dir.Close()
		t.Fatal("runtime state accepted a non-private final directory")
	}
	dir, err := openSecretParentDirectory(shared)
	if err != nil {
		t.Fatalf("secret parent refused a non-writable shared directory: %v", err)
	}
	_ = dir.Close()
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if dir, err := openSecretParentDirectory(shared); err == nil {
		_ = dir.Close()
		t.Fatal("secret parent accepted a world-writable directory")
	}
}
