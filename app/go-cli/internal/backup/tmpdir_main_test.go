package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain resolves the temporary directory before any test creates one.
//
// The host-side stores this package tests refuse a path with a symlinked
// ancestor, on purpose: on the VPS that is how a planted link would redirect a
// root-owned write. On macOS, /var is a symlink to /private/var and t.TempDir
// lives under it, so every store test failed on the safety check instead of on
// what it tested, and the macOS CI job stayed red. Resolving TMPDIR once keeps
// the check intact and gives the tests the path the store will accept.
func TestMain(m *testing.M) {
	if resolved, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		_ = os.Setenv("TMPDIR", resolved)
	}
	os.Exit(m.Run())
}
