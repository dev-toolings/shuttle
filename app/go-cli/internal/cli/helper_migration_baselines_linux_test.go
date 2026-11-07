//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A coordinated deploy archives baselines below the journal. The migration
// inspection refused that directory, so the next signed helper update failed.
func TestHelperMigrationJournalAcceptsPrivateBaselineArchive(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	baselines := filepath.Join(directory, rootOperationBaselineDirName)
	if err := os.Mkdir(baselines, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := testHelperMigrationFS()
	if err := inspectHelperMigrationJournal(helperMigrationPaths{JournalPath: directory}, fs, nil, helperMigrationOwnReservationProof{}); err != nil {
		t.Fatalf("private baseline archive refused: %v", err)
	}
	if err := os.Chmod(baselines, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := inspectHelperMigrationJournal(helperMigrationPaths{JournalPath: directory}, fs, nil, helperMigrationOwnReservationProof{}); err == nil {
		t.Fatal("non-private baseline archive accepted")
	}
}
