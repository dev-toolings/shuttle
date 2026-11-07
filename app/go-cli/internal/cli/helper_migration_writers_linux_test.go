//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A crash can leave the uncommitted state file next to the authoritative JSON.
// Its bytes are not a closure proof and must survive inspection unchanged.
func TestMigrationWriterProofRetainsPrivateTemporaries(t *testing.T) {
	for _, id := range []string{strings.Repeat("a", 32), "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b10"} {
		for _, invalid := range []string{"", "mode", "owner", "directory", "symlink", "name"} {
			t.Run(id+"/"+invalid, func(t *testing.T) {
				root := t.TempDir()
				name := "." + id + "." + strings.Repeat("b", 24) + ".tmp"
				if invalid == "name" {
					name = "." + id + ".unknown.tmp"
				}
				path := filepath.Join(root, name)
				body := []byte(`{"unfinished":`)
				switch invalid {
				case "directory":
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(filepath.Join(root, "absent"), path); err != nil {
						t.Fatal(err)
					}
				default:
					if err := os.WriteFile(path, body, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if invalid == "mode" {
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				fs := testHelperMigrationFS()
				if invalid == "owner" {
					fs.ownerOK = func(os.FileInfo) bool { return false }
				}
				proof, err := readMigrationWriterProofWithFS(root, fs)
				if (err != nil) != (invalid != "") {
					t.Fatalf("invalid=%s err=%v", invalid, err)
				}
				if invalid == "" {
					if len(proof.Writers) != 0 {
						t.Fatal("temporary counted as a committed writer proof")
					}
					retained, err := os.ReadFile(path)
					if err != nil || string(retained) != string(body) {
						t.Fatalf("temporary changed: %v", err)
					}
				}
			})
		}
	}
}
