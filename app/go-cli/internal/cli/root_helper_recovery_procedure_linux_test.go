//go:build linux

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the documented administrator procedure itself, with all host paths
// replaced by fixtures and syslog disabled. No sudo, flock, or host is used.
func TestInterruptedHelperProbeRecoveryProcedure(t *testing.T) {
	// make ci uses a golang image and does not install Python for the Go job.
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("administrator procedure fixture requires python3, unavailable: %v", err)
	}

	doc, err := os.ReadFile("../../../../docs/operations-recovery.md")
	if err != nil {
		t.Fatal(err)
	}
	_, script, ok := strings.Cut(string(doc), "<<'PYRECOVERY'\n")
	if !ok {
		t.Fatal("recovery procedure missing")
	}
	script, _, ok = strings.Cut(script, "\nPYRECOVERY")
	if !ok {
		t.Fatal("recovery procedure terminator missing")
	}
	for _, state := range []string{"absent", "prepared", "completed", "completed-candidate-installed", "candidate-installed", "foreign", "missing-proof", "invalid-proof", "wrong-host"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			migration, journal, installed := filepath.Join(root, "migration"), filepath.Join(root, "operations"), filepath.Join(root, "shuttle-root")
			if err := os.MkdirAll(migration, 0o700); err != nil {
				t.Fatal(err)
			}
			source := []byte("source helper")
			if err := os.WriteFile(installed, source, 0o755); err != nil {
				t.Fatal(err)
			}
			proof := testHelperMigrationOwnReservationProof()
			proof.CandidateSHA256 = digestBytes([]byte("candidate helper"))
			operationID := proof.OperationID
			record := map[string]any{"id": operationID, "kind": "helper-update", "state": "recovery_required", "recovery_required": true, "host": proof.HostFingerprint}
			writeRecoveryHelperFile(t, filepath.Join(journal, operationID+".json"), record)
			intentPath, ownPath := filepath.Join(migration, "intent.json"), filepath.Join(migration, "own-reservation.json")
			intentID := ""
			if state == "prepared" || strings.HasPrefix(state, "completed") {
				intent := testHelperMigrationIntent()
				intent.Source, intent.Host, intent.BootID = installed+"#"+digestBytes(source), proof.HostFingerprint, proof.BootID
				intent.CandidateSHA256 = proof.CandidateSHA256
				if state == "prepared" {
					intentID = intent.ID
				} else {
					intent.Phase = helperMigrationPhaseComplete
				}
				writeRecoveryHelperFile(t, intentPath, intent)
			}
			if state == "candidate-installed" || state == "completed-candidate-installed" {
				proof.CandidateSHA256 = digestBytes(source)
			}
			if state == "foreign" {
				proof.OperationID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			if state == "wrong-host" {
				proof.HostFingerprint = "SHA256:" + strings.Repeat("Z", 43)
			}
			if state != "missing-proof" {
				writeRecoveryHelperFile(t, ownPath, proof)
			}
			if state == "invalid-proof" {
				if err := os.WriteFile(ownPath, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			beforeOwn, _ := os.ReadFile(ownPath)
			beforeIntent, _ := os.ReadFile(intentPath)
			local := strings.NewReplacer("/var/lib/shuttle/helper-migration", migration, "/var/lib/shuttle/operations", journal, "/usr/local/libexec/shuttle-root", installed).Replace(script)
			local = strings.Replace(local, "root = pathlib.Path", "syslog.syslog = lambda *args: None\nroot = pathlib.Path", 1)
			command := exec.Command(python, "-", operationID, intentID)
			command.Stdin = strings.NewReader(local)
			output, err := command.CombinedOutput()
			success := state == "absent" || state == "prepared" || state == "completed"
			if (err == nil) != success {
				t.Fatalf("recovery outcome: %v\n%s", err, output)
			}
			afterOwn, ownErr := os.ReadFile(ownPath)
			afterIntent, intentErr := os.ReadFile(intentPath)
			if success {
				if !os.IsNotExist(ownErr) || (state != "completed" && !os.IsNotExist(intentErr)) {
					t.Fatal("abandoned attempt was not cleared")
				}
				if state == "completed" && (intentErr != nil || string(afterIntent) != string(beforeIntent)) {
					t.Fatal("completed intent changed")
				}
			} else if string(afterOwn) != string(beforeOwn) || string(afterIntent) != string(beforeIntent) {
				t.Fatal("refused recovery changed evidence")
			}
			if _, err := os.Stat(filepath.Join(journal, operationID+".json")); err != nil {
				t.Fatal("procedure changed operation journal")
			}
		})
	}
}

func TestOldHelperDestroyCleanupRecoveryProcedure(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for administrator procedure fixture")
	}
	doc, err := os.ReadFile("../../../../docs/operations-recovery.md")
	if err != nil {
		t.Fatal(err)
	}
	_, script, ok := strings.Cut(string(doc), "<<'PYDESTROYCLEANUP'\n")
	if !ok {
		t.Fatal("old-helper destroy-cleanup procedure missing")
	}
	script, _, ok = strings.Cut(script, "\nPYDESTROYCLEANUP")
	if !ok {
		t.Fatal("old-helper procedure terminator missing")
	}
	for _, scenario := range []string{"empty", "absent", "pending-journal", "symlink", "wrong-mode", "wrong-owner", "active-operation", "pending-destroy", "malformed-record", "pending-intent", "own-proof"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			operations, migration := filepath.Join(root, "operations"), filepath.Join(root, "migration")
			cleanup := filepath.Join(operations, "destroy-cleanup")
			if err := os.MkdirAll(cleanup, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(migration, 0o700); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "absent":
				if err := os.Remove(cleanup); err != nil {
					t.Fatal(err)
				}
			case "pending-journal":
				if err := os.WriteFile(filepath.Join(cleanup, "pending.json"), []byte("pending destroy evidence"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(cleanup); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), cleanup); err != nil {
					t.Fatal(err)
				}
			case "wrong-mode":
				if err := os.Chmod(cleanup, 0o755); err != nil {
					t.Fatal(err)
				}
			case "active-operation", "pending-destroy", "malformed-record":
				body := `{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":"shuttle.operation/v1","kind":"helper-update","state":"active","recovery_required":false}`
				if scenario == "pending-destroy" {
					body = `{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":"shuttle.operation/v1","kind":"destroy","state":"recovery_required","recovery_required":true}`
				}
				if scenario == "malformed-record" {
					body = "invalid"
				}
				if err := os.WriteFile(filepath.Join(operations, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			case "pending-intent":
				if err := os.WriteFile(filepath.Join(migration, "intent.json"), []byte(`{"phase":"prepared"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "own-proof":
				if err := os.WriteFile(filepath.Join(migration, "own-reservation.json"), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			local := strings.ReplaceAll(script, "/var/lib/shuttle/operations", operations)
			local = strings.ReplaceAll(local, "/var/lib/shuttle/helper-migration", migration)
			local = strings.ReplaceAll(local, "st_uid == 0", "st_uid == os.getuid()")
			if scenario == "wrong-owner" {
				local = strings.ReplaceAll(local, "st_uid == os.getuid()", "st_uid == -1")
			}
			local = strings.ReplaceAll(local, "syslog.syslog", "lambda_syslog")
			local = "lambda_syslog = lambda *args: None\n" + local
			out, err := exec.Command(python, "-c", local).CombinedOutput()
			succeeds := scenario == "empty" || scenario == "absent"
			if (err == nil) != succeeds {
				t.Fatalf("scenario=%s error=%v output=%s", scenario, err, out)
			}
			_, statErr := os.Lstat(cleanup)
			if succeeds && !os.IsNotExist(statErr) {
				t.Fatalf("empty directory retained: %v", statErr)
			}
			if !succeeds && statErr != nil {
				t.Fatalf("refusal removed cleanup evidence: %v", statErr)
			}
			if scenario == "pending-journal" {
				body, err := os.ReadFile(filepath.Join(cleanup, "pending.json"))
				if err != nil || string(body) != "pending destroy evidence" {
					t.Fatalf("pending journal changed: %v", err)
				}
			}
		})
	}
}
