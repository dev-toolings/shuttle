//go:build linux

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
)

func TestHelperCandidatePolicyRefusalLeavesNoRecovery(t *testing.T) {
	for _, tc := range []struct{ name, candidate, message string }{
		{"downgrade", "v0.0.65", "--allow-downgrade"},
		{"pending intent", "v0.0.65", "--allow-downgrade"},
		{"malformed", "invalid", "cannot compare helper version"},
		{"missing", "", "valid Shuttle version"},
		{"development", "dev", "pending destroy journal"},
		{"unconfirmed", "v0.0.67", "candidate termination is unconfirmed"},
		{"timeout", "v0.0.67", "context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			proof := testHelperMigrationOwnReservationProof()
			c := coord.New(coord.Options{Root: root, LockPath: filepath.Join(t.TempDir(), "lock"), BootID: func() (string, error) { return proof.BootID, nil }})
			_, err := c.Reserve(context.Background(), coord.Request{ID: proof.OperationID, Kind: proof.OperationKind, Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint})
			if err != nil {
				t.Fatal(err)
			}
			oldFS, oldRoot := rootHelperCandidateFS, rootDestroyCleanupRoot
			rootHelperCandidateFS = testHelperMigrationFS
			rootDestroyCleanupRoot = filepath.Join(root, "destroy-cleanup")
			t.Cleanup(func() { rootHelperCandidateFS, rootDestroyCleanupRoot = oldFS, oldRoot })
			if tc.name == "development" {
				if err := os.Mkdir(rootDestroyCleanupRoot, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootDestroyCleanupRoot, "pending.json"), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			oldC, oldI, oldG, oldP, oldV := rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, rootHelperUpdatePreflightRuntime, version.Version
			t.Cleanup(func() {
				rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, rootHelperUpdatePreflightRuntime, version.Version = oldC, oldI, oldG, oldP, oldV
			})
			rootOperationCoordinator = func() *coord.Coordinator { return c }
			rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return nil }
			rootCoordinatedMutationGuard = func(string) error { return nil }
			paths := helperMigrationPaths{JournalPath: root, IntentPath: filepath.Join(t.TempDir(), "migration", "intent.json"), BackupStagingPath: filepath.Join(root, "absent")}
			rootHelperUpdatePreflightRuntime = func() helperMigrationRuntime {
				return helperMigrationRuntime{paths: paths, fs: testHelperMigrationFS(), writerProof: readMigrationWriterProof, bootID: func() (string, error) { return proof.BootID, nil }}
			}
			version.Version = "v0.0.66"
			plan := rootplan.Plan{Helper: &rootplan.HelperOperation{PayloadSHA256: proof.CandidateSHA256}, Action: "helper-update", OperationID: proof.OperationID, OperationKind: proof.OperationKind, OperatorKeyFingerprint: proof.OwnerKeyFingerprint, RequiredHostFingerprint: proof.HostFingerprint, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
			output := "shuttle version " + tc.candidate
			if tc.candidate == "" {
				output = "no version"
			}
			installed := filepath.Join(t.TempDir(), "installed")
			if err := os.WriteFile(installed, []byte("installed"), 0755); err != nil {
				t.Fatal(err)
			}
			// Use a real local ELF for validation and staging; only its process
			// output is simulated. All policy and cleanup run through apply.
			payload, err := os.ReadFile("/bin/true")
			if err != nil {
				t.Fatal(err)
			}
			proof.CandidateSHA256 = rootplan.PayloadDigest(payload)
			plan.Helper.PayloadSHA256 = proof.CandidateSHA256
			oldExecutable, oldCommand := rootHelperUpdateExecutable, rootHelperCandidateCommand
			t.Cleanup(func() { rootHelperUpdateExecutable, rootHelperCandidateCommand = oldExecutable, oldCommand })
			rootHelperUpdateExecutable = installed
			rootHelperCandidateCommand = func(context.Context, string, string, string) ([]byte, bool, error) {
				if tc.name == "pending intent" {
					if err := writeHelperMigrationIntent(testHelperMigrationFS(), paths.IntentPath, testHelperMigrationIntent()); err != nil {
						return nil, false, err
					}
				}
				if tc.name == "unconfirmed" {
					return nil, false, errHelperProbeUnconfirmed
				}
				if tc.name == "timeout" {
					return nil, false, context.DeadlineExceeded
				}
				return []byte(output), false, nil
			}
			err = applyRootHelperUpdate(plan, payload)
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("wrong refusal: %v", err)
			}
			body, err := os.ReadFile(installed)
			if err != nil || string(body) != "installed" {
				t.Fatalf("refusal replaced helper: %q %v", body, err)
			}
			record, err := c.Get(context.Background(), proof.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "unconfirmed" || tc.name == "timeout" || tc.name == "pending intent" {
				if tc.name == "pending intent" {
					if stored, err := readHelperMigrationOwnReservationProof(testHelperMigrationFS(), paths); err != nil || stored == nil {
						t.Fatalf("pending intent lost admission: %v %v", stored, err)
					}
				}
				if record.State != coord.RecoveryRequired || !record.RecoveryRequired {
					t.Fatalf("uncertain probe lost recovery fence: %+v", record)
				}
				if _, err = c.Reserve(context.Background(), coord.Request{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Kind: "deploy", App: "demo", Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint}); err == nil {
					t.Fatal("uncertain probe allowed deploy")
				}
				return
			}
			if stored, err := readHelperMigrationOwnReservationProof(testHelperMigrationFS(), paths); err != nil || stored != nil {
				t.Fatalf("refusal did not clear admission: %v %v", stored, err)
			}
			if record.State != "failed" || record.RecoveryRequired {
				t.Fatalf("policy refusal requires recovery: state=%s recovery_required=%t", record.State, record.RecoveryRequired)
			}
			if _, err = c.Reserve(context.Background(), coord.Request{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Kind: "deploy", App: "demo", Principal: proof.OwnerKeyFingerprint, OwnerKeyFingerprint: proof.OwnerKeyFingerprint, Host: proof.HostFingerprint}); err != nil {
				t.Fatalf("following deploy blocked: %v", err)
			}
		})
	}
}

func TestHelperPendingDestroyTemporaryClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mode         os.FileMode
		owner, allow bool
	}{
		{".shuttle-root-123456789", 0600, true, true},
		{"pending.json", 0600, true, false},
		{".shuttle-root-", 0600, true, false},
		{".shuttle-root-123x", 0600, true, false},
		{".shuttle-root-123.tmp", 0600, true, false},
		{".shuttle-root-123", 0644, true, false},
		{".shuttle-root-124", 0600, false, false},
		{".shuttle-root-127", os.ModeSetuid | 0600, true, false},
		{".shuttle-root-125", os.ModeDir | 0700, true, false},
		{".shuttle-root-126", os.ModeSymlink | 0600, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, tc.name)
			var err error
			switch {
			case tc.mode.IsDir():
				err = os.Mkdir(path, tc.mode.Perm())
			case tc.mode&os.ModeSymlink != 0:
				err = os.Symlink("missing", path)
			default:
				err = os.WriteFile(path, []byte("retain evidence"), tc.mode)
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.mode.IsRegular() {
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			fs := testHelperMigrationFS()
			fs.ownerOK = func(info os.FileInfo) bool { return info.IsDir() || tc.owner }
			err = refuseHelperRollbackWithPendingDestroy(root, fs)
			if (err == nil) != tc.allow {
				t.Fatalf("pending destroy classification: allow=%t err=%v", tc.allow, err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
				t.Fatalf("entry changed: %v", err)
			}
			if tc.mode.IsRegular() {
				body, err := os.ReadFile(path)
				if err != nil || string(body) != "retain evidence" {
					t.Fatalf("evidence changed: %q %v", body, err)
				}
			}
		})
	}
}
