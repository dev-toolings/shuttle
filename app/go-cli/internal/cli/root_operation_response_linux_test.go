//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

// Frozen top-level Record shape from c762f5f. Nested types did not change in
// the registry fix. Do not replace this with the current Record: doing so
// would silently teach the compatibility test every newly added journal field.
type legacyOperationRecord struct {
	Schema              string        `json:"schema"`
	ID                  string        `json:"id"`
	Revision            uint64        `json:"revision"`
	Kind                string        `json:"kind"`
	Scope               string        `json:"scope"`
	App                 string        `json:"app,omitempty"`
	Principal           string        `json:"principal"`
	OwnerKeyFingerprint string        `json:"owner_key_fingerprint,omitempty"`
	Host                string        `json:"host,omitempty"`
	HostBootID          string        `json:"host_boot_id"`
	StartedAt           string        `json:"started_at"`
	UpdatedAt           string        `json:"updated_at"`
	LeaseUntil          string        `json:"lease_until"`
	State               string        `json:"state"`
	RecoveryRequired    bool          `json:"recovery_required"`
	Result              string        `json:"result,omitempty"`
	Phases              []coord.Phase `json:"phases,omitempty"`
	// CurrentManifestSHA256 is the full digest of the current.yml this
	// operation wrote, journaled before the file itself. Recovery reads it as
	// the operation's own proof for that artifact; see JournalCurrentManifest.
	CurrentManifestSHA256 string `json:"current_manifest_sha256,omitempty"`
	// RecoveryCurrentManifestSHA256 binds the exact current.yml produced by a
	// deploy recovery that keeps a newer infrastructure image. It is separate
	// from CurrentManifestSHA256, which remains the failed deploy's own proof.
	RecoveryCurrentManifestSHA256 string `json:"recovery_current_manifest_sha256,omitempty"`
	// FirstReleaseConvergenceState is durable evidence for whether the first
	// release passed its stack convergence wait. Recovery may remove a first
	// release only when this state is not-converged.
	FirstReleaseConvergenceState          string                    `json:"first_release_convergence_state,omitempty"`
	FirstReleaseConvergenceManifestSHA256 string                    `json:"first_release_convergence_manifest_sha256,omitempty"`
	RunTarget                             *coord.RunTarget          `json:"run_target,omitempty"`
	RecoveryActions                       []string                  `json:"recovery_actions,omitempty"`
	RecoveryPlanDigest                    string                    `json:"recovery_plan_digest,omitempty"`
	RecoveryObservation                   coord.RecoveryObservation `json:"recovery_observation,omitempty"`
	RecoveryIntent                        *coord.RecoveryIntent     `json:"recovery_intent,omitempty"`
	Events                                []coord.Event             `json:"events,omitempty"`
}

func TestRootOperationResponsesKeepLegacyShapeAndDurableRegistryProof(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	owner := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	c := coord.New(coord.Options{Root: root, LockPath: filepath.Join(t.TempDir(), "root.lock"), BootID: func() (string, error) { return "boot-a", nil }})
	oldC, oldI, oldG := rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard
	t.Cleanup(func() {
		rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard = oldC, oldI, oldG
	})
	rootOperationCoordinator = func() *coord.Coordinator { return c }
	rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return nil }
	rootCoordinatedMutationGuard = func(string) error { return nil }
	h, err := c.Reserve(ctx, coord.Request{Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	request := coord.PhaseRequest{ID: h.ID(), Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host, Name: "writers-initialize"}
	store := operationwriters.NewStore(root)
	var binding operationwriters.Binding
	if err := c.ExecutePhase(ctx, request, func(_ context.Context, record coord.Record) error {
		binding = operationWriterBinding(record)
		_, err := store.InitializeLocked(binding, operationwriters.Baseline{ConfiguredNativePGVersion: "not-configured", ConfiguredNativePGCluster: "not-configured"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	intent := coord.RegistryReplacement{Image: "registry:3@sha256:" + strings.Repeat("a", 64), VolumeSHA256: "sha256:" + strings.Repeat("b", 64)}
	request.Name = "stack-apply"
	request.Concurrent = true
	if err := c.ExecutePhase(ctx, request, func(phase context.Context, _ coord.Record) error {
		return coord.JournalRegistryReplacement(phase, intent)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CloseAdmissionsLocked(binding); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitClosureLocked(binding, nil); err != nil {
		t.Fatal(err)
	}
	for _, surface := range []string{"operation-renew", "active status", "operation-finish", "completed status"} {
		t.Run(surface, func(t *testing.T) {
			var body []byte
			var err error
			var decoded legacyOperationRecord
			status := strings.HasSuffix(surface, "status")
			if status {
				body, err = operationsRootStatus(ctx)
			} else {
				plan := rootplan.Plan{Action: surface, OperationID: h.ID(), OperationKind: "deploy", OperationApp: "demo", OperatorUser: "deploy", OperatorKeyFingerprint: owner, RequiredHostFingerprint: host, ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339), Control: &rootplan.OperationControl{Result: "deployment completed"}}
				body, err = controlRootOperationWith(ctx, c, plan)
			}
			if err != nil {
				t.Fatal(err)
			}
			if status {
				var records []legacyOperationRecord
				err = decodeSingleJSON(body, &records)
				if err == nil && len(records) != 1 {
					t.Fatalf("status has %d records", len(records))
				}
				if err == nil {
					decoded = records[0]
				}
			} else {
				err = decodeSingleJSON(body, &decoded)
			}
			if err != nil {
				t.Errorf("old strict CLI cannot read %s: %v", surface, err)
			}
			stored, err := c.Get(ctx, h.ID())
			if err != nil {
				t.Fatal(err)
			}
			if stored.RegistryReplacement == nil || *stored.RegistryReplacement != intent {
				t.Fatal("response projection erased the durable registry proof")
			}
			raw, err := os.ReadFile(filepath.Join(root, h.ID()+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var oldJournal legacyOperationRecord
			if err := decodeSingleJSON(raw, &oldJournal); err == nil || !strings.Contains(err.Error(), `unknown field "registry_replacement"`) {
				t.Fatalf("old strict journal reader unexpectedly accepted the durable field: %v", err)
			}
			// Only the helper-only proof may be omitted; retain every established
			// response field and its value, including the final completed state.
			stored.RegistryReplacement = nil
			expected, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			var want legacyOperationRecord
			if err := decodeSingleJSON(expected, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, want) {
				t.Errorf("%s changed established response fields", surface)
			}
		})
	}
}

// The candidate's pure-help admission scan calls this writer inventory reader
// before replacement. An old full-record decoder must reject the on-disk proof,
// even though old clients can read the projected status and control responses.
func TestHelperCandidateScanReadsRetainedRegistryJournal(t *testing.T) {
	root := t.TempDir()
	writers := filepath.Join(root, "writers")
	if err := os.Mkdir(writers, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	binding := testRecoveryBinding()
	state := closedWriterState(t, binding, testRecoveryBaseline("", false, ""))
	record := coord.Record{Schema: coord.Schema, ID: binding.OperationID, Kind: "deploy", State: "completed", Host: binding.HostKey, HostBootID: binding.BootID, RegistryReplacement: &coord.RegistryReplacement{Image: "registry:3@sha256:" + strings.Repeat("a", 64), VolumeSHA256: "sha256:" + strings.Repeat("b", 64)}}
	for path, value := range map[string]any{filepath.Join(writers, binding.OperationID+".json"): state, filepath.Join(root, binding.OperationID+".json"): record} {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fs := testHelperMigrationFS()
	paths := helperMigrationPaths{JournalPath: root}
	reader := func(path string) (helperMigrationWriterProof, error) { return readMigrationWriterProofWithFS(path, fs) }
	if err := inspectRootHelperMigrationStateWithWriterReader(paths, fs, reader); err != nil {
		t.Fatalf("candidate cannot read the retained registry journal: %v", err)
	}
}

// Frozen snapshot shape read by the c762f5f CLI's administrator-side Python
// program. It reads the raw journal into record, bypassing helper response
// projection, for both --dry-run and --yes before observing or closing writers.
type legacyWriterRecoverySnapshot struct {
	Record  legacyOperationRecord  `json:"record"`
	Writers operationwriters.State `json:"writers"`
}

const registryWriterRecoverySnapshotJSON = `{
  "record": {
    "schema": "shuttle.operation/v1",
    "id": "01234567-89ab-cdef-0123-456789abcdef",
    "kind": "deploy",
    "app": "demo",
    "owner_key_fingerprint": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "host": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "host_boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "state": "recovery_required",
    "recovery_required": true,
    "registry_replacement": {
      "image": "registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "volume_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  },
  "writers": {
    "schema": "shuttle.operation-writers/v1",
    "binding": {
      "operation_id": "01234567-89ab-cdef-0123-456789abcdef",
      "generation": 1,
      "host_key": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    },
    "revision": 2,
    "admissions": "open",
    "writers": [
      {
        "id": "ssh-build-runner",
        "kind": "remote_runner",
        "remote": {
          "host_key": "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
          "run_token": "aabbccdd1122334455667788"
        }
      }
    ],
    "baseline": {
      "current": {
        "present": false,
        "full_sha256": ""
      },
      "previous": {
        "present": false,
        "full_sha256": ""
      },
      "configured_native_pg_version": "18.6",
      "configured_native_pg_cluster": "main"
    }
  }
}`

func TestWriterRecoveryNestedSnapshotRequiresRegistryAwareCLI(t *testing.T) {
	body := []byte(registryWriterRecoverySnapshotJSON)
	var legacy legacyWriterRecoverySnapshot
	if err := decodeSingleJSON(body, &legacy); err == nil || err.Error() != `json: unknown field "registry_replacement"` {
		t.Fatalf("old nested snapshot decoder must reject the raw registry proof: %v", err)
	}
	var current writerRecoverySnapshot
	if err := decodeSingleJSON(body, &current); err != nil {
		t.Fatalf("current CLI rejected the nested snapshot: %v", err)
	}
	proof := current.Record.RegistryReplacement
	if proof == nil || proof.Validate() != nil || proof.Image != "registry:3@sha256:"+strings.Repeat("a", 64) || proof.VolumeSHA256 != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("current CLI lost the journaled registry proof: %+v", proof)
	}
	if err := validateWriterRecoveryIdentities(current.Record.ID, current.Record.App, current.Record.Host, current.Record.OwnerKeyFingerprint, current); err != nil {
		t.Fatal(err)
	}
	if current.Writers.Admissions != operationwriters.AdmissionsOpen || len(current.Writers.Writers) != 1 || current.Writers.Writers[0].ID != "ssh-build-runner" {
		t.Fatal("snapshot decoding changed the open writer inventory")
	}
	// Without the new journal field the same old snapshot decoder still works;
	// the compatibility requirement is specific to records carrying the proof.
	current.Record.RegistryReplacement = nil
	withoutProof, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	legacy = legacyWriterRecoverySnapshot{}
	if err := decodeSingleJSON(withoutProof, &legacy); err != nil {
		t.Fatalf("old reader rejected a snapshot without registry proof: %v", err)
	}
	if legacy.Record.ID != current.Record.ID || !reflect.DeepEqual(legacy.Writers, current.Writers) {
		t.Fatal("old reader lost the established snapshot identity or writers")
	}
}
