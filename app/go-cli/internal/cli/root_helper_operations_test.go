//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestRecoveryRootApplyReportIncludesCompletedStepsAndError(t *testing.T) {
	body, err := marshalRecoveryApplyReport(coord.RecoveryPlan{
		Schema:     "shuttle.recovery-plan/v1",
		ID:         testRecoveryOpID,
		State:      coord.RecoveryRequired,
		Actions:    []string{"restore original backup replica counts and verify every application task"},
		PlanDigest: "sha256:" + strings.Repeat("c", 64),
	}, []string{"restore original backup replica counts and verify every application task"}, []string{}, errors.New("sync pending backup marker parent: disk full"))
	if body == nil {
		t.Fatal("apply report body was nil")
	}
	if err == nil {
		t.Fatal("apply report dropped the original error")
	}
	var report recoveryApplyReport
	if decodeErr := json.Unmarshal(body, &report); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(report.CompletedSteps) != 1 || report.Error == "" {
		t.Fatalf("apply report lost failed-step fields: %+v", report)
	}
}

// TestRefusalControlRequiresClosedWriters drives the operation-refuse control
// itself, not requireRootWritersClosed directly: a refusal is a terminal state
// without recovery, so it must enforce the same writer closure as finish, and a
// test of the helper function alone would still pass if the control stopped
// calling it.
func TestRefusalControlRequiresClosedWriters(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldVerifier, oldGuard := rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard
	rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return nil }
	rootCoordinatedMutationGuard = func(string) error { return nil }
	t.Cleanup(func() { rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard = oldVerifier, oldGuard })
	owner := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	ctx := context.Background()
	c := coord.New(coord.Options{Root: dir, LockPath: filepath.Join(dir, "root.lock"), BootID: func() (string, error) { return "boot-a", nil }})
	h, err := c.Reserve(ctx, coord.Request{Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	store := operationwriters.NewStore(dir)
	var binding operationwriters.Binding
	// The reservation carries a completed writers-initialize phase, exactly as
	// reserveRootOperation leaves it, so only the writer closure decides.
	if err := c.ExecutePhase(ctx, coord.PhaseRequest{ID: h.ID(), Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host, Name: "writers-initialize"}, func(_ context.Context, record coord.Record) error {
		binding = operationWriterBinding(record)
		_, err := store.InitializeLocked(binding, operationwriters.Baseline{ConfiguredNativePGVersion: "not-configured", ConfiguredNativePGCluster: "not-configured"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	plan := rootplan.Plan{Action: "operation-refuse", OperationID: h.ID(), OperationKind: "run", OperationApp: "demo", OperatorUser: "deploy", OperatorKeyFingerprint: owner, RequiredHostFingerprint: host, ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339), Control: &rootplan.OperationControl{Result: "refused before any mutation: test"}}
	if _, err := controlRootOperationWith(ctx, c, plan); err == nil {
		t.Fatal("refusal with open writer admissions was accepted")
	}
	record, err := c.Get(ctx, h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "active" || record.RecoveryRequired || len(record.Phases) != 1 {
		t.Fatalf("rejected refusal changed the record: %+v", record)
	}
	if _, err := store.CloseAdmissionsLocked(binding); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitClosureLocked(binding, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := controlRootOperationWith(ctx, c, plan); err != nil {
		t.Fatalf("refusal with closed writers rejected: %v", err)
	}
	record, err = c.Get(ctx, h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "failed" || record.RecoveryRequired {
		t.Fatalf("refusal did not end in failed without recovery: %+v", record)
	}
}
