package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestRemoteOperationFinalizesAfterWriterCleanupAndKeepsFailure(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "cleanup-failure"}[cleanupFails], func(t *testing.T) {
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			var mu sync.Mutex
			var actions []string
			cleanupComplete := false
			writerRoot := t.TempDir()
			if err := os.Chmod(writerRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			store := operationwriters.NewStore(writerRoot)
			var binding operationwriters.Binding

			fixture, pin := administratorSSHFixture(t, func(user, command string, input []byte) shuttlessh.Result {
				p, _, err := decodeRootHelperEnvelope(bytes.NewReader(input))
				if err != nil {
					return shuttlessh.Result{Code: 1, Stderr: err.Error()}
				}
				if err := rootplan.Verify(p, pub, time.Now()); err != nil {
					return shuttlessh.Result{Code: 1, Stderr: err.Error()}
				}
				mu.Lock()
				defer mu.Unlock()
				label := p.Action
				if p.Control != nil && p.Control.Phase != "" {
					label += ":" + p.Control.Phase
				}
				actions = append(actions, label)
				if p.Action == "operation-reserve" {
					binding = operationwriters.Binding{OperationID: p.OperationID, Generation: 1, HostKey: p.RequiredHostFingerprint, BootID: "01234567-1234-1234-1234-123456789abc"}
					_, err := store.InitializeLocked(binding, operationwriters.Baseline{ConfiguredNativePGVersion: "not-configured", ConfiguredNativePGCluster: "not-configured"})
					if err != nil {
						return shuttlessh.Result{Code: 1, Stderr: err.Error()}
					}
					return shuttlessh.Result{Code: 0}
				}
				if !cleanupComplete {
					return shuttlessh.Result{Code: 1, Stderr: "writer still running"}
				}
				if p.Action == "operation-writers-close" || p.Action == "operation-writers-commit" {
					var state operationwriters.State
					var err error
					if p.Action == "operation-writers-close" {
						state, err = store.CloseAdmissionsLocked(binding)
					} else {
						state, err = store.CommitClosureLocked(binding, p.Writers.Receipts)
					}
					if err != nil {
						return shuttlessh.Result{Code: 1, Stderr: err.Error()}
					}
					body, _ := json.Marshal(state)
					return shuttlessh.Result{Stdout: string(body)}
				}
				state := "completed"
				if p.Action == "operation-renew" {
					state = "active"
				}
				if p.Action == "operation-abort" {
					state = coord.RecoveryRequired
				}
				body, _ := json.Marshal(coord.Record{ID: p.OperationID, Kind: p.OperationKind, App: p.OperationApp, State: state})
				return shuttlessh.Result{Stdout: string(body)}
			})
			client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, "deploy", fixture.port, pin)
			if err != nil {
				t.Fatal(err)
			}
			identity := trustedHostIdentity{OperatorKeyFingerprint: fixture.operatorKeyFingerprint, HostKeyFingerprint: pin}
			run := func() (result error) {
				op, err := beginRemoteOperation(client, identity, key, "deploy", "demo")
				if err != nil {
					return err
				}
				defer op.finish(&result)
				defer func() {
					mu.Lock()
					cleanupComplete = true
					mu.Unlock()
					if cleanupFails {
						mergeOperationCleanupError(&result, op, errors.New("cleanup failed"))
					}
				}()
				return nil
			}
			err = run()
			if (err != nil) != cleanupFails {
				t.Fatalf("cleanup error lost: %v", err)
			}
			if cleanupFails && (err == nil || !strings.Contains(err.Error(), "promotion=") || !strings.Contains(err.Error(), "cleanup=failed")) {
				t.Fatalf("cleanup failure hid the distinct promotion result: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			want := "operation-finish"
			if cleanupFails {
				want = "operation-abort"
			}
			if len(actions) != 6 || actions[0] != "operation-reserve" || actions[1] != "operation-writers-close" || actions[2] != "operation-writers-commit" || actions[3] != "operation-renew:client-promotion" || actions[4] != "operation-renew:client-cleanup" || actions[5] != want {
				t.Fatalf("wrong durable lifecycle: %v", actions)
			}
		})
	}
}

func TestFinishStopsControlsAfterRecoveryProgressAndStillClosesWriters(t *testing.T) {
	oldClose, oldProgress, oldControl := remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl
	t.Cleanup(func() {
		remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl = oldClose, oldProgress, oldControl
	})
	closed, progressCalls, controlCalls := 0, 0, 0
	remoteOperationCloseWriters = func(*remoteOperation) error { closed++; return nil }
	remoteOperationProgress = func(*remoteOperation, string, string) error {
		progressCalls++
		return recoveryHint("operation-id", "deploy")
	}
	remoteOperationControl = func(*remoteOperation, string, string) error { controlCalls++; return nil }
	op := &remoteOperation{kind: "deploy", id: "operation-id", promotionAttempted: true}
	original := errors.New("swarm promotion failed")
	result := original
	op.finish(&result)
	if closed != 1 || progressCalls != 1 || controlCalls != 0 {
		t.Fatalf("writer close=%d progress=%d controls=%d", closed, progressCalls, controlCalls)
	}
	if !errors.Is(result, original) || strings.Count(result.Error(), recoveryHint("operation-id", "deploy").Error()) != 1 {
		t.Fatalf("finish result did not preserve one recovery hint and original: %v", result)
	}
}

func TestFinishRecoveryErrorFromRefuseSkipsAbortForDeployAndRun(t *testing.T) {
	oldClose, oldProgress, oldControl := remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl
	t.Cleanup(func() {
		remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl = oldClose, oldProgress, oldControl
	})
	remoteOperationCloseWriters = func(*remoteOperation) error { return nil }
	remoteOperationProgress = func(*remoteOperation, string, string) error { return nil }
	for _, kind := range []string{"deploy", "run"} {
		t.Run(kind, func(t *testing.T) {
			var actions []string
			remoteOperationControl = func(_ *remoteOperation, action, _ string) error {
				actions = append(actions, action)
				return recoveryHint("operation-id", kind)
			}
			op := &remoteOperation{kind: kind, id: "operation-id", refusedBeforeMutation: true, promotionAttempted: kind == "deploy"}
			result := errors.New("operation failed before mutation")
			op.finish(&result)
			if !reflect.DeepEqual(actions, []string{"operation-refuse"}) || strings.Count(result.Error(), recoveryHint("operation-id", kind).Error()) != 1 {
				t.Fatalf("actions=%v result=%v", actions, result)
			}
		})
	}
}

func TestKeepAliveRecoveryClassificationStopsWritersBeforeProbeAndDeduplicatesFinish(t *testing.T) {
	oldInterval, oldClose, oldProgress, oldControl := operationKeepAliveInterval, remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl
	t.Cleanup(func() {
		operationKeepAliveInterval = oldInterval
		remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl = oldClose, oldProgress, oldControl
	})
	operationKeepAliveInterval = 10 * time.Millisecond
	var stopped atomic.Bool
	finishCloseCount := 0
	renewStarted := make(chan struct{}, 1)
	const operationID = "12345678-1234-1234-1234-123456789abc"
	fixture, pin := administratorSSHFixture(t, func(_, _ string, input []byte) shuttlessh.Result {
		plan, _, err := decodeRootHelperEnvelope(bytes.NewReader(input))
		if err != nil {
			return shuttlessh.Result{Code: 1, Stderr: err.Error()}
		}
		if plan.Action == "operation-renew" {
			select {
			case renewStarted <- struct{}{}:
			default:
			}
			return shuttlessh.Result{Code: 1, Stderr: "warning from helper\noperation is not active for this phase"}
		}
		if plan.Action != "operations-status" || !stopped.Load() {
			return shuttlessh.Result{Code: 1, Stderr: "status read preceded writer stop"}
		}
		body, _ := json.Marshal([]coord.Record{{ID: operationID, Kind: "deploy", State: coord.RecoveryRequired, RecoveryRequired: true}})
		return shuttlessh.Result{Stdout: string(body)}
	})
	client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, fixture.user, fixture.port, pin)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	op := &remoteOperation{id: operationID, kind: "deploy", client: client, key: key, identity: trustedHostIdentity{HostKeyFingerprint: pin, OperatorKeyFingerprint: fixture.operatorKeyFingerprint}}
	remoteOperationCloseWriters = func(*remoteOperation) error { finishCloseCount++; return nil }
	remoteOperationProgress = func(*remoteOperation, string, string) error {
		t.Fatal("finish sent progress after keepalive recovery")
		return nil
	}
	remoteOperationControl = func(*remoteOperation, string, string) error {
		t.Fatal("finish sent control after keepalive recovery")
		return nil
	}
	stop := op.keepAlive(func() error { stopped.Store(true); return errors.New("writer close failed") })
	select {
	case <-renewStarted:
	case <-time.After(time.Second):
		t.Fatal("keepalive did not send a renewal")
	}
	first := stop()
	var hint *operationRequiresRecoveryError
	if !errors.As(first, &hint) || !strings.Contains(first.Error(), "writer close failed") {
		t.Fatalf("keepalive result lost recovery or writer error: %v", first)
	}
	second := stop()
	if first == nil || second == nil || !errors.Is(first, second) && first.Error() != second.Error() {
		t.Fatalf("repeated stop returned inconsistent failures: %v / %v", first, second)
	}
	deployErr := error(errors.New("swarm failed"))
	mergeOperationCleanupError(&deployErr, op, first)
	mergeOperationCleanupError(&deployErr, op, second)
	op.finish(&deployErr)
	if strings.Count(deployErr.Error(), recoveryHint(op.id, "deploy").Error()) != 1 {
		t.Fatalf("recovery line duplicated or missing: %v", deployErr)
	}
	if !strings.Contains(deployErr.Error(), "promotion=") || !strings.Contains(deployErr.Error(), "cleanup=failed:") {
		t.Fatalf("deploy cleanup wrapper changed: %v", deployErr)
	}
	if finishCloseCount != 1 {
		t.Fatalf("remoteOperationCloseWriters ran %d times", finishCloseCount)
	}
	var nilErr error
	mergeOperationCleanupError(&nilErr, op, nil)
	if nilErr != nil {
		t.Fatalf("nil cleanup created an error: %v", nilErr)
	}
	cleanupOnly := errors.New("cleanup only")
	mergeOperationCleanupError(&nilErr, op, cleanupOnly)
	if nilErr != cleanupOnly || strings.Contains(nilErr.Error(), "%!w(<nil>)") {
		t.Fatalf("nil operation error was wrapped incorrectly: %v", nilErr)
	}
}

func TestRemoteOperationRefusalControlsAndFallback(t *testing.T) {
	for _, mode := range []string{"refuse", "close-fails", "refuse-fails"} {
		t.Run(mode, func(t *testing.T) {
			var actions []string
			closeCount := 0
			oldClose, oldControl := remoteOperationCloseWriters, remoteOperationControl
			remoteOperationCloseWriters = func(*remoteOperation) error {
				closeCount++
				if mode == "close-fails" {
					return errors.New("writer close failed")
				}
				return nil
			}
			remoteOperationControl = func(_ *remoteOperation, action, _ string) error {
				actions = append(actions, action)
				if action == "operation-refuse" && mode == "refuse-fails" {
					return errors.New("coordinator rejected refusal")
				}
				return nil
			}
			t.Cleanup(func() { remoteOperationCloseWriters, remoteOperationControl = oldClose, oldControl })
			op := &remoteOperation{kind: "run", refusedBeforeMutation: true, refusalReason: "dump failed"}
			operationErr := errors.New("helper refused before mutation")
			op.finish(&operationErr)
			want := []string{"operation-refuse"}
			if mode == "close-fails" || mode == "refuse-fails" {
				want = []string{"operation-abort"}
				if mode == "refuse-fails" {
					want = []string{"operation-refuse", "operation-abort"}
				}
			}
			if !reflect.DeepEqual(actions, want) {
				t.Fatalf("wrong refusal control sequence: got %v want %v", actions, want)
			}
			if closeCount != 1 {
				t.Fatalf("writer closure was attempted %d times", closeCount)
			}
		})
	}
}

func TestDeployRefusalControlRequiresClosedWritersAndNoSecretPhase(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		promotionAttempted    bool
		refused               bool
		refusalReason         string
		secretsPhaseAttempted bool
		cleanupFailed         bool
		writerCloseFails      bool
		refuseFails           bool
		wantRefusalResult     string
		wantFinal             string
	}{
		{name: "build error before promotion", wantRefusalResult: "refused before any mutation: client failed before promotion", wantFinal: "operation-refuse"},
		{name: "helper refusal", promotionAttempted: true, refused: true, refusalReason: "no retained image to update from", wantRefusalResult: "refused before any mutation: no retained image to update from", wantFinal: "operation-refuse"},
		{name: "secret phase already journaled", promotionAttempted: true, refused: true, refusalReason: "stack rejected", secretsPhaseAttempted: true, wantFinal: "operation-abort"},
		{name: "builder cleanup failed", cleanupFailed: true, wantFinal: "operation-abort"},
		{name: "promotion error without helper marker", promotionAttempted: true, wantFinal: "operation-abort"},
		{name: "refuse failure falls back to abort", refused: true, refusalReason: "bounded reason", refuseFails: true, wantRefusalResult: "refused before any mutation: bounded reason", wantFinal: "operation-abort"},
		{name: "writers remain open", writerCloseFails: true, wantFinal: "operation-abort"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var renews []string
			var sequence []string
			op := &remoteOperation{id: "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b10", kind: "deploy", app: "demo", promotionAttempted: tc.promotionAttempted, secretsPhaseAttempted: tc.secretsPhaseAttempted, cleanupFailed: tc.cleanupFailed}
			oldProgress := remoteOperationProgress
			remoteOperationProgress = func(_ *remoteOperation, phase, result string) error {
				renews = append(renews, phase+":"+result)
				sequence = append(sequence, "operation-renew:"+phase)
				return nil
			}
			if tc.refused {
				refusalErr := stackPromotionError(rootPreflightRefusalMarker + tc.refusalReason)
				recordStackPromotionRefusal(op, refusalErr)
			}
			var controls []string
			var refusalResult string
			oldClose, oldControl := remoteOperationCloseWriters, remoteOperationControl
			remoteOperationCloseWriters = func(*remoteOperation) error {
				if tc.writerCloseFails {
					return errors.New("writer closure failed")
				}
				return nil
			}
			remoteOperationControl = func(_ *remoteOperation, action, result string) error {
				controls = append(controls, action)
				sequence = append(sequence, action)
				if action == "operation-refuse" {
					refusalResult = result
					if tc.refuseFails {
						return errors.New("coordinator rejected refusal")
					}
				}
				return nil
			}
			t.Cleanup(func() {
				remoteOperationCloseWriters, remoteOperationControl, remoteOperationProgress = oldClose, oldControl, oldProgress
			})
			operationErr := error(errors.New("build failed: Docker Hub 429"))
			op.finish(&operationErr)
			cleanupResult := "completed"
			if tc.cleanupFailed || tc.writerCloseFails {
				cleanupResult = "failed"
			}
			promotionResult := "not-started"
			if tc.promotionAttempted && !tc.refused {
				promotionResult = "attempted-unverified"
			}
			if !reflect.DeepEqual(renews, []string{"client-promotion:" + promotionResult, "client-cleanup:" + cleanupResult}) {
				t.Fatalf("deploy progress renews differ: %v", renews)
			}
			wantControls := []string{tc.wantFinal}
			if tc.wantRefusalResult != "" && tc.refuseFails {
				wantControls = []string{"operation-refuse", "operation-abort"}
			}
			if !reflect.DeepEqual(controls, wantControls) {
				t.Fatalf("deploy final controls=%v want %v", controls, wantControls)
			}
			wantSequence := []string{"operation-renew:client-promotion", "operation-renew:client-cleanup"}
			wantSequence = append(wantSequence, wantControls...)
			if !reflect.DeepEqual(sequence, wantSequence) {
				t.Fatalf("deploy control order=%v want %v", sequence, wantSequence)
			}
			if tc.wantRefusalResult != "" && refusalResult != tc.wantRefusalResult {
				t.Fatalf("refusal result=%q want %q", refusalResult, tc.wantRefusalResult)
			}
			if refusalResult != "" && (len(refusalResult) > 512 || strings.ContainsAny(refusalResult, "\r\n\x00")) {
				t.Fatalf("refusal result is not a bounded single line: len=%d result=%q", len(refusalResult), refusalResult)
			}
			if tc.name == "build error before promotion" && strings.Contains(refusalResult, "Docker Hub") {
				t.Fatalf("local build error leaked into the refusal journal result: %q", refusalResult)
			}
			if operationErr == nil || !strings.Contains(operationErr.Error(), "build failed") {
				t.Fatalf("original deploy error was lost: %v", operationErr)
			}
		})
	}
}

func TestSuccessfulDeployControlRecordRemainsUnchanged(t *testing.T) {
	var sequence []string
	oldClose, oldProgress, oldControl := remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl
	remoteOperationCloseWriters = func(*remoteOperation) error { return nil }
	remoteOperationProgress = func(_ *remoteOperation, phase, result string) error {
		sequence = append(sequence, "renew:"+phase+"="+result)
		return nil
	}
	remoteOperationControl = func(_ *remoteOperation, action, result string) error {
		sequence = append(sequence, action+"="+result)
		return nil
	}
	t.Cleanup(func() {
		remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl = oldClose, oldProgress, oldControl
	})
	op := &remoteOperation{kind: "deploy", promotion: "applied-unverified", promotionAttempted: true}
	var operationErr error
	op.finish(&operationErr)
	want := []string{
		"renew:client-promotion=applied-unverified",
		"renew:client-cleanup=completed",
		"operation-finish=all requested changes verified; client and remote writer cleanup completed",
	}
	if operationErr != nil || !reflect.DeepEqual(sequence, want) {
		t.Fatalf("successful deploy control record changed: err=%v sequence=%v", operationErr, sequence)
	}
}

func TestRemoteOperationKnownOutcomeRefusesOnlyAfterWriterClosure(t *testing.T) {
	for _, mode := range []string{"closed", "close-fails", "refuse-fails"} {
		t.Run(mode, func(t *testing.T) {
			var actions, results []string
			oldClose, oldControl := remoteOperationCloseWriters, remoteOperationControl
			remoteOperationCloseWriters = func(*remoteOperation) error {
				if mode == "close-fails" {
					return errors.New("writer close failed")
				}
				return nil
			}
			remoteOperationControl = func(_ *remoteOperation, action, result string) error {
				actions = append(actions, action)
				results = append(results, result)
				if action == "operation-refuse" && mode == "refuse-fails" {
					return errors.New("coordinator rejected refusal")
				}
				return nil
			}
			t.Cleanup(func() { remoteOperationCloseWriters, remoteOperationControl = oldClose, oldControl })
			reason, ok := knownRunOutcomeReason(rootKnownOutcomeMarker + "exit status 3")
			if !ok {
				t.Fatal("known outcome marker was not recognized")
			}
			op := &remoteOperation{kind: "run", knownOutcome: true, knownOutcomeReason: reason}
			operationErr := errors.New("operation fail failed: exit status 3")
			op.finish(&operationErr)
			want := []string{"operation-refuse"}
			if mode == "close-fails" {
				want = []string{"operation-abort"}
			} else if mode == "refuse-fails" {
				want = []string{"operation-refuse", "operation-abort"}
			}
			if !reflect.DeepEqual(actions, want) {
				t.Fatalf("wrong known-outcome control sequence: got %v want %v", actions, want)
			}
			if mode != "close-fails" && (len(results) == 0 || results[0] != rootKnownOutcomeControlPrefix+"exit status 3") {
				t.Fatalf("known refusal result was not sent: %v", results)
			}
			if mode == "closed" && strings.Contains(operationErr.Error(), "operation-abort failed") {
				t.Fatalf("successful refusal emitted a misleading abort error: %v", operationErr)
			}
		})
	}
}

func TestRemoteJSONRejectsMultipleDocuments(t *testing.T) {
	var record coord.Record
	if err := decodeSingleJSON([]byte(`{"id":"`+strings.Repeat("a", 32)+`"}{}`), &record); err == nil {
		t.Fatal("multiple control responses accepted")
	}
}

// A successful abort is the CLI moving the record to recovery_required itself,
// so the failure must end with exactly one line naming the recovery.
func TestSuccessfulAbortAppendsOneRecoveryHint(t *testing.T) {
	oldClose, oldProgress, oldControl := remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl
	remoteOperationCloseWriters = func(*remoteOperation) error { return nil }
	remoteOperationProgress = func(*remoteOperation, string, string) error { return nil }
	var actions []string
	remoteOperationControl = func(_ *remoteOperation, action, _ string) error {
		actions = append(actions, action)
		return nil
	}
	t.Cleanup(func() {
		remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl = oldClose, oldProgress, oldControl
	})
	op := &remoteOperation{id: "op-1", kind: "deploy", promotion: "applied-unverified", promotionAttempted: true}
	operationErr := errors.New("availability probe transport failed")
	op.finish(&operationErr)
	if !reflect.DeepEqual(actions, []string{"operation-abort"}) {
		t.Fatalf("controls = %v, want one operation-abort", actions)
	}
	if !strings.Contains(operationErr.Error(), "availability probe transport failed") {
		t.Fatalf("original error lost: %v", operationErr)
	}
	if got := strings.Count(operationErr.Error(), "operation op-1 requires recovery"); got != 1 {
		t.Fatalf("recovery lines = %d in %q, want 1", got, operationErr.Error())
	}
}

// The pre-promotion renewal is classified: when it finds the record already
// recovery_required, deploy ends with exactly one recovery line and finish
// sends no further control.
func TestRenewBeforePromotionRecoveryEndsWithOneHint(t *testing.T) {
	oldClose, oldProgress, oldControl := remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl
	remoteOperationCloseWriters = func(*remoteOperation) error { return nil }
	var controls []string
	remoteOperationProgress = func(_ *remoteOperation, phase, _ string) error {
		controls = append(controls, "renew:"+phase)
		return nil
	}
	remoteOperationControl = func(o *remoteOperation, action, _ string) error {
		controls = append(controls, action)
		if action == "operation-renew" {
			return recoveryHint(o.id, o.kind)
		}
		return nil
	}
	t.Cleanup(func() {
		remoteOperationCloseWriters, remoteOperationProgress, remoteOperationControl = oldClose, oldProgress, oldControl
	})
	op := &remoteOperation{id: "op-2", kind: "deploy"}
	operationErr := op.renewBeforePromotion()
	op.finish(&operationErr)
	if !reflect.DeepEqual(controls, []string{"operation-renew"}) {
		t.Fatalf("controls = %v, want only the pre-promotion renew", controls)
	}
	if got := strings.Count(operationErr.Error(), "operation op-2 requires recovery"); got != 1 {
		t.Fatalf("recovery lines = %d in %q, want 1", got, operationErr.Error())
	}
}
