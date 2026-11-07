package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestRecoveryPlanOutputIncludesConfirmationDigestAndActions(t *testing.T) {
	plan := coord.RecoveryPlan{ID: strings.Repeat("a", 32), State: coord.RecoveryRequired, Observed: coord.RecoveryObservation{ServiceState: "not observed", RegistryState: "not observed", DataState: "not observed"}, Actions: []string{"inspect retained releases"}, PlanDigest: "sha256:" + strings.Repeat("b", 64)}
	var out bytes.Buffer
	if err := writeRecoveryPlan(&out, plan); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{plan.ID, plan.PlanDigest, "inspect retained releases", "not observed"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("recovery plan output is missing %q: %s", want, out.String())
		}
	}
}

func TestRecoveryObserverDoesNotClaimRemoteStateFromAWorkstation(t *testing.T) {
	if observation, err := localRecoveryObserver(context.Background(), coord.Record{ID: strings.Repeat("a", 32), Kind: "deploy", App: "demo"}); err != nil {
		t.Fatal(err)
	} else if observation.Safe && observation.ServiceState == "not observed" {
		t.Fatal("an unverified recovery observation must not be safe")
	}
}

// A helper-update blocker is non-retryable and must name its own recovery path.
func TestReserveRemoteOperationAddsHelperUpdateRecoveryHint(t *testing.T) {
	const blockerID = "12345678-1234-1234-1234-123456789abc"
	fixture, pin := administratorSSHFixture(t, func(_, _ string, _ []byte) shuttlessh.Result {
		return shuttlessh.Result{Code: 1, Stderr: "operation " + blockerID + " requires recovery for helper-update (target VPS, age 1s); waited 0s"}
	})
	client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, fixture.user, fixture.port, pin)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := trustedHostIdentity{HostKeyFingerprint: pin, OperatorKeyFingerprint: fixture.operatorKeyFingerprint}
	_, err = reserveRemoteOperation(client, identity, key, "deploy", "demo")
	want := recoveryHint(blockerID, "helper-update").Error()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("reserve error = %v, want helper-update recovery hint %q", err, want)
	}
}

func TestOperationsCommandIsRegisteredAndRemoteJSONRejectsHelperTrailer(t *testing.T) {
	root := NewRootCommand()
	command, _, err := root.Find([]string{"operations", "status"})
	if err != nil || command == nil || command.Name() != "status" {
		t.Fatalf("operations status is not registered: command=%v err=%v", command, err)
	}
	if err := validateRemoteJSON("{\"records\":[]}\noperation=operations-status digest=sha256:test\n"); err == nil {
		t.Fatal("helper stdout trailer was accepted as a JSON protocol response")
	}
}

func TestRecoverCommandKeepsConfirmationFlags(t *testing.T) {
	cmd := newOperationsRecoverCommand()
	for _, name := range []string{"dry-run", "yes", "plan-digest", "json"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("recovery command lost flag %s", name)
		}
	}
}

func TestPartialRecoveryApplyJSONSurvivesNonzeroExit(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	body := []byte(partialRecoveryApplyJSON(id, digest))
	remoteErr := errors.New("remote recovery-apply failed: caddy route was not applied")
	var out bytes.Buffer
	err := presentRemoteRecoveryApply(&out, true, id, digest, body, remoteErr)
	if err == nil {
		t.Fatal("partial apply must remain an error")
	}
	if err != remoteErr {
		t.Fatalf("CLI replaced the helper error: %v", err)
	}
	var report remoteRecoveryApplyResult
	if decodeErr := json.Unmarshal(out.Bytes(), &report); decodeErr != nil {
		t.Fatalf("stdout was not recovery-apply JSON: %v (%s)", decodeErr, out.String())
	}
	if report.Schema != recoveryApplySchemaName || report.Error == "" || len(report.CompletedSteps) != 1 || len(report.RemainingRecovery) != 1 {
		t.Fatalf("stdout lost partial apply fields: %+v", report)
	}
	if report.CompletedSteps[0] != "restore original backup replica counts and verify every application task" {
		t.Fatalf("completed_steps mismatch: %v", report.CompletedSteps)
	}
	if report.RemainingRecovery[0] != "apply the retained Caddy route and verify the route" {
		t.Fatalf("remaining_recovery mismatch: %v", report.RemainingRecovery)
	}
}

func TestPartialRecoveryApplyHumanOutputKeepsStepsOnError(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	var out bytes.Buffer
	err := presentRemoteRecoveryApply(&out, false, id, digest, []byte(partialRecoveryApplyJSON(id, digest)), errors.New("remote recovery-apply failed: disk full"))
	if err == nil {
		t.Fatal("partial apply must remain an error")
	}
	for _, want := range []string{id, digest, "completed:", "remaining:", "error:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("human recovery output is missing %q: %s", want, out.String())
		}
	}
}

func TestRemoteOperationsResultKeepsRecoveryApplyStdoutOnFailure(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	body := partialRecoveryApplyJSON(id, digest)
	got, err := remoteOperationsResult("recovery-apply", shuttlessh.Result{Code: 1, Stdout: body, Stderr: "caddy route was not applied"})
	if err == nil || string(got) != body {
		t.Fatalf("recovery-apply stdout was discarded on nonzero: body=%q err=%v", got, err)
	}
	got, err = remoteOperationsResult("recovery-apply", shuttlessh.Result{Code: 1, Stdout: "not-json", Stderr: "boom"})
	if err == nil || got != nil {
		t.Fatalf("garbage recovery-apply stdout was accepted: body=%q err=%v", got, err)
	}
	got, err = remoteOperationsResult("recovery-plan", shuttlessh.Result{Code: 1, Stdout: body, Stderr: "boom"})
	if err == nil || got != nil {
		t.Fatalf("recovery-plan still has to discard stdout on failure: body=%q err=%v", got, err)
	}
}

func TestRootHelperEmitsProtocolJSONWhenActionFails(t *testing.T) {
	body := []byte(partialRecoveryApplyJSON(strings.Repeat("a", 32), "sha256:"+strings.Repeat("b", 64)))
	var out bytes.Buffer
	err := emitRootHelperResult(&out, "recovery-apply", "sha256:test", true, body, errors.New("caddy route was not applied"))
	if err == nil || err.Error() != "caddy route was not applied" {
		t.Fatalf("apply error lost: %v", err)
	}
	if !bytes.Equal(out.Bytes(), body) {
		t.Fatalf("helper dropped protocol JSON: %q", out.String())
	}
}

func TestRootHelperJSONSuccessOmitsPlainOperationLine(t *testing.T) {
	var out bytes.Buffer
	if err := emitRootHelperResult(&out, "recovery-apply", "sha256:test", true, []byte("{}\n"), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "operation=") {
		t.Fatalf("json protocol wrote a plaintext trailer: %s", out.String())
	}
}

func TestDecodeRemoteRecoveryApplyRejectsMalformedAndMismatchedEnvelopes(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	if _, err := decodeRemoteRecoveryApply([]byte(`{"ok":true}`), id, digest); err == nil {
		t.Fatal("arbitrary JSON was accepted as a recovery apply result")
	}
	if _, err := decodeRemoteRecoveryApply([]byte(`{"schema":"shuttle.other/v1","id":"`+id+`","plan_digest":"`+digest+`"}`), id, digest); err == nil {
		t.Fatal("unknown schema was accepted")
	}
	missingSteps := `{"schema":"shuttle.recovery-apply/v1","id":"` + id + `","state":"recovery_required","observed":{},"actions":[],"plan_digest":"` + digest + `","remaining_recovery":[]}`
	if _, err := decodeRemoteRecoveryApply([]byte(missingSteps), id, digest); err == nil {
		t.Fatal("apply envelope missing completed_steps was accepted")
	}
	notArray := `{"schema":"shuttle.recovery-apply/v1","id":"` + id + `","state":"recovery_required","observed":{},"actions":[],"plan_digest":"` + digest + `","completed_steps":"nope","remaining_recovery":[]}`
	if _, err := decodeRemoteRecoveryApply([]byte(notArray), id, digest); err == nil {
		t.Fatal("non-array completed_steps was accepted")
	}
	if _, err := decodeRemoteRecoveryApply([]byte(partialRecoveryApplyJSON(strings.Repeat("c", 32), digest)), id, digest); err == nil {
		t.Fatal("mismatched operation id was accepted")
	}
	if _, err := decodeRemoteRecoveryApply([]byte(partialRecoveryApplyJSON(id, "sha256:"+strings.Repeat("d", 64))), id, digest); err == nil {
		t.Fatal("mismatched plan digest was accepted")
	}
	extra := strings.TrimSuffix(partialRecoveryApplyJSON(id, digest), "\n")
	extra = strings.TrimSuffix(extra, "}") + `,"unexpected":true}`
	if _, err := decodeRemoteRecoveryApply([]byte(extra+"\n"), id, digest); err == nil {
		t.Fatal("unknown apply field was accepted")
	}
}

func TestDryRunRecoveryStillDecodesAsRecoveryPlan(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	var plan coord.RecoveryPlan
	if err := decodeSingleJSON([]byte(partialRecoveryApplyJSON(id, digest)), &plan); err == nil {
		t.Fatal("dry-run RecoveryPlan decoder accepted recovery-apply extra fields")
	}
	if err := decodeSingleJSON([]byte(legacyRecoveryPlanJSON(id, digest)), &plan); err != nil {
		t.Fatalf("dry-run RecoveryPlan decoder rejected the old plan shape: %v", err)
	}
	if plan.ID != id || plan.PlanDigest != digest || plan.Schema != recoveryPlanSchemaName {
		t.Fatalf("dry-run plan decode lost identity: %+v", plan)
	}
}

func TestLegacyRecoveryPlanShapeStillPresentsAsSuccess(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	var out bytes.Buffer
	if err := presentRemoteRecoveryApply(&out, true, id, digest, []byte(legacyRecoveryPlanJSON(id, digest)), nil); err != nil {
		t.Fatalf("old recovery-plan/v1 apply result was refused: %v", err)
	}
	var plan coord.RecoveryPlan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Schema != recoveryPlanSchemaName || strings.Contains(out.String(), "completed_steps") {
		t.Fatalf("old apply JSON shape changed: %s", out.String())
	}
}

func partialRecoveryApplyJSON(id, digest string) string {
	return `{
  "schema": "shuttle.recovery-apply/v1",
  "id": "` + id + `",
  "state": "recovery_required",
  "observed": {"safe": false, "executor_count": 0, "service_state": "not observed", "registry_state": "not observed", "data_state": "not observed"},
  "actions": ["restore original backup replica counts and verify every application task", "apply the retained Caddy route and verify the route"],
  "plan_digest": "` + digest + `",
  "completed_steps": ["restore original backup replica counts and verify every application task"],
  "error": "caddy route was not applied",
  "remaining_recovery": ["apply the retained Caddy route and verify the route"]
}
`
}

func legacyRecoveryPlanJSON(id, digest string) string {
	return `{
  "schema": "shuttle.recovery-plan/v1",
  "id": "` + id + `",
  "state": "recovery_required",
  "observed": {"safe": false, "executor_count": 0, "service_state": "not observed", "registry_state": "not observed", "data_state": "not observed"},
  "actions": ["inspect retained releases"],
  "plan_digest": "` + digest + `"
}
`
}

func TestRecoveryApplyRejectsIncompleteKnownEnvelope(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	for _, key := range []string{"state", "observed", "actions"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(partialRecoveryApplyJSON(id, digest)), &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, key)
		body, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRemoteRecoveryApply(body, id, digest); err == nil {
			t.Fatalf("missing %s accepted", key)
		}
	}
}

func TestRootHelperNonJSONFailurePreservesOldOutputContract(t *testing.T) {
	var out bytes.Buffer
	sentinel := errors.New("action failed")
	if err := emitRootHelperResult(&out, "run", "sha256:test", false, []byte("partial payload"), sentinel); err != sentinel {
		t.Fatalf("original error lost: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("non-JSON error unexpectedly emitted protocol bytes: %q", out.String())
	}
}

func TestDeployOnlyRecoversItsOwnApplicationsAbortedDeploy(t *testing.T) {
	blocked := errors.New("reserve coordinated operation failed: reserve coordinated operation: operation 17445cfd-fd55-ffee-a9ad-37b0c99d2bf6 requires recovery for deploy (target ohb-console, age 8m47s); waited 0s")
	if id, ok := noopDeployRecoveryCandidate(blocked, "deploy", "ohb-console"); !ok || id != "17445cfd-fd55-ffee-a9ad-37b0c99d2bf6" {
		t.Fatalf("same-application aborted deploy was not a candidate: %q %v", id, ok)
	}
	for name, tc := range map[string]struct {
		err       error
		kind, app string
	}{
		"other application": {blocked, "deploy", "other"},
		"not a deploy":      {blocked, "rollback", "ohb-console"},
		"helper update":     {errors.New("operation 17445cfd-fd55-ffee-a9ad-37b0c99d2bf6 requires recovery for helper-update (target VPS, age 1s); waited 0s"), "deploy", "VPS"},
		"live operation":    {errors.New("operation 17445cfd-fd55-ffee-a9ad-37b0c99d2bf6 is active for deploy (target ohb-console, age 1s); waited 0s"), "deploy", "ohb-console"},
	} {
		if _, ok := noopDeployRecoveryCandidate(tc.err, tc.kind, tc.app); ok {
			t.Fatalf("%s: must stay an operator recovery", name)
		}
	}
}

func TestAutomaticRecoveryAcceptsOnlyAPlanWithNothingToDo(t *testing.T) {
	id := "17445cfd-fd55-ffee-a9ad-37b0c99d2bf6"
	noop := coord.RecoveryPlan{ID: id, State: coord.RecoveryRequired, PlanDigest: "sha256:" + strings.Repeat("b", 64), Observed: coord.RecoveryObservation{Safe: true, ServiceState: "configured application tasks match retained current digests and container health"}, Actions: []string{"observe actual service state", "verify registry health and retained releases", "confirm all writers stopped"}}
	if err := noopRecoveryPlan(noop, id); err != nil {
		t.Fatalf("bookkeeping-only plan was refused: %v", err)
	}
	unsafe := noop
	unsafe.Observed = coord.RecoveryObservation{Safe: false, MissingProof: []string{"freshness_window"}}
	acting := noop
	acting.Observed.Actions = []string{"restore previous release digests"}
	terminal := noop
	terminal.State = "recovered"
	for name, plan := range map[string]coord.RecoveryPlan{"unsafe": unsafe, "acting": acting, "terminal": terminal} {
		if err := noopRecoveryPlan(plan, id); err == nil {
			t.Fatalf("%s plan must be left to the operator", name)
		}
	}
	if err := noopRecoveryPlan(noop, strings.Repeat("a", 32)); err == nil {
		t.Fatal("a plan for another operation must be refused")
	}
}
