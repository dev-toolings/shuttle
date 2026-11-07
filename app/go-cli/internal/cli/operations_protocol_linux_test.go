//go:build linux

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestRecoveryApplyTransportAcceptsActualProducerEmptySteps(t *testing.T) {
	plan := coord.RecoveryPlan{Schema: recoveryPlanSchemaName, ID: strings.Repeat("a", 32), State: coord.RecoveryRequired, PlanDigest: "sha256:" + strings.Repeat("b", 64), Actions: []string{"restore route"}}
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "partial_before_first_step"}[partial], func(t *testing.T) {
			var applyErr error
			var remaining []string
			if partial {
				applyErr = errors.New("route write failed")
				remaining = []string{"restore route"}
			}
			body, producerErr := marshalRecoveryApplyReport(plan, nil, remaining, applyErr)
			if !errors.Is(producerErr, applyErr) {
				t.Fatalf("producer error: %v", producerErr)
			}
			var helperOut bytes.Buffer
			helperErr := emitRootHelperResult(&helperOut, "recovery-apply", plan.PlanDigest, true, body, producerErr)
			status := 0
			stderr := ""
			if helperErr != nil {
				status = 1
				stderr = helperErr.Error()
			}
			transportBody, transportErr := remoteOperationsResult("recovery-apply", shuttlessh.Result{Code: status, Stdout: helperOut.String(), Stderr: stderr})
			var stdout bytes.Buffer
			cliErr := presentRemoteRecoveryApply(&stdout, true, plan.ID, plan.PlanDigest, transportBody, transportErr)
			if (cliErr != nil) != partial {
				t.Fatalf("partial=%v returned %v", partial, cliErr)
			}
			var report remoteRecoveryApplyResult
			if err := decodeSingleJSON(stdout.Bytes(), &report); err != nil {
				t.Fatalf("producer JSON lost: %v, output=%q", err, stdout.String())
			}
			if report.ID != plan.ID || report.CompletedSteps == nil || report.RemainingRecovery == nil {
				t.Fatalf("empty step inventory not preserved: %+v", report)
			}
			if partial && (report.Error == "" || len(report.RemainingRecovery) != 1) {
				t.Fatalf("partial failure fields lost: %+v", report)
			}
		})
	}
}

func TestRecoveryApplyRejectsSuccessWithUnfinishedSteps(t *testing.T) {
	id := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	body := strings.Replace(partialRecoveryApplyJSON(id, digest), `"error": "caddy route was not applied",`, "", 1)
	var out bytes.Buffer
	if err := presentRemoteRecoveryApply(&out, true, id, digest, []byte(body), nil); err == nil {
		t.Fatal("unfinished recovery returned success")
	}
	if out.Len() == 0 {
		t.Fatal("unfinished recovery report was hidden")
	}
}
