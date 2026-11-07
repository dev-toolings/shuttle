package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// captureStderr collects what output.Attn writes, which is where every budget
// warning goes.
func captureStderr(t *testing.T, run func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = writer
	done := make(chan string, 1)
	go func() {
		body, _ := io.ReadAll(reader)
		done <- string(body)
	}()
	run()
	os.Stderr = original
	_ = writer.Close()
	body := <-done
	_ = reader.Close()
	return body
}

// captureStdout collects what output.Detail writes. It is a sibling of
// captureStderr rather than a parameter of it because the two streams carry
// different verdicts: an accepted answer is progress and goes to stdout, a drift
// worth an operator's attention is a warning and goes to stderr. A test that
// captured only one would silently miss the other.
func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	done := make(chan string, 1)
	go func() {
		body, _ := io.ReadAll(reader)
		done <- string(body)
	}()
	run()
	os.Stdout = original
	_ = writer.Close()
	body := <-done
	_ = reader.Close()
	return body
}

// A promoted, healthy, serving release must not be reported as a failed command
// because a stopwatch ran out. Shuttle used to return "promotion SLO missed" and
// "total deploy SLO missed" as errors here, so a buyer whose Symfony deploy took
// 40 s saw `shuttle deploy` exit non-zero on an application that was up. The
// budget is an objective: it is measured and reported, never enforced.
func TestOverBudgetHealthyDeploySucceedsWithAWarning(t *testing.T) {
	deploy := config.Deploy{PromotionSLOSeconds: 30, TotalSLOSeconds: 30}
	var err error
	body := captureStderr(t, func() {
		err = finishSwarmDeploy(deploy, 62*time.Second, 91*time.Second,
			deployStageDurations{Promotion: 62 * time.Second}, nil)
	})
	if err != nil {
		t.Fatalf("an over-budget but healthy deploy must succeed, got %v", err)
	}
	if !strings.Contains(body, "Promotion SLO missed") {
		t.Errorf("the promotion overrun must be warned about, got:\n%s", body)
	}
	if !strings.Contains(body, "Total deploy SLO missed") {
		t.Errorf("the total overrun must be warned about, got:\n%s", body)
	}
}

func TestTotalSLOMissNamesDominantBuildCauseWithoutBudgetAdvice(t *testing.T) {
	deploy := config.Deploy{TotalSLOSeconds: 400}
	build := buildProgressReport{
		Service:  "web",
		Duration: 6*time.Minute + 7*time.Second,
		Summary: buildProgressSummary{
			Steps:        16,
			Executed:     16,
			SlowestLabel: "[full 2/4] RUN playwright install chromium",
			Slowest:      3*time.Minute + 12*time.Second,
			RebuiltStage: "full",
		},
	}
	body := captureStderr(t, func() {
		reportDeploySLO(
			measureDeploySLO(deploy, 50*time.Second, 7*time.Minute+57*time.Second),
			deploySLOReportContext{
				Stages: deployStageDurations{Build: 6*time.Minute + 7*time.Second, Push: 40 * time.Second, Promotion: 50 * time.Second, Total: 7*time.Minute + 57*time.Second},
				Builds: []buildProgressReport{build},
			},
		)
	})
	for _, want := range []string{
		"Total deploy SLO missed: 7m57s > 6m40s",
		"build took 6m7s",
		"stage full rebuilt from its base: base image changed or build cache was cold (full rebuild)",
		"slowest step [full 2/4] RUN playwright install chromium 3m12s",
		"deploy.total_slo_seconds is the budget",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("SLO warning is missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(strings.ToLower(body), "raise") {
		t.Errorf("SLO warning must not tell the operator to raise a budget:\n%s", body)
	}
}

// The ordering bug: the promotion budget was checked and returned before the
// total budget was ever compared, so an over-budget promotion suppressed the
// total line entirely. Both budgets are now always measured and always reported.
func TestBothBudgetsAreReportedEvenWhenThePromotionOverruns(t *testing.T) {
	outcomes := measureDeploySLO(config.Deploy{PromotionSLOSeconds: 30, TotalSLOSeconds: 45}, 62*time.Second, 20*time.Second)
	if len(outcomes) != 2 {
		t.Fatalf("both budgets must be measured, got %d outcomes", len(outcomes))
	}
	if !outcomes[0].Missed || outcomes[0].Label != "Promotion SLO" {
		t.Errorf("the promotion overrun must be reported first, got %+v", outcomes[0])
	}
	if outcomes[1].Missed || outcomes[1].Label != "Total deploy SLO" {
		t.Errorf("a total within budget must still be reported as met, got %+v", outcomes[1])
	}
}

func TestFirstReleaseDoesNotEvaluateTotalDeploySLO(t *testing.T) {
	got := measureDeploySLO(config.Deploy{PromotionSLOSeconds: 30, TotalSLOSeconds: 30}, 20*time.Second, 34*time.Second, true)
	if len(got) != 1 || got[0].Field != "deploy.promotion_slo_seconds" {
		t.Fatalf("first release outcomes = %+v, want only the measured promotion SLO", got)
	}
	oldHelper := measureDeploySLO(config.Deploy{PromotionSLOSeconds: 30, TotalSLOSeconds: 30}, 20*time.Second, 34*time.Second)
	if len(oldHelper) != 2 || !oldHelper[1].Missed {
		t.Fatalf("an old helper response must keep total SLO evaluation: %+v", oldHelper)
	}
}

// A real failure stays a failure: an application that never answers its public
// health URL is a broken release, and the caller rolls it back.
func TestUnhealthyApplicationStillFailsThePromotion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := &config.Config{Deploy: config.Deploy{
		AvailabilityURL:        server.URL,
		AvailabilityIntervalMS: 50,
		PromotionSLOSeconds:    config.MinDeploySLOSeconds,
	}}
	if err := waitForPublicAvailability(cfg, config.PromotionModeLegacy); err == nil {
		t.Fatal("an application that never answers must fail the promotion")
	}
}

func TestHealthyApplicationPassesTheAvailabilityGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := &config.Config{Deploy: config.Deploy{
		AvailabilityURL:        server.URL,
		AvailabilityIntervalMS: 50,
		PromotionSLOSeconds:    config.MinDeploySLOSeconds,
	}}
	if err := waitForPublicAvailability(cfg, config.PromotionModeLegacy); err != nil {
		t.Fatalf("a healthy application must pass the availability gate, got %v", err)
	}
}

// The invariant that made the old budget unfalsifiable: the waits a promotion
// performs in sequence must fit inside the budget the promotion is measured
// against. With independent constants they summed to 95 s inside a 30 s budget.
func TestInternalPromotionWaitsFitInsideTheBudget(t *testing.T) {
	for _, seconds := range []int{config.MinDeploySLOSeconds, 30, 45, config.MaxDeploySLOSeconds} {
		waits := config.DeployWaits(seconds)
		budget := time.Duration(seconds) * time.Second
		if waits.Total() > budget {
			t.Errorf("internal waits for a %s budget total %s: %+v", budget, waits.Total(), waits)
		}
		if waits.StackConvergence <= 0 || waits.CaddyReload <= 0 || waits.OriginProof <= 0 || waits.Availability <= 0 {
			t.Errorf("every wait must stay usable at a %s budget: %+v", budget, waits)
		}
	}
}

// The HTTPS origin proof is one of those sequential waits, so its two calls must
// share the allocated slice rather than each claiming a constant of their own.
func TestOriginProofBudgetsStayInsideTheirShare(t *testing.T) {
	share := config.DeployWaits(30).OriginProof
	direct, edge := originProofBudgets(&config.Config{Deploy: config.Deploy{PromotionSLOSeconds: 30}}, config.PromotionModeLegacy)
	if direct != share || edge != 0 {
		t.Errorf("without an edge the direct proof takes the whole share, got %s + %s for %s", direct, edge, share)
	}
	direct, edge = originProofBudgets(&config.Config{Deploy: config.Deploy{PromotionSLOSeconds: 30, EdgeProxy: true}}, config.PromotionModeLegacy)
	if direct+edge > share {
		t.Errorf("the edge-fronted proof must fit in %s, got %s + %s", share, direct, edge)
	}
	if edge <= 0 {
		t.Errorf("an edge-fronted proof still needs a budget for the edge call, got %s", edge)
	}
}

// Each budget names its own stage: a promotion SLO miss blames the promotion
// even when the build dominated the whole deploy.
func TestPromotionSLOMissNamesThePromotionEvenWhenTheBuildDominates(t *testing.T) {
	deploy := config.Deploy{PromotionSLOSeconds: 60, TotalSLOSeconds: 400}
	body := captureStderr(t, func() {
		reportDeploySLO(
			measureDeploySLO(deploy, 90*time.Second, 7*time.Minute),
			deploySLOReportContext{Stages: deployStageDurations{Build: 5 * time.Minute, Promotion: 90 * time.Second, Total: 7 * time.Minute}},
		)
	})
	if !strings.Contains(body, "Promotion SLO missed: 1m30s > 1m0s: promotion took 1m30s") {
		t.Errorf("promotion miss must name the promotion:\n%s", body)
	}
	if !strings.Contains(body, "Total deploy SLO missed: 7m0s > 6m40s: build took 5m0s") {
		t.Errorf("total miss must name the dominant stage:\n%s", body)
	}
}

// The total timer starts before the tracked stages: when the untracked part is
// the largest, the warning says so instead of blaming a tracked stage.
func TestTotalSLOMissNamesSetupWhenTheUntrackedRemainderDominates(t *testing.T) {
	deploy := config.Deploy{TotalSLOSeconds: 60}
	body := captureStderr(t, func() {
		reportDeploySLO(
			measureDeploySLO(deploy, 10*time.Second, 2*time.Minute),
			deploySLOReportContext{Stages: deployStageDurations{Build: 20 * time.Second, Push: time.Second, Promotion: 10 * time.Second, Total: 2 * time.Minute}},
		)
	})
	if !strings.Contains(body, "setup and other steps took 1m29s") {
		t.Errorf("total miss must name the untracked remainder:\n%s", body)
	}
}

// Compose passes no stage timings: its total SLO miss names no stage and gives
// no advice to raise the budget.
func TestComposeTotalSLOMissNamesNoStage(t *testing.T) {
	deploy := config.Deploy{TotalSLOSeconds: 60}
	body := captureStderr(t, func() {
		reportDeploySLO(measureDeploySLO(deploy, 10*time.Second, 2*time.Minute))
	})
	if strings.Contains(body, " took ") || strings.Contains(strings.ToLower(body), "raise") {
		t.Errorf("compose total miss must name no stage and no budget advice:\n%s", body)
	}
	if !strings.Contains(body, "Total deploy SLO missed: 2m0s > 1m0s") {
		t.Errorf("compose total miss line missing:\n%s", body)
	}
}
