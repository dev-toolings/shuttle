package readiness

import (
	"fmt"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

const (
	EvidenceUnavailable = "evidence_unavailable"
	NotApplicable       = "not_applicable"
)

// Observe the collection boundary as well as each parser. An implementation
// that forgets an exit-code check cannot accidentally certify an empty result.
type observedAdapter struct {
	execx.Adapter
	failures []int
}

func (a *observedAdapter) Run(command string, timeout time.Duration) execx.Result {
	result := a.Adapter.Run(command, timeout)
	if result.ExitCode != 0 {
		a.failures = append(a.failures, result.ExitCode)
	}
	return result
}

func evaluateCheck(adapter execx.Adapter, check Check) CheckResult {
	observed := &observedAdapter{Adapter: adapter}
	result := check(observed)
	if len(observed.failures) > 0 && result.Status == Passed {
		result = unavailableResult(result, "A collection command failed; no successful audit can be inferred.")
	}
	return normalizeEvidence(result)
}

func normalizeEvidence(result CheckResult) CheckResult {
	if result.Status == Unknown {
		result.Status = Skipped
	}
	if result.Status == Skipped && result.SkipReason == "" {
		result.SkipReason = EvidenceUnavailable
	}
	return result
}

func unavailableResult(result CheckResult, summary string) CheckResult {
	result.Status = Skipped
	result.SkipReason = EvidenceUnavailable
	result.Summary = summary
	return result
}

func collectionUnavailable(id, title, category string, severity Severity) CheckResult {
	return CheckResult{ID: id, Title: title, Category: category, Severity: severity,
		Status: Skipped, SkipReason: EvidenceUnavailable,
		Summary: "Collection failed or returned malformed evidence; this check could not be completed."}
}

func SummarizeCoverage(checks []CheckResult) Coverage {
	c := Coverage{Total: len(checks)}
	for _, check := range checks {
		if check.Ignored {
			c.Exceptions++
			continue
		}
		switch check.Status {
		case Passed:
			c.Passed++
		case Failed:
			c.Failed++
		case Skipped:
			if check.SkipReason == NotApplicable {
				c.NotApplicable++
			} else {
				c.Unavailable++
			}
		default:
			c.Unavailable++
		}
	}
	return c
}

func ChecksValidated(checks []CheckResult) bool {
	c := SummarizeCoverage(checks)
	return c.Passed > 0 && c.Failed == 0 && c.Unavailable == 0 && c.Exceptions == 0
}

func EvidenceLevel(checks []CheckResult) Level {
	if ChecksValidated(checks) {
		return "production-ready"
	}
	level := ReadinessLevel(Score(checks))
	if level == "production-ready" {
		return "almost-ready"
	}
	return level
}

func coverageLabel(checks []CheckResult) string {
	c := SummarizeCoverage(checks)
	return fmt.Sprintf("Evidence: %d passed, %d failed, %d unavailable, %d not applicable, %d exceptions. Validated: %t", c.Passed, c.Failed, c.Unavailable, c.NotApplicable, c.Exceptions, ChecksValidated(checks))
}

// A check may explicitly replace an unsuccessful optional probe with complete
// evidence from an independent fallback. Only failures inside that scope are
// acknowledged; unrelated collection failures remain visible.
func collectionCheckpoint(adapter execx.Adapter) int {
	if observed, ok := adapter.(*observedAdapter); ok {
		return len(observed.failures)
	}
	return 0
}
func collectionRecovered(adapter execx.Adapter, checkpoint int) {
	if observed, ok := adapter.(*observedAdapter); ok {
		observed.failures = observed.failures[:checkpoint]
	}
}

func pipefailCommand(command string) string {
	return "bash -o pipefail -c " + shellQuote(command)
}
