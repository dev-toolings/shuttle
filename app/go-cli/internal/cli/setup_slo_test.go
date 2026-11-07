package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// A VPS that is configured, hardened, SSH-locked down and proven must not be
// reported as a failed command because a stopwatch ran out. The old code
// returned an error whose own text read "host remains converged", so a buyer's
// very first contact with the product exited non-zero on a host that was ready,
// indistinguishable from a real convergence failure. The budget is an
// objective: it is measured and reported, never enforced.
func TestOverBudgetConvergedSetupSucceedsWithAWarning(t *testing.T) {
	var out bytes.Buffer
	var err error
	body := captureStderr(t, func() {
		err = finishSetup(&out, 600, 14*time.Minute)
	})
	if err != nil {
		t.Fatalf("an over-budget but converged setup must succeed, got %v", err)
	}
	if !strings.Contains(out.String(), "Setup converged safely in 14m0s.") {
		t.Errorf("the convergence must still be announced, got:\n%s", out.String())
	}
	if !strings.Contains(body, "Setup SLO missed") || !strings.Contains(body, "setup.slo_seconds") {
		t.Errorf("the overrun must be warned about and name the field to raise, got:\n%s", body)
	}
}

func TestWithinBudgetSetupReportsTheBudgetAsMet(t *testing.T) {
	var out bytes.Buffer
	body := captureStderr(t, func() {
		if err := finishSetup(&out, 600, 7*time.Minute); err != nil {
			t.Fatalf("a converged setup must succeed, got %v", err)
		}
	})
	if strings.Contains(body, "Setup SLO missed") {
		t.Errorf("a setup inside its budget must not warn, got:\n%s", body)
	}
}

// setup.slo_seconds was validated on load and then ignored by setup.go, which
// compared against a hard-coded ten minutes. Raising the field must now move the
// verdict, otherwise the setting still regulates nothing.
func TestSetupBudgetComesFromTheConfiguredField(t *testing.T) {
	twelve := 12 * time.Minute
	if outcome := measureSetupSLO(600, twelve); !outcome.Missed {
		t.Errorf("12 min against a 600 s budget must be reported as missed: %+v", outcome)
	}
	if outcome := measureSetupSLO(1800, twelve); outcome.Missed || outcome.Budget != 30*time.Minute {
		t.Errorf("raising setup.slo_seconds to 1800 must make the same run fit: %+v", outcome)
	}
	// A plan-less caller (or a configuration predating the field) falls back to
	// the shipped default rather than to a zero budget that misses instantly.
	if outcome := measureSetupSLO(0, time.Minute); outcome.Missed || outcome.Budget != time.Duration(config.DefaultSetupSLOSeconds)*time.Second {
		t.Errorf("an unset budget must fall back to the shipped default: %+v", outcome)
	}
}
