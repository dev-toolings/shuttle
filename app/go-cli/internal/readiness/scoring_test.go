package readiness

import "testing"

func TestScore(t *testing.T) {
	checks := []CheckResult{
		{Severity: Critical, Status: Failed},
		{Severity: High, Status: Failed},
		{Severity: Medium, Status: Passed},
	}
	if got := Score(checks); got != 70 {
		t.Fatalf("expected 70, got %d", got)
	}
}

func TestLevel(t *testing.T) {
	if ReadinessLevel(95) != "production-ready" {
		t.Fatal("expected production-ready")
	}
	if ReadinessLevel(80) != "almost-ready" {
		t.Fatal("expected almost-ready")
	}
	if ReadinessLevel(65) != "risky" {
		t.Fatal("expected risky")
	}
}
