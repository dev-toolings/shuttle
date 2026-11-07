package cli

import (
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestRunPlanValidityAndTransportBudget(t *testing.T) {
	if rootRunTransportTimeout != 19*time.Minute {
		t.Fatalf("run transport timeout is %s, want derived 19 minutes", rootRunTransportTimeout)
	}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	identity := trustedHostIdentity{OperatorKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", HostKeyFingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
	plan, err := newSignedRunPlan("api", "migrate", rootplan.RunOptions{RequireBackup: true}, identity, now)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := time.Parse(time.RFC3339, plan.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if expires.Sub(generated) != 15*time.Minute {
		t.Fatalf("run plan validity is %s", expires.Sub(generated))
	}
	if plan.Run == nil || !plan.Run.RequireBackup {
		t.Fatalf("run options missing from plan: %+v", plan.Run)
	}
	var captured time.Duration
	old := setRootRunTransportTimeout
	setRootRunTransportTimeout = func(_ *shuttlessh.Client, timeout time.Duration) { captured = timeout }
	t.Cleanup(func() { setRootRunTransportTimeout = old })
	configureRootRunTransportTimeout(nil)
	if captured != 19*time.Minute {
		t.Fatalf("client received timeout %s", captured)
	}
}
