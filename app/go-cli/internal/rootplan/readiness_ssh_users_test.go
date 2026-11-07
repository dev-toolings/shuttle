package rootplan

import (
	"strings"
	"testing"
	"time"
)

func TestReadinessAuditSignsTheExactSSHAccountPolicy(t *testing.T) {
	now := time.Now().UTC()
	plan, err := NewReadinessAuditWithAccess("demo", "demo.example.com", "/health", "node", 22, false, nil, []string{"deploy", "ops"}, testOperatorKey, testHostKey, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(plan.Audit.AllowedSSHUsers, " "); got != "deploy ops" {
		t.Fatalf("signed SSH users = %q, want deploy ops", got)
	}

	for _, users := range [][]string{{"ops", "deploy"}, {"deploy", "deploy"}, {"ops"}, {"deploy", "ops root"}} {
		if _, err := NewReadinessAuditWithAccess("demo", "demo.example.com", "/health", "node", 22, false, nil, users, testOperatorKey, testHostKey, now, time.Minute); err == nil {
			t.Errorf("unsafe readiness SSH policy accepted: %v", users)
		}
	}
}

func TestReadinessAuditKeepsDeployOnlyWireFormat(t *testing.T) {
	plan, err := NewReadinessAuditWithAccess("demo", "demo.example.com", "/health", "node", 22, false, nil, []string{"deploy"}, testOperatorKey, testHostKey, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Audit.AllowedSSHUsers) != 0 {
		t.Fatalf("deploy-only default should stay omitted, got %v", plan.Audit.AllowedSSHUsers)
	}
}
