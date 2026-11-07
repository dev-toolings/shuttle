package rootplan

import (
	"strings"
	"testing"
	"time"
)

func TestReadOnlyDebugPlansAreClosedAndScoped(t *testing.T) {
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	now := time.Now().UTC()
	valid := []struct {
		mode, service string
		lines         int
	}{
		{"debug-ps", "", 0},
		{"debug-services", "", 0},
		{"debug-network", "", 0},
		{"debug-tasks", "web", 0},
		{"debug-inspect", "web", 0},
		{"debug-logs", "web", 200},
	}
	for _, test := range valid {
		if _, err := NewStackAudit(test.mode, "demo", test.service, test.lines, fingerprint, fingerprint, now, time.Minute); err != nil {
			t.Errorf("valid %s plan rejected: %v", test.mode, err)
		}
	}
	for _, test := range []struct {
		mode, app, service string
		lines              int
	}{
		{"debug-ps", "../demo", "", 0},
		{"debug-ps", "demo", "web", 0},
		{"debug-network", "demo", "", 1},
		{"debug-tasks", "demo", "../web", 0},
		{"debug-inspect", "demo", "", 0},
		{"debug-logs", "demo", "web", 0},
		{"debug-logs", "demo", "web", 1001},
	} {
		if _, err := NewStackAudit(test.mode, test.app, test.service, test.lines, fingerprint, fingerprint, now, time.Minute); err == nil {
			t.Errorf("unsafe debug plan accepted: %#v", test)
		}
	}
	plan, err := NewStackAudit("debug-ps", "demo", "", 0, fingerprint, fingerprint, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	plan.Baseline = &BaselineOperation{AllowedSSHUsers: []string{"deploy"}}
	if _, err := seal(plan); err == nil {
		t.Fatal("debug audit accepted an unrelated SSH baseline payload")
	}
}
