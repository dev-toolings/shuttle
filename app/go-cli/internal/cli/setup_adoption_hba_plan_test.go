package cli

import (
	"strings"
	"testing"
)

func TestAdoptionPlanReportsUnprovenPostgresAccess(t *testing.T) {
	s := adoptionPrerequisiteFixture(t)
	plan := adoptionPlan(setupIdentity{}, "demo", "fingerprint", s, setupOptions{}, adoptionEdgePlan{}, nil, false)
	for _, part := range []string{"PostgreSQL access from the Docker gateway subnet is not proven", "host all all 172.18.0.0/16 scram-sha-256", "healthcheck must test PostgreSQL"} {
		if !strings.Contains(plan, part) {
			t.Fatalf("plan omits %q: %s", part, plan)
		}
	}
	s.GatewaySubnet = ""
	plan = adoptionPlan(setupIdentity{}, "demo", "fingerprint", s, setupOptions{}, adoptionEdgePlan{}, nil, false)
	if !strings.Contains(plan, "<Docker gateway subnet>") || strings.Contains(plan, "172.18.0.0/16") {
		t.Fatalf("plan invented an unknown gateway subnet: %s", plan)
	}
}
