package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"strings"
	"testing"
	"time"
)

func TestDestroyExposesExplicitDatabaseConsentAndReadOnlyPreview(t *testing.T) {
	cmd := newDestroyCommand()
	for _, name := range []string{"drop-databases", "dry-run"} {
		flag := cmd.Flags().Lookup(name)
		if flag == nil || flag.DefValue != "false" {
			t.Errorf("destroy needs --%s defaulting to false, got %v", name, flag)
		}
	}
}

func TestDestroyRefusesHelperWithoutSafeOptions(t *testing.T) {
	report := currentRootHelperCapabilities()
	features := report.Features
	report.Features = nil
	for _, feature := range features {
		if feature != capabilityDestroySafeOptions {
			report.Features = append(report.Features, feature)
		}
	}
	if err := destroyCapabilityDecision(report, "example.invalid"); err == nil {
		t.Fatal("destroy accepted a helper that can ignore explicit consent or preview")
	}
}

func TestDestroyPlanStartsAfterReservationWait(t *testing.T) {
	now := time.Now()
	fp := "SHA256:" + strings.Repeat("a", 43)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	plan, err := newDestroyOperationPlan("demo", fp, fp, true, false, func() (string, error) { now = now.Add(3 * time.Minute); return strings.Repeat("a", 32), nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	plan, err = rootplan.Sign(plan, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := rootplan.Verify(plan, public, now); err != nil {
		t.Fatalf("reservation consumed the destroy plan lifetime: %v", err)
	}
}
