package cli

import (
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// A helper that predates the mode field prints nothing (a later release) or only
// first_release (a first one). The client then spends the budget the way it did
// before the helper chose anything.
func TestHelperResponseWithoutAModeIsTreatedAsLegacy(t *testing.T) {
	for name, body := range map[string]string{
		"first release without a mode": `{"first_release":true}`,
		"empty object":                 `{}`,
		"empty body":                   ``,
		"not json":                     `stack converged`,
		"unknown mode":                 `{"first_release":false,"mode":"turbo"}`,
		"empty mode":                   `{"first_release":false,"mode":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := promotionOutcomeFromPromoteResponse(body).Mode; got != config.PromotionModeLegacy {
				t.Fatalf("mode of %q = %q, want legacy", body, got)
			}
		})
	}
}

func TestHelperResponseKeepsFirstReleaseAndReadsTheMode(t *testing.T) {
	first := promotionOutcomeFromPromoteResponse(`{"first_release":true}`)
	if !first.FirstRelease || first.Mode != config.PromotionModeLegacy {
		t.Fatalf("first release outcome = %+v", first)
	}
	if !firstReleaseFromPromoteResponse(`{"first_release":true,"mode":"legacy"}`) || firstReleaseFromPromoteResponse(`{"mode":"capped"}`) {
		t.Fatal("first_release must be read whatever the mode is")
	}
	later := promotionOutcomeFromPromoteResponse(`{"first_release":false,"mode":"capped"}`)
	if later.FirstRelease || later.Mode != config.PromotionModeCapped {
		t.Fatalf("later release outcome = %+v", later)
	}
}

// Compose is not part of DEV-DEPL-83: whatever mode a caller passes, its origin
// proof and its availability wait (promotionWaitsFor is the budget both read)
// spend DeployWaits, and the edge keeps its third. 200 s is a budget where the
// capped mode would change every wait, so a Compose path that followed the mode
// could not pass.
func TestComposeKeepsDeployWaitsForOriginProofAndAvailability(t *testing.T) {
	compose := &config.Config{Deploy: config.Deploy{Strategy: config.StrategyCompose, PromotionSLOSeconds: 200}}
	want := config.DeployWaits(200)
	capped := config.SwarmWaits(200, config.PromotionModeCapped)
	if capped.OriginProof == want.OriginProof || capped.Availability == want.Availability {
		t.Fatalf("this test cannot tell the modes apart: capped %+v, DeployWaits %+v", capped, want)
	}
	for _, mode := range []config.PromotionMode{config.PromotionModeLegacy, config.PromotionModeCapped} {
		if got := promotionWaitsFor(compose, mode); got != want {
			t.Fatalf("Compose waits in %s mode = %+v, want DeployWaits %+v", mode, got, want)
		}
		direct, edge := originProofBudgets(compose, mode)
		if direct != want.OriginProof || edge != 0 {
			t.Fatalf("Compose origin proof in %s mode = %s + %s, want the whole %s", mode, direct, edge, want.OriginProof)
		}
	}
	compose.Deploy.EdgeProxy = true
	for _, mode := range []config.PromotionMode{config.PromotionModeLegacy, config.PromotionModeCapped} {
		direct, edge := originProofBudgets(compose, mode)
		if direct != want.OriginProof*2/3 || edge != want.OriginProof/3 {
			t.Fatalf("Compose edge-fronted origin proof in %s mode = %s + %s, want two thirds and one third of %s", mode, direct, edge, want.OriginProof)
		}
	}
}

// A Swarm promotion spends the shares of the mode the helper reported. At the
// 90 s budget the capped origin proof is 10 s: all of it direct without an edge,
// 4 s direct and 6 s for the edge request with edge_proxy.
func TestSwarmOriginProofBudgetsFollowTheReportedModeAtNinetySeconds(t *testing.T) {
	swarm := &config.Config{Deploy: config.Deploy{Strategy: config.StrategySwarm, PromotionSLOSeconds: 90}}
	direct, edge := originProofBudgets(swarm, config.PromotionModeCapped)
	if direct != 10*time.Second || edge != 0 {
		t.Fatalf("capped origin proof without an edge = %s + %s, want 10s + 0s", direct, edge)
	}
	swarm.Deploy.EdgeProxy = true
	direct, edge = originProofBudgets(swarm, config.PromotionModeCapped)
	if direct != 4*time.Second || edge != 6*time.Second {
		t.Fatalf("capped origin proof behind an edge = %s + %s, want 4s + 6s", direct, edge)
	}
	direct, edge = originProofBudgets(swarm, config.PromotionModeLegacy)
	if direct != 12*time.Second || edge != 6*time.Second {
		t.Fatalf("legacy origin proof behind an edge = %s + %s, want the 18s share split 12s + 6s", direct, edge)
	}
	if got := promotionWaitsFor(swarm, config.PromotionModeCapped).Availability; got != 9*time.Second {
		t.Fatalf("capped availability wait at 90s = %s, want 9s", got)
	}
}
