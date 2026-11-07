package config

import (
	"fmt"
	"time"
)

// PromotionMode is how one Swarm promotion spends the promotion budget
// (deploy.promotion_slo_seconds). The root helper chooses it, before it runs
// `docker stack deploy`, from state only it can read, and reports it to the
// client, which spends the rest of the budget the same way.
type PromotionMode string

const (
	// PromotionModeLegacy is the flat 55/15/20/10 split of DeployWaits, plus the
	// first-release convergence floor. It is the safe answer whenever the
	// helper cannot prove the cheaper one is enough, and the answer of every
	// response that names no mode at all (a helper older than this release).
	PromotionModeLegacy PromotionMode = "legacy"
	// PromotionModeCapped gives the convergence wait what the budget leaves after
	// small fixed ceilings for the steps that follow it. It is only chosen for a
	// release that follows an earlier one, on an application whose certificates
	// are all in the edge's store, so none of the following steps has an ACME
	// issuance to wait for.
	PromotionModeCapped PromotionMode = "capped"
)

// ParsePromotionMode reads the mode a helper reported. Anything but "capped" is
// legacy: an absent field comes from a helper that predates the field, and an
// unknown value must not shrink a wait.
func ParsePromotionMode(value string) PromotionMode {
	if PromotionMode(value) == PromotionModeCapped {
		return PromotionModeCapped
	}
	return PromotionModeLegacy
}

const (
	// CappedStepCeiling bounds each step that follows convergence in capped mode
	// (Caddy reload, origin proof, public availability). On a host that already
	// holds the certificates, the measured post-convergence steps of a Swarm
	// promotion fit well inside it; web (SLO 90 s) spent its time waiting for
	// a healthy task, not on these.
	CappedStepCeiling = 10 * time.Second
	// CappedConvergenceCeiling caps the convergence wait in capped mode. With
	// the three ceilings above it makes the longest helper-side wait
	// 410 s + 10 s = 420 s, which is what the legacy split also reaches at the
	// 600 s maximum budget.
	CappedConvergenceCeiling = 410 * time.Second
	// CappedWaitsFitUnder is the budget up to which the four capped waits add up
	// to exactly the budget (the three ceilings are all reached from 100 s, so
	// convergence is the budget minus 30 s, until it hits its own ceiling at
	// 410 s). Above it the waits total 440 s, which stays under the budget.
	CappedWaitsFitUnder = CappedConvergenceCeiling + 3*CappedStepCeiling
	// EdgeRequestFloor is the least the single public request of an edge_proxy
	// origin proof keeps in capped mode. It is taken from the direct proof's
	// share of the origin proof, never from convergence.
	EdgeRequestFloor = 6 * time.Second
)

// SwarmWaits is how a Swarm promotion in the given mode spends its budget. The
// Compose strategy keeps DeployWaits, which is unchanged.
//
// Legacy is exactly DeployWaits: 55 % convergence, 15 % Caddy reload, 20 %
// origin proof, 10 % availability. At a 90 s budget that is a 49.5 s
// convergence window, which web exceeded on 01-11-2026 while its new task
// was healthy only a few seconds later.
//
// Capped keeps the three steps after convergence at 15 %, 20 % and 10 % of the
// budget with a 10 s ceiling each, and gives convergence the rest, up to 410 s.
// At 90 s that is 10 + 10 + 9 s after a 61 s convergence window; at 600 s it is
// 10 + 10 + 10 s after 410 s. Convergence is never below its legacy share,
// because the three capped steps never take more than the 45 % legacy gives
// them.
func SwarmWaits(promotionSLOSeconds int, mode PromotionMode) DeployWaitBudget {
	if mode != PromotionModeCapped {
		return DeployWaits(promotionSLOSeconds)
	}
	if promotionSLOSeconds < MinDeploySLOSeconds {
		promotionSLOSeconds = MinDeploySLOSeconds
	}
	if promotionSLOSeconds > MaxDeploySLOSeconds {
		promotionSLOSeconds = MaxDeploySLOSeconds
	}
	budget := time.Duration(promotionSLOSeconds) * time.Second
	reload := min(budget*15/100, CappedStepCeiling)
	proof := min(budget*20/100, CappedStepCeiling)
	availability := min(budget*10/100, CappedStepCeiling)
	return DeployWaitBudget{
		StackConvergence: min(budget-reload-proof-availability, CappedConvergenceCeiling),
		CaddyReload:      reload,
		OriginProof:      proof,
		Availability:     availability,
	}
}

// SwarmOriginProofSplit divides the origin-proof share between the call that
// proves the VPS directly and, behind an edge, the single public request.
//
// Legacy keeps two thirds / one third. Capped keeps the edge request at six
// seconds or more (a third of the share, if that is more), taken from the
// direct share: at a 90 s budget the 10 s share is 4 s direct plus 6 s for the
// edge request. On a share too small for that, the edge request takes two thirds
// of it at most, so the direct proof is never left with nothing.
func SwarmOriginProofSplit(waits DeployWaitBudget, mode PromotionMode, edgeProxy bool) (direct, edge time.Duration) {
	share := waits.OriginProof
	if !edgeProxy {
		return share, 0
	}
	if mode != PromotionModeCapped {
		return share * 2 / 3, share / 3
	}
	edge = max(share/3, min(EdgeRequestFloor, share*2/3))
	return share - edge, edge
}

// SwarmHelperWait is the longest the privileged helper waits in one stack-apply
// of the given mode: the convergence wait (with the first-release floor, if this
// is a first release) plus the shared-edge reload. The Hashvault confirmation
// that follows runs outside the budget and is added by the caller.
func SwarmHelperWait(promotionSLOSeconds int, mode PromotionMode, firstRelease bool) time.Duration {
	waits := SwarmWaits(promotionSLOSeconds, mode)
	convergence := waits.StackConvergence
	if firstRelease {
		convergence = max(convergence, FirstReleaseStackConvergenceFloor)
	}
	return convergence + waits.CaddyReload
}

// SwarmWorstCaseHelperWait is the longest helper-side wait of either mode. The
// client learns the mode only when the call returns, so its SSH deadline has to
// cover the larger of the two: legacy with the first-release floor, or capped.
// Both total 420 s at the 600 s maximum budget.
func SwarmWorstCaseHelperWait(promotionSLOSeconds int) time.Duration {
	return max(
		SwarmHelperWait(promotionSLOSeconds, PromotionModeLegacy, true),
		SwarmHelperWait(promotionSLOSeconds, PromotionModeCapped, false),
	)
}

// Terms of the shortest promotion budget a rollout can be expected to fit in:
// 60 s of fixed cost (pull, scheduling, first start), the healthcheck
// start_period the stack renders, two update monitors (the new task's, and the
// settle before the old one goes), and 29 s for the steps after convergence (the
// capped 10 + 10 + 9 s of a 90 s budget).
const (
	RolloutFixedAllowance       = 60 * time.Second
	RolloutPostStepsAllowance   = 29 * time.Second
	rolloutUpdateMonitorsNeeded = 2
)

// PromotionSLOWarning returns the advice to print when the project's own
// deploy.promotion_slo_seconds is shorter than a rollout of this stack can take:
// the budget is below 60 s + maxStartPeriod + 2 x the update monitor + 29 s,
// where maxStartPeriod is the longest healthcheck start_period the stack
// renders. It returns "" when the budget is enough, and always when the project
// never wrote the budget itself: a default nobody chose is not advice-worthy,
// and the preset defaults (30 and 45 s) are all below this floor by design.
//
// It is a warning and never an error: the budgets are measurements the deploy
// reports, not gates (see validateDeploySLO).
func (cfg *Config) PromotionSLOWarning(maxStartPeriod time.Duration) string {
	if cfg == nil || !cfg.Deploy.promotionSLOSetByProject {
		return ""
	}
	monitor := time.Duration(cfg.EffectiveUpdateMonitorSeconds()) * time.Second
	needed := RolloutFixedAllowance + maxStartPeriod + rolloutUpdateMonitorsNeeded*monitor + RolloutPostStepsAllowance
	budget := time.Duration(cfg.Deploy.PromotionSLOSeconds) * time.Second
	if budget >= needed {
		return ""
	}
	return fmt.Sprintf("deploy.promotion_slo_seconds is %s for stack %s, below the %s its rollout needs (%s fixed + %s healthcheck start_period + 2 x %s update monitor + %s after convergence): a release can be reported as missing the budget while its new task is healthy",
		budget, cfg.App, needed, RolloutFixedAllowance, maxStartPeriod, monitor, RolloutPostStepsAllowance)
}

// SwarmWorstCaseWaits is the field-wise larger of the two modes' waits, without
// the first-release floor. Recovery paths do not know which mode the interrupted
// deploy ran in, so they wait as long as the longer one would have.
func SwarmWorstCaseWaits(promotionSLOSeconds int) DeployWaitBudget {
	legacy := SwarmWaits(promotionSLOSeconds, PromotionModeLegacy)
	capped := SwarmWaits(promotionSLOSeconds, PromotionModeCapped)
	return DeployWaitBudget{
		StackConvergence: max(legacy.StackConvergence, capped.StackConvergence),
		CaddyReload:      max(legacy.CaddyReload, capped.CaddyReload),
		OriginProof:      max(legacy.OriginProof, capped.OriginProof),
		Availability:     max(legacy.Availability, capped.Availability),
	}
}
