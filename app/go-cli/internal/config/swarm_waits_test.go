package config

import (
	"strings"
	"testing"
	"time"
)

func seconds(value float64) time.Duration { return time.Duration(value * float64(time.Second)) }

// Legacy is today's split, untouched: at a 90 s budget the convergence window is
// 49.5 s, which web exceeded on 01-11-2026 while its new task was healthy.
func TestSwarmWaitsLegacyKeepsTheFlatShares(t *testing.T) {
	got := SwarmWaits(90, PromotionModeLegacy)
	want := DeployWaitBudget{StackConvergence: seconds(49.5), CaddyReload: seconds(13.5), OriginProof: seconds(18), Availability: seconds(9)}
	if got != want {
		t.Fatalf("legacy waits at 90 s = %+v, want %+v", got, want)
	}
	if got != DeployWaits(90) {
		t.Fatalf("legacy must be DeployWaits itself, got %+v", got)
	}
	at600 := SwarmWaits(600, PromotionModeLegacy)
	if at600.StackConvergence != 330*time.Second || at600.CaddyReload != 90*time.Second || at600.OriginProof != 120*time.Second || at600.Availability != 60*time.Second {
		t.Fatalf("legacy waits at 600 s = %+v", at600)
	}
	// An unknown mode must not shrink a wait.
	if SwarmWaits(90, PromotionMode("")) != DeployWaits(90) || SwarmWaits(90, PromotionMode("fast")) != DeployWaits(90) {
		t.Fatal("anything but capped is legacy")
	}
}

// Capped gives convergence what the budget leaves after the three ceilings:
// 90 s is 10 + 10 + 9 after a 61 s window; 600 s is capped at 410 s.
func TestSwarmWaitsCappedLeavesConvergenceTheRest(t *testing.T) {
	at90 := SwarmWaits(90, PromotionModeCapped)
	want90 := DeployWaitBudget{StackConvergence: 61 * time.Second, CaddyReload: 10 * time.Second, OriginProof: 10 * time.Second, Availability: 9 * time.Second}
	if at90 != want90 {
		t.Fatalf("capped waits at 90 s = %+v, want %+v", at90, want90)
	}
	at600 := SwarmWaits(600, PromotionModeCapped)
	want600 := DeployWaitBudget{StackConvergence: 410 * time.Second, CaddyReload: 10 * time.Second, OriginProof: 10 * time.Second, Availability: 10 * time.Second}
	if at600 != want600 {
		t.Fatalf("capped waits at 600 s = %+v, want %+v", at600, want600)
	}
}

// The waits of a promotion run one after another, so in either mode they can
// never sum to more than the budget. Above CappedWaitsFitUnder (440 s) the capped
// waits total 440 s, under the budget; up to it they use the budget exactly.
func TestSwarmWaitsNeverOutlastTheBudgetInEitherMode(t *testing.T) {
	if CappedWaitsFitUnder != 440*time.Second {
		t.Fatalf("documented threshold = %s, want 440s", CappedWaitsFitUnder)
	}
	for slo := MinDeploySLOSeconds; slo <= MaxDeploySLOSeconds; slo++ {
		budget := time.Duration(slo) * time.Second
		for _, mode := range []PromotionMode{PromotionModeLegacy, PromotionModeCapped} {
			waits := SwarmWaits(slo, mode)
			if waits.Total() > budget {
				t.Fatalf("%s mode at %d s authorises %s of waiting: %+v", mode, slo, waits.Total(), waits)
			}
			if waits.StackConvergence <= 0 || waits.CaddyReload <= 0 || waits.OriginProof <= 0 || waits.Availability <= 0 {
				t.Fatalf("%s mode at %d s leaves a wait unusable: %+v", mode, slo, waits)
			}
		}
		capped := SwarmWaits(slo, PromotionModeCapped).Total()
		if budget <= CappedWaitsFitUnder && capped != budget {
			t.Fatalf("capped waits at %d s total %s, want exactly the budget", slo, capped)
		}
		if budget > CappedWaitsFitUnder && capped != CappedWaitsFitUnder {
			t.Fatalf("capped waits at %d s total %s, want %s", slo, capped, CappedWaitsFitUnder)
		}
	}
}

// A capped promotion is never given less time to converge than a legacy one for
// the same budget; at the 10 s floor the two are equal.
func TestSwarmWaitsCappedConvergenceIsNeverBelowLegacy(t *testing.T) {
	if got, want := SwarmWaits(10, PromotionModeCapped).StackConvergence, SwarmWaits(10, PromotionModeLegacy).StackConvergence; got < want {
		t.Fatalf("capped convergence at 10 s = %s, below legacy %s", got, want)
	}
	for slo := MinDeploySLOSeconds; slo <= MaxDeploySLOSeconds; slo++ {
		capped, legacy := SwarmWaits(slo, PromotionModeCapped).StackConvergence, SwarmWaits(slo, PromotionModeLegacy).StackConvergence
		if capped < legacy {
			t.Fatalf("capped convergence at %d s = %s, below legacy %s", slo, capped, legacy)
		}
	}
}

// The helper-side wait (convergence plus the edge reload) of each mode is 420 s
// at the 600 s budget, legacy including the first-release floor, and the deadline
// uses the larger. The client adds the 45 s Hashvault confirmation and its 120 s
// margin to that: 585 s, which a cli test holds under the 600 s root budget.
func TestSwarmHelperWaitWorstCaseIs420SecondsAtTheMaximumBudget(t *testing.T) {
	if got := SwarmHelperWait(600, PromotionModeLegacy, true); got != 420*time.Second {
		t.Fatalf("legacy helper wait at 600 s = %s, want 420s", got)
	}
	if got := SwarmHelperWait(600, PromotionModeCapped, false); got != 420*time.Second {
		t.Fatalf("capped helper wait at 600 s = %s, want 420s", got)
	}
	if got := SwarmWorstCaseHelperWait(600); got != 420*time.Second {
		t.Fatalf("worst case at 600 s = %s, want 420s", got)
	}
	for slo := MinDeploySLOSeconds; slo <= MaxDeploySLOSeconds; slo++ {
		if got := SwarmWorstCaseHelperWait(slo); got > 420*time.Second {
			t.Fatalf("worst case at %d s = %s, above the 420s ceiling", slo, got)
		}
	}
	// The first-release floor is what makes the legacy side the larger one at a
	// small budget.
	if got, want := SwarmWorstCaseHelperWait(30), FirstReleaseStackConvergenceFloor+DeployWaits(30).CaddyReload; got != want {
		t.Fatalf("worst case at 30 s = %s, want %s", got, want)
	}
}

// Recovery cannot know the mode of the deploy it interrupted, so it waits as long
// as the longer mode would have; at the shipped default the two agree.
func TestSwarmWorstCaseWaitsAreTheLongerOfBothModes(t *testing.T) {
	for _, slo := range []int{MinDeploySLOSeconds, 30, 45, 90, 500, MaxDeploySLOSeconds} {
		worst := SwarmWorstCaseWaits(slo)
		for _, mode := range []PromotionMode{PromotionModeLegacy, PromotionModeCapped} {
			waits := SwarmWaits(slo, mode)
			if worst.StackConvergence < waits.StackConvergence || worst.CaddyReload < waits.CaddyReload {
				t.Fatalf("worst case at %d s = %+v is shorter than the %s mode %+v", slo, worst, mode, waits)
			}
		}
	}
	if SwarmWorstCaseWaits(30) != DeployWaits(30) {
		t.Fatal("at the default budget recovery timing must be unchanged")
	}
}

// The edge request keeps six seconds in the capped mode, taken from the direct
// share and never from convergence. Both SLO 90 figures are published.
func TestSwarmOriginProofSplitAtNinetySeconds(t *testing.T) {
	capped := SwarmWaits(90, PromotionModeCapped)
	direct, edge := SwarmOriginProofSplit(capped, PromotionModeCapped, false)
	if direct != 10*time.Second || edge != 0 {
		t.Fatalf("capped, no edge proxy: %s + %s, want 10s + 0", direct, edge)
	}
	direct, edge = SwarmOriginProofSplit(capped, PromotionModeCapped, true)
	if direct != 4*time.Second || edge != EdgeRequestFloor {
		t.Fatalf("capped, edge proxy: %s + %s, want 4s + 6s", direct, edge)
	}
	if direct+edge != capped.OriginProof {
		t.Fatalf("the split must spend exactly the share, got %s + %s of %s", direct, edge, capped.OriginProof)
	}
	if capped.StackConvergence != 61*time.Second {
		t.Fatal("the edge floor must not touch convergence")
	}
	legacy := SwarmWaits(90, PromotionModeLegacy)
	direct, edge = SwarmOriginProofSplit(legacy, PromotionModeLegacy, true)
	if direct != 12*time.Second || edge != 6*time.Second {
		t.Fatalf("legacy, edge proxy: %s + %s, want 12s + 6s", direct, edge)
	}
	direct, edge = SwarmOriginProofSplit(legacy, PromotionModeLegacy, false)
	if direct != 18*time.Second || edge != 0 {
		t.Fatalf("legacy, no edge proxy: %s + %s, want 18s + 0", direct, edge)
	}
}

func TestSwarmOriginProofSplitNeverLeavesTheDirectProofNothing(t *testing.T) {
	for slo := MinDeploySLOSeconds; slo <= MaxDeploySLOSeconds; slo++ {
		waits := SwarmWaits(slo, PromotionModeCapped)
		direct, edge := SwarmOriginProofSplit(waits, PromotionModeCapped, true)
		if direct <= 0 || edge <= 0 || direct+edge != waits.OriginProof {
			t.Fatalf("capped split at %d s = %s + %s of %s", slo, direct, edge, waits.OriginProof)
		}
	}
}

func TestParsePromotionModeTreatsAMissingModeAsLegacy(t *testing.T) {
	for value, want := range map[string]PromotionMode{"capped": PromotionModeCapped, "legacy": PromotionModeLegacy, "": PromotionModeLegacy, "turbo": PromotionModeLegacy, "CAPPED": PromotionModeLegacy} {
		if got := ParsePromotionMode(value); got != want {
			t.Errorf("ParsePromotionMode(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestUpdateMonitorDefaultsToFiveSecondsAndIsBounded(t *testing.T) {
	cfg, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Deploy.UpdateMonitorSeconds != 5 || cfg.EffectiveUpdateMonitorSeconds() != 5 {
		t.Fatalf("omitted update_monitor_seconds = %d, want 5", cfg.Deploy.UpdateMonitorSeconds)
	}
	zero, err := loadYAML(t, strings.Replace(validConfig, "  retain: 2\n", "  retain: 2\n  update_monitor_seconds: 0\n", 1))
	if err != nil || zero.Deploy.UpdateMonitorSeconds != 5 {
		t.Fatalf("0 must mean the default, got %v / %v", zero, err)
	}
	for _, accepted := range []string{"2", "10", "60"} {
		cfg, err := loadYAML(t, strings.Replace(validConfig, "  retain: 2\n", "  retain: 2\n  update_monitor_seconds: "+accepted+"\n", 1))
		if err != nil || strings.TrimSpace(accepted) != itoa(cfg.Deploy.UpdateMonitorSeconds) {
			t.Fatalf("update_monitor_seconds %s: %v / %v", accepted, cfg, err)
		}
	}
	for _, refused := range []string{"1", "61", "-5", "3600"} {
		_, err := loadYAML(t, strings.Replace(validConfig, "  retain: 2\n", "  retain: 2\n  update_monitor_seconds: "+refused+"\n", 1))
		if err == nil || !strings.Contains(err.Error(), "deploy.update_monitor_seconds") {
			t.Fatalf("update_monitor_seconds %s must be refused, got %v", refused, err)
		}
	}
	// A Config that never went through Load resolves the same default.
	if got := (&Config{}).EffectiveUpdateMonitorSeconds(); got != DefaultUpdateMonitorSeconds {
		t.Fatalf("zero Config resolved %d", got)
	}
}

func itoa(value int) string { return strings.TrimSpace(strings.Join([]string{fmtInt(value)}, "")) }

func fmtInt(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for negative, rest := value < 0, value; rest != 0; rest /= 10 {
		digit := rest % 10
		if digit < 0 {
			digit = -digit
		}
		digits = string(rune('0'+digit)) + digits
		if rest/10 == 0 && negative {
			digits = "-" + digits
		}
	}
	return digits
}

// nil is one task at a time, an explicit 0 is every task at once, N is N, and a
// negative width is refused.
func TestUpdateParallelismNilZeroAndN(t *testing.T) {
	var cfg *Config
	if got := cfg.UpdateParallelism("web"); got != 1 {
		t.Fatalf("nil config resolved %d", got)
	}
	zero, three := 0, 3
	cfg = &Config{Services: map[string]Service{
		"web":    {Port: 3000},
		"worker": {UpdateParallelism: &zero},
		"batch":  {UpdateParallelism: &three},
	}}
	for name, want := range map[string]int{"web": 1, "absent": 1, "worker": 0, "batch": 3} {
		if got := cfg.UpdateParallelism(name); got != want {
			t.Errorf("UpdateParallelism(%q) = %d, want %d", name, got, want)
		}
	}

	body := strings.Replace(validConfig, "    port: 3000\n", "    port: 3000\n    update_parallelism: 0\n", 1)
	loaded, err := loadYAML(t, body)
	if err != nil {
		t.Fatalf("an explicit 0 must load: %v", err)
	}
	if loaded.Services["web"].UpdateParallelism == nil || loaded.UpdateParallelism("web") != 0 {
		t.Fatalf("explicit 0 was lost: %+v", loaded.Services["web"])
	}
	unset, err := loadYAML(t, validConfig)
	if err != nil || unset.Services["web"].UpdateParallelism != nil || unset.UpdateParallelism("web") != 1 {
		t.Fatalf("omitted parallelism must stay nil and resolve to 1: %v", err)
	}
	_, err = loadYAML(t, strings.Replace(validConfig, "    port: 3000\n", "    port: 3000\n    update_parallelism: -1\n", 1))
	if err == nil || !strings.Contains(err.Error(), "services.web.update_parallelism") {
		t.Fatalf("a negative width must be refused, got %v", err)
	}
}

// The warning fires only when the project wrote promotion_slo_seconds itself, and
// only below 60 s + the longest start_period + 2 x the monitor + 29 s. Projects on
// the shipped defaults stay silent.
func TestPromotionSLOWarningFiresOnlyForAProjectBudgetThatIsTooShort(t *testing.T) {
	explicit, err := loadYAML(t, strings.Replace(validConfig, "  total_slo_seconds: 30\n", "  total_slo_seconds: 90\n  promotion_slo_seconds: 90\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	// 60 + 30 + 2*5 + 29 = 129 s.
	warning := explicit.PromotionSLOWarning(30 * time.Second)
	if !strings.Contains(warning, "demo") || !strings.Contains(warning, "deploy.promotion_slo_seconds") || !strings.Contains(warning, "2m9s") {
		t.Fatalf("a 90 s budget below the 129 s floor must warn and name the stack, got %q", warning)
	}
	// 60 + 0 + 2*5 + 29 = 99 s: 90 s is still short, 100 s is not.
	if explicit.PromotionSLOWarning(0) == "" {
		t.Fatal("90 s is below 99 s, a warning is expected")
	}
	enough, err := loadYAML(t, strings.Replace(validConfig, "  total_slo_seconds: 30\n", "  total_slo_seconds: 100\n  promotion_slo_seconds: 100\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	if got := enough.PromotionSLOWarning(0); got != "" {
		t.Fatalf("100 s covers a rollout with no start_period, got %q", got)
	}
	if got := enough.PromotionSLOWarning(30 * time.Second); got == "" {
		t.Fatal("100 s does not cover a 30 s start_period")
	}

	// A project on defaults never warns, however short the default is.
	defaults, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got := defaults.PromotionSLOWarning(30 * time.Second); got != "" {
		t.Fatalf("a default budget must stay silent, got %q", got)
	}
	// The monitor is part of the floor.
	slow, err := loadYAML(t, strings.Replace(strings.Replace(validConfig, "  total_slo_seconds: 30\n", "  total_slo_seconds: 105\n  promotion_slo_seconds: 105\n  update_monitor_seconds: 30\n", 1), "  retain: 2\n", "  retain: 2\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	// 60 + 0 + 2*30 + 29 = 149 s.
	if slow.PromotionSLOWarning(0) == "" {
		t.Fatal("a 30 s monitor raises the floor to 149 s, a 105 s budget must warn")
	}
}
