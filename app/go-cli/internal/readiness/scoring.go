package readiness

var penalties = map[Severity]int{
	Critical: 20,
	High:     10,
	Medium:   5,
	Low:      2,
	Info:     0,
}

func Score(checks []CheckResult) int {
	total := 100
	for _, check := range checks {
		if check.Ignored {
			continue
		}
		if check.Status == Failed {
			total -= penalties[check.Severity]
		}
	}
	if total < 0 {
		return 0
	}
	if total > 100 {
		return 100
	}
	return total
}

func ReadinessLevel(score int) Level {
	switch {
	case score >= 90:
		return "production-ready"
	case score >= 75:
		return "almost-ready"
	case score >= 50:
		return "risky"
	default:
		return "not-production-ready"
	}
}

func LevelLabel(level Level) string {
	switch level {
	case "production-ready":
		return "Production Ready"
	case "almost-ready":
		return "Almost Ready"
	case "risky":
		return "Risky"
	default:
		return "Not Production Ready"
	}
}
