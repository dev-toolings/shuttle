package readiness

type Severity string
type Status string
type Level string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"

	Passed  Status = "passed"
	Failed  Status = "failed"
	Skipped Status = "skipped"
	Unknown Status = "unknown"
)

type CheckResult struct {
	ID               string         `json:"id"`
	Title            string         `json:"title"`
	Category         string         `json:"category"`
	Severity         Severity       `json:"severity"`
	Status           Status         `json:"status"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details,omitempty"`
	Remediation      string         `json:"remediation,omitempty"`
	AutoFixAvailable bool           `json:"autoFixAvailable"`
	Ignored          bool           `json:"ignored,omitempty"`
	IgnoreReason     string         `json:"ignoreReason,omitempty"`
	Evidence         map[string]any `json:"evidence,omitempty"`
	SkipReason       string         `json:"skipReason,omitempty"`
}

type Report struct {
	Target      string        `json:"target"`
	Profile     []string      `json:"profile"`
	ConfigPath  string        `json:"configPath,omitempty"`
	Score       int           `json:"score"`
	Level       Level         `json:"level"`
	Checks      []CheckResult `json:"checks"`
	GeneratedAt string        `json:"generatedAt"`
	Coverage    Coverage      `json:"coverage"`
	Validated   bool          `json:"validated"`
}

type Coverage struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Unavailable   int `json:"unavailable"`
	NotApplicable int `json:"notApplicable"`
	Exceptions    int `json:"exceptions"`
}
