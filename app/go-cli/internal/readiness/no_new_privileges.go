package readiness

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

// Swarm's Compose converter discards security_opt. Only the live daemon can
// prove the default inherited by newly created tasks; reading daemon.json
// would also pass before the operator's required Docker restart.
func checkDockerNoNewPrivileges(adapter execx.Adapter) CheckResult {
	result := CheckResult{
		ID: "docker.no_new_privileges", Title: "Docker enables no-new-privileges for new containers",
		Category: "docker", Severity: High, Status: Failed,
		Remediation: "During planned maintenance, merge no-new-privileges: true into Docker daemon.json, restart Docker, and recreate existing tasks including the Caddy edge; setup never restarts an existing daemon for this setting. Check setuid and file-capability dependencies first.",
	}
	res := adapter.Run("docker info --format '{{json .SecurityOptions}}'", 5*time.Second)
	var options []string
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &options) != nil || options == nil {
		result.Status = Skipped
		result.Summary = "The running Docker daemon's security options could not be read."
		return result
	}
	enabled := slices.Contains(options, "name=no-new-privileges")
	result.Status = ternaryStatus(enabled)
	result.Summary = ternary(enabled, "The running daemon enables no-new-privileges for new containers, including Swarm tasks; existing tasks are not proven by this check.", "The running daemon does not enable no-new-privileges by default; Swarm ignores security_opt in stack YAML.")
	result.Evidence = map[string]any{"daemonNoNewPrivileges": enabled, "scope": "new-containers", "securityOptions": options}
	return result
}
