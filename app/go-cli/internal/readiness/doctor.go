package readiness

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

type Check func(execx.Adapter) CheckResult

type registeredCheck struct {
	category string
	check    Check
}

// Host language packages are not dependencies of Shuttle's Swarm application
// deployments. This is configuration evidence about scope, not a waiver of the
// Docker workload health, root-user or restart-policy checks.
func hostRuntimeCheck(cfg Config, id, title string, severity Severity, check Check) Check {
	if !cfg.ContainerizedApplication {
		return check
	}
	return func(execx.Adapter) CheckResult {
		return CheckResult{
			ID: id, Title: title, Category: "runtime", Severity: severity,
			Status: Skipped, SkipReason: NotApplicable,
			Summary:  "Shuttle deploys this application's language runtime in Swarm containers; host language packages are not required. Docker workload checks remain applicable.",
			Evidence: map[string]any{"deploymentModel": "swarm", "checkScope": "host-language-runtime", "applicationRuntime": "container"},
		}
	}
}

func RunWithConfig(adapter execx.Adapter, target string, profile []string, cfg Config, configPath string) Report {
	return RunWithConfigProgress(adapter, target, profile, cfg, configPath, nil)
}

// MarkPublicChecksNotApplicable records that an internal app has no public
// route. The helper calls this only after verifying that no deployed service
// carries the signed stack's publication label.
func MarkPublicChecksNotApplicable(report *Report) {
	public := []CheckResult{
		{ID: "tls.cert_missing", Title: "TLS certificate is present and valid", Category: "tls", Severity: Critical},
		{ID: "tls.hsts_missing", Title: "HSTS header is enforced", Category: "tls", Severity: Medium},
		{ID: "dns.domain_not_pointing_to_server", Title: "DNS A record points to this server", Category: "dns", Severity: Medium},
		{ID: "monitoring.no_health_endpoint", Title: "App exposes a health endpoint", Category: "monitoring", Severity: Medium},
	}
	for _, check := range public {
		id := check.ID
		check.Status = Skipped
		check.SkipReason = NotApplicable
		check.Summary = "This internal app has no public route; this check does not apply."
		found := false
		for i := range report.Checks {
			if report.Checks[i].ID == id {
				report.Checks[i] = check
				found = true
				break
			}
		}
		if !found {
			report.Checks = append(report.Checks, check)
		}
	}
	report.Score = Score(report.Checks)
	report.Coverage = SummarizeCoverage(report.Checks)
	report.Validated = ChecksValidated(report.Checks)
	report.Level = EvidenceLevel(report.Checks)
}

// RunWithConfigProgress is RunWithConfig with an optional callback that is
// invoked after every evaluated check. The callback is deliberately kept out
// of Report so JSON consumers remain stable while interactive callers can
// render progress without guessing how many checks are active.
func RunWithConfigProgress(adapter execx.Adapter, target string, profile []string, cfg Config, configPath string, progress func(done, total int)) Report {
	if target == "" {
		target = "local"
	}
	if len(profile) == 0 {
		profile = cfg.Checks.Profile
	}
	if len(profile) == 0 {
		profile = []string{"all"}
	}

	enabledCategories := profileCategories(profile)
	checks := []registeredCheck{
		{"system", checkOSSupported},
		{"system", checkDiskSpace},
		{"system", checkUpdatesPending},
		{"system", checkMemoryLow},
		{"system", checkRebootRequired},
		{"system", checkFailedSystemdUnits},
		{"system", checkResolvedLinkLocalProtocols},
		{"security", checkRecentFailedSSHLogins},
		{"filesystem", checkUnexpectedSUIDSGID},
		{"docker", checkDockerInstalled},
		{"docker", checkDockerServiceEnabled},
		{"docker", checkDockerNoNewPrivileges},
		{"docker", checkLoopbackRegistry},
		{"docker", checkDockerGatewayMTU},
		{"docker", checkDockerRestartPolicies},
		{"docker", checkDockerHealthchecks},
		{"docker", checkDockerRunningAsRoot},
		{"docker", checkDockerSockExposed},
		{"firewall", checkDockerPublishedSensitivePorts},
		{"firewall", checkDockerUserPolicy},
		{"firewall", checkUFWActive},
		{"firewall", checkDatabasePorts},
		{"secrets", checkEnvWorldReadable},
		{"secrets", checkEnvTracked},
		{"secrets", checkSecretsWeakPermissions},
		{"reverse-proxy", checkCaddyInstalled},
		{"reverse-proxy", checkCaddyAdminExposed},
		{"reverse-proxy", checkCaddySecurityHeaders},
		{"reverse-proxy", checkCaddyConfigValid},
		{"reverse-proxy", checkSharedEdgeServes},
		{"database", checkAdminerRestricted},
		{"ssh", checkSSHBaselineDropInEffective},
		{"ssh", checkSSHRootLogin},
		{"ssh", checkSSHPasswordAuth},
		{"ssh", func(adapter execx.Adapter) CheckResult { return checkSSHPortForAccess(adapter, cfg.Access) }},
		{"ssh", checkSSHConfigValid},
		{"ssh", checkSSHKeyboardInteractive},
		{"ssh", func(adapter execx.Adapter) CheckResult { return checkSSHAllowedUsers(adapter, cfg.Access) }},
		{"system", checkUnattendedUpgrades},
		{"system", checkFail2ban},
		{"system", checkUnattendedSecurityPolicy},
		{"system", checkSecurityUpdatesPending},
		{"system", checkOtherUpdatesPending},
		{"system", checkAPTCacheFresh},
		{"system", checkFail2banSSHDJail},
		{"system", func(adapter execx.Adapter) CheckResult { return checkFail2banSSHDPort(adapter, cfg.Access) }},
		{"system", checkAppArmorActive},
		{"access", func(adapter execx.Adapter) CheckResult { return checkExpectedUser(adapter, cfg.Access) }},
		{"access", func(adapter execx.Adapter) CheckResult { return checkExpectedUserSSHFiles(adapter, cfg.Access) }},
		{"access", func(adapter execx.Adapter) CheckResult {
			return checkExpectedUserNoPasswordlessSudo(adapter, cfg.Access)
		}},
		{"access", func(adapter execx.Adapter) CheckResult { return checkExpectedUserDockerGroup(adapter, cfg.Access) }},
		{"firewall", func(adapter execx.Adapter) CheckResult { return checkSSHPrivateInterface(adapter, cfg.Access) }},
		{"firewall", func(adapter execx.Adapter) CheckResult { return checkUnexpectedPublicTCP(adapter, cfg.Access) }},
		{"firewall", func(adapter execx.Adapter) CheckResult { return checkDockerPublicTCP(adapter, cfg.Access) }},
		{"system", checkSwap},
		{"system", checkTimeSync},
		{"tls", checkTLSCertificate(cfg.App.Domain)},
		{"tls", checkHSTSHeader(cfg.App.Domain)},
		{"dns", checkDNSPointsToServer(cfg.App.Domain)},
		{"monitoring", checkHealthEndpoint(cfg.App.Domain, cfg.App.HealthcheckPath)},
		{"backups", checkDatabaseBackup},
		{"postgresql", checkPostgreSQLService},
		{"redis", checkRedisService},
		{"postgresql", checkDatabaseBindHBA},
		{"php", hostRuntimeCheck(cfg, "runtime.php_fpm_service", "PHP-FPM service is active", High, checkPHPFPMService)},
		{"php", hostRuntimeCheck(cfg, "runtime.php_fpm_socket", "PHP-FPM socket is present", High, checkPHPFPMSocket)},
		{"php", hostRuntimeCheck(cfg, "runtime.php_opcache", "PHP-FPM OPcache drop-in is configured", Medium, checkPHPOpCache)},
		{"node", hostRuntimeCheck(cfg, "runtime.node_npm_versions", "Node.js and npm versions are available", High, checkNodeNPMVersions)},
	}
	activeChecks := make([]registeredCheck, 0, len(checks))
	for _, check := range checks {
		if categoryEnabled(check.category, enabledCategories) {
			activeChecks = append(activeChecks, check)
		}
	}
	composeEnabled := categoryEnabled("compose", enabledCategories)
	var composeSnap composeSnapshot
	if composeEnabled {
		composeSnap = loadCompose(adapter)
	}
	total := len(activeChecks)
	if composeEnabled {
		total += 5
	}
	done := 0
	results := make([]CheckResult, 0, total)
	appendResult := func(result CheckResult) {
		results = append(results, normalizeEvidence(applyConfig(result, cfg)))
		done++
		if progress != nil {
			progress(done, total)
		}
	}
	for _, check := range activeChecks {
		appendResult(evaluateCheck(adapter, check.check))
	}
	if composeEnabled {
		appendResult(checkComposeMissingProdFile(composeSnap))
		appendResult(checkComposeEnvFileMissing(adapter, composeSnap))
		appendResult(checkComposeLatestTag(composeSnap))
		appendResult(checkComposeNoResourceLimits(composeSnap))
		appendResult(checkComposeBindMountSensitivePaths(composeSnap))
	}
	score := Score(results)
	return Report{
		Target:      target,
		Profile:     profile,
		ConfigPath:  configPath,
		Score:       score,
		Level:       EvidenceLevel(results),
		Coverage:    SummarizeCoverage(results),
		Validated:   ChecksValidated(results),
		Checks:      results,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func profileCategories(profile []string) map[string]bool {
	out := map[string]bool{}
	for _, item := range profile {
		item = strings.ToLower(strings.TrimSpace(item))
		switch item {
		case "", "all":
			return nil
		case "caddy":
			out["reverse-proxy"] = true
		case "private-vps", "private-tailscale":
			// Retained as an explicit unknown category for old configs; the
			// Tailscale/private-access posture is intentionally standby-only.
			out[item] = true
		case "postgres", "postgresql":
			out["postgresql"] = true
		case "runtime", "runtimes":
			addCategories(out, "postgresql", "php", "node")
		case "php-fpm", "php":
			out["php"] = true
		case "node", "nodejs":
			out["node"] = true
		default:
			out[item] = true
		}
	}
	return out
}

func addCategories(set map[string]bool, categories ...string) {
	for _, category := range categories {
		set[category] = true
	}
}

func categoryEnabled(category string, enabled map[string]bool) bool {
	if enabled == nil {
		return true
	}
	return enabled[category]
}

func ConsoleWithOptions(report Report, color, showSkipped bool) string {
	var b strings.Builder
	title := "DeployShuttle Doctor Report"
	if color {
		title = ansiCyan + title + ansiReset
	}
	fmt.Fprintf(&b, "%s\n\n", title)
	fmt.Fprintf(&b, "Target: %s\n", report.Target)
	fmt.Fprintf(&b, "Profile: %s\n", strings.Join(report.Profile, ", "))
	score := fmt.Sprintf("Score: %d/100 - %s", report.Score, LevelLabel(EvidenceLevel(report.Checks)))
	if color {
		score = colorForLevel(EvidenceLevel(report.Checks)) + score + ansiReset
	}
	fmt.Fprintf(&b, "%s\n", score)
	fmt.Fprintf(&b, "%s\n", coverageLabel(report.Checks))
	fmt.Fprintf(&b, "Generated: %s\n\n", report.GeneratedAt)
	for _, severity := range []Severity{Critical, High, Medium, Low, Info} {
		var group []CheckResult
		for _, check := range report.Checks {
			if check.Status == Skipped && check.SkipReason == NotApplicable && !showSkipped {
				continue
			}
			if check.Severity == severity {
				group = append(group, check)
			}
		}
		if len(group) == 0 {
			continue
		}
		heading := strings.Title(string(severity))
		if color {
			heading = colorForSeverity(severity) + heading + ansiReset
		}
		fmt.Fprintf(&b, "%s:\n", heading)
		for _, check := range group {
			marker := "[?]"
			if check.Status == Passed && !check.Ignored {
				marker = "[ok]"
			} else if check.Status == Failed {
				marker = "[x]"
			}
			if color {
				marker = colorForStatus(check.Status) + marker + ansiReset
			}
			fmt.Fprintf(&b, "  %s %s - %s\n", marker, check.Title, check.Summary)
			if check.Ignored {
				fmt.Fprintf(&b, "      Ignored: %s\n", check.IgnoreReason)
			}
			if check.Status == Failed && check.Remediation != "" {
				fmt.Fprintf(&b, "      Fix: %s\n", check.Remediation)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func colorForStatus(status Status) string {
	switch status {
	case Passed:
		return ansiGreen
	case Failed:
		return ansiRed
	default:
		return ansiYellow
	}
}

func colorForSeverity(severity Severity) string {
	switch severity {
	case Critical, High:
		return ansiRed
	case Medium:
		return ansiYellow
	default:
		return ansiCyan
	}
}

func colorForLevel(level Level) string {
	switch level {
	case "production-ready":
		return ansiGreen
	case "almost-ready":
		return ansiYellow
	case "risky":
		return ansiYellow
	default:
		return ansiRed
	}
}

func applyConfig(result CheckResult, cfg Config) CheckResult {
	if listContains(cfg.Checks.Ignore, result.ID) {
		return markIgnored(result, "ignored by checks.ignore")
	}
	switch result.ID {
	case "docker.sock_exposed":
		return ignoreAllowedWorkloads(result, cfg.Docker.AllowDockerSocket, "allowed by docker.allowDockerSocket")
	case "docker.containers_running_as_root":
		return ignoreAllowedWorkloads(result, cfg.Docker.AllowRoot, "allowed by docker.allowRoot")
	case "docker.containers_without_healthcheck":
		return ignoreAllowedWorkloads(result, cfg.Docker.WorkerServices, "allowed by docker.workerServices")
	default:
		return result
	}
}

func ignoreAllowedWorkloads(result CheckResult, allow []string, reason string) CheckResult {
	workloads, ok := evidenceStringSlice(result.Evidence["workloads"])
	if !ok || len(workloads) == 0 {
		return result
	}
	remaining := []string{}
	ignored := []string{}
	for _, workload := range workloads {
		if matchesAnyWorkload(workload, allow) {
			ignored = append(ignored, workload)
			continue
		}
		remaining = append(remaining, workload)
	}
	if len(ignored) == 0 {
		return result
	}
	if result.Evidence == nil {
		result.Evidence = map[string]any{}
	}
	result.Evidence["workloads"] = remaining
	result.Evidence["ignoredWorkloads"] = ignored
	if len(remaining) == 0 {
		return markIgnored(result, reason)
	}
	result.Summary = strings.Replace(result.Summary, fmt.Sprintf("%d Docker workload(s)", len(workloads)), fmt.Sprintf("%d Docker workload(s)", len(remaining)), 1)
	return result
}

func markIgnored(result CheckResult, reason string) CheckResult {
	result.Ignored = true
	result.IgnoreReason = reason
	result.Status = Passed
	if result.Evidence == nil {
		result.Evidence = map[string]any{}
	}
	result.Evidence["ignored"] = true
	return result
}

func JSON(report Report) string {
	report.Level = EvidenceLevel(report.Checks)
	report.Coverage = SummarizeCoverage(report.Checks)
	report.Validated = ChecksValidated(report.Checks)
	raw, _ := json.MarshalIndent(report, "", "  ")
	return string(raw)
}

func checkOSSupported(adapter execx.Adapter) CheckResult {
	res := adapter.Run("cat /etc/os-release", 3*time.Second)
	out := res.Stdout
	id := capture(out, `(?m)^ID="?([^"\n]+)"?`)
	version := capture(out, `(?m)^VERSION_ID="?([^"\n]+)"?`)
	supported := (id == "ubuntu" && version == "24.04") || (id == "debian" && version == "13")
	status := Passed
	if !supported {
		status = Failed
	}
	if res.ExitCode != 0 {
		status = Unknown
	}
	return CheckResult{ID: "system.os_supported", Title: "Operating system is supported", Category: "system", Severity: High, Status: status, Summary: fmt.Sprintf("%s %s", fallback(id, "unknown"), fallback(version, "unknown")), Remediation: "Use Ubuntu 24.04 or Debian 13.", Evidence: map[string]any{"id": id, "version": version}}
}

func checkDiskSpace(adapter execx.Adapter) CheckResult {
	res := adapter.Run(pipefailCommand("df -Pk / | awk 'NR==2 {print $5}'"), 3*time.Second)
	usage, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(res.Stdout), "%"))
	if res.ExitCode != 0 || err != nil || usage < 0 || usage > 100 {
		return collectionUnavailable("system.disk_space_low", "Disk space has enough free capacity", "system", Medium)
	}
	status := Passed
	severity := Medium
	if usage >= 90 {
		status = Failed
		severity = Critical
	} else if usage >= 80 {
		status = Failed
	}
	return CheckResult{ID: "system.disk_space_low", Title: "Disk space has enough free capacity", Category: "system", Severity: severity, Status: status, Summary: fmt.Sprintf("Root filesystem usage is %d%%.", usage), Remediation: "Free disk space, prune unused Docker resources, or increase VPS disk size.", Evidence: map[string]any{"usagePercent": usage}}
}

func checkDockerInstalled(adapter execx.Adapter) CheckResult {
	res := adapter.Run("command -v docker && docker --version", 3*time.Second)
	status := Passed
	summary := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 {
		status = Failed
		summary = "Docker is not installed or not available in PATH."
	}
	return CheckResult{ID: "docker.not_installed", Title: "Docker is installed", Category: "docker", Severity: High, Status: status, Summary: summary, Remediation: "Install Docker Engine before running production Docker workloads."}
}

func checkDockerServiceEnabled(adapter execx.Adapter) CheckResult {
	res := adapter.Run("systemctl is-enabled docker 2>/dev/null && systemctl is-active docker 2>/dev/null", 3*time.Second)
	lines := nonEmptyLines(res.Stdout)
	enabled := len(lines) > 0 && lines[0] == "enabled"
	active := len(lines) > 1 && lines[1] == "active"
	status := Passed
	if !enabled || !active {
		status = Failed
	}
	return CheckResult{
		ID:          "docker.service_not_enabled",
		Title:       "Docker service is enabled and active",
		Category:    "docker",
		Severity:    High,
		Status:      status,
		Summary:     ternary(status == Passed, "Docker service is enabled on boot and active.", "Docker service is not enabled on boot or not active."),
		Remediation: "Run systemctl enable --now docker on systemd hosts.",
		Evidence: map[string]any{
			"enabled": enabled,
			"active":  active,
		},
	}
}

func checkDockerRestartPolicies(adapter execx.Adapter) CheckResult {
	res := adapter.Run(dockerRuntimeCommand(
		"for id in $(docker service ls -q); do docker service inspect --format '{{.Spec.Name}}\t{{.Spec.TaskTemplate.RestartPolicy.Condition}}' \"$id\"; done",
		dockerClassicInspectCommand("{{.Name}}\t{{.HostConfig.RestartPolicy.Name}}"),
	), 5*time.Second)
	if res.ExitCode != 0 || !validRuntimeEvidence(res.Stdout) {
		return collectionUnavailable("docker.containers_without_restart_policy", "Docker workloads have restart policies", "docker", High)
	}
	mode, body := splitRuntimeOutput(res.Stdout)
	missing := []string{}
	for _, line := range nonEmptyLines(body) {
		name, policy := splitTab2(line)
		policy = strings.TrimSpace(policy)
		if !listContains([]string{"", "no", "none", "always", "unless-stopped", "on-failure", "any"}, policy) {
			return collectionUnavailable("docker.containers_without_restart_policy", "Docker workloads have restart policies", "docker", High)
		}
		if policy == "" || policy == "no" || policy == "none" {
			missing = append(missing, strings.TrimPrefix(name, "/"))
		}
	}
	status := Passed
	if len(missing) > 0 {
		status = Failed
	}
	return CheckResult{
		ID:          "docker.containers_without_restart_policy",
		Title:       "Docker workloads have restart policies",
		Category:    "docker",
		Severity:    High,
		Status:      status,
		Summary:     ternary(len(missing) == 0, "All Docker workloads have restart policies.", fmt.Sprintf("%d Docker workload(s) lack restart policy.", len(missing))),
		Remediation: "For Docker classic, set restart: unless-stopped/always. For Swarm, set deploy.restart_policy.condition to on-failure or any.",
		Evidence: map[string]any{
			"runtimeMode": mode,
			"workloads":   missing,
		},
	}
}

func checkDockerHealthchecks(adapter execx.Adapter) CheckResult {
	res := adapter.Run(dockerRuntimeCommand(
		"for id in $(docker service ls -q); do docker service inspect --format '{{.Spec.Name}}\t{{json .Spec.TaskTemplate.ContainerSpec.Healthcheck}}' \"$id\"; done",
		dockerClassicInspectCommand("{{.Name}}\t{{json .Config.Healthcheck}}"),
	), 5*time.Second)
	if res.ExitCode != 0 || !validRuntimeEvidence(res.Stdout) {
		return collectionUnavailable("docker.containers_without_healthcheck", "Docker workloads have healthchecks", "docker", Medium)
	}
	mode, body := splitRuntimeOutput(res.Stdout)
	missing := []string{}
	for _, line := range nonEmptyLines(body) {
		name, health := splitTab2(line)
		if health != "" && !json.Valid([]byte(health)) {
			return collectionUnavailable("docker.containers_without_healthcheck", "Docker workloads have healthchecks", "docker", Medium)
		}
		if healthMissing(health) {
			missing = append(missing, strings.TrimPrefix(name, "/"))
		}
	}
	status := Passed
	if len(missing) > 0 {
		status = Failed
	}
	return CheckResult{
		ID:          "docker.containers_without_healthcheck",
		Title:       "Docker workloads have healthchecks",
		Category:    "docker",
		Severity:    Medium,
		Status:      status,
		Summary:     ternary(len(missing) == 0, "All Docker workloads have healthchecks.", fmt.Sprintf("%d Docker workload(s) lack healthchecks.", len(missing))),
		Remediation: "Add Docker HEALTHCHECK instructions or compose/swarm healthcheck definitions for web apps and stateful services. Workers can use command-level health probes or be explicitly documented.",
		Evidence: map[string]any{
			"runtimeMode": mode,
			"workloads":   missing,
		},
	}
}

// resolveImageUserPipeline reads "name|user|image" rows and fills in the user
// from the image config whenever the workload spec left it empty. It emits the
// "name<TAB>user" shape the caller parses.
//
// The separator is deliberately not a tab: a tab is IFS whitespace, so a run of
// them collapses into a single delimiter and an empty user field would silently
// shift the image into the user column. That turned the check into a false
// negative for exactly the root workloads it exists to catch. Neither Docker
// workload names nor image references can contain a pipe.
const resolveImageUserPipeline = "while IFS='|' read -r name user image; do " +
	"if [ -z \"$user\" ] && [ -n \"$image\" ]; then user=$(docker image inspect --format '{{.Config.User}}' \"$image\") || exit; fi; " +
	"printf '%s\t%s\n' \"$name\" \"$user\"; done"

func checkDockerRunningAsRoot(adapter execx.Adapter) CheckResult {
	// An empty user on the service or container spec only means the stack did not
	// override it: a Dockerfile USER directive still applies and is the value the
	// workload actually runs as. Resolving the image config avoids reporting every
	// correctly built image as root, which is what the remediation asks for.
	res := adapter.Run(dockerRuntimeCommand(
		"for id in $(docker service ls -q); do docker service inspect --format '{{.Spec.Name}}|{{.Spec.TaskTemplate.ContainerSpec.User}}|{{.Spec.TaskTemplate.ContainerSpec.Image}}' \"$id\"; done | "+resolveImageUserPipeline,
		dockerClassicInspectCommand("{{.Name}}|{{.Config.User}}|{{.Image}}")+" | "+resolveImageUserPipeline,
	), 15*time.Second)
	if res.ExitCode != 0 || !validRuntimeEvidence(res.Stdout) {
		return collectionUnavailable("docker.containers_running_as_root", "Docker workloads do not run as root", "docker", Medium)
	}
	mode, body := splitRuntimeOutput(res.Stdout)
	rootWorkloads := []string{}
	for _, line := range nonEmptyLines(body) {
		name, user := splitTab2(line)
		user = strings.TrimSpace(user)
		uid, _, _ := strings.Cut(user, ":")
		if uid == "" || uid == "0" || uid == "root" {
			rootWorkloads = append(rootWorkloads, strings.TrimPrefix(name, "/"))
		}
	}
	status := Passed
	if len(rootWorkloads) > 0 {
		status = Failed
	}
	return CheckResult{
		ID:          "docker.containers_running_as_root",
		Title:       "Docker workloads do not run as root",
		Category:    "docker",
		Severity:    Medium,
		Status:      status,
		Summary:     ternary(len(rootWorkloads) == 0, "No Docker workload appears to run as root.", fmt.Sprintf("%d Docker workload(s) appear to run as root.", len(rootWorkloads))),
		Remediation: "Set USER in Dockerfiles or service/container user fields for application workloads. Some trusted infrastructure images may need an explicit ignore later.",
		Evidence: map[string]any{
			"runtimeMode": mode,
			"workloads":   rootWorkloads,
		},
	}
}

func checkDockerSockExposed(adapter execx.Adapter) CheckResult {
	res := adapter.Run(dockerRuntimeCommand(
		"for id in $(docker service ls -q); do docker service inspect --format '{{.Spec.Name}}\t{{json .Spec.TaskTemplate.ContainerSpec.Mounts}}' \"$id\"; done",
		dockerClassicInspectCommand("{{.Name}}\t{{json .Mounts}}"),
	), 5*time.Second)
	if res.ExitCode != 0 || !validRuntimeEvidence(res.Stdout) {
		return collectionUnavailable("docker.sock_exposed", "Docker socket is not exposed to workloads", "docker", High)
	}
	mode, body := splitRuntimeOutput(res.Stdout)
	exposed := []string{}
	readWrite := []string{}
	for _, line := range nonEmptyLines(body) {
		name, mounts := splitTab2(line)
		var parsedMounts []struct {
			Source   string
			ReadOnly bool
			RW       *bool
		}
		if json.Unmarshal([]byte(mounts), &parsedMounts) != nil {
			return collectionUnavailable("docker.sock_exposed", "Docker socket is not exposed to workloads", "docker", High)
		}
		socket, writable := false, false
		for _, mount := range parsedMounts {
			if mount.Source == "/var/run/docker.sock" || mount.Source == "/run/docker.sock" {
				socket = true
				writable = writable || (!mount.ReadOnly && (mount.RW == nil || *mount.RW))
			}
		}
		if !socket {
			continue
		}
		cleanName := strings.TrimPrefix(name, "/")
		exposed = append(exposed, cleanName)
		if writable {
			readWrite = append(readWrite, cleanName)
		}
	}
	status := Passed
	severity := High
	if len(exposed) > 0 {
		status = Failed
	}
	if len(readWrite) > 0 {
		severity = Critical
	}
	return CheckResult{
		ID:          "docker.sock_exposed",
		Title:       "Docker socket is not exposed to workloads",
		Category:    "docker",
		Severity:    severity,
		Status:      status,
		Summary:     ternary(len(exposed) == 0, "No Docker workload mounts /var/run/docker.sock.", fmt.Sprintf("%d Docker workload(s) mount /var/run/docker.sock.", len(exposed))),
		Remediation: "Avoid mounting the Docker socket. If needed for tools like Dozzle/Uptime Kuma, keep it read-only, IP-restricted, and explicitly documented.",
		Evidence: map[string]any{
			"runtimeMode":        mode,
			"workloads":          exposed,
			"readWriteWorkloads": readWrite,
		},
	}
}

func checkUFWActive(adapter execx.Adapter) CheckResult {
	res := adapter.Run("command -v ufw >/dev/null 2>&1 && ufw status", 3*time.Second)
	active := res.ExitCode == 0 && regexp.MustCompile(`(?mi)^Status:\s+active$`).MatchString(res.Stdout)
	status := Failed
	if active {
		status = Passed
	}
	return CheckResult{ID: "firewall.ufw_inactive", Title: "UFW firewall is active", Category: "firewall", Severity: High, Status: status, Summary: ternary(active, "UFW is active.", "UFW is missing or inactive."), Remediation: "Enable a firewall with SSH, HTTP and HTTPS explicitly allowed.", AutoFixAvailable: true}
}

func checkDatabasePorts(adapter execx.Adapter) CheckResult {
	res := adapter.Run("if command -v ss >/dev/null 2>&1; then ss -ltnp || exit; elif command -v netstat >/dev/null 2>&1; then netstat -ltnp || exit; else exit 127; fi; printf '\\n---UFW---\\n'; command -v ufw >/dev/null 2>&1 && ufw status verbose || true", 3*time.Second)
	listenerText, firewallText, _ := strings.Cut(res.Stdout, "\n---UFW---\n")
	if res.ExitCode != 0 || !validListenerEvidence(listenerText) {
		return collectionUnavailable("firewall.database_port_public", "Sensitive database ports are not public", "firewall", Critical)
	}
	listeners := publicDatabaseListeners(listenerText)
	ports := uniqueListenerPorts(listeners)
	status := Passed
	severity := Critical
	summary := "No public sensitive database listeners detected."
	remediation := "Bind databases to localhost/private Docker networks and close public database ports."
	firewallRestricted := databasePortsFirewallRestricted(firewallText, ports)
	if len(ports) > 0 {
		status = Failed
		if firewallRestricted {
			severity = High
			summary = "Sensitive database listeners bind public interfaces, but UFW appears to restrict public access: " + strings.Join(ports, ", ") + "."
			remediation = "Prefer binding databases to localhost or a private Docker bridge. Keep UFW allowing DB access only from the API/Adminer network or explicit admin IPs."
		} else {
			summary = "Public sensitive database listeners detected: " + strings.Join(ports, ", ") + "."
			remediation = "Do not expose PostgreSQL/MySQL/Redis/Admin databases to the Internet. Bind to localhost/private Docker networks or restrict the port to trusted API/Adminer sources only."
		}
	}
	return CheckResult{
		ID:          "firewall.database_port_public",
		Title:       "Sensitive database ports are not public",
		Category:    "firewall",
		Severity:    severity,
		Status:      status,
		Summary:     summary,
		Remediation: remediation,
		Evidence: map[string]any{
			"publicPorts":          ports,
			"listeners":            listeners,
			"firewallRestricted":   firewallRestricted,
			"expectedAccessModel":  "API/Adminer may access DB through localhost/private network or explicit allowlist; the DB port should not be reachable from the Internet.",
			"firewallStatusSample": strings.TrimSpace(firewallText),
		},
	}
}

func checkEnvWorldReadable(adapter execx.Adapter) CheckResult {
	probe := adapter.Run("if [ -f .env ]; then printf present; else printf absent; fi", time.Second)
	if probe.ExitCode != 0 || (probe.Stdout != "present" && probe.Stdout != "absent") {
		return collectionUnavailable("secrets.env_world_readable", ".env is not world-readable", "secrets", Critical)
	}
	if probe.Stdout == "absent" {
		return CheckResult{ID: "secrets.env_world_readable", Title: ".env is not world-readable", Category: "secrets", Severity: Critical, Status: Skipped, SkipReason: NotApplicable, Summary: "No .env file is present."}
	}
	res := adapter.Run("stat -c '%a' .env 2>/dev/null || stat -f '%Lp' .env", time.Second)
	mode := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 || !regexp.MustCompile(`^[0-7]{3,4}$`).MatchString(mode) {
		return collectionUnavailable("secrets.env_world_readable", ".env is not world-readable", "secrets", Critical)
	}
	worldReadable := strings.HasSuffix(mode, "4") || strings.HasSuffix(mode, "5") || strings.HasSuffix(mode, "6") || strings.HasSuffix(mode, "7")
	status := Passed
	if worldReadable {
		status = Failed
	}
	return CheckResult{ID: "secrets.env_world_readable", Title: ".env is not world-readable", Category: "secrets", Severity: Critical, Status: status, Summary: "Current .env permissions: " + mode + ".", Remediation: "Run chmod 600 .env and keep secrets out of shared-readable files.", AutoFixAvailable: true}
}

func checkEnvTracked(adapter execx.Adapter) CheckResult {
	res := adapter.Run("if [ ! -e .git ]; then printf __no_git__; else git ls-files -- .env; fi", time.Second)
	if res.ExitCode != 0 {
		return collectionUnavailable("secrets.env_in_git", ".env is not tracked by Git", "secrets", Critical)
	}
	if res.Stdout == "__no_git__" {
		return CheckResult{ID: "secrets.env_in_git", Title: ".env is not tracked by Git", Category: "secrets", Severity: Critical, Status: Skipped, SkipReason: NotApplicable, Summary: "The audit directory contains no Git checkout; source history was not inspected."}
	}
	tracked := strings.TrimSpace(res.Stdout) != ""
	status := Passed
	if tracked {
		status = Failed
	}
	return CheckResult{ID: "secrets.env_in_git", Title: ".env is not tracked by Git", Category: "secrets", Severity: Critical, Status: status, Summary: ternary(tracked, ".env is tracked by Git.", ".env is not tracked by Git."), Remediation: "Remove .env from Git history/tracking and keep .env in .gitignore."}
}

func checkCaddyInstalled(adapter execx.Adapter) CheckResult {
	res := adapter.Run("command -v caddy >/dev/null 2>&1 || docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^caddy$|caddy'", 3*time.Second)
	installed := res.ExitCode == 0
	status := Failed
	if installed {
		status = Passed
	}
	return CheckResult{ID: "caddy.not_installed", Title: "Caddy or Caddy container is present", Category: "reverse-proxy", Severity: Medium, Status: status, Summary: ternary(installed, "Caddy was detected.", "No Caddy binary or running Caddy container detected."), Remediation: "Install/configure Caddy or another reverse proxy before exposing the app."}
}

func checkCaddyAdminExposed(adapter execx.Adapter) CheckResult {
	res := adapter.Run("if command -v ss >/dev/null 2>&1; then ss -ltnp || exit; elif command -v netstat >/dev/null 2>&1; then netstat -ltnp || exit; else exit 127; fi", 3*time.Second)
	if res.ExitCode != 0 || !validListenerEvidence(res.Stdout) {
		return collectionUnavailable("caddy.admin_exposed", "Caddy admin API is not publicly exposed", "reverse-proxy", Critical)
	}
	exposed := []string{}
	for _, line := range nonEmptyLines(res.Stdout) {
		if !regexp.MustCompile(`(?::|\]:)2019\b`).MatchString(line) {
			continue
		}
		if publicListenerPort(line, "2019") {
			exposed = append(exposed, line)
		}
	}
	status := Passed
	if len(exposed) > 0 {
		status = Failed
	}
	return CheckResult{
		ID:          "caddy.admin_exposed",
		Title:       "Caddy admin API is not publicly exposed",
		Category:    "reverse-proxy",
		Severity:    Critical,
		Status:      status,
		Summary:     ternary(len(exposed) == 0, "No public Caddy admin listener detected.", "Caddy admin API appears to listen on a public interface."),
		Remediation: "Bind Caddy admin API to localhost, disable it when unused, or keep it on an internal-only network.",
		Evidence: map[string]any{
			"listeners": exposed,
		},
	}
}

func checkAdminerRestricted(adapter execx.Adapter) CheckResult {
	detected := adapter.Run("docker ps --format '{{.Names}}\t{{.Image}}'", 3*time.Second)
	if detected.ExitCode != 0 {
		return collectionUnavailable("adminer.ip_restriction_missing", "Adminer is IP restricted", "database", High)
	}
	for _, line := range nonEmptyLines(detected.Stdout) {
		if len(strings.Split(line, "\t")) != 2 {
			return collectionUnavailable("adminer.ip_restriction_missing", "Adminer is IP restricted", "database", High)
		}
	}
	if !strings.Contains(strings.ToLower(detected.Stdout), "adminer") {
		return CheckResult{ID: "adminer.ip_restriction_missing", Title: "Adminer is IP restricted", Category: "database", Severity: High, Status: Skipped, SkipReason: NotApplicable, Summary: "No running Adminer container was found."}
	}
	config := adapter.Run(pipefailCommand("grep -Rih --include='*.caddy' --include='Caddyfile' 'adminer\\|remote_ip\\|client_ip\\|basic_auth\\|respond .*403' /etc/caddy /opt/caddy 2>/dev/null | sed -n '1,200p'"), 3*time.Second)
	if config.ExitCode != 0 {
		return collectionUnavailable("adminer.ip_restriction_missing", "Adminer is IP restricted", "database", High)
	}
	text := config.Stdout
	hasIPRestriction := regexp.MustCompile(`(?i)(remote_ip|client_ip)`).MatchString(text)
	hasDeny := regexp.MustCompile(`(?i)(respond\s+.*403|abort|deny)`).MatchString(text)
	hasAuth := regexp.MustCompile(`(?i)basic_auth`).MatchString(text)
	status := Skipped
	summary := "Restriction directives exist, but their association with the Adminer route and deny-by-default behavior could not be verified."
	if !hasIPRestriction || !hasDeny {
		status = Failed
		summary = "Adminer is running, but no clear IP restriction/deny rule was detected in Caddy config."
	}
	return CheckResult{
		ID:       "adminer.ip_restriction_missing",
		Title:    "Adminer is IP restricted",
		Category: "database",
		Severity: High,
		Status:   status,
		SkipReason: func() string {
			if status == Skipped {
				return EvidenceUnavailable
			}
			return ""
		}(),
		Summary:     summary,
		Remediation: "Expose Adminer only behind the reverse proxy with an allowlist for your home IP, deny-by-default behavior, and basic auth. Do not publish Adminer directly with Docker ports.",
		Evidence: map[string]any{
			"adminerContainer": strings.TrimSpace(detected.Stdout),
			"ipRestriction":    hasIPRestriction,
			"denyRule":         hasDeny,
			"basicAuth":        hasAuth,
		},
	}
}

func publicDatabaseListeners(output string) []map[string]string {
	listeners := []map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, port := range []string{"5432", "3306", "6379", "7700", "9200", "27017"} {
			if !regexp.MustCompile(`(?::|\]:)` + port + `\b`).MatchString(line) {
				continue
			}
			if !publicListenerPort(line, port) {
				continue
			}
			process := capture(line, `users:\(\("([^"]+)`)
			if process == "" {
				process = capture(line, `\b([a-zA-Z0-9._-]+)\s*$`)
			}
			listeners = append(listeners, map[string]string{
				"port":    port,
				"process": fallback(process, "unknown"),
				"line":    line,
			})
		}
	}
	return listeners
}

func localListenerEndpoint(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return ""
	}
	switch {
	case fields[0] == "LISTEN":
		return fields[3] // ss -ltnp
	case len(fields) >= 6 && fields[1] == "LISTEN":
		return fields[4] // ss with Netid
	case len(fields) >= 6 && (fields[0] == "tcp" || fields[0] == "tcp6") && fields[5] == "LISTEN":
		return fields[3] // netstat
	}
	return ""
}

func validListenerEvidence(body string) bool {
	seen := false
	for _, line := range nonEmptyLines(body) {
		if strings.Contains(line, "Local Address") {
			seen = true
			continue
		}
		if strings.HasPrefix(line, "Active Internet connections") {
			continue
		}
		endpoint := localListenerEndpoint(line)
		_, port, ok := strings.Cut(endpoint, ":")
		// IPv6 addresses may contain several colons; the last component is the port.
		if idx := strings.LastIndex(endpoint, ":"); idx >= 0 {
			port = endpoint[idx+1:]
			ok = true
		}
		n, err := strconv.Atoi(port)
		if endpoint == "" || !ok || err != nil || n < 1 || n > 65535 {
			return false
		}
		seen = true
	}
	return seen
}

func publicListenerPort(line, port string) bool {
	endpoint := localListenerEndpoint(line)
	if !strings.HasSuffix(endpoint, ":"+port) {
		return false
	}
	host := strings.Trim(strings.TrimSuffix(endpoint, ":"+port), "[]")
	if host == "*" {
		return true
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && !privateDockerBindAddress(host)
}

func uniqueListenerPorts(listeners []map[string]string) []string {
	seen := map[string]bool{}
	ports := []string{}
	for _, listener := range listeners {
		port := listener["port"]
		if port == "" || seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return ports
}

func databasePortsFirewallRestricted(firewallText string, ports []string) bool {
	if len(ports) == 0 {
		return false
	}
	if !regexp.MustCompile(`(?mi)^Status:\s+active$`).MatchString(firewallText) {
		return false
	}
	if !regexp.MustCompile(`(?mi)^Default:\s+deny\s+\(incoming\)`).MatchString(firewallText) {
		return false
	}
	for _, port := range ports {
		publicAllow := regexp.MustCompile(`(?mi)^` + regexp.QuoteMeta(port) + `(?:/tcp)?\s+ALLOW IN\s+Anywhere(?:\s|$)|^` + regexp.QuoteMeta(port) + `(?:/tcp)?\s+ALLOW IN\s+0\.0\.0\.0/0(?:\s|$)|^` + regexp.QuoteMeta(port) + `(?:/tcp)?\s+\(v6\)\s+ALLOW IN\s+Anywhere`)
		if publicAllow.MatchString(firewallText) {
			return false
		}
	}
	return true
}

func dockerRuntimeCommand(swarmCommand string, classicCommand string) string {
	swarmCommand = strings.ReplaceAll(swarmCommand, "for id in $(docker service ls -q); do", "ids=$(docker service ls -q) || exit; for id in $ids; do")
	command := "control=$(docker info --format '{{.Swarm.ControlAvailable}}') || exit; case \"$control\" in true|false) ;; *) exit 65 ;; esac; if [ \"$control\" = true ]; then echo __shuttle_runtime=swarm; " + swarmCommand + "; fi; echo __shuttle_runtime=classic; " + classicCommand
	return "bash -o pipefail -ec " + shellQuote(command)
}

// BSD xargs, shipped by macOS, has no GNU -r flag. Reading container IDs in a
// POSIX shell loop also avoids invoking docker inspect when the list is empty.
func dockerClassicInspectCommand(format string) string {
	return "docker ps -q | while IFS= read -r id; do [ -n \"$id\" ] || continue; managed=$(docker inspect --format '{{if index .Config.Labels \"com.docker.swarm.service.name\"}}yes{{else}}no{{end}}' \"$id\") || exit; if [ \"$managed\" = no ]; then docker inspect --format '" + format + "' \"$id\" || exit; fi; done"
}

func validRuntimeEvidence(output string) bool {
	seen := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.Trim(raw, "\r ")
		if line == "" {
			continue
		}
		if line == "__shuttle_runtime=swarm" || line == "__shuttle_runtime=classic" {
			seen = true
			continue
		}
		name, _, ok := strings.Cut(line, "\t")
		if !seen || !ok || strings.TrimSpace(name) == "" {
			return false
		}
	}
	return seen
}

func splitRuntimeOutput(output string) (string, string) {
	seen := map[string]bool{}
	bodyLines := []string{}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "__shuttle_runtime=") {
			seen[strings.TrimPrefix(line, "__shuttle_runtime=")] = true
			continue
		}
		bodyLines = append(bodyLines, line)
	}
	mode := "classic"
	if seen["swarm"] && seen["classic"] {
		mode = "mixed"
	} else if seen["swarm"] {
		mode = "swarm"
	}
	return mode, strings.Join(bodyLines, "\n")
}

func splitTab2(line string) (string, string) {
	left, right, ok := strings.Cut(line, "\t")
	if !ok {
		return strings.TrimSpace(line), ""
	}
	return strings.TrimSpace(left), strings.TrimSpace(right)
}

func healthMissing(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == "null" {
		return true
	}
	var health struct{ Test []string }
	if json.Unmarshal([]byte(value), &health) != nil || len(health.Test) == 0 {
		return true
	}
	return health.Test[0] == "NONE" || (health.Test[0] != "CMD" && health.Test[0] != "CMD-SHELL") || len(health.Test) < 2
}

func nonEmptyLines(value string) []string {
	lines := []string{}
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func listContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func evidenceStringSlice(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		return typed, true
	case []any:
		values := []string{}
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			values = append(values, text)
		}
		return values, true
	default:
		return nil, false
	}
}

func matchesAnyWorkload(workload string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchesWorkload(workload, pattern) {
			return true
		}
	}
	return false
}

func matchesWorkload(workload string, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == workload {
		return true
	}
	if strings.HasSuffix(pattern, "*") && strings.HasPrefix(workload, strings.TrimSuffix(pattern, "*")) {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(workload, strings.TrimPrefix(pattern, "*")) {
		return true
	}
	return false
}

func capture(input string, pattern string) string {
	matches := regexp.MustCompile(pattern).FindStringSubmatch(input)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func fallback(value string, def string) string {
	if value == "" {
		return def
	}
	return value
}

func ternary(condition bool, yes string, no string) string {
	if condition {
		return yes
	}
	return no
}
