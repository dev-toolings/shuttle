package readiness

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

// Every probe below asks sudo only when it is not already root. The root
// helper's monitoring unit runs them as root under NoNewPrivileges and
// ProtectSystem=strict, where `sudo -n true` cannot read /etc/sudoers: on
// demo prod (2026-10-28) each one-minute run logged 3 to 4 "unable to open
// /etc/sudoers : Operation not permitted" lines, then sudo's failed mail to
// root added exim "Permission denied" lines. Root needs no sudo at all.
const privateSSHDCommand = "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; command -v sshd >/dev/null 2>&1 || exit 127; if [ $(id -u) != 0 ] && sudo -n true >/dev/null 2>&1; then exec sudo -n sshd -T; fi; exec sshd -T"

const privateUFWStatusCommand = "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; command -v ufw >/dev/null 2>&1 || exit 127; if [ $(id -u) != 0 ] && sudo -n true >/dev/null 2>&1; then exec sudo -n ufw status; fi; exec ufw status"

// dockerUserPolicyCommand is intentionally read-only. Docker inserts the
// DOCKER-USER chain ahead of its own forwarding chains, but a terminal RETURN
// there can bypass UFW unless UFW's before-forward policy is called first. The
// marker makes the privilege path visible in doctor evidence without making a
// second probe (which could race with a ruleset reload).
// A Docker bridge with no global IPv6 address cannot forward IPv6 to any
// container, so an empty IPv6 DOCKER-USER chain guards nothing on such a host.
// Reading /sys and ip(8) keeps this cheap: no docker daemon call is made, so the
// probe stays inside the read-only budget of the surrounding check.
const dockerUserPolicyCommand = `PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; probe() { family="$1"; binary="$2"; printf '__shuttle_family=%s\n' "$family"; if ! command -v "$binary" >/dev/null 2>&1; then echo __shuttle_unavailable=1; return 0; fi; if [ $(id -u) != 0 ] && sudo -n true >/dev/null 2>&1; then echo __shuttle_privilege=sudo-n; sudo -n "$binary" -S DOCKER-USER || echo __shuttle_unavailable=1; return 0; fi; echo __shuttle_privilege=direct; "$binary" -S DOCKER-USER || echo __shuttle_unavailable=1; }; count=0; interfaces=$(ls /sys/class/net) || exit; for iface in $interfaces; do case "$iface" in docker*|br-*) addresses=$(ip -6 addr show dev "$iface" scope global) || exit; case "$addresses" in *inet6*) count=1 ;; esac ;; esac; done; printf '__shuttle_docker_ipv6=%s\n' "$count"; probe ipv4 iptables; probe ipv6 ip6tables`

const dockerPublicPortsCommand = `set -eu; docker info >/dev/null 2>&1; docker ps --format 'classic	{{.Names}}	{{.Ports}}'; control=$(docker info --format '{{.Swarm.ControlAvailable}}') || exit; case "$control" in true|false) ;; *) exit 65 ;; esac; if [ "$control" = true ]; then ids=$(docker service ls -q) || exit; for id in $ids; do docker service inspect --format 'swarm	{{.Spec.Name}}	{{json .Endpoint.Spec.Ports}}' "$id" || exit; done; fi`

var (
	dockerUserChainPattern  = regexp.MustCompile(`(?i)^(?:-N\s+DOCKER-USER\b|Chain\s+DOCKER-USER\b|-[AI]\s+DOCKER-USER\b)`)
	dockerUserTargetPattern = regexp.MustCompile(`(?i)(?:--?jump|-j|--?goto|-g)\s+(\S+)(?:\s|$)`)
)

type swarmPublishedPort struct {
	Protocol      string `json:"Protocol"`
	PublishedPort int    `json:"PublishedPort"`
	PublishMode   string `json:"PublishMode"`
}

type dockerUserFamilyProbe struct {
	rules       string
	privilege   string
	unavailable bool
}

func privateAccessConfigured(access AccessConfig) bool {
	mode := strings.ToLower(strings.TrimSpace(access.Mode))
	return access.Private || mode == "private-vps" || mode == "private-tailscale" || access.DeployUser != "" || len(access.AllowedSSHUsers) > 0 || access.TailscaleInterface != "" || len(access.AllowedPublicTCPPorts) > 0 || access.TailscaleSSH != nil || access.TailscaleAutoUpdate != nil
}

func privateTailscaleConfigured(access AccessConfig) bool {
	mode := strings.ToLower(strings.TrimSpace(access.Mode))
	return access.Private || mode == "private-vps" || mode == "private-tailscale" || access.TailscaleInterface != "" || access.TailscaleSSH != nil || access.TailscaleAutoUpdate != nil
}

func expectedTailscaleInterface(access AccessConfig) string {
	if value := strings.TrimSpace(access.TailscaleInterface); value != "" {
		return value
	}
	return "tailscale0"
}

func expectedSSHUsers(access AccessConfig) []string {
	if len(access.AllowedSSHUsers) > 0 {
		return normalizedStrings(access.AllowedSSHUsers)
	}
	if access.DeployUser != "" {
		return []string{access.DeployUser}
	}
	return nil
}

// checkDockerUserPolicy proves that Docker's filter hook exists and that it
// gives UFW's user-forward policy a chance before a Docker RETURN path. It
// never changes the ruleset. A missing chain or hook is a finding; inability
// to inspect the ruleset with the available privilege is skipped explicitly.
func checkDockerUserPolicy(adapter execx.Adapter) CheckResult {
	res := adapter.Run(dockerUserPolicyCommand, 3*time.Second)
	families, dockerIPv6 := parseDockerUserProbeOutput(res.Stdout)
	privilege := "unknown"
	for _, family := range families {
		if privilege == "unknown" || family.privilege == "sudo-n" {
			privilege = family.privilege
		}
	}
	evidence := map[string]any{
		"command":   "iptables -S DOCKER-USER and ip6tables -S DOCKER-USER",
		"privilege": privilege,
		"stdout":    strings.TrimSpace(res.Stdout),
	}
	if strings.TrimSpace(res.Stderr) != "" {
		evidence["stderr"] = strings.TrimSpace(res.Stderr)
	}
	if res.ExitCode == 127 || dockerUserPrivilegeError(res) || len(families) != 2 {
		return CheckResult{
			ID: "firewall.docker_user_policy", Title: "Docker forwards traffic through UFW before returning",
			Category: "firewall", Severity: High, Status: Skipped,
			Summary:     "Cannot inspect the DOCKER-USER chain with the available privilege.",
			Details:     strings.TrimSpace(res.Stderr),
			Remediation: "Run the readiness check as root or grant non-interactive sudo for read-only iptables inspection.",
			Evidence:    evidence,
		}
	}
	familyEvidence := map[string]any{}
	allChainPresent, allUFWForward, allBeforeReturn := true, true, true
	returnPathCount := 0
	for _, name := range []string{"ipv4", "ipv6"} {
		family := families[name]
		if family.unavailable {
			return CheckResult{ID: "firewall.docker_user_policy", Title: "Docker forwards traffic through UFW before returning", Category: "firewall", Severity: High, Status: Skipped, Summary: fmt.Sprintf("Cannot inspect the %s DOCKER-USER chain because its iptables backend is unavailable.", name), Remediation: "Install the active IPv4 and IPv6 iptables backends or run the readiness check where both filter families are inspectable.", Evidence: evidence}
		}
		chainPresent, ufwForward, ufwBeforeReturn, returnPaths, unsafePaths := dockerUserPolicyOrder(family.rules, name)
		convention := "shuttle"
		switch {
		case ufwForward && ufwBeforeReturn:
		case dockerUserUFWDockerPolicy(family.rules, name):
			ufwForward, ufwBeforeReturn, unsafePaths = true, true, nil
			convention = "ufw-docker"
		case name == "ipv6" && !dockerIPv6 && dockerUserChainIsEmpty(family.rules):
			// No Docker bridge carries a global IPv6 address, so no container is
			// reachable over IPv6 and the empty chain guards nothing.
			ufwForward, ufwBeforeReturn = true, true
			convention = "ipv6-inactive"
		}
		familyEvidence[name] = map[string]any{"chainPresent": chainPresent, "ufwForwardPolicy": ufwForward, "ufwForwardBeforeReturn": ufwBeforeReturn, "returnPaths": returnPaths, "unsafeControlFlow": unsafePaths, "privilege": family.privilege, "convention": convention}
		allChainPresent = allChainPresent && chainPresent
		allUFWForward = allUFWForward && ufwForward
		allBeforeReturn = allBeforeReturn && ufwBeforeReturn
		returnPathCount += len(returnPaths)
	}
	evidence["families"] = familyEvidence
	evidence["chainPresent"] = allChainPresent
	evidence["ufwForwardPolicy"] = allUFWForward
	evidence["ufwForwardBeforeReturn"] = allBeforeReturn
	if !allChainPresent {
		return CheckResult{
			ID: "firewall.docker_user_policy", Title: "Docker forwards traffic through UFW before returning",
			Category: "firewall", Severity: High, Status: Failed,
			Summary:     "Docker's DOCKER-USER chain is absent in at least one active IP family.",
			Remediation: "Enable Docker iptables integration so DOCKER-USER exists, then route it through ufw-before-forward before its RETURN rule.",
			Evidence:    evidence,
		}
	}
	if !allUFWForward {
		return CheckResult{
			ID: "firewall.docker_user_policy", Title: "Docker forwards traffic through UFW before returning",
			Category: "firewall", Severity: High, Status: Failed,
			Summary:     "DOCKER-USER exists but subjects no forwarded traffic to UFW.",
			Remediation: "Either jump from DOCKER-USER to ufw-before-forward then ufw-skip-to-policy-forward before any terminal RETURN, or install the ufw-docker rule set. With the first option and 'ufw default deny routed', container egress also needs matching 'ufw route allow' rules or outbound connections are dropped.",
			Evidence:    evidence,
		}
	}
	if !allBeforeReturn {
		return CheckResult{
			ID: "firewall.docker_user_policy", Title: "Docker forwards traffic through UFW before returning",
			Category: "firewall", Severity: High, Status: Failed,
			Summary:     "DOCKER-USER invokes UFW only after unsafe Docker control flow.",
			Remediation: "Move the DOCKER-USER jump to ufw-before-forward before every terminal verdict or custom jump/goto path.",
			Evidence:    evidence,
		}
	}

	summary := "DOCKER-USER subjects forwarded traffic to UFW before Docker's RETURN path."
	if returnPathCount == 0 {
		summary = "DOCKER-USER subjects forwarded traffic to UFW in both IPv4 and IPv6; no Docker RETURN path was exposed by these views."
	}
	if conventions := dockerUserConventions(familyEvidence); conventions != "" {
		summary += " Convention: " + conventions + "."
	}
	return CheckResult{
		ID: "firewall.docker_user_policy", Title: "Docker forwards traffic through UFW before returning",
		Category: "firewall", Severity: High, Status: Passed,
		Summary:  summary,
		Evidence: evidence,
	}
}

func parseDockerUserProbeOutput(output string) (map[string]dockerUserFamilyProbe, bool) {
	families := map[string]dockerUserFamilyProbe{}
	dockerIPv6 := false
	current := ""
	lines := make([]string, 0)
	flush := func() {
		if current == "" {
			return
		}
		family := families[current]
		family.rules = strings.Join(lines, "\n")
		families[current] = family
		lines = nil
	}
	for _, line := range nonEmptyLines(output) {
		switch {
		case strings.HasPrefix(line, "__shuttle_docker_ipv6="):
			dockerIPv6 = strings.TrimPrefix(line, "__shuttle_docker_ipv6=") == "1"
		case strings.HasPrefix(line, "__shuttle_family="):
			flush()
			current = strings.TrimPrefix(line, "__shuttle_family=")
			families[current] = dockerUserFamilyProbe{privilege: "unknown"}
		case strings.HasPrefix(line, "__shuttle_privilege=") && current != "":
			family := families[current]
			family.privilege = strings.TrimPrefix(line, "__shuttle_privilege=")
			families[current] = family
		case line == "__shuttle_unavailable=1" && current != "":
			family := families[current]
			family.unavailable = true
			families[current] = family
		default:
			lines = append(lines, line)
		}
	}
	flush()
	return families, dockerIPv6
}

func dockerUserPolicyOrder(output, family string) (chainPresent, ufwForward, ufwBeforeReturn bool, returnPaths, unsafePaths []string) {
	expectedForward := "ufw-before-forward"
	expectedPolicy := "ufw-skip-to-policy-forward"
	if family == "ipv6" {
		expectedForward = "ufw6-before-forward"
		expectedPolicy = "ufw6-skip-to-policy-forward"
	}
	chainIndex := -1
	forwardIndex := -1
	policyIndex := -1
	firstUnsafeIndex := -1
	firstTerminalIndex := -1
	lines := nonEmptyLines(output)
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if chainIndex == -1 && dockerUserChainPattern.MatchString(trimmed) {
			chainIndex = index
		}
		if !strings.HasPrefix(strings.ToUpper(trimmed), "-A DOCKER-USER") {
			continue
		}
		target := dockerUserTargetPattern.FindStringSubmatch(trimmed)
		if len(target) < 2 {
			continue
		}
		targetName := strings.ToLower(target[1])
		switch targetName {
		case strings.ToLower(expectedForward):
			if forwardIndex == -1 {
				forwardIndex = index
			}
			continue
		case strings.ToLower(expectedPolicy):
			if policyIndex == -1 {
				policyIndex = index
			}
			continue
		case "return":
			returnPaths = append(returnPaths, trimmed)
			if firstTerminalIndex == -1 {
				firstTerminalIndex = index
			}
			continue
		default:
			// Any non-UFW jump/goto is treated as unsafe control flow. This is
			// deliberately fail-closed: ACCEPT, DROP, REJECT, and custom chains
			// can all bypass the UFW policy depending on their continuation.
			returnPaths = append(returnPaths, trimmed)
			unsafePaths = append(unsafePaths, trimmed)
			if firstUnsafeIndex == -1 {
				firstUnsafeIndex = index
			}
			if firstTerminalIndex == -1 {
				firstTerminalIndex = index
			}
		}
	}
	chainPresent = chainIndex >= 0
	ufwForward = forwardIndex >= 0 && policyIndex >= 0
	// The before-forward hook must run before the explicit UFW default policy,
	// and both must precede every terminal/custom path in DOCKER-USER.
	ufwBeforeReturn = ufwForward && forwardIndex < policyIndex &&
		(firstUnsafeIndex == -1 || forwardIndex < firstUnsafeIndex) &&
		(firstTerminalIndex == -1 || policyIndex < firstTerminalIndex)
	return chainPresent, ufwForward, ufwBeforeReturn, returnPaths, unsafePaths
}

// dockerUserConventions renders the accepted posture per family, so the report
// says which of the two supported rule sets was recognised.
func dockerUserConventions(familyEvidence map[string]any) string {
	parts := []string{}
	for _, name := range []string{"ipv4", "ipv6"} {
		entry, ok := familyEvidence[name].(map[string]any)
		if !ok {
			continue
		}
		if convention, ok := entry["convention"].(string); ok && convention != "" {
			parts = append(parts, name+"="+convention)
		}
	}
	return strings.Join(parts, ", ")
}

// dockerUserUFWDockerPolicy recognises the ufw-docker convention, the other
// widely deployed way to stop Docker from bypassing UFW: DOCKER-USER hands
// traffic to UFW's user-forward rules, returns early for private sources, then
// denies public traffic aimed at private container networks before its terminal
// RETURN. Public inbound is refused exactly like the shuttle block, while
// container egress keeps flowing, so it is accepted as an equivalent posture.
func dockerUserUFWDockerPolicy(output, family string) bool {
	expectedUserForward := "ufw-user-forward"
	privateSpace := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if family == "ipv6" {
		expectedUserForward = "ufw6-user-forward"
		privateSpace = []string{"fc00::/7"}
	}
	userForwardIndex, denyIndex, terminalIndex := -1, -1, -1
	denied := map[string]bool{}
	for index, line := range nonEmptyLines(output) {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "-A DOCKER-USER") {
			continue
		}
		target := dockerUserTargetPattern.FindStringSubmatch(trimmed)
		if len(target) < 2 {
			continue
		}
		switch targetName := strings.ToLower(target[1]); {
		case targetName == expectedUserForward:
			if userForwardIndex == -1 {
				userForwardIndex = index
			}
		case strings.Contains(targetName, "logging-deny"), targetName == "drop", targetName == "reject":
			if destination, ok := dockerUserDestination(trimmed); ok {
				denied[destination] = true
			}
			if denyIndex == -1 {
				denyIndex = index
			}
		case targetName == "return":
			// Source-scoped RETURNs keep private and reply traffic flowing; only
			// a bare RETURN ends the chain for everything that reaches it.
			if terminalIndex == -1 && dockerUserRuleIsUnconditional(trimmed) {
				terminalIndex = index
			}
		}
	}
	if userForwardIndex == -1 || denyIndex == -1 {
		return false
	}
	if terminalIndex != -1 && (userForwardIndex > terminalIndex || denyIndex > terminalIndex) {
		return false
	}
	for _, network := range privateSpace {
		if !denied[network] {
			return false
		}
	}
	return true
}

// dockerUserDestination returns the -d/--destination network of an iptables rule.
func dockerUserDestination(rule string) (string, bool) {
	fields := strings.Fields(rule)
	for index, field := range fields {
		switch strings.ToLower(field) {
		case "-d", "--destination", "--dst":
			if index+1 < len(fields) {
				return strings.ToLower(fields[index+1]), true
			}
		}
	}
	return "", false
}

// dockerUserRuleIsUnconditional reports whether a rule carries no match criteria,
// so every packet reaching it takes its target.
func dockerUserRuleIsUnconditional(rule string) bool {
	fields := strings.Fields(rule)
	// iptables -S always renders rules as "-A CHAIN [matches] -j TARGET", so any
	// field beyond the append and jump pairs is a match criterion.
	for index := 0; index < len(fields); index++ {
		switch strings.ToLower(fields[index]) {
		case "-a", "--append", "-j", "--jump", "-g", "--goto":
			index++
		default:
			return false
		}
	}
	return true
}

// dockerUserChainIsEmpty reports whether the chain exists with no rule at all.
func dockerUserChainIsEmpty(output string) bool {
	present := false
	for _, line := range nonEmptyLines(output) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "-A DOCKER-USER") {
			return false
		}
		if dockerUserChainPattern.MatchString(trimmed) {
			present = true
		}
	}
	return present
}

func dockerUserPrivilegeError(res execx.Result) bool {
	text := strings.ToLower(strings.TrimSpace(res.Stdout + "\n" + res.Stderr))
	if strings.Contains(text, "__shuttle_unavailable=1") || strings.Contains(text, "__shuttle_iptables_unavailable=1") {
		return true
	}
	for _, marker := range []string{
		"permission denied",
		"operation not permitted",
		"must be root",
		"need to be root",
		"could not fetch rule set generation id",
		"cannot initialize iptables table",
		"iptables: command not found",
		"iptables: not found",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func checkSSHPortForAccess(adapter execx.Adapter, access AccessConfig) CheckResult {
	values, skipped, ok := effectiveSSHDConfig(adapter)
	if !ok {
		skipped.ID, skipped.Title, skipped.Category, skipped.Severity = "ssh.port_matches_config", "SSH listens on the configured port", "ssh", High
		return skipped
	}
	expected := access.SSHPort
	if expected == 0 {
		expected = 22
	}
	actual, err := strconv.Atoi(strings.TrimSpace(values["port"]))
	if err != nil || actual < 1 || actual > 65535 {
		return skippedPrivateCheck("ssh.port_matches_config", "SSH listens on the configured port", "sshd -T did not report one valid port.")
	}
	matched := actual == expected
	return CheckResult{ID: "ssh.port_matches_config", Title: "SSH listens on the configured port", Category: "ssh", Severity: High, Status: ternaryStatus(matched), Summary: ternary(matched, fmt.Sprintf("Effective SSH port %d matches config.json.", actual), fmt.Sprintf("Effective SSH port %d differs from configured port %d.", actual, expected)), Remediation: "Align the OpenSSH port, config.json and firewall rule, then validate with sshd -T.", Evidence: map[string]any{"actual": actual, "expected": expected, "source": "sshd -T"}}
}

func checkSSHConfigValid(adapter execx.Adapter) CheckResult {
	res := adapter.Run(strings.Replace(privateSSHDCommand, " -T", " -t", 2), 3*time.Second)
	if res.ExitCode == 0 {
		return CheckResult{ID: "ssh.configuration_valid", Title: "OpenSSH configuration is valid", Category: "ssh", Severity: High, Status: Passed, Summary: "sshd -t completed successfully.", Evidence: map[string]any{"command": "sshd -t"}}
	}
	if commandUnavailable(res) {
		return skippedPrivateCheck("ssh.configuration_valid", "OpenSSH configuration is valid", "sshd is not available or cannot be run without privilege.")
	}
	return CheckResult{ID: "ssh.configuration_valid", Title: "OpenSSH configuration is valid", Category: "ssh", Severity: High, Status: Failed, Summary: "sshd -t rejected the active OpenSSH configuration.", Details: strings.TrimSpace(res.Stderr), Remediation: "Fix the reported OpenSSH configuration error and rerun 'sshd -t' before reloading the service.", Evidence: map[string]any{"command": "sshd -t"}}
}

func effectiveSSHDConfig(adapter execx.Adapter) (map[string]string, CheckResult, bool) {
	res := adapter.Run(privateSSHDCommand, 3*time.Second)
	if res.ExitCode != 0 {
		summary := "Could not read the effective OpenSSH configuration with sshd -T."
		if commandUnavailable(res) {
			summary = "sshd is not available or effective configuration requires unavailable privilege."
		}
		return nil, skippedPrivateCheck("", "", summary), false
	}
	values := map[string]string{}
	for _, line := range nonEmptyLines(res.Stdout) {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		// sshd -T prints one line per value of a repeatable directive, so
		// "AllowUsers deploy ops" comes back as two allowusers lines. Keeping
		// only the last one made the allow-list check read a single account:
		// every host using --operator-user failed its own audit while its
		// configuration was exactly what setup had signed.
		if existing, seen := values[key]; seen {
			values[key] = existing + " " + value
			continue
		}
		values[key] = value
	}
	return values, CheckResult{}, true
}

func checkSSHKeyboardInteractive(adapter execx.Adapter) CheckResult {
	values, skipped, ok := effectiveSSHDConfig(adapter)
	if !ok {
		skipped.ID, skipped.Title, skipped.Category, skipped.Severity = "ssh.keyboard_interactive_enabled", "SSH keyboard-interactive authentication is disabled", "ssh", High
		return skipped
	}
	value, exists := values["kbdinteractiveauthentication"]
	if !exists || (value != "yes" && value != "no") {
		return skippedPrivateCheck("ssh.keyboard_interactive_enabled", "SSH keyboard-interactive authentication is disabled", "sshd -T did not report KbdInteractiveAuthentication.")
	}
	enabled := strings.EqualFold(value, "yes")
	return CheckResult{ID: "ssh.keyboard_interactive_enabled", Title: "SSH keyboard-interactive authentication is disabled", Category: "ssh", Severity: High, Status: ternaryStatus(!enabled), Summary: "KbdInteractiveAuthentication = " + value + ".", Remediation: "Set 'KbdInteractiveAuthentication no' in an OpenSSH drop-in, validate with sshd -t, and reload sshd.", Evidence: map[string]any{"kbdInteractiveAuthentication": value, "source": "sshd -T"}}
}

func checkSSHAllowedUsers(adapter execx.Adapter, access AccessConfig) CheckResult {
	expected := expectedSSHUsers(access)
	if len(expected) == 0 {
		return skippedPrivateCheck("ssh.allowed_users", "Only expected users can use OpenSSH", "No access.allowedSSHUsers or access.deployUser expectation is configured.")
	}
	values, skipped, ok := effectiveSSHDConfig(adapter)
	if !ok {
		skipped.ID, skipped.Title, skipped.Category, skipped.Severity = "ssh.allowed_users", "Only expected users can use OpenSSH", "ssh", High
		return skipped
	}
	actual := normalizedStrings(strings.Fields(values["allowusers"]))
	if len(actual) == 1 && actual[0] == "none" {
		actual = nil
	}
	matched := sameStrings(actual, expected)
	summary := "AllowUsers matches the configured SSH user allow-list."
	if !matched {
		summary = "AllowUsers does not match the configured SSH user allow-list."
	}
	return CheckResult{ID: "ssh.allowed_users", Title: "Only expected users can use OpenSSH", Category: "ssh", Severity: High, Status: ternaryStatus(matched), Summary: summary, Remediation: "Set AllowUsers to the configured access.allowedSSHUsers list in an OpenSSH drop-in, then validate with sshd -t.", Evidence: map[string]any{"expected": expected, "actual": actual, "source": "sshd -T"}}
}

func checkExpectedUser(adapter execx.Adapter, access AccessConfig) CheckResult {
	user, ok := configuredUser(access)
	if !ok {
		return skippedPrivateCheck("access.deploy_user_exists", "Expected deploy user exists", "No access.deployUser is configured.")
	}
	res := adapter.Run("getent passwd -- "+user, 2*time.Second)
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) == "" {
		return CheckResult{ID: "access.deploy_user_exists", Title: "Expected deploy user exists", Category: "access", Severity: High, Status: Failed, Summary: "Configured deploy user does not exist.", Remediation: "Create the configured access.deployUser before disabling alternate administrator access.", Evidence: map[string]any{"user": user}}
	}
	fields := strings.Split(strings.TrimSpace(res.Stdout), ":")
	home := ""
	if len(fields) >= 6 {
		home = fields[5]
	}
	return CheckResult{ID: "access.deploy_user_exists", Title: "Expected deploy user exists", Category: "access", Severity: High, Status: ternaryStatus(home != ""), Summary: ternary(home != "", "Configured deploy user exists.", "Configured deploy user has no usable home directory."), Remediation: "Create the configured access.deployUser with a dedicated home directory.", Evidence: map[string]any{"user": user, "home": home}}
}

func checkExpectedUserSSHFiles(adapter execx.Adapter, access AccessConfig) CheckResult {
	user, ok := configuredUser(access)
	if !ok {
		return skippedPrivateCheck("access.deploy_user_ssh_files", "Deploy user home and SSH keys are protected", "No access.deployUser is configured.")
	}
	cmd := "home=$(getent passwd -- " + user + " | cut -d: -f6); test -n \"$home\"; " +
		"printf \"home=%s\\n\" \"$(stat -c %a \"$home\")\"; " +
		"printf \"ssh=%s\\n\" \"$(stat -c %a \"$home/.ssh\")\"; " +
		"printf \"authorized=%s\\n\" \"$(stat -c %a \"$home/.ssh/authorized_keys\")\"; " +
		"printf \"keys=%s\\n\" \"$(stat -c %s \"$home/.ssh/authorized_keys\")\""
	res := adapter.Run(privilegedCommand(cmd), 3*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("access.deploy_user_ssh_files", "Deploy user home and SSH keys are protected", "Deploy user home or SSH key metadata is not readable with available privilege.")
	}
	values := keyValueLines(res.Stdout)
	keys, _ := strconv.Atoi(values["keys"])
	valid := values["home"] == "700" && values["ssh"] == "700" && values["authorized"] == "600" && keys > 0
	return CheckResult{ID: "access.deploy_user_ssh_files", Title: "Deploy user home and SSH keys are protected", Category: "access", Severity: High, Status: ternaryStatus(valid), Summary: ternary(valid, "Deploy user home, .ssh directory, and authorized_keys are protected.", "Deploy user home, .ssh directory, or authorized_keys permissions do not meet policy."), Remediation: "Set home and .ssh to 0700, authorized_keys to 0600, and install at least one authorized key for the configured deploy user.", Evidence: map[string]any{"user": user, "homeMode": values["home"], "sshMode": values["ssh"], "authorizedKeysMode": values["authorized"], "authorizedKeyBytes": keys}}
}

func checkExpectedUserNoPasswordlessSudo(adapter execx.Adapter, access AccessConfig) CheckResult {
	user, ok := configuredUser(access)
	if !ok {
		return skippedPrivateCheck("access.deploy_user_nopasswd", "Deploy user has no NOPASSWD sudo rule", "No access.deployUser is configured.")
	}
	// sudo cannot run under NoNewPrivileges (the root helper's units): skip
	// quietly instead of logging a sudoers error and a failed mail to root.
	res := adapter.Run("grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status 2>/dev/null && exit 126; "+privilegedCommand("sudo -n -l -U "+user), 3*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("access.deploy_user_nopasswd", "Deploy user has no NOPASSWD sudo rule", "Sudo policy for the deploy user cannot be inspected with available privilege.")
	}
	passwordless := []string{}
	valid := true
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToUpper(line), "NOPASSWD:") {
			continue
		}
		passwordless = append(passwordless, line)
		if !strings.HasSuffix(line, "NOPASSWD: /usr/local/libexec/shuttle-root apply") {
			valid = false
		}
	}
	valid = valid && len(passwordless) == 1
	return CheckResult{ID: "access.deploy_user_nopasswd", Title: "Deploy user sudo is limited to the signed helper", Category: "access", Severity: High, Status: ternaryStatus(valid), Summary: ternary(valid, "The only NOPASSWD rule invokes the typed root helper.", "The deploy user has a missing or broader NOPASSWD rule."), Remediation: "Keep exactly one NOPASSWD rule: /usr/local/libexec/shuttle-root apply.", Evidence: map[string]any{"user": user, "passwordlessRules": passwordless}}
}

func checkExpectedUserDockerGroup(adapter execx.Adapter, access AccessConfig) CheckResult {
	user, ok := configuredUser(access)
	if !ok {
		return skippedPrivateCheck("access.deploy_user_docker_group", "Deploy user Docker access matches policy", "No access.deployUser is configured.")
	}
	res := adapter.Run("id -nG -- "+user, 2*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("access.deploy_user_docker_group", "Deploy user Docker access matches policy", "Deploy user group membership cannot be read.")
	}
	groups := normalizedStrings(strings.Fields(res.Stdout))
	if len(groups) == 0 {
		return skippedPrivateCheck("access.deploy_user_docker_group", "Deploy user has no root-equivalent Docker access", "No group membership evidence was returned.")
	}
	inDocker := false
	for _, group := range groups {
		if group == "docker" {
			inDocker = true
		}
	}
	declared := false
	if access.DockerAccess != nil {
		declared = *access.DockerAccess
	}
	matched := !inDocker && !declared
	return CheckResult{ID: "access.deploy_user_docker_group", Title: "Deploy user has no root-equivalent Docker access", Category: "access", Severity: High, Status: ternaryStatus(matched), Summary: ternary(matched, "Deploy user is outside the Docker group and policy does not request it.", "Deploy user has or requests root-equivalent Docker socket access."), Remediation: "Remove the deploy user from the Docker group and set access.dockerAccess to false; use the future signed privileged helper for typed Docker operations.", Evidence: map[string]any{"user": user, "groups": groups, "inDockerGroup": inDocker, "declaredDockerAccess": declared}}
}

func checkSSHPrivateInterface(adapter execx.Adapter, access AccessConfig) CheckResult {
	if !privateTailscaleConfigured(access) {
		return CheckResult{ID: "firewall.ssh_private_interface_only", Title: "UFW permits SSH only over the private Tailscale interface", Category: "firewall", Severity: High, Status: Skipped, SkipReason: NotApplicable, Summary: "Private Tailscale access is not configured; this private-interface policy is not applicable."}
	}
	res := adapter.Run(privateUFWStatusCommand, 3*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("firewall.ssh_private_interface_only", "UFW permits SSH only over the private Tailscale interface", "UFW status is unavailable; cannot inspect SSH firewall rules.")
	}
	iface := expectedTailscaleInterface(access)
	sshPort := access.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}
	privateRule, publicRules := sshPrivateUFWRules(res.Stdout, iface, sshPort)
	valid := privateRule && len(publicRules) == 0
	return CheckResult{ID: "firewall.ssh_private_interface_only", Title: "UFW permits SSH only over the private Tailscale interface", Category: "firewall", Severity: High, Status: ternaryStatus(valid), Summary: ternary(valid, "SSH is allowed on the configured private Tailscale interface only.", "SSH is missing its private Tailscale allow rule or has a public UFW allow rule."), Remediation: "Allow SSH on the configured Tailscale interface before removing every public SSH UFW rule, then verify a new tailnet SSH session.", Evidence: map[string]any{"interface": iface, "sshPort": sshPort, "privateRule": privateRule, "publicRules": publicRules}}
}

// sshPrivateUFWRules treats every SSH allow/limit rule outside the exact
// configured interface as a violation, including source-CIDR rules. A
// source-restricted LAN rule is still a non-tailnet administrative path.
func sshPrivateUFWRules(output, privateInterface string, sshPort int) (bool, []string) {
	privateRule := false
	violations := []string{}
	portToken := fmt.Sprintf("%d/tcp", sshPort)
	for _, line := range nonEmptyLines(output) {
		lower := strings.ToLower(strings.TrimSpace(line))
		// UFW prints UDP rules in the same table. They are governed separately
		// and must never be reclassified as unexpected TCP exposure.
		if regexp.MustCompile(`^\S+/udp(?:\s|$)`).MatchString(lower) {
			continue
		}
		fields := strings.Fields(lower)
		isAction := false
		isInbound := false
		isForwarded := false
		for _, field := range fields {
			switch field {
			case "allow", "limit":
				isAction = true
			case "in":
				isInbound = true
			case "fwd":
				isForwarded = true
			}
		}
		// `ufw status` omits the IN direction for ordinary inbound rules and
		// prints only `ALLOW`/`LIMIT`; explicit FWD rules remain excluded.
		if isAction && !isInbound && !isForwarded {
			isInbound = true
		}
		if !isAction || !isInbound || (!strings.Contains(lower, portToken) && !strings.Contains(lower, "openssh")) {
			continue
		}
		private := exactUFWInterface(lower, privateInterface)
		if private {
			privateRule = true
			continue
		}
		violations = append(violations, strings.TrimSpace(line))
	}
	return privateRule, violations
}

func exactUFWInterface(lowerLine, expected string) bool {
	fields := strings.Fields(strings.ToLower(lowerLine))
	expected = strings.ToLower(strings.TrimSpace(expected))
	for index, field := range fields {
		if field == "on" && index+1 < len(fields) {
			return strings.TrimSuffix(fields[index+1], ",") == expected
		}
	}
	return false
}

func checkUnexpectedPublicTCP(adapter execx.Adapter, access AccessConfig) CheckResult {
	if !privateAccessConfigured(access) {
		return skippedPrivateCheck("firewall.unexpected_public_tcp_ports", "No unexpected public TCP ports are allowed", "Private access policy is not configured.")
	}
	res := adapter.Run(privateUFWStatusCommand, 3*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("firewall.unexpected_public_tcp_ports", "No unexpected public TCP ports are allowed", "UFW status is unavailable; cannot inspect public TCP rules.")
	}
	allowed := stringSet(access.AllowedPublicTCPPorts)
	unexpected := publicUFWTCPRules(res.Stdout, allowed, expectedTailscaleInterface(access))
	sshPort := access.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}
	sshViolations := []string{}
	if strings.EqualFold(strings.TrimSpace(access.Mode), "private-vps") || strings.EqualFold(strings.TrimSpace(access.Mode), "private-tailscale") || access.Private {
		_, sshViolations = sshPrivateUFWRules(res.Stdout, expectedTailscaleInterface(access), sshPort)
	}
	seenRules := map[string]bool{}
	for _, rule := range unexpected {
		seenRules[rule] = true
	}
	for _, rule := range sshViolations {
		if !seenRules[rule] {
			unexpected = append(unexpected, rule)
			seenRules[rule] = true
		}
	}
	sort.Strings(unexpected)
	return CheckResult{ID: "firewall.unexpected_public_tcp_ports", Title: "No unexpected public TCP ports are allowed", Category: "firewall", Severity: High, Status: ternaryStatus(len(unexpected) == 0), Summary: ternary(len(unexpected) == 0, "No unexpected public TCP UFW allow rules were found.", "Unexpected public TCP UFW allow rule(s) were found."), Remediation: "Remove public UFW TCP allow rules not listed in access.allowedPublicTCPPorts; keep administrative ports private.", Evidence: map[string]any{"allowedPorts": sortedSet(allowed), "unexpectedRules": unexpected}}
}

func checkDockerPublicTCP(adapter execx.Adapter, access AccessConfig) CheckResult {
	if !privateAccessConfigured(access) {
		return skippedPrivateCheck("firewall.docker_public_tcp_ports", "Docker does not bypass the public TCP policy", "Private access policy is not configured.")
	}
	res := adapter.Run(dockerPublicPortsCommand, 5*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("firewall.docker_public_tcp_ports", "Docker does not bypass the public TCP policy", "Docker is not available; cannot inspect published TCP ports.")
	}
	allowed := stringSet(access.AllowedPublicTCPPorts)
	exposures := dockerPublicTCPExposures(res.Stdout, allowed)
	return CheckResult{ID: "firewall.docker_public_tcp_ports", Title: "Docker does not bypass the public TCP policy", Category: "firewall", Severity: High, Status: ternaryStatus(len(exposures) == 0), Summary: ternary(len(exposures) == 0, "Docker does not publish unexpected TCP ports on public interfaces.", "Docker publishes TCP ports not allowed by the private access policy."), Remediation: "Bind Docker ports to localhost/private networks or explicitly list intentional public application ports in access.allowedPublicTCPPorts.", Evidence: map[string]any{"allowedPorts": sortedSet(allowed), "exposures": exposures}}
}

func dockerPublicTCPExposures(output string, allowed map[string]bool) []map[string]string {
	exposures := []map[string]string{}
	classicPattern := regexp.MustCompile(`(?:^|,\s*)(\[[^]]+\]|[^,:[:space:]]+|::):(\d+)->[^,]*?/tcp`)
	for _, line := range nonEmptyLines(output) {
		fields := strings.SplitN(line, "\t", 3)
		// A container that publishes nothing prints an empty third field, and
		// the line is trimmed before it gets here, so the trailing tab is gone
		// and only two fields survive. Demanding three reported the safest
		// workload on the host as an unparseable row, and one idle container
		// was enough to fail a High firewall check. Two fields mean no ports.
		if len(fields) == 2 {
			fields = append(fields, "")
		}
		if len(fields) != 3 {
			exposures = append(exposures, map[string]string{"parseError": "unparseable published-port row"})
			continue
		}
		runtimeMode, name, ports := fields[0], strings.TrimPrefix(fields[1], "/"), fields[2]
		switch runtimeMode {
		case "classic":
			for _, match := range classicPattern.FindAllStringSubmatch(ports, -1) {
				if !privateDockerBindAddress(match[1]) && !allowed[match[2]] {
					exposures = append(exposures, map[string]string{"runtime": "classic", "workload": name, "port": match[2], "bindAddress": match[1]})
				}
			}
		case "swarm":
			var published []swarmPublishedPort
			if json.Unmarshal([]byte(ports), &published) != nil {
				exposures = append(exposures, map[string]string{"runtime": "swarm", "workload": name, "parseError": "unparseable published-port metadata"})
				continue
			}
			for _, port := range published {
				value := strconv.Itoa(port.PublishedPort)
				if strings.EqualFold(port.Protocol, "tcp") && port.PublishedPort > 0 && !allowed[value] {
					exposures = append(exposures, map[string]string{"runtime": "swarm", "workload": name, "port": value, "publishMode": port.PublishMode})
				}
			}
		}
	}
	return exposures
}

func privateDockerBindAddress(value string) bool {
	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	tailscaleCGNAT := &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	return tailscaleCGNAT.Contains(ip)
}

func checkUnattendedSecurityPolicy(adapter execx.Adapter) CheckResult {
	if adapter.Run("command -v apt-config >/dev/null 2>&1", time.Second).ExitCode != 0 {
		return skippedPrivateCheck("system.unattended_security_policy", "Automatic updates follow security-only policy", "apt-config is not available; cannot inspect unattended-upgrades policy.")
	}
	res := adapter.Run(privilegedCommand("apt-config dump"), 3*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("system.unattended_security_policy", "Automatic updates follow security-only policy", "APT policy cannot be inspected with available privilege.")
	}
	text := res.Stdout
	lower := strings.ToLower(text)
	auto := regexp.MustCompile(`apt::periodic::unattended-upgrade\s+"1"`).MatchString(lower)
	securityCount, nonSecurityCount := unattendedOriginCounts(text)
	securityOnly := securityCount > 0 && nonSecurityCount == 0
	autoReboot := regexp.MustCompile(`(?im)^\s*unattended-upgrade::automatic-reboot\s+"false"\s*;`).MatchString(lower)
	valid := auto && securityOnly && autoReboot
	return CheckResult{ID: "system.unattended_security_policy", Title: "Automatic updates follow security-only policy", Category: "system", Severity: Medium, Status: ternaryStatus(valid), Summary: ternary(valid, "Unattended upgrades are enabled for security updates without automatic reboot.", "Unattended-upgrades policy is missing security-only, enabled, or no-auto-reboot safeguards."), Remediation: "Run `shuttle setup --adopt` to apply Shuttle's security-only unattended-upgrades policy.", Evidence: map[string]any{"enabled": auto, "securityOnly": securityOnly, "securityOrigins": securityCount, "nonSecurityOrigins": nonSecurityCount, "automaticReboot": autoReboot}}
}

// `apt-config dump` prints a list as a header line with an empty value,
// `Unattended-Upgrade::Allowed-Origins "";`, followed by one entry per line,
// `Unattended-Upgrade::Allowed-Origins:: "<origin>";`. Only entries count: the
// first version also counted the header, so every valid policy failed.
// Named children (`Allowed-Origins::extra "Ubuntu:noble";`) are entries too:
// unattended-upgrades reads every child of the list, so every child counts.
var aptListEntry = regexp.MustCompile(`(?i)^\s*unattended-upgrade::(allowed-origins|origins-pattern)::\S*\s+"([^"]*)"\s*;\s*$`)

func unattendedOriginCounts(dump string) (security, nonSecurity int) {
	for _, line := range strings.Split(dump, "\n") {
		match := aptListEntry.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if isSecurityAPTOrigin(strings.ToLower(match[1]), match[2]) {
			security++
		} else {
			nonSecurity++
		}
	}
	return security, nonSecurity
}

// The accepted origins are exactly the ones Shuttle's drop-in writes for
// Ubuntu 24.04 and Debian 13, as unexpanded tokens. A suffix rule accepted
// `*:*-security` or `origin=*,codename=*-security`, which pull from any
// repository that names a "-security" suite: not a security-only policy.
var securityAllowedOrigins = map[string]bool{
	"${distro_id}:${distro_codename}-security":             true,
	"${distro_id}ESMApps:${distro_codename}-apps-security": true,
	"${distro_id}ESM:${distro_codename}-infra-security":    true,
}

func isSecurityAPTOrigin(kind, value string) bool {
	if kind == "allowed-origins" {
		return securityAllowedOrigins[value]
	}
	fields := map[string]string{}
	for _, field := range strings.Split(value, ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || fields[key] != "" {
			return false
		}
		fields[key] = val
	}
	return len(fields) == 3 && fields["origin"] == "Debian" && fields["codename"] == "${distro_codename}-security" && fields["label"] == "Debian-Security"
}

func checkSecurityUpdatesPending(adapter execx.Adapter) CheckResult {
	security, _, skipped := pendingAPTUpdates(adapter)
	if skipped != nil {
		skipped.ID, skipped.Title = "system.security_updates_pending", "No pending security package updates"
		return *skipped
	}
	status := ternaryStatus(security == 0)
	return CheckResult{ID: "system.security_updates_pending", Title: "No pending security package updates", Category: "system", Severity: High, Status: status, Summary: ternary(security == 0, "No pending security package updates.", fmt.Sprintf("%d pending security package update(s).", security)), Remediation: "Apply pending security updates promptly or verify unattended-upgrades will install them.", Evidence: map[string]any{"pendingCount": security}}
}

func checkOtherUpdatesPending(adapter execx.Adapter) CheckResult {
	_, other, skipped := pendingAPTUpdates(adapter)
	if skipped != nil {
		skipped.ID, skipped.Title = "system.other_updates_pending", "No pending non-security package updates"
		return *skipped
	}
	status := ternaryStatus(other == 0)
	return CheckResult{ID: "system.other_updates_pending", Title: "No pending non-security package updates", Category: "system", Severity: Medium, Status: status, Summary: ternary(other == 0, "No pending non-security package updates.", fmt.Sprintf("%d pending non-security package update(s).", other)), Remediation: "Review and apply pending non-security updates in a maintenance window.", Evidence: map[string]any{"pendingCount": other}}
}

func checkAPTCacheFresh(adapter execx.Adapter) CheckResult {
	if adapter.Run("command -v apt >/dev/null 2>&1", time.Second).ExitCode != 0 {
		return skippedPrivateCheck("system.apt_cache_stale", "APT package cache is fresh", "apt is not available; cannot inspect package cache freshness.")
	}
	res := adapter.Run("for f in /var/lib/apt/periodic/update-success-stamp /var/lib/apt/lists; do if [ -e \"$f\" ]; then stat -c %Y \"$f\"; exit $?; fi; done; exit 1", 2*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("system.apt_cache_stale", "APT package cache is fresh", "No readable APT update timestamp was found.")
	}
	stamp, err := strconv.ParseInt(strings.TrimSpace(res.Stdout), 10, 64)
	if err != nil {
		return skippedPrivateCheck("system.apt_cache_stale", "APT package cache is fresh", "APT update timestamp could not be parsed.")
	}
	age := time.Since(time.Unix(stamp, 0)).Round(time.Hour)
	fresh := age >= 0 && age <= 7*24*time.Hour
	return CheckResult{ID: "system.apt_cache_stale", Title: "APT package cache is fresh", Category: "system", Severity: Medium, Status: ternaryStatus(fresh), Summary: ternary(fresh, "APT package cache is fresh.", "APT package cache is older than seven days."), Remediation: "Run 'apt update' or repair the scheduled APT update job before relying on update status.", Evidence: map[string]any{"ageHours": int(age.Hours()), "maxAgeHours": 168}}
}

func checkFail2banSSHDJail(adapter execx.Adapter) CheckResult {
	if adapter.Run("command -v fail2ban-client >/dev/null 2>&1", time.Second).ExitCode != 0 {
		return skippedPrivateCheck("system.fail2ban_sshd_jail_inactive", "fail2ban sshd jail is active", "fail2ban-client is not available; cannot inspect the sshd jail.")
	}
	res := adapter.Run(privilegedCommand("fail2ban-client status sshd"), 3*time.Second)
	if res.ExitCode != 0 {
		return CheckResult{ID: "system.fail2ban_sshd_jail_inactive", Title: "fail2ban sshd jail is active", Category: "system", Severity: Medium, Status: Failed, Summary: "fail2ban sshd jail is not active or cannot be queried.", Remediation: "Enable the sshd jail and verify 'fail2ban-client status sshd' succeeds."}
	}
	return CheckResult{ID: "system.fail2ban_sshd_jail_inactive", Title: "fail2ban sshd jail is active", Category: "system", Severity: Medium, Status: Passed, Summary: "fail2ban sshd jail is active.", Evidence: map[string]any{"jail": "sshd"}}
}

func checkAppArmorActive(adapter execx.Adapter) CheckResult {
	aaStatus := "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; command -v aa-status >/dev/null 2>&1 || exit 127; if [ $(id -u) != 0 ] && sudo -n true >/dev/null 2>&1; then exec sudo -n aa-status --enabled; fi; exec aa-status --enabled"
	if adapter.Run("PATH=/usr/sbin:/usr/bin:/sbin:/bin; command -v aa-status >/dev/null 2>&1", time.Second).ExitCode != 0 {
		return CheckResult{ID: "system.apparmor_inactive", Title: "AppArmor is active", Category: "system", Severity: Medium, Status: Failed, Summary: "AppArmor status tool is not installed.", Remediation: "Install and enable AppArmor on this VPS."}
	}
	res := adapter.Run(aaStatus, 3*time.Second)
	if res.ExitCode != 0 {
		if commandUnavailable(res) {
			return skippedPrivateCheck("system.apparmor_inactive", "AppArmor is active", "AppArmor status cannot be read with available privilege.")
		}
		return CheckResult{ID: "system.apparmor_inactive", Title: "AppArmor is active", Category: "system", Severity: Medium, Status: Failed, Summary: "AppArmor is not active.", Remediation: "Enable AppArmor and load the required security profiles."}
	}
	return CheckResult{ID: "system.apparmor_inactive", Title: "AppArmor is active", Category: "system", Severity: Medium, Status: Passed, Summary: "AppArmor is active."}
}

func pendingAPTUpdates(adapter execx.Adapter) (int, int, *CheckResult) {
	if adapter.Run("command -v apt >/dev/null 2>&1", time.Second).ExitCode != 0 {
		result := skippedPrivateCheck("", "", "apt is not available; cannot inspect pending package updates.")
		return 0, 0, &result
	}
	res := adapter.Run(pipefailCommand("LC_ALL=C apt list --upgradable 2>/dev/null | sed 1d"), 5*time.Second)
	if res.ExitCode != 0 {
		result := skippedPrivateCheck("", "", "APT could not list pending package updates.")
		return 0, 0, &result
	}
	security, other := 0, 0
	for _, line := range nonEmptyLines(res.Stdout) {
		if strings.Contains(strings.ToLower(line), "security") {
			security++
		} else {
			other++
		}
	}
	return security, other, nil
}

func privilegedCommand(command string) string {
	return "if [ $(id -u) != 0 ] && sudo -n true >/dev/null 2>&1; then exec sudo -n sh -c '" + strings.ReplaceAll(command, "'", "'\\\"'\\\"'") + "'; fi; exec sh -c '" + strings.ReplaceAll(command, "'", "'\\\"'\\\"'") + "'"
}

func configuredUser(access AccessConfig) (string, bool) {
	user := strings.TrimSpace(access.DeployUser)
	if !regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`).MatchString(user) {
		return "", false
	}
	return user, true
}

func skippedPrivateCheck(id, title, summary string) CheckResult {
	category := "system"
	if prefix, _, ok := strings.Cut(id, "."); ok {
		category = prefix
	}
	severity := Medium
	switch id {
	case "ssh.configuration_valid", "ssh.root_login_enabled", "ssh.password_auth_enabled", "ssh.keyboard_interactive_enabled", "ssh.allowed_users", "tailscale.connected", "access.deploy_user_exists", "access.deploy_user_ssh_files", "access.deploy_user_nopasswd", "access.deploy_user_docker_group", "firewall.ssh_private_interface_only", "firewall.unexpected_public_tcp_ports", "firewall.docker_public_tcp_ports":
		severity = High
	case "tailscale.auto_update":
		severity = Low
	}
	return CheckResult{ID: id, Title: title, Category: category, Severity: severity, Status: Skipped, Summary: summary}
}

func commandUnavailable(res execx.Result) bool {
	text := strings.ToLower(res.Stdout + "\n" + res.Stderr)
	return res.ExitCode == 127 || strings.Contains(text, "not found") || strings.Contains(text, "permission denied") || strings.Contains(text, "not permitted") || strings.Contains(text, "must be root") || strings.Contains(text, "need to be root") || strings.Contains(text, "no hostkeys available")
}

func ternaryStatus(condition bool) Status {
	if condition {
		return Passed
	}
	return Failed
}

func normalizedStrings(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	return sortedSet(seen)
}

func sameStrings(left, right []string) bool {
	left, right = normalizedStrings(left), normalizedStrings(right)
	return strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func stringSet(values []string) map[string]bool {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if regexp.MustCompile(`^\d{1,5}$`).MatchString(value) {
			set[value] = true
		}
	}
	return set
}

func sortedSet(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func keyValueLines(value string) map[string]string {
	result := map[string]string{}
	for _, line := range nonEmptyLines(value) {
		key, val, ok := strings.Cut(line, "=")
		if ok {
			result[strings.TrimSpace(key)] = strings.TrimSpace(val)
		}
	}
	return result
}

func publicUFWTCPRules(output string, allowed map[string]bool, privateInterface string) []string {
	rules := []string{}
	publicPattern := regexp.MustCompile(`^(.+?)\s+(?:allow|limit)(?:\s+(in|fwd))?\s+(?:anywhere|0\.0\.0\.0/0|::/0)`)
	numericTCP := regexp.MustCompile(`^(\d{1,5})/tcp(?:\s+\(v6\))?(?:\s+on\s+(\S+))?$`)
	for _, line := range nonEmptyLines(output) {
		lower := strings.ToLower(strings.TrimSpace(line))
		if regexp.MustCompile(`^\S+/udp(?:\s|$)`).MatchString(lower) {
			continue
		}
		public := publicPattern.FindStringSubmatch(lower)
		if len(public) != 3 {
			continue
		}
		forwarded := public[2] == "fwd"
		if !forwarded && exactUFWInterface(public[1], privateInterface) {
			continue
		}
		port := numericTCP.FindStringSubmatch(strings.TrimSpace(public[1]))
		if forwarded || len(port) < 2 || !allowed[port[1]] {
			rules = append(rules, strings.TrimSpace(line))
		}
	}
	return rules
}
