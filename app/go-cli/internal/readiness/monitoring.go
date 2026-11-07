package readiness

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

// ParseMonitoringSSHD exposes the same effective sshd key/value parsing used
// by readiness checks to the long-running monitor. Keeping this bridge small
// prevents the two callers from disagreeing about Match-expanded values.
func ParseMonitoringSSHD(body string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			key := strings.ToLower(fields[0])
			value := strings.Join(fields[1:], " ")
			if previous, ok := values[key]; ok {
				values[key] = previous + " " + value
			} else {
				values[key] = value
			}
		}
	}
	return values
}

// MonitoringSSHMatches reports whether effective sshd output satisfies the
// key-only, port and optional exact AllowUsers policy supplied by the caller.
func MonitoringSSHMatches(body string, expectedUsers []string, expectedPort int) bool {
	values := ParseMonitoringSSHD(body)
	if !MonitoringSSHKeyOnly(body) {
		return false
	}
	if expectedPort > 0 && values["port"] != stringInt(expectedPort) {
		return false
	}
	if len(expectedUsers) == 0 {
		return true
	}
	got := strings.Fields(values["allowusers"])
	want := append([]string(nil), expectedUsers...)
	sort.Strings(got)
	sort.Strings(want)
	return strings.Join(got, "\x00") == strings.Join(want, "\x00")
}

// MonitoringSSHKeyOnly rejects missing fields as well as an explicit unsafe
// value. An incomplete sshd -T response is evidence unavailable, never proof.
func MonitoringSSHKeyOnly(body string) bool {
	values := ParseMonitoringSSHD(body)
	for key, expected := range map[string]string{
		"permitrootlogin":              "no",
		"passwordauthentication":       "no",
		"kbdinteractiveauthentication": "no",
		"pubkeyauthentication":         "yes",
	} {
		if values[key] != expected {
			return false
		}
	}
	return true
}

func stringInt(value int) string {
	if value == 0 {
		return "0"
	}
	const digits = "0123456789"
	buf := [20]byte{}
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = digits[value%10]
		value /= 10
	}
	return string(buf[i:])
}

var ufwDefaultPolicyPattern = regexp.MustCompile(`(?i)^default:\s*([a-z]+)\s*\(\s*incoming\s*\)\s*,\s*([a-z]+)\s*\(\s*outgoing\s*\)\s*,\s*([a-z]+)\s*\(\s*routed\s*\)\s*$`)

// ParseMonitoringUFWDefaultPolicies reads the verbose Default line as three
// explicit policies. A missing, truncated or extra-field line is not evidence.
func ParseMonitoringUFWDefaultPolicies(body string) (incoming, outgoing, routed string, ok bool) {
	for _, line := range strings.Split(body, "\n") {
		match := ufwDefaultPolicyPattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 4 {
			continue
		}
		incoming = strings.ToLower(match[1])
		outgoing = strings.ToLower(match[2])
		routed = strings.ToLower(match[3])
		if incoming == "" || outgoing == "" || routed == "" {
			return "", "", "", false
		}
		return incoming, outgoing, routed, true
	}
	return "", "", "", false
}

// MonitoringUFWAllowsOnlySafeDefaults requires an active firewall and explicit
// deny incoming plus deny routed policies. Active without Default, or a
// permissive third-field routed policy, is rejected.
func MonitoringUFWAllowsOnlySafeDefaults(body string) bool {
	if !regexp.MustCompile(`(?im)^status:\s*active\s*$`).MatchString(body) {
		return false
	}
	incoming, _, routed, ok := ParseMonitoringUFWDefaultPolicies(body)
	if !ok {
		return false
	}
	return incoming == "deny" && routed == "deny"
}

// MonitoringDockerUserOrder is kept as a pure convenience wrapper for callers
// that already collected both iptables families.
func MonitoringDockerUserOrder(ipv4, ipv6 string) bool {
	chain4, forward4, before4, _, _ := dockerUserPolicyOrder(ipv4, "ipv4")
	chain6, forward6, before6, _, _ := dockerUserPolicyOrder(ipv6, "ipv6")
	return chain4 && forward4 && before4 && chain6 && forward6 && before6
}

func dockerUserForwardBeforeReturn(body, hook string) bool {
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "docker-user") || !strings.Contains(lower, strings.ToLower(hook)) {
		return false
	}
	return !strings.Contains(lower, "-j return") || strings.Index(lower, strings.ToLower(hook)) < strings.Index(lower, "-j return")
}

// These wrappers reuse the readiness parsers instead of reimplementing their
// firewall and Fail2ban semantics in monitoring.
func MonitoringDockerUserPolicyOrder(output, family string) (bool, bool, bool, []string, []string) {
	return dockerUserPolicyOrder(output, family)
}

func MonitoringDockerUserUFWDockerPolicy(output, family string) bool {
	return dockerUserUFWDockerPolicy(output, family)
}

func MonitoringDockerUserChainIsEmpty(output string) bool {
	return dockerUserChainIsEmpty(output)
}

func MonitoringPublicUFWTCPRules(output string, allowed map[string]bool, privateInterface string) []string {
	return publicUFWTCPRules(output, allowed, privateInterface)
}

func MonitoringSSHPrivateUFWRules(output, privateInterface string, sshPort int) (bool, []string) {
	return sshPrivateUFWRules(output, privateInterface, sshPort)
}

func MonitoringExpectedSSHUsers(access AccessConfig) []string {
	return expectedSSHUsers(access)
}

func MonitoringCheckSSHPortForAccess(adapter execx.Adapter, access AccessConfig) CheckResult {
	return normalizeEvidence(checkSSHPortForAccess(adapter, access))
}

func MonitoringCheckFail2banSSHDJail(adapter execx.Adapter) CheckResult {
	return normalizeEvidence(checkFail2banSSHDJail(adapter))
}

func MonitoringCheckFail2banSSHDPort(adapter execx.Adapter, access AccessConfig) CheckResult {
	return normalizeEvidence(checkFail2banSSHDPort(adapter, access))
}

type monitoringObservedAdapter struct {
	execx.Adapter
	failed bool
}

func (a *monitoringObservedAdapter) Run(command string, timeout time.Duration) execx.Result {
	result := a.Adapter.Run(command, timeout)
	if result.ExitCode != 0 {
		a.failed = true
	}
	return result
}

// MonitoringCheckDockerUserPolicy reuses the full IPv4, IPv6 and inactive
// Docker bridge semantics from the readiness check. A failed collection cannot
// be converted into a passing result by a partial fixture.
func MonitoringCheckDockerUserPolicy(adapter execx.Adapter) CheckResult {
	observed := &monitoringObservedAdapter{Adapter: adapter}
	result := normalizeEvidence(checkDockerUserPolicy(observed))
	if observed.failed && result.Status == Passed {
		return unavailableResult(result, "A Docker-USER collection command failed; the firewall posture is unavailable.")
	}
	return result
}

func MonitoringLocalListenerEndpoint(line string) string {
	return localListenerEndpoint(line)
}

func MonitoringValidListenerEvidence(body string) bool {
	return validListenerEvidence(body)
}

func MonitoringPublicListenerPort(line, port string) bool {
	return publicListenerPort(line, port)
}
