package readiness

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func checkRebootRequired(adapter execx.Adapter) CheckResult {
	res := adapter.Run("if [ -e /var/run/reboot-required ]; then printf required; else printf clear; fi", time.Second)
	if res.ExitCode != 0 || (strings.TrimSpace(res.Stdout) != "required" && strings.TrimSpace(res.Stdout) != "clear") {
		return skippedPrivateCheck("system.reboot_required", "No reboot is pending", "Could not inspect /var/run/reboot-required.")
	}
	required := strings.TrimSpace(res.Stdout) == "required"
	return CheckResult{ID: "system.reboot_required", Title: "No reboot is pending", Category: "system", Severity: High, Status: ternaryStatus(!required), Summary: ternary(required, "The host requires a reboot to finish applying updates.", "No pending reboot marker is present."), Remediation: "Schedule a controlled reboot, reconnect, then rerun shuttle doctor --strict.", Evidence: map[string]any{"required": required}}
}

func checkFail2banSSHDPort(adapter execx.Adapter, access AccessConfig) CheckResult {
	values, skipped, ok := effectiveSSHDConfig(adapter)
	if !ok {
		skipped.ID, skipped.Title, skipped.Category, skipped.Severity = "system.fail2ban_sshd_port", "Fail2ban protects the effective SSH port", "system", High
		return skipped
	}
	sshPort, err := strconv.Atoi(strings.TrimSpace(values["port"]))
	if err != nil || sshPort < 1 || sshPort > 65535 {
		return skippedPrivateCheck("system.fail2ban_sshd_port", "Fail2ban protects the effective SSH port", "sshd -T did not report one valid port.")
	}
	if access.SSHPort > 0 && access.SSHPort != sshPort {
		return CheckResult{ID: "system.fail2ban_sshd_port", Title: "Fail2ban protects the effective SSH port", Category: "system", Severity: High, Status: Failed, Summary: "The configured and effective SSH ports differ, so Fail2ban alignment cannot be trusted.", Remediation: "Align config.json and sshd before checking Fail2ban.", Evidence: map[string]any{"configuredPort": access.SSHPort, "effectivePort": sshPort}}
	}
	res := adapter.Run("command -v fail2ban-client >/dev/null 2>&1 || exit 127; fail2ban-client status sshd >/dev/null 2>&1 || exit 2; awk -F= '/^[[:space:]]*port[[:space:]]*=/{gsub(/[[:space:]]/, \"\", $2); print $2; found=1} END{exit !found}' /etc/fail2ban/jail.d/shuttle-sshd.local", 3*time.Second)
	if res.ExitCode == 127 {
		return skippedPrivateCheck("system.fail2ban_sshd_port", "Fail2ban protects the effective SSH port", "fail2ban-client is unavailable.")
	}
	if res.ExitCode != 0 {
		return CheckResult{ID: "system.fail2ban_sshd_port", Title: "Fail2ban protects the effective SSH port", Category: "system", Severity: High, Status: Failed, Summary: "The active sshd jail or its managed port configuration could not be verified.", Remediation: "Enable the sshd jail and align /etc/fail2ban/jail.d/shuttle-sshd.local with the effective SSH port."}
	}
	ports := map[int]bool{}
	for _, raw := range regexp.MustCompile(`[0-9]+`).FindAllString(res.Stdout, -1) {
		if port, parseErr := strconv.Atoi(raw); parseErr == nil && port >= 1 && port <= 65535 {
			ports[port] = true
		}
	}
	matched := ports[sshPort]
	return CheckResult{ID: "system.fail2ban_sshd_port", Title: "Fail2ban protects the effective SSH port", Category: "system", Severity: High, Status: ternaryStatus(matched), Summary: ternary(matched, fmt.Sprintf("Fail2ban sshd jail protects port %d.", sshPort), fmt.Sprintf("Fail2ban sshd jail does not protect effective SSH port %d.", sshPort)), Remediation: "Set the sshd jail port to the effective OpenSSH port and reload Fail2ban.", Evidence: map[string]any{"effectivePort": sshPort, "jailOutput": strings.TrimSpace(res.Stdout)}}
}

func checkRecentFailedSSHLogins(adapter execx.Adapter) CheckResult {
	command := `command -v journalctl >/dev/null 2>&1 || exit 127
body=$(journalctl -u ssh --since '-24 hours' --no-pager -o cat 2>/dev/null) || exit 2
printf '%s\n' "$body" | awk 'BEGIN{IGNORECASE=1} /Failed password|Invalid user|authentication failure|Connection closed by authenticating user/{count++} END{print count+0}'`
	res := adapter.Run(command, 5*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("security.failed_ssh_logins_recent", "Recent SSH authentication failures stay below the alert threshold", "SSH journal entries are unavailable; refusing to report a false zero.")
	}
	count, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil || count < 0 {
		return skippedPrivateCheck("security.failed_ssh_logins_recent", "Recent SSH authentication failures stay below the alert threshold", "Could not parse the aggregated SSH failure count.")
	}
	const threshold = 20
	return CheckResult{ID: "security.failed_ssh_logins_recent", Title: "Recent SSH authentication failures stay below the alert threshold", Category: "security", Severity: Medium, Status: ternaryStatus(count < threshold), Summary: ternary(count < threshold, fmt.Sprintf("%d failed SSH authentication event(s) in the last 24 hours.", count), fmt.Sprintf("%d failed SSH authentication events in the last 24 hours exceed the threshold of %d.", count, threshold)), Remediation: "Review the SSH journal, confirm Fail2ban bans offenders, and restrict upstream access if scanning persists.", Evidence: map[string]any{"windowHours": 24, "count": count, "threshold": threshold}}
}

func checkFailedSystemdUnits(adapter execx.Adapter) CheckResult {
	res := adapter.Run("systemctl --failed --no-legend --plain 2>/dev/null", 3*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("system.failed_units", "No systemd units are failed", "systemctl could not enumerate failed units.")
	}
	units := []string{}
	for _, line := range nonEmptyLines(res.Stdout) {
		if fields := strings.Fields(line); len(fields) > 0 {
			units = append(units, fields[0])
		}
	}
	return CheckResult{ID: "system.failed_units", Title: "No systemd units are failed", Category: "system", Severity: Medium, Status: ternaryStatus(len(units) == 0), Summary: ternary(len(units) == 0, "No failed systemd units were reported.", fmt.Sprintf("%d systemd unit(s) are failed.", len(units))), Remediation: "Inspect each failed unit with systemctl status and journalctl, then repair or deliberately disable it.", Evidence: map[string]any{"units": units}}
}

func checkResolvedLinkLocalProtocols(adapter execx.Adapter) CheckResult {
	res := adapter.Run("command -v resolvectl >/dev/null 2>&1 || exit 127; resolvectl status", 3*time.Second)
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "Protocols:") {
		return skippedPrivateCheck("network.link_local_name_resolution", "LLMNR and multicast DNS are disabled", "resolvectl could not report the effective link-local name-resolution state.")
	}
	unsafe := []string{}
	for _, line := range nonEmptyLines(res.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "+llmnr") || strings.Contains(lower, "+mdns") || strings.Contains(lower, "llmnr/") || strings.Contains(lower, "mdns/") {
			unsafe = append(unsafe, strings.TrimSpace(line))
		}
	}
	disabled := len(unsafe) == 0
	return CheckResult{ID: "network.link_local_name_resolution", Title: "LLMNR and multicast DNS are disabled", Category: "system", Severity: Medium, Status: ternaryStatus(disabled), Summary: ternary(disabled, "No active LLMNR or multicast-DNS scope was reported.", "Link-local name resolution remains enabled on at least one interface."), Remediation: "Set LLMNR=no and MulticastDNS=no in a systemd-resolved drop-in, restart systemd-resolved, and recheck every interface.", Evidence: map[string]any{"unsafeProtocols": unsafe}}
}

func checkLoopbackRegistry(adapter execx.Adapter) CheckResult {
	command := `docker container inspect shuttle-registry --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.HostConfig.RestartPolicy.Name}} {{range (index .HostConfig.PortBindings "5000/tcp")}}{{.HostIp}}:{{.HostPort}}{{end}}'`
	res := adapter.Run(command, 3*time.Second)
	if res.ExitCode != 0 {
		return CheckResult{ID: "docker.loopback_registry", Title: "Persistent registry is healthy and loopback-only", Category: "docker", Severity: High, Status: Failed, Summary: "The Shuttle registry container is missing or cannot be inspected.", Remediation: "Re-run setup to create the pinned shuttle-registry container and verify its loopback endpoint."}
	}
	fields := strings.Fields(strings.TrimSpace(res.Stdout))
	valid := len(fields) == 4 && fields[0] == "running" && fields[1] == "healthy" && fields[2] == "always" && fields[3] == "127.0.0.1:5000"
	return CheckResult{ID: "docker.loopback_registry", Title: "Persistent registry is healthy and loopback-only", Category: "docker", Severity: High, Status: ternaryStatus(valid), Summary: ternary(valid, "The persistent registry is healthy, restartable and bound only to 127.0.0.1:5000.", "The persistent registry does not match its required runtime, health, restart or loopback binding."), Remediation: "Re-run setup and keep shuttle-registry healthy with restart=always and only 127.0.0.1:5000 published.", Evidence: map[string]any{"state": strings.TrimSpace(res.Stdout)}}
}

// checkDockerGatewayMTU reports a docker_gwbridge that is wider than the
// network under it. Swarm tasks and host-mode ports (the shared edge) leave
// the host through that bridge; at 1500 on a 1460 or 1450 link, full-size
// segments are dropped while handshakes succeed, so ACME and outbound API
// calls hang without an error. Setup aligns the bridge before `swarm init`;
// a Swarm initialised earlier, or by someone else, keeps its 1500 bridge, and
// this is where the operator learns it. An empty driver option is Docker's
// default of 1500.
func checkDockerGatewayMTU(adapter execx.Adapter) CheckResult {
	const id, title = "docker.gateway_mtu", "Docker gateway bridge fits the network MTU"
	command := `iface=$(ip -o -4 route show default | awk '{print $5; exit}')
[ -n "$iface" ] || exit 3
host=$(cat "/sys/class/net/$iface/mtu") || exit 3
if docker network inspect docker_gwbridge >/dev/null 2>&1; then
  gw=$(docker network inspect docker_gwbridge --format '{{index .Options "com.docker.network.driver.mtu"}}')
  printf '%s %s %s\n' "$iface" "$host" "${gw:-1500}"
else
  printf '%s %s absent\n' "$iface" "$host"
fi`
	res := adapter.Run(command, 3*time.Second)
	fields := strings.Fields(strings.TrimSpace(res.Stdout))
	if res.ExitCode != 0 || len(fields) != 3 {
		return collectionUnavailable(id, title, "docker", Medium)
	}
	host, err := strconv.Atoi(fields[1])
	if err != nil || host <= 0 {
		return collectionUnavailable(id, title, "docker", Medium)
	}
	evidence := map[string]any{"interface": fields[0], "hostMTU": host, "gatewayMTU": fields[2]}
	if fields[2] == "absent" {
		return CheckResult{ID: id, Title: title, Category: "docker", Severity: Medium, Status: Skipped, SkipReason: NotApplicable, Summary: "docker_gwbridge does not exist; Swarm is not initialised on this host.", Evidence: evidence}
	}
	gateway, err := strconv.Atoi(fields[2])
	if err != nil || gateway <= 0 {
		return collectionUnavailable(id, title, "docker", Medium)
	}
	fits := gateway <= host
	return CheckResult{ID: id, Title: title, Category: "docker", Severity: Medium, Status: ternaryStatus(fits),
		Summary:     ternary(fits, fmt.Sprintf("docker_gwbridge MTU %d fits %s (MTU %d).", gateway, fields[0], host), fmt.Sprintf("docker_gwbridge MTU %d exceeds %s (MTU %d): full-size packets from containers are dropped, so ACME and outbound calls can hang.", gateway, fields[0], host)),
		Remediation: fmt.Sprintf("Recreate docker_gwbridge with --opt com.docker.network.driver.mtu=%d. Docker only accepts that before swarm init, so it means leaving and re-initialising the Swarm in a maintenance window.", host),
		Evidence:    evidence}
}

func checkUnexpectedSUIDSGID(adapter execx.Adapter) CheckResult {
	command := `command -v find >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1 || exit 127
find / -xdev \( -path /var/lib/docker -o -path /var/lib/containerd -o -path /proc -o -path /sys -o -path /run -o -path /tmp \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | while IFS= read -r path; do
  dpkg-query -S "$path" >/dev/null 2>&1 && continue
  # usrmerge: /bin is a symlink to /usr/bin, and a package may register either
  # spelling. fuse3 owns /bin/fusermount3, find walks /usr/bin/fusermount3, and
  # dpkg-query knows nothing about that path — reporting a distribution binary
  # as an unmanaged privileged executable.
  alt=""
  case "$path" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/*) alt=${path#/usr} ;;
    /bin/*|/sbin/*|/lib/*) alt="/usr$path" ;;
  esac
  [ -n "$alt" ] && dpkg-query -S "$alt" >/dev/null 2>&1 && continue
  printf '%s\n' "$path"
done`
	res := adapter.Run(pipefailCommand(command), 15*time.Second)
	if res.ExitCode != 0 {
		return skippedPrivateCheck("filesystem.unmanaged_suid_sgid", "SUID and SGID executables are package-managed", "Could not inspect package ownership of privileged executables.")
	}
	paths := nonEmptyLines(res.Stdout)
	return CheckResult{ID: "filesystem.unmanaged_suid_sgid", Title: "SUID and SGID executables are package-managed", Category: "filesystem", Severity: High, Status: ternaryStatus(len(paths) == 0), Summary: ternary(len(paths) == 0, "Every discovered SUID/SGID executable belongs to an installed package.", fmt.Sprintf("%d unmanaged SUID/SGID executable(s) were found.", len(paths))), Remediation: "Quarantine unexpected privileged executables, investigate their origin, and reinstall trusted package-owned binaries.", Evidence: map[string]any{"unmanagedPaths": paths}}
}

// shuttleSSHDDropIn is the signed SSH baseline the root helper installs.
const shuttleSSHDDropIn = "/etc/ssh/sshd_config.d/00-shuttle.conf"

// checkSSHBaselineDropInEffective catches a drop-in that is present on disk but
// inert. A provider image or a console-driven "reset SSH" can leave an
// sshd_config that never includes /etc/ssh/sshd_config.d, or includes it after
// its own PermitRootLogin line; sshd keeps the first value it reads, so the
// baseline silently stops applying while its file still looks correct.
func checkSSHBaselineDropInEffective(adapter execx.Adapter) CheckResult {
	const id, title = "ssh.baseline_drop_in_effective", "The signed SSH baseline is in effect"
	if adapter.Run("test -f "+shuttleSSHDDropIn, time.Second).ExitCode != 0 {
		return skippedPrivateCheck(id, title, "The Shuttle SSH baseline drop-in is not installed on this host.")
	}
	values, skipped, ok := effectiveSSHDConfig(adapter)
	if !ok {
		skipped.ID, skipped.Title, skipped.Category, skipped.Severity = id, title, "ssh", High
		return skipped
	}
	ignored := []string{}
	for keyword, expected := range map[string]string{"permitrootlogin": "no", "passwordauthentication": "no", "pubkeyauthentication": "yes"} {
		if strings.ToLower(values[keyword]) != expected {
			ignored = append(ignored, keyword)
		}
	}
	sort.Strings(ignored)
	included := adapter.Run("grep -Eqi '^[[:space:]]*Include[[:space:]]+(/etc/ssh/)?sshd_config\\.d/\\*' /etc/ssh/sshd_config", time.Second).ExitCode == 0
	return CheckResult{
		ID: id, Title: title, Category: "ssh", Severity: High, Status: ternaryStatus(len(ignored) == 0),
		Summary: ternary(len(ignored) == 0, "The baseline drop-in is installed and its directives are the effective ones.",
			fmt.Sprintf("%s is installed but sshd ignores it for: %s.", shuttleSSHDDropIn, strings.Join(ignored, ", "))),
		Remediation: "Ensure /etc/ssh/sshd_config reads 'Include /etc/ssh/sshd_config.d/*.conf' before setting those directives itself, then rerun shuttle setup to reapply the signed baseline.",
		Evidence:    map[string]any{"dropIn": shuttleSSHDDropIn, "ignoredDirectives": ignored, "mainConfigIncludesDropInDir": included},
	}
}

// checkSharedEdgeServes proves the shared Caddy answers HTTP on the loopback.
//
// Every other reverse-proxy check inspects configuration: that the Caddyfile
// validates, that the admin API is private, that security headers are set. All
// of them stayed green on a host whose edge had been listening on 80/443 while
// resetting every connection, so `doctor` reported a healthy VPS while nothing
// was served. Configuration being valid is not evidence that it is serving.
func checkSharedEdgeServes(adapter execx.Adapter) CheckResult {
	const id, title = "reverse-proxy.edge_serves_http", "The shared edge answers HTTP requests"
	if adapter.Run("docker ps --format '{{.Names}}' 2>/dev/null | grep -q shuttle-edge_caddy", 3*time.Second).ExitCode != 0 {
		return skippedPrivateCheck(id, title, "The shared Caddy container is not visible from this adapter.")
	}
	// Any HTTP status proves the edge completed a request. A bare edge with no
	// application route legitimately answers 404, so only a transport-level
	// failure (reset, refused, timeout) counts as broken.
	res := adapter.Run(`curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/ 2>/dev/null || printf 000`, 8*time.Second)
	code := strings.TrimSpace(res.Stdout)
	served := res.ExitCode == 0 && regexp.MustCompile(`^[1-5][0-9]{2}$`).MatchString(code)
	return CheckResult{
		ID: id, Title: title, Category: "reverse-proxy", Severity: High, Status: ternaryStatus(served),
		Summary: ternary(served,
			fmt.Sprintf("The shared edge completed a loopback HTTP request (status %s).", code),
			"The shared edge is running and bound to port 80 but does not complete HTTP requests."),
		Remediation: "Inspect `docker service ps shuttle-edge_caddy` for a task stuck binding host ports, then redeploy the edge so exactly one task holds 80/443.",
		Evidence:    map[string]any{"loopbackStatus": code},
	}
}
