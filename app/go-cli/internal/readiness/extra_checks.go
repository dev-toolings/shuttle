package readiness

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
)

func safeHostname(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func safeHTTPPath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '/' || r == '_' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// sensitiveDockerPorts lists ports that should never be published on 0.0.0.0
// when used in production. Mirrors firewall.database_port_public + Caddy admin.
var sensitiveDockerPorts = []string{"5432", "3306", "6379", "7700", "9200", "27017", "2019", "1025", "8025"}

func runtimeServiceCheck(adapter execx.Adapter, id, title, service string) CheckResult {
	res := adapter.Run("systemctl is-active --quiet "+service, 3*time.Second)
	result := CheckResult{ID: id, Title: title, Category: "runtime", Severity: High}
	if res.ExitCode == 0 {
		result.Status = Passed
		result.Summary = service + " is active."
		return result
	}
	result.Status = Failed
	result.Summary = service + " is not active or systemd is unavailable."
	result.Remediation = "Install and enable the configured runtime service, then verify it with systemctl."
	return result
}

func checkPostgreSQLService(adapter execx.Adapter) CheckResult {
	return runtimeServiceCheck(adapter, "runtime.postgresql_service", "PostgreSQL service is active", "postgresql")
}

func checkRedisService(adapter execx.Adapter) CheckResult {
	// `--filter name=` matches a service name by PREFIX, so `name=_redis` never
	// matched the `<stack>_redis` Swarm creates: the check reported "no Redis
	// service" on a host running two of them. Measured on domebao (08-09-2026),
	// where `docker service ls` listed domebao_redis and domebao-preprod_redis
	// while both filtered forms returned nothing.
	res := adapter.Run(`names=$(docker service ls --format '{{.Name}}' | grep -E '(^|_)redis$') || exit 1; test -n "$names" || exit 1; for name in $names; do docker service inspect --format '{{.Spec.Name}}|{{json .Spec.TaskTemplate.ContainerSpec.Args}}|{{range .Spec.TaskTemplate.ContainerSpec.Secrets}}{{.SecretName}} {{end}}|{{.Spec.Mode.Replicated.Replicas}}' "$name" || exit; done`, 5*time.Second)
	result := CheckResult{ID: "runtime.redis_service", Title: "Private authenticated Redis services are configured", Category: "runtime", Severity: High}
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) == "" {
		result.Status = Failed
		result.Summary = "No application Redis Swarm service could be inspected."
		result.Remediation = "Redeploy with production.redis enabled."
		return result
	}
	for _, line := range nonEmptyLines(res.Stdout) {
		parts := strings.Split(line, "|")
		if len(parts) != 4 || !strings.Contains(parts[1], "--requirepass") || !strings.Contains(parts[2], "_redis_password_v1") || strings.TrimSpace(parts[3]) != "1" {
			result.Status = Failed
			result.Summary = "A Redis service is missing authentication, its Docker Secret, or the expected replica count."
			result.Remediation = "Redeploy Redis through Shuttle."
			result.Evidence = map[string]any{"service": line}
			return result
		}
	}
	result.Status = Passed
	result.Summary = "Redis is private, authenticated by Docker Secret, persistent and replicated as configured."
	return result
}

// checkDatabaseBindHBA rejects public listeners and permissive PostgreSQL HBA
// rules. It is intentionally strict when the configured database component is
// enabled: missing inspection tools/configuration is a failed posture.
func checkDatabaseBindHBA(adapter execx.Adapter) CheckResult {
	listeners := adapter.Run("ss -ltnH", 3*time.Second)
	hba := adapter.Run("command -v psql >/dev/null && command -v runuser >/dev/null && runuser -u postgres -- psql -AtF '|' -c \"SELECT coalesce(type,''), coalesce(address,''), coalesce(netmask,''), coalesce(auth_method,''), coalesce(error,'') FROM pg_hba_file_rules\"", 3*time.Second)
	result := CheckResult{ID: "runtime.database_bind_hba", Title: "Database bind and PostgreSQL HBA posture is private", Category: "runtime", Severity: High, Evidence: map[string]any{}}
	if listeners.ExitCode != 0 || hba.ExitCode != 0 {
		result.Status = Failed
		result.Summary = "Could not inspect database listeners or PostgreSQL pg_hba.conf."
		result.Remediation = "Install ss, keep database listeners on localhost/private interfaces, and provide a readable pg_hba.conf."
		return result
	}
	if (strings.TrimSpace(listeners.Stdout) != "" && !validListenerEvidence(listeners.Stdout)) || strings.TrimSpace(hba.Stdout) == "" {
		return collectionUnavailable(result.ID, result.Title, result.Category, result.Severity)
	}
	for _, line := range nonEmptyLines(hba.Stdout) {
		fields := strings.Split(line, "|")
		if len(fields) != 5 || (fields[0] != "local" && !strings.HasPrefix(fields[0], "host")) {
			return collectionUnavailable(result.ID, result.Title, result.Category, result.Severity)
		}
	}
	public := []string{}
	for _, line := range nonEmptyLines(listeners.Stdout) {
		if publicListenerPort(line, "5432") || publicListenerPort(line, "6379") {
			public = append(public, localListenerEndpoint(line))
		}
	}
	permissive := postgresHBAViolations(hba.Stdout)
	result.Evidence["publicListeners"] = public
	result.Evidence["hba"] = nonEmptyLines(hba.Stdout)
	result.Evidence["permissiveRules"] = permissive
	if len(public) > 0 || len(permissive) > 0 {
		result.Status = Failed
		result.Summary = "Database listeners or PostgreSQL HBA rules allow public access."
		result.Remediation = "Bind PostgreSQL and Redis to localhost/private interfaces and replace public trust HBA rules with restricted networks and authentication."
		return result
	}
	result.Status = Passed
	result.Summary = "Database listeners and PostgreSQL HBA rules are private."
	return result
}

func checkPHPFPMService(adapter execx.Adapter) CheckResult {
	res := adapter.Run("systemctl list-units --type=service --state=active 'php*-fpm.service' --no-legend", 3*time.Second)
	result := CheckResult{ID: "runtime.php_fpm_service", Title: "PHP-FPM service is active", Category: "runtime", Severity: High}
	if res.ExitCode == 0 && strings.TrimSpace(res.Stdout) != "" {
		result.Status = Passed
		result.Summary = "An active PHP-FPM service was detected."
		result.Evidence = map[string]any{"services": nonEmptyLines(res.Stdout)}
		return result
	}
	if !phpFPMInstalled(adapter) {
		result.Status = Skipped
		result.Summary = "PHP-FPM is not installed; this check is not applicable."
		return result
	}
	result.Status = Failed
	result.Summary = "No active PHP-FPM service was detected or systemd is unavailable."
	result.Remediation = "Install and enable the configured php-fpm service."
	return result
}

func checkPHPFPMSocket(adapter execx.Adapter) CheckResult {
	res := adapter.Run("find /run/php -maxdepth 1 -type s -name 'php*-fpm.sock' -print", 3*time.Second)
	result := CheckResult{ID: "runtime.php_fpm_socket", Title: "PHP-FPM socket is present", Category: "runtime", Severity: High}
	if res.ExitCode == 0 && strings.TrimSpace(res.Stdout) != "" {
		result.Status = Passed
		result.Summary = "A PHP-FPM Unix socket is present."
		result.Evidence = map[string]any{"sockets": nonEmptyLines(res.Stdout)}
		return result
	}
	if !phpFPMInstalled(adapter) {
		result.Status = Skipped
		result.Summary = "PHP-FPM is not installed; this check is not applicable."
		return result
	}
	result.Status = Failed
	result.Summary = "No PHP-FPM Unix socket was detected."
	result.Remediation = "Start PHP-FPM and configure the application to use its Unix socket."
	return result
}

func checkPHPOpCache(adapter execx.Adapter) CheckResult {
	res := adapter.Run("for f in /etc/php/*/fpm/conf.d/99-shuttle-opcache.ini; do [ -r \"$f\" ] || continue; grep -Eq '^[[:space:]]*opcache\\.enable[[:space:]]*=[[:space:]]*1([[:space:]]|$)' \"$f\" && printf '%s\\n' \"$f\" && exit 0; done; exit 1", 3*time.Second)
	value := strings.TrimSpace(res.Stdout)
	result := CheckResult{ID: "runtime.php_opcache", Title: "PHP-FPM OPcache drop-in is configured", Category: "runtime", Severity: Medium, Evidence: map[string]any{"fpmConfig": value}}
	if res.ExitCode == 0 && value != "" {
		result.Status = Passed
		result.Summary = "The managed PHP-FPM OPcache drop-in enables OPcache."
		return result
	}
	if !phpFPMInstalled(adapter) {
		result.Status = Skipped
		result.Summary = "PHP-FPM is not installed; this check is not applicable."
		return result
	}
	result.Status = Failed
	result.Summary = "PHP-FPM OPcache configuration is missing or disabled."
	result.Remediation = "Install/enable Zend OPcache and set opcache.enable=1 in the versioned PHP-FPM configuration."
	return result
}

func phpFPMInstalled(adapter execx.Adapter) bool {
	res := adapter.Run("systemctl list-unit-files --type=service 'php*-fpm.service' --no-legend | grep -q . || command -v php-fpm >/dev/null 2>&1", 3*time.Second)
	return res.ExitCode == 0
}

func postgresHBAViolations(raw string) []string {
	violations := []string{}
	for _, line := range nonEmptyLines(raw) {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "|") {
			fields := strings.Split(trimmed, "|")
			if len(fields) < 5 {
				violations = append(violations, trimmed)
				continue
			}
			if fields[4] != "" {
				violations = append(violations, trimmed)
				continue
			}
			// A reject rule denies the connection: it can never make access
			// public. On demo prod (2026-10-28) the standard closing rules
			// `host 0.0.0.0/0 reject`, `host ::/0 reject` and `local reject`
			// were listed as permissive, and doctor reported a private
			// database (127.0.0.1 and 172.16.0.0/12 over scram-sha-256) as
			// publicly reachable.
			if fields[3] == "reject" {
				continue
			}
			if fields[0] == "local" {
				if fields[3] != "peer" {
					violations = append(violations, trimmed)
				}
				continue
			}
			if !strings.HasPrefix(fields[0], "host") {
				continue
			}
			if fields[3] != "scram-sha-256" || !hbaRangeIsPrivate(fields[1], fields[2]) {
				violations = append(violations, trimmed)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "local" {
			if fields[3] != "peer" {
				violations = append(violations, trimmed)
			}
			continue
		}
		if !strings.HasPrefix(fields[0], "host") || len(fields) < 5 {
			continue
		}
		address, method := fields[3], fields[4]
		if method != "scram-sha-256" || !hbaRangeIsPrivate(address, "") {
			violations = append(violations, trimmed)
		}
	}
	return violations
}

// hbaRangeIsPrivate reports whether a pg_hba address covers loopback or private
// space only. Both ends of the range must stay private, so 0.0.0.0/0 and
// over-broad masks such as 172.16.0.0/8 are still rejected. Docker bridge
// networks vary per host (172.17.0.0/16, 172.18.0.0/16 and beyond), so they are
// matched by range rather than hardcoded.
func hbaRangeIsPrivate(address, netmask string) bool {
	switch strings.ToLower(strings.TrimSpace(address)) {
	case "localhost", "samehost":
		return true
	}
	network, ok := hbaNetwork(address, netmask)
	if !ok {
		return false
	}
	return hbaPrivateIP(network.IP) && hbaPrivateIP(hbaLastAddress(network))
}

func hbaPrivateIP(ip net.IP) bool {
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func hbaNetwork(address, netmask string) (*net.IPNet, bool) {
	address = strings.TrimSpace(address)
	netmask = strings.TrimSpace(netmask)
	if address == "" {
		return nil, false
	}
	if strings.Contains(address, "/") {
		_, network, err := net.ParseCIDR(address)
		if err != nil {
			return nil, false
		}
		return network, true
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, false
	}
	if netmask == "" {
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, true
	}
	mask := net.ParseIP(netmask)
	if mask == nil {
		return nil, false
	}
	if v4 := mask.To4(); v4 != nil {
		return &net.IPNet{IP: ip.Mask(net.IPMask(v4)), Mask: net.IPMask(v4)}, true
	}
	converted := net.IPMask(mask.To16())
	return &net.IPNet{IP: ip.Mask(converted), Mask: converted}, true
}

func hbaLastAddress(network *net.IPNet) net.IP {
	ip, mask := network.IP, network.Mask
	if len(mask) == net.IPv4len {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
	}
	if len(ip) != len(mask) {
		return nil
	}
	last := make(net.IP, len(ip))
	for i := range ip {
		last[i] = ip[i] | ^mask[i]
	}
	return last
}

func checkNodeNPMVersions(adapter execx.Adapter) CheckResult {
	res := adapter.Run("node --version && npm --version", 3*time.Second)
	lines := nonEmptyLines(res.Stdout)
	result := CheckResult{ID: "runtime.node_npm_versions", Title: "Node.js and npm versions are available", Category: "runtime", Severity: High, Evidence: map[string]any{"versions": lines}}
	if res.ExitCode == 0 && len(lines) >= 2 && regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(lines[0]) && regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+`).MatchString(lines[1]) {
		result.Status = Passed
		result.Summary = fmt.Sprintf("Node.js %s and npm %s are available.", lines[0], lines[1])
		return result
	}
	result.Status = Failed
	result.Summary = "Node.js and npm versions are unavailable or could not be parsed."
	result.Remediation = "Install supported Node.js and npm binaries and ensure both are available on PATH."
	return result
}

// checkUpdatesPending counts pending APT upgrades. Skipped on non-APT hosts.
func checkUpdatesPending(adapter execx.Adapter) CheckResult {
	if adapter.Run("command -v apt >/dev/null 2>&1", time.Second).ExitCode != 0 {
		return CheckResult{
			ID: "system.updates_pending", Title: "No pending package updates",
			Category: "system", Severity: Medium, Status: Skipped,
			Summary: "apt is not available; cannot evaluate pending updates.",
		}
	}
	res := adapter.Run("body=$(apt list --upgradable 2>/dev/null) || exit; printf '%s\\n' \"$body\" | tail -n +2 | wc -l", 5*time.Second)
	count, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if res.ExitCode != 0 || err != nil || count < 0 {
		return collectionUnavailable("system.updates_pending", "No pending package updates", "system", Medium)
	}
	status := Passed
	severity := Medium
	summary := "No pending package updates."
	if count > 0 {
		status = Failed
		summary = fmt.Sprintf("%d pending package update(s).", count)
		if count >= 50 {
			severity = High
		}
	}
	return CheckResult{
		ID: "system.updates_pending", Title: "No pending package updates",
		Category: "system", Severity: severity, Status: status,
		Summary:     summary,
		Remediation: "Run 'apt update && apt upgrade' (or rely on unattended-upgrades) to apply pending package updates.",
		Evidence:    map[string]any{"pendingCount": count},
	}
}

// checkMemoryLow warns when available memory is below 10% of total.
func checkMemoryLow(adapter execx.Adapter) CheckResult {
	res := adapter.Run(pipefailCommand("free -m | awk '/^Mem:/ {print $2, $7}'"), 2*time.Second)
	parts := strings.Fields(strings.TrimSpace(res.Stdout))
	if res.ExitCode != 0 || len(parts) < 2 {
		return CheckResult{
			ID: "system.memory_low", Title: "Available memory has enough headroom",
			Category: "system", Severity: Medium, Status: Skipped,
			Summary: "free is not available or returned no data.",
		}
	}
	total, totalErr := strconv.Atoi(parts[0])
	available, availableErr := strconv.Atoi(parts[1])
	if totalErr != nil || availableErr != nil || total <= 0 || available < 0 || available > total {
		return CheckResult{
			ID: "system.memory_low", Title: "Available memory has enough headroom",
			Category: "system", Severity: Medium, Status: Skipped,
			Summary: "Could not parse total memory.",
		}
	}
	pct := (available * 100) / total
	status := Passed
	severity := Medium
	summary := fmt.Sprintf("Available memory is %d%% of total (%d MB / %d MB).", pct, available, total)
	if pct < 5 {
		status = Failed
		severity = High
	} else if pct < 10 {
		status = Failed
	}
	return CheckResult{
		ID: "system.memory_low", Title: "Available memory has enough headroom",
		Category: "system", Severity: severity, Status: status,
		Summary:     summary,
		Remediation: "Add swap, scale up the VPS, or reduce container memory footprint. Investigate workloads with abnormal RSS growth.",
		Evidence:    map[string]any{"totalMB": total, "availableMB": available, "availablePercent": pct},
	}
}

// checkDockerPublishedSensitivePorts inspects docker port mappings and flags
// containers publishing sensitive ports on public interfaces.
func checkDockerPublishedSensitivePorts(adapter execx.Adapter) CheckResult {
	res := adapter.Run("docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null", 5*time.Second)
	if res.ExitCode != 0 {
		return CheckResult{
			ID: "firewall.docker_published_sensitive_ports", Title: "Docker does not publish sensitive ports publicly",
			Category: "firewall", Severity: High, Status: Skipped,
			Summary: "Docker is not available; cannot evaluate published ports.",
		}
	}
	exposures := []map[string]string{}
	for _, line := range nonEmptyLines(res.Stdout) {
		name, ports := splitTab2(line)
		if !strings.Contains(line, "\t") && !regexp.MustCompile(`^/?[a-zA-Z0-9][a-zA-Z0-9_.-]*$`).MatchString(line) {
			return collectionUnavailable("firewall.docker_published_sensitive_ports", "Docker does not publish sensitive ports publicly", "firewall", High)
		}
		for _, port := range sensitiveDockerPorts {
			pattern := regexp.MustCompile(`(\[[^]]+\]|[0-9a-fA-F.:]+):` + port + `->`)
			for _, match := range pattern.FindAllStringSubmatch(ports, -1) {
				if !privateDockerBindAddress(match[1]) {
					exposures = append(exposures, map[string]string{"workload": strings.TrimPrefix(name, "/"), "port": port})
				}
			}
		}
	}
	status := Passed
	summary := "No Docker container publishes a sensitive port on public interfaces."
	if len(exposures) > 0 {
		status = Failed
		names := make([]string, 0, len(exposures))
		for _, e := range exposures {
			names = append(names, e["workload"]+":"+e["port"])
		}
		summary = fmt.Sprintf("%d sensitive Docker port mapping(s) on public interfaces: %s.", len(exposures), strings.Join(names, ", "))
	}
	return CheckResult{
		ID: "firewall.docker_published_sensitive_ports", Title: "Docker does not publish sensitive ports publicly",
		Category: "firewall", Severity: High, Status: status,
		Summary:     summary,
		Remediation: "Bind sensitive container ports to 127.0.0.1 (e.g. '127.0.0.1:5432:5432') or to a private Docker network instead of '0.0.0.0'.",
		Evidence:    map[string]any{"exposures": exposures, "sensitivePorts": sensitiveDockerPorts},
	}
}

// caddyfileSearchCommand reads host-managed files or the shared Swarm config.
const caddyfileSearchCommand = "for f in /etc/caddy/Caddyfile /etc/shuttle/Caddyfile /opt/shuttle/caddy/Caddyfile ./Caddyfile; do if [ -r \"$f\" ]; then echo __caddyfile__=\"$f\"; cat \"$f\"; exit $?; fi; done; id=$(docker ps --filter label=com.docker.swarm.service.name=shuttle-edge_caddy -q | head -n 1); test -n \"$id\" && echo __caddyfile__=swarm:shuttle-edge_caddy && docker exec \"$id\" cat /etc/caddy/Caddyfile"

// checkCaddySecurityHeaders looks for HSTS + X-Content-Type-Options in Caddyfile.
func checkCaddySecurityHeaders(adapter execx.Adapter) CheckResult {
	res := adapter.Run(caddyfileSearchCommand, 3*time.Second)
	if res.ExitCode != 0 {
		return CheckResult{
			ID: "caddy.no_security_headers", Title: "Caddy emits baseline security headers",
			Category: "reverse-proxy", Severity: Medium, Status: Skipped,
			Summary: "No readable Caddyfile detected (looked in /etc/caddy, /opt/caddy, and current dir).",
		}
	}
	path := capture(res.Stdout, `__caddyfile__=([^\n]+)`)
	body := res.Stdout
	hasHSTS := regexp.MustCompile(`(?i)Strict-Transport-Security`).MatchString(body)
	hasNoSniff := regexp.MustCompile(`(?i)X-Content-Type-Options`).MatchString(body)
	hasReferrer := regexp.MustCompile(`(?i)Referrer-Policy`).MatchString(body)
	missing := []string{}
	if !hasHSTS {
		missing = append(missing, "Strict-Transport-Security")
	}
	if !hasNoSniff {
		missing = append(missing, "X-Content-Type-Options")
	}
	if !hasReferrer {
		missing = append(missing, "Referrer-Policy")
	}
	status := Passed
	summary := "Caddyfile sets baseline security headers."
	if len(missing) > 0 {
		status = Failed
		summary = "Caddyfile is missing baseline security headers: " + strings.Join(missing, ", ") + "."
	}
	return CheckResult{
		ID: "caddy.no_security_headers", Title: "Caddy emits baseline security headers",
		Category: "reverse-proxy", Severity: Medium, Status: status,
		Summary:     summary,
		Remediation: "Add a 'header' block in Caddyfile setting Strict-Transport-Security, X-Content-Type-Options nosniff, and a Referrer-Policy.",
		Evidence:    map[string]any{"caddyfile": strings.TrimSpace(path), "missing": missing},
	}
}

// checkCaddyConfigValid runs `caddy validate` on the active Caddyfile.
func checkCaddyConfigValid(adapter execx.Adapter) CheckResult {
	command := "if command -v caddy >/dev/null 2>&1 && [ -r /etc/caddy/Caddyfile ]; then caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; else id=$(docker ps --filter label=com.docker.swarm.service.name=shuttle-edge_caddy -q | head -n 1); test -n \"$id\" && docker exec \"$id\" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; fi"
	res := adapter.Run(command, 5*time.Second)
	if res.ExitCode == 0 {
		return CheckResult{
			ID: "caddy.invalid_config", Title: "Caddy configuration is valid",
			Category: "reverse-proxy", Severity: High, Status: Passed,
			Summary: "Caddy validated the active shared configuration.",
		}
	}
	return CheckResult{
		ID: "caddy.invalid_config", Title: "Caddy configuration is valid",
		Category: "reverse-proxy", Severity: High, Status: Failed,
		Summary:     "Caddy could not validate the active shared configuration.",
		Remediation: "Fix the Caddyfile errors reported by 'caddy validate' before reloading the proxy.",
		Evidence:    map[string]any{"output": strings.TrimSpace(res.Stdout + "\n" + res.Stderr)},
	}
}

// checkTLSCert verifies the public TLS certificate of cfg.App.Domain.
// Combined check: missing cert OR expiring soon.
func checkTLSCertificate(domain string) Check {
	return func(adapter execx.Adapter) CheckResult {
		if domain == "" || !safeHostname(domain) {
			return CheckResult{
				ID: "tls.cert_missing", Title: "TLS certificate is present and valid",
				Category: "tls", Severity: Critical, Status: Skipped,
				Summary: "No valid domain configured in config.json; skipping TLS check.",
			}
		}
		if adapter.Run("command -v openssl >/dev/null 2>&1", time.Second).ExitCode != 0 {
			return CheckResult{
				ID: "tls.cert_missing", Title: "TLS certificate is present and valid",
				Category: "tls", Severity: Critical, Status: Skipped,
				Summary: "openssl is not available; cannot evaluate TLS certificate.",
			}
		}
		quoted := shell.Escape(domain)
		cmd := fmt.Sprintf("echo | openssl s_client -servername %s -connect %s:443 -verify_return_error -verify_hostname %s 2>/dev/null | openssl x509 -noout -enddate -subject 2>/dev/null", quoted, quoted, quoted)
		res := adapter.Run(pipefailCommand(cmd), 8*time.Second)
		if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) == "" {
			return CheckResult{
				ID: "tls.cert_missing", Title: "TLS certificate is present and valid",
				Category: "tls", Severity: Critical, Status: Failed,
				Summary:     "Could not retrieve a TLS certificate for " + domain + ".",
				Remediation: "Verify the domain points to this server, that ports 80/443 are open, and that Caddy/your reverse proxy issued a certificate.",
				Evidence:    map[string]any{"domain": domain},
			}
		}
		notAfter := capture(res.Stdout, `notAfter=([^\n]+)`)
		end, err := time.Parse("Jan 2 15:04:05 2006 MST", strings.TrimSpace(notAfter))
		if err != nil {
			return CheckResult{
				ID: "tls.cert_missing", Title: "TLS certificate is present and valid",
				Category: "tls", Severity: Critical, Status: Unknown,
				Summary:  "Could not parse certificate expiration date.",
				Evidence: map[string]any{"domain": domain, "notAfter": notAfter},
			}
		}
		days := int(time.Until(end).Hours() / 24)
		status := Passed
		severity := Medium
		summary := fmt.Sprintf("Certificate for %s is valid; expires in %d day(s).", domain, days)
		remediation := ""
		if days < 0 {
			status = Failed
			severity = Critical
			summary = fmt.Sprintf("Certificate for %s expired %d day(s) ago.", domain, -days)
			remediation = "Renew the TLS certificate immediately; users get a browser warning until then."
		} else if days < 14 {
			status = Failed
			severity = High
			summary = fmt.Sprintf("Certificate for %s expires in %d day(s).", domain, days)
			remediation = "Investigate ACME renewal failure (Caddy logs, DNS, ports 80/443) before the cert expires."
		}
		return CheckResult{
			ID: "tls.cert_missing", Title: "TLS certificate is present and valid",
			Category: "tls", Severity: severity, Status: status,
			Summary:     summary,
			Remediation: remediation,
			Evidence:    map[string]any{"domain": domain, "notAfter": notAfter, "daysRemaining": days},
		}
	}
}

// checkSecretsWeakPermissions finds env/key files in the project tree that are world-readable.
func checkSecretsWeakPermissions(adapter execx.Adapter) CheckResult {
	cmd := "find . -maxdepth 3 -type f \\( -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa' -o -name 'id_ed25519' \\) -perm /o+r 2>/dev/null"
	res := adapter.Run(cmd, 3*time.Second)
	if res.ExitCode != 0 {
		return CheckResult{
			ID: "secrets.weak_file_permissions", Title: "Secret files are not world-readable",
			Category: "secrets", Severity: High, Status: Skipped,
			Summary: "find is not available or returned an error.",
		}
	}
	files := nonEmptyLines(res.Stdout)
	status := Passed
	summary := "No world-readable secret files detected in the project tree."
	if len(files) > 0 {
		status = Failed
		summary = fmt.Sprintf("%d world-readable secret file(s): %s.", len(files), strings.Join(files, ", "))
	}
	return CheckResult{
		ID: "secrets.weak_file_permissions", Title: "Secret files are not world-readable",
		Category: "secrets", Severity: High, Status: status,
		Summary:     summary,
		Remediation: "chmod 600 the affected secret files (env/keys/PEM) and ensure their containing directory is not world-listable.",
		Evidence:    map[string]any{"files": files},
	}
}

// checkHSTSHeader probes the public URL and verifies a Strict-Transport-Security header.
func checkHSTSHeader(domain string) Check {
	return func(adapter execx.Adapter) CheckResult {
		if domain == "" || !safeHostname(domain) {
			return CheckResult{
				ID: "tls.hsts_missing", Title: "HSTS header is enforced",
				Category: "tls", Severity: Medium, Status: Skipped,
				Summary: "No valid app.domain configured; skipping HSTS probe.",
			}
		}
		if adapter.Run("command -v curl >/dev/null 2>&1", time.Second).ExitCode != 0 {
			return CheckResult{
				ID: "tls.hsts_missing", Title: "HSTS header is enforced",
				Category: "tls", Severity: Medium, Status: Skipped,
				Summary: "curl is not available on the target.",
			}
		}
		url := "https://" + domain
		res := adapter.Run("curl -sI --max-time 5 "+shell.Escape(url)+" | grep -i '^Strict-Transport-Security'", 8*time.Second)
		if res.ExitCode == 0 && strings.TrimSpace(res.Stdout) != "" {
			return CheckResult{
				ID: "tls.hsts_missing", Title: "HSTS header is enforced",
				Category: "tls", Severity: Medium, Status: Passed,
				Summary:  "HSTS header present on " + url + ".",
				Evidence: map[string]any{"url": url, "header": strings.TrimSpace(res.Stdout)},
			}
		}
		return CheckResult{
			ID: "tls.hsts_missing", Title: "HSTS header is enforced",
			Category: "tls", Severity: Medium, Status: Failed,
			Summary:     "No Strict-Transport-Security header on " + url + ".",
			Remediation: "Add 'header Strict-Transport-Security \"max-age=31536000; includeSubDomains\"' in the Caddyfile (or equivalent in your reverse proxy).",
			Evidence:    map[string]any{"url": url},
		}
	}
}

// checkDNSPointsToServer compares the A record for app.domain with the server's
// public IP. Skipped if either side cannot be determined.
func checkDNSPointsToServer(domain string) Check {
	return func(adapter execx.Adapter) CheckResult {
		if domain == "" || !safeHostname(domain) {
			return CheckResult{
				ID: "dns.domain_not_pointing_to_server", Title: "DNS A record points to this server",
				Category: "dns", Severity: Medium, Status: Skipped,
				Summary: "No valid app.domain configured; skipping DNS check.",
			}
		}
		if adapter.Run("command -v dig >/dev/null 2>&1", time.Second).ExitCode != 0 {
			return CheckResult{
				ID: "dns.domain_not_pointing_to_server", Title: "DNS A record points to this server",
				Category: "dns", Severity: Medium, Status: Skipped,
				Summary: "dig is not available on the target.",
			}
		}
		checkpoint := collectionCheckpoint(adapter)
		dnsRes := adapter.Run(pipefailCommand("dig +short A "+shell.Escape(domain)+" | tail -n 1"), 5*time.Second)
		dnsIP := strings.TrimSpace(dnsRes.Stdout)
		resolverNote := ""
		if dnsRes.ExitCode != 0 || net.ParseIP(dnsIP).To4() == nil {
			// The host resolver can be filtered, offline, or still holding a
			// negative answer. Ask a public resolver before declaring the
			// record missing, otherwise a local DNS fault is reported as a
			// zone misconfiguration the operator does not actually have.
			fallbackDNS := adapter.Run(pipefailCommand("dig +short A "+shell.Escape(domain)+" @1.1.1.1 | tail -n 1"), 5*time.Second)
			dnsIP = strings.TrimSpace(fallbackDNS.Stdout)
			if fallbackDNS.ExitCode != 0 {
				return collectionUnavailable("dns.domain_not_pointing_to_server", "DNS A record points to this server", "dns", Medium)
			} else if net.ParseIP(dnsIP).To4() != nil {
				collectionRecovered(adapter, checkpoint)
			}
			if dnsIP != "" {
				resolverNote = " Resolved through 1.1.1.1; this host's own resolver returned nothing, which is worth investigating separately."
			}
		}
		if dnsIP == "" {
			return CheckResult{
				ID: "dns.domain_not_pointing_to_server", Title: "DNS A record points to this server",
				Category: "dns", Severity: Medium, Status: Failed,
				Summary:     "dig returned no A record for " + domain + ".",
				Remediation: "Create an A record for " + domain + " pointing at this server's public IP.",
				Evidence:    map[string]any{"domain": domain},
			}
		}
		ipRes := adapter.Run("curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null", 8*time.Second)
		serverIP := strings.TrimSpace(ipRes.Stdout)
		if ipRes.ExitCode != 0 || net.ParseIP(serverIP).To4() == nil || net.ParseIP(dnsIP).To4() == nil {
			return CheckResult{
				ID: "dns.domain_not_pointing_to_server", Title: "DNS A record points to this server",
				Category: "dns", Severity: Medium, Status: Skipped,
				Summary:  "Could not determine the server's public IP; DNS A record is " + dnsIP + ".",
				Evidence: map[string]any{"domain": domain, "dnsIP": dnsIP},
			}
		}
		if dnsIP == serverIP {
			return CheckResult{
				ID: "dns.domain_not_pointing_to_server", Title: "DNS A record points to this server",
				Category: "dns", Severity: Medium, Status: Passed,
				Summary:  domain + " resolves to this server (" + serverIP + ")." + resolverNote,
				Evidence: map[string]any{"domain": domain, "dnsIP": dnsIP, "serverIP": serverIP},
			}
		}
		return CheckResult{
			ID: "dns.domain_not_pointing_to_server", Title: "DNS A record points to this server",
			Category: "dns", Severity: Medium, Status: Failed,
			Summary:     fmt.Sprintf("%s resolves to %s but server's public IP is %s.%s", domain, dnsIP, serverIP, resolverNote),
			Remediation: "Update the A record to point directly at this server.",
			Evidence:    map[string]any{"domain": domain, "dnsIP": dnsIP, "serverIP": serverIP},
		}
	}
}

// checkDatabaseBackup detects a recent backup artifact or a backup-related cron job.
func checkDatabaseBackup(adapter execx.Adapter) CheckResult {
	timer := adapter.Run("systemctl is-enabled --quiet shuttle-postgres-backup.timer && systemctl is-active --quiet shuttle-postgres-backup.timer", 3*time.Second)
	artifactsRes := adapter.Run(pipefailCommand("find /var/backups/shuttle-postgres -maxdepth 1 -type f -name '*.sql.gz' -mtime -2 2>/dev/null | sed -n '1,5p'"), 5*time.Second)
	artifacts := nonEmptyLines(artifactsRes.Stdout)
	if timer.ExitCode == 0 && artifactsRes.ExitCode == 0 && len(artifacts) > 0 {
		return CheckResult{
			ID: "db.no_backup_detected", Title: "Database backups are configured",
			Category: "backups", Severity: High, Status: Passed,
			Summary:  fmt.Sprintf("The backup timer is active and %d recent local backup(s) exist.", len(artifacts)),
			Evidence: map[string]any{"artifacts": artifacts, "timerActive": true},
		}
	}
	return CheckResult{
		ID: "db.no_backup_detected", Title: "Database backups are configured",
		Category: "backups", Severity: High, Status: Failed,
		Summary:     "The native PostgreSQL backup timer is inactive or no recent local backup exists.",
		Remediation: "Enable shuttle-postgres-backup.timer and run /usr/local/sbin/shuttle-postgres-backup once.",
		Evidence:    map[string]any{"artifacts": artifacts, "timerActive": timer.ExitCode == 0},
	}
}

// checkHealthEndpoint probes cfg.App.Domain + cfg.App.HealthcheckPath for a 2xx response.
func checkHealthEndpoint(domain string, path string) Check {
	return func(adapter execx.Adapter) CheckResult {
		if domain == "" || path == "" || !safeHostname(domain) || !safeHTTPPath(path) {
			return CheckResult{
				ID: "monitoring.no_health_endpoint", Title: "App exposes a health endpoint",
				Category: "monitoring", Severity: Medium, Status: Skipped,
				Summary: "app.domain or app.healthcheckPath is missing or invalid; skipping health probe.",
			}
		}
		if adapter.Run("command -v curl >/dev/null 2>&1", time.Second).ExitCode != 0 {
			return CheckResult{
				ID: "monitoring.no_health_endpoint", Title: "App exposes a health endpoint",
				Category: "monitoring", Severity: Medium, Status: Skipped,
				Summary: "curl is not available on the target.",
			}
		}
		url := "https://" + domain + path
		res := adapter.Run("curl -fsS --max-time 5 -o /dev/null -w '%{http_code}' "+shell.Escape(url), 8*time.Second)
		code := strings.TrimSpace(res.Stdout)
		if res.ExitCode == 0 && regexp.MustCompile(`^2[0-9]{2}$`).MatchString(code) {
			return CheckResult{
				ID: "monitoring.no_health_endpoint", Title: "App exposes a health endpoint",
				Category: "monitoring", Severity: Medium, Status: Passed,
				Summary:  url + " returned HTTP " + code + ".",
				Evidence: map[string]any{"url": url, "httpCode": code},
			}
		}
		return CheckResult{
			ID: "monitoring.no_health_endpoint", Title: "App exposes a health endpoint",
			Category: "monitoring", Severity: Medium, Status: Failed,
			Summary:     url + " did not return a 2xx response (got " + fallback(code, "n/a") + ").",
			Remediation: "Implement a health endpoint returning 200 OK and reference it via services.web.healthcheck.path in config.json.",
			Evidence:    map[string]any{"url": url, "httpCode": code},
		}
	}
}
