package readiness

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func TestUpdatesPendingSkippedWithoutApt(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 1}
	}}
	res := checkUpdatesPending(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestUpdatesPendingPassesWhenZero(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v apt") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "0\n"}
	}}
	res := checkUpdatesPending(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestUpdatesPendingFailsWithCount(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v apt") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "12\n"}
	}}
	res := checkUpdatesPending(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
	if res.Severity != Medium {
		t.Fatalf("expected medium severity, got %s", res.Severity)
	}
}

func TestUpdatesPendingHighSeverityWhenLargeBacklog(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v apt") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "120\n"}
	}}
	res := checkUpdatesPending(adapter)
	if res.Severity != High {
		t.Fatalf("expected high severity, got %s", res.Severity)
	}
}

func TestMemoryLowFailsBelow10Percent(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "8000 400\n"}
	}}
	res := checkMemoryLow(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestMemoryLowCriticalSeverityBelow5Percent(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "8000 200\n"}
	}}
	res := checkMemoryLow(adapter)
	if res.Severity != High {
		t.Fatalf("expected high severity, got %s", res.Severity)
	}
}

func TestMemoryLowPassesWithHeadroom(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "8000 4000\n"}
	}}
	res := checkMemoryLow(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestMemoryLowSkippedOnEmptyOutput(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: ""}
	}}
	res := checkMemoryLow(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestDockerPublishedSensitivePortsFlagsBinding(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "pg_main\t0.0.0.0:5432->5432/tcp\nweb\t0.0.0.0:443->443/tcp\n"}
	}}
	res := checkDockerPublishedSensitivePorts(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
	if !strings.Contains(res.Summary, "pg_main:5432") {
		t.Fatalf("expected summary to include pg_main:5432, got %q", res.Summary)
	}
}

func TestDockerPublishedSensitivePortsPassesWithLocalhostBinding(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "pg_main\t127.0.0.1:5432->5432/tcp\n"}
	}}
	res := checkDockerPublishedSensitivePorts(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestDockerPublishedSensitivePortsSkippedWithoutDocker(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 1}
	}}
	res := checkDockerPublishedSensitivePorts(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestCaddySecurityHeadersFailsOnMissing(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "__caddyfile__=/etc/caddy/Caddyfile\nexample.com {\n  reverse_proxy app:3000\n}\n"}
	}}
	res := checkCaddySecurityHeaders(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
	missing, _ := res.Evidence["missing"].([]string)
	if len(missing) != 3 {
		t.Fatalf("expected 3 missing headers, got %v", missing)
	}
}

func TestCaddySecurityHeadersPassesWithBaseline(t *testing.T) {
	body := "__caddyfile__=/etc/caddy/Caddyfile\nexample.com {\n  header Strict-Transport-Security max-age=31536000\n  header X-Content-Type-Options nosniff\n  header Referrer-Policy strict-origin\n}\n"
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: body}
	}}
	res := checkCaddySecurityHeaders(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestCaddySecurityHeadersSkippedWhenNoCaddyfile(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 1}
	}}
	res := checkCaddySecurityHeaders(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestCaddyConfigValidFailsWithoutHostOrSwarmBinary(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 1}
	}}
	res := checkCaddyConfigValid(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestCaddyConfigValidPassesWhenValidate0(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0}
	}}
	res := checkCaddyConfigValid(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestMissingEnvAndAdminerAreSafeAbsence(t *testing.T) {
	adapter := scriptedAdapter{respond: func(command string) execx.Result {
		if strings.Contains(command, "printf absent") {
			return execx.Result{Stdout: "absent"}
		}
		return execx.Result{}
	}}
	if got := checkEnvWorldReadable(adapter); got.Status != Skipped || got.SkipReason != NotApplicable {
		t.Fatalf("proven absent .env should be not applicable: %+v", got)
	}
	if got := checkAdminerRestricted(adapter); got.Status != Skipped || got.SkipReason != NotApplicable {
		t.Fatalf("proven absent Adminer should be not applicable: %+v", got)
	}
}

func TestCaddyConfigValidFailsOnValidateError(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 1, Stdout: "syntax error at line 4"}
	}}
	res := checkCaddyConfigValid(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestTLSCertificateSkippedWithoutDomain(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0}
	}}
	res := checkTLSCertificate("")(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestTLSCertificateFailsWhenOpenSSLReturnsEmpty(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v openssl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: ""}
	}}
	res := checkTLSCertificate("example.com")(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestTLSCertificatePassesForHealthyOrigin(t *testing.T) {
	expires := time.Now().Add(90*24*time.Hour).UTC().Format("Jan 2 15:04:05 2006") + " GMT"
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v openssl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "notAfter=" + expires + "\n"}
	}}
	res := checkTLSCertificate("example.com")(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed when the origin serves TLS, got %+v", res)
	}
}

func TestDirectDNSPointsToServerFailsOnMismatch(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.Contains(cmd, "command -v dig"):
			return execx.Result{ExitCode: 0}
		case strings.Contains(cmd, "dig +short A"):
			return execx.Result{ExitCode: 0, Stdout: "104.21.73.19\n"}
		default:
			return execx.Result{ExitCode: 0, Stdout: "81.49.255.182\n"}
		}
	}}
	res := checkDNSPointsToServer("app.example.com")(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed without a tunnel, got %+v", res)
	}
}

func TestTLSCertificateFailsWhenExpiringSoon(t *testing.T) {
	expires := time.Now().Add(7*24*time.Hour).UTC().Format("Jan 2 15:04:05 2006") + " GMT"
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v openssl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "notAfter=" + expires + "\nsubject=CN=example.com\n"}
	}}
	res := checkTLSCertificate("example.com")(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
	if res.Severity != High {
		t.Fatalf("expected high severity, got %s", res.Severity)
	}
}

func TestTLSCertificatePassesWhenLongLived(t *testing.T) {
	expires := time.Now().Add(60*24*time.Hour).UTC().Format("Jan 2 15:04:05 2006") + " GMT"
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v openssl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: fmt.Sprintf("notAfter=%s\nsubject=CN=example.com\n", expires)}
	}}
	res := checkTLSCertificate("example.com")(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestSecretsWeakPermissionsPassesOnEmpty(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: ""}
	}}
	res := checkSecretsWeakPermissions(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestSecretsWeakPermissionsFailsWhenFilesFound(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "./.env.production\n./certs/server.key\n"}
	}}
	res := checkSecretsWeakPermissions(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
	files, _ := res.Evidence["files"].([]string)
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %v", files)
	}
}

func TestHealthEndpointSkippedWithoutDomain(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0}
	}}
	res := checkHealthEndpoint("", "/health")(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestPostgreSQLAndRedisRuntimeChecks(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.Contains(cmd, "systemctl is-active --quiet postgresql"):
			return execx.Result{ExitCode: 0}
		case strings.Contains(cmd, "docker service ls"):
			return execx.Result{ExitCode: 0, Stdout: "demo_redis|[\"--requirepass\"]|demo_redis_password_v1 |1\n"}
		case strings.HasPrefix(cmd, "ss -ltnH"):
			return execx.Result{ExitCode: 0, Stdout: "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:6379 0.0.0.0:*\n"}
		case strings.Contains(cmd, "pg_hba_file_rules"):
			return execx.Result{ExitCode: 0, Stdout: "local|||peer|\nhost|127.0.0.1||scram-sha-256|\n"}
		default:
			return execx.Result{ExitCode: 1}
		}
	}}
	for _, got := range []CheckResult{checkPostgreSQLService(adapter), checkRedisService(adapter), checkDatabaseBindHBA(adapter)} {
		if got.Status != Passed {
			t.Fatalf("expected runtime check to pass, got %+v", got)
		}
	}
}

func TestDatabaseBindHBARejectsPublicPosture(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.HasPrefix(cmd, "ss -ltnH") {
			return execx.Result{ExitCode: 0, Stdout: "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n"}
		}
		return execx.Result{ExitCode: 0, Stdout: "host|0.0.0.0|0.0.0.0|trust|\n"}
	}}
	if got := checkDatabaseBindHBA(adapter); got.Status != Failed {
		t.Fatalf("expected public database posture to fail, got %+v", got)
	}
}

func TestDatabaseBindHBARejectsCoveringTrustRule(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.HasPrefix(cmd, "ss -ltnH") {
			return execx.Result{ExitCode: 0, Stdout: "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"}
		}
		return execx.Result{ExitCode: 0, Stdout: "host|172.16.0.0|255.240.0.0|trust|\nhost|127.0.0.1||scram-sha-256|\n"}
	}}
	if got := checkDatabaseBindHBA(adapter); got.Status != Failed {
		t.Fatalf("expected covering trust HBA rule to fail, got %+v", got)
	}
}

func TestDatabaseBindHBARejectsLocalTrustRule(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.HasPrefix(cmd, "ss -ltnH") {
			return execx.Result{ExitCode: 0, Stdout: "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"}
		}
		return execx.Result{ExitCode: 0, Stdout: "local|||trust|\n"}
	}}
	if got := checkDatabaseBindHBA(adapter); got.Status != Failed {
		t.Fatalf("expected local trust HBA rule to fail, got %+v", got)
	}
}

// Swarm names a stack service <stack>_redis, and `docker service ls --filter
// name=` matches by PREFIX: `name=_redis` matched nothing on a host running
// domebao_redis and domebao-preprod_redis, so the check reported no Redis
// service at all.
func TestRedisServiceFindsAStackScopedService(t *testing.T) {
	var listed string
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		listed = cmd
		if strings.Contains(cmd, "--filter name=_redis") {
			return execx.Result{ExitCode: 1}
		}
		return execx.Result{ExitCode: 0, Stdout: `domebao_redis|["--requirepass","x"]|domebao_redis_password_v1 |1` + "\n"}
	}}
	got := checkRedisService(adapter)
	if strings.Contains(listed, "--filter name=_redis") {
		t.Fatalf("a prefix filter cannot find <stack>_redis: %q", listed)
	}
	if got.Status != Passed {
		t.Fatalf("a stack-scoped Redis service must be found: %+v", got)
	}
}

func TestRedisServiceRejectsUnauthenticatedPing(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "systemctl is-active --quiet redis-server") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "PONG\n"}
	}}
	if got := checkRedisService(adapter); got.Status != Failed {
		t.Fatalf("expected unauthenticated Redis ping to fail, got %+v", got)
	}
}

func TestPHPRuntimeChecks(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.Contains(cmd, "list-units --type=service"):
			return execx.Result{ExitCode: 0, Stdout: "php8.3-fpm.service loaded active running PHP 8.3 FastCGI Process Manager\n"}
		case strings.HasPrefix(cmd, "find /run/php"):
			return execx.Result{ExitCode: 0, Stdout: "/run/php/php8.3-fpm.sock\n"}
		case strings.HasPrefix(cmd, "for f in /etc/php"):
			return execx.Result{ExitCode: 0, Stdout: "/etc/php/8.3/fpm/conf.d/99-shuttle-opcache.ini\n"}
		default:
			return execx.Result{ExitCode: 1}
		}
	}}
	for _, got := range []CheckResult{checkPHPFPMService(adapter), checkPHPFPMSocket(adapter), checkPHPOpCache(adapter)} {
		if got.Status != Passed {
			t.Fatalf("expected PHP runtime check to pass, got %+v", got)
		}
	}
}

func TestPHPRuntimeChecksSkipWhenPHPFPMIsAbsent(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 1}
	}}
	for _, got := range []CheckResult{checkPHPFPMService(adapter), checkPHPFPMSocket(adapter), checkPHPOpCache(adapter)} {
		if got.Status != Skipped {
			t.Fatalf("expected absent PHP-FPM to be skipped, got %+v", got)
		}
	}
}

func TestNodeNPMVersionsRequireBothBinaries(t *testing.T) {
	passed := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "v22.14.0\n10.9.2\n"}
	}}
	if got := checkNodeNPMVersions(passed); got.Status != Passed {
		t.Fatalf("expected node/npm versions to pass, got %+v", got)
	}
	missingNPM := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 127, Stdout: "v22.14.0\n"}
	}}
	if got := checkNodeNPMVersions(missingNPM); got.Status != Failed {
		t.Fatalf("expected missing npm to fail, got %+v", got)
	}
}

func TestHealthEndpointPassesOn200(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v curl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "200"}
	}}
	res := checkHealthEndpoint("example.com", "/health")(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestHealthEndpointFailsOn500(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v curl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 22, Stdout: "500"}
	}}
	res := checkHealthEndpoint("example.com", "/health")(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestUnsafeDomainNeverReachesAdapter(t *testing.T) {
	calls := 0
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		calls++
		return execx.Result{ExitCode: 0}
	}}
	res := checkTLSCertificate("x; id >/tmp/pwned")(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
	if calls != 0 {
		t.Fatalf("adapter was invoked %d times", calls)
	}
	health := checkHealthEndpoint("example.com", "/; id")(adapter)
	if health.Status != Skipped {
		t.Fatalf("expected skipped health path, got %+v", health)
	}
	quoted := checkHealthEndpoint("example.com", "/health")(scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v curl") {
			return execx.Result{ExitCode: 0}
		}
		if !strings.Contains(cmd, "'https://example.com/health'") {
			t.Fatalf("expected quoted url, got %s", cmd)
		}
		return execx.Result{ExitCode: 0, Stdout: "200"}
	}})
	if quoted.Status != Passed {
		t.Fatalf("expected passed quoted probe, got %+v", quoted)
	}
}

func TestDNSPointsToServerAcceptsAnIPv6OnlyName(t *testing.T) {
	for name, tc := range map[string]struct {
		addresses string
		want      Status
	}{
		"address on this host":    {"2: eth0    inet6 2001:db8::10/64 scope global\n", Passed},
		"address on another host": {"2: eth0    inet6 2001:db8::99/64 scope global\n", Failed},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
				switch {
				case strings.Contains(cmd, "command -v dig"):
					return execx.Result{ExitCode: 0}
				case strings.Contains(cmd, "dig +short AAAA"):
					return execx.Result{ExitCode: 0, Stdout: "2001:db8::10\n"}
				case strings.Contains(cmd, "dig +short A"):
					return execx.Result{ExitCode: 0}
				case strings.Contains(cmd, "ip -o -6 addr"):
					return execx.Result{ExitCode: 0, Stdout: tc.addresses}
				default:
					return execx.Result{ExitCode: 0}
				}
			}}
			if res := checkDNSPointsToServer("app.example.com")(adapter); res.Status != tc.want {
				t.Fatalf("expected %v, got %+v", tc.want, res)
			}
		})
	}
}
