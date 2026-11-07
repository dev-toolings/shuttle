package readiness

import (
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func TestLoadComposeReturnsBodyWhenFound(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "__compose__=docker-compose.prod.yml\nservices:\n  web:\n    image: app:1.2.3\n"}
	}}
	snap := loadCompose(adapter)
	if !snap.Found {
		t.Fatal("expected compose found")
	}
	if snap.Path != "docker-compose.prod.yml" {
		t.Fatalf("expected path docker-compose.prod.yml, got %q", snap.Path)
	}
	if !strings.Contains(snap.Body, "image: app:1.2.3") {
		t.Fatalf("expected body to include image line, got %q", snap.Body)
	}
}

func TestLoadComposeAbsentWhenSearchFails(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 1}
	}}
	snap := loadCompose(adapter)
	if snap.Found {
		t.Fatal("expected compose not found")
	}
}

func TestComposeMissingProdFile(t *testing.T) {
	res := checkComposeMissingProdFile(composeSnapshot{})
	if res.Status != Skipped {
		t.Fatalf("expected skipped when no compose, got %+v", res)
	}
	res = checkComposeMissingProdFile(composeSnapshot{Found: true, Path: "docker-compose.yml"})
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestComposeEnvFileMissingDetectsAbsentFile(t *testing.T) {
	body := "services:\n  api:\n    env_file: .env.production\n"
	snap := composeSnapshot{Found: true, Path: "docker-compose.yml", Body: body}
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		// 'test -f' returns non-zero -> file missing
		return execx.Result{ExitCode: 1}
	}}
	res := checkComposeEnvFileMissing(adapter, snap)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
	if !strings.Contains(res.Summary, ".env.production") {
		t.Fatalf("expected summary to mention .env.production, got %q", res.Summary)
	}
}

func TestComposeEnvFilePassesWhenAllResolve(t *testing.T) {
	body := "services:\n  api:\n    env_file: .env.production\n"
	snap := composeSnapshot{Found: true, Path: "docker-compose.yml", Body: body}
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0}
	}}
	res := checkComposeEnvFileMissing(adapter, snap)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestComposeLatestTagFlagsLatestAndUntagged(t *testing.T) {
	body := "services:\n  api:\n    image: api:latest\n  web:\n    image: nginx\n  worker:\n    image: ghcr.io/org/worker:1.2.3\n"
	snap := composeSnapshot{Found: true, Path: "compose.yml", Body: body}
	res := checkComposeLatestTag(snap)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
	offenders, _ := res.Evidence["offenders"].([]string)
	if len(offenders) != 2 {
		t.Fatalf("expected 2 offenders, got %v", offenders)
	}
}

func TestComposeLatestTagAcceptsRegistryWithPort(t *testing.T) {
	body := "services:\n  api:\n    image: registry.local:5000/team/api:1.2.3\n"
	snap := composeSnapshot{Found: true, Path: "compose.yml", Body: body}
	res := checkComposeLatestTag(snap)
	if res.Status != Passed {
		t.Fatalf("registry-with-port should be accepted, got %+v", res)
	}
}

func TestComposeNoResourceLimitsFlagsAbsence(t *testing.T) {
	body := "services:\n  api:\n    image: api:1\n  web:\n    image: web:1\n"
	snap := composeSnapshot{Found: true, Path: "compose.yml", Body: body}
	res := checkComposeNoResourceLimits(snap)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestComposeNoResourceLimitsPassesWithMemLimit(t *testing.T) {
	body := "services:\n  api:\n    image: api:1\n    mem_limit: 512m\n"
	snap := composeSnapshot{Found: true, Path: "compose.yml", Body: body}
	res := checkComposeNoResourceLimits(snap)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestComposeBindMountFlagsDockerSock(t *testing.T) {
	body := "services:\n  ci:\n    image: runner:1\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
	snap := composeSnapshot{Found: true, Path: "compose.yml", Body: body}
	res := checkComposeBindMountSensitivePaths(snap)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestComposeBindMountPassesOnNamedVolume(t *testing.T) {
	body := "services:\n  api:\n    image: api:1\n    volumes:\n      - apidata:/data\nvolumes:\n  apidata:\n"
	snap := composeSnapshot{Found: true, Path: "compose.yml", Body: body}
	res := checkComposeBindMountSensitivePaths(snap)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestHSTSHeaderSkippedWithoutDomain(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result { return execx.Result{ExitCode: 0} }}
	res := checkHSTSHeader("")(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestHSTSHeaderPassesWhenHeaderPresent(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v curl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "Strict-Transport-Security: max-age=31536000\n"}
	}}
	res := checkHSTSHeader("example.com")(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestHSTSHeaderFailsWhenAbsent(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v curl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkHSTSHeader("example.com")(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestDNSPointsToServerSkippedWithoutDomain(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{} }}
	res := checkDNSPointsToServer("")(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestDNSPointsToServerFailsOnMismatch(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.Contains(cmd, "command -v dig"):
			return execx.Result{ExitCode: 0}
		case strings.Contains(cmd, "dig +short"):
			return execx.Result{ExitCode: 0, Stdout: "1.2.3.4\n"}
		case strings.Contains(cmd, "ipify") || strings.Contains(cmd, "ifconfig.me"):
			return execx.Result{ExitCode: 0, Stdout: "5.6.7.8\n"}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkDNSPointsToServer("example.com")(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestDNSPointsToServerPassesOnMatch(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.Contains(cmd, "command -v dig"):
			return execx.Result{ExitCode: 0}
		case strings.Contains(cmd, "dig +short"):
			return execx.Result{ExitCode: 0, Stdout: "1.2.3.4\n"}
		case strings.Contains(cmd, "ipify") || strings.Contains(cmd, "ifconfig.me"):
			return execx.Result{ExitCode: 0, Stdout: "1.2.3.4\n"}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkDNSPointsToServer("example.com")(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestDatabaseBackupFailsWithoutNativeTimer(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 1}
	}}
	res := checkDatabaseBackup(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestDatabaseBackupPassesOnArtifact(t *testing.T) {
	calls := 0
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		calls++
		switch {
		case strings.Contains(cmd, "shuttle-postgres-backup.timer"):
			return execx.Result{ExitCode: 0}
		case strings.Contains(cmd, "find /var/backups/shuttle-postgres"):
			return execx.Result{ExitCode: 0, Stdout: "/var/backups/shuttle-postgres/db.sql.gz\n"}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkDatabaseBackup(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed (calls=%d), got %+v", calls, res)
	}
}

func TestDatabaseBackupFailsWithoutEvidence(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.Contains(cmd, "shuttle-postgres-backup.timer"):
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: ""}
	}}
	res := checkDatabaseBackup(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

// Suppress unused-import warning when time isn't used in the test body.
var _ = time.Second

func TestComposeEvidenceCoversEveryServiceAndYAMLSyntax(t *testing.T) {
	snap := composeSnapshot{Found: true, Path: "compose.yml", Body: "services: {bounded: {image: 'web:1', mem_limit: 512m}, unbounded: {image: 'worker:latest'}}\n"}
	if got := checkComposeNoResourceLimits(snap); got.Status != Failed {
		t.Fatalf("one service's limit hid an unbounded service: %+v", got)
	}
	if got := checkComposeLatestTag(snap); got.Status != Failed {
		t.Fatalf("flow-style latest image escaped audit: %+v", got)
	}
	snap.Body = "services:\n  web:\n    image: web:1\n    volumes:\n      - type: bind\n        source: /root\n        target: /data\n"
	if got := checkComposeBindMountSensitivePaths(snap); got.Status != Failed {
		t.Fatalf("long volume syntax escaped audit: %+v", got)
	}
	snap.Body = "services:\n  web:\n    image: web:1\n    env_file:\n      - .env.production\n"
	if got := checkComposeEnvFileMissing(unavailableAdapter{}, snap); got.Status != Failed {
		t.Fatalf("multiline env_file escaped audit: %+v", got)
	}
	malformed := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{Stdout: "__compose__=compose.yml\nservices: [broken"} }}
	if snap := loadCompose(malformed); snap.Found {
		t.Fatal("malformed YAML accepted as evidence")
	}
}
