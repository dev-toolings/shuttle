package readiness

import (
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

type scriptedAdapter struct {
	respond func(cmd string) execx.Result
}

func (s scriptedAdapter) Run(cmd string, _ time.Duration) execx.Result {
	return s.respond(cmd)
}

func TestSSHRootLoginFailsOnYes(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "PermitRootLogin yes\n"}
	}}
	res := checkSSHRootLogin(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestSSHRootLoginPassesOnProhibitPassword(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "PermitRootLogin prohibit-password\n"}
	}}
	res := checkSSHRootLogin(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestSSHRootLoginSkippedWhenConfigUnreadable(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 1} }}
	res := checkSSHRootLogin(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestSSHPasswordAuthFailsOnYes(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "PasswordAuthentication yes\n"}
	}}
	res := checkSSHPasswordAuth(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestUnattendedUpgradesPassesWhenInstalledAndEnabled(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.HasPrefix(cmd, "dpkg -s"):
			return execx.Result{ExitCode: 0}
		case strings.HasPrefix(cmd, "systemctl is-enabled"):
			return execx.Result{ExitCode: 0}
		case strings.Contains(cmd, "command -v systemctl"):
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkUnattendedUpgrades(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestUnattendedUpgradesSkippedWhenNoSystemctl(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result { return execx.Result{ExitCode: 1} }}
	res := checkUnattendedUpgrades(adapter)
	if res.Status != Skipped {
		t.Fatalf("expected skipped, got %+v", res)
	}
}

func TestFail2banPassesWhenActive(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v systemctl") {
			return execx.Result{ExitCode: 0}
		}
		if strings.HasPrefix(cmd, "systemctl is-active fail2ban") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkFail2ban(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestSwapFailsWhenEmpty(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: ""}
	}}
	res := checkSwap(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}

func TestSwapPassesWhenConfigured(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "/swapfile\n"}
	}}
	res := checkSwap(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v", res)
	}
}

func TestTimeSyncDetectsFirstActiveDaemon(t *testing.T) {
	calls := []string{}
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		calls = append(calls, cmd)
		if strings.Contains(cmd, "command -v systemctl") {
			return execx.Result{ExitCode: 0}
		}
		if strings.Contains(cmd, "is-active chrony") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkTimeSync(adapter)
	if res.Status != Passed {
		t.Fatalf("expected passed, got %+v\ncalls: %v", res, calls)
	}
	if got := res.Evidence["daemon"]; got != "chrony" {
		t.Fatalf("expected chrony daemon, got %v", got)
	}
}

func TestTimeSyncFailsWhenNoneActive(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v systemctl") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 1}
	}}
	res := checkTimeSync(adapter)
	if res.Status != Failed {
		t.Fatalf("expected failed, got %+v", res)
	}
}
