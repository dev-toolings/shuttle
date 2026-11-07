package readiness

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func TestRebootRequiredFailsClosed(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: "required"} }}
	if got := checkRebootRequired(adapter); got.Status != Failed || got.Severity != High {
		t.Fatalf("expected pending reboot failure, got %+v", got)
	}
}

func TestFail2banPortMatchesEffectiveSSH(t *testing.T) {
	adapter := scriptedAdapter{respond: func(command string) execx.Result {
		if strings.Contains(command, "sshd -T") {
			return execx.Result{ExitCode: 0, Stdout: "port 2222\n"}
		}
		return execx.Result{ExitCode: 0, Stdout: "2222\n"}
	}}
	if got := checkFail2banSSHDPort(adapter, AccessConfig{SSHPort: 2222}); got.Status != Passed {
		t.Fatalf("expected aligned port, got %+v", got)
	}
}

func TestFail2banPortRejectsMismatch(t *testing.T) {
	adapter := scriptedAdapter{respond: func(command string) execx.Result {
		if strings.Contains(command, "sshd -T") {
			return execx.Result{ExitCode: 0, Stdout: "port 2222\n"}
		}
		return execx.Result{ExitCode: 0, Stdout: "22\n"}
	}}
	if got := checkFail2banSSHDPort(adapter, AccessConfig{SSHPort: 2222}); got.Status != Failed {
		t.Fatalf("expected mismatched jail failure, got %+v", got)
	}
}

func TestRecentFailedSSHLoginsNeverTurnsUnreadableLogsIntoZero(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 2} }}
	if got := checkRecentFailedSSHLogins(adapter); got.Status != Skipped {
		t.Fatalf("expected unavailable journal to skip, got %+v", got)
	}
}

func TestRecentFailedSSHLoginsEnforcesThreshold(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: "20\n"} }}
	if got := checkRecentFailedSSHLogins(adapter); got.Status != Failed {
		t.Fatalf("expected threshold failure, got %+v", got)
	}
}

func TestFailedSystemdUnitsReportsNames(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "broken.service loaded failed failed Broken\n"}
	}}
	got := checkFailedSystemdUnits(adapter)
	if got.Status != Failed || !strings.Contains(got.Summary, "1 systemd") {
		t.Fatalf("expected failed unit finding, got %+v", got)
	}
}

func TestUnexpectedSUIDSGIDRejectsUnmanagedPath(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: "/usr/local/bin/suspicious\n"} }}
	if got := checkUnexpectedSUIDSGID(adapter); got.Status != Failed {
		t.Fatalf("expected unmanaged SUID finding, got %+v", got)
	}
}

func TestLinkLocalNameResolutionRejectsEffectiveLLMNR(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "Global\n Protocols: +LLMNR -mDNS\nLink 2\n Current Scopes: DNS LLMNR/IPv4\n"}
	}}
	if got := checkResolvedLinkLocalProtocols(adapter); got.Status != Failed {
		t.Fatalf("expected active LLMNR to fail, got %+v", got)
	}
}

func TestLinkLocalNameResolutionPassesWhenDisabledEverywhere(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "Global\n Protocols: -LLMNR -mDNS\nLink 2\n Current Scopes: DNS\n Protocols: +DefaultRoute -LLMNR -mDNS\n"}
	}}
	if got := checkResolvedLinkLocalProtocols(adapter); got.Status != Passed {
		t.Fatalf("expected disabled link-local protocols to pass, got %+v", got)
	}
}

func TestLoopbackRegistryRequiresContainerHealthAndBinding(t *testing.T) {
	good := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "running healthy always 127.0.0.1:5000\n"}
	}}
	if got := checkLoopbackRegistry(good); got.Status != Passed {
		t.Fatalf("expected healthy loopback registry to pass: %+v", got)
	}
	missing := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 1} }}
	if got := checkLoopbackRegistry(missing); got.Status != Failed {
		t.Fatalf("expected missing registry to fail: %+v", got)
	}
	public := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "running healthy always 0.0.0.0:5000\n"}
	}}
	if got := checkLoopbackRegistry(public); got.Status != Failed {
		t.Fatalf("expected public registry binding to fail: %+v", got)
	}
}

// sshdDriftAdapter reproduces the state a provider "reset SSH" leaves behind:
// the signed drop-in is still on disk, but the rewritten sshd_config never
// includes it, so sshd reports the vendor defaults instead.
func sshdDriftAdapter(effective string, includesDropInDir bool) scriptedAdapter {
	return scriptedAdapter{respond: func(cmd string) execx.Result {
		switch {
		case strings.Contains(cmd, shuttleSSHDDropIn):
			return execx.Result{ExitCode: 0}
		case strings.Contains(cmd, "Include"):
			if includesDropInDir {
				return execx.Result{ExitCode: 0}
			}
			return execx.Result{ExitCode: 1}
		default:
			return execx.Result{ExitCode: 0, Stdout: effective}
		}
	}}
}

func TestSSHBaselineDropInEffectiveFailsWhenIgnored(t *testing.T) {
	res := checkSSHBaselineDropInEffective(sshdDriftAdapter("permitrootlogin yes\npasswordauthentication yes\npubkeyauthentication yes\n", false))
	if res.Status != Failed {
		t.Fatalf("an ignored baseline drop-in must fail: %+v", res)
	}
	ignored := fmt.Sprint(res.Evidence["ignoredDirectives"])
	if !strings.Contains(ignored, "permitrootlogin") || !strings.Contains(ignored, "passwordauthentication") {
		t.Fatalf("the failure must name every ignored directive, got %s", ignored)
	}
	if res.Evidence["mainConfigIncludesDropInDir"] != false {
		t.Fatalf("the evidence must report the missing include: %+v", res.Evidence)
	}
}

func TestSSHBaselineDropInEffectivePassesWhenApplied(t *testing.T) {
	res := checkSSHBaselineDropInEffective(sshdDriftAdapter("permitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\n", true))
	if res.Status != Passed {
		t.Fatalf("an applied baseline drop-in must pass: %+v", res)
	}
}

func TestSSHBaselineDropInEffectiveSkippedWithoutDropIn(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, shuttleSSHDDropIn) {
			return execx.Result{ExitCode: 1}
		}
		return execx.Result{ExitCode: 0}
	}}
	if res := checkSSHBaselineDropInEffective(adapter); res.Status != Skipped {
		t.Fatalf("a host without the baseline drop-in must be skipped, not judged: %+v", res)
	}
}

// The incident this guards against: the edge listened on 80/443 and reset every
// connection, while every configuration-level reverse-proxy check stayed green.
func TestSharedEdgeServesFailsWhenListeningButNotServing(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "docker ps") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "000"}
	}}
	res := checkSharedEdgeServes(adapter)
	if res.Status != Failed || res.Severity != High {
		t.Fatalf("a resetting edge must fail at High severity: %+v", res)
	}
}

// A bare edge with no application route answers 404. That is a serving edge.
func TestSharedEdgeServesAcceptsAnyHTTPStatus(t *testing.T) {
	for _, code := range []string{"200", "404", "502"} {
		adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
			if strings.Contains(cmd, "docker ps") {
				return execx.Result{ExitCode: 0}
			}
			return execx.Result{ExitCode: 0, Stdout: code}
		}}
		if res := checkSharedEdgeServes(adapter); res.Status != Passed {
			t.Fatalf("status %s proves the edge served a request: %+v", code, res)
		}
	}
}

func TestSharedEdgeServesSkippedWithoutEdgeContainer(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 1} }}
	if res := checkSharedEdgeServes(adapter); res.Status != Skipped {
		t.Fatalf("a host without the shared edge must be skipped: %+v", res)
	}
}

func TestDockerGatewayMTUMustFitTheDefaultRoute(t *testing.T) {
	for name, tc := range map[string]struct {
		stdout string
		want   Status
	}{
		"aligned on a 1460 link": {"ens4 1460 1460\n", Passed},
		"default bridge on 1500": {"eth0 1500 1500\n", Passed},
		"default bridge on 1450": {"eth0 1450 1500\n", Failed},
		"no swarm yet":           {"eth0 1450 absent\n", Skipped},
		"malformed":              {"eth0\n", Skipped},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: tc.stdout} }}
			if got := checkDockerGatewayMTU(adapter); got.Status != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, got)
			}
		})
	}
}
