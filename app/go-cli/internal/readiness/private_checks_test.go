package readiness

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func privateAccess() AccessConfig {
	no := false
	yes := true
	return AccessConfig{
		Mode:                "private-tailscale",
		Private:             true,
		DeployUser:          "deploy",
		AllowedSSHUsers:     []string{"deploy"},
		TailscaleInterface:  "tailscale0",
		TailscaleSSH:        &no,
		TailscaleAutoUpdate: &yes,
		DockerAccess:        &no,
	}
}

func TestInternalPublicChecksAreNotApplicableAndStrictValidated(t *testing.T) {
	report := Report{Checks: []CheckResult{{ID: "host.example", Status: Passed, Severity: Low}}}
	MarkPublicChecksNotApplicable(&report)
	if !report.Validated || report.Coverage.NotApplicable != 4 {
		t.Fatalf("internal readiness should pass strict validation: %+v", report)
	}
	for _, check := range report.Checks[1:] {
		if check.Status != Skipped || check.SkipReason != NotApplicable {
			t.Errorf("public check was not explicitly inapplicable: %+v", check)
		}
	}
}

func TestUnattendedSecurityPolicyUsesMergedOrigins(t *testing.T) {
	for name, dump := range map[string]string{
		"ubuntu security-only": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESMApps:${distro_codename}-apps-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESM:${distro_codename}-infra-security";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"debian security-only": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
Unattended-Upgrade::Automatic-Reboot "false";`,
	} {
		t.Run(name, func(t *testing.T) {
			adapter := scriptedAdapter{respond: func(command string) execx.Result {
				if strings.Contains(command, "command -v apt-config") {
					return execx.Result{ExitCode: 0}
				}
				return execx.Result{ExitCode: 0, Stdout: dump}
			}}
			if got := checkUnattendedSecurityPolicy(adapter); got.Status != Passed {
				t.Fatalf("security-only merged policy failed: %+v", got)
			}
		})
	}
}

func TestUnattendedSecurityPolicyRejectsBroaderOrIncompletePolicy(t *testing.T) {
	for name, dump := range map[string]string{
		"plain codename remains": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"unrelated security field": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename},comment=security";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"wildcard allowed origin": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Allowed-Origins:: "*:*-security";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"wildcard origin pattern": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=*,codename=*-security";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"third-party security suite": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Allowed-Origins:: "Docker:noble-security";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"named broad allowed origin": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins::broad "Ubuntu:noble";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"named broad origin pattern": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
Unattended-Upgrade::Origins-Pattern::extra "origin=Debian,codename=${distro_codename}";
Unattended-Upgrade::Automatic-Reboot "false";`,
		"reboot enabled": `APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
Unattended-Upgrade::Automatic-Reboot "true";`,
	} {
		t.Run(name, func(t *testing.T) {
			adapter := scriptedAdapter{respond: func(command string) execx.Result {
				if strings.Contains(command, "command -v apt-config") {
					return execx.Result{ExitCode: 0}
				}
				return execx.Result{ExitCode: 0, Stdout: dump}
			}}
			if got := checkUnattendedSecurityPolicy(adapter); got.Status != Failed {
				t.Fatalf("unsafe merged policy passed: %+v", got)
			}
		})
	}
}

func TestEffectiveSSHPolicyUsesSSHDAndIncludesAllExpectedSettings(t *testing.T) {
	var calls []string
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		calls = append(calls, cmd)
		return execx.Result{ExitCode: 0, Stdout: "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\nallowusers deploy\n"}
	}}
	if got := checkSSHRootLogin(adapter); got.Status != Passed {
		t.Fatalf("root login check = %+v", got)
	}
	if got := checkSSHPasswordAuth(adapter); got.Status != Passed {
		t.Fatalf("password auth check = %+v", got)
	}
	if got := checkSSHKeyboardInteractive(adapter); got.Status != Passed {
		t.Fatalf("keyboard interactive check = %+v", got)
	}
	if got := checkSSHAllowedUsers(adapter, privateAccess()); got.Status != Passed {
		t.Fatalf("AllowUsers check = %+v", got)
	}
	for _, cmd := range calls {
		if !strings.Contains(cmd, "sshd -T") {
			t.Fatalf("effective SSH check did not use sshd -T: %q", cmd)
		}
	}
}

// sshd -T prints one line per value of a repeatable directive, so an
// "AllowUsers deploy ops" drop-in comes back as two allowusers lines. Reading
// only the last one made every host with an --operator-user fail its own
// allow-list audit while its configuration was exactly what setup had signed.
func TestAllowedUsersReadsEveryAllowUsersLine(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "permitrootlogin no\nallowusers deploy\nallowusers ops\n"}
	}}
	access := privateAccess()
	access.AllowedSSHUsers = []string{"deploy", "ops"}
	got := checkSSHAllowedUsers(adapter, access)
	if got.Status != Passed {
		t.Fatalf("AllowUsers check = %+v", got)
	}
	if actual, ok := got.Evidence["actual"].([]string); !ok || len(actual) != 2 {
		t.Fatalf("both accounts must be read back: %#v", got.Evidence["actual"])
	}
}

func TestPrivateFirewallCheckUsesConfiguredSSHPort(t *testing.T) {
	access := privateAccess()
	access.SSHPort = 2222
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "2222/tcp on tailscale0 ALLOW IN Anywhere\n"}
	}}
	got := checkSSHPrivateInterface(adapter, access)
	if got.Status != Passed || got.Evidence["sshPort"] != 2222 {
		t.Fatalf("configured SSH port check = %+v", got)
	}
}

func TestEffectiveSSHPolicySkipsWhenPrivilegeIsUnavailable(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 1, Stderr: "permission denied"}
	}}
	if got := checkSSHRootLogin(adapter); got.Status != Skipped {
		t.Fatalf("expected skipped when sshd -T cannot run, got %+v", got)
	}
}

func TestPrivateUFWRejectsIPv4AndIPv6PublicSSHAndTCP(t *testing.T) {
	ufw := `Status: active

To                         Action      From
--                         ------      ----
	  22/tcp on tailscale0       ALLOW       Anywhere
	  22/tcp (v6)                ALLOW       Anywhere (v6)
  8080/tcp                   ALLOW IN    Anywhere`
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "ufw status") {
			return execx.Result{ExitCode: 0, Stdout: ufw}
		}
		return execx.Result{ExitCode: 0}
	}}
	access := privateAccess()
	if got := checkSSHPrivateInterface(adapter, access); got.Status != Failed {
		t.Fatalf("expected public IPv6 SSH rule to fail, got %+v", got)
	}
	got := checkUnexpectedPublicTCP(adapter, access)
	if got.Status != Failed {
		t.Fatalf("expected public TCP rules to fail, got %+v", got)
	}
	rules, _ := got.Evidence["unexpectedRules"].([]string)
	if len(rules) != 2 {
		t.Fatalf("expected IPv6 SSH plus port 8080 evidence, got %#v", rules)
	}
}

func TestPublicUFWAllowsDeclaredSSHAndEdgePorts(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: "22/tcp ALLOW IN Anywhere\n80/tcp ALLOW IN Anywhere\n443/tcp ALLOW IN Anywhere\n443/udp ALLOW IN Anywhere\n443/udp (v6) ALLOW IN Anywhere (v6)\n"}
	}}
	access := AccessConfig{Mode: "public", SSHPort: 22, DeployUser: "deploy", AllowedPublicTCPPorts: []string{"22", "80", "443"}}
	if got := checkUnexpectedPublicTCP(adapter, access); got.Status != Passed {
		t.Fatalf("declared public ports should pass: %+v", got)
	}
}

func TestPublicSSHPrivateInterfaceCheckPassesAsNotApplicable(t *testing.T) {
	got := checkSSHPrivateInterface(scriptedAdapter{}, AccessConfig{Mode: "public"})
	if got.Status != Skipped || got.SkipReason != NotApplicable {
		t.Fatalf("public access should make the private-interface policy non-blocking: %+v", got)
	}
}

func TestPrivateUFWRejectsUnknownPublicApplicationProfile(t *testing.T) {
	got := publicUFWTCPRules("OpenSSH                    ALLOW       Anywhere\n", map[string]bool{}, "tailscale0")
	if len(got) != 1 || !strings.Contains(got[0], "OpenSSH") {
		t.Fatalf("expected public application profile evidence, got %#v", got)
	}
}

func TestPrivateUFWRejectsPublicEthernetButAllowsTailscaleInterface(t *testing.T) {
	status := "8080/tcp on eth0          ALLOW       Anywhere\n22/tcp on tailscale0     ALLOW       Anywhere\n"
	got := publicUFWTCPRules(status, map[string]bool{}, "tailscale0")
	if len(got) != 1 || !strings.Contains(got[0], "eth0") {
		t.Fatalf("expected only public ethernet rule, got %#v", got)
	}
}

func TestPrivateUFWRejectsPublicForwardRules(t *testing.T) {
	status := "8080/tcp                   ALLOW FWD   Anywhere\n8080/tcp (v6)              ALLOW FWD   Anywhere (v6)\n"
	got := publicUFWTCPRules(status, map[string]bool{"8080": true}, "tailscale0")
	if len(got) != 2 {
		t.Fatalf("expected forwarded rules to fail without an explicit forwarding model, got %#v", got)
	}
}

func TestPrivateUFWRejectsPublicLimitRules(t *testing.T) {
	got := publicUFWTCPRules("22/tcp                     LIMIT       Anywhere\n", map[string]bool{}, "tailscale0")
	if len(got) != 1 {
		t.Fatalf("expected public LIMIT rule, got %#v", got)
	}
}

func TestPrivateUFWRejectsSourceRestrictedNonTailnetSSH(t *testing.T) {
	status := "22/tcp on tailscale0 ALLOW IN Anywhere\n22/tcp ALLOW IN 192.168.1.0/24\n"
	private, violations := sshPrivateUFWRules(status, "tailscale0", 22)
	if !private || len(violations) != 1 || !strings.Contains(violations[0], "192.168.1.0/24") {
		t.Fatalf("expected source-restricted non-tailnet SSH violation, private=%t violations=%#v", private, violations)
	}
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "ufw status") {
			return execx.Result{ExitCode: 0, Stdout: status}
		}
		return execx.Result{ExitCode: 0}
	}}
	if got := checkSSHPrivateInterface(adapter, privateAccess()); got.Status != Failed {
		t.Fatalf("expected private SSH check to fail on source-restricted rule, got %+v", got)
	}
}

func TestPrivateUFWRequiresExactTailscaleInterface(t *testing.T) {
	for _, spoofed := range []string{"22/tcp on tailscale0-public ALLOW IN Anywhere\n", "22/tcp on tailscale0.100 ALLOW IN Anywhere\n"} {
		private, violations := sshPrivateUFWRules(spoofed, "tailscale0", 22)
		if private || len(violations) != 1 {
			t.Fatalf("spoofed interface accepted: private=%t violations=%#v for %q", private, violations, spoofed)
		}
	}
	if !exactUFWInterface("22/tcp on tailscale0 ALLOW IN Anywhere", "tailscale0") {
		t.Fatal("exact tailscale interface was not recognized")
	}
	spoofed := publicUFWTCPRules("8443/tcp on tailscale0-public ALLOW IN Anywhere\n", map[string]bool{}, "tailscale0")
	if len(spoofed) != 1 {
		t.Fatalf("spoofed non-SSH interface was accepted as private: %#v", spoofed)
	}
}

func TestDockerPublicTCPDetectsFirewallBypass(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "docker ps") {
			return execx.Result{ExitCode: 0, Stdout: "classic\tweb\t0.0.0.0:8080->8080/tcp, :::443->443/tcp\n"}
		}
		return execx.Result{ExitCode: 0}
	}}
	access := privateAccess()
	access.AllowedPublicTCPPorts = []string{"443"}
	got := checkDockerPublicTCP(adapter, access)
	if got.Status != Failed {
		t.Fatalf("expected Docker bypass to fail, got %+v", got)
	}
	exposures, _ := got.Evidence["exposures"].([]map[string]string)
	if len(exposures) != 1 || exposures[0]["port"] != "8080" {
		t.Fatalf("unexpected Docker exposure evidence %#v", exposures)
	}
}

func TestDockerPublicTCPDetectsSwarmRoutingMesh(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "docker service inspect") {
			return execx.Result{ExitCode: 0, Stdout: "swarm\tpublic-api\t[{\"Protocol\":\"tcp\",\"TargetPort\":8080,\"PublishedPort\":8443,\"PublishMode\":\"ingress\"}]\n"}
		}
		return execx.Result{ExitCode: 0}
	}}
	got := checkDockerPublicTCP(adapter, privateAccess())
	if got.Status != Failed {
		t.Fatalf("expected Swarm routing-mesh exposure to fail, got %+v", got)
	}
	exposures, _ := got.Evidence["exposures"].([]map[string]string)
	if len(exposures) != 1 || exposures[0]["runtime"] != "swarm" || exposures[0]["port"] != "8443" {
		t.Fatalf("unexpected Swarm evidence %#v", exposures)
	}
}

func TestDockerPublicTCPFailsClosedOnMalformedSwarmMetadata(t *testing.T) {
	got := dockerPublicTCPExposures("swarm\tapi\tnot-json\n", map[string]bool{})
	if len(got) != 1 || got[0]["parseError"] == "" {
		t.Fatalf("malformed Swarm metadata did not fail closed: %#v", got)
	}
}

func TestDockerPublicTCPClassifiesExplicitBindAddresses(t *testing.T) {
	output := "classic\tweb\t127.0.0.1:3000->3000/tcp, 192.168.1.26:8081->8080/tcp, 100.77.138.37:9000->9000/tcp, [fd7a:115c:a1e0::1]:9100->9100/tcp, 203.0.113.10:8443->443/tcp, mystery:9443->443/tcp\n"
	got := dockerPublicTCPExposures(output, map[string]bool{})
	if len(got) != 2 || got[0]["port"] != "8443" || got[1]["port"] != "9443" {
		t.Fatalf("explicit Docker bind classification = %#v", got)
	}
}

func TestAPTCacheFailsWhenStale(t *testing.T) {
	stamp := time.Now().Add(-8 * 24 * time.Hour).Unix()
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v apt") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: strconv.FormatInt(stamp, 10)}
	}}
	if got := checkAPTCacheFresh(adapter); got.Status != Failed {
		t.Fatalf("expected stale cache to fail, got %+v", got)
	}
}

func TestPendingUpdatesSplitSecurityFromOther(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "command -v apt") {
			return execx.Result{ExitCode: 0}
		}
		return execx.Result{ExitCode: 0, Stdout: "openssl/noble-security 3.0 [upgradable]\ncurl/noble-updates 8.0 [upgradable]\n"}
	}}
	if got := checkSecurityUpdatesPending(adapter); got.Status != Failed || got.Evidence["pendingCount"] != 1 {
		t.Fatalf("unexpected security update result %+v", got)
	}
	if got := checkOtherUpdatesPending(adapter); got.Status != Failed || got.Evidence["pendingCount"] != 1 {
		t.Fatalf("unexpected other update result %+v", got)
	}
}

func TestNoPasswordlessSudoSkipsWhenPrivilegeCannotBeProved(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "sudo -n -l") {
			return execx.Result{ExitCode: 1, Stderr: "permission denied"}
		}
		return execx.Result{ExitCode: 0}
	}}
	if got := checkExpectedUserNoPasswordlessSudo(adapter, privateAccess()); got.Status != Skipped {
		t.Fatalf("expected skipped without sudo privilege, got %+v", got)
	}
}

func TestDeployUserSSHFileMetadataParsesEachPathIndependently(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if !strings.Contains(cmd, "stat -c %a") || !strings.Contains(cmd, "stat -c %s") {
			t.Fatalf("metadata command must inspect modes and key size independently: %s", cmd)
		}
		return execx.Result{ExitCode: 0, Stdout: "home=700\nssh=700\nauthorized=600\nkeys=102\n"}
	}}
	if got := checkExpectedUserSSHFiles(adapter, privateAccess()); got.Status != Passed {
		t.Fatalf("expected protected deploy SSH metadata to pass, got %+v", got)
	}
}

func TestDeployUserDockerAccessIsAlwaysReportedRootEquivalent(t *testing.T) {
	adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "id -nG") {
			return execx.Result{ExitCode: 0, Stdout: "deploy docker\n"}
		}
		return execx.Result{ExitCode: 0}
	}}
	if got := checkExpectedUserDockerGroup(adapter, privateAccess()); got.Status != Failed {
		t.Fatalf("expected Docker-capable deploy user to fail, got %+v", got)
	}
	access := privateAccess()
	yes := true
	access.DockerAccess = &yes
	if got := checkExpectedUserDockerGroup(adapter, access); got.Status != Failed {
		t.Fatalf("expected requested Docker membership to fail even when declared, got %+v", got)
	}
	adapter = scriptedAdapter{respond: func(cmd string) execx.Result {
		if strings.Contains(cmd, "id -nG") {
			return execx.Result{ExitCode: 0, Stdout: "deploy\n"}
		}
		return execx.Result{ExitCode: 0}
	}}
	access = privateAccess()
	if got := checkExpectedUserDockerGroup(adapter, access); got.Status != Passed {
		t.Fatalf("expected unprivileged deploy user to pass, got %+v", got)
	}
}

func TestAdministrativeBinariesUseSbinFallbacks(t *testing.T) {
	if !strings.Contains(privateSSHDCommand, "/usr/sbin") {
		t.Fatalf("sshd probe has no /usr/sbin fallback: %s", privateSSHDCommand)
	}
	if !strings.Contains(privateUFWStatusCommand, "/usr/sbin") {
		t.Fatalf("ufw probe has no /usr/sbin fallback: %s", privateUFWStatusCommand)
	}
}

const dockerUserPolicyPresentFixture = `__shuttle_family=ipv4
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j ufw-before-forward
-A DOCKER-USER -j ufw-skip-to-policy-forward
-A DOCKER-USER -j RETURN
__shuttle_family=ipv6
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j ufw6-before-forward
-A DOCKER-USER -j ufw6-skip-to-policy-forward
-A DOCKER-USER -j RETURN
`

func TestDockerUserPolicyPassesWhenUFWRunsBeforeReturn(t *testing.T) {
	adapter := scriptedAdapter{respond: func(command string) execx.Result {
		if command != dockerUserPolicyCommand {
			t.Fatalf("unexpected probe command: %s", command)
		}
		return execx.Result{ExitCode: 0, Stdout: dockerUserPolicyPresentFixture}
	}}

	got := checkDockerUserPolicy(adapter)
	if got.Status != Passed {
		t.Fatalf("expected present DOCKER-USER policy to pass, got %+v", got)
	}
	if got.Evidence["privilege"] != "sudo-n" {
		t.Fatalf("expected sudo privilege evidence, got %#v", got.Evidence["privilege"])
	}
	if got.Evidence["ufwForwardBeforeReturn"] != true {
		t.Fatalf("expected UFW ordering evidence, got %#v", got.Evidence["ufwForwardBeforeReturn"])
	}
}

func TestDockerUserPolicyFailsWhenChainIsAbsent(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{
			ExitCode: 1,
			Stdout:   "__shuttle_family=ipv4\n__shuttle_privilege=sudo-n\n__shuttle_family=ipv6\n__shuttle_privilege=sudo-n\n",
			Stderr:   "iptables v1.8.10 (nf_tables): chain 'DOCKER-USER' does not exist",
		}
	}}

	got := checkDockerUserPolicy(adapter)
	if got.Status != Failed {
		t.Fatalf("expected absent DOCKER-USER chain to fail, got %+v", got)
	}
	if got.Evidence["chainPresent"] != false {
		t.Fatalf("expected chain absence evidence, got %#v", got.Evidence["chainPresent"])
	}
	if !strings.Contains(got.Summary, "absent") {
		t.Fatalf("expected an absent-chain summary, got %q", got.Summary)
	}
}

func TestDockerUserPolicySkipsWhenChainIsUninspectable(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{
			ExitCode: 1,
			Stdout:   "__shuttle_family=ipv4\n__shuttle_privilege=direct\n__shuttle_family=ipv6\n__shuttle_privilege=direct\n",
			Stderr:   "iptables: Permission denied (you must be root)",
		}
	}}

	got := checkDockerUserPolicy(adapter)
	if got.Status != Skipped {
		t.Fatalf("expected privilege-blocked inspection to skip, got %+v", got)
	}
	if got.Evidence["privilege"] != "direct" {
		t.Fatalf("expected direct privilege evidence, got %#v", got.Evidence["privilege"])
	}
	if !strings.Contains(strings.ToLower(got.Summary), "privilege") {
		t.Fatalf("expected privilege explanation, got %q", got.Summary)
	}
}

func TestDockerUserPolicyFailsWhenUFWComesAfterReturn(t *testing.T) {
	output := `__shuttle_family=ipv4
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j RETURN
-A DOCKER-USER -j ufw-before-forward
-A DOCKER-USER -j ufw-skip-to-policy-forward
__shuttle_family=ipv6
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j RETURN
-A DOCKER-USER -j ufw6-before-forward
-A DOCKER-USER -j ufw6-skip-to-policy-forward
`
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: output}
	}}

	got := checkDockerUserPolicy(adapter)
	if got.Status != Failed {
		t.Fatalf("expected late UFW hook to fail, got %+v", got)
	}
	if got.Evidence["ufwForwardBeforeReturn"] != false {
		t.Fatalf("expected ordering failure evidence, got %#v", got.Evidence["ufwForwardBeforeReturn"])
	}
}

func TestDockerUserPolicyFailsWhenIPv6BypassesUFW(t *testing.T) {
	output := `__shuttle_family=ipv4
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j ufw-before-forward
-A DOCKER-USER -j RETURN
__shuttle_family=ipv6
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j RETURN
`
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: output}
	}}
	got := checkDockerUserPolicy(adapter)
	if got.Status != Failed || got.Evidence["ufwForwardBeforeReturn"] != false {
		t.Fatalf("expected IPv6 policy bypass to fail, got %+v", got)
	}
}

func TestDockerUserPolicyFailsWhenTerminalAcceptPrecedesUFWInBothFamilies(t *testing.T) {
	output := `__shuttle_family=ipv4
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j ACCEPT
-A DOCKER-USER -j ufw-before-forward
-A DOCKER-USER -j ufw-skip-to-policy-forward
__shuttle_family=ipv6
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -j REJECT
-A DOCKER-USER -j ufw6-before-forward
-A DOCKER-USER -j ufw6-skip-to-policy-forward
`
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: output} }}
	got := checkDockerUserPolicy(adapter)
	if got.Status != Failed {
		t.Fatalf("expected terminal verdicts before UFW to fail, got %+v", got)
	}
	families, ok := got.Evidence["families"].(map[string]any)
	if !ok {
		t.Fatalf("missing family evidence: %#v", got.Evidence)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		entry, ok := families[family].(map[string]any)
		if !ok || entry["ufwForwardBeforeReturn"] != false {
			t.Fatalf("expected unsafe %s ordering evidence, got %#v", family, entry)
		}
	}
}

func TestDockerUserPolicyFailsWhenGotoAcceptPrecedesUFW(t *testing.T) {
	output := `__shuttle_family=ipv4
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -g ACCEPT
-A DOCKER-USER -j ufw-before-forward
-A DOCKER-USER -j ufw-skip-to-policy-forward
__shuttle_family=ipv6
__shuttle_privilege=sudo-n
-N DOCKER-USER
-A DOCKER-USER -g ACCEPT
-A DOCKER-USER -j ufw6-before-forward
-A DOCKER-USER -j ufw6-skip-to-policy-forward
`
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: output} }}
	if got := checkDockerUserPolicy(adapter); got.Status != Failed {
		t.Fatalf("expected goto ACCEPT before UFW to fail, got %+v", got)
	}
}

func TestDockerUserPolicyProbeIsReadOnly(t *testing.T) {
	for _, forbidden := range []string{"iptables -A", "iptables -D", "iptables -F", "ufw allow", "ufw delete"} {
		if strings.Contains(dockerUserPolicyCommand, forbidden) {
			t.Fatalf("probe unexpectedly contains mutating command %q: %s", forbidden, dockerUserPolicyCommand)
		}
	}
	if output, err := exec.Command("sh", "-n", "-c", dockerUserPolicyCommand).CombinedOutput(); err != nil {
		t.Fatalf("DOCKER-USER probe shell syntax: %v: %s", err, output)
	}
}

// ufwDockerFixture is the verbatim DOCKER-USER rule set of a production VPS
// hardened with the ufw-docker convention, IPv6 disabled on every Docker
// network. Applying the shuttle block on top of it was measured to drop all
// container egress, so this posture has to be accepted on its own terms.
const ufwDockerFixture = `__shuttle_docker_ipv6=0
__shuttle_family=ipv4
__shuttle_privilege=direct
-N DOCKER-USER
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -s 10.0.0.0/8 -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 192.168.0.0/16 -j RETURN
-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN
-A DOCKER-USER -d 192.168.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
-A DOCKER-USER -d 10.0.0.0/8 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
-A DOCKER-USER -d 172.16.0.0/12 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
-A DOCKER-USER -d 192.168.0.0/16 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny
-A DOCKER-USER -d 10.0.0.0/8 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny
-A DOCKER-USER -d 172.16.0.0/12 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny
-A DOCKER-USER -j RETURN
__shuttle_family=ipv6
__shuttle_privilege=direct
-N DOCKER-USER
`

func TestDockerUserPolicyAcceptsUFWDockerConvention(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result {
		return execx.Result{ExitCode: 0, Stdout: ufwDockerFixture}
	}}
	got := checkDockerUserPolicy(adapter)
	if got.Status != Passed {
		t.Fatalf("expected the ufw-docker convention to pass, got %+v", got)
	}
	families, _ := got.Evidence["families"].(map[string]any)
	ipv4, _ := families["ipv4"].(map[string]any)
	if ipv4["convention"] != "ufw-docker" {
		t.Fatalf("expected the ufw-docker convention in evidence, got %#v", ipv4["convention"])
	}
	ipv6, _ := families["ipv6"].(map[string]any)
	if ipv6["convention"] != "ipv6-inactive" {
		t.Fatalf("expected an inactive IPv6 family, got %#v", ipv6["convention"])
	}
}

func TestDockerUserPolicyRejectsUFWDockerWithoutDenyRules(t *testing.T) {
	output := `__shuttle_docker_ipv6=0
__shuttle_family=ipv4
__shuttle_privilege=direct
-N DOCKER-USER
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j RETURN
__shuttle_family=ipv6
__shuttle_privilege=direct
-N DOCKER-USER
`
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: output} }}
	if got := checkDockerUserPolicy(adapter); got.Status != Failed {
		t.Fatalf("expected a user-forward jump without deny rules to fail, got %+v", got)
	}
}

func TestDockerUserPolicyRejectsUFWDockerWithPartialPrivateCoverage(t *testing.T) {
	output := `__shuttle_docker_ipv6=0
__shuttle_family=ipv4
__shuttle_privilege=direct
-N DOCKER-USER
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -d 172.16.0.0/12 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
-A DOCKER-USER -j RETURN
__shuttle_family=ipv6
__shuttle_privilege=direct
-N DOCKER-USER
`
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: output} }}
	if got := checkDockerUserPolicy(adapter); got.Status != Failed {
		t.Fatalf("expected partial private-space coverage to fail, got %+v", got)
	}
}

func TestDockerUserPolicyRejectsDenyRulesAfterTerminalReturn(t *testing.T) {
	output := `__shuttle_docker_ipv6=0
__shuttle_family=ipv4
__shuttle_privilege=direct
-N DOCKER-USER
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j RETURN
-A DOCKER-USER -d 192.168.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
-A DOCKER-USER -d 10.0.0.0/8 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
-A DOCKER-USER -d 172.16.0.0/12 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
__shuttle_family=ipv6
__shuttle_privilege=direct
-N DOCKER-USER
`
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: output} }}
	if got := checkDockerUserPolicy(adapter); got.Status != Failed {
		t.Fatalf("expected deny rules after a terminal RETURN to fail, got %+v", got)
	}
}

func TestDockerUserPolicyRejectsEmptyIPv6ChainWhenDockerHasIPv6(t *testing.T) {
	output := strings.Replace(ufwDockerFixture, "__shuttle_docker_ipv6=0", "__shuttle_docker_ipv6=1", 1)
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 0, Stdout: output} }}
	if got := checkDockerUserPolicy(adapter); got.Status != Failed {
		t.Fatalf("expected an unguarded IPv6 chain to fail when Docker carries IPv6, got %+v", got)
	}
}

func TestDockerUserRuleIsUnconditional(t *testing.T) {
	if !dockerUserRuleIsUnconditional("-A DOCKER-USER -j RETURN") {
		t.Fatal("a bare RETURN must be unconditional")
	}
	for _, rule := range []string{
		"-A DOCKER-USER -s 10.0.0.0/8 -j RETURN",
		"-A DOCKER-USER -i eth0 -j RETURN",
		"-A DOCKER-USER -p udp -m udp --sport 53 -j RETURN",
	} {
		if dockerUserRuleIsUnconditional(rule) {
			t.Fatalf("rule %q carries match criteria and must not be unconditional", rule)
		}
	}
}

// A container that publishes no port prints an empty last field, and the line
// is trimmed before parsing, so only two fields arrive. That is the safest
// workload on the host and it must not be reported at all.
func TestDockerPublicTCPExposuresAcceptsAContainerWithoutPorts(t *testing.T) {
	output := "classic\tmercure-hub_mercure.1.abc\nclassic\tedge.1.def\t0.0.0.0:80->80/tcp"
	exposures := dockerPublicTCPExposures(output, map[string]bool{"80": true})
	if len(exposures) != 0 {
		t.Fatalf("a portless container was reported: %v", exposures)
	}
}
