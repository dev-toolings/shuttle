package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func dockerUserScript(t *testing.T) string {
	t.Helper()
	return setupRuntimeCommand(22, []int{80, 443}, setupModeFresh)
}

// DOCKER-USER governs what may enter from outside, but it is traversed by every
// forwarded packet. With br_netfilter, two containers on the same bridge cross
// FORWARD as well — before Docker's own per-bridge ACCEPT rules — so a deny list
// written for ingress cut an application off from its own database while every
// container healthcheck, probing 127.0.0.1 inside its namespace, still reported
// healthy.
func TestDockerUserPolicyOnlyFiltersIngress(t *testing.T) {
	script := dockerUserScript(t)
	exempt := strings.Index(script, `-A DOCKER-USER ! -i "$external" -j RETURN`)
	if exempt < 0 {
		t.Fatal("traffic that did not arrive on the external interface is not exempted; east-west traffic is being filtered by an ingress policy")
	}
	firstDeny := strings.Index(script, "-j ufw-docker-logging-deny\n")
	if firstDeny < 0 {
		t.Fatal("the deny rules are gone")
	}
	if exempt > firstDeny {
		t.Error("the exemption comes after the first deny, so east-west traffic is dropped before reaching it")
	}
}

// The external interface is derived, because eth0 is a convention and not a
// guarantee. If it cannot be determined the script must refuse rather than
// install a policy that would filter everything.
func TestDockerUserPolicyDerivesTheExternalInterface(t *testing.T) {
	script := dockerUserScript(t)
	if !strings.Contains(script, "ip -o -4 route show default") {
		t.Error("the external interface is assumed rather than derived")
	}
	if !strings.Contains(script, "refusing to install a policy that would filter east-west traffic") {
		t.Error("an undeterminable interface must refuse, not fall through to a policy that denies everything")
	}
}

func TestDockerUserPolicyBeforeNetworking(t *testing.T) {
	program := strings.SplitN(dockerUserScript(t), "<<'SHUTTLE_DOCKER_FIREWALL'\n", 2)[1]
	program = strings.SplitN(program, "\nSHUTTLE_DOCKER_FIREWALL\n", 2)[0]
	for _, dockerReady := range []bool{false, true} {
		t.Run(fmt.Sprintf("docker-ready-%t", dockerReady), func(t *testing.T) {
			dir := t.TempDir()
			iptables := filepath.Join(dir, "iptables")
			chainResult := "exit 1"
			if dockerReady {
				chainResult = "exit 0"
			}
			for name, content := range map[string]string{
				iptables:                 "#!/bin/sh\n" + chainResult + "\n",
				filepath.Join(dir, "ip"): "#!/bin/sh\nexit 0\n",
			} {
				if err := os.WriteFile(name, []byte(content), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
			cmd.Stdin = strings.NewReader(strings.Replace(program, "iptables=/usr/sbin/iptables", "iptables="+iptables, 1))
			output, err := cmd.CombinedOutput()
			if !dockerReady && err != nil {
				t.Fatalf("UFW must start before Docker and networking: %v\n%s", err, output)
			}
			if dockerReady && (err == nil || !strings.Contains(string(output), "cannot determine the external interface")) {
				t.Fatalf("a live Docker chain without a route must fail closed: %v\n%s", err, output)
			}
		})
	}
}

func TestDockerUserBootMigrationPreservesUnknownPolicies(t *testing.T) {
	current := strings.SplitN(dockerUserScript(t), "<<'SHUTTLE_DOCKER_FIREWALL'\n", 2)[1]
	current = strings.SplitN(current, "SHUTTLE_DOCKER_FIREWALL\n", 2)[0]
	migration := setupFirewallBootMigration(current)
	legacy := strings.SplitN(migration, "<<'SHUTTLE_FIREWALL_LEGACY'\n", 2)[1]
	legacy = strings.SplitN(legacy, "SHUTTLE_FIREWALL_LEGACY\n", 2)[0]
	for _, scenario := range []struct {
		name, policy string
		wantFailure  bool
	}{
		{"legacy", legacy, false},
		{"current", current, false},
		{"custom", "#!/bin/sh\n# operator policy\n", true},
		{"missing", "", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			policy := filepath.Join(dir, "shuttle-docker-user-firewall")
			if scenario.policy != "" {
				if err := os.WriteFile(policy, []byte(scenario.policy), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh")
			cmd.Stdin = strings.NewReader(strings.ReplaceAll(migration, "/usr/local/libexec", dir))
			out, err := cmd.CombinedOutput()
			if (err != nil) != scenario.wantFailure {
				t.Fatalf("migration result: %v\n%s", err, out)
			}
			got, err := os.ReadFile(policy)
			if scenario.name == "missing" {
				if !os.IsNotExist(err) {
					t.Fatalf("missing policy was created: %v", err)
				}
				return
			}
			want := current
			if scenario.wantFailure {
				want = scenario.policy
			}
			if err != nil || string(got) != want {
				t.Fatalf("unexpected policy after migration: %v\n%s", err, got)
			}
		})
	}
	program := dockerUserScript(t)
	if strings.Index(program, "touch /etc/shuttle/setup.d/40-runtime") > strings.Index(program, "if [ ! -f /etc/shuttle/setup.d/41-firewall-boot ]") {
		t.Fatal("boot migration must run after the original runtime checkpoint")
	}
}

// Invariant 5: generated shell is tested as text, and must parse.
func TestDockerUserPolicyIsValidShell(t *testing.T) {
	path := filepath.Join(t.TempDir(), "40-runtime.sh")
	if err := os.WriteFile(path, []byte(dockerUserScript(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v\n%s", err, out)
	}
}

// The managed PostgreSQL listens on the Docker gateway so containers can reach
// it. The gateway is an address of the host, so that connection is INPUT
// traffic, and the default-deny policy dropped it — leaving the database
// Shuttle provisions unreachable by the application it exists to serve, on
// every host, and silently: the service is up, the port listens, the
// connection times out.
func TestManagedDatabaseIsReachableFromContainers(t *testing.T) {
	script := dockerUserScript(t)
	if !strings.Contains(script, `ufw allow from "$subnet" to "$gateway" port 5432 proto tcp`) {
		t.Fatal("nothing opens 5432 from the Docker gateway subnet; every container would time out reaching the managed database")
	}
	// Opened from the gateway subnet only, and only on 5432.
	if strings.Contains(script, "ufw allow 5432/tcp") {
		t.Error("5432 must not be opened to the world; the gateway subnet is the one path the design assumes")
	}
	allow := strings.Index(script, `port 5432 proto tcp`)
	enable := strings.Index(script, "ufw --force enable")
	if allow < 0 || enable < 0 || allow > enable {
		t.Error("the rule must be added before the firewall is enabled, or the first deploy races the policy")
	}
	if !strings.Contains(script, "the managed database would be unreachable from every container") {
		t.Error("an undeterminable gateway must fail loudly rather than leave the database quietly unreachable")
	}
}
