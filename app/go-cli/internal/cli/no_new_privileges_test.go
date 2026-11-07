package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshDockerEnablesNoNewPrivilegesBeforeInstall(t *testing.T) {
	program := setupDockerCommand(setupModeFresh)
	option := strings.Index(program, `"no-new-privileges":true`)
	install := strings.Index(program, "apt-get install -y docker-ce")
	existing := strings.Index(program, "if ! command -v docker")
	if option < existing || option > install {
		t.Fatal("new Docker installations must configure no-new-privileges before the package starts dockerd")
	}
	if strings.Contains(program, "systemctl restart docker") {
		t.Fatal("setup must not restart an existing daemon")
	}
}

func TestRootStackDoesNotClaimIgnoredSecurityOptIsProtection(t *testing.T) {
	body := strings.Replace(validRootStack(), "    security_opt: [no-new-privileges:true]\n", "", 1)
	if err := validateRootStack([]byte(body)); err != nil {
		t.Fatalf("Swarm ignores security_opt; YAML presence cannot prove protection: %v", err)
	}
}

// Execute only the generated configuration fragment, with its host path
// redirected to a temporary directory, never the installer or a Docker daemon.
func TestDockerInitialConfigurationPreservesOperatorFile(t *testing.T) {
	program := setupDockerCommand(setupModeFresh)
	start := strings.Index(program, "  if [ ! -e /etc/docker/daemon.json ]; then")
	end := strings.Index(program, "  apt-get install -y docker-ce")
	if start < 0 || end < start {
		t.Fatal("initial configuration fragment missing")
	}
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "docker")
			want := "{\"no-new-privileges\":true}\n"
			if existing {
				want = "{\"log-driver\":\"local\",\"no-new-privileges\":false}\n"
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "daemon.json"), []byte(want), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fragment := strings.ReplaceAll(program[start:end], "/etc/docker", dir)
			if out, err := exec.Command("sh", "-ec", fragment).CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			got, err := os.ReadFile(filepath.Join(dir, "daemon.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}
