package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestContainerPoliciesSkipGuestOwnedKernelOperations(t *testing.T) {
	program := setupBaseCommandWithPolicies(setupModeFresh, "host", "host")
	for _, forbidden := range []string{"fallocate -l 2G /swapfile", "systemctl enable --now apparmor"} {
		if strings.Contains(program, forbidden) {
			t.Fatalf("host-owned LXC policy still contains %q", forbidden)
		}
	}
	for _, required := range []string{"AppArmor profile loading is owned by the host kernel", "Swap is owned by the host kernel", "systemctl enable --now fail2ban"} {
		if !strings.Contains(program, required) {
			t.Fatalf("host-owned LXC policy lost %q", required)
		}
	}
}

func TestRecreateTargetIsAnExactValidatedResource(t *testing.T) {
	value := config.InfrastructureConfig{TerraformResource: "proxmox_virtual_environment_container.shuttle"}
	target := "-target=" + value.TerraformResource
	if target != "-target=proxmox_virtual_environment_container.shuttle" {
		t.Fatalf("unexpected destructive target %q", target)
	}
}

func TestSSHAttestationFingerprintPatternDoesNotAcceptTrailingInput(t *testing.T) {
	valid := "256 SHA256:8vMN5qYF148h8rQzcAF+UykMz/sOpwQqL/xXT1LbIBQ root@host (ED25519)"
	if got := sshFingerprintPattern.FindString(valid); got != "SHA256:8vMN5qYF148h8rQzcAF+UykMz/sOpwQqL/xXT1LbIBQ" {
		t.Fatalf("fingerprint not extracted: %q", got)
	}
}

func TestInventoryContainsGuest(t *testing.T) {
	body := `[{"vmid":211},{"vmid":240}]`
	for _, tc := range []struct {
		guestID int
		want    bool
	}{
		{guestID: 240, want: true},
		{guestID: 241, want: false},
	} {
		got, err := inventoryContainsGuest(body, tc.guestID)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("inventoryContainsGuest(%d) = %t, want %t", tc.guestID, got, tc.want)
		}
	}
}

func TestInventoryContainsGuestRejectsMalformedJSON(t *testing.T) {
	if _, err := inventoryContainsGuest(`not-json`, 240); err == nil {
		t.Fatal("malformed PVE inventory was accepted")
	}
}

func TestRecreateValidatesAdministratorBeforeDestruction(t *testing.T) {
	project := infraProject{cfg: adoptionApplyConfig(t)}
	project.cfg.Infrastructure.PublicKey = writeOperatorPublicKey(t)
	if _, err := prepareInfraSetup(project); err == nil || !strings.Contains(err.Error(), "before destroying the guest") {
		t.Fatalf("recreate accepted a setup without administrator: %v", err)
	}
	project.cfg.Setup.OperatorUser = "ops"
	project.cfg.Setup.OperatorPublicKey = project.cfg.Infrastructure.PublicKey
	if _, err := prepareInfraSetup(project); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("recreate accepted a shared deploy/administrator key: %v", err)
	}
	project.cfg.Setup.OperatorPublicKey = writeOperatorPublicKey(t)
	options, err := prepareInfraSetup(project)
	if err != nil {
		t.Fatal(err)
	}
	if options.operator == nil || options.operator.user != "ops" || options.target != "root@203.0.113.7:22" || options.expectedHostKey != "" {
		t.Fatalf("invalid pre-attestation setup options: %#v", options)
	}
}

// Nothing retained survives the destruction, so every refusal the deploy would
// give has to come first, from its local checks and from the helper's policy.
func TestRecreateRefusesWhatTheDeployWouldRefuseBeforeDestruction(t *testing.T) {
	const web = "services:\n  web:\n    build: .\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n"
	tests := []struct{ name, compose, want string }{
		{"deployable", web, ""},
		{"global section", web + "volumes:\n  data: {driver_opts: {type: nfs}}\n", "volume data"},
		{"profile", web + "    profiles: [debug]\n", "profiles"},
		{"legacy secrets file", web + "    env_file: .env.secrets\n", ".env.secrets"},
		{"nothing to build", "services:\n  web:\n    image: demo\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n", "no services with build"},
		{"no healthcheck", "services:\n  web:\n    build: .\n", "healthcheck"},
		{"privileged", web + "    privileged: true\n", "privileged"},
		{"bind mount", web + "    volumes: [\"./data:/data\"]\n", "volume"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := infraProject{cfg: adoptionApplyConfig(t)}
			project.cfg.Infrastructure.PublicKey = writeOperatorPublicKey(t)
			project.cfg.Setup.OperatorUser = "ops"
			project.cfg.Setup.OperatorPublicKey = writeOperatorPublicKey(t)
			compose := filepath.Join(t.TempDir(), "docker-compose.yml")
			project.cfg.Deploy.ComposeFiles = []string{compose}
			if err := os.WriteFile(compose, []byte(test.compose), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := prepareInfraRecreate(project)
			if test.want == "" {
				if err != nil {
					t.Fatalf("deployable compose file refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("recreate would destroy the guest before refusing, got %v", err)
			}
		})
	}
}

// pvecli and Ansible inherit this process's environment, and run right after
// the check: application values from .env must not reach them.
func TestRecreateCheckLeavesDotenvOutOfTheEnvironment(t *testing.T) {
	project := infraProject{cfg: adoptionApplyConfig(t)}
	project.cfg.Infrastructure.PublicKey = writeOperatorPublicKey(t)
	project.cfg.Setup.OperatorUser = "ops"
	project.cfg.Setup.OperatorPublicKey = writeOperatorPublicKey(t)
	dir := t.TempDir()
	dotenv := filepath.Join(dir, "app.env")
	if err := os.WriteFile(dotenv, []byte("SHUTTLE_TEST_APP_VALUE=leak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project.cfg.Deploy.EnvFile = dotenv
	project.cfg.Deploy.ComposeFiles = []string{filepath.Join(dir, "missing.yml")}
	_, _ = prepareInfraRecreate(project)
	if value, set := os.LookupEnv("SHUTTLE_TEST_APP_VALUE"); set {
		t.Fatalf("application value reached the environment: %q", value)
	}
}
