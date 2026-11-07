package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

func authorizedKeyFingerprint(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, rest, err := gossh.ParseAuthorizedKey(bytes.TrimSpace(body))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("parse test public key: %v", err)
	}
	return gossh.FingerprintSHA256(key)
}

func TestSetupOperatorRequiresADistinctKey(t *testing.T) {
	deployKey := writeOperatorPublicKey(t)
	deployFingerprint := authorizedKeyFingerprint(t, deployKey)
	options := setupOptions{operatorUser: "ops", operatorKeyPath: deployKey}
	if _, err := resolveSetupOperatorAccess(&config.Config{}, options, deployFingerprint); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("deploy key reuse was accepted: %v", err)
	}

	options.operatorKeyPath = writeOperatorPublicKey(t)
	operator, err := resolveSetupOperatorAccess(&config.Config{}, options, deployFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if operator.user != "ops" || operator.fingerprint == "" || operator.fingerprint == deployFingerprint {
		t.Fatalf("unexpected operator access: %#v", operator)
	}
}

func TestSetupOperatorAccountIsRootEquivalentButDeployStaysRestricted(t *testing.T) {
	program := setupOperatorCommand("ops")
	for _, required := range []string{
		"useradd --create-home --shell /bin/bash",
		"passwd -l",
		"/tmp/shuttle-emergency-operator.pub",
		"/etc/sudoers.d/91-shuttle-operator",
		"ops ALL=(ALL:ALL) NOPASSWD: ALL",
		"gpasswd -d",
		"visudo -cf",
	} {
		if !strings.Contains(program, required) {
			t.Fatalf("operator convergence is missing %q:\n%s", required, program)
		}
	}
	if strings.Contains(program, "usermod -a -G") || strings.Contains(program, "deploy") {
		t.Fatalf("operator convergence must not grant Docker membership or change deploy:\n%s", program)
	}
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(program)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("operator shell does not parse: %v\n%s", err, output)
	}
}

func TestSetupOperatorIsAvailableInBothModesAndVisibleInThePlan(t *testing.T) {
	cfg := &config.Config{Setup: config.SetupConfig{OperatorUser: "ops"}}
	fresh := setupStages(cfg, 22, setupModeFresh)
	adopt := setupStages(cfg, 22, setupModeAdoption)
	if fresh[len(fresh)-1].name != "operator" {
		t.Fatalf("fresh stages do not converge the operator: %v", fresh)
	}
	if adopt[len(adopt)-1].name != "operator" {
		t.Fatal("adoption must converge the configured replacement administrator")
	}

	identity := setupIdentity{host: "203.0.113.10", port: 22}
	legacy := setupPlan(identity, 16)
	if !strings.Contains(legacy, "cannot proceed without an administrator") {
		t.Fatalf("a plan without an administrator must explain the refusal: %s", legacy)
	}

	operator := &setupOperatorAccess{user: "ops", fingerprint: "SHA256:operator"}
	withOperator := setupPlanWithOperator(identity, 16, operator)
	for _, required := range []string{"create ops", "SHA256:operator", "NOPASSWD root access", "prove every retained SSH path"} {
		if !strings.Contains(withOperator, required) {
			t.Fatalf("operator plan is missing %q:\n%s", required, withOperator)
		}
	}
}

func TestSetupOperatorFlagsAreExplicit(t *testing.T) {
	command := newSetupCommand()
	for _, name := range []string{"operator-user", "operator-public-key"} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("setup is missing --%s", name)
		}
	}
}

func TestTrustedHostIdentityRetainsTheCommittedSSHPolicy(t *testing.T) {
	// os.UserConfigDir reads HOME on macOS and XDG_CONFIG_HOME on Linux.
	configHome := t.TempDir()
	t.Setenv("HOME", configHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	value := trustedHostIdentity{
		Version: 2, Host: "203.0.113.10", Port: 22,
		HostKeyFingerprint:     "SHA256:" + strings.Repeat("A", 43),
		OperatorKeyFingerprint: "SHA256:" + strings.Repeat("B", 43),
		AllowedSSHUsers:        []string{"deploy", "ops"},
	}
	if err := saveTrustedHostIdentity(value); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadTrustedHostIdentity(value.Host, value.Port)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(loaded.AllowedSSHUsers, " "); got != "deploy ops" {
		t.Fatalf("persisted SSH policy = %q, want deploy ops", got)
	}
}
