package cli

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// The preflight reads and refuses; it never repairs. A retained account is one
// Shuttle promised to leave alone, so the script that inspects it must not be
// able to touch it even by accident.
func TestSetupRetainedUsersPreflightIsReadOnlyAndParses(t *testing.T) {
	if setupRetainedUsersPreflightCommand(nil) != "" {
		t.Fatal("no retained account must generate no program")
	}
	program := setupRetainedUsersPreflightCommand([]string{"alice", "bob"})
	for _, required := range []string{"'alice' 'bob'", "authorized_keys", "ssh-keygen -lf", "does not exist", "system account", "no login shell", "closes password logins"} {
		if !strings.Contains(program, required) {
			t.Fatalf("retained preflight is missing %q:\n%s", required, program)
		}
	}
	for _, forbidden := range []string{"useradd", "usermod", "gpasswd", "chmod", "chown", "install ", "mv ", "cp ", "sed -i", "tee ", "sudoers", ">\""} {
		if strings.Contains(program, forbidden) {
			t.Fatalf("retained preflight must be read-only, found %q:\n%s", forbidden, program)
		}
	}
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(program)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("retained preflight shell does not parse: %v\n%s", err, output)
	}

	// Executed for real against an account that cannot exist: the refusal
	// must name it, because the operator fixes accounts on the host by name.
	run := exec.Command("sh", "-s")
	run.Stdin = strings.NewReader(setupRetainedUsersPreflightCommand([]string{"shuttle-no-such-account"}))
	output, err := run.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "retained account shuttle-no-such-account does not exist") {
		t.Fatalf("a missing account must be refused by name: err=%v\n%s", err, output)
	}
}

func TestSetupRetainedUsersMergeFlagsWithConfigurationAndRefuseTheOperator(t *testing.T) {
	cfg := &config.Config{Setup: config.SetupConfig{RetainedUsers: []string{"bob"}}}
	operator := &setupOperatorAccess{user: "ops"}

	retained, err := resolveSetupRetainedUsers(cfg, setupOptions{retainUsers: []string{"alice", "bob"}}, operator)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(retained, " "); got != "alice bob" {
		t.Fatalf("merged retained accounts = %q, want sorted, deduplicated \"alice bob\"", got)
	}

	if _, err := resolveSetupRetainedUsers(cfg, setupOptions{retainUsers: []string{"ops"}}, operator); err == nil || !strings.Contains(err.Error(), "names the operator") {
		t.Fatalf("retaining the operator must be refused: %v", err)
	}
	if _, err := resolveSetupRetainedUsers(cfg, setupOptions{retainUsers: []string{"root"}}, nil); err == nil {
		t.Fatal("retaining root must be refused: PermitRootLogin no wins regardless")
	}
	if retained, err := resolveSetupRetainedUsers(&config.Config{}, setupOptions{}, nil); err != nil || retained != nil {
		t.Fatalf("nothing to retain must resolve to nothing: %v %v", retained, err)
	}
}

// Rule 4: with nothing to retain the signed lists and the printed reports are
// exactly what they were. With something to retain, the accounts enter every
// signed AllowUsers list and no login proof — Shuttle holds no key of theirs.
func TestRetainedAccountsAreSignedButNeverProven(t *testing.T) {
	if setupExtraSSHUsers(nil, nil) != nil {
		t.Fatal("a fresh setup with no operator and nothing retained must sign the historical baseline")
	}
	if got := strings.Join(setupExtraSSHUsers(&setupOperatorAccess{user: "ops"}, nil), " "); got != "ops" {
		t.Fatalf("operator-only extra users = %q", got)
	}
	if got := strings.Join(setupExtraSSHUsers(&setupOperatorAccess{user: "ops"}, []string{"bob", "alice"}), " "); got != "alice bob ops" {
		t.Fatalf("fresh extra users = %q, want sorted \"alice bob ops\"", got)
	}

	identity := setupIdentity{user: "admin", host: "203.0.113.10", port: 22}
	options := setupOptions{adopt: true, retained: []string{"bob"}, operator: &setupOperatorAccess{user: "ops"}}
	if got := strings.Join(adoptionPreservedSSHUsers(identity, options), " "); got != "admin ops" {
		t.Fatalf("proven administrators = %q; a retained account must not enter the login proofs", got)
	}
	if got := strings.Join(adoptionSignedSSHUsers(identity, options), " "); got != "admin bob ops" {
		t.Fatalf("signed accounts = %q, want \"admin bob ops\"", got)
	}
	if got := describeAdoptionAllowUsers(identity, options); got != "AllowUsers admin bob deploy ops" {
		t.Fatalf("plan directive = %q", got)
	}
	// The retained account arriving as first contact is signed once.
	identity.user = "bob"
	if got := describeAdoptionAllowUsers(identity, options); got != "AllowUsers bob deploy ops" {
		t.Fatalf("plan directive with retained first contact = %q", got)
	}

	if setupRetainedUsersSummary(identity, nil) != "" {
		t.Fatal("no retained account must add nothing to the report")
	}
	summary := setupRetainedUsersSummary(identity, []string{"alice", "bob"})
	for _, want := range []string{"ssh -p 22 alice@203.0.113.10", "ssh -p 22 bob@203.0.113.10", "left as they are", "neither grants nor removes", "not proven"} {
		if !strings.Contains(summary, want) {
			t.Errorf("retained report is missing %q:\n%s", want, summary)
		}
	}
}

func TestRetainedFirstContactCannotAlsoBeLockedOut(t *testing.T) {
	identity := setupIdentity{user: "bob"}
	if err := refuseRetainedFirstContactLockOut(identity, setupOptions{adopt: true, lockOutFirstContactUser: true, retained: []string{"bob"}}); err == nil {
		t.Fatal("retaining the account --lock-out-first-contact-user removes must be refused")
	}
	if err := refuseRetainedFirstContactLockOut(identity, setupOptions{adopt: true, lockOutFirstContactUser: true, retained: []string{"alice"}}); err != nil {
		t.Fatalf("locking out one account while retaining another is coherent: %v", err)
	}
	if err := refuseRetainedFirstContactLockOut(identity, setupOptions{adopt: true, retained: []string{"bob"}}); err != nil {
		t.Fatalf("without the lock-out flag there is nothing to contradict: %v", err)
	}
}

func TestSetupRetainUserFlagIsExplicitAndRepeatable(t *testing.T) {
	command := newSetupCommand()
	flag := command.Flags().Lookup("retain-user")
	if flag == nil {
		t.Fatal("setup is missing --retain-user")
	}
	if flag.Value.Type() != "stringArray" {
		t.Fatalf("--retain-user must be repeatable, got %s", flag.Value.Type())
	}
}
