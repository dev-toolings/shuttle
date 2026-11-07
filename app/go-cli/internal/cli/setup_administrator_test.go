package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestSetupRequiresSurvivingAdministrator(t *testing.T) {
	for _, tc := range []struct {
		name, first, operator, allowed string
		adopt, lockOut, refused        bool
	}{
		{name: "fresh without administrator", first: "root", refused: true},
		{name: "fresh with administrator", first: "root", operator: "ops", allowed: "ops"},
		{name: "adopt root without replacement", first: "root", adopt: true, refused: true},
		{name: "adopt deploy without replacement", first: "deploy", adopt: true, refused: true},
		{name: "adopt root with replacement", first: "root", adopt: true, operator: "ops", allowed: "ops"},
		{name: "retain existing administrator", first: "admin", adopt: true, allowed: "admin"},
		{name: "retain both administrators", first: "admin", adopt: true, operator: "ops", allowed: "admin ops"},
		{name: "same retained operator is deduplicated", first: "ops", adopt: true, operator: "ops", allowed: "ops"},
		{name: "lock out without replacement", first: "admin", adopt: true, lockOut: true, refused: true},
		{name: "lock out with replacement", first: "admin", adopt: true, lockOut: true, operator: "ops", allowed: "ops"},
		{name: "cannot replace self", first: "ops", adopt: true, lockOut: true, operator: "ops", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := setupIdentity{user: tc.first}
			options := setupOptions{adopt: tc.adopt, lockOutFirstContactUser: tc.lockOut}
			if tc.operator != "" {
				options.operator = &setupOperatorAccess{user: tc.operator}
			}
			err := requireSetupAdministrator(identity, options)
			if (err != nil) != tc.refused {
				t.Fatalf("administrator gate returned %v (refused=%t)", err, tc.refused)
			}
			if !tc.refused && tc.adopt {
				if got := strings.Join(adoptionPreservedSSHUsers(identity, options), " "); got != tc.allowed {
					t.Fatalf("retained administrators = %q, want %q", got, tc.allowed)
				}
			}
		})
	}
}

func TestSetupRefusesMissingAdministratorBeforeSSH(t *testing.T) {
	withTempDir(t, func(dir string) {
		init := newInitCommand()
		init.SetOut(&bytes.Buffer{})
		init.SetArgs([]string{"--preset", "nextjs", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--force"})
		if err := init.Execute(); err != nil {
			t.Fatal(err)
		}
		for _, adopt := range []bool{false, true} {
			for _, dryRun := range []bool{false, true} {
				cmd := newSetupCommand()
				cmd.SetOut(&bytes.Buffer{})
				cmd.SetErr(&bytes.Buffer{})
				args := []string{"--config", filepath.Join(dir, "config.json"), "--target", "root@203.0.113.10:22",
					"--expected-host-key", "SHA256:" + strings.Repeat("A", 43), "--public-key", writeOperatorPublicKey(t)}
				if adopt {
					args = append(args, "--adopt")
				}
				if dryRun {
					args = append(args, "--dry-run")
				} else {
					args = append(args, "--yes")
				}
				cmd.SetArgs(args)
				if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "setup requires an SSH administrator") {
					t.Fatalf("adopt=%t dryRun=%t reached SSH instead of rejecting missing administrator: %v", adopt, dryRun, err)
				}
			}
		}
	})
}

func TestSetupOperatorIncompletePairIsRefused(t *testing.T) {
	for _, options := range []setupOptions{{operatorUser: "ops"}, {operatorKeyPath: "ops.pub"}} {
		if _, err := resolveSetupOperatorAccess(&config.Config{}, options, ""); err == nil || !strings.Contains(err.Error(), "declared together") {
			t.Fatalf("incomplete operator pair accepted: %v", err)
		}
	}
}

func TestAdoptionAttestsAdministratorKeyWithoutReplacingDeployIdentity(t *testing.T) {
	identity := setupIdentity{user: "ops", operatorKeyFingerprint: "SHA256:deploy"}
	options := setupOptions{operator: &setupOperatorAccess{user: "ops", fingerprint: "SHA256:ops"}}
	survey := adoptionSurveyIdentity(identity, options)
	if survey.operatorKeyFingerprint != "SHA256:ops" || identity.operatorKeyFingerprint != "SHA256:deploy" {
		t.Fatal("adoption conflated the first-contact key with the deploy/signing identity")
	}
	identity.user = "root"
	if got := adoptionSurveyIdentity(identity, options); got.operatorKeyFingerprint != "SHA256:deploy" {
		t.Fatal("a newly declared operator must not attest first contact through root")
	}
	identity.user = "admin"
	if got := adoptionSurveyIdentity(identity, setupOptions{}); got.operatorKeyFingerprint != "SHA256:deploy" {
		t.Fatal("legacy adoption must still attest the key declared with --public-key")
	}
}

func TestSetupAccessReportIncludesPortAndPasswordBehavior(t *testing.T) {
	identity := setupIdentity{host: "203.0.113.10", port: 7022}
	report := setupAccessSummary(identity, []string{"admin", "ops"})
	for _, want := range []string{"ssh -p 7022 deploy@203.0.113.10", "ssh -p 7022 admin@203.0.113.10", "ssh -p 7022 ops@203.0.113.10", "sudo -i (no password required)", "No Linux password is generated"} {
		if !strings.Contains(report, want) {
			t.Errorf("missing %q from access report: %s", want, report)
		}
	}
}

// Execute the generated account program against temporary files and stub only
// privileged account commands. File append, permissions, symlink checks and
// repeated convergence run as real shell operations, without touching host users.
type operatorSandbox struct {
	dir, home, keys, bin string
}

func newOperatorSandbox(t *testing.T) operatorSandbox {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("executes Linux account-management shell")
	}
	dir := t.TempDir()
	s := operatorSandbox{dir: dir, home: filepath.Join(dir, "home", "ops"), bin: filepath.Join(dir, "bin")}
	s.keys = filepath.Join(s.home, ".ssh", "authorized_keys")
	for _, path := range []string{s.bin, filepath.Dir(s.keys), filepath.Join(dir, "sudoers")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"id": `case "$1" in
-u) printf '%s\n' "${ACCOUNT_UID:-1001}";;
-gn) echo ops;;
-nG) echo 'ops sudo docker';;
*) test -f "$CASE_DIR/account";;
esac`,
		"getent":  `printf 'ops:x:1001:1001::%s:%s\n' "${ACCOUNT_HOME:-$CASE_DIR/home/ops}" "${ACCOUNT_SHELL:-/bin/bash}"`,
		"useradd": `touch "$CASE_DIR/account"; mkdir -p "$CASE_DIR/home/ops"`,
		"passwd":  `echo passwd >>"$CASE_DIR/mutations"`,
		"chown":   `exit 0`,
		"gpasswd": `test -f "$CASE_DIR/sudoers/91-shuttle-operator-ops"; echo gpasswd >>"$CASE_DIR/mutations"`,
		"visudo":  `test "${FAIL_VISUDO:-no}" != yes`,
	} {
		if err := os.WriteFile(filepath.Join(s.bin, name), []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"account": "", "operator.pub": "ssh-ed25519 new-key ops\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s operatorSandbox) run(program string, env ...string) ([]byte, error) {
	program = strings.NewReplacer(
		"/home/", s.dir+"/home/",
		"/etc/sudoers.d", s.dir+"/sudoers",
		"/tmp/shuttle-emergency-operator.pub", s.dir+"/operator.pub",
		`-o "$user" -g "$group"`, "",
	).Replace(program)
	command := exec.Command("sh", "-s")
	command.Stdin = strings.NewReader(program)
	command.Env = append(os.Environ(), "PATH="+s.bin+":"+os.Getenv("PATH"), "CASE_DIR="+s.dir)
	command.Env = append(command.Env, env...)
	return command.CombinedOutput()
}

func TestOperatorConvergencePreservesKeysAndResumes(t *testing.T) {
	s := newOperatorSandbox(t)
	// No trailing newline: appending must not corrupt the incumbent key.
	oldKey := "ssh-ed25519 old-key incumbent"
	if err := os.WriteFile(s.keys, []byte(oldKey), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyRule := filepath.Join(s.dir, "sudoers", "91-shuttle-operator")
	if err := os.WriteFile(legacyRule, []byte("admin ALL=(ALL:ALL) NOPASSWD: ALL\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	// A failed rule validation must not remove incumbent sudo membership.
	if out, err := s.run(setupOperatorCommand("ops"), "FAIL_VISUDO=yes"); err == nil {
		t.Fatalf("failed sudo policy validation was ignored: %s", out)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "mutations")); !os.IsNotExist(err) {
		t.Fatalf("existing password or group membership changed before valid sudo policy: %v", err)
	}
	for range 2 {
		if out, err := s.run(setupOperatorCommand("ops")); err != nil {
			t.Fatalf("operator convergence failed: %v\n%s", err, out)
		}
	}
	keys, err := os.ReadFile(s.keys)
	if err != nil || string(keys) != oldKey+"\nssh-ed25519 new-key ops\n" {
		t.Fatalf("keys lost, corrupted or duplicated on resume: %q, %v", keys, err)
	}
	legacy, err := os.ReadFile(legacyRule)
	if err != nil || string(legacy) != "admin ALL=(ALL:ALL) NOPASSWD: ALL\n" {
		t.Fatalf("another administrator's sudo policy changed: %q, %v", legacy, err)
	}
	mutations, _ := os.ReadFile(filepath.Join(s.dir, "mutations"))
	if strings.Contains("\n"+string(mutations), "\npasswd\n") {
		t.Fatal("convergence must preserve an existing operator's console password")
	}
}

func TestNewOperatorHasKeyAccessAndALockedPassword(t *testing.T) {
	s := newOperatorSandbox(t)
	if err := os.Remove(filepath.Join(s.dir, "account")); err != nil {
		t.Fatal(err)
	}
	if out, err := s.run(setupOperatorPreflightCommand("ops")); err == nil {
		t.Fatalf("leftover home was accepted for a new administrator: %s", out)
	}
	if err := os.RemoveAll(s.home); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if out, err := s.run(setupOperatorCommand("ops")); err != nil {
			t.Fatalf("new operator convergence failed: %v\n%s", err, out)
		}
	}
	mutations, err := os.ReadFile(filepath.Join(s.dir, "mutations"))
	if err != nil || strings.Count("\n"+string(mutations), "\npasswd\n") != 1 {
		t.Fatalf("password must be locked on creation only: %q, %v", mutations, err)
	}
	for path, permission := range map[string]os.FileMode{
		s.keys: 0o600,
		filepath.Join(s.dir, "sudoers", "91-shuttle-operator-ops"): 0o440,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != permission {
			t.Fatalf("unexpected access-file permissions for %s: %v, %v", path, info, err)
		}
	}
}

func TestOperatorPreflightRefusesIncompatibleAccountsWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		unsafeKey bool
	}{
		{name: "root UID", env: "ACCOUNT_UID=0"},
		{name: "system UID", env: "ACCOUNT_UID=42"},
		{name: "wrong home", env: "ACCOUNT_HOME=/root"},
		{name: "no login", env: "ACCOUNT_SHELL=/usr/sbin/nologin"},
		{name: "symlink keys", unsafeKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newOperatorSandbox(t)
			if tc.unsafeKey {
				if err := os.Symlink(filepath.Join(s.dir, "operator.pub"), s.keys); err != nil {
					t.Fatal(err)
				}
			}
			env := []string{}
			if tc.env != "" {
				env = append(env, tc.env)
			}
			if out, err := s.run(setupOperatorPreflightCommand("ops"), env...); err == nil {
				t.Fatalf("incompatible account accepted: %s", out)
			}
			if _, err := os.Stat(filepath.Join(s.dir, "mutations")); !os.IsNotExist(err) {
				t.Fatalf("read-only preflight mutated account: %v", err)
			}
		})
	}
}
