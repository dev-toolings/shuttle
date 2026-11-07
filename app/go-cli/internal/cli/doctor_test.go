package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/readiness"
)

func TestDoctorStrictFlagIsRegistered(t *testing.T) {
	command := newDoctorCommand()
	flag := command.Flags().Lookup("strict")
	if flag == nil {
		t.Fatal("expected doctor --strict flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("expected --strict default false, got %q", flag.DefValue)
	}
}

func TestDoctorShowSkippedFlagIsRegistered(t *testing.T) {
	command := newDoctorCommand()
	flag := command.Flags().Lookup("show-skipped")
	if flag == nil {
		t.Fatal("expected doctor --show-skipped flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("expected --show-skipped default false, got %q", flag.DefValue)
	}
}

func TestDoctorHasBlockingChecks(t *testing.T) {
	if doctorHasBlockingChecks([]readiness.CheckResult{{Status: readiness.Passed}}) {
		t.Fatal("passed checks must not block strict mode")
	}
	for _, status := range []readiness.Status{readiness.Failed, readiness.Skipped} {
		if !doctorHasBlockingChecks([]readiness.CheckResult{{Status: status}}) {
			t.Fatalf("%s checks must block strict mode", status)
		}
	}
}

func TestParseSSHTarget(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  sshTarget
	}{
		{
			name:  "user and host",
			input: "root@example.com",
			want:  sshTarget{User: "root", Host: "example.com", Port: 22},
		},
		{
			name:  "user host and port",
			input: "deploy@example.com:2222",
			want:  sshTarget{User: "deploy", Host: "example.com", Port: 2222},
		},
		{
			name:  "host only",
			input: "203.0.113.10",
			want:  sshTarget{Host: "203.0.113.10", Port: 22},
		},
		{
			name:  "bracketed ipv6 with port",
			input: "deploy@[2001:db8::1]:2222",
			want:  sshTarget{User: "deploy", Host: "2001:db8::1", Port: 2222},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSSHTarget(tt.input)
			if err != nil {
				t.Fatalf("parse target: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %#v, got %#v", tt.want, got)
			}
		})
	}
}

func TestParseSSHTargetRejectsInvalidPort(t *testing.T) {
	if _, err := parseSSHTarget("deploy@example.com:not-a-port"); err == nil {
		t.Fatal("expected invalid port to fail")
	}
}

func TestWriteDoctorOutputCreatesParentDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".shuttle", "latest-report.json")
	if err := writeDoctorOutput(path, `{"score":100}`); err != nil {
		t.Fatalf("write output: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(raw) != "{\"score\":100}\n" {
		t.Fatalf("unexpected output %q", string(raw))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestDoctorStrictAllowsOnlyProvenNonApplicability(t *testing.T) {
	checks := []readiness.CheckResult{{Status: readiness.Passed}, {Status: readiness.Skipped, SkipReason: readiness.NotApplicable}}
	if doctorHasBlockingChecks(checks) {
		t.Fatal("proven non-applicability must not block strict audit")
	}
	checks[1] = readiness.CheckResult{Status: readiness.Passed, Ignored: true}
	if !doctorHasBlockingChecks(checks) {
		t.Fatal("an exception cannot certify readiness")
	}
	if !doctorHasBlockingChecks(nil) {
		t.Fatal("empty audit cannot certify readiness")
	}
}
