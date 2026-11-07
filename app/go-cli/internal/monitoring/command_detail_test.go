package monitoring

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestUFWUnavailableSaysWhy(t *testing.T) {
	configValue := collectorConfig()
	configValue.Security.CheckUFW = true
	configValue.Security.RequireUFW = true
	traceback := "Traceback (most recent call last):\n  File \"/usr/lib/python3/dist-packages/ufw\", line 1, in main\nOSError: [Errno 30] Read-only file system: '/run/ufw.lock'"
	engine := New("demo", configValue, Adapters{Run: func(_ context.Context, args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "ufw status verbose" {
			return nil, fmt.Errorf("unexpected command: %s", strings.Join(args, " "))
		}
		return nil, &exec.ExitError{Stderr: []byte(traceback)}
	}})

	checks := engine.securityChecks(context.Background())
	if len(checks) != 1 {
		t.Fatalf("got %d security checks, want one: %#v", len(checks), checks)
	}
	check := checks[0]
	if check.State != StateUnavailable {
		t.Fatalf("UFW failure state = %s, want %s: %#v", check.State, StateUnavailable, check)
	}
	const prefix = "UFW posture could not be inspected: "
	if !strings.HasPrefix(check.Summary, prefix) || !strings.Contains(check.Summary, "Read-only file system: '/run/ufw.lock'") {
		t.Fatalf("UFW summary omitted its command cause: %q", check.Summary)
	}
	if got, want := check.Evidence["command_error"], check.Summary[len(prefix):]; got != want {
		t.Fatalf("command_error evidence = %#v, want summary detail %q", got, want)
	}
}

func TestCommandFailureDetailSanitizes(t *testing.T) {
	input := append([]byte(strings.Repeat("trace ", 150)+"\x1b[31m"+strings.Repeat("tail ", 30)+"\u202e\u200b "), 0xff)
	input = append(input, []byte(" final-cause-word")...)
	detail := commandFailureDetail(errors.New(string(input)))
	if !utf8.ValidString(detail) {
		t.Fatalf("detail is not valid UTF-8: %q", detail)
	}
	for _, char := range detail {
		if unicode.Is(unicode.C, char) {
			t.Fatalf("detail retains Unicode category C rune U+%04X", char)
		}
	}
	if len(detail) > 240 || !strings.HasPrefix(detail, "... ") || !strings.HasSuffix(detail, "final-cause-word") {
		t.Fatalf("detail has wrong bounded tail shape (%d bytes): %q", len(detail), detail)
	}

	// Place a three-byte rune so the nominal tail cut lands in its encoding.
	straddling := strings.Repeat("a", 1000) + "界" + strings.Repeat("z", 226) + "finalword"
	got := commandFailureDetail(errors.New(straddling))
	want := "... " + strings.Repeat("z", 226) + "finalword"
	if got != want || !utf8.ValidString(got) {
		t.Fatalf("multibyte tail cut split or retained a partial rune: got %q, want %q", got, want)
	}
}

func TestCommandFailureDetailRedactsSecrets(t *testing.T) {
	stderr := "failed https://discord.com/api/webhooks/123/abcdef token=s3cr3t Authorization: Bearer xyz"
	detail := commandFailureDetail(&exec.ExitError{Stderr: []byte(stderr)})
	for _, secret := range []string{"discord.com", "abcdef", "s3cr3t", "xyz"} {
		if strings.Contains(detail, secret) {
			t.Errorf("detail retained %q: %q", secret, detail)
		}
	}
	if !strings.Contains(detail, "<url>") || !strings.Contains(detail, "<redacted>") {
		t.Fatalf("redaction markers are missing: %q", detail)
	}
}

func TestCommandFailureDetailRedactsQuotedKeys(t *testing.T) {
	for _, stderr := range []string{
		`{"password":"s3cr3t"}`,
		`{"Authorization":"Bearer xyz-token"}`,
		`{"db_password": "with \"quote\" s3cr3t"}`,
		`X-Auth-Token: s3cr3t`,
		`'api_key'='s3cr3t'`,
	} {
		detail := commandFailureDetail(&exec.ExitError{Stderr: []byte(stderr)})
		for _, secret := range []string{"s3cr3t", "xyz-token"} {
			if strings.Contains(detail, secret) {
				t.Errorf("detail of %s retained %q: %q", stderr, secret, detail)
			}
		}
		if !strings.Contains(detail, "<redacted>") {
			t.Errorf("detail of %s has no redaction marker: %q", stderr, detail)
		}
	}
}

func TestCommandFailureDetailFallsBackToError(t *testing.T) {
	plain := errors.New(`exec: "ufw": executable file not found in $PATH`)
	if got := commandFailureDetail(plain); got != plain.Error() {
		t.Fatalf("plain error detail = %q, want %q", got, plain.Error())
	}

	// Preserve a normal process status string while keeping a blank ExitError.Stderr discoverable.
	blankStderr := errorWithExitStatus{ExitError: &exec.ExitError{Stderr: []byte(" \n\t")}, message: "exit status 1"}
	if got := commandFailureDetail(blankStderr); got != "exit status 1" {
		t.Fatalf("blank stderr did not fall back to Error(): %q", got)
	}
	if got := commandFailureDetail(nil); got != "" {
		t.Fatalf("nil error detail = %q, want empty", got)
	}
	if got := commandFailureSummary("command failed", nil); got != "command failed" {
		t.Fatalf("summary without error detail = %q", got)
	}
}

type errorWithExitStatus struct {
	*exec.ExitError
	message string
}

func (e errorWithExitStatus) Error() string { return e.message }

func (e errorWithExitStatus) Unwrap() error { return e.ExitError }

func TestCommandChecksCarryDetail(t *testing.T) {
	tests := []struct {
		name      string
		wantState string
		configure func(*config.MonitoringConfig)
		prepare   func(*Engine)
		fails     func([]string) bool
		collect   func(*testing.T, Engine) Result
	}{
		{
			name:      "docker info",
			wantState: StateUnavailable,
			fails:     func(args []string) bool { return len(args) >= 2 && args[0] == "docker" && args[1] == "info" },
			collect: func(_ *testing.T, engine Engine) Result {
				return engine.runCheck(context.Background(), "services.docker", "Docker", "service", func(ctx context.Context) (string, string, map[string]any) {
					return engine.docker(ctx)
				})
			},
		},
		{
			name:      "registry inspect",
			wantState: StateUnavailable,
			fails: func(args []string) bool {
				return len(args) >= 3 && args[0] == "docker" && args[1] == "inspect" && args[2] == "shuttle-registry"
			},
			collect: func(_ *testing.T, engine Engine) Result {
				return engine.runCheck(context.Background(), "services.registry", "Registry", "service", func(ctx context.Context) (string, string, map[string]any) {
					return engine.registry(ctx)
				})
			},
		},
		{
			name:      "systemctl is-active postgresql",
			wantState: StateUnavailable,
			prepare:   func(engine *Engine) { engine.PostgresVersion = 18 },
			fails:     func(args []string) bool { return strings.Join(args, " ") == "systemctl is-active postgresql" },
			collect: func(_ *testing.T, engine Engine) Result {
				return engine.runCheck(context.Background(), "services.postgresql", "PostgreSQL", "service", func(ctx context.Context) (string, string, map[string]any) {
					return engine.postgres(ctx)
				})
			},
		},
		{
			name:      "sshd -T",
			wantState: StateUnavailable,
			configure: func(cfg *config.MonitoringConfig) {
				cfg.Security.CheckSSH = true
				cfg.Security.ExpectedSSHPort = 2222
				cfg.Security.ExpectedSSHUsers = []string{"deploy"}
			},
			fails: func(args []string) bool {
				return len(args) >= 3 && args[0] == "sshd" && args[1] == "-T" && args[2] == "-C"
			},
			collect: singleSecurityCheck,
		},
		{
			name:      "systemctl is-active fail2ban",
			wantState: StateDegraded,
			configure: func(cfg *config.MonitoringConfig) { cfg.Security.CheckFail2ban = true },
			fails:     func(args []string) bool { return strings.Join(args, " ") == "systemctl is-active fail2ban" },
			collect:   singleSecurityCheck,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stderr := "distinctive command failure: " + test.name
			cfg := collectorConfig()
			if test.configure != nil {
				test.configure(&cfg)
			}
			runner := func(_ context.Context, args ...string) ([]byte, error) {
				if test.fails(args) {
					return nil, &exec.ExitError{Stderr: []byte(stderr)}
				}
				if test.name == "sshd -T" && len(args) > 0 && args[0] == "sh" {
					return []byte("permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 2222\nallowusers deploy\n"), nil
				}
				return nil, fmt.Errorf("unexpected command: %s", strings.Join(args, " "))
			}
			engine := New("demo", cfg, Adapters{Run: runner})
			if test.prepare != nil {
				test.prepare(&engine)
			}
			result := test.collect(t, engine)
			if result.State != test.wantState {
				t.Fatalf("state = %s, want %s: %#v", result.State, test.wantState, result)
			}
			if !strings.HasSuffix(result.Summary, stderr) {
				t.Fatalf("summary does not end with command detail %q: %q", stderr, result.Summary)
			}
			if got := result.Evidence["command_error"]; got != stderr {
				t.Fatalf("command_error evidence = %#v, want %q", got, stderr)
			}
		})
	}
}

func singleSecurityCheck(t *testing.T, engine Engine) Result {
	t.Helper()
	checks := engine.securityChecks(context.Background())
	if len(checks) != 1 {
		t.Fatalf("got %d security checks, want one: %#v", len(checks), checks)
	}
	return checks[0]
}

func TestDiskPathProbesReturnTheirCommandError(t *testing.T) {
	failure := &exec.ExitError{Stderr: []byte("permission denied while trying to connect to the Docker daemon socket")}
	engine := New("demo", collectorConfig(), Adapters{Run: func(context.Context, ...string) ([]byte, error) {
		return nil, failure
	}})
	engine.PostgresVersion = 16
	if _, ok, reason, err := engine.observedPostgresDataDir(context.Background()); ok || reason != "pg_lsclusters_unobserved" || err != failure {
		t.Fatalf("pg_lsclusters failure = ok %t reason %q err %v", ok, reason, err)
	}
	if _, ok, reason, err := engine.observedRegistryDataPath(context.Background()); ok || reason != "registry_mounts_unobserved" || err != failure {
		t.Fatalf("registry mount failure = ok %t reason %q err %v", ok, reason, err)
	}
	if _, err := engine.observedDockerRootDir(context.Background()); err != failure {
		t.Fatalf("docker root failure = %v", err)
	}
	evidence := withCommandError(map[string]any{"reason": "pg_lsclusters_unobserved"}, failure)
	if !strings.Contains(fmt.Sprint(evidence["command_error"]), "permission denied") {
		t.Fatalf("evidence lost the command cause: %#v", evidence)
	}
}
