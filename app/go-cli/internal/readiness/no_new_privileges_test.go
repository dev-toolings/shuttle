package readiness

import (
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
	"testing"
)

func TestDoctorRegistersEffectiveNoNewPrivilegesCheck(t *testing.T) {
	adapter := scriptedAdapter{respond: func(string) execx.Result { return execx.Result{ExitCode: 1} }}
	report := RunWithConfig(adapter, "local", []string{"docker"}, Config{}, "")
	for _, check := range report.Checks {
		if check.ID == "docker.no_new_privileges" {
			if check.Status == Passed {
				t.Fatal("unreadable daemon must not pass")
			}
			return
		}
	}
	t.Fatal("doctor has no effective no-new-privileges check")
}

func TestDockerNoNewPrivilegesReadsEffectiveDaemon(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		exit       int
		want       Status
	}{
		{"enabled", `["name=seccomp,profile=builtin","name=no-new-privileges"]`, 0, Passed},
		{"disabled", `["name=seccomp,profile=builtin"]`, 0, Failed},
		{"empty", `[]`, 0, Failed},
		{"unavailable", "", 1, Skipped},
		{"malformed", `true`, 0, Skipped},
		{"null", `null`, 0, Skipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := scriptedAdapter{respond: func(cmd string) execx.Result {
				if cmd != "docker info --format '{{json .SecurityOptions}}'" {
					t.Fatalf("must query the live daemon: %s", cmd)
				}
				return execx.Result{Stdout: tc.body, ExitCode: tc.exit}
			}}
			got := checkDockerNoNewPrivileges(adapter)
			if got.Status != tc.want {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
		})
	}
}
