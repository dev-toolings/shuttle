package readiness

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

func TestBuildRunnerKeepsProductionRegistryReadinessStrict(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want Status
	}{
		{name: "healthy loopback", out: "running healthy always 127.0.0.1:5000\n", want: Passed},
		{name: "wrong restart policy", out: "running healthy unless-stopped 127.0.0.1:5000\n", want: Failed},
		{name: "wrong bind", out: "running healthy always 0.0.0.0:5000\n", want: Failed},
		{name: "unhealthy", out: "running unhealthy always 127.0.0.1:5000\n", want: Failed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := scriptedAdapter{respond: func(command string) execx.Result {
				if !strings.Contains(command, "shuttle-registry") {
					t.Fatalf("registry check command lost its target: %s", command)
				}
				return execx.Result{ExitCode: 0, Stdout: tc.out}
			}}
			if got := checkLoopbackRegistry(adapter); got.Status != tc.want {
				t.Fatalf("registry readiness = %s, want %s: %+v", got.Status, tc.want, got)
			}
		})
	}
}
