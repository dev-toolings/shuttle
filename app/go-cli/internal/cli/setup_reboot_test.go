package cli

import (
	"testing"

	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestRebootCompletionRequiresChangedBootID(t *testing.T) {
	before := "11111111-1111-1111-1111-111111111111"
	for name, test := range map[string]struct {
		result shuttlessh.Result
		want   bool
	}{
		"changed": {result: shuttlessh.Result{Code: 0, Stdout: "22222222-2222-2222-2222-222222222222\n"}, want: true},
		"same":    {result: shuttlessh.Result{Code: 0, Stdout: before + "\n"}},
		"offline": {result: shuttlessh.Result{Code: 255}},
		"empty":   {result: shuttlessh.Result{Code: 0}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := rebootCompleted(before, test.result); got != test.want {
				t.Fatalf("rebootCompleted() = %t, want %t", got, test.want)
			}
		})
	}
}
