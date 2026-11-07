package cli

import (
	"os/exec"
	"testing"
)

func TestComposeHostBuildFailureOutcome(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 1").Run()
	for _, tc := range []struct {
		name, diagnostic string
		unknown          bool
	}{
		{"completed build step", "ERROR: failed to build: failed to solve: process /bin/sh -c false did not complete successfully: exit code: 1", false},
		{"lost connection", "ERROR: failed to build: failed to solve: rpc error: code = Unavailable desc = connection reset by peer", true},
		{"ambiguous failure", "build failed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := composeHostBuildOutcomeUnknown(err, tc.diagnostic); got != tc.unknown {
				t.Fatalf("unknown=%v, want %v", got, tc.unknown)
			}
		})
	}
}
