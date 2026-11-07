package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelperUpdateExplicitRollbackFlag(t *testing.T) {
	command := newHelperUpdateCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"--allow-downgrade", "--help"})
	if err := command.Execute(); err != nil {
		t.Fatalf("explicit rollback flag unavailable: %v", err)
	}
	if !strings.Contains(output.String(), "--allow-downgrade") {
		t.Fatal("rollback flag is not documented in help")
	}
}

// Runtime helper-update failures should show their cause without Cobra usage.
func TestHelperUpdateRuntimeFailureSilencesUsage(t *testing.T) {
	command := newHelperUpdateCommand()
	command.SetArgs([]string{"--config", "/no/such/shuttle-config", "--yes"})
	if err := command.Execute(); err == nil || strings.Contains(err.Error(), "Usage:") {
		t.Fatalf("helper update runtime error = %v", err)
	}
}
