package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestDeployCommandsSilenceUsageOnlyForRuntimeFailures(t *testing.T) {
	tests := []struct {
		name string
		make func() *cobra.Command
		args []string
	}{
		{"deploy", newDeployCommand, []string{"--config", "/no/such/shuttle-config"}},
		{"deploy-existing-stack", newDeployCommand, []string{"existing-stack", "--config", "/no/such/existing-stack.json"}},
		{"helper-update", newHelperCommand, []string{"update", "--config", "/no/such/shuttle-config", "--yes"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.make()
			root := &cobra.Command{Use: "shuttle"}
			root.AddCommand(cmd)
			var stderr bytes.Buffer
			root.SetErr(&stderr)
			root.SetOut(&bytes.Buffer{})
			root.SetArgs(append([]string{cmd.Name()}, tc.args...))
			if err := root.Execute(); err == nil {
				t.Fatal("expected runtime failure")
			}
			if strings.Contains(stderr.String(), "Usage:") {
				t.Fatalf("runtime failure printed usage: %s", stderr.String())
			}
			// main prints the error once; cobra must not print it again.
			if strings.Contains(stderr.String(), "Error:") {
				t.Fatalf("runtime failure printed by cobra as well as main: %s", stderr.String())
			}
		})
	}
	for _, tc := range []struct {
		name string
		make func() *cobra.Command
		args []string
	}{
		{"deploy", newDeployCommand, []string{"--unknown-flag"}},
		{"deploy-existing-stack", newDeployCommand, []string{"existing-stack", "--unknown-flag"}},
		{"helper-update", newHelperCommand, []string{"update", "--unknown-flag"}},
	} {
		t.Run("unknown-flag-"+tc.name, func(t *testing.T) {
			cmd := tc.make()
			root := &cobra.Command{Use: "shuttle"}
			root.AddCommand(cmd)
			var stderr bytes.Buffer
			var stdout bytes.Buffer
			root.SetErr(&stderr)
			root.SetOut(&stdout)
			root.SetArgs(append([]string{cmd.Name()}, tc.args...))
			if err := root.Execute(); err == nil || !strings.Contains(stdout.String()+stderr.String(), "Usage:") {
				t.Fatalf("unknown flag error=%v stdout=%q stderr=%q, want usage", err, stdout.String(), stderr.String())
			}
		})
	}
}

func TestLogsValidatesLinesBeforeLoadingConfiguration(t *testing.T) {
	for _, value := range []string{"-1", "0", "1001", "5000"} {
		t.Run(value, func(t *testing.T) {
			command := newLogsCommand()
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			command.SetArgs([]string{"--lines", value, "--config", "missing-config.json"})
			err := command.Execute()
			if err == nil || err.Error() != "--lines must be between 1 and 1000" {
				t.Fatalf("logs --lines %s: %v", value, err)
			}
			if bytes.Contains(output.Bytes(), []byte("Usage:")) {
				t.Fatalf("invalid --lines dumped usage: %s", output.String())
			}
		})
	}
}

func TestRunSkipBackupRequiresDeclaredBackupPolicy(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "config", "testdata", "valid-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(fixture))
	body = strings.TrimSuffix(body, "}") + `,"operations":{"migrate":{"service":"web","command":["php","migrate"]}}}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	command := newRunCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"migrate", "--skip-backup", "--config", path})
	err = command.Execute()
	if err == nil || err.Error() != "--skip-backup applies only to an operation that declares backup_before" {
		t.Fatalf("--skip-backup without backup_before was not refused: %v", err)
	}
}
