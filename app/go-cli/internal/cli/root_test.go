package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCommandNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, command := range NewRootCommand().Commands() {
		name := command.Name()
		if seen[name] {
			t.Fatalf("command %q is registered twice on the root command; the second one is unreachable", name)
		}
		seen[name] = true
	}
}

func TestRootHelpListsOnlySupportedCommands(t *testing.T) {
	root := NewRootCommand()
	buffer := new(bytes.Buffer)
	root.SetOut(buffer)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	body := buffer.String()
	for _, removed := range []string{"completion", "help", "provision", "harden", "report", "monitor"} {
		if strings.Contains(strings.ToLower(body), "\n  "+removed+" ") {
			t.Fatalf("root help exposes removed command %q:\n%s", removed, body)
		}
	}
}

func TestCommandSurface(t *testing.T) {
	root := NewRootCommand()
	want := []string{"backup", "debug", "deploy", "destroy", "doctor", "helper", "infra", "init", "logs", "operations", "rollback", "run", "secrets", "setup", "skills", "status", "update"}
	commands := root.Commands()
	if len(commands) != len(want) {
		t.Fatalf("root exposes %d commands, want %d", len(commands), len(want))
	}
	for index, command := range commands {
		if command.Name() != want[index] {
			t.Fatalf("command[%d]=%q, want %q", index, command.Name(), want[index])
		}
	}
}
