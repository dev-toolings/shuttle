package cli

import (
	"reflect"
	"sort"
	"testing"
)

func TestDebugCommandSurfaceIsClosed(t *testing.T) {
	command := newDebugCommand()
	got := []string{}
	for _, child := range command.Commands() {
		got = append(got, child.Name())
	}
	sort.Strings(got)
	want := []string{"inspect", "logs", "network", "ps", "services", "tasks"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("debug commands = %v, want %v", got, want)
	}
}

func TestDebugCommandsDoNotAcceptDockerArguments(t *testing.T) {
	for _, name := range []string{"ps", "services", "network"} {
		command := newDebugCommand()
		command.SetArgs([]string{name, "--all"})
		if err := command.Execute(); err == nil {
			t.Fatalf("debug %s accepted a Docker flag", name)
		}
	}
	for _, name := range []string{"tasks", "inspect"} {
		command := newDebugCommand()
		command.SetArgs([]string{name})
		if err := command.Execute(); err == nil {
			t.Fatalf("debug %s accepted no service", name)
		}
	}
}

func TestDebugLogsBoundsAreSealedByRootPlan(t *testing.T) {
	for _, value := range []string{"0", "1001"} {
		command := newDebugCommand()
		command.SetArgs([]string{"logs", "web", "--lines", value})
		if err := command.Execute(); err == nil || err.Error() != "--lines must be between 1 and 1000" {
			t.Fatalf("debug logs accepted --lines %s", value)
		}
	}
}
