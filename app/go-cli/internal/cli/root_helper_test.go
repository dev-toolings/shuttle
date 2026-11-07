package cli

import "testing"

func TestRootHelperHasOnlyTypedApplySurface(t *testing.T) {
	root := NewRootHelperCommand()
	if !root.CompletionOptions.DisableDefaultCmd {
		t.Fatal("root helper completion command is enabled")
	}
	commands := root.Commands()
	if len(commands) != 1 || commands[0].Name() != "apply" {
		t.Fatalf("unexpected root helper commands: %#v", commands)
	}
	if commands[0].Args == nil {
		t.Fatal("root helper apply does not reject arguments")
	}
}
