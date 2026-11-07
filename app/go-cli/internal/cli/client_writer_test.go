package cli

import (
	"os"
	"os/exec"
	"testing"
)

func TestRunClientWriterRejectsMissingOperationAndCommand(t *testing.T) {
	if err := runClientWriter(nil, exec.Command("/bin/true")); err == nil {
		t.Fatal("nil operation was accepted")
	}
	if err := runClientWriter(&remoteOperation{}, nil); err == nil {
		t.Fatal("nil command was accepted")
	}
	started := exec.Command("/bin/true")
	started.Process = &os.Process{Pid: os.Getpid()}
	if err := runClientWriter(&remoteOperation{}, started); err == nil {
		t.Fatal("already-started command was accepted")
	}
	extra := exec.Command("/bin/true")
	extra.ExtraFiles = []*os.File{os.Stdin}
	if err := runClientWriter(&remoteOperation{}, extra); err == nil {
		t.Fatal("command with extra files was accepted")
	}
}
