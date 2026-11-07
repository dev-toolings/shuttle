//go:build !linux

package cli

import (
	"fmt"
	"os/exec"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
)

// runClientWriterOnPlatform refuses on anything but Linux. An untracked
// Start() here would run docker/build/push with no kernel identity the
// later fence could prove, and PIDs from this host must never be treated
// as VPS-local writers.
func runClientWriterOnPlatform(operation *remoteOperation, command *exec.Cmd) error {
	name := command.Path
	if name == "" && len(command.Args) > 0 {
		name = command.Args[0]
	}
	if name == "" {
		name = "command"
	}
	return fmt.Errorf("client-origin command fencing is only supported on Linux: refusing untracked execution of %s", name)
}

func runClientWriterShim() int {
	return 1
}

func closeRecordedClientWriter(_ *remoteOperation, writer operationwriters.Writer, _ operationwriters.Binding) (operationwriters.Receipt, error) {
	id := writer.ID
	if id == "" {
		id = "client_origin"
	}
	return operationwriters.Receipt{}, fmt.Errorf("client-origin command fencing is only supported on Linux: refusing untracked closure of %s", id)
}
