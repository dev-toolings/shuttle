package cli

import (
	"errors"
	"os"
	"os/exec"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
)

// clientWriterShimArg is argv[1] for the private admission shim. It is not a
// cobra command. init() intercepts it before the public CLI runs, so a user
// who types the token still cannot reach untracked docker/build/push.
const clientWriterShimArg = "__shuttle_client_writer_shim"

// clientWriterReleaseFD is the inherited extra file in the shim. exec.Cmd
// maps ExtraFiles[0] to FD 3. The byte on this pipe is the only admission
// gate: without it the shim exits and the target image is never exec'd.
const clientWriterReleaseFD = 3

func init() {
	if len(os.Args) > 1 && os.Args[1] == clientWriterShimArg {
		os.Exit(runClientWriterShim())
	}
}

// clientOriginAdmission is the durable registration seam. Production always
// calls remoteOperation.registerWriter. Tests may replace only this callback;
// they cannot replace fencing, the shim, or syscall.Exec.
type clientOriginAdmission func(operation *remoteOperation, writer operationwriters.Writer, fence func(operationwriters.Binding) (operationwriters.Receipt, error)) error

var registerClientOriginWriter clientOriginAdmission = admitClientOriginWriter

func admitClientOriginWriter(operation *remoteOperation, writer operationwriters.Writer, fence func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
	if operation == nil {
		return errors.New("client origin writer requires a remote operation")
	}
	return operation.registerWriter(writer, fence)
}

// runClientWriter starts command on this machine only after a client_origin
// writer has been registered against operation. The target (docker, build,
// push) is not exec'd until that admission succeeds. Parent calls this in
// place of command.Run and later closeWriters, which invokes the retained
// fence with the VPS binding.
func runClientWriter(operation *remoteOperation, command *exec.Cmd) error {
	if operation == nil {
		return errors.New("client origin writer requires a remote operation")
	}
	if command == nil {
		return errors.New("client origin writer requires a command")
	}
	if command.Process != nil {
		return errors.New("client origin writer must start the command itself so the target cannot run before admission")
	}
	if len(command.ExtraFiles) > 0 {
		return errors.New("client origin writer does not inherit caller extra files: the private admission pipe occupies the first extra FD")
	}
	return runClientWriterOnPlatform(operation, command)
}
