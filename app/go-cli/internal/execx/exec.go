package execx

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

type Adapter interface {
	Run(command string, timeout time.Duration) Result
}

type Local struct {
	Dir string
}

func (l Local) Run(command string, timeout time.Duration) Result {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "sh", "-lc", command)
	if l.Dir != "" {
		cmd.Dir = l.Dir
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return Result{ExitCode: 124, Stderr: "command timed out"}
	}
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return Result{ExitCode: exit.ExitCode(), Stdout: stdout.String(), Stderr: stderr.String()}
		}
		return Result{ExitCode: 1, Stdout: stdout.String(), Stderr: err.Error()}
	}

	return Result{ExitCode: 0, Stdout: stdout.String(), Stderr: stderr.String()}
}
