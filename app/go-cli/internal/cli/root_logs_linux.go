//go:build linux

package cli

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	rootLogsOutputLimit = 3 << 20 // under the 4 MiB SSH transport cap (defaultSSHMaxOutputBytes)
	rootLogsTimeout     = 15 * time.Second
)

type rootLogsOutput struct {
	limitedDebugOutput
	cancel context.CancelFunc
}

func (output *rootLogsOutput) Write(payload []byte) (int, error) {
	n, err := output.limitedDebugOutput.Write(payload)
	if output.truncated {
		// Discarding excess bytes alone still waits for Docker to exit. Stop
		// the producer as soon as its output exceeds the collection contract.
		output.cancel()
	}
	return n, err
}

func collectRootServiceLogs(newCommand func(context.Context) *exec.Cmd) (string, error) {
	return collectRootLogCommands(func(ctx context.Context) ([]*exec.Cmd, error) {
		return []*exec.Cmd{newCommand(ctx)}, nil
	})
}

// collectRootServiceTaskLogs reads a service's logs one task at a time.
// Docker 29 keeps `docker service logs <service>` open after the last line
// once the service has several tasks, while the same read scoped to one task
// returns at once (observed on 29.7.2, 19-10-2026). Tasks are read oldest
// first, so the running task ends the output as the service-wide read did.
func collectRootServiceTaskLogs(listTasks func(context.Context) *exec.Cmd, newTaskCommand func(context.Context, string) *exec.Cmd) (string, error) {
	return collectRootLogCommands(func(ctx context.Context) ([]*exec.Cmd, error) {
		list := listTasks(ctx)
		list.WaitDelay = time.Second
		body, err := list.Output()
		if err != nil {
			return nil, fmt.Errorf("list service tasks: %w", err)
		}
		ids := strings.Fields(string(body))
		commands := make([]*exec.Cmd, 0, len(ids))
		for index := len(ids) - 1; index >= 0; index-- {
			if !rootTaskID.MatchString(ids[index]) {
				return nil, fmt.Errorf("list service tasks: unexpected task id %q", ids[index])
			}
			commands = append(commands, newTaskCommand(ctx, ids[index]))
		}
		return commands, nil
	})
}

var rootTaskID = regexp.MustCompile(`^[a-z0-9]{1,64}$`)

func collectRootLogCommands(newCommands func(context.Context) ([]*exec.Cmd, error)) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rootLogsTimeout)
	defer cancel()
	output := &rootLogsOutput{
		limitedDebugOutput: limitedDebugOutput{limit: rootLogsOutputLimit},
		cancel:             cancel,
	}
	commands, err := newCommands(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("read service logs: Docker did not finish within %s, lower --lines or check Docker log availability", rootLogsTimeout)
		}
		return "", err
	}
	for _, command := range commands {
		// Docker tails each task's stdout and stderr separately, so --tail does
		// not bound the total bytes. CombinedOutput previously collected without
		// a cap or deadline and left stalls to the opaque SSH transport timeout.
		// One shared writer makes os/exec serialize both streams, preserving the
		// existing combined output without racing the buffer or stopping drains.
		command.Stdout, command.Stderr = output, output
		// A child retaining an output pipe must not outlive the collection budget.
		command.WaitDelay = time.Second
		err := command.Run()
		if output.truncated {
			return "", fmt.Errorf("service logs output exceeded %d bytes, lower --lines", rootLogsOutputLimit)
		}
		if ctx.Err() != nil {
			return "", fmt.Errorf("read service logs: Docker did not finish within %s, lower --lines or check Docker log availability", rootLogsTimeout)
		}
		if err != nil {
			return "", fmt.Errorf("read service logs: %w: %s", err, strings.TrimSpace(string(output.body)))
		}
	}
	return string(output.body), nil
}
