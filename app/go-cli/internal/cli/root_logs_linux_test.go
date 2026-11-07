//go:build linux

package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRootLogsDrainsLargeOutputAndStopsOnOverflow(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		blocks int
	}{
		{name: "below limit", blocks: 12},
		{name: "overflowing producer", blocks: 60},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			started := time.Now()
			body, err := collectRootServiceLogs(func(ctx context.Context) *exec.Cmd {
				// Alternate streams past pipe capacities. On overflow, keep
				// producing forever so discarding without cancellation fails.
				program := fmt.Sprintf(`i=0; while [ "$i" -lt %d ]; do
head -c 32768 /dev/zero | tr '\000' o
head -c 32768 /dev/zero | tr '\000' e >&2
i=$((i+1))
done`, scenario.blocks)
				if scenario.blocks*65536 > rootLogsOutputLimit {
					program += "\nwhile :; do head -c 32768 /dev/zero; done"
				}
				return exec.CommandContext(ctx, "/bin/sh", "-c", program)
			})
			if time.Since(started) > 5*time.Second {
				t.Fatalf("log collection stalled: %v", err)
			}
			if scenario.blocks*65536 > rootLogsOutputLimit {
				want := fmt.Sprintf("service logs output exceeded %d bytes, lower --lines", rootLogsOutputLimit)
				if err == nil || err.Error() != want || body != "" {
					t.Fatalf("overflow: err=%v body bytes=%d", err, len(body))
				}
			} else if err != nil || len(body) != scenario.blocks*65536 || strings.Count(body, "o") != scenario.blocks*32768 || strings.Count(body, "e") != scenario.blocks*32768 {
				t.Fatalf("lost combined logs: err=%v body bytes=%d", err, len(body))
			}
		})
	}
}

func TestRootServiceTaskLogsReadsEachTaskOldestFirst(t *testing.T) {
	var read []string
	body, err := collectRootServiceTaskLogs(func(ctx context.Context) *exec.Cmd {
		// `docker service ps` lists the newest task first.
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'running\\nexited\\n'")
	}, func(ctx context.Context, task string) *exec.Cmd {
		read = append(read, task)
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s line\\n' \"$1\"", "sh", task)
	})
	if err != nil || body != "exited line\nrunning line\n" || strings.Join(read, ",") != "exited,running" {
		t.Fatalf("task logs: err=%v body=%q read=%v", err, body, read)
	}
}

func TestRootServiceTaskLogsRefusesUnexpectedTaskIDs(t *testing.T) {
	_, err := collectRootServiceTaskLogs(func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf -- '--follow\\n'")
	}, func(ctx context.Context, task string) *exec.Cmd {
		t.Fatalf("read unexpected task %q", task)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected task id") {
		t.Fatalf("unexpected task id accepted: %v", err)
	}
}
