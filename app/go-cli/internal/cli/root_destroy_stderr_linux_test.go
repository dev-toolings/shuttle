//go:build linux

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The VM's Docker prints absence on stderr, not in its exit error's text.
// Run a process with that exact stream shape so an in-memory runner cannot
// accidentally supply the diagnostic that command.Output would otherwise lose.
func TestDestroyDiscoveryPreservesSubprocessStderr(t *testing.T) {
	for _, scenario := range []string{"absent volumes", "absent secrets", "daemon failure"} {
		t.Run(scenario, func(t *testing.T) {
			volumeReply := `printf '%s\n' '{"com.docker.stack.namespace":"managed-app"}'
printf '%s\n' 'WARNING: fixture daemon warning' >&2`
			if scenario == "absent volumes" {
				volumeReply = `printf 'Error response from daemon: volume %s not found\n' "$object" >&2
exit 1`
			}
			if scenario == "daemon failure" {
				volumeReply = `printf '%s\n' 'permission denied while inspecting volume' >&2
exit 1`
			}
			script := filepath.Join(t.TempDir(), "docker-fixture")
			body := fmt.Sprintf(`#!/bin/sh
for object do :; done
case "$1 $2" in
  'volume ls'|'secret ls') exit 0 ;;
  'volume inspect') %s ;;
  'secret inspect')
    printf 'Error response from daemon: secret %%s not found\n' "$object" >&2
    exit 1 ;;
  *) printf 'unexpected command: %%s\n' "$*" >&2; exit 91 ;;
esac
`, volumeReply)
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			run := func(args ...string) ([]byte, error) {
				return runRootSubprocessOutput(ctx, script, args...)
			}
			var out bytes.Buffer
			err := previewDestroyResources(ctx, t.TempDir(), t.TempDir(), "managed-app", false, postgresRemoval{}, &out, run,
				func(context.Context, string) (int64, error) { t.Fatal("unexpected PostgreSQL query"); return 0, nil })
			if scenario == "daemon failure" {
				if err == nil || !strings.Contains(err.Error(), "permission denied") {
					t.Fatalf("daemon failure must stay visible, not be treated as absence: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Docker's stderr-only absence must not stop preview: %v", err)
			}
			if !strings.Contains(out.String(), "dry-run: no resources or state changed") || strings.Contains(out.String(), "WARNING:") {
				t.Fatalf("preview failed or mixed stderr into parsed stdout: %s", out.String())
			}
			if scenario == "absent volumes" {
				if strings.Contains(out.String(), "would remove volume") || strings.Contains(out.String(), "would remove secret") {
					t.Fatalf("absent resources were listed for removal: %s", out.String())
				}
				// Real destroy uses combined output. The same daemon stderr must
				// also remain recognizable by its shared volume discovery.
				volumes, err := discoverOwnedVolumes("managed-app", func(args ...string) ([]byte, error) {
					return runRootSubprocess(ctx, script, args...)
				}, time.Now().Add(time.Second), time.Now)
				if err != nil || len(volumes) != 0 {
					t.Fatalf("combined-output destroy discovery: volumes=%v err=%v", volumes, err)
				}
			}
			_, err = run("secret", "inspect", "--format", "{{.Spec.Name}}", "managed-app_redis_password_v1")
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("diagnostic wrapping lost the subprocess exit status: %v", err)
			}
		})
	}
}
