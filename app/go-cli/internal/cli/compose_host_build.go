package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Keep diagnostics bounded while still forwarding the whole stream. A build
// result without a definite BuildKit exit is uncertain: the local Docker CLI
// can exit after the SSH connection breaks while the daemon is still building.
type composeBuildDiagnostics struct{ bytes.Buffer }

func (b *composeBuildDiagnostics) Write(p []byte) (int, error) {
	n := len(p)
	const limit = 128 << 10
	if b.Len() < limit {
		_, _ = b.Buffer.Write(p[:min(len(p), limit-b.Len())])
	}
	return n, nil
}

func runComposeHostBuild(args []string, capture *buildProgressCapture) (error, bool) {
	cmd := exec.Command("docker", args...)
	diagnostics := &composeBuildDiagnostics{}
	cmd.Stdout = buildProgressTee{terminal: os.Stdout, capture: capture}
	cmd.Stderr = buildProgressTee{terminal: io.MultiWriter(os.Stderr, diagnostics), capture: capture}
	err := cmd.Run()
	return err, composeHostBuildOutcomeUnknown(err, diagnostics.String())
}

func composeHostBuildOutcomeUnknown(err error, diagnostic string) bool {
	if err == nil {
		return false
	}
	var missing *exec.Error
	var pathErr *os.PathError
	if errors.As(err, &missing) || errors.As(err, &pathErr) {
		return false
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return true
	}
	text := strings.ToLower(diagnostic)
	// BuildKit explicitly reports the exit code of a failed build step. Other
	// Docker failures include connection loss and do not prove remote completion.
	return !(strings.Contains(text, "failed to solve:") && strings.Contains(text, "did not complete successfully: exit code:"))
}
