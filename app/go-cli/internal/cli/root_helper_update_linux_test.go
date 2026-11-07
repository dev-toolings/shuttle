//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
)

func TestRootHelperCandidateDowngradeRefused(t *testing.T) {
	old := version.Version
	version.Version = "v0.0.66"
	t.Cleanup(func() { version.Version = old })
	path := writeProbeCandidate(t, "if [ \"$1\" = --version ]; then echo 'shuttle version v0.0.65'; else echo 'Apply signed Shuttle root operations'; fi\n")
	if err := probeRootHelperCandidate(path, false); err == nil || !strings.Contains(err.Error(), "--allow-downgrade") {
		t.Fatalf("older candidate accepted without signed rollback consent: %v", err)
	}
}

func TestRootHelperCandidateReleaseOrderingAndRollback(t *testing.T) {
	oldVersion, oldRoot := version.Version, rootDestroyCleanupRoot
	rootDestroyCleanupRoot = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { version.Version, rootDestroyCleanupRoot = oldVersion, oldRoot })
	for _, tt := range []struct {
		name, installed, candidate string
		allow, wantError           bool
	}{
		{"explicit rollback", "v0.0.66", "v0.0.65", true, false},
		{"same release", "v0.0.65", "v0.0.65", false, false},
		{"numeric patch upgrade", "v0.0.9", "v0.0.65", false, false},
		{"numeric minor downgrade", "v0.10.0", "v0.9.99", false, true},
		{"major downgrade", "v1.0.0", "v0.99.99", false, true},
		{"dev candidate", "v0.0.65", "dev", false, false},
		{"dev installed", "dev", "v0.0.65", false, false},
		{"git describe candidate", "v0.0.65", "v0.0.64-3-gabcdef0", false, false},
		{"dirty tag installed", "v0.0.65-dirty", "v0.0.64", false, false},
		{"dirty commit candidate", "v0.0.65", "abcdef0-dirty", false, false},
		{"missing version", "v0.0.65", "", true, true},
		{"malformed candidate", "v0.0.65", "not-a-version", true, true},
		{"malformed installed", "unknown", "v0.0.65", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			version.Version = tt.installed
			path := writeProbeCandidate(t, fmt.Sprintf("if [ \"$1\" = --version ]; then echo 'shuttle version %s'; else echo 'Apply signed Shuttle root operations'; fi\n", tt.candidate))
			installed := filepath.Join(t.TempDir(), "shuttle-root")
			if err := os.WriteFile(installed, []byte("installed"), 0o755); err != nil {
				t.Fatal(err)
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			err = replaceRootHelper(installed, payload, func(staged string) error { return probeRootHelperCandidate(staged, tt.allow) })
			if (err != nil) != tt.wantError {
				t.Fatalf("candidate %s replacing %s (allow=%t): %v", tt.candidate, tt.installed, tt.allow, err)
			}
			actual, err := os.ReadFile(installed)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantError && string(actual) != "installed" {
				t.Fatal("refused candidate replaced installed helper")
			}
			if !tt.wantError && !bytes.Equal(actual, payload) {
				t.Fatal("accepted candidate was not installed")
			}
		})
	}
}

func TestRootHelperCandidatePendingDestroyBlocksRollbackAndDevelopment(t *testing.T) {
	oldVersion, oldRoot, oldFS := version.Version, rootDestroyCleanupRoot, rootHelperCandidateFS
	rootHelperCandidateFS = testHelperMigrationFS
	rootDestroyCleanupRoot = filepath.Join(t.TempDir(), "destroy-cleanup")
	if err := os.Mkdir(rootDestroyCleanupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDestroyCleanupRoot, "pending.json"), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { version.Version, rootDestroyCleanupRoot, rootHelperCandidateFS = oldVersion, oldRoot, oldFS })
	for _, tt := range []struct {
		name, installed, candidate string
		allow, wantError           bool
	}{
		{"explicit rollback", "v0.0.66", "v0.0.65", true, true},
		{"dev candidate", "v0.0.66", "dev", false, true},
		{"dev installed", "dev", "v0.0.66", false, true},
		{"release upgrade can repair destroy", "v0.0.65", "v0.0.66", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			version.Version = tt.installed
			path := writeProbeCandidate(t, fmt.Sprintf("if [ \"$1\" = --version ]; then echo 'shuttle version %s'; else echo 'Apply signed Shuttle root operations'; fi\n", tt.candidate))
			err := probeRootHelperCandidate(path, tt.allow)
			if (err != nil) != tt.wantError || (tt.wantError && !strings.Contains(err.Error(), "helper replacement refused while a pending destroy journal exists")) {
				t.Fatalf("pending destroy guard: %v", err)
			}
			if err := os.Remove(filepath.Join(rootDestroyCleanupRoot, "pending.json")); err != nil {
				t.Fatal(err)
			}
			if err := probeRootHelperCandidate(path, tt.allow); err != nil {
				t.Fatalf("empty directory blocked candidate: %v", err)
			}
			if err := os.WriteFile(filepath.Join(rootDestroyCleanupRoot, "pending.json"), []byte("pending"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDestroyCleanupSchemaBoundary(t *testing.T) {
	for _, schema := range []string{"shuttle.destroy-cleanup/v1", "shuttle.destroy-cleanup/v2", "shuttle.destroy-cleanup/v999"} {
		t.Run(schema, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			journal := destroyCleanupJournal{Schema: schema, OperationID: strings.Repeat("a", 32), App: "demo", DropDatabases: true, DrainBoundNanos: int64(30 * time.Second)}
			path, err := destroyCleanupJournalPath(root, journal.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(journal)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			read, _, err := readDestroyCleanupJournalAt(root, journal.OperationID, journal.App)
			if schema == "shuttle.destroy-cleanup/v999" {
				if err == nil || read != nil {
					t.Fatal("unknown schema did not fail closed")
				}
				if err := writeDestroyCleanupJournalAt(root, journal); err == nil {
					t.Fatal("unknown schema was rewritten")
				}
				return
			}
			if err != nil || read == nil || !read.DropDatabases {
				t.Fatalf("v1 consent lost: %+v %v", read, err)
			}
			if err := writeDestroyCleanupJournalAt(root, *read); err != nil {
				t.Fatal(err)
			}
			body, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &journal); err != nil {
				t.Fatal(err)
			}
			if journal.Schema != "shuttle.destroy-cleanup/v2" || !journal.DropDatabases {
				t.Fatalf("consent was written under an unsafe schema: %+v", journal)
			}
		})
	}
}

func TestDestroyCleanupV1WithoutConsentKeepsData(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := destroyCleanupJournal{Schema: "shuttle.destroy-cleanup/v1", OperationID: strings.Repeat("b", 32), App: "demo", DrainBoundNanos: int64(30 * time.Second)}
	path, err := destroyCleanupJournalPath(root, journal.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("drop_databases")) {
		t.Fatal("fixture must omit consent")
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	read, _, err := readDestroyCleanupJournalAt(root, journal.OperationID, journal.App)
	if err != nil || read == nil || read.DropDatabases {
		t.Fatalf("legacy journal acquired drop consent: %+v %v", read, err)
	}
}

func writeProbeCandidate(t *testing.T, script string) string {
	t.Helper()
	if !strings.Contains(script, "--version") {
		script = "if [ \"$1\" = --version ]; then echo 'shuttle version dev'; exit 0; fi\n" + script
		oldRoot := rootDestroyCleanupRoot
		rootDestroyCleanupRoot = filepath.Join(t.TempDir(), "absent")
		t.Cleanup(func() { rootDestroyCleanupRoot = oldRoot })
	}
	path := filepath.Join(t.TempDir(), "candidate")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRootHelperProbeReportsSanitizedStderrDetail(t *testing.T) {
	path := writeProbeCandidate(t, "printf 'distinctive-probe-cause\\n\\033[31mred\\033[0m\u202e' >&2; printf '%1024s' x >&2; exit 1\n")
	err := probeRootHelperCandidate(path, false)
	if err == nil {
		t.Fatal("failed candidate probe succeeded")
	}
	message := err.Error()
	const prefix = "replacement binary does not expose the shuttle-root interface:"
	if !strings.HasPrefix(message, prefix) {
		t.Fatalf("unexpected probe error: %v", err)
	}
	detail := strings.TrimSpace(strings.TrimPrefix(message, prefix))
	if !strings.Contains(detail, "distinctive-probe-cause") {
		t.Fatalf("stderr cause missing from detail: %q", detail)
	}
	if len(detail) > 240 || !utf8.ValidString(detail) {
		t.Fatalf("detail is not bounded valid UTF-8: len=%d %q", len(detail), detail)
	}
	for _, value := range detail {
		if unicode.Is(unicode.C, value) {
			t.Fatalf("detail contains Unicode category C rune U+%04X", value)
		}
	}
}

func TestBoundedHelperProbeDetailDoesNotSplitUTF8Rune(t *testing.T) {
	detail := boundedHelperProbeDetail(strings.Repeat("a", 239) + "é" + strings.Repeat("b", 10))
	if !utf8.ValidString(detail) || len(detail) > 240 {
		t.Fatalf("detail is not bounded valid UTF-8: len=%d %q", len(detail), detail)
	}
	if detail != strings.Repeat("a", 239) {
		t.Fatalf("rune crossing byte 240 was not omitted whole: len=%d %q", len(detail), detail)
	}
}

func TestRootHelperProbeOutputIsBounded(t *testing.T) {
	path := writeProbeCandidate(t, "head -c 65536 /dev/zero | tr '\\000' x; printf 'Apply signed Shuttle root operations after limit'; exit 0\n")
	body, truncated, err := runHelperProbeCommand(path)
	if len(body) > 64<<10 || !truncated {
		t.Fatalf("probe output was not bounded: len=%d truncated=%v", len(body), truncated)
	}
	// Exit 0 isolates the intended trade-off: a marker printed only after the
	// 64 KiB capture is not seen, so the candidate is refused. A real
	// shuttle-root prints it in its first line of --help.
	if err != nil {
		t.Fatalf("candidate exiting 0 returned an execution error: %v", err)
	}
	if err := probeRootHelperCandidate(path, false); err == nil || !strings.HasPrefix(err.Error(), "replacement binary does not expose the shuttle-root interface:") {
		t.Fatalf("candidate with marker only after output limit did not fail with interface error: %v", err)
	}
}

func TestRootHelperProbeExitZeroWithoutMarkerIncludesDetail(t *testing.T) {
	path := writeProbeCandidate(t, "printf 'candidate omitted interface marker'; exit 0\n")
	err := probeRootHelperCandidate(path, false)
	if err == nil || !strings.HasPrefix(err.Error(), "replacement binary does not expose the shuttle-root interface:") || !strings.Contains(err.Error(), "candidate omitted interface marker") {
		t.Fatalf("unexpected missing-marker probe error: %v", err)
	}
}

func TestRootHelperReplacementProbeFailurePreservesInstalledFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "shuttle-root")
	installed := []byte("installed-helper")
	if err := os.WriteFile(path, installed, 0o755); err != nil {
		t.Fatal(err)
	}
	probeErr := fmt.Errorf("candidate probe failed")
	err := replaceRootHelper(path, []byte("replacement-helper"), func(string) error {
		return probeErr
	})
	if err != probeErr {
		t.Fatalf("unexpected replacement error: %v", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, installed) {
		t.Fatalf("installed helper changed after failed probe: %q %v", actual, err)
	}
	if _, err := os.Lstat(path + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("failed probe created previous helper: %v", err)
	}
}

func TestRootHelperReplacementIsProbedAtomicAndRecoverable(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "shuttle-root")
	if err := os.WriteFile(path, []byte("old-helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	newHelper := []byte("new-helper")
	probed := false
	err := replaceRootHelper(path, newHelper, func(candidate string) error {
		probed = true
		body, err := os.ReadFile(candidate)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, newHelper) {
			t.Fatalf("probe saw the wrong candidate: %q", body)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !probed {
		t.Fatal("replacement was installed without probing it")
	}
	installed, _ := os.ReadFile(path)
	previous, _ := os.ReadFile(path + ".previous")
	if !bytes.Equal(installed, newHelper) || string(previous) != "old-helper" {
		t.Fatalf("unexpected installed/previous helpers: %q / %q", installed, previous)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("replacement mode is not 0755: %v %v", info, err)
	}
}

func TestRootHelperELFValidationMatchesCurrentArchitecture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRootHelperELF(body); err != nil {
		t.Fatalf("the current Linux test executable must match this host: %v", err)
	}
	if err := validateRootHelperELF([]byte("not an ELF")); err == nil {
		t.Fatal("non-ELF helper was accepted")
	}
}

// A candidate can finish while a fork still holds its output descriptors.
// Both execution and output collection must spend the same deadline.
func TestRootHelperProbeDeadlineIncludesForkedOutput(t *testing.T) {
	for _, script := range []string{
		"sleep 1 & wait",
		"sleep 1 & exit 0",
		"sleep 1 & kill -TERM $$",
		"setsid sleep 1 & exit 0",
	} {
		t.Run(script, func(t *testing.T) {
			if script == "setsid sleep 1 & exit 0" {
				// Without a handshake, the parent can exit before setsid runs.
				// Group cleanup then legitimately kills the child and succeeds,
				// making the escaped-output assertion depend on scheduling.
				marker := filepath.Join(t.TempDir(), "detached")
				script = fmt.Sprintf("setsid sh -c 'touch \"%s\"; exec sleep 1' & while [ ! -f \"%s\" ]; do sleep 0.001; done; exit 0", marker, marker)
			}
			path := writeProbeCandidate(t, script)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, _, err := runHelperProbeCommandContext(ctx, path)
			if time.Since(start) > 600*time.Millisecond {
				t.Errorf("probe exceeded deadline: %s", time.Since(start))
			}
			if err == nil && script != "sleep 1 & exit 0" {
				t.Error("blocked or signaled probe succeeded")
			}
			if script == "sleep 1 & wait" && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("missing timeout cause: %v", err)
			}
		})
	}
}

func TestRootHelperProbeStopsForkedChild(t *testing.T) {
	for _, end := range []string{"wait", "exit 0", "kill -TERM $$"} {
		t.Run(end, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			path := writeProbeCandidate(t, fmt.Sprintf("sleep 1 & echo $! > '%s'; %s", pidFile, end))
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			_, _, _ = runHelperProbeCommandContext(ctx, path)
			body, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
			if err != nil {
				t.Fatal(err)
			}
			// Orphaned children may be zombies until the test host's init reaps them;
			// they must no longer execute or hold any descriptor.
			until := time.Now().Add(200 * time.Millisecond)
			for {
				status, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				// Procfs can return ESRCH if the process is reaped after open.
				if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				fields := strings.Fields(string(status))
				if len(fields) > 2 && fields[2] == "Z" {
					break
				}
				if time.Now().After(until) {
					t.Fatalf("candidate child %d still running", pid)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestRootHelperProbeRetriesShareDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	calls := 0
	start := time.Now()
	_, _, err := runHelperProbeWithRetries(ctx, "candidate", func(attempt context.Context, _ string) ([]byte, bool, error) {
		calls++
		got, _ := attempt.Deadline()
		if got != deadline {
			t.Fatal("retry replaced the overall deadline")
		}
		return nil, false, syscall.ETXTBSY
	})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 2 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("retries escaped deadline: calls=%d elapsed=%s err=%v", calls, time.Since(start), err)
	}
}

func TestRootHelperProbeFailureReportsObservedState(t *testing.T) {
	for _, state := range []string{"absent", "prepared", "unreadable"} {
		t.Run(state, func(t *testing.T) {
			paths := helperMigrationPaths{IntentPath: filepath.Join(t.TempDir(), "migration", "intent.json")}
			fs := testHelperMigrationFS()
			if state == "prepared" {
				if err := writeHelperMigrationIntent(fs, paths.IntentPath, testHelperMigrationIntent()); err != nil {
					t.Fatal(err)
				}
			} else if state == "unreadable" {
				if err := os.MkdirAll(filepath.Dir(paths.IntentPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(paths.IntentPath, []byte("not-json"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := writeProbeCandidate(t, "ulimit -c 0; kill -SEGV $$")
			_, _, cause := runHelperProbeCommand(path)
			message := helperProbeFailureWithFS(cause, nil, fs, paths).Error()
			if !strings.Contains(message, "signal") || strings.Contains(message, "30s") || strings.Contains(message, "--dry-run") || strings.Contains(message, "retained") {
				t.Fatalf("unverified probe message: %s", message)
			}
			switch state {
			case "absent":
				if !strings.Contains(message, "no migration intent") {
					t.Fatal(message)
				}
			case "prepared":
				if !strings.Contains(message, paths.IntentPath) || !strings.Contains(message, "prepared") || !strings.Contains(message, "docs/operations-recovery.md#interrupted-helper-probe") {
					t.Fatal(message)
				}
			case "unreadable":
				if !strings.Contains(message, "cannot read migration intent") {
					t.Fatal(message)
				}
			}
		})
	}
}

func TestRootHelperProbeRetriesBusyExecutableOnRealPath(t *testing.T) {
	path := writeProbeCandidate(t, "echo 'Apply signed Shuttle root operations'")
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { time.Sleep(150 * time.Millisecond); _ = writer.Close(); close(closed) }()
	defer func() { <-closed }()
	if err := probeRootHelperCandidate(path, false); err != nil {
		t.Fatalf("real probe did not retry ETXTBSY: %v", err)
	}
}
