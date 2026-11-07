//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

var (
	preRunTestBehavior  string
	preRunTestArgsPath  string
	preRunTestPIDPath   string
	preRunTestExisting  map[string]bool
	preRunTestSize      int64
	preRunTestAvailable uint64
	preRunTestTotal     uint64
)

func TestPreRunCommandProcess(t *testing.T) {
	if os.Getenv("SHUTTLE_PRE_RUN_HELPER") != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		os.Exit(91)
	}
	name := os.Args[separator+1]
	args := os.Args[separator+2:]
	behavior := os.Getenv("SHUTTLE_PRE_RUN_BEHAVIOR")
	if path := os.Getenv("SHUTTLE_PRE_RUN_ARGS_FILE"); path != "" {
		_ = os.WriteFile(path, []byte(strings.Join(args, "\n")), 0o600)
	}
	if behavior == "group-parent" && name == "pg_dump" {
		child := exec.Command(os.Args[0], "-test.run=TestPreRunCommandProcess", "--", "child")
		child.Env = append(os.Environ(), "SHUTTLE_PRE_RUN_HELPER=1", "SHUTTLE_PRE_RUN_BEHAVIOR=group-child")
		if err := child.Start(); err != nil {
			os.Exit(92)
		}
		if path := os.Getenv("SHUTTLE_PRE_RUN_PID_FILE"); path != "" {
			_ = os.WriteFile(path, []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	if behavior == "group-child" || name == "child" {
		for {
			time.Sleep(time.Hour)
		}
	}
	switch name {
	case "psql":
		query := strings.Join(args, " ")
		if strings.Contains(query, "pg_database_size") {
			fmt.Fprint(os.Stdout, os.Getenv("SHUTTLE_PRE_RUN_SIZE"))
		} else {
			fmt.Fprint(os.Stdout, "1")
		}
	case "pg_dump":
		database := ""
		if len(args) > 0 {
			database = args[len(args)-1]
		}
		if behavior == "fail-dump" || behavior == "fail-db:"+database {
			fmt.Fprint(os.Stderr, "dump failed\nDETAIL: rejected")
			os.Exit(2)
		}
		if behavior == "hang" {
			for {
				time.Sleep(time.Hour)
			}
		}
		if behavior != "empty-dump" {
			_, _ = os.Stdout.Write([]byte("custom archive bytes"))
		}
	case "pg_restore":
		_, _ = io.Copy(io.Discard, os.Stdin)
		if behavior == "fail-restore" {
			fmt.Fprint(os.Stderr, "archive is invalid")
			os.Exit(2)
		}
	default:
		os.Exit(93)
	}
	os.Exit(0)
}

func TestDeclaredOperationExitCodeHelper(t *testing.T) {
	value := os.Getenv("SHUTTLE_DECLARED_EXIT_CODE")
	if value == "" {
		return
	}
	if value == "signal" {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		return
	}
	code, err := strconv.Atoi(value)
	if err != nil {
		os.Exit(2)
	}
	os.Exit(code)
}

func declaredOperationExitForTest(t *testing.T, value string) error {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestDeclaredOperationExitCodeHelper$")
	command.Env = append(os.Environ(), "SHUTTLE_DECLARED_EXIT_CODE="+value)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("helper subprocess returned %T, want *exec.ExitError: %v", err, err)
	}
	return err
}

func TestDeclaredOperationExitClassificationRequiresNoNewRunningExec(t *testing.T) {
	for _, value := range []string{"1", "3", "124", "126", "127", "137", "125", "255", "signal"} {
		t.Run(value, func(t *testing.T) {
			execErr := declaredOperationExitForTest(t, value)
			knownCode := value == "1" || value == "3" || value == "124" || value == "126" || value == "127" || value == "137"
			for _, scenario := range []struct {
				name       string
				after      []string
				exists     bool
				inspectErr error
				wantKnown  bool
			}{
				{name: "no new exec", after: []string{"prior"}, exists: true, wantKnown: knownCode},
				{name: "new exec still listed", after: []string{"prior", "new"}, exists: true},
				{name: "post check fails", inspectErr: errors.New("docker unavailable")},
				{name: "container disappeared", exists: false, wantKnown: knownCode},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					inspectCalls, execCalls := 0, 0
					inspect := func(string) ([]string, bool, error) {
						inspectCalls++
						if inspectCalls == 1 {
							return []string{"prior"}, true, nil
						}
						return scenario.after, scenario.exists, scenario.inspectErr
					}
					run := func(string, []string, io.Writer) error {
						execCalls++
						return execErr
					}
					got := classifyDeclaredOperationExec(strings.Repeat("a", 64), []string{"node", "fail"}, io.Discard, inspect, run)
					_, isKnown := got.(*coord.KnownOutcomeError)
					if isKnown != scenario.wantKnown {
						t.Fatalf("known outcome=%v, want %v, error=%v", isKnown, scenario.wantKnown, got)
					}
					if execCalls != 1 {
						t.Fatalf("docker exec called %d times", execCalls)
					}
				})
			}
		})
	}
	t.Run("non exit error", func(t *testing.T) {
		inspectCalls := 0
		got := classifyDeclaredOperationExec("container", nil, io.Discard, func(string) ([]string, bool, error) {
			inspectCalls++
			return []string{}, true, nil
		}, func(string, []string, io.Writer) error { return errors.New("transport failure") })
		if _, ok := got.(*coord.KnownOutcomeError); ok {
			t.Fatalf("non-exit error was classified as known: %v", got)
		}
		if inspectCalls != 1 {
			t.Fatalf("non-exit error triggered a post check: %d", inspectCalls)
		}
	})
}

func setupPreRunBackupTest(t *testing.T) string {
	t.Helper()
	oldRoot, oldDaily, oldNow := preRunBackupRoot, preRunDailyLockPath, preRunNow
	oldTimeout, oldCommand := preRunDumpTimeout, preRunCommand
	oldExists, oldSize, oldFilesystem := preRunDatabaseExists, preRunDatabaseSize, preRunFilesystem
	oldLedger, oldOwners, oldStack := preRunLedger, preRunOwners, preRunStackDatabases
	oldExecutable, oldIdentity := preRunExecutable, preRunPostgresIdentity
	oldCredential, oldPrefix, oldEnv := preRunCredentialEnabled, preRunCommandPrefix, preRunCommandEnvironment
	oldCoordinator, oldIdentityVerifier, oldCoordGuard, oldGuard := rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, preRunVerifyIdentity
	oldPreRunGuard, oldLookup, oldContainer, oldExec := preRunMutationGuard, declaredOperationsLookup, declaredOperationContainer, declaredOperationExec
	t.Cleanup(func() {
		preRunBackupRoot, preRunDailyLockPath, preRunNow = oldRoot, oldDaily, oldNow
		preRunDumpTimeout, preRunCommand = oldTimeout, oldCommand
		preRunDatabaseExists, preRunDatabaseSize, preRunFilesystem = oldExists, oldSize, oldFilesystem
		preRunLedger, preRunOwners, preRunStackDatabases = oldLedger, oldOwners, oldStack
		preRunExecutable, preRunPostgresIdentity = oldExecutable, oldIdentity
		preRunCredentialEnabled, preRunCommandPrefix, preRunCommandEnvironment = oldCredential, oldPrefix, oldEnv
		rootOperationCoordinator, rootCoordinatedIdentityVerifier, rootCoordinatedMutationGuard, preRunVerifyIdentity = oldCoordinator, oldIdentityVerifier, oldCoordGuard, oldGuard
		preRunMutationGuard, declaredOperationsLookup, declaredOperationContainer, declaredOperationExec = oldPreRunGuard, oldLookup, oldContainer, oldExec
	})
	root := t.TempDir()
	preRunBackupRoot = filepath.Join(root, "pre-run")
	preRunDailyLockPath = filepath.Join(root, "daily", ".backup.lock")
	preRunNow = func() time.Time { return time.Date(2026, 10, 26, 12, 34, 56, 0, time.UTC) }
	// The fake pg_dump and pg_restore re-exec this test binary, twice per
	// archive. A 1s budget failed six tests on a loaded CI runner (PR #20,
	// 2026-10-26) while proving nothing: the deadline itself is covered by
	// TestPreRunBackupDeadlineCleansUp, which sets its own 40ms budget.
	preRunDumpTimeout = func() time.Duration { return 30 * time.Second }
	preRunTestBehavior = ""
	preRunTestArgsPath = filepath.Join(root, "restore-args")
	preRunTestPIDPath = filepath.Join(root, "child.pid")
	preRunTestExisting = map[string]bool{"demo": true}
	preRunTestSize, preRunTestAvailable, preRunTestTotal = 100, 2<<30, 10<<30
	preRunLedger = func(string) (postgresLedger, error) { return postgresLedger{Version: 1}, nil }
	preRunOwners = func() (map[string]string, map[string]string, error) {
		return map[string]string{}, map[string]string{}, nil
	}
	preRunStackDatabases = func(string) ([]string, error) { return nil, nil }
	preRunDatabaseExists = func(_ context.Context, name string) (bool, error) { return preRunTestExisting[name], nil }
	preRunDatabaseSize = func(context.Context, string) (int64, error) { return preRunTestSize, nil }
	preRunFilesystem = func(string) (uint64, uint64, error) { return preRunTestAvailable, preRunTestTotal, nil }
	preRunCommand = func(ctx context.Context, _ bool, name string, args ...string) *exec.Cmd {
		commandArgs := append([]string{"-test.run=TestPreRunCommandProcess", "--", name}, args...)
		command := exec.CommandContext(ctx, os.Args[0], commandArgs...)
		command.Env = append(os.Environ(), "SHUTTLE_PRE_RUN_HELPER=1", "SHUTTLE_PRE_RUN_BEHAVIOR="+preRunTestBehavior, "SHUTTLE_PRE_RUN_ARGS_FILE="+preRunTestArgsPath)
		return command
	}
	preRunVerifyIdentity = func(rootplan.Plan) error { return nil }
	preRunMutationGuard = func(string) error { return nil }
	return root
}

func archiveFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".dump") {
			result = append(result, entry.Name())
		}
	}
	return result
}

func TestPreRunBackupPublishesVerifiedPrivateArchive(t *testing.T) {
	setupPreRunBackupTest(t)
	var output bytes.Buffer
	if err := preRunBackup("demo", "migrate", &output); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(preRunBackupRoot, "demo")
	files := archiveFiles(t, dir)
	want := "20261026T123456Z-migrate-demo.dump"
	if len(files) != 1 || files[0] != want {
		t.Fatalf("unexpected archives: %v", files)
	}
	info, err := os.Stat(filepath.Join(dir, want))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode is %o", info.Mode().Perm())
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("archive directory mode is %o", info.Mode().Perm())
	}
	if !strings.Contains(output.String(), "backup  app=demo db=demo -> "+filepath.Join(dir, want)+" (20 B, verified)") {
		t.Fatalf("archive line missing: %s", output.String())
	}
	args, err := os.ReadFile(preRunTestArgsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "--list" {
		t.Fatalf("pg_restore must read stdin without an archive path, args=%q", args)
	}
}

func TestPreRunBackupFailuresRemoveAllArchives(t *testing.T) {
	for _, behavior := range []string{"fail-dump", "empty-dump", "fail-restore"} {
		t.Run(behavior, func(t *testing.T) {
			setupPreRunBackupTest(t)
			preRunTestBehavior = behavior
			err := preRunBackup("demo", "migrate", io.Discard)
			if err == nil {
				t.Fatal("invalid dump passed")
			}
			if files := archiveFiles(t, filepath.Join(preRunBackupRoot, "demo")); len(files) != 0 {
				t.Fatalf("failed dump left archives: %v", files)
			}
		})
	}
}

func TestPreRunBackupSecondDatabaseFailureRemovesFirstPublishedArchive(t *testing.T) {
	setupPreRunBackupTest(t)
	preRunTestExisting["customer"] = true
	preRunStackDatabases = func(string) ([]string, error) { return []string{"customer"}, nil }
	preRunTestBehavior = "fail-db:demo"
	err := preRunBackup("demo", "migrate", io.Discard)
	if err == nil {
		t.Fatal("second database failure was ignored")
	}
	if files := archiveFiles(t, filepath.Join(preRunBackupRoot, "demo")); len(files) != 0 {
		t.Fatalf("partial archive set remained: %v", files)
	}
}

func TestPreRunBackupSpaceGuardKeepsTenPercentFree(t *testing.T) {
	for _, test := range []struct {
		name      string
		available uint64
	}{{"below required", 99}, {"below reserve", 199}} {
		t.Run(test.name, func(t *testing.T) {
			setupPreRunBackupTest(t)
			preRunTestAvailable, preRunTestTotal = test.available, 1000
			err := preRunBackup("demo", "migrate", io.Discard)
			if err == nil || !strings.Contains(err.Error(), "not enough space") {
				t.Fatalf("space refusal missing: %v", err)
			}
		})
	}
}

func TestPreRunBackupDatabaseCandidateOwnershipAndValidation(t *testing.T) {
	t.Run("adopted derived database", func(t *testing.T) {
		setupPreRunBackupTest(t)
		var lookedUp []string
		preRunDatabaseExists = func(_ context.Context, name string) (bool, error) {
			lookedUp = append(lookedUp, name)
			return name == "demo", nil
		}
		if err := preRunBackup("demo", "migrate", io.Discard); err != nil {
			t.Fatal(err)
		}
		if len(lookedUp) != 1 || lookedUp[0] != "demo" {
			t.Fatalf("adopted derived database was not probed: %v", lookedUp)
		}
	})
	t.Run("owned by another app", func(t *testing.T) {
		setupPreRunBackupTest(t)
		preRunOwners = func() (map[string]string, map[string]string, error) {
			return nil, map[string]string{"demo": "other-app"}, nil
		}
		called := false
		preRunDatabaseExists = func(context.Context, string) (bool, error) { called = true; return true, nil }
		if err := preRunBackup("demo", "migrate", io.Discard); err == nil || !strings.Contains(err.Error(), "no PostgreSQL database") {
			t.Fatalf("foreign database should not be backed up: %v", err)
		}
		if called {
			t.Fatal("database claimed by another app was probed")
		}
	})
	t.Run("reserved label name", func(t *testing.T) {
		setupPreRunBackupTest(t)
		preRunStackDatabases = func(string) ([]string, error) { return []string{"postgres"}, nil }
		if _, err := preRunDatabaseCandidates("demo"); err == nil || !strings.Contains(err.Error(), "reserved PostgreSQL name") {
			t.Fatalf("reserved name accepted: %v", err)
		}
	})
	t.Run("recorded but absent", func(t *testing.T) {
		setupPreRunBackupTest(t)
		preRunLedger = func(string) (postgresLedger, error) { return postgresLedger{Databases: []string{"history"}}, nil }
		preRunTestExisting = map[string]bool{}
		var output bytes.Buffer
		err := preRunBackup("demo", "migrate", &output)
		if err == nil || !strings.Contains(err.Error(), "no PostgreSQL database") {
			t.Fatalf("empty candidate set was accepted: %v", err)
		}
		if !strings.Contains(output.String(), "backup  skip db=history: recorded but absent") {
			t.Fatalf("absent recorded database was not reported: %s", output.String())
		}
	})
}

func TestPreRunBackupRejectsSizeFailuresLocksAndSweepsStaleFiles(t *testing.T) {
	t.Run("size error", func(t *testing.T) {
		setupPreRunBackupTest(t)
		preRunDatabaseSize = func(context.Context, string) (int64, error) { return 0, errors.New("psql failed") }
		if err := preRunBackup("demo", "migrate", io.Discard); err == nil || !strings.Contains(err.Error(), "psql failed") {
			t.Fatalf("size failure not refused: %v", err)
		}
	})
	t.Run("pre-run lock held", func(t *testing.T) {
		setupPreRunBackupTest(t)
		if err := os.MkdirAll(preRunBackupRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(filepath.Join(preRunBackupRoot, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		if err := preRunBackup("demo", "migrate", io.Discard); err == nil || !strings.Contains(err.Error(), "another pre-run backup") {
			t.Fatalf("held lock not refused: %v", err)
		}
	})
	t.Run("daily lock held", func(t *testing.T) {
		setupPreRunBackupTest(t)
		if err := os.MkdirAll(filepath.Dir(preRunDailyLockPath), 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(preRunDailyLockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		if err := preRunBackup("demo", "migrate", io.Discard); err == nil || !strings.Contains(err.Error(), "daily PostgreSQL backup is running") {
			t.Fatalf("daily backup lock not respected: %v", err)
		}
	})
	t.Run("stale temporary swept", func(t *testing.T) {
		setupPreRunBackupTest(t)
		dir := filepath.Join(preRunBackupRoot, "demo")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		stale := filepath.Join(dir, ".pre-run-stale")
		if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := preRunBackup("demo", "migrate", io.Discard); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Fatalf("stale file remains: %v", err)
		}
	})
}

func TestPreRunBackupDeadlineCleansUp(t *testing.T) {
	setupPreRunBackupTest(t)
	preRunDumpTimeout = func() time.Duration { return 40 * time.Millisecond }
	preRunTestBehavior = "hang"
	err := preRunBackup("demo", "migrate", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "deadline 40ms exceeded while dumping demo") {
		t.Fatalf("deadline failure missing database and budget: %v", err)
	}
	if files := archiveFiles(t, filepath.Join(preRunBackupRoot, "demo")); len(files) != 0 {
		t.Fatalf("deadline left archive: %v", files)
	}
}

func TestDefaultPreRunCommandKillsGrandchildOnDeadline(t *testing.T) {
	setupPreRunBackupTest(t)
	preRunCommand = defaultPreRunCommand
	preRunExecutable = func(string) string { return os.Args[0] }
	preRunCommandPrefix = func(name string) []string { return []string{"-test.run=TestPreRunCommandProcess", "--", name} }
	preRunCommandEnvironment = func() []string {
		return []string{"SHUTTLE_PRE_RUN_HELPER=1", "SHUTTLE_PRE_RUN_BEHAVIOR=group-parent", "SHUTTLE_PRE_RUN_PID_FILE=" + preRunTestPIDPath}
	}
	preRunCredentialEnabled = func() bool { return false }
	uid, gid := os.Getuid(), os.Getgid()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	preRunPostgresIdentity = func() (int, int, string, error) { return uid, gid, home, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := preRunCommand(ctx, true, "pg_dump", "-Fc", "--no-password", "-d", "demo")
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- command.Run() }()
	var childPID int
	for time.Now().Before(started.Add(4 * time.Second)) {
		body, err := os.ReadFile(preRunTestPIDPath)
		if err == nil {
			childPID, _ = strconv.Atoi(string(body))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		select {
		case err := <-done:
			t.Fatalf("command exited before starting grandchild: %v", err)
		default:
			t.Fatal("grandchild did not start")
		}
	}
	if err := <-done; err == nil {
		t.Fatal("deadline did not cancel pg_dump")
	}
	if elapsed := time.Since(started); elapsed > 6*time.Second {
		t.Fatalf("process group outlived context and WaitDelay: %s", elapsed)
	}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", childPID)); os.IsNotExist(err) {
			return
		}
		if body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", childPID)); err == nil && strings.Contains(string(body), ") Z ") {
			return
		}
	}
	t.Fatalf("grandchild %d survived the process-group cancellation", childPID)
}

func TestPreRunBackupRetentionAndCollision(t *testing.T) {
	t.Run("retention", func(t *testing.T) {
		setupPreRunBackupTest(t)
		dir := filepath.Join(preRunBackupRoot, "demo")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "20200101T000000Z-migrate-demo.dump"), []byte("current"), 0o600); err != nil {
			t.Fatal(err)
		}
		stamps := []string{"20260101T000000Z", "20260201T000000Z", "20260301T000000Z", "20260401T000000Z", "20260501T000000Z", "20260601T000000Z", "20260701T000000Z"}
		for _, stamp := range stamps {
			if err := os.WriteFile(filepath.Join(dir, stamp+"-migrate-demo.dump"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "manual.dump"), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := retainPreRunArchives(dir, "20200101T000000Z"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "20200101T000000Z-migrate-demo.dump")); err != nil {
			t.Fatal("current stamp must remain even when clock is behind")
		}
		if _, err := os.Stat(filepath.Join(dir, "20260101T000000Z-migrate-demo.dump")); !os.IsNotExist(err) {
			t.Fatalf("oldest generation was retained: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "manual.dump")); err != nil {
			t.Fatal("non-matching file was touched")
		}
	})
	t.Run("collision", func(t *testing.T) {
		setupPreRunBackupTest(t)
		dir := filepath.Join(preRunBackupRoot, "demo")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		final := filepath.Join(dir, "20261026T123456Z-migrate-demo.dump")
		if err := os.WriteFile(final, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := preRunBackup("demo", "migrate", io.Discard); err == nil {
			t.Fatal("same-second archive collision was overwritten")
		}
		body, err := os.ReadFile(final)
		if err != nil || string(body) != "existing" {
			t.Fatalf("existing archive changed: %q %v", body, err)
		}
	})
}

func TestDeclaredOperationsRefusesMultipleOperationLabels(t *testing.T) {
	setupPreRunBackupTest(t)
	oldServices, oldLabel := declaredOperationsServices, declaredOperationsLabel
	t.Cleanup(func() { declaredOperationsServices, declaredOperationsLabel = oldServices, oldLabel })
	declaredOperationsServices = func(string) ([]string, error) { return []string{"demo_z", "demo_a"}, nil }
	declaredOperationsLabel = func(string) (string, error) {
		return `{"migrate":{"service":"api","command":["php","migrate"]}}`, nil
	}
	if _, err := declaredOperations("demo"); err == nil || err.Error() != "more than one service of demo declares operations (demo_a, demo_z); only the published service may" {
		t.Fatalf("ambiguous service labels were not refused deterministically: %v", err)
	}
	declaredOperationsLabel = func(service string) (string, error) {
		if service == "demo_z" {
			return "", errors.New("inspect failed")
		}
		return "", nil
	}
	if _, err := declaredOperations("demo"); err == nil || !strings.Contains(err.Error(), "inspect service demo_z") {
		t.Fatalf("inspect failure was hidden: %v", err)
	}
}

func TestPreflightBackupDecisionAndLiveReservation(t *testing.T) {
	setupPreRunBackupTest(t)
	declaredOperationsLookup = func(string) (map[string]declaredOperation, error) {
		return map[string]declaredOperation{"migrate": {Service: "api", Command: []string{"php", "migrate"}, BackupBefore: true}}, nil
	}
	declaredOperationContainer = func(string) (string, error) { return "container-before", nil }
	plan := rootplan.Plan{Action: "run", ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), Run: &rootplan.RunOperation{App: "demo", Operation: "migrate", RequireBackup: true, SkipBackup: true}}
	preRunReservation = func(context.Context, rootplan.Plan) error { return nil }
	var output bytes.Buffer
	if _, _, err := preflightDeclaredOperation(plan, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "backup  skipped by --skip-backup (operation migrate)\n" {
		t.Fatalf("skip line mismatch: %q", output.String())
	}
	preRunReservation = func(context.Context, rootplan.Plan) error { return errors.New("no live reservation") }
	if _, _, err := preflightDeclaredOperation(plan, io.Discard); err == nil || !strings.Contains(err.Error(), "no live reservation") {
		t.Fatalf("missing reservation was accepted: %v", err)
	}
}

func TestPreflightRefusesBackupPolicyMismatches(t *testing.T) {
	for _, test := range []struct {
		name                 string
		require, skip, label bool
		contains             string
	}{
		{name: "skip absent label", require: true, skip: true, contains: "skip_backup was requested"},
		{name: "label not required", label: true, contains: "plan does not require it"},
		{name: "config newer than stack", require: true, contains: "run shuttle deploy first"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setupPreRunBackupTest(t)
			preRunReservation = func(context.Context, rootplan.Plan) error { return nil }
			declaredOperationsLookup = func(string) (map[string]declaredOperation, error) {
				return map[string]declaredOperation{"migrate": {Service: "api", Command: []string{"php", "migrate"}, BackupBefore: test.label}}, nil
			}
			declaredOperationContainer = func(string) (string, error) { return "container", nil }
			plan := rootplan.Plan{Action: "run", ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), Run: &rootplan.RunOperation{App: "demo", Operation: "migrate", RequireBackup: test.require, SkipBackup: test.skip}}
			if _, _, err := preflightDeclaredOperation(plan, io.Discard); err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("policy mismatch not refused: %v", err)
			}
		})
	}
}

func TestRunDeclaredOperationPreflightsBeforeExecAndUsesNewContainer(t *testing.T) {
	for _, behavior := range []string{"success", "fail-dump", "container-gone"} {
		t.Run(behavior, func(t *testing.T) {
			setupPreRunBackupTest(t)
			preRunReservation = func(context.Context, rootplan.Plan) error { return nil }
			rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return nil }
			rootCoordinatedMutationGuard = func(string) error { return nil }
			declaredOperationsLookup = func(string) (map[string]declaredOperation, error) {
				return map[string]declaredOperation{"migrate": {Service: "api", Command: []string{"php", "migrate"}, BackupBefore: true}}, nil
			}
			containerCalls := 0
			declaredOperationContainer = func(string) (string, error) {
				containerCalls++
				if containerCalls == 1 {
					return strings.Repeat("a", 64), nil
				}
				if behavior == "container-gone" {
					return "", errors.New("service has no running task")
				}
				return strings.Repeat("b", 64), nil
			}
			var events []string
			declaredOperationExec = func(container string, command []string, _ io.Writer) error {
				events = append(events, "exec:"+container)
				if len(archiveFiles(t, filepath.Join(preRunBackupRoot, "demo"))) == 0 {
					t.Error("exec began before a verified archive existed")
				}
				return nil
			}
			if behavior == "fail-dump" {
				preRunTestBehavior = "fail-dump"
			}
			root := t.TempDir()
			c := coord.New(coord.Options{Root: filepath.Join(root, "records"), LockPath: filepath.Join(root, "root.lock"), BootID: func() (string, error) { return "boot-a", nil }})
			owner, host := "SHA256:"+strings.Repeat("a", 43), "SHA256:"+strings.Repeat("b", 43)
			h, err := c.Reserve(context.Background(), coord.Request{Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
			if err != nil {
				t.Fatal(err)
			}
			rootOperationCoordinator = func() *coord.Coordinator { return c }
			plan := rootplan.Plan{Action: "run", OperationID: h.ID(), OperationKind: "run", OperationApp: "demo", OperatorUser: "deploy", OperatorKeyFingerprint: owner, RequiredHostFingerprint: host, ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), Run: &rootplan.RunOperation{App: "demo", Operation: "migrate", RequireBackup: true}}
			var stderr bytes.Buffer
			oldStderr := os.Stderr
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stderr = writer
			result := runDeclaredOperationForPlan(plan, io.Discard)
			writer.Close()
			os.Stderr = oldStderr
			marker, _ := io.ReadAll(reader)
			reader.Close()
			stderr.Write(marker)
			if behavior == "success" {
				if result != nil {
					t.Fatal(result)
				}
				if len(events) != 1 || events[0] != "exec:"+strings.Repeat("b", 64) {
					t.Fatalf("exec did not target post-backup container: %v", events)
				}
				body, err := os.ReadFile(filepath.Join(c.Root(), h.ID()+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(body, &fields); err != nil {
					t.Fatal(err)
				}
				wantFields := []string{"schema", "id", "revision", "kind", "scope", "app", "principal", "owner_key_fingerprint", "host", "host_boot_id", "started_at", "updated_at", "lease_until", "state", "recovery_required", "phases", "run_target", "recovery_observation", "events"}
				if len(fields) != len(wantFields) {
					t.Fatalf("successful run journal keys changed: %v", fields)
				}
				for _, key := range wantFields {
					if fields[key] == nil {
						t.Fatalf("successful run journal is missing %q: %v", key, fields)
					}
				}
				var phaseFields []map[string]json.RawMessage
				if err := json.Unmarshal(fields["phases"], &phaseFields); err != nil {
					t.Fatal(err)
				}
				if len(phaseFields) != 1 || len(phaseFields[0]) != 4 || phaseFields[0]["known"] != nil {
					t.Fatalf("successful run phase added a known field: %s", body)
				}
				var target map[string]string
				if err := json.Unmarshal(fields["run_target"], &target); err != nil || len(target) != 2 || target["service"] != "api" || target["container"] != strings.Repeat("b", 64) {
					t.Fatalf("successful run target was not journaled: %s (%v)", fields["run_target"], err)
				}
			} else {
				if result == nil {
					t.Fatal("pre-flight failure was ignored")
				}
				if len(events) != 0 {
					t.Fatalf("failed pre-flight reached exec: %v", events)
				}
				if !strings.Contains(stderr.String(), rootPreflightRefusalMarker) {
					t.Fatalf("pre-flight refusal marker missing: %s", stderr.String())
				}
			}
		})
	}
}

// TestRunPhaseBoundaryDecidesRefusalMarker pins the line between a safe
// refusal and mandatory recovery. The marker lets the client end the operation
// as failed without recovery_required, so it may only appear when no phase was
// appended for the run: a coordinator rejection before phase entry, or a plan too
// short to finish the pre-flight. Once ExecutePhase has appended the run phase,
// a failure is a mutation boundary and must abort into recovery as before.
func TestRunPhaseBoundaryDecidesRefusalMarker(t *testing.T) {
	for _, tc := range []struct {
		name        string
		validity    time.Duration
		identityErr error
		guardErr    error
		wantMarker  bool
		wantPhase   bool
		wantArchive bool
	}{
		{name: "rejected-before-phase", validity: 15 * time.Minute, identityErr: errors.New("identity drifted"), wantMarker: true, wantArchive: true},
		{name: "failed-after-phase-start", validity: 15 * time.Minute, guardErr: errors.New("helper migration in progress"), wantPhase: true, wantArchive: true},
		{name: "short-validity", validity: 5 * time.Minute, wantMarker: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupPreRunBackupTest(t)
			preRunReservation = func(context.Context, rootplan.Plan) error { return nil }
			rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return tc.identityErr }
			rootCoordinatedMutationGuard = func(string) error { return tc.guardErr }
			declaredOperationsLookup = func(string) (map[string]declaredOperation, error) {
				return map[string]declaredOperation{"migrate": {Service: "api", Command: []string{"php", "migrate"}, BackupBefore: true}}, nil
			}
			declaredOperationContainer = func(string) (string, error) { return strings.Repeat("c", 64), nil }
			execCalls := 0
			declaredOperationExec = func(string, []string, io.Writer) error {
				execCalls++
				return nil
			}
			root := t.TempDir()
			c := coord.New(coord.Options{Root: filepath.Join(root, "records"), LockPath: filepath.Join(root, "root.lock"), BootID: func() (string, error) { return "boot-a", nil }})
			owner, host := "SHA256:"+strings.Repeat("a", 43), "SHA256:"+strings.Repeat("b", 43)
			h, err := c.Reserve(context.Background(), coord.Request{Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
			if err != nil {
				t.Fatal(err)
			}
			rootOperationCoordinator = func() *coord.Coordinator { return c }
			plan := rootplan.Plan{Action: "run", OperationID: h.ID(), OperationKind: "run", OperationApp: "demo", OperatorUser: "deploy", OperatorKeyFingerprint: owner, RequiredHostFingerprint: host, ExpiresAt: time.Now().Add(tc.validity).UTC().Format(time.RFC3339), Run: &rootplan.RunOperation{App: "demo", Operation: "migrate", RequireBackup: true}}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			oldStderr := os.Stderr
			os.Stderr = writer
			result := runDeclaredOperationForPlan(plan, io.Discard)
			writer.Close()
			os.Stderr = oldStderr
			stderr, _ := io.ReadAll(reader)
			reader.Close()
			if result == nil {
				t.Fatal("failure was reported as success")
			}
			if execCalls != 0 {
				t.Fatalf("declared command ran %d times", execCalls)
			}
			if got := strings.Contains(string(stderr), rootPreflightRefusalMarker); got != tc.wantMarker {
				t.Fatalf("refusal marker present=%v, want %v; stderr=%q", got, tc.wantMarker, stderr)
			}
			record, err := c.Get(context.Background(), h.ID())
			if err != nil {
				t.Fatal(err)
			}
			hasRunPhase := false
			for _, phase := range record.Phases {
				if phase.Name == "run" {
					hasRunPhase = true
				}
			}
			if hasRunPhase != tc.wantPhase {
				t.Fatalf("run phase present=%v, want %v: %+v", hasRunPhase, tc.wantPhase, record.Phases)
			}
			if tc.wantPhase && !record.RecoveryRequired {
				t.Fatalf("failure after phase entry did not require recovery: %+v", record)
			}
			if !tc.wantPhase && record.RecoveryRequired {
				t.Fatalf("refusal before phase entry required recovery: %+v", record)
			}
			archived := false
			if _, statErr := os.Stat(filepath.Join(preRunBackupRoot, "demo")); statErr == nil {
				archived = len(archiveFiles(t, filepath.Join(preRunBackupRoot, "demo"))) > 0
			}
			if archived != tc.wantArchive {
				t.Fatalf("archive present=%v, want %v", archived, tc.wantArchive)
			}
		})
	}
}

func TestRunKnownOutcomeMarkerAndUnknownFailure(t *testing.T) {
	for _, known := range []bool{true, false} {
		t.Run(map[bool]string{true: "known", false: "unknown"}[known], func(t *testing.T) {
			setupPreRunBackupTest(t)
			preRunReservation = func(context.Context, rootplan.Plan) error { return nil }
			preRunVerifyIdentity = func(rootplan.Plan) error { return nil }
			preRunMutationGuard = func(string) error { return nil }
			rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { return nil }
			rootCoordinatedMutationGuard = func(string) error { return nil }
			declaredOperationsLookup = func(string) (map[string]declaredOperation, error) {
				return map[string]declaredOperation{"fail": {Service: "api", Command: []string{"node", "-e", "process.exit(3)"}}}, nil
			}
			container := strings.Repeat("d", 64)
			declaredOperationContainer = func(string) (string, error) { return container, nil }
			execCalls := 0
			declaredOperationExec = func(string, []string, io.Writer) error {
				execCalls++
				if known {
					return coord.KnownOutcome(errors.New("exit status 3"))
				}
				return errors.New("Docker request was interrupted")
			}
			root := t.TempDir()
			c := coord.New(coord.Options{Root: filepath.Join(root, "records"), LockPath: filepath.Join(root, "root.lock"), BootID: func() (string, error) { return "boot-a", nil }})
			owner, host := "SHA256:"+strings.Repeat("a", 43), "SHA256:"+strings.Repeat("b", 43)
			h, err := c.Reserve(context.Background(), coord.Request{Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
			if err != nil {
				t.Fatal(err)
			}
			rootOperationCoordinator = func() *coord.Coordinator { return c }
			plan := rootplan.Plan{Action: "run", OperationID: h.ID(), OperationKind: "run", OperationApp: "demo", OperatorUser: "deploy", OperatorKeyFingerprint: owner, RequiredHostFingerprint: host, ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), Run: &rootplan.RunOperation{App: "demo", Operation: "fail"}}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			oldStderr := os.Stderr
			os.Stderr = writer
			result := runDeclaredOperationForPlan(plan, io.Discard)
			writer.Close()
			os.Stderr = oldStderr
			stderr, _ := io.ReadAll(reader)
			reader.Close()
			if result == nil || execCalls != 1 {
				t.Fatalf("run result=%v exec calls=%d", result, execCalls)
			}
			record, err := c.Get(context.Background(), h.ID())
			if err != nil {
				t.Fatal(err)
			}
			if known {
				if !strings.Contains(result.Error(), "exit status 3") || !strings.Contains(string(stderr), rootKnownOutcomeMarker) || record.State != "active" || record.RecoveryRequired || !record.Phases[len(record.Phases)-1].Known {
					t.Fatalf("known command failure was not qualified: error=%v stderr=%q record=%+v", result, stderr, record)
				}
			} else if strings.Contains(string(stderr), rootKnownOutcomeMarker) || record.State != coord.RecoveryRequired || !record.RecoveryRequired || record.Phases[len(record.Phases)-1].Known {
				t.Fatalf("unknown command failure was qualified: stderr=%q record=%+v", stderr, record)
			}
		})
	}
}

func TestKnownOutcomeMarkerBoundsClientControlResult(t *testing.T) {
	reason := strings.Repeat("failure", 400)
	cleaned := cleanRootKnownOutcomeReason(reason)
	marker := rootKnownOutcomeMarker + cleaned
	control := rootKnownOutcomeControlPrefix + cleaned
	if len(marker) > 512 || len(control) > 512 {
		t.Fatalf("known outcome exceeds protocol limit: marker=%d control=%d", len(marker), len(control))
	}
	parsed, ok := knownRunOutcomeReason(marker)
	if !ok || parsed != cleaned {
		t.Fatalf("known outcome marker did not round-trip: %v %q", ok, parsed)
	}
}

func TestPreflightRefusalMarkerIsBoundedSingleLineAndAcceptedByPlan(t *testing.T) {
	setupPreRunBackupTest(t)
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	refusal := emitPreflightRefusal(errors.New(strings.Repeat("bad dump\n", 200)))
	writer.Close()
	os.Stderr = oldStderr
	marker, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.TrimSuffix(marker, []byte("\n"))
	if len(line) == 0 || len(line) > 512 || bytes.ContainsAny(line, "\r\n\x00") {
		t.Fatalf("marker is not bounded single-line: len=%d %q", len(marker), marker)
	}
	reason, ok := refusedBeforeMutationReason(string(marker))
	if !ok {
		t.Fatal("client did not recognize refusal marker")
	}
	result := rootRefusalControlPrefix + reason
	if len(result) > 512 || strings.ContainsAny(result, "\r\n\x00") {
		t.Fatalf("control result invalid: %d %q", len(result), result)
	}
	plan, err := rootplan.NewOperationControl("operation-refuse", strings.Repeat("a", 32), "run", "demo", result, "SHA256:"+strings.Repeat("a", 43), "SHA256:"+strings.Repeat("b", 43), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Control == nil || plan.Control.Result != result {
		t.Fatalf("operation-refuse plan lost result: %+v", plan.Control)
	}
	var refusalError *rootPreflightRefusal
	if !errors.As(refusal, &refusalError) {
		t.Fatalf("wrong error type %T", refusal)
	}
}
