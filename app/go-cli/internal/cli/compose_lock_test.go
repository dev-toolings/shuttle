package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestComposeLockExcludesConcurrentRetention(t *testing.T) {
	root := t.TempDir()
	first := composeLockAcquireCommand(root, "first", "operator", "deploy")
	second := composeLockAcquireCommand(root, "second", "operator", "deploy")
	for _, script := range []string{first, second, composeLockReleaseCommand(root, "first")} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v: %s", err, out)
		}
	}
	if out, err := exec.Command("sh", "-c", first).CombinedOutput(); err != nil {
		t.Fatalf("first lock: %v: %s", err, out)
	}
	preparing := filepath.Join(root, "preparing")
	if err := os.Mkdir(preparing, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "active"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("active", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	// A second deploy must fail before it can run the same directory phase that
	// deleted a concurrent preparation on the base commit.
	retention := strings.Split(composeRetainCommand(root, "example"), "docker images")[0]
	out, err := exec.Command("sh", "-c", second+"\n"+retention).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "attempt=first") || !strings.Contains(string(out), "age_seconds=") {
		t.Fatalf("second lock: %v: %s", err, out)
	}
	if _, err := os.Stat(preparing); err != nil {
		t.Fatalf("retention removed concurrent preparation: %v", err)
	}
}

func TestComposeLockReleaseChecksOwner(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("sh", "-c", composeLockAcquireCommand(root, "first", "operator", "rollback")).CombinedOutput(); err != nil {
		t.Fatalf("acquire: %v: %s", err, out)
	}
	if err := exec.Command("sh", "-c", composeLockReleaseCommand(root, "other")).Run(); err == nil {
		t.Fatal("wrong owner removed lock")
	}
	if out, err := exec.Command("sh", "-c", composeLockReleaseCommand(root, "first")).CombinedOutput(); err != nil {
		t.Fatalf("release: %v: %s", err, out)
	}
	if out, err := exec.Command("sh", "-c", composeLockAcquireCommand(root, "next", "operator", "destroy")).CombinedOutput(); err != nil {
		t.Fatalf("reacquire: %v: %s", err, out)
	}
}

func TestComposeUnknownOutcomeRetainsLock(t *testing.T) {
	h := composeHost{lock: &composeLock{id: "test"}}
	h.observe(ssh.Result{Code: 1, OutcomeUnknown: true})
	if err := h.releaseLock(); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("release: %v", err)
	}
}

func TestComposeRetentionRequiresLockOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "preparing"), 0700); err != nil {
		t.Fatal(err)
	}
	script := composeLockedRetentionCommand(root, "example", "first")
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v: %s", err, out)
	}
	if err := exec.Command("sh", "-c", script).Run(); err == nil {
		t.Fatal("retention ran without a lock")
	}
	if _, err := os.Stat(filepath.Join(root, "preparing")); err != nil {
		t.Fatalf("preparing release removed: %v", err)
	}
}

func TestComposeRetentionKeepsNewerPreparation(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("sh", "-c", composeLockAcquireCommand(root, "first", "operator", "deploy")).CombinedOutput(); err != nil {
		t.Fatalf("acquire: %v: %s", err, out)
	}
	preparing := filepath.Join(root, "preparing")
	if err := os.Mkdir(preparing, 0700); err != nil {
		t.Fatal(err)
	}
	earlier := time.Now().Add(-time.Minute)
	if err := os.Chtimes(filepath.Join(root, ".lock"), earlier, earlier); err != nil {
		t.Fatal(err)
	}
	script := strings.Split(composeLockedRetentionCommand(root, "example", "first"), "docker images")[0]
	if out, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("retention directory phase: %v: %s", err, out)
	}
	if _, err := os.Stat(preparing); err != nil {
		t.Fatalf("newer preparation removed: %v", err)
	}
}

func TestComposeBreakLockRequiresDisplayedAttempt(t *testing.T) {
	cfg := composeTestConfig(t)
	host := composeHost{cfg: cfg, home: t.TempDir(), user: "operator", client: &ssh.Client{}}
	id := strings.Repeat("a", 32)
	if out, err := exec.Command("sh", "-c", composeLockAcquireCommand(host.releaseRoot(), id, "operator", "deploy")).CombinedOutput(); err != nil {
		t.Fatalf("acquire: %v: %s", err, out)
	}
	oldConnector, oldRunner := composeHostConnector, composeRemoteRunner
	t.Cleanup(func() { composeHostConnector, composeRemoteRunner = oldConnector, oldRunner })
	composeHostConnector = func(*config.Config) (composeHost, error) { return host, nil }
	composeRemoteRunner = func(_ *ssh.Client, command string) ssh.Result {
		cmd := exec.Command("sh", "-c", command)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			code = 1
		}
		return ssh.Result{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	}
	var out bytes.Buffer
	if err := composeBreakLock(cfg, strings.NewReader("no\n"), &out); err == nil {
		t.Fatal("unconfirmed break succeeded")
	}
	if !strings.Contains(out.String(), "attempt="+id) || !strings.Contains(out.String(), "command=deploy") {
		t.Fatalf("holder not displayed: %s", out.String())
	}
	if _, err := os.Stat(composeLockDir(host.releaseRoot())); err != nil {
		t.Fatalf("unconfirmed break removed lock: %v", err)
	}
	out.Reset()
	if err := composeBreakLock(cfg, strings.NewReader(id+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(composeLockDir(host.releaseRoot())); !os.IsNotExist(err) {
		t.Fatalf("confirmed lock remains: %v", err)
	}
}

func TestComposeRollbackAndDestroyRefuseExistingLock(t *testing.T) {
	cfg := composeTestConfig(t)
	host := composeHost{cfg: cfg, home: t.TempDir(), user: "operator", client: &ssh.Client{}}
	if out, err := exec.Command("sh", "-c", composeLockAcquireCommand(host.releaseRoot(), "first", "operator", "deploy")).CombinedOutput(); err != nil {
		t.Fatalf("acquire: %v: %s", err, out)
	}
	oldConnector, oldRunner := composeHostConnector, composeRemoteRunner
	t.Cleanup(func() { composeHostConnector, composeRemoteRunner = oldConnector, oldRunner })
	composeHostConnector = func(*config.Config) (composeHost, error) { return host, nil }
	composeRemoteRunner = func(_ *ssh.Client, command string) ssh.Result {
		cmd := exec.Command("sh", "-c", command)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			code = 1
		}
		return ssh.Result{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	}
	for name, operation := range map[string]func() error{"rollback": func() error { return composeRollback(cfg, false) }, "destroy": func() error { return composeDestroy(cfg, false) }} {
		if err := operation(); err == nil || !strings.Contains(err.Error(), "attempt=first") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestComposeLockInterruptedCreationHasCompleteMetadata(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	// Stop immediately before publication, as a lost SSH session can.
	script := "#!/bin/sh\nkill -KILL \"$PPID\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "ln"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", composeLockAcquireCommand(root, strings.Repeat("a", 32), "operator", "deploy"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	if err := cmd.Run(); err == nil {
		t.Fatal("expected interrupted creation")
	}
	lock := composeLockDir(root)
	if _, err := os.Stat(lock); os.IsNotExist(err) {
		return
	} else if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(lock)
	if err != nil || !strings.Contains(string(data), "holder=operator") || !strings.Contains(string(data), "started=") {
		t.Fatalf("published lock incomplete: %q %v", data, err)
	}
}

func TestComposeLockConcurrentPublicationHasOneWinner(t *testing.T) {
	root := t.TempDir()
	const count = 12
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%032x", i)
		go func() {
			results <- exec.Command("sh", "-c", composeLockAcquireCommand(root, id, "operator", "deploy")).Run()
		}()
	}
	successes := 0
	for i := 0; i < count; i++ {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("%d simultaneous reservations succeeded, want one", successes)
	}
	data, err := os.ReadFile(filepath.Join(root, ".lock"))
	if err != nil || !strings.Contains(string(data), "holder=operator") || !strings.Contains(string(data), "started=") {
		t.Fatalf("published lock incomplete: %q %v", data, err)
	}
}

func TestComposeLockInterruptedAfterPublicationIsReadable(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	script := "#!/bin/sh\n/bin/ln \"$@\" || exit $?\nkill -KILL \"$PPID\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ln"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	cmd := exec.Command("sh", "-c", composeLockAcquireCommand(root, id, "operator", "deploy"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	if err := cmd.Run(); err == nil {
		t.Fatal("expected interrupted publication")
	}
	holder, err := os.ReadFile(filepath.Join(root, ".lock"))
	if err != nil || !strings.Contains(string(holder), "attempt="+id) || !strings.Contains(string(holder), "started=") {
		t.Fatalf("holder=%q err=%v", holder, err)
	}
}

func TestComposeLockIsCompleteRegularFile(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 32)
	if out, err := exec.Command("sh", "-c", composeLockAcquireCommand(root, id, "operator", "deploy")).CombinedOutput(); err != nil {
		t.Fatalf("acquire: %v: %s", err, out)
	}
	lock := composeLockDir(root)
	info, err := os.Stat(lock)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("lock must be a regular file: %v, %v", info, err)
	}
	contents, err := os.ReadFile(lock)
	if err != nil || !strings.Contains(string(contents), "attempt="+id) || !strings.Contains(string(contents), "started=") || !strings.Contains(string(contents), "holder=operator") {
		t.Fatalf("lock contents=%q: %v", contents, err)
	}
}

func TestComposeLockLinkFailureWithoutHolderReportsPublicationError(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	// Inject a link failure with no existing lock to exercise the error branch.
	if err := os.WriteFile(filepath.Join(bin, "ln"), []byte("#!/bin/sh\necho arbitrary-diagnostic >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", composeLockAcquireCommand(root, "first", "operator", "deploy"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "could not be published") || strings.Contains(string(out), "project is locked") {
		t.Fatalf("result: %v: %s", err, out)
	}
}
