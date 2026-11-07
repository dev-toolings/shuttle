//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestRunClientWriterDoesNotExecuteTargetBeforeAdmission(t *testing.T) {
	operation := testClientWriterOperation(t)
	dir := t.TempDir()
	sent := filepath.Join(dir, "ran")
	var fence func(operationwriters.Binding) (operationwriters.Receipt, error)
	swapClientOriginAdmission(t, func(_ *remoteOperation, writer operationwriters.Writer, next func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
		if err := writer.Validate(); err != nil {
			t.Fatalf("registered writer is invalid: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
		if _, err := os.Stat(sent); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("target ran before admission: %v", err)
		}
		fence = next
		return nil
	})
	cmd := exec.Command("/bin/sh", "-c", `printf ran > "$1"`, "probe", sent)
	if err := runClientWriter(operation, cmd); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sent); err != nil {
		t.Fatalf("admitted target did not run: %v", err)
	}
	if fence == nil {
		t.Fatal("admission did not retain a fence callback")
	}
	receipt, err := fence(testClientWriterBinding())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Kind != operationwriters.WriterKindClientOrigin || receipt.Client == nil || !receipt.ResourcesClosed {
		t.Fatalf("unexpected client origin receipt: %+v", receipt)
	}
}

func TestRunClientWriterRefusalNeverStartsTarget(t *testing.T) {
	operation := testClientWriterOperation(t)
	dir := t.TempDir()
	sent := filepath.Join(dir, "ran")
	swapClientOriginAdmission(t, func(_ *remoteOperation, _ operationwriters.Writer, _ func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
		time.Sleep(150 * time.Millisecond)
		if _, err := os.Stat(sent); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("target ran despite registration refusal: %v", err)
		}
		return errors.New("registration refused")
	})
	cmd := exec.Command("/bin/sh", "-c", `printf ran > "$1"`, "probe", sent)
	if err := runClientWriter(operation, cmd); err == nil {
		t.Fatal("refused registration started the target")
	}
	if _, err := os.Stat(sent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused target executed")
	}
}

func TestRunClientWriterCancellationNeverStartsTarget(t *testing.T) {
	operation := testClientWriterOperation(t)
	dir := t.TempDir()
	sent := filepath.Join(dir, "ran")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	release := make(chan struct{})
	swapClientOriginAdmission(t, func(_ *remoteOperation, _ operationwriters.Writer, _ func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
		close(ready)
		<-release
		return errors.New("cancelled during registration")
	})
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `printf ran > "$1"`, "probe", sent)
	go func() {
		<-ready
		cancel()
		close(release)
	}()
	if err := runClientWriter(operation, cmd); err == nil {
		t.Fatal("cancelled admission started the target")
	}
	if _, err := os.Stat(sent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled target executed")
	}
}

func TestRunClientWriterFenceDoesNotKillUnrelatedProcess(t *testing.T) {
	if fd, err := unix.PidfdOpen(os.Getpid(), 0); err != nil {
		t.Skip(err)
	} else {
		_ = unix.Close(fd)
	}
	operation := testClientWriterOperation(t)
	other := exec.Command("sleep", "30")
	other.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = other.Process.Kill()
		_ = other.Wait()
	}()
	otherIdentity, err := readClientProcIdentity(other.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	var registered operationwriters.Writer
	var fence func(operationwriters.Binding) (operationwriters.Receipt, error)
	swapClientOriginAdmission(t, func(_ *remoteOperation, writer operationwriters.Writer, next func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
		registered = writer
		fence = next
		return nil
	})
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 &")
	if err := runClientWriter(operation, cmd); err != nil {
		t.Fatal(err)
	}
	if registered.Client == nil || fence == nil {
		t.Fatal("admission did not retain the observed group")
	}
	if _, err := fence(testClientWriterBinding()); err != nil {
		t.Fatal(err)
	}
	current, err := readClientProcIdentity(otherIdentity.PID)
	if err != nil {
		t.Fatalf("fencing the client origin group affected an unrelated process: %v", err)
	}
	if current.StartTicks != otherIdentity.StartTicks {
		t.Fatalf("unrelated process identity changed: %+v", current)
	}
	live, err := liveClientWriterMembers(context.Background(), registered.Client.Group)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Fatalf("fenced group still has members: %+v", live)
	}
}

func testClientWriterOperation(t *testing.T) *remoteOperation {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.NewSignerFromKey(key); err != nil {
		t.Fatal(err)
	}
	return &remoteOperation{key: key, id: testClientWriterBinding().OperationID, kind: "deploy", app: "demo", identity: trustedHostIdentity{HostKeyFingerprint: testClientWriterBinding().HostKey}}
}

func testClientWriterBinding() operationwriters.Binding {
	return operationwriters.Binding{
		OperationID: "01234567-89ab-cdef-0123-456789abcdef",
		Generation:  1,
		HostKey:     "SHA256:" + "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 43 base64 chars
		BootID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
}

func swapClientOriginAdmission(t *testing.T, next clientOriginAdmission) {
	t.Helper()
	previous := registerClientOriginWriter
	registerClientOriginWriter = next
	t.Cleanup(func() { registerClientOriginWriter = previous })
}

func TestRunClientWriterPreservesDirectoryEnvironmentOutputAndExit(t *testing.T) {
	operation := testClientWriterOperation(t)
	swapClientOriginAdmission(t, func(_ *remoteOperation, _ operationwriters.Writer, _ func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
		return nil
	})
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "target.sh"), []byte("#!/bin/sh\nprintf '%s:%s' \"$SHUTTLE_WRITER_TEST\" \"$PWD\"\nprintf failure >&2\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("./target.sh")
	command.Dir = directory
	command.Env = append(os.Environ(), "SHUTTLE_WRITER_TEST=kept")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := runClientWriter(operation, command)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("exit status lost: %v", err)
	}
	if stdout.String() != "kept:"+directory || stderr.String() != "failure" {
		t.Fatalf("streams/env/dir lost: %q %q", stdout.String(), stderr.String())
	}
	if command.ProcessState == nil || command.ProcessState.ExitCode() != 7 {
		t.Fatal("original Cmd state was not retained")
	}
}

func TestRunClientWriterCancellationAndSignalFenceRunningGroup(t *testing.T) {
	for _, mode := range []string{"context", "signal"} {
		t.Run(mode, func(t *testing.T) {
			operation := testClientWriterOperation(t)
			var registered operationwriters.Writer
			swapClientOriginAdmission(t, func(_ *remoteOperation, w operationwriters.Writer, _ func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
				registered = w
				return nil
			})
			started := filepath.Join(t.TempDir(), "started")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/sh", "-c", `printf started > "$1"; sleep 30`, "probe", started)
			done := make(chan error, 1)
			go func() { done <- runClientWriter(operation, command) }()
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, err := os.Stat(started); err == nil {
					break
				}
				if time.Now().After(deadline) {
					cancel()
					t.Fatal("target did not start")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if mode == "context" {
				cancel()
			} else if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("interrupted command reported success")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("interrupted command was not fenced")
			}
			if registered.Client == nil {
				t.Fatal("missing group identity")
			}
			live, err := liveClientWriterMembers(context.Background(), registered.Client.Group)
			if err != nil {
				t.Fatal(err)
			}
			if len(live) > 0 {
				t.Fatalf("live writers survived interruption: %+v", live)
			}
		})
	}
}

func TestRunClientWriterFenceRefusesDifferentBinding(t *testing.T) {
	operation := testClientWriterOperation(t)
	var fence func(operationwriters.Binding) (operationwriters.Receipt, error)
	swapClientOriginAdmission(t, func(_ *remoteOperation, _ operationwriters.Writer, f func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
		fence = f
		return nil
	})
	if err := runClientWriter(operation, exec.Command("/bin/true")); err != nil {
		t.Fatal(err)
	}
	binding := testClientWriterBinding()
	binding.OperationID = strings.Repeat("d", 32)
	if _, err := fence(binding); err == nil {
		t.Fatal("another operation received closure proof")
	}
}

func TestCloseRecordedClientWriterSignsExitedGroupAgainstVPSBinding(t *testing.T) {
	if fd, err := unix.PidfdOpen(os.Getpid(), 0); err != nil {
		t.Skip(err)
	} else {
		_ = unix.Close(fd)
	}
	operation := testClientWriterOperation(t)
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	identity, err := readClientProcIdentity(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if identity.PGID != identity.PID || identity.SID != identity.PID {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Skipf("test process did not become its own session and group: %+v", identity)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	machineID, bootID, err := readClientOriginHost()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(operation.key)
	if err != nil {
		t.Fatal(err)
	}
	origin := operationwriters.ClientOrigin{
		MachineID:      machineID,
		BootID:         bootID,
		KeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		RunToken:       "recorded-client-token",
		Group:          operationwriters.LocalGroup{LeaderPID: identity.PID, LeaderStartTicks: identity.StartTicks, PGID: identity.PGID, SID: identity.SID},
	}
	writer := operationwriters.Writer{ID: "client-origin:recorded-client-token", Kind: operationwriters.WriterKindClientOrigin, Client: &origin}
	binding := testClientWriterBinding()
	receipt, err := closeRecordedClientWriter(operation, writer, binding)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Kind != operationwriters.WriterKindClientOrigin || receipt.Client == nil || !receipt.ResourcesClosed || !receipt.AdmissionsClosed {
		t.Fatalf("unexpected recorded client receipt: %+v", receipt)
	}
	if receipt.Client.Origin != origin {
		t.Fatalf("signed origin diverged: %+v", receipt.Client.Origin)
	}
	if receipt.Client.Binding != binding {
		t.Fatalf("receipt bound the kernel boot instead of the VPS operation: %+v", receipt.Client.Binding)
	}
	if receipt.Client.Binding.BootID == origin.BootID && binding.BootID != origin.BootID {
		t.Fatal("client boot leaked into the VPS binding")
	}
	if receipt.Client.Origin.BootID != bootID {
		t.Fatalf("client origin boot was not retained: %s", receipt.Client.Origin.BootID)
	}
	if len(receipt.Client.Signature) == 0 || receipt.Client.SignatureFormat == "" {
		t.Fatal("recorded client receipt was not signed")
	}
}

func TestCloseRecordedClientWriterClosesWriterOfEndedBoot(t *testing.T) {
	operation := testClientWriterOperation(t)
	machineID, bootID, err := readClientOriginHost()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(operation.key)
	if err != nil {
		t.Fatal(err)
	}
	// The recorded PID is this test's own: a fence that probed or signaled it
	// would kill the test, which is exactly what an ended boot must never do.
	self := os.Getpid()
	origin := operationwriters.ClientOrigin{
		MachineID:      machineID,
		BootID:         "00000000-0000-0000-0000-000000000000",
		KeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		RunToken:       "previous-boot-token",
		Group:          operationwriters.LocalGroup{LeaderPID: self, LeaderStartTicks: 1, PGID: self, SID: self},
	}
	if origin.BootID == bootID {
		t.Skip("current boot id collides with the fixture")
	}
	writer := operationwriters.Writer{ID: "client-origin:previous-boot-token", Kind: operationwriters.WriterKindClientOrigin, Client: &origin}
	receipt, err := closeRecordedClientWriter(operation, writer, testClientWriterBinding())
	if err != nil {
		t.Fatalf("writer of an ended boot was not closed: %v", err)
	}
	if receipt.Client == nil || !receipt.ResourcesClosed || !receipt.AdmissionsClosed || len(receipt.Client.Local.ObservedMembers) != 0 {
		t.Fatalf("unexpected ended-boot receipt: %+v", receipt)
	}
	if receipt.Client.Origin.BootID != origin.BootID {
		t.Fatalf("ended boot was not retained in the signed origin: %s", receipt.Client.Origin.BootID)
	}
}

func TestCloseRecordedClientWriterRefusesForeignIdentity(t *testing.T) {
	operation := testClientWriterOperation(t)
	machineID, bootID, err := readClientOriginHost()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(operation.key)
	if err != nil {
		t.Fatal(err)
	}
	origin := operationwriters.ClientOrigin{
		MachineID:      machineID,
		BootID:         bootID,
		KeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		RunToken:       "recorded-client-token",
		Group:          operationwriters.LocalGroup{LeaderPID: 4242, LeaderStartTicks: 9001, PGID: 4242, SID: 4242},
	}
	writer := operationwriters.Writer{ID: "client-origin:recorded-client-token", Kind: operationwriters.WriterKindClientOrigin, Client: &origin}
	binding := testClientWriterBinding()
	foreign := binding
	foreign.OperationID = "01234567-89ab-cdef-0123-456789abcdee"
	if _, err := closeRecordedClientWriter(operation, writer, foreign); err == nil {
		t.Fatal("another operation received a recorded client receipt")
	}
	// Fresh values rather than struct copies: remoteOperation holds a mutex.
	wrongHost := remoteOperation{id: operation.id, kind: operation.kind, app: operation.app, identity: operation.identity, key: operation.key}
	wrongHost.identity.HostKeyFingerprint = "SHA256:" + strings.Repeat("Z", 43)
	if _, err := closeRecordedClientWriter(&wrongHost, writer, binding); err == nil {
		t.Fatal("another VPS host received a recorded client receipt")
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := remoteOperation{id: operation.id, kind: operation.kind, app: operation.app, identity: operation.identity, key: otherKey}
	if _, err := closeRecordedClientWriter(&wrongKey, writer, binding); err == nil {
		t.Fatal("another operator key received a recorded client receipt")
	}
	wrongMachine := origin
	wrongMachine.MachineID = "other-machine"
	wrongWriter := writer
	wrongWriter.Client = &wrongMachine
	if _, err := closeRecordedClientWriter(operation, wrongWriter, binding); err == nil {
		t.Fatal("another machine identity received a recorded client receipt")
	}
	if _, err := closeRecordedClientWriter(operation, operationwriters.Writer{ID: "ssh-build-runner", Kind: operationwriters.WriterKindRemoteRunner, Remote: &operationwriters.RemoteRunner{HostKey: binding.HostKey, RunToken: "aabbccdd1122334455667788"}}, binding); err == nil {
		t.Fatal("SSH runner was closed as a client origin writer")
	}
}
