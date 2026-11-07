//go:build linux

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const (
	clientWriterMachinePath = "/etc/machine-id"
	clientWriterBootPath    = "/proc/sys/kernel/random/boot_id"
	clientWriterProcRoot    = "/proc"
)

type clientOriginRun struct {
	writer      operationwriters.Writer
	origin      operationwriters.ClientOrigin
	group       operationwriters.LocalGroup
	signer      ssh.Signer
	operationID string
	hostKey     string
}

func runClientWriterShim() int {
	if len(os.Args) < 3 {
		return 2
	}
	release := os.NewFile(uintptr(clientWriterReleaseFD), "admission-release")
	if release == nil {
		return 2
	}
	buf := make([]byte, 1)
	n, err := release.Read(buf)
	closeErr := release.Close()
	if n != 1 || err != nil || closeErr != nil {
		// No release byte means admission failed or the parent died. Exit
		// without exec so docker/build/push cannot run even once.
		return 1
	}
	path := os.Args[2]
	args := os.Args[3:]
	if len(args) == 0 {
		args = []string{path}
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		return 127
	}
	return 127
}

func runClientWriterOnPlatform(operation *remoteOperation, command *exec.Cmd) error {
	signer, err := ssh.NewSignerFromKey(operation.key)
	if err != nil {
		return fmt.Errorf("client origin signer: %w", err)
	}
	machineID, bootID, err := readClientOriginHost()
	if err != nil {
		return err
	}
	path, args, err := resolveClientWriterTarget(command)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	token, err := newClientWriterRunToken()
	if err != nil {
		return err
	}
	releaseR, releaseW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer releaseR.Close()
	defer releaseW.Close()
	// Reuse the original Cmd: its private CommandContext state stays with the
	// standard library. Cancel only notifies our owner, which fences the exact
	// observed group before waiting for termination.
	cancelled := make(chan struct{})
	var cancelOnce sync.Once
	if command.Cancel != nil {
		command.Cancel = func() error { cancelOnce.Do(func() { close(cancelled) }); return nil }
	}
	command.Path = self
	command.Args = append([]string{self, clientWriterShimArg, path}, args...)
	command.ExtraFiles = []*os.File{releaseR}
	attributes := syscall.SysProcAttr{}
	if command.SysProcAttr != nil {
		attributes = *command.SysProcAttr
	}
	attributes.Setsid = true
	attributes.Setpgid = false
	attributes.Pdeathsig = syscall.SIGKILL
	command.SysProcAttr = &attributes
	if command.WaitDelay == 0 {
		command.WaitDelay = 2 * time.Second
	}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stopped)
	if err := command.Start(); err != nil {
		return err
	}
	_ = releaseR.Close()
	group, _, err := observeClientWriterLeader(command.Process.Pid)
	if err != nil {
		_ = releaseW.Close()
		_ = command.Process.Kill()
		return errors.Join(err, command.Wait())
	}
	origin := operationwriters.ClientOrigin{MachineID: machineID, BootID: bootID, KeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()), RunToken: token, Group: group}
	run := &clientOriginRun{origin: origin, group: group, signer: signer, operationID: operation.id, hostKey: operation.identity.HostKeyFingerprint}
	run.writer = operationwriters.Writer{ID: "client-origin:" + token, Kind: operationwriters.WriterKindClientOrigin, Client: &run.origin}
	abort := func(cause error) error {
		_ = releaseW.Close()
		_, fenceErr := run.localFence(operationwriters.Binding{OperationID: run.operationID, Generation: 1, HostKey: run.hostKey, BootID: bootID})
		if fenceErr != nil {
			_ = command.Process.Kill()
		}
		return errors.Join(cause, fenceErr, command.Wait())
	}
	if err := run.writer.Validate(); err != nil {
		return abort(err)
	}
	admission := registerClientOriginWriter
	admitted := make(chan error, 1)
	go func() { admitted <- admission(operation, run.writer, run.fence) }()
	select {
	case err := <-admitted:
		if err != nil {
			return abort(err)
		}
	case <-cancelled:
		err := abort(context.Canceled)
		return errors.Join(err, <-admitted)
	case sig := <-stopped:
		err := abort(fmt.Errorf("client writer interrupted by %s", sig))
		return errors.Join(err, <-admitted)
	}
	select {
	case <-cancelled:
		return abort(context.Canceled)
	default:
	}
	select {
	case sig := <-stopped:
		return abort(fmt.Errorf("client writer interrupted by %s", sig))
	default:
	}
	if _, err := releaseW.Write([]byte{1}); err != nil {
		return abort(err)
	}
	if err := releaseW.Close(); err != nil {
		return abort(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		return err
	case <-cancelled:
		_, err := run.localFence(operationwriters.Binding{OperationID: run.operationID, Generation: 1, HostKey: run.hostKey, BootID: bootID})
		if err != nil {
			_ = command.Process.Kill()
		}
		return errors.Join(context.Canceled, err, <-wait)
	case sig := <-stopped:
		_, err := run.localFence(operationwriters.Binding{OperationID: run.operationID, Generation: 1, HostKey: run.hostKey, BootID: bootID})
		if err != nil {
			_ = command.Process.Kill()
		}
		return errors.Join(fmt.Errorf("client writer interrupted by %s", sig), err, <-wait)
	}
}

func (run *clientOriginRun) localFence(binding operationwriters.Binding) (*operationwriters.LocalFenceReceipt, error) {
	machineID, bootID, err := readClientOriginHost()
	if err != nil {
		return nil, err
	}
	if machineID != run.origin.MachineID {
		return nil, errors.New("client origin machine changed; refusing local PID fencing")
	}
	if binding.OperationID != run.operationID || binding.HostKey != run.hostKey || binding.Generation != 1 {
		return nil, errors.New("client origin operation binding differs")
	}
	// Same machine, later boot: the writer died with its boot. Refusing here
	// left an interrupted deploy recovery_required with no way out, and the
	// application refused every later deploy. The ended boot is the proof; the
	// recorded PIDs are never touched because they now name other processes.
	if bootID != run.origin.BootID {
		return operationwriters.EndedBootLocalReceipt(binding.Generation, run.group, time.Now())
	}
	// Kernel observations belong to this client boot. The signed closure below
	// is separately bound to the VPS boot received from the durable registry.
	localBinding := binding
	localBinding.BootID = bootID
	ctx, cancel := context.WithTimeout(context.Background(), operationwriters.DefaultFenceTimeout)
	defer cancel()
	receipts, err := operationwriters.FenceLocalGroups(ctx, operationwriters.LocalSnapshot{Binding: localBinding, Generation: binding.Generation, AdmissionsClosed: true, Groups: []operationwriters.LocalGroup{run.group}})
	if err != nil {
		return nil, err
	}
	if len(receipts) != 1 || receipts[0].Local == nil {
		return nil, errors.New("client origin fence did not return its kernel proof")
	}
	return receipts[0].Local, nil
}

// closeRecordedClientWriter fences a client_origin writer recorded by an
// interrupted CLI invocation. Kernel fencing stays on this machine and boot;
// the signed receipt is bound to the original VPS operation identity.
func closeRecordedClientWriter(operation *remoteOperation, writer operationwriters.Writer, binding operationwriters.Binding) (operationwriters.Receipt, error) {
	if operation == nil {
		return operationwriters.Receipt{}, errors.New("client origin writer requires a remote operation")
	}
	if writer.Kind != operationwriters.WriterKindClientOrigin || writer.Client == nil {
		return operationwriters.Receipt{}, errors.New("recorded client origin writer is missing")
	}
	if err := writer.Validate(); err != nil {
		return operationwriters.Receipt{}, err
	}
	signer, err := ssh.NewSignerFromKey(operation.key)
	if err != nil {
		return operationwriters.Receipt{}, fmt.Errorf("client origin signer: %w", err)
	}
	if ssh.FingerprintSHA256(signer.PublicKey()) != writer.Client.KeyFingerprint {
		return operationwriters.Receipt{}, errors.New("recorded client origin key does not match this operator")
	}
	origin := *writer.Client
	run := &clientOriginRun{
		origin:      origin,
		group:       origin.Group,
		signer:      signer,
		operationID: operation.id,
		hostKey:     operation.identity.HostKeyFingerprint,
	}
	run.writer = writer
	run.writer.Client = &run.origin
	return run.fence(binding)
}

func (run *clientOriginRun) fence(binding operationwriters.Binding) (operationwriters.Receipt, error) {
	if run == nil || run.signer == nil {
		return operationwriters.Receipt{}, errors.New("missing client origin signer")
	}
	if run.writer.Client == nil || *run.writer.Client != run.origin || run.origin.Group != run.group {
		return operationwriters.Receipt{}, errors.New("client origin identity differs")
	}
	local, err := run.localFence(binding)
	if err != nil {
		return operationwriters.Receipt{}, err
	}
	return operationwriters.SignClientOriginReceipt(binding, run.writer, *local, run.signer)
}

func resolveClientWriterTarget(command *exec.Cmd) (string, []string, error) {
	path := command.Path
	args := append([]string(nil), command.Args...)
	if path == "" && len(args) > 0 {
		path = args[0]
	}
	if path == "" {
		return "", nil, errors.New("client origin writer requires a command path")
	}
	if !filepath.IsAbs(path) && !strings.ContainsRune(path, os.PathSeparator) {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return "", nil, fmt.Errorf("client origin writer: resolve %s: %w", path, err)
		}
		path = resolved
	}
	return path, args, nil
}

func newClientWriterRunToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("client origin writer: run token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func readClientOriginHost() (machineID, bootID string, err error) {
	machineID, err = readBoundedIdentity(clientWriterMachinePath, 128)
	if err != nil {
		return "", "", fmt.Errorf("client origin writer: machine-id: %w", err)
	}
	bootID, err = readBoundedIdentity(clientWriterBootPath, 128)
	if err != nil {
		return "", "", fmt.Errorf("client origin writer: boot id: %w", err)
	}
	if strings.ContainsAny(machineID, "/\\") || strings.ContainsAny(bootID, "/\\") {
		return "", "", errors.New("client origin writer: machine or boot identity contains a path separator")
	}
	return machineID, bootID, nil
}

func readBoundedIdentity(path string, limit int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)))
	if err != nil {
		return "", err
	}
	if len(data) >= limit {
		return "", fmt.Errorf("%s exceeded the bounded read", path)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return value, nil
}

func observeClientWriterLeader(pid int) (operationwriters.LocalGroup, operationwriters.ProcessIdentity, error) {
	if pid <= 0 {
		return operationwriters.LocalGroup{}, operationwriters.ProcessIdentity{}, errors.New("client origin writer: shim pid is invalid")
	}
	var last error
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		identity, err := readClientProcIdentity(pid)
		if err != nil {
			last = err
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if identity.PGID != pid || identity.SID != pid {
			last = fmt.Errorf("client origin shim pid %d is not its own session and group", pid)
			time.Sleep(5 * time.Millisecond)
			continue
		}
		group := operationwriters.LocalGroup{
			LeaderPID:        identity.PID,
			LeaderStartTicks: identity.StartTicks,
			PGID:             identity.PGID,
			SID:              identity.SID,
		}
		return group, identity, nil
	}
	if last == nil {
		last = errors.New("client origin shim did not become a session leader")
	}
	return operationwriters.LocalGroup{}, operationwriters.ProcessIdentity{}, last
}

func liveClientWriterMembers(ctx context.Context, group operationwriters.LocalGroup) ([]operationwriters.ProcessIdentity, error) {
	inspection, err := operationwriters.InspectLocalGroups(ctx, operationwriters.LocalSnapshot{
		Generation: 1,
		Groups:     []operationwriters.LocalGroup{group},
	})
	if err != nil {
		return nil, err
	}
	if len(inspection.Groups) != 1 {
		return nil, errors.New("client origin inspect did not return the registered group")
	}
	var live []operationwriters.ProcessIdentity
	for _, member := range inspection.Groups[0].Members {
		if member.State != "Z" && member.State != "X" && member.State != "x" {
			live = append(live, member)
		}
	}
	return live, nil
}

func readClientProcIdentity(pid int) (operationwriters.ProcessIdentity, error) {
	path := filepath.Join(clientWriterProcRoot, strconv.Itoa(pid), "stat")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return operationwriters.ProcessIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil {
		return operationwriters.ProcessIdentity{}, err
	}
	if len(data) == 4096 {
		return operationwriters.ProcessIdentity{}, errors.New("proc stat exceeded bounded read")
	}
	return parseClientProcStat(data, pid)
}

func parseClientProcStat(data []byte, pid int) (operationwriters.ProcessIdentity, error) {
	text := string(data)
	closeParen := strings.LastIndexByte(text, ')')
	if closeParen < 0 || closeParen+2 >= len(text) {
		return operationwriters.ProcessIdentity{}, fmt.Errorf("malformed proc stat for pid %d", pid)
	}
	fields := strings.Fields(text[closeParen+2:])
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return operationwriters.ProcessIdentity{}, fmt.Errorf("short proc stat for pid %d", pid)
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return operationwriters.ProcessIdentity{}, fmt.Errorf("invalid proc parent for pid %d", pid)
	}
	pgid, err := strconv.Atoi(fields[2])
	if err != nil {
		return operationwriters.ProcessIdentity{}, fmt.Errorf("invalid proc group for pid %d", pid)
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return operationwriters.ProcessIdentity{}, fmt.Errorf("invalid proc session for pid %d", pid)
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return operationwriters.ProcessIdentity{}, fmt.Errorf("invalid proc start time for pid %d", pid)
	}
	return operationwriters.ProcessIdentity{PID: pid, StartTicks: startTicks, PPID: ppid, PGID: pgid, SID: sid, State: fields[0]}, nil
}
