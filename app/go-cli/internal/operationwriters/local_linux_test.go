//go:build linux

package operationwriters

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func startTestGroup(t *testing.T, command string, args ...string) (*exec.Cmd, LocalGroup, <-chan error) {
	t.Helper()
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	identity, err := readProcIdentity("/proc", cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if identity.PGID != cmd.Process.Pid || identity.SID != cmd.Process.Pid {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Skipf("test process did not become its own session and group: %+v", identity)
	}
	wait := make(chan error, 1)
	go func() {
		wait <- cmd.Wait()
	}()
	return cmd, LocalGroup{LeaderPID: identity.PID, LeaderStartTicks: identity.StartTicks, PGID: identity.PGID, SID: identity.SID}, wait
}

func TestInspectLocalGroupsReadsOnlyKernelIdentity(t *testing.T) {
	cmd, group, wait := startTestGroup(t, "sleep", "30")
	defer func() {
		_ = cmd.Process.Kill()
		<-wait
	}()
	inspection, err := InspectLocalGroups(context.Background(), LocalSnapshot{Generation: 1, Groups: []LocalGroup{group}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Groups) != 1 || !inspection.Groups[0].LeaderPresent || len(inspection.Groups[0].Members) == 0 {
		t.Fatalf("unexpected kernel inspection: %+v", inspection)
	}
	for _, member := range inspection.Groups[0].Members {
		if member.PID == cmd.Process.Pid && member.StartTicks != group.LeaderStartTicks {
			t.Fatalf("leader birth time was not retained: %+v", member)
		}
	}
}

func TestFenceKillsChildAfterLeaderAndLeavesOtherGroupAlive(t *testing.T) {
	cmd, group, wait := startTestGroup(t, "/bin/sh", "-c", "sleep 30 & sleep 0.05; exit 0")
	defer func() {
		_ = cmd.Process.Kill()
		select {
		case <-wait:
		case <-time.After(time.Second):
		}
	}()

	other := exec.Command("sleep", "30")
	other.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := readProcIdentity("/proc", other.Process.Pid)
	if err != nil {
		_ = other.Process.Kill()
		_ = other.Wait()
		t.Fatal(err)
	}
	defer func() {
		_ = other.Process.Kill()
		_ = other.Wait()
	}()
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("leader did not exit")
	}
	receipts, err := FenceLocalGroups(context.Background(), LocalSnapshot{Generation: 1, AdmissionsClosed: true, Groups: []LocalGroup{group}})
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].Local == nil || !receipts[0].ResourcesClosed {
		t.Fatalf("unexpected local fence receipts: %+v", receipts)
	}
	if _, err := readProcIdentity("/proc", otherIdentity.PID); err != nil {
		t.Fatalf("fencing target group affected unrelated process: %v", err)
	}
}

func TestFenceHonorsDeadlineInsteadOfFalseClosure(t *testing.T) {
	cmd, group, wait := startTestGroup(t, "sleep", "30")
	defer func() {
		_ = cmd.Process.Kill()
		<-wait
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := FenceLocalGroups(ctx, LocalSnapshot{Generation: 1, AdmissionsClosed: true, Groups: []LocalGroup{group}})
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err == nil || !errors.Is(err, ErrFenceTimeout) {
		t.Fatalf("deadline result = %v, want timeout and no closed proof", err)
	}
}

func TestPIDReuseAndMissingProcAreExplicit(t *testing.T) {
	group := LocalGroup{LeaderPID: 44, LeaderStartTicks: 100, PGID: 44, SID: 44}
	_, err := observeGroup(group, map[int]ProcessIdentity{44: {PID: 44, StartTicks: 101, PGID: 44, SID: 44}})
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("PID reuse result = %v", err)
	}
	_, err = InspectLocalGroups(context.Background(), LocalSnapshot{Generation: 1, ProcRoot: "/proc/does-not-exist", Groups: []LocalGroup{group}})
	if !errors.Is(err, ErrProcessMissing) {
		t.Fatalf("missing proc result = %v", err)
	}
}

func TestProcStatParserDoesNotUseArguments(t *testing.T) {
	fields := []string{"S", "1", "10", "10"}
	fields = append(fields, strings.Repeat("0 ", 15)+"123")
	identity, err := parseProcStat([]byte("42 (name with spaces) "+strings.Join(fields, " ")), 42)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != 42 || identity.StartTicks != 123 {
		t.Fatalf("parsed identity = %+v", identity)
	}
	if _, err := unix.PidfdOpen(-1, 0); err == nil {
		t.Fatal("invalid PID unexpectedly opened")
	}
}
