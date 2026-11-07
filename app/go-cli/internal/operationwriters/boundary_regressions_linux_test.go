//go:build linux

package operationwriters

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestFenceClosesUnreapedExitedWriter(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(2 * time.Second)
	var identity ProcessIdentity
	for {
		var err error
		identity, err = readProcIdentity("/proc", cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if identity.State == "Z" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not reach unreaped exit state")
		}
		time.Sleep(time.Millisecond)
	}
	group := LocalGroup{LeaderPID: identity.PID, LeaderStartTicks: identity.StartTicks, PGID: identity.PGID, SID: identity.SID}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receipts, err := FenceLocalGroups(ctx, LocalSnapshot{Generation: 1, AdmissionsClosed: true, Groups: []LocalGroup{group}})
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || !receipts[0].ResourcesClosed || len(receipts[0].Local.ObservedMembers) != 1 || receipts[0].Local.ObservedMembers[0].State != "Z" {
		t.Fatalf("missing terminal kernel proof: %+v", receipts)
	}
}

func TestFenceClosesReapedRegisteredWriterWithCurrentBoot(t *testing.T) {
	cmd, group, wait := startTestGroup(t, "/bin/sh", "-c", "exit 0")
	defer func() { _ = cmd.Process.Kill() }()
	if err := <-wait; err != nil {
		t.Fatal(err)
	}
	binding := testLinuxBinding(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receipts, err := FenceLocalGroups(ctx, LocalSnapshot{Binding: binding, Generation: binding.Generation, AdmissionsClosed: true, Groups: []LocalGroup{group}})
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || !receipts[0].ResourcesClosed || len(receipts[0].Local.ObservedMembers) != 0 {
		t.Fatalf("missing fresh empty inventory proof: %+v", receipts)
	}
	writer := Writer{ID: receipts[0].WriterID, Kind: WriterKindLocalGroup, Local: &group}
	if err := validateReceipts(binding, []Writer{writer}, receipts, time.Now().UTC(), DefaultReceiptMaxAge, DefaultClockSkew); err != nil {
		t.Fatal(err)
	}
}
