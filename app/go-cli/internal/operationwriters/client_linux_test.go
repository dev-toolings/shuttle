//go:build linux

package operationwriters

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func testLinuxBinding(t *testing.T) Binding {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	binding.BootID = strings.TrimSpace(string(data))
	return binding
}

func TestMixedStateFencesOnlyVPSLocalWriters(t *testing.T) {
	localCmd, localGroup, localWait := startTestGroup(t, "sleep", "30")
	defer func() {
		_ = localCmd.Process.Kill()
		select {
		case <-localWait:
		case <-time.After(time.Second):
		}
	}()
	clientCmd, clientGroup, clientWait := startTestGroup(t, "sleep", "30")
	defer func() {
		_ = clientCmd.Process.Kill()
		select {
		case <-clientWait:
		case <-time.After(time.Second):
		}
	}()

	now := time.Now().UTC()
	store, err := OpenStore(StoreOptions{Root: privateTestRoot(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testLinuxBinding(t)
	if _, err := store.InitializeLocked(binding, testBaseline()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterLocked(binding, Writer{ID: "vps", Kind: WriterKindLocalGroup, Local: &localGroup}); err != nil {
		t.Fatal(err)
	}
	signer, fingerprint := testClientSigner(t)
	origin := testClientOrigin(fingerprint)
	origin.Group = clientGroup
	clientWriter := Writer{ID: "cli", Kind: WriterKindClientOrigin, Client: &origin}
	if _, err := store.RegisterLocked(binding, clientWriter); err != nil {
		t.Fatal(err)
	}
	state, err := store.CloseAdmissionsLocked(binding)
	if err != nil {
		t.Fatal(err)
	}

	inspection, err := InspectLocalGroups(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Groups) != 1 || inspection.Groups[0].Group != localGroup {
		t.Fatalf("mixed inspect included client-origin PIDs: %+v", inspection)
	}

	receipts, err := FenceLocalGroups(context.Background(), state)
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].Kind != WriterKindLocalGroup || receipts[0].WriterID != "vps" || receipts[0].Client != nil {
		t.Fatalf("mixed fence produced client-origin closure: %+v", receipts)
	}
	if _, err := readProcIdentity("/proc", clientGroup.LeaderPID); err != nil {
		t.Fatalf("VPS fence signaled a client-origin PID: %v", err)
	}
	if _, err := readProcIdentity("/proc", localGroup.LeaderPID); err == nil {
		t.Fatal("VPS local writer was still alive after fence")
	}

	if _, err := store.CommitClosureLocked(binding, receipts); err == nil || !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("missing client receipt error = %v, want ErrInvalidReceipt", err)
	}

	signed, err := SignClientOriginReceipt(binding, clientWriter, testClientLocalFence(t, binding, origin, now), signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitClosureLocked(binding, []Receipt{receipts[0], signed}); err != nil {
		t.Fatal(err)
	}
	if _, err := readProcIdentity("/proc", clientGroup.LeaderPID); err != nil {
		t.Fatalf("committing a signed client receipt must not inspect or kill the CLI PID: %v", err)
	}
}
