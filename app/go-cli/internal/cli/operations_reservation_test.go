package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func reservationTestClient(t *testing.T, handle func(user, command string, stdin []byte) shuttlessh.Result) (*shuttlessh.Client, trustedHostIdentity, ed25519.PrivateKey) {
	t.Helper()
	// Other tests execute commands with --config and leave the recorded
	// invocation behind (DEV-DEPL-50); hints here describe a bare invocation.
	previous := recoveryInvocation
	recoveryInvocation = ""
	t.Cleanup(func() { recoveryInvocation = previous })
	fixture, pin := administratorSSHFixture(t, handle)
	client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, fixture.user, fixture.port, pin)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := trustedHostIdentity{HostKeyFingerprint: pin, OperatorKeyFingerprint: fixture.operatorKeyFingerprint}
	return client, identity, key
}

func decodeReservationID(stdin []byte) (string, error) {
	plan, _, err := decodeRootHelperEnvelope(bytes.NewReader(stdin))
	if err != nil {
		return "", err
	}
	if plan.Action != "operation-reserve" {
		return "", errors.New("unexpected reservation action: " + plan.Action)
	}
	return plan.OperationID, nil
}

type reservationSendLog struct {
	mu        sync.Mutex
	ids       []string
	decodeErr error
}

func (l *reservationSendLog) record(stdin []byte) string {
	id, err := decodeReservationID(stdin)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil && l.decodeErr == nil {
		l.decodeErr = err
	}
	l.ids = append(l.ids, id)
	return id
}

func (l *reservationSendLog) snapshot() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ids...), l.decodeErr
}

func setReservationUnknownPause(t *testing.T, pause time.Duration) {
	t.Helper()
	previous := operationReservationUnknownPause
	operationReservationUnknownPause = pause
	t.Cleanup(func() { operationReservationUnknownPause = previous })
}

func TestOperationReservationLostReplyAdoptsOwnRecord(t *testing.T) {
	setReservationUnknownPause(t, time.Millisecond)
	var sends reservationSendLog
	client, identity, key := reservationTestClient(t, func(_, command string, stdin []byte) shuttlessh.Result {
		if !strings.HasSuffix(command, "/usr/local/libexec/shuttle-root apply") {
			return shuttlessh.Result{Code: 1, Stderr: "unexpected command"}
		}
		id := sends.record(stdin)
		ids, _ := sends.snapshot()
		if len(ids) == 1 {
			return shuttlessh.Result{Code: -1}
		}
		if id != ids[0] {
			return shuttlessh.Result{Code: 1, Stderr: "reservation ID changed"}
		}
		return shuttlessh.Result{Code: 0}
	})

	id, err := reserveRemoteOperation(client, identity, key, "deploy", "demo")
	if err != nil {
		t.Fatalf("reserve after lost reply: %v", err)
	}
	ids, decodeErr := sends.snapshot()
	if decodeErr != nil {
		t.Fatalf("decode signed reservation: %v", decodeErr)
	}
	if len(ids) != 2 || ids[0] != id || ids[1] != id {
		t.Fatalf("reservation sends = %v, returned id = %s, want two sends with that id", ids, id)
	}
}

func TestOperationReservationReusesOneIDAcrossBusyWait(t *testing.T) {
	var sends reservationSendLog
	client, identity, key := reservationTestClient(t, func(_, command string, stdin []byte) shuttlessh.Result {
		if !strings.HasSuffix(command, "/usr/local/libexec/shuttle-root apply") {
			return shuttlessh.Result{Code: 1, Stderr: "unexpected command"}
		}
		sends.record(stdin)
		ids, _ := sends.snapshot()
		if len(ids) <= 2 {
			return shuttlessh.Result{Code: 1, Stderr: "operation busy is active for another request"}
		}
		return shuttlessh.Result{Code: 0}
	})

	id, err := reserveRemoteOperation(client, identity, key, "deploy", "demo")
	if err != nil {
		t.Fatalf("reserve after busy refusals: %v", err)
	}
	ids, decodeErr := sends.snapshot()
	if decodeErr != nil {
		t.Fatalf("decode signed reservation: %v", decodeErr)
	}
	if len(ids) != 3 || ids[0] != id || ids[1] != id || ids[2] != id {
		t.Fatalf("reservation sends = %v, returned id = %s, want three sends with that id", ids, id)
	}
}

func TestOperationReservationUnknownOutcomeNamesTheID(t *testing.T) {
	setReservationUnknownPause(t, time.Millisecond)
	var sends reservationSendLog
	client, identity, key := reservationTestClient(t, func(_, command string, stdin []byte) shuttlessh.Result {
		if !strings.HasSuffix(command, "/usr/local/libexec/shuttle-root apply") {
			return shuttlessh.Result{Code: 1, Stderr: "unexpected command"}
		}
		sends.record(stdin)
		return shuttlessh.Result{Code: -1}
	})

	_, err := reserveRemoteOperation(client, identity, key, "deploy", "demo")
	if err == nil {
		t.Fatal("reservation with every reply lost succeeded")
	}
	ids, decodeErr := sends.snapshot()
	if decodeErr != nil {
		t.Fatalf("decode signed reservation: %v", decodeErr)
	}
	if len(ids) != operationReservationUnknownAttempts {
		t.Fatalf("reservation sends = %d, want %d", len(ids), operationReservationUnknownAttempts)
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("reservation ID changed across unknown replies: %v", ids)
		}
	}
	for _, want := range []string{ids[0], "shuttle operations recover " + ids[0] + " --dry-run"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("reservation error %q does not contain %q", err, want)
		}
	}
}

func TestOperationReservationHelperRefusalIsNotRetriedAsUnknown(t *testing.T) {
	var sends atomic.Int32
	client, identity, key := reservationTestClient(t, func(_, command string, _ []byte) shuttlessh.Result {
		sends.Add(1)
		return shuttlessh.Result{Code: 1, Stderr: "identity mismatch"}
	})

	_, err := reserveRemoteOperation(client, identity, key, "deploy", "demo")
	if err == nil || sends.Load() != 1 || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("helper refusal = %v after %d sends, want one definitive refusal", err, sends.Load())
	}
	if strings.Contains(err.Error(), "may require recovery") {
		t.Fatalf("definitive helper refusal gained an uncertain-outcome hint: %v", err)
	}
}

func TestOperationReservationReplayRecoveryRequiredGetsHint(t *testing.T) {
	setReservationUnknownPause(t, time.Millisecond)
	var sends reservationSendLog
	client, identity, key := reservationTestClient(t, func(_, command string, stdin []byte) shuttlessh.Result {
		id := sends.record(stdin)
		ids, _ := sends.snapshot()
		if len(ids) == 1 {
			return shuttlessh.Result{Code: -1}
		}
		return shuttlessh.Result{Code: 1, Stderr: "operation " + id + " already exists in state recovery_required and cannot be reused"}
	})

	_, err := reserveRemoteOperation(client, identity, key, "deploy", "demo")
	ids, decodeErr := sends.snapshot()
	if decodeErr != nil {
		t.Fatalf("decode signed reservation: %v", decodeErr)
	}
	if err == nil || len(ids) != 2 || ids[1] != ids[0] {
		t.Fatalf("replayed reservation = %v after %d sends", err, len(ids))
	}
	if !strings.Contains(err.Error(), recoveryHint(ids[0], "deploy").Error()) {
		t.Fatalf("recovery hint missing from reservation error: %v", err)
	}
}

func TestOperationReservationOlderHelperReplayFailureGetsHint(t *testing.T) {
	setReservationUnknownPause(t, time.Millisecond)
	var sends reservationSendLog
	client, identity, key := reservationTestClient(t, func(_, _ string, stdin []byte) shuttlessh.Result {
		sends.record(stdin)
		ids, _ := sends.snapshot()
		if len(ids) == 1 {
			return shuttlessh.Result{Code: -1}
		}
		return shuttlessh.Result{Code: 1, Stderr: "writers-initialize failed: baseline conflict"}
	})

	_, err := reserveRemoteOperation(client, identity, key, "deploy", "demo")
	ids, decodeErr := sends.snapshot()
	if decodeErr != nil {
		t.Fatalf("decode signed reservation: %v", decodeErr)
	}
	if err == nil || len(ids) != 2 || ids[1] != ids[0] {
		t.Fatalf("older helper replay = %v after %d sends", err, len(ids))
	}
	if !strings.Contains(err.Error(), ids[0]) || !strings.Contains(err.Error(), "shuttle operations recover "+ids[0]+" --dry-run") {
		t.Fatalf("replay failure omitted reservation recovery hint: %v", err)
	}
}

func TestOperationReservationLostReplyThenIdentityRefusalKeepsHint(t *testing.T) {
	setReservationUnknownPause(t, time.Millisecond)
	var sends reservationSendLog
	client, identity, key := reservationTestClient(t, func(_, _ string, stdin []byte) shuttlessh.Result {
		sends.record(stdin)
		ids, _ := sends.snapshot()
		if len(ids) == 1 {
			return shuttlessh.Result{Code: -1}
		}
		return shuttlessh.Result{Code: 1, Stderr: "read host identity: identity mismatch"}
	})

	_, err := reserveRemoteOperation(client, identity, key, "deploy", "demo")
	ids, decodeErr := sends.snapshot()
	if decodeErr != nil {
		t.Fatalf("decode signed reservation: %v", decodeErr)
	}
	if err == nil || len(ids) != 2 {
		t.Fatalf("lost reply then identity refusal = %v after %d sends", err, len(ids))
	}
	if !strings.Contains(err.Error(), "shuttle operations recover "+ids[0]+" --dry-run") {
		t.Fatalf("identity refusal after a lost reply dropped the reservation ID: %v", err)
	}
}
