package operationwriters

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testClientSigner(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, ssh.FingerprintSHA256(signer.PublicKey())
}

func testClientOrigin(fingerprint string) ClientOrigin {
	return ClientOrigin{
		MachineID:      "cli-host-1",
		BootID:         "11111111-2222-3333-4444-555555555555",
		KeyFingerprint: fingerprint,
		RunToken:       "client-run-token",
		Group:          LocalGroup{LeaderPID: 4242, LeaderStartTicks: 9001, PGID: 4242, SID: 4242},
	}
}

func testClientLocalFence(t *testing.T, binding Binding, origin ClientOrigin, observedAt time.Time) LocalFenceReceipt {
	t.Helper()
	members := []ProcessIdentity{{
		PID:        origin.Group.LeaderPID,
		StartTicks: origin.Group.LeaderStartTicks,
		PGID:       origin.Group.PGID,
		SID:        origin.Group.SID,
		State:      "R",
	}}
	hash, err := localEvidenceHash(binding.Generation, []LocalGroup{origin.Group}, members)
	if err != nil {
		t.Fatal(err)
	}
	return LocalFenceReceipt{
		Generation:       binding.Generation,
		ObservedAt:       formatTime(observedAt),
		AdmissionsClosed: true,
		ResourcesClosed:  true,
		EvidenceSHA256:   hash,
		KernelProof:      "linux-pidfd-v1",
		Groups:           []LocalGroup{origin.Group},
		ObservedMembers:  members,
	}
}

func testLocalFence(t *testing.T, binding Binding, group LocalGroup, observedAt time.Time) Receipt {
	t.Helper()
	members := []ProcessIdentity{{
		PID:        group.LeaderPID,
		StartTicks: group.LeaderStartTicks,
		PGID:       group.PGID,
		SID:        group.SID,
		State:      "R",
	}}
	hash, err := localEvidenceHash(binding.Generation, []LocalGroup{group}, members)
	if err != nil {
		t.Fatal(err)
	}
	local := &LocalFenceReceipt{
		Generation:       binding.Generation,
		ObservedAt:       formatTime(observedAt),
		AdmissionsClosed: true,
		ResourcesClosed:  true,
		EvidenceSHA256:   hash,
		KernelProof:      "linux-pidfd-v1",
		Groups:           []LocalGroup{group},
		ObservedMembers:  members,
	}
	return Receipt{
		WriterID:         "vps",
		Kind:             WriterKindLocalGroup,
		Generation:       binding.Generation,
		ObservedAt:       local.ObservedAt,
		AdmissionsClosed: true,
		ResourcesClosed:  true,
		EvidenceSHA256:   hash,
		Local:            local,
	}
}

func TestClientOriginReceiptRejectsTamperAndUnsignedProof(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	store, err := OpenStore(StoreOptions{Root: privateTestRoot(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	if _, err := store.InitializeLocked(binding, testBaseline()); err != nil {
		t.Fatal(err)
	}
	signer, fingerprint := testClientSigner(t)
	origin := testClientOrigin(fingerprint)
	writer := Writer{ID: "cli", Kind: WriterKindClientOrigin, Client: &origin}
	if _, err := store.RegisterLocked(binding, writer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CloseAdmissionsLocked(binding); err != nil {
		t.Fatal(err)
	}
	local := testClientLocalFence(t, binding, origin, now)
	valid, err := SignClientOriginReceipt(binding, writer, local, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitClosureLocked(binding, []Receipt{valid}); err != nil {
		t.Fatal(err)
	}

	otherSigner, _ := testClientSigner(t)
	cases := []struct {
		name string
		mut  func(Receipt) Receipt
	}{
		{"boot", func(r Receipt) Receipt { r.Client.Origin.BootID = "00000000-0000-0000-0000-000000000000"; return r }},
		{"token", func(r Receipt) Receipt { r.Client.Origin.RunToken = "tampered-token"; return r }},
		{"generation", func(r Receipt) Receipt {
			r.Client.Binding.Generation = 99
			return r
		}},
		{"key", func(r Receipt) Receipt {
			r.Client.PublicKey = otherSigner.PublicKey().Marshal()
			return r
		}},
		{"operation", func(r Receipt) Receipt {
			r.Client.Binding.OperationID = "018f3a7e-8e3b-4a8c-9a2d-000000000000"
			return r
		}},
		{"unsigned", func(r Receipt) Receipt { r.Client.Signature = nil; return r }},
		{"missing-format", func(r Receipt) Receipt { r.Client.SignatureFormat = ""; return r }},
		{"boolean-only", func(r Receipt) Receipt {
			r.Client = nil
			return r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clone := valid
			clientCopy := *valid.Client
			clone.Client = &clientCopy
			tampered := tc.mut(clone)
			if err := validateReceipts(binding, []Writer{writer}, []Receipt{tampered}, now, DefaultReceiptMaxAge, DefaultClockSkew); err == nil || !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("tamper %s error = %v, want ErrInvalidReceipt", tc.name, err)
			}
		})
	}
}

func TestSignClientOriginReceiptRejectsMismatchedSigner(t *testing.T) {
	binding := testBinding()
	_, fingerprint := testClientSigner(t)
	other, _ := testClientSigner(t)
	origin := testClientOrigin(fingerprint)
	writer := Writer{ID: "cli", Kind: WriterKindClientOrigin, Client: &origin}
	local := testClientLocalFence(t, binding, origin, time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC))
	if _, err := SignClientOriginReceipt(binding, writer, local, other); err == nil || !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("mismatched signer error = %v, want ErrInvalidReceipt", err)
	}
	if _, err := SignClientOriginReceipt(binding, writer, local, nil); err == nil || !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("nil signer error = %v, want ErrInvalidReceipt", err)
	}
}

func TestClientOriginAloneNeverInspectsOrFencesLocalPIDs(t *testing.T) {
	origin := testClientOrigin("SHA256:" + strings.Repeat("b", 43))
	origin.Group = LocalGroup{LeaderPID: 1, LeaderStartTicks: 1, PGID: 1, SID: 1}
	state := State{
		Schema:     Schema,
		Binding:    testBinding(),
		Revision:   3,
		Admissions: AdmissionsClosed,
		Writers:    []Writer{{ID: "cli", Kind: WriterKindClientOrigin, Client: &origin}},
		Baseline:   testBaseline(),
	}
	_, err := InspectLocalGroups(context.Background(), state)
	if err == nil || !errors.Is(err, ErrInvalidState) || !strings.Contains(err.Error(), "client_origin") {
		t.Fatalf("InspectLocalGroups error = %v, want client_origin skip", err)
	}
	if errors.Is(err, ErrProcessMissing) || errors.Is(err, ErrBootMismatch) || errors.Is(err, ErrFenceTimeout) || errors.Is(err, ErrPIDReused) {
		t.Fatalf("InspectLocalGroups probed local PIDs: %v", err)
	}
	_, err = FenceLocalGroups(context.Background(), state)
	if err == nil || !errors.Is(err, ErrInvalidState) || !strings.Contains(err.Error(), "client_origin") {
		t.Fatalf("FenceLocalGroups error = %v, want client_origin skip", err)
	}
	if errors.Is(err, ErrProcessMissing) || errors.Is(err, ErrBootMismatch) || errors.Is(err, ErrFenceTimeout) || errors.Is(err, ErrPIDReused) {
		t.Fatalf("FenceLocalGroups probed or signaled local PIDs: %v", err)
	}
}

func TestMixedStateCannotCloseWithoutClientOriginReceipt(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	store, err := OpenStore(StoreOptions{Root: privateTestRoot(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	if _, err := store.InitializeLocked(binding, testBaseline()); err != nil {
		t.Fatal(err)
	}
	group := LocalGroup{LeaderPID: 91, LeaderStartTicks: 123, PGID: 91, SID: 91}
	if _, err := store.RegisterLocked(binding, Writer{ID: "vps", Kind: WriterKindLocalGroup, Local: &group}); err != nil {
		t.Fatal(err)
	}
	signer, fingerprint := testClientSigner(t)
	origin := testClientOrigin(fingerprint)
	writer := Writer{ID: "cli", Kind: WriterKindClientOrigin, Client: &origin}
	if _, err := store.RegisterLocked(binding, writer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CloseAdmissionsLocked(binding); err != nil {
		t.Fatal(err)
	}

	localReceipt := testLocalFence(t, binding, group, now)
	if _, err := store.CommitClosureLocked(binding, []Receipt{localReceipt}); err == nil || !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("missing client receipt error = %v, want ErrInvalidReceipt", err)
	}
	unsigned := Receipt{
		WriterID:         "cli",
		Kind:             WriterKindClientOrigin,
		Generation:       binding.Generation,
		ObservedAt:       formatTime(now),
		AdmissionsClosed: true,
		ResourcesClosed:  true,
		EvidenceSHA256:   localReceipt.EvidenceSHA256,
	}
	if _, err := store.CommitClosureLocked(binding, []Receipt{localReceipt, unsigned}); err == nil || !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("unsigned client receipt error = %v, want ErrInvalidReceipt", err)
	}
	signed, err := SignClientOriginReceipt(binding, writer, testClientLocalFence(t, binding, origin, now), signer)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := store.CommitClosureLocked(binding, []Receipt{localReceipt, signed})
	if err != nil {
		t.Fatal(err)
	}
	if closed.Closure == nil || closed.Closure.ProofHash == "" {
		t.Fatal("expected authenticated mixed closure")
	}
	if !strings.Contains(closed.Closure.ProofHash, "sha256:") {
		t.Fatalf("unexpected proof hash %q", closed.Closure.ProofHash)
	}
}
