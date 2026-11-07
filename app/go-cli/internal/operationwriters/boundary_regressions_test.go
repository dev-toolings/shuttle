package operationwriters

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadMissingInventoryDoesNotCreateDirectories(t *testing.T) {
	root := privateTestRoot(t)
	_, err := NewStore(root).Read(testBinding())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read missing inventory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "writers")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read created writer directory: %v", err)
	}
}

func TestRemoteReceiptAcceptsActualSHU1TunnelIdentity(t *testing.T) {
	binding := testBinding()
	now := time.Now().UTC()
	remote := RemoteRunner{HostKey: binding.HostKey, RunToken: "token"}
	writer := Writer{ID: "runner", Kind: WriterKindRemoteRunner, Remote: &remote}
	evidence := "sha256:" + strings.Repeat("a", 64)
	receipt := Receipt{WriterID: writer.ID, Kind: writer.Kind, Generation: binding.Generation, ObservedAt: formatTime(now), AdmissionsClosed: true, ResourcesClosed: true, EvidenceSHA256: evidence, Remote: &RemoteRunnerReceipt{HostKey: remote.HostKey, RunToken: remote.RunToken, Generation: binding.Generation, ObservedAt: formatTime(now), AdmissionsClosed: true, ResourcesClosed: true, ResourceIDs: []string{"buildkit:runner-1"}, TunnelID: "token:deploy@198.51.100.31:22", EvidenceSHA256: evidence, AuthenticatedProof: "SHU1-Fence/v1"}}
	if err := validateReceipts(binding, []Writer{writer}, []Receipt{receipt}, now, DefaultReceiptMaxAge, DefaultClockSkew); err != nil {
		t.Fatal(err)
	}
	receipt.Remote.TunnelID = "token:deploy@host:22\nforged"
	if err := validateReceipts(binding, []Writer{writer}, []Receipt{receipt}, now, DefaultReceiptMaxAge, DefaultClockSkew); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("unsafe tunnel accepted: %v", err)
	}
}

func TestClientSignatureCannotReplayUnderAnotherWriterID(t *testing.T) {
	signer, fingerprint := testClientSigner(t)
	origin := testClientOrigin(fingerprint)
	binding := testBinding()
	now := time.Now().UTC()
	writer := Writer{ID: "client-one", Kind: WriterKindClientOrigin, Client: &origin}
	receipt, err := SignClientOriginReceipt(binding, writer, testClientLocalFence(t, binding, origin, now), signer)
	if err != nil {
		t.Fatal(err)
	}
	writer.ID = "client-two"
	receipt.WriterID = writer.ID
	if err := validateReceipts(binding, []Writer{writer}, []Receipt{receipt}, now, DefaultReceiptMaxAge, DefaultClockSkew); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("client receipt replayed under a different writer: %v", err)
	}
}
