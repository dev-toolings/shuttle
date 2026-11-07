package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestSSHRunnerClosureReceiptBindsHostTokenAndGeneration(t *testing.T) {
	hostKey := "SHA256:" + strings.Repeat("C", 43)
	writer := operationwriters.Writer{
		ID:     "ssh-build-runner",
		Kind:   operationwriters.WriterKindRemoteRunner,
		Remote: &operationwriters.RemoteRunner{HostKey: hostKey, RunToken: "aabbccdd1122334455667788"},
	}
	binding := operationwriters.Binding{
		OperationID: "01234567-89ab-cdef-0123-456789abcdef",
		Generation:  1,
		HostKey:     "SHA256:" + strings.Repeat("A", 43),
		BootID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
	finished := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	proof := shuttlessh.FenceResult{
		Status:             shuttlessh.FenceStatusFenced,
		RunToken:           writer.Remote.RunToken,
		RunnerHostKey:      hostKey,
		ActualContainerIDs: []string{strings.Repeat("a", 64)},
		TunnelIdentity:     writer.Remote.RunToken + ":build@192.0.2.10:22",
		AdmissionState:     "closed",
		FinishedAt:         finished,
		ProofHash:          "sha256:" + strings.Repeat("e", 64),
	}
	receipt, err := sshRunnerClosureReceipt(writer, binding, proof)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.WriterID != writer.ID || receipt.Kind != writer.Kind || receipt.Generation != binding.Generation || receipt.Remote == nil {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if receipt.Remote.HostKey != hostKey || receipt.Remote.RunToken != writer.Remote.RunToken || receipt.Remote.Generation != binding.Generation {
		t.Fatalf("receipt lost runner identity: %+v", receipt.Remote)
	}
	if receipt.Remote.AuthenticatedProof != "SHU1-Fence/v1" || !receipt.AdmissionsClosed || !receipt.ResourcesClosed {
		t.Fatalf("receipt is not a typed fence proof: %+v", receipt)
	}
	if receipt.EvidenceSHA256 != proof.ProofHash || receipt.Remote.EvidenceSHA256 != proof.ProofHash {
		t.Fatalf("receipt lost observed proof hash: %+v", receipt)
	}
	if receipt.ObservedAt != finished.Format(time.RFC3339Nano) {
		t.Fatalf("receipt timestamp = %s", receipt.ObservedAt)
	}

	wrongHost := proof
	wrongHost.RunnerHostKey = "SHA256:" + strings.Repeat("Z", 43)
	if _, err := sshRunnerClosureReceipt(writer, binding, wrongHost); err == nil {
		t.Fatal("another runner host key produced a closure receipt")
	}
	wrongToken := proof
	wrongToken.RunToken = "ffffffffffffffffffffffff"
	if _, err := sshRunnerClosureReceipt(writer, binding, wrongToken); err == nil {
		t.Fatal("another run token produced a closure receipt")
	}
	open := proof
	open.AdmissionState = "open"
	if _, err := sshRunnerClosureReceipt(writer, binding, open); err == nil {
		t.Fatal("open admissions produced a closure receipt")
	}
	unresolved := proof
	unresolved.Status = shuttlessh.FenceStatusUnresolved
	if _, err := sshRunnerClosureReceipt(writer, binding, unresolved); err == nil {
		t.Fatal("unresolved fence produced a closure receipt")
	}
	if _, err := sshRunnerClosureReceipt(operationwriters.Writer{ID: "client", Kind: operationwriters.WriterKindClientOrigin}, binding, proof); err == nil {
		t.Fatal("client origin writer received an SSH runner receipt")
	}
	if _, err := sshRunnerClosureReceipt(writer, operationwriters.Binding{}, proof); err == nil {
		t.Fatal("unbound generation produced a closure receipt")
	}
}
