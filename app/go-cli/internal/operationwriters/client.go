package operationwriters

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// SignClientOriginReceipt builds a terminal receipt for a client_origin writer.
//
// Trust boundary: the caller fences its own process groups on the CLI host
// and then signs that kernel-derived LocalFenceReceipt. The VPS never inspects
// or signals those PIDs. InspectLocalGroups and FenceLocalGroups skip
// client_origin writers and never emit a VPS closure receipt for them. A
// snapshot that contains only client-origin groups errors without probing or
// signaling local PIDs. Genuine local_group writers keep VPS-local kernel
// fencing.
//
// The signature covers Origin, Binding, and Local. Outer receipt flags,
// timestamp, and evidence must equal that authenticated Local payload.
func SignClientOriginReceipt(binding Binding, writer Writer, local LocalFenceReceipt, signer ssh.Signer) (Receipt, error) {
	if err := validateBinding(binding); err != nil {
		return Receipt{}, err
	}
	if err := validateWriter(writer); err != nil {
		return Receipt{}, err
	}
	if writer.Kind != WriterKindClientOrigin || writer.Client == nil {
		return Receipt{}, fmt.Errorf("%w: SignClientOriginReceipt requires a client_origin writer", ErrInvalidWriter)
	}
	if signer == nil {
		return Receipt{}, fmt.Errorf("%w: client origin signer is required", ErrInvalidReceipt)
	}
	publicKey := signer.PublicKey()
	if publicKey == nil {
		return Receipt{}, fmt.Errorf("%w: client origin signer has no public key", ErrInvalidReceipt)
	}
	if ssh.FingerprintSHA256(publicKey) != writer.Client.KeyFingerprint {
		return Receipt{}, fmt.Errorf("%w: signer fingerprint does not match registered client origin key", ErrInvalidReceipt)
	}
	payload, err := marshalClientOriginSignPayload(writer.ID, *writer.Client, binding, local)
	if err != nil {
		return Receipt{}, err
	}
	signature, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: sign client origin receipt: %v", ErrInvalidReceipt, err)
	}
	evidence := proofEvidence(local.EvidenceSHA256, local.EvidenceHash)
	receipt := Receipt{
		WriterID:         writer.ID,
		Kind:             WriterKindClientOrigin,
		Generation:       binding.Generation,
		ObservedAt:       local.ObservedAt,
		AdmissionsClosed: proofBool(local.AdmissionsClosed, local.ActualClosedAdmission),
		ResourcesClosed:  proofBool(local.ResourcesClosed, local.ResourceClosure),
		EvidenceSHA256:   evidence,
		Client: &ClientOriginReceipt{
			Origin:          *writer.Client,
			Binding:         binding,
			Local:           local,
			PublicKey:       publicKey.Marshal(),
			SignatureFormat: signature.Format,
			Signature:       append([]byte(nil), signature.Blob...),
		},
	}
	if err := verifyClientOriginReceipt(binding, writer, receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func marshalClientOriginSignPayload(writerID string, origin ClientOrigin, binding Binding, local LocalFenceReceipt) ([]byte, error) {
	payload := struct {
		Schema   string            `json:"schema"`
		WriterID string            `json:"writer_id"`
		Origin   ClientOrigin      `json:"origin"`
		Binding  Binding           `json:"binding"`
		Local    LocalFenceReceipt `json:"local"`
	}{Schema: "shuttle.client-origin-closure/v1", WriterID: writerID, Origin: origin, Binding: binding, Local: local}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical client origin payload: %v", ErrInvalidReceipt, err)
	}
	return data, nil
}

func verifyClientOriginReceipt(binding Binding, writer Writer, receipt Receipt) error {
	if writer.Kind != WriterKindClientOrigin || writer.Client == nil {
		return fmt.Errorf("%w: client receipt for %q is not bound to a client_origin writer", ErrInvalidReceipt, receipt.WriterID)
	}
	if receipt.Client == nil || receipt.Local != nil || receipt.Remote != nil {
		return fmt.Errorf("%w: client receipt for %q lacks authenticated client-origin proof", ErrInvalidReceipt, receipt.WriterID)
	}
	client := receipt.Client
	if client.Origin != *writer.Client {
		return fmt.Errorf("%w: client receipt for %q origin does not match the registered writer", ErrInvalidReceipt, receipt.WriterID)
	}
	if !sameBinding(client.Binding, binding) || client.Binding.Generation != receipt.Generation {
		return fmt.Errorf("%w: client receipt for %q operation binding does not match", ErrInvalidReceipt, receipt.WriterID)
	}
	if client.Origin.BootID != writer.Client.BootID || client.Origin.RunToken != writer.Client.RunToken || client.Origin.MachineID != writer.Client.MachineID || client.Origin.KeyFingerprint != writer.Client.KeyFingerprint || client.Origin.Group != writer.Client.Group {
		return fmt.Errorf("%w: client receipt for %q machine, boot, token, key, or group does not match", ErrInvalidReceipt, receipt.WriterID)
	}
	if client.Local.ObservedAt != receipt.ObservedAt || proofBool(client.Local.AdmissionsClosed, client.Local.ActualClosedAdmission) != proofBool(receipt.AdmissionsClosed, receipt.ActualClosedAdmission) || proofBool(client.Local.ResourcesClosed, client.Local.ResourceClosure) != proofBool(receipt.ResourcesClosed, receipt.ResourceClosure) {
		return fmt.Errorf("%w: client receipt for %q outer flags do not match the authenticated local payload", ErrInvalidReceipt, receipt.WriterID)
	}
	evidence := proofEvidence(receipt.EvidenceSHA256, receipt.EvidenceHash)
	if err := validateKernelLocalReceipt(binding, writer.Client.Group, &client.Local, evidence, receipt.WriterID); err != nil {
		return err
	}
	if len(client.PublicKey) == 0 || client.SignatureFormat == "" || len(client.Signature) == 0 {
		return fmt.Errorf("%w: client receipt for %q is missing a signature", ErrInvalidReceipt, receipt.WriterID)
	}
	publicKey, err := ssh.ParsePublicKey(client.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: client receipt for %q public key is not valid SSH wire encoding", ErrInvalidReceipt, receipt.WriterID)
	}
	fingerprint := ssh.FingerprintSHA256(publicKey)
	if fingerprint != writer.Client.KeyFingerprint || fingerprint != client.Origin.KeyFingerprint {
		return fmt.Errorf("%w: client receipt for %q key fingerprint does not match the registered writer", ErrInvalidReceipt, receipt.WriterID)
	}
	payload, err := marshalClientOriginSignPayload(writer.ID, client.Origin, client.Binding, client.Local)
	if err != nil {
		return err
	}
	if err := publicKey.Verify(payload, &ssh.Signature{Format: client.SignatureFormat, Blob: client.Signature}); err != nil {
		return fmt.Errorf("%w: client receipt for %q signature is not authentic", ErrInvalidReceipt, receipt.WriterID)
	}
	return nil
}
