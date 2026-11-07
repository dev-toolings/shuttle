package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

type registeredOperationWriter struct {
	writer operationwriters.Writer
	fence  func(operationwriters.Binding) (operationwriters.Receipt, error)
}

// Keep the transport separate from writer signing and closure validation so
// local protocol tests exercise the real inventory rather than bypassing it.
var remoteOperationWriterRequest = func(o *remoteOperation, envelope []byte) shuttlessh.Result {
	return o.client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
}

func (o *remoteOperation) writerTransition(action string, payload rootplan.OperationWriters) (operationwriters.State, error) {
	plan, err := rootplan.NewOperationWriters(action, o.id, o.kind, o.app, o.identity.OperatorKeyFingerprint, o.identity.HostKeyFingerprint, payload, time.Now(), 2*time.Minute)
	if err == nil {
		plan, err = rootplan.Sign(plan, o.key)
	}
	if err != nil {
		return operationwriters.State{}, err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return operationwriters.State{}, err
	}
	reply := remoteOperationWriterRequest(o, envelope)
	if reply.Code != 0 {
		return operationwriters.State{}, fmt.Errorf("%s failed: %s", action, strings.TrimSpace(reply.Stderr))
	}
	var state operationwriters.State
	if err := decodeSingleJSON([]byte(reply.Stdout), &state); err != nil {
		return state, err
	}
	if err := state.Validate(); err != nil {
		return state, err
	}
	if state.Binding.OperationID != o.id || state.Binding.Generation != 1 || state.Binding.HostKey != o.identity.HostKeyFingerprint {
		return state, errors.New("writer response belongs to another reservation")
	}
	return state, nil
}

func (o *remoteOperation) registerWriter(writer operationwriters.Writer, fence func(operationwriters.Binding) (operationwriters.Receipt, error)) error {
	o.writerMu.Lock()
	defer o.writerMu.Unlock()
	if o.writersClosed {
		return errors.New("operation writer admissions are closed")
	}

	if fence == nil {
		return errors.New("writer registration requires a closure observer")
	}
	if _, err := o.writerTransition("operation-writer-register", rootplan.OperationWriters{Generation: 1, Writer: &writer}); err != nil {
		return err
	}
	o.writers = append(o.writers, registeredOperationWriter{writer: writer, fence: fence})
	return nil
}

func (o *remoteOperation) closeWriters() error {
	o.writersCloseOnce.Do(func() { o.writersCloseErr = o.closeWriterInventory() })
	return o.writersCloseErr
}

func (o *remoteOperation) closeWriterInventory() error {
	o.writerMu.Lock()
	defer o.writerMu.Unlock()
	o.writersClosed = true

	state, err := o.writerTransition("operation-writers-close", rootplan.OperationWriters{Generation: 1})
	if err != nil {
		return err
	}
	if len(state.Writers) != len(o.writers) {
		return errors.New("writer closure inventory changed during the operation")
	}
	receipts := make([]operationwriters.Receipt, 0, len(o.writers))
	for _, writer := range o.writers {
		receipt, err := writer.fence(state.Binding)
		if err != nil {
			return fmt.Errorf("writer %s closure unresolved: %w", writer.writer.ID, err)
		}
		receipts = append(receipts, receipt)
	}
	_, err = o.writerTransition("operation-writers-commit", rootplan.OperationWriters{Generation: 1, Receipts: receipts})
	return err
}

func (o *remoteOperation) registerSSHRunner(runner *shuttlessh.BuildRunner) error {
	identity, ok := runner.CurrentRunIdentity()
	if !ok {
		return errors.New("SSH builder has no active run identity")
	}
	writer := operationwriters.Writer{ID: "ssh-build-runner", Kind: operationwriters.WriterKindRemoteRunner, Remote: &operationwriters.RemoteRunner{HostKey: identity.RunnerHostKey, RunToken: identity.RunToken}}
	return o.registerWriter(writer, func(binding operationwriters.Binding) (operationwriters.Receipt, error) {
		proof, err := runner.Fence(identity.RunToken)
		if err != nil {
			return operationwriters.Receipt{}, err
		}
		return sshRunnerClosureReceipt(writer, binding, proof)
	})
}

// sshRunnerClosureReceipt is the shared typed proof for a live Fence and for
// ObserveClosedRun during writer recovery. Both paths must bind the same
// recorded host key, run token and generation; a successful process exit is
// not a receipt.
func sshRunnerClosureReceipt(writer operationwriters.Writer, binding operationwriters.Binding, proof shuttlessh.FenceResult) (operationwriters.Receipt, error) {
	if writer.Kind != operationwriters.WriterKindRemoteRunner || writer.Remote == nil {
		return operationwriters.Receipt{}, errors.New("SSH runner receipt requires a remote_runner writer")
	}
	if err := writer.Validate(); err != nil {
		return operationwriters.Receipt{}, err
	}
	if proof.Status != shuttlessh.FenceStatusFenced || proof.AdmissionState != "closed" || proof.RunnerHostKey != writer.Remote.HostKey || proof.RunToken != writer.Remote.RunToken {
		return operationwriters.Receipt{}, errors.New("SSH runner did not prove its resources fenced")
	}
	if binding.Generation == 0 {
		return operationwriters.Receipt{}, errors.New("SSH runner receipt requires a bound generation")
	}
	at := proof.FinishedAt.UTC().Format(time.RFC3339Nano)
	resourceIDs := append([]string(nil), proof.ActualContainerIDs...)
	remote := &operationwriters.RemoteRunnerReceipt{
		HostKey:            proof.RunnerHostKey,
		RunToken:           proof.RunToken,
		Generation:         binding.Generation,
		ObservedAt:         at,
		AdmissionsClosed:   true,
		ResourcesClosed:    true,
		ResourceIDs:        resourceIDs,
		TunnelID:           proof.TunnelIdentity,
		EvidenceSHA256:     proof.ProofHash,
		AuthenticatedProof: "SHU1-Fence/v1",
	}
	return operationwriters.Receipt{
		WriterID:         writer.ID,
		Kind:             writer.Kind,
		Generation:       binding.Generation,
		ObservedAt:       at,
		AdmissionsClosed: true,
		ResourcesClosed:  true,
		EvidenceSHA256:   proof.ProofHash,
		Remote:           remote,
	}, nil
}
