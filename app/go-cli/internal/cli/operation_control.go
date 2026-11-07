package cli

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// remoteOperation is owned by one invocation. Its finalizer runs after all
// registered writer cleanup, so a successful promotion alone never frees the
// durable reservation while BuildKit or a registry tunnel can still write.
type remoteOperation struct {
	id, kind, app         string
	promotion             string
	promotionAttempted    bool
	secretsPhaseAttempted bool
	refusedBeforeMutation bool
	refusalReason         string
	knownOutcome          bool
	knownOutcomeReason    string
	cleanupFailed         bool
	writers               []registeredOperationWriter
	writerMu              sync.Mutex
	writersClosed         bool
	writersCloseOnce      sync.Once
	writersCloseErr       error
	client                *shuttlessh.Client
	identity              trustedHostIdentity
	key                   ed25519.PrivateKey
}

var (
	remoteOperationCloseWriters = func(operation *remoteOperation) error { return operation.closeWriters() }
	remoteOperationProgress     = func(operation *remoteOperation, phase, result string) error {
		return operation.classifiedControl("operation-renew", phase, result)
	}
	remoteOperationControl = func(operation *remoteOperation, action, result string) error {
		return operation.classifiedControl(action, "", result)
	}
)

var operationKeepAliveInterval = time.Minute

type operationControlError struct{ ID, Action, Stderr string }

func (e *operationControlError) Error() string {
	return fmt.Sprintf("operation %s %s failed: %s", e.ID, e.Action, e.Stderr)
}

func beginRemoteOperation(client *shuttlessh.Client, identity trustedHostIdentity, key ed25519.PrivateKey, kind, app string) (*remoteOperation, error) {
	id, err := reserveRemoteOperation(client, identity, key, kind, app)
	if err != nil {
		return nil, err
	}
	return &remoteOperation{id: id, kind: kind, app: app, client: client, identity: identity, key: key}, nil
}

func (o *remoteOperation) control(action, result string) error {
	return o.sendControl(action, "", result)
}

// renewBeforePromotion is the renewal deploy sends after stopping keepAlive
// and before promotion. It classifies its failure like finish does: a raw
// "operation-renew failed" here, followed by finish's recovery line, was the
// same noise DEV-DEPL-47 removed elsewhere. keepAlive has already stopped its
// writers by then, so the status read never runs with a builder still writing.
func (o *remoteOperation) renewBeforePromotion() error {
	return remoteOperationControl(o, "operation-renew", "")
}

func (o *remoteOperation) classifiedControl(action, phase, result string) error {
	err := o.sendControl(action, phase, result)
	return classifyControlError(err, o.client, o.identity, o.key, o.id, o.kind)
}

func (o *remoteOperation) sendControl(action, phase, result string) error {
	plan, err := rootplan.NewOperationControl(action, o.id, o.kind, o.app, result, o.identity.OperatorKeyFingerprint, o.identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
	if err == nil && phase != "" {
		plan, err = rootplan.NewOperationProgress(o.id, o.kind, o.app, phase, result, o.identity.OperatorKeyFingerprint, o.identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, o.key)
	}
	if err != nil {
		return err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return err
	}
	reply := o.client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if reply.Code != 0 {
		return &operationControlError{ID: o.id, Action: action, Stderr: strings.TrimSpace(reply.Stderr)}
	}
	var record coord.Record
	if err := decodeSingleJSON([]byte(reply.Stdout), &record); err != nil {
		return fmt.Errorf("operation control returned invalid JSON: %w", err)
	}
	if record.ID != o.id || record.Kind != o.kind || record.App != o.app {
		return errors.New("operation control returned another reservation")
	}
	want := "active"
	if action == "operation-finish" {
		want = "completed"
	}
	if action == "operation-abort" {
		want = coord.RecoveryRequired
	}
	if action == "operation-refuse" {
		want = "failed"
	}
	if record.State != want {
		return fmt.Errorf("operation control returned state %q, expected %q", record.State, want)
	}
	return nil
}

func (o *remoteOperation) promotionResult() string {
	if o.promotion != "" {
		return o.promotion
	}
	if o.promotionAttempted && !o.refusedBeforeMutation {
		return "attempted-unverified"
	}
	return "not-started"
}

func (o *remoteOperation) finish(operationErr *error) {
	if o == nil {
		return
	}
	writersClosed := o.kind == "helper-update"
	if o.kind != "helper-update" {
		if err := remoteOperationCloseWriters(o); err != nil {
			o.cleanupFailed = true
			*operationErr = errors.Join(*operationErr, err)
		} else {
			writersClosed = true
		}
	}
	if o.kind == "deploy" {
		promotion := o.promotionResult()
		cleanup := "completed"
		if o.cleanupFailed {
			cleanup = "failed"
		}
		if !containsRecoveryHint(*operationErr) {
			progressErr := remoteOperationProgress(o, "client-promotion", promotion)
			*operationErr = errors.Join(*operationErr, progressErr)
			if !containsRecoveryHint(progressErr) && !containsRecoveryHint(*operationErr) {
				*operationErr = errors.Join(*operationErr, remoteOperationProgress(o, "client-cleanup", cleanup))
			}
		}
		// Only a failed deploy is refused. A deploy that ends without error and
		// without a promotion attempt (nothing to promote) must still finish:
		// refusing it would record a success as a failure.
		if *operationErr != nil && !containsRecoveryHint(*operationErr) && writersClosed && !o.cleanupFailed && !o.secretsPhaseAttempted && (!o.promotionAttempted || o.refusedBeforeMutation) {
			reason := cleanRootRefusalReason(o.refusalReason)
			if reason == "" {
				reason = "client failed before promotion"
			}
			result := rootRefusalControlPrefix + reason
			if err := remoteOperationControl(o, "operation-refuse", result); err == nil {
				return
			} else {
				*operationErr = errors.Join(*operationErr, err)
				if containsRecoveryHint(err) {
					return
				}
				o.abortWithRecoveryHint(operationErr, "promotion="+promotion+"; cleanup="+cleanup+"; actual state requires explicit observation")
				return
			}
		}
	}
	if !containsRecoveryHint(*operationErr) && o.refusedBeforeMutation && writersClosed && o.kind == "run" {
		result := "refused before any mutation: " + cleanRootRefusalReason(o.refusalReason)
		if err := remoteOperationControl(o, "operation-refuse", result); err == nil {
			return
		} else {
			*operationErr = errors.Join(*operationErr, err)
			if containsRecoveryHint(err) {
				return
			}
			o.abortWithRecoveryHint(operationErr, "operation or writer cleanup failed; actual state requires explicit observation")
			return
		}
	}
	if !containsRecoveryHint(*operationErr) && o.knownOutcome && (o.kind == "run" || o.kind == "destroy") && writersClosed {
		result := rootKnownOutcomeControlPrefix + cleanRootKnownOutcomeReason(o.knownOutcomeReason)
		if o.kind == "destroy" {
			result = "destroy failed with a known outcome: " + cleanRootKnownOutcomeReason(o.knownOutcomeReason)
		}
		if err := remoteOperationControl(o, "operation-refuse", result); err == nil {
			return
		} else {
			*operationErr = errors.Join(*operationErr, err)
			if containsRecoveryHint(err) {
				return
			}
			o.abortWithRecoveryHint(operationErr, "operation or writer cleanup failed; actual state requires explicit observation")
			return
		}
	}
	action, result := "operation-finish", "all requested changes verified; client and remote writer cleanup completed"
	if *operationErr != nil {
		action, result = "operation-abort", "operation or writer cleanup failed; actual state requires explicit observation"
		if o.kind == "deploy" {
			promotion := o.promotionResult()
			cleanup := "completed"
			if o.cleanupFailed {
				cleanup = "failed"
			}
			result = "promotion=" + promotion + "; cleanup=" + cleanup + "; actual state requires explicit observation"
		}
	}
	if !containsRecoveryHint(*operationErr) {
		if action == "operation-abort" {
			o.abortWithRecoveryHint(operationErr, result)
		} else if err := remoteOperationControl(o, action, result); err != nil {
			*operationErr = errors.Join(*operationErr, err)
		}
	}
	if o.kind == "deploy" && o.cleanupFailed && *operationErr != nil {
		promotion := o.promotionResult()
		*operationErr = fmt.Errorf("promotion=%s; cleanup=failed: %w", promotion, *operationErr)
	}
}

// keepAlive supervises a client-side build/export interval. Stop it before a
// root phase, which renews its own lease while it holds its executor flock. A
// renewal failure closes the writers and remains an error even if build exits 0.
func (o *remoteOperation) keepAlive(stopWriters func() error) func() error {
	done := make(chan struct{})
	exited := make(chan struct{})
	var once sync.Once
	var failure error
	go func() {
		defer close(exited)
		timer := time.NewTicker(operationKeepAliveInterval)
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				if err := o.control("operation-renew", ""); err != nil {
					stopErr := stopWriters()
					classified := classifyControlError(err, o.client, o.identity, o.key, o.id, o.kind)
					failure = errors.Join(classified, stopErr)
					return
				}
			}
		}
	}()
	return func() error { once.Do(func() { close(done) }); <-exited; return failure }
}

func mergeOperationCleanupError(operationErr *error, operation *remoteOperation, cleanupErr error) {
	if cleanupErr != nil && operation != nil {
		operation.cleanupFailed = true
	}
	if cleanupErr == nil {
		return
	}
	if *operationErr == nil {
		*operationErr = cleanupErr
		return
	}
	if errors.Is(*operationErr, cleanupErr) {
		return
	}
	*operationErr = fmt.Errorf("%w; cleanup also failed: %w", *operationErr, cleanupErr)
}

// abortWithRecoveryHint sends operation-abort and, when it succeeds, names the
// recovery. A successful abort is the CLI itself moving the record to
// recovery_required (sendControl checks that state), so the operator must be
// told what to run next: before, a promotion transport failure or a writer
// cleanup failure ended with the original error alone, and the next deploy was
// refused with no hint. A failed abort keeps its error, or the classified
// recovery line when the helper had already closed the record.
func (o *remoteOperation) abortWithRecoveryHint(operationErr *error, result string) {
	if err := remoteOperationControl(o, "operation-abort", result); err != nil {
		*operationErr = errors.Join(*operationErr, err)
		return
	}
	*operationErr = errors.Join(*operationErr, recoveryHint(o.id, o.kind))
}

func containsRecoveryHint(err error) bool {
	var hint *operationRequiresRecoveryError
	return errors.As(err, &hint)
}
