package cli

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

const (
	destroyDrainCeiling  = 5 * time.Minute
	destroyClientTimeout = preRunDumpDeadline + destroyDrainCeiling + rootHelperOperationMargin
)

func destroyStack(cfg *config.Config, out io.Writer, dropDatabases, dryRun bool) (operationErr error) {
	group, host, err := singleVPS(cfg)
	if err != nil {
		return err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return err
	}
	report, err := queryRootHelperCapabilitiesWithClient(group, host, client)
	if err != nil {
		if rootHelperLacksCapabilities(err) {
			return fmt.Errorf("the root helper on %s predates the destroy fix and could drop a database it did not create; run shuttle helper update --dry-run, then shuttle helper update --yes", host)
		}
		return fmt.Errorf("cannot verify the destroy capability of the root helper on %s: %w", host, err)
	}
	if err := destroyCapabilityDecision(report, host); err != nil {
		return err
	}
	client.SetOperationTimeout(destroyClientTimeout)
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return err
	}
	var lease *remoteOperation
	plan, err := newDestroyOperationPlan(cfg.App, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, dropDatabases, dryRun, func() (string, error) {
		var reserveErr error
		lease, reserveErr = beginRemoteOperation(client, identity, privateKey, "destroy", cfg.App)
		if reserveErr != nil {
			return "", reserveErr
		}
		return lease.id, nil
	}, time.Now)
	if lease != nil {
		defer lease.finish(&operationErr)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return err
	}
	// Stream the exact targets and dump paths before the helper starts removal;
	// buffering until exit would hide the safety report until after deletion.
	result := client.RunWithStreams("sudo -n /usr/local/libexec/shuttle-root apply", bytes.NewReader(envelope), out)
	return reportDestroyResult(out, result, lease)
}

func destroyCapabilityDecision(report rootHelperCapabilities, host string) error {
	if !slices.Contains(report.Features, capabilityDestroyLedgerOnly) {
		return fmt.Errorf("the root helper on %s predates the destroy fix and could drop a database it did not create; run shuttle helper update --dry-run, then shuttle helper update --yes", host)
	}
	if !slices.Contains(report.Features, capabilityDestroyRecovery) {
		return fmt.Errorf("the root helper on %s cannot recover an interrupted destroy; run shuttle helper update --dry-run, then shuttle helper update --yes", host)
	}
	if !slices.Contains(report.Features, capabilityDestroySafeOptions) {
		return fmt.Errorf("the root helper on %s lacks explicit database consent, pre-destroy dumps and read-only preview; run shuttle helper update --dry-run, then shuttle helper update --yes", host)
	}
	return nil
}

func isDestroyDryRun(plan rootplan.Plan) bool {
	return plan.Action == "stack-apply" && plan.Stack != nil && plan.Stack.Remove && plan.Stack.DryRun
}

func reportDestroyResult(out io.Writer, result shuttlessh.Result, lease *remoteOperation) error {
	if lease != nil && result.Code != 0 {
		lease.knownOutcomeReason, lease.knownOutcome = knownRunOutcomeReason(result.Stderr)
	}
	if result.Stdout != "" {
		if _, err := fmt.Fprint(out, result.Stdout); err != nil {
			return err
		}
	}
	if result.Code != 0 {
		return fmt.Errorf("signed destroy failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

func newDestroyOperationPlan(app, operator, host string, drop, dry bool, reserve func() (string, error), now func() time.Time) (rootplan.Plan, error) {
	var id string
	if !dry {
		var err error
		id, err = reserve()
		if err != nil {
			return rootplan.Plan{}, err
		}
	}
	// Reservation can wait longer than the two-minute signed plan lifetime.
	// Start that lifetime only after admission, never while waiting in line.
	plan, err := rootplan.NewStackRemove(app, operator, host, now(), 2*time.Minute)
	if err != nil {
		return rootplan.Plan{}, err
	}
	plan.Stack.DropDatabases, plan.Stack.DryRun = drop, dry
	if !dry {
		return bindOperationPlan(plan, id, "destroy", app)
	}
	return plan, nil
}
