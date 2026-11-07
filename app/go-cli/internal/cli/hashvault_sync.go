package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/spf13/cobra"
)

func newHashvaultSyncCommand() *cobra.Command {
	var flags configFlags
	cmd := &cobra.Command{Use: "sync", Short: "Confirm the currently healthy Hashvault-backed release", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) (operationErr error) {
		cfg, err := loadWithFlags(flags)
		if err != nil {
			return err
		}
		if !cfg.UsesHashvaultSecrets() {
			return errors.New("secrets sync requires secrets.backend: hashvault")
		}
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
		if err := ensureRequiredRootHelperCapabilities(cfg, group, host, client); err != nil {
			return err
		}
		keyPath, _, err := ensureRootOperationKeyPair()
		if err != nil {
			return err
		}
		key, err := rootplan.ReadPrivateKey(keyPath)
		if err != nil {
			return err
		}
		operation, err := beginRemoteOperation(client, identity, key, "secrets-sync", cfg.App)
		if err != nil {
			return err
		}
		// A pending confirmation is reported to the operator but is not an
		// operation failure: the host is unchanged, so the operation finishes
		// cleanly and the next sync, deploy or rollback is not fenced.
		var pending error
		defer func() {
			operation.finish(&operationErr)
			if operationErr == nil {
				operationErr = pending
			}
		}()
		plan, err := rootplan.NewHashvaultSyncAction(cfg.App, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
		if err == nil {
			plan, err = bindOperationPlan(plan, operation.id, "secrets-sync", cfg.App)
		}
		if err == nil {
			plan, err = rootplan.Sign(plan, key)
		}
		if err != nil {
			return err
		}
		envelope, err := encodeRootHelperEnvelope(plan, nil)
		if err != nil {
			return err
		}
		// The SSH default of two minutes is shorter than the helper's own
		// convergence check plus the confirmation it then waits for.
		client.SetOperationTimeout(hashvaultSyncStackWait + hashvaultSyncConfirmBudget + rootHelperOperationMargin)
		result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
		outcome, err := hashvaultSyncOutcome(result.Code, result.Stdout, result.Stderr)
		if err != nil {
			return err
		}
		switch outcome {
		case hashvaultSyncPendingMarker:
			pending = fmt.Errorf("hashvault confirmation is still pending: %s; run shuttle secrets sync again once the vault is unsealed and the release has converged", strings.TrimSpace(result.Stderr))
		case hashvaultSyncNoReleaseMarker:
			pending = errors.New(errHashvaultNoReleaseText)
		default:
			fmt.Fprintln(cmd.OutOrStdout(), "Hashvault release confirmation synchronized.")
		}
		return nil
	}}
	addConfigFlags(cmd, &flags)
	return cmd
}

// Marker lines the helper prints, each on a line of its own, before its usual
// operation=... trailer. Exit status alone
// cannot carry "pending": a non-zero exit aborts the operation, which fences
// the application until recovery.
const (
	hashvaultSyncPendingMarker   = "hashvault-sync=pending"
	hashvaultSyncConfirmedMarker = "hashvault-sync=confirmed"
	hashvaultSyncNoReleaseMarker = "hashvault-sync=no-release"
	errHashvaultNoReleaseText    = "the current release carries no Hashvault preparation; deploy it with secrets.backend: hashvault first"
)

// hashvaultSyncOutcome reads the helper's answer. No marker, or both, on a
// zero exit is a helper that does not speak this protocol: refused, never read
// as a confirmation.
func hashvaultSyncOutcome(code int, stdout, stderr string) (string, error) {
	if code != 0 {
		return "", fmt.Errorf("hashvault sync failed: %s; the operation needs shuttle operations recover before the next sync", strings.TrimSpace(stderr))
	}
	found := []string{}
	for _, line := range strings.Split(stdout, "\n") {
		switch line = strings.TrimSpace(line); line {
		case hashvaultSyncConfirmedMarker, hashvaultSyncPendingMarker, hashvaultSyncNoReleaseMarker:
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		return "", errors.New("root helper did not report a single hashvault sync outcome")
	}
	return found[0], nil
}
