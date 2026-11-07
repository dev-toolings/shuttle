package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backuplifecycle"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func backupMonitoringExpectsRemote(cfg *config.Config) bool {
	return cfg != nil && cfg.Monitoring != nil && cfg.Monitoring.Enabled && cfg.Monitoring.Backup.Expected
}

// negotiateBackupLifecycle performs the capability audit before the source
// process can quiesce services or write an archive. An old helper remains a
// valid local-backup target for unmanaged apps unless the operator explicitly
// configured remote backup proof. Managed PostgreSQL also requires its destroy
// safety capability before capture.
func negotiateBackupLifecycle(cfg *config.Config, client *shuttlessh.Client, host string) (bool, error) {
	group, _, err := singleVPS(cfg)
	if err != nil {
		return false, err
	}
	report, err := queryRootHelperCapabilitiesWithClient(group, host, client)
	return interpretManagedBackupLifecycleCapability(cfg != nil && cfg.Database.Managed(), backupMonitoringExpectsRemote(cfg), err, report)
}

// interpretBackupLifecycleCapability decides whether remote publication is
// available before capture has any effect. A required monitoring proof refuses
// an old helper immediately. Without that proof, a historical local backup
// remains valid.
func interpretBackupLifecycleCapability(expectsRemote bool, queryErr error, report rootHelperCapabilities) (bool, error) {
	if queryErr != nil {
		if rootHelperLacksCapabilities(queryErr) {
			if expectsRemote {
				return false, fmt.Errorf("backup monitoring requires root helper capability %q; installed helper predates capability negotiation, run `shuttle helper update` before capture: %w", capabilityBackupLifecycle, queryErr)
			}
			return false, nil
		}
		return false, fmt.Errorf("cannot negotiate backup lifecycle capability before capture: %w", queryErr)
	}
	if err := requireRootHelperCapabilities(report, []string{capabilityBackupLifecycle}); err != nil {
		if expectsRemote {
			return false, fmt.Errorf("backup monitoring requires root helper capability %q; run `shuttle helper update` before capture: %w", capabilityBackupLifecycle, err)
		}
		return false, nil
	}
	return true, nil
}

func interpretManagedBackupLifecycleCapability(managed, expectsRemote bool, queryErr error, report rootHelperCapabilities) (bool, error) {
	if managed {
		if queryErr != nil {
			return false, fmt.Errorf("managed PostgreSQL safety requires capability %s; run `shuttle helper update --dry-run`, then `shuttle helper update --yes`: %w", capabilityDestroyLedgerOnly, queryErr)
		}
		if err := requireRootHelperCapabilities(report, []string{capabilityDestroyLedgerOnly}); err != nil {
			return false, fmt.Errorf("%w; managed PostgreSQL safety requires a helper with %s: run `shuttle helper update --dry-run`, then `shuttle helper update --yes`", err, capabilityDestroyLedgerOnly)
		}
	}
	return interpretBackupLifecycleCapability(expectsRemote, queryErr, report)
}

func markSourceCaptureComplete(status *backupLifecycleStatus, now time.Time) {
	status.SourceCapture = backuplifecycle.StageComplete
	status.Phase = backuplifecycle.PhaseSourceDone
	status.UpdatedAt = lifecycleTimestamp(now)
}

// UUID operation IDs begin with a numeric hex digit 10/16 of the time, while
// lifecycle attempt IDs must begin with a letter. The fixed prefix keeps every
// backup attempt valid by construction without weakening the shared validator.
func backupLifecycleAttemptID(operationID string) string {
	return "backup-" + operationID
}

func markEncryptionComplete(status *backupLifecycleStatus, now time.Time) {
	status.Encryption = backuplifecycle.StageComplete
	// v0.0.56 published encryption under the already-published source phase.
	// The helper rejected that duplicate, then rejected the failure status as
	// inventing encryption; give this completion its own admitted phase.
	status.Phase = backuplifecycle.PhaseEncryptionDone
	status.UpdatedAt = lifecycleTimestamp(now)
}

func markLifecycleFailure(status *backupLifecycleStatus, now time.Time) {
	status.State = backuplifecycle.StateFailed
	status.Phase = backuplifecycle.PhaseFailed
	status.Error = "backup lifecycle stage failed"
	status.UpdatedAt = lifecycleTimestamp(now)
	if status.SourceCapture != backuplifecycle.StageComplete {
		status.SourceCapture = backuplifecycle.StageFailed
		return
	}
	if status.Encryption != backuplifecycle.StageComplete {
		status.Encryption = backuplifecycle.StageFailed
		return
	}
	if status.Receipt != backuplifecycle.StageComplete {
		status.Receipt = backuplifecycle.StageFailed
	}
}

func lifecycleTimestamp(now time.Time) string { return now.UTC().Format(time.RFC3339Nano) }

func persistLocalLifecycle(path string, status backupLifecycleStatus) error {
	body, err := backuplifecycle.Marshal(status)
	if err != nil {
		return err
	}
	return backuplifecycle.WriteStatusFile(path, append(body, '\n'))
}

func lifecycleFailure(primary error, localErr, remoteErr error) error {
	parts := []error{primary}
	if localErr != nil {
		parts = append(parts, fmt.Errorf("local backup lifecycle status was not saved: %w", localErr))
	}
	if remoteErr != nil {
		parts = append(parts, fmt.Errorf("remote backup lifecycle publication failed: %w", remoteErr))
	}
	return errors.Join(parts...)
}
