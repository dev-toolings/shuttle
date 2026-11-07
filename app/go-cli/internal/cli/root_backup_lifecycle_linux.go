//go:build linux

package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backuplifecycle"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

// publishRootBackupStatus is intentionally independent from monitoring
// installation. Backup evidence remains available when monitoring is disabled,
// and a failed monitoring install cannot turn a valid archive into an
// unobservable one.
func publishRootBackupStatus(plan rootplan.Plan, payload []byte) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		status, err := validateRootBackupStatusPayload(plan, payload, time.Now().UTC())
		if err != nil {
			return err
		}
		store := backuplifecycle.Store{Root: backuplifecycle.DefaultRoot}
		if err := store.Apply(status); err != nil {
			return fmt.Errorf("persist backup lifecycle status: %w", err)
		}
		return nil
	})
}

func validateRootBackupStatusPayload(plan rootplan.Plan, payload []byte, now time.Time) (backuplifecycle.Status, error) {
	if plan.BackupStatus == nil || !rootAppName.MatchString(plan.BackupStatus.App) {
		return backuplifecycle.Status{}, errors.New("invalid backup status operation")
	}
	if rootplan.PayloadDigest(payload) != plan.BackupStatus.PayloadSHA256 {
		return backuplifecycle.Status{}, errors.New("backup status payload does not match the signed digest")
	}
	status, err := backuplifecycle.Decode(payload)
	if err != nil {
		return backuplifecycle.Status{}, fmt.Errorf("invalid backup status payload: %w", err)
	}
	if status.App != plan.BackupStatus.App || status.AttemptID != plan.BackupStatus.OperationID {
		return backuplifecycle.Status{}, errors.New("backup status payload does not match the signed operation")
	}
	if status.HostKey != plan.RequiredHostFingerprint {
		return backuplifecycle.Status{}, errors.New("backup status host fingerprint does not match the signed operation")
	}
	created, err := time.Parse(time.RFC3339Nano, status.CreatedAt)
	updated, updatedErr := time.Parse(time.RFC3339Nano, status.UpdatedAt)
	if err != nil || updatedErr != nil || created.After(now.Add(2*time.Minute)) || updated.After(now.Add(2*time.Minute)) {
		return backuplifecycle.Status{}, errors.New("backup status timestamp is invalid or from the future")
	}
	return status, nil
}
