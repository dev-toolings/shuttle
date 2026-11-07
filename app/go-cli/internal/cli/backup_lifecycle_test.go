package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backuplifecycle"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestPersistLocalLifecycleUsesTheSharedProducerDTO(t *testing.T) {
	stamp := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	status := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-1", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: stamp, UpdatedAt: stamp, State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	path := filepath.Join(t.TempDir(), "status.json")
	if err := persistLocalLifecycle(path, status); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backuplifecycle.Decode(body); err != nil {
		t.Fatalf("local producer DTO could not be decoded by the shared validator: %v", err)
	}
}

func TestBackupAttemptIDPrefixesDigitStartingOperationID(t *testing.T) {
	operationID := "01234567-89ab-cdef-0123-456789abcdef"
	attemptID := backupLifecycleAttemptID(operationID)
	if attemptID != "backup-"+operationID {
		t.Fatalf("unexpected lifecycle attempt ID: %q", attemptID)
	}
	status := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: attemptID, Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: "2026-09-13T12:00:00Z", UpdatedAt: "2026-09-13T12:00:00Z", State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	if err := backuplifecycle.Validate(status); err != nil {
		t.Fatalf("digit-leading operation ID did not produce a valid attempt ID: %v", err)
	}
}

func TestLifecycleFailureJoinsPublicationAndPrimaryErrors(t *testing.T) {
	primary := errors.New("archive failed")
	publication := errors.New("helper unavailable")
	err := lifecycleFailure(primary, nil, publication)
	if !errors.Is(err, primary) || !errors.Is(err, publication) {
		t.Fatalf("lifecycle failure hid one of its causes: %v", err)
	}
}

func TestBackupRemoteExpectationIsExplicit(t *testing.T) {
	cfg := &config.Config{Monitoring: &config.MonitoringConfig{Enabled: true}}
	if backupMonitoringExpectsRemote(cfg) {
		t.Fatal("remote backup proof was expected without backup monitoring")
	}
	cfg.Monitoring.Backup.Expected = true
	if !backupMonitoringExpectsRemote(cfg) {
		t.Fatal("configured backup proof was not expected")
	}
}

func TestOldHelperCapabilityNegotiationBeforeCapture(t *testing.T) {
	lacks := errors.New("unsupported audit operation")
	if publish, err := interpretBackupLifecycleCapability(true, lacks, rootHelperCapabilities{}); err == nil || publish {
		t.Fatal("monitoring-required old helper was allowed to capture")
	}
	if publish, err := interpretBackupLifecycleCapability(false, lacks, rootHelperCapabilities{}); err != nil || publish {
		t.Fatal("legacy local backup without remote proof was not preserved")
	}
	report := currentRootHelperCapabilities()
	if publish, err := interpretBackupLifecycleCapability(true, nil, report); err != nil || !publish {
		t.Fatal("current helper was not accepted")
	}
	stale := rootHelperCapabilities{Protocol: 1, Version: "old", Features: []string{capabilitySignedHelperUpdate}}
	if publish, err := interpretBackupLifecycleCapability(true, nil, stale); err == nil || publish {
		t.Fatal("missing backup-lifecycle capability was accepted")
	}
	if publish, err := interpretBackupLifecycleCapability(false, nil, stale); err != nil || publish {
		t.Fatal("legacy local outcome was not preserved for a helper without backup-lifecycle")
	}
}

func TestMarkLifecycleFailureRecordsTheActualStage(t *testing.T) {
	stamp := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	begin := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-1", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: lifecycleTimestamp(stamp), UpdatedAt: lifecycleTimestamp(stamp), State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	sourceFailed := begin
	markLifecycleFailure(&sourceFailed, stamp)
	if sourceFailed.SourceCapture != backuplifecycle.StageFailed || sourceFailed.Encryption != backuplifecycle.StageNotStarted || sourceFailed.Phase != backuplifecycle.PhaseFailed {
		t.Fatalf("source failure was not recorded: %#v", sourceFailed)
	}
	if err := backuplifecycle.Validate(sourceFailed); err != nil {
		t.Fatal(err)
	}
	sourceDone := begin
	markSourceCaptureComplete(&sourceDone, stamp)
	if sourceDone.SourceCapture != backuplifecycle.StageComplete || sourceDone.Phase != backuplifecycle.PhaseSourceDone {
		t.Fatalf("source success was not recorded immediately: %#v", sourceDone)
	}
	if err := backuplifecycle.Validate(sourceDone); err != nil {
		t.Fatal(err)
	}
	encryptionFailed := sourceDone
	markLifecycleFailure(&encryptionFailed, stamp)
	if encryptionFailed.SourceCapture != backuplifecycle.StageComplete || encryptionFailed.Encryption != backuplifecycle.StageFailed || encryptionFailed.Receipt != backuplifecycle.StageNotStarted {
		t.Fatalf("encryption close failure hid source success: %#v", encryptionFailed)
	}
	if err := backuplifecycle.Validate(encryptionFailed); err != nil {
		t.Fatal(err)
	}
	encrypted := sourceDone
	markEncryptionComplete(&encrypted, stamp)
	if encrypted.Encryption != backuplifecycle.StageComplete || encrypted.Receipt != backuplifecycle.StageNotStarted || encrypted.Phase != backuplifecycle.PhaseEncryptionDone {
		t.Fatalf("encryption success was recorded after receipt: %#v", encrypted)
	}
	if err := backuplifecycle.Validate(encrypted); err != nil {
		t.Fatal(err)
	}
	receiptFailedFromEncryption := encrypted
	markLifecycleFailure(&receiptFailedFromEncryption, stamp)
	if receiptFailedFromEncryption.Encryption != backuplifecycle.StageComplete || receiptFailedFromEncryption.Receipt != backuplifecycle.StageFailed {
		t.Fatalf("receipt failure was labeled encryption: %#v", receiptFailedFromEncryption)
	}
	if err := backuplifecycle.Validate(receiptFailedFromEncryption); err != nil {
		t.Fatal(err)
	}
}

func TestBackupFailureAfterEncryptionIsAcceptedByHelperValidator(t *testing.T) {
	stamp := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	begin := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-failure-after-encryption", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: lifecycleTimestamp(stamp), UpdatedAt: lifecycleTimestamp(stamp), State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	sourceDone := begin
	markSourceCaptureComplete(&sourceDone, stamp)
	encrypted := sourceDone
	markEncryptionComplete(&encrypted, stamp)
	failed := encrypted
	markLifecycleFailure(&failed, stamp)

	statuses := []backupLifecycleStatus{begin, sourceDone, encrypted, failed}
	for index := range statuses {
		if index == 0 {
			if err := backuplifecycle.Validate(statuses[index]); err != nil {
				t.Fatalf("helper rejected source status: %v", err)
			}
			continue
		}
		if err := backuplifecycle.ValidateTransition(statuses[index-1], statuses[index]); err != nil {
			t.Fatalf("helper rejected %s transition: %v", statuses[index].Phase, err)
		}
	}
	if failed.State != backuplifecycle.StateFailed || failed.Encryption != backuplifecycle.StageComplete {
		t.Fatalf("failure status did not preserve completed encryption: %#v", failed)
	}
}

func TestBackupCleanupFailureAfterPublicationRemainsFailedWithArchiveIntact(t *testing.T) {
	now := time.Now().UTC()
	status := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-late", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: lifecycleTimestamp(now), UpdatedAt: lifecycleTimestamp(now), State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseReceipt, SourceCapture: backuplifecycle.StageComplete, Encryption: backuplifecycle.StageComplete, Receipt: backuplifecycle.StageComplete, Cloud: backuplifecycle.CloudNotConfigured, ArchiveSHA256: strings.Repeat("b", 64)}
	before := status
	markLifecycleFailure(&status, now.Add(time.Second))
	if err := backuplifecycle.ValidateTransition(before, status); err != nil {
		t.Fatal(err)
	}
	if status.State != backuplifecycle.StateFailed || !backuplifecycle.LocalArtifactSuccess(status) {
		t.Fatal("cleanup failure corrupted truthful archive outcome")
	}
	path := filepath.Join(t.TempDir(), "status.json")
	if err := persistLocalLifecycle(path, status); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backuplifecycle.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.State != backuplifecycle.StateFailed {
		t.Fatal("persisted lifecycle falsely succeeded")
	}
}
