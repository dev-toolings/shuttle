//go:build linux

package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backuplifecycle"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestProducerHelperStoreRoundTrip(t *testing.T) {
	status := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-1", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: "2026-09-13T12:00:00Z", UpdatedAt: "2026-09-13T12:00:00Z", State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	body, err := backuplifecycle.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	plan := rootplan.Plan{BackupStatus: &rootplan.BackupStatusOperation{App: status.App, OperationID: status.AttemptID, PayloadSHA256: rootplan.PayloadDigest(body)}, RequiredHostFingerprint: status.HostKey}
	decoded, err := validateRootBackupStatusPayload(plan, body, time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store := backuplifecycle.Store{Root: root}
	if err := store.Apply(decoded); err != nil {
		t.Fatal(err)
	}
	journal, err := store.Load(status.App)
	if err != nil || journal.LatestAttempt == nil || journal.LatestAttempt.AttemptID != status.AttemptID || journal.LatestAttemptOrder != 1 {
		t.Fatalf("helper-decoded begin was not stored: %#v %v", journal, err)
	}
}

func TestRootBackupStatusAcceptsSuccessfulLocalLifecycleSequence(t *testing.T) {
	stamp := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	begin := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-local-sequence", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: lifecycleTimestamp(stamp), UpdatedAt: lifecycleTimestamp(stamp), State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	sourceDone := begin
	markSourceCaptureComplete(&sourceDone, stamp)
	encrypted := sourceDone
	markEncryptionComplete(&encrypted, stamp)
	receipt := encrypted
	receipt.Receipt = backuplifecycle.StageComplete
	receipt.ArchiveSHA256 = strings.Repeat("b", 64)
	receipt.Phase = backuplifecycle.PhaseReceipt
	complete := receipt
	complete.State = backuplifecycle.StateComplete
	complete.Phase = backuplifecycle.PhaseComplete
	statuses := []backupLifecycleStatus{begin, sourceDone, encrypted, receipt, complete}

	now := stamp.Add(time.Minute)
	var previous *backuplifecycle.Status
	for _, status := range statuses {
		body, err := backuplifecycle.Marshal(status)
		if err != nil {
			t.Fatalf("marshal %s status: %v", status.Phase, err)
		}
		plan := rootplan.Plan{BackupStatus: &rootplan.BackupStatusOperation{App: status.App, OperationID: status.AttemptID, PayloadSHA256: rootplan.PayloadDigest(body)}, RequiredHostFingerprint: status.HostKey}
		decoded, err := validateRootBackupStatusPayload(plan, body, now)
		if err != nil {
			t.Fatalf("helper rejected %s payload: %v", status.Phase, err)
		}
		if previous == nil {
			err = backuplifecycle.Validate(decoded)
		} else {
			err = backuplifecycle.ValidateTransition(*previous, decoded)
		}
		if err != nil {
			t.Fatalf("helper rejected %s transition: %v", status.Phase, err)
		}
		previous = &decoded
	}
	if previous == nil || previous.State != backuplifecycle.StateComplete {
		t.Fatalf("local lifecycle did not reach complete: %#v", previous)
	}
}

func TestRootBackupStatusBindsFullPayloadToSignedPlan(t *testing.T) {
	status := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-1", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: "2026-09-13T12:00:00Z", UpdatedAt: "2026-09-13T12:00:00Z", State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	body, err := backuplifecycle.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	plan := rootplan.Plan{BackupStatus: &rootplan.BackupStatusOperation{App: status.App, OperationID: status.AttemptID, PayloadSHA256: rootplan.PayloadDigest(body)}, RequiredHostFingerprint: status.HostKey}
	if _, err := validateRootBackupStatusPayload(plan, body, time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	plan.RequiredHostFingerprint = "SHA256:" + strings.Repeat("B", 43)
	if _, err := validateRootBackupStatusPayload(plan, body, time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC)); err == nil {
		t.Fatal("wrong required host fingerprint was accepted")
	}
}

func TestRootBackupStatusRejectsUnknownAndTrailingJSON(t *testing.T) {
	status := backupLifecycleStatus{Schema: backuplifecycle.Schema, App: "demo", AttemptID: "backup-1", Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: "2026-09-13T12:00:00Z", UpdatedAt: "2026-09-13T12:00:00Z", State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.CloudNotConfigured}
	body, err := backuplifecycle.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC)
	for _, invalid := range [][]byte{append(append([]byte{}, body...), []byte(`{"unexpected":true}`)...), []byte(strings.TrimSuffix(string(body), "}") + `,"unexpected":true}`)} {
		plan := rootplan.Plan{BackupStatus: &rootplan.BackupStatusOperation{App: status.App, OperationID: status.AttemptID, PayloadSHA256: rootplan.PayloadDigest(invalid)}, RequiredHostFingerprint: status.HostKey}
		_, decodeErr := validateRootBackupStatusPayload(plan, invalid, now)
		if decodeErr == nil {
			t.Fatal("invalid JSON payload was accepted")
		}
		if strings.Contains(decodeErr.Error(), "does not match the signed digest") {
			t.Fatalf("hash guard fired before JSON decode: %v", decodeErr)
		}
	}
}
