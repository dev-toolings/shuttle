package backuplifecycle

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testStatus(attempt, phase string) Status {
	stamp := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	status := Status{Schema: Schema, App: "demo", AttemptID: attempt, Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: stamp, UpdatedAt: stamp, State: StatePending, Phase: PhaseSource, SourceCapture: StageNotStarted, Encryption: StageNotStarted, Receipt: StageNotStarted, Cloud: CloudNotConfigured}
	switch phase {
	case PhaseSourceDone:
		status.SourceCapture = StageComplete
		status.Phase = PhaseSourceDone
	case PhaseEncryptionDone:
		status.SourceCapture = StageComplete
		status.Encryption = StageComplete
		status.Phase = PhaseEncryptionDone
	case PhaseReceipt:
		status.SourceCapture = StageComplete
		status.Encryption = StageComplete
		status.Receipt = StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.Phase = PhaseReceipt
	case PhaseCloud:
		status.SourceCapture = StageComplete
		status.Encryption = StageComplete
		status.Receipt = StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.Cloud = CloudComplete
		status.Phase = PhaseCloud
	case PhaseCloudFailed:
		status.SourceCapture = StageComplete
		status.Encryption = StageComplete
		status.Receipt = StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.Cloud = CloudFailed
		status.State = StateFailed
		status.Phase = PhaseCloudFailed
	case PhaseComplete:
		status.SourceCapture = StageComplete
		status.Encryption = StageComplete
		status.Receipt = StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.State = StateComplete
		status.Phase = PhaseComplete
	case PhaseFailed:
		status.SourceCapture = StageFailed
		status.State = StateFailed
		status.Phase = PhaseFailed
	}
	return status
}

func testCloudStatus(attempt, phase string) Status {
	status := testStatus(attempt, phase)
	switch phase {
	case PhaseSource, PhaseSourceDone, PhaseEncryptionDone, PhaseReceipt:
		status.Cloud = StageNotStarted
	case PhaseComplete:
		status.Cloud = CloudComplete
	}
	return status
}

func TestDecodeIsStrictAndBounded(t *testing.T) {
	status := testStatus("backup-1", PhaseSource)
	body, err := Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append(body, []byte(`{"extra":true}`)...)); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
	unknown := strings.TrimSuffix(string(body), "}") + `,"unexpected":"value"}`
	if _, err := Decode([]byte(unknown)); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if _, err := Decode([]byte(strings.Replace(string(body), `"host_key":"`, `"host_key":"wrong`, 1))); err == nil {
		t.Fatal("wrong host fingerprint was accepted")
	}
}

func TestValidateTransitionBindsImmutableFieldsAndStages(t *testing.T) {
	begin := testStatus("backup-1", PhaseSource)
	sourceDone := testStatus("backup-1", PhaseSourceDone)
	receipt := testStatus("backup-1", PhaseReceipt)
	if err := ValidateTransition(begin, sourceDone); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTransition(sourceDone, receipt); err != nil {
		t.Fatal(err)
	}
	wrongHost := sourceDone
	wrongHost.Host = "other.example"
	if err := ValidateTransition(begin, wrongHost); err == nil {
		t.Fatal("host change was accepted")
	}
	wrongCreated := sourceDone
	wrongCreated.CreatedAt = time.Date(2026, 9, 13, 11, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if err := ValidateTransition(begin, wrongCreated); err == nil {
		t.Fatal("created_at change was accepted")
	}
	digestB := receipt
	digestB.ArchiveSHA256 = strings.Repeat("c", 64)
	digestB.Phase = PhaseCloud
	digestB.Cloud = CloudComplete
	configuredReceipt := testCloudStatus("backup-1", PhaseReceipt)
	if err := ValidateTransition(configuredReceipt, digestB); err == nil {
		t.Fatal("receipt digest A advancing to cloud digest B was accepted")
	}
	if err := ValidateTransition(receipt, begin); err == nil {
		t.Fatal("completed source stage was allowed to regress")
	}
	complete := testStatus("backup-1", PhaseComplete)
	if err := ValidateTransition(complete, receipt); err == nil {
		t.Fatal("completed backup was allowed to regress")
	}
	jumpedBegin := testStatus("backup-jump", PhaseSource)
	jumped := testCloudStatus("backup-jump", PhaseCloudFailed)
	jumped.CreatedAt = jumpedBegin.CreatedAt
	jumped.UpdatedAt = jumpedBegin.UpdatedAt
	if err := ValidateTransition(jumpedBegin, jumped); err == nil {
		t.Fatal("begin jumped directly to cloud_failed")
	}
}

func TestFailureAfterVerifiedReceiptDoesNotRegressStagesOrClaimCompletion(t *testing.T) {
	receipt := testStatus("backup-late-failure", PhaseReceipt)
	failed := receipt
	failed.State, failed.Phase, failed.Error = StateFailed, PhaseFailed, "archive cleanup failed"
	if err := ValidateTransition(receipt, failed); err != nil {
		t.Fatal(err)
	}
	if !LocalArtifactSuccess(failed) || failed.State == StateComplete {
		t.Fatal("late failure lost its archive identity or claimed completion")
	}
	failed.Error = ""
	if err := Validate(failed); err == nil {
		t.Fatal("late failure without an explanation was accepted")
	}
}

func TestSuccessfulLocalBackupPublicationSequence(t *testing.T) {
	source := testStatus("backup-local", PhaseSource)
	sourceDone := testStatus("backup-local", PhaseSourceDone)
	encrypted := testStatus("backup-local", PhaseEncryptionDone)
	receipt := testStatus("backup-local", PhaseReceipt)
	complete := testStatus("backup-local", PhaseComplete)
	sequence := []Status{source, sourceDone, encrypted, receipt, complete}
	for index := range sequence {
		if index == 0 {
			if err := Validate(sequence[index]); err != nil {
				t.Fatalf("validate source: %v", err)
			}
			continue
		}
		if err := ValidateTransition(sequence[index-1], sequence[index]); err != nil {
			t.Fatalf("validate %s transition: %v", sequence[index].Phase, err)
		}
	}
}

func TestFailureAfterEncryptionIsAccepted(t *testing.T) {
	encrypted := testStatus("backup-encryption-failure", PhaseEncryptionDone)
	failed := encrypted
	failed.State = StateFailed
	failed.Phase = PhaseFailed
	failed.Receipt = StageFailed
	failed.Error = "backup lifecycle stage failed"
	if err := ValidateTransition(encrypted, failed); err != nil {
		t.Fatalf("failed status after encryption was rejected: %v", err)
	}
}

func TestDecodeJournalLoadsV056SourcePhase(t *testing.T) {
	status := testStatus("backup-v056", PhaseSourceDone)
	journal := Journal{
		Schema:                JournalSchema,
		App:                   status.App,
		LatestAttempt:         &status,
		LatestAttemptOrder:    1,
		LatestAttemptReceived: status.UpdatedAt,
		AdmittedAttempts:      []AttemptAdmission{{AttemptID: status.AttemptID, Order: 1}},
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := DecodeJournal(body)
	if err != nil || loaded.LatestAttempt == nil || loaded.LatestAttempt.Phase != PhaseSourceDone {
		t.Fatalf("v0.0.56 journal phase did not load: %#v %v", loaded.LatestAttempt, err)
	}
}
