package backuplifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	Schema                  = "shuttle.application-backup-status/v2"
	JournalSchema           = "shuttle.application-backup-journal/v1"
	MaxStatusBytes          = 64 << 10
	MaxJournalBytes         = 256 << 10
	MaxErrorBytes           = 512
	maxAdmittedAttempts     = 64
	maxRetainedAdmissions   = 32
	journalWriteReserve     = 8 << 10
	compactedAttemptHashLen = 16
	StatePending            = "pending"
	StateFailed             = "failed"
	StateComplete           = "complete"
	StageNotStarted         = "not_started"
	StageComplete           = "complete"
	StageFailed             = "failed"
	CloudNotConfigured      = "not_configured"
	CloudComplete           = "complete"
	CloudFailed             = "failed"
	PhaseSource             = "source"
	PhaseSourceDone         = "source_capture_complete"
	PhaseEncryptionDone     = "encryption_complete"
	PhaseReceipt            = "receipt_verified"
	PhaseCloud              = "cloud_verified"
	PhaseCloudFailed        = "cloud_failed"
	PhaseComplete           = "complete"
	PhaseFailed             = "failed"
)

var (
	appPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	attemptPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	hostKeyPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Status is the signed producer-to-helper DTO. Every consumer decodes this
// exact shape so a producer cannot publish a field the helper or collector
// silently drops.
type Status struct {
	Schema        string `json:"schema"`
	App           string `json:"app"`
	AttemptID     string `json:"attempt_id"`
	Host          string `json:"host"`
	HostKey       string `json:"host_key"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	State         string `json:"state"`
	Phase         string `json:"phase"`
	SourceCapture string `json:"source_capture"`
	Encryption    string `json:"encryption"`
	Receipt       string `json:"receipt"`
	Cloud         string `json:"cloud"`
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`
	Error         string `json:"error,omitempty"`
}

// AttemptAdmission is the server-ordered identity of a BEGIN that was
// accepted under the VPS flock. Superseded IDs cannot start again.
type AttemptAdmission struct {
	AttemptID string `json:"attempt_id"`
	Order     uint64 `json:"order"`
}

// Journal is the root-owned durable view. LatestAttempt can fail without
// replacing LastSuccess, which is the proof of the last usable local archive
// and receipt, independent of optional cloud export.
type Journal struct {
	Schema                 string             `json:"schema"`
	App                    string             `json:"app"`
	LatestAttempt          *Status            `json:"latest_attempt,omitempty"`
	LastSuccess            *Status            `json:"last_success,omitempty"`
	LatestAttemptOrder     uint64             `json:"latest_attempt_order"`
	LatestAttemptReceived  string             `json:"latest_attempt_received_at,omitempty"`
	LastSuccessReceived    string             `json:"last_success_received_at,omitempty"`
	AdmittedAttempts       []AttemptAdmission `json:"admitted_attempts,omitempty"`
	CompactedAttemptHashes []string           `json:"compacted_attempt_hashes,omitempty"`
}

func DefaultStatusPath(app string) string {
	return "/var/lib/shuttle/backups/" + app + "/status.json"
}

func Validate(status Status) error {
	if status.Schema != Schema || !appPattern.MatchString(status.App) || !attemptPattern.MatchString(status.AttemptID) {
		return errors.New("invalid backup lifecycle coordinates")
	}
	if status.Host == "" || strings.ContainsAny(status.Host, "\r\n\t /\\") || !hostKeyPattern.MatchString(status.HostKey) {
		return errors.New("invalid backup lifecycle host binding")
	}
	created, err := parseTimestamp(status.CreatedAt)
	if err != nil {
		return errors.New("invalid backup lifecycle created_at")
	}
	updated, err := parseTimestamp(status.UpdatedAt)
	if err != nil || updated.Before(created) {
		return errors.New("invalid backup lifecycle updated_at")
	}
	if status.State != StatePending && status.State != StateFailed && status.State != StateComplete {
		return errors.New("invalid backup lifecycle state")
	}
	if !validStage(status.SourceCapture) || !validStage(status.Encryption) || !validStage(status.Receipt) {
		return errors.New("invalid backup lifecycle stage")
	}
	if status.Cloud != CloudNotConfigured && status.Cloud != StageNotStarted && status.Cloud != CloudComplete && status.Cloud != CloudFailed {
		return errors.New("invalid backup lifecycle cloud state")
	}
	if status.Phase != PhaseSource && status.Phase != PhaseSourceDone && status.Phase != PhaseEncryptionDone && status.Phase != PhaseReceipt && status.Phase != PhaseCloud && status.Phase != PhaseCloudFailed && status.Phase != PhaseComplete && status.Phase != PhaseFailed {
		return errors.New("invalid backup lifecycle phase")
	}
	if status.ArchiveSHA256 != "" && !digestPattern.MatchString(status.ArchiveSHA256) {
		return errors.New("invalid backup lifecycle archive identity")
	}
	if len(status.Error) > MaxErrorBytes || strings.ContainsAny(status.Error, "\r\n\t/\\") {
		return errors.New("backup lifecycle error is not bounded or redacted")
	}
	if status.Phase == PhaseReceipt || status.Phase == PhaseCloud || status.Phase == PhaseCloudFailed || status.Phase == PhaseComplete {
		if !localArtifactSuccess(status) {
			return errors.New("backup lifecycle receipt phase lacks a verified local artifact")
		}
	}
	if status.State == StateComplete && status.Phase != PhaseComplete {
		return errors.New("complete backup lifecycle must use the complete phase")
	}
	if status.State == StateFailed && status.Phase != PhaseFailed && status.Phase != PhaseCloudFailed {
		return errors.New("failed backup lifecycle must identify its failed phase")
	}
	if status.Phase == PhaseComplete && status.Cloud == CloudFailed {
		return errors.New("complete backup lifecycle cannot have a failed cloud stage")
	}
	if status.Phase == PhaseCloudFailed && status.Cloud != CloudFailed {
		return errors.New("cloud_failed phase requires a failed cloud stage")
	}
	if err := validateStageDependencies(status); err != nil {
		return err
	}
	switch status.Phase {
	case PhaseSource:
		if status.State != StatePending || status.SourceCapture != StageNotStarted || status.Encryption != StageNotStarted || status.Receipt != StageNotStarted || (status.Cloud != CloudNotConfigured && status.Cloud != StageNotStarted) || status.ArchiveSHA256 != "" {
			return errors.New("source phase has an invalid stage progression")
		}
	case PhaseSourceDone:
		if status.State != StatePending || status.SourceCapture != StageComplete || status.Receipt != StageNotStarted || (status.Encryption != StageNotStarted && status.Encryption != StageComplete) || (status.Cloud != CloudNotConfigured && status.Cloud != StageNotStarted) || status.ArchiveSHA256 != "" {
			return errors.New("source completion phase has an invalid stage progression")
		}
	case PhaseEncryptionDone:
		if status.State != StatePending || status.SourceCapture != StageComplete || status.Encryption != StageComplete || status.Receipt != StageNotStarted || (status.Cloud != CloudNotConfigured && status.Cloud != StageNotStarted) || status.ArchiveSHA256 != "" {
			return errors.New("encryption completion phase has an invalid stage progression")
		}
	case PhaseReceipt:
		if status.State != StatePending || (status.Cloud != CloudNotConfigured && status.Cloud != StageNotStarted) {
			return errors.New("receipt phase has an invalid stage progression")
		}
	case PhaseCloud:
		if status.State != StatePending || status.Cloud != CloudComplete {
			return errors.New("cloud phase has an invalid stage progression")
		}
	case PhaseCloudFailed:
		if status.State != StateFailed || status.Cloud != CloudFailed || !localArtifactSuccess(status) {
			return errors.New("cloud failure phase has an invalid stage progression")
		}
	case PhaseComplete:
		if status.State != StateComplete || (status.Cloud != CloudNotConfigured && status.Cloud != CloudComplete) {
			return errors.New("complete phase has an invalid stage progression")
		}
	case PhaseFailed:
		// Cleanup or coordination can fail after the local archive and receipt
		// were verified. Keep those completed stages truthful while recording
		// the failed attempt instead of claiming overall completion.
		lateFailure := localArtifactSuccess(status) && status.Error != ""
		if status.State != StateFailed || (!hasFailedLocalStage(status) && !lateFailure) {
			return errors.New("failed phase must record the actual failed stage or a failure after verified publication")
		}
	}
	return nil
}

func validateStageDependencies(status Status) error {
	if status.SourceCapture != StageComplete && (status.Encryption == StageComplete || status.Receipt == StageComplete) {
		return errors.New("later backup stages cannot complete before source capture")
	}
	if status.Encryption != StageComplete && status.Receipt == StageComplete {
		return errors.New("receipt cannot complete before encryption")
	}
	if status.SourceCapture == StageFailed && (status.Encryption != StageNotStarted || status.Receipt != StageNotStarted) {
		return errors.New("failed source capture cannot continue later stages")
	}
	if status.Encryption == StageFailed && status.Receipt != StageNotStarted {
		return errors.New("failed encryption cannot continue the receipt stage")
	}
	if localArtifactSuccess(status) && status.Receipt != StageComplete {
		return errors.New("verified local artifact requires a completed receipt")
	}
	return nil
}

func hasFailedLocalStage(status Status) bool {
	return status.SourceCapture == StageFailed || status.Encryption == StageFailed || status.Receipt == StageFailed
}

func validStage(value string) bool {
	return value == StageNotStarted || value == StageComplete || value == StageFailed
}

func localArtifactSuccess(status Status) bool {
	return status.SourceCapture == StageComplete && status.Encryption == StageComplete && status.Receipt == StageComplete && digestPattern.MatchString(status.ArchiveSHA256)
}

func LocalArtifactSuccess(status Status) bool { return localArtifactSuccess(status) }

func parseTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	return time.Parse(time.RFC3339Nano, value)
}

func Marshal(status Status) ([]byte, error) {
	if err := Validate(status); err != nil {
		return nil, err
	}
	body, err := json.Marshal(status)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxStatusBytes {
		return nil, errors.New("backup lifecycle status exceeds the size limit")
	}
	return body, nil
}

func Decode(body []byte) (Status, error) {
	if len(body) == 0 || len(body) > MaxStatusBytes {
		return Status{}, errors.New("backup lifecycle status exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var status Status
	if err := decoder.Decode(&status); err != nil {
		return Status{}, errors.New("decode backup lifecycle status")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Status{}, errors.New("backup lifecycle status must contain one JSON document")
	}
	if err := Validate(status); err != nil {
		return Status{}, err
	}
	return status, nil
}

func ValidateTransition(previous, next Status) error {
	if err := Validate(previous); err != nil {
		return err
	}
	if err := Validate(next); err != nil {
		return err
	}
	if previous.App != next.App || previous.AttemptID != next.AttemptID || previous.Host != next.Host || previous.HostKey != next.HostKey {
		return errors.New("backup lifecycle transition changes its binding")
	}
	if previous.CreatedAt != next.CreatedAt {
		return errors.New("backup lifecycle transition changes created_at")
	}
	if !cloudConfigurationCompatible(previous.Cloud, next.Cloud) {
		return errors.New("backup lifecycle transition changes cloud configuration")
	}
	if previous == next {
		return nil
	}
	if previous.State == StateComplete || previous.State == StateFailed {
		return errors.New("backup lifecycle transition follows a terminal state")
	}
	if completedStageRegressed(previous, next) {
		return errors.New("backup lifecycle completed stage regressed")
	}
	if previous.ArchiveSHA256 != "" && next.ArchiveSHA256 != previous.ArchiveSHA256 {
		return errors.New("backup lifecycle archive identity changed")
	}
	if previous.ArchiveSHA256 == "" && next.ArchiveSHA256 != "" && next.Phase != PhaseReceipt && next.Phase != PhaseFailed && next.Phase != PhaseCloudFailed && next.Phase != PhaseComplete && next.Phase != PhaseCloud {
		return errors.New("backup lifecycle archive identity appeared before receipt")
	}
	if phaseRank(next.Phase) < phaseRank(previous.Phase) {
		return errors.New("backup lifecycle phase regressed")
	}
	if phaseRank(next.Phase) == phaseRank(previous.Phase) {
		return errors.New("conflicting duplicate backup lifecycle phase")
	}
	// v0.0.56 and legacy clients can advance directly from source capture to a
	// verified receipt. Keep that transition valid while new producers publish
	// the separately admitted encryption phase.
	legacyDirectReceipt := previous.Phase == PhaseSourceDone && next.Phase == PhaseReceipt
	if next.Phase != PhaseFailed && next.Phase != PhaseCloudFailed && !legacyDirectReceipt && !(previous.Phase == PhaseReceipt && next.Phase == PhaseComplete && next.Cloud == CloudNotConfigured) && phaseRank(next.Phase) > phaseRank(previous.Phase)+1 {
		return errors.New("backup lifecycle phase skipped a required stage")
	}
	if next.Phase == PhaseCloudFailed {
		if previous.Phase != PhaseReceipt && previous.Phase != PhaseCloud {
			return errors.New("cloud failure skipped a required local receipt")
		}
		if !localArtifactSuccess(previous) {
			return errors.New("cloud failure requires an admitted local receipt")
		}
	}
	if next.Phase == PhaseFailed {
		if next.SourceCapture == StageComplete && previous.SourceCapture != StageComplete {
			return errors.New("failed backup invented a completed source stage")
		}
		if next.Encryption == StageComplete && previous.Encryption != StageComplete {
			return errors.New("failed backup invented a completed encryption stage")
		}
		if next.Receipt == StageComplete && previous.Receipt != StageComplete {
			return errors.New("failed backup invented a completed receipt stage")
		}
		if next.ArchiveSHA256 != "" && previous.ArchiveSHA256 != "" && next.ArchiveSHA256 != previous.ArchiveSHA256 {
			return errors.New("failed backup changed archive identity")
		}
		if next.ArchiveSHA256 != "" && previous.ArchiveSHA256 == "" && previous.Phase != PhaseReceipt && previous.Phase != PhaseCloud && previous.Phase != PhaseComplete {
			return errors.New("failed backup invented an archive identity")
		}
	}
	return nil
}

func cloudConfigurationCompatible(previous, next string) bool {
	previousConfigured := previous != CloudNotConfigured
	nextConfigured := next != CloudNotConfigured
	return previousConfigured == nextConfigured
}

func completedStageRegressed(previous, next Status) bool {
	return stageLostCompletion(previous.SourceCapture, next.SourceCapture) || stageLostCompletion(previous.Encryption, next.Encryption) || stageLostCompletion(previous.Receipt, next.Receipt) || (previous.Cloud == CloudComplete && next.Cloud != CloudComplete)
}

func stageLostCompletion(previous, next string) bool {
	return previous == StageComplete && next != StageComplete
}

func phaseRank(phase string) int {
	switch phase {
	case PhaseSource:
		return 1
	case PhaseSourceDone:
		return 2
	case PhaseEncryptionDone:
		return 3
	case PhaseReceipt:
		return 4
	case PhaseCloud:
		return 5
	case PhaseComplete:
		return 6
	case PhaseCloudFailed, PhaseFailed:
		return 7
	default:
		return 0
	}
}

func DecodeJournal(body []byte) (Journal, error) {
	if len(body) == 0 || len(body) > MaxJournalBytes {
		return Journal{}, errors.New("backup lifecycle journal exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var journal Journal
	if err := decoder.Decode(&journal); err != nil {
		return Journal{}, errors.New("decode backup lifecycle journal")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Journal{}, errors.New("backup lifecycle journal must contain one JSON document")
	}
	if err := ValidateJournal(journal); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

func ValidateJournal(journal Journal) error {
	if journal.Schema != JournalSchema || !appPattern.MatchString(journal.App) {
		return errors.New("invalid backup lifecycle journal")
	}
	if journal.LatestAttempt != nil {
		if err := Validate(*journal.LatestAttempt); err != nil {
			return fmt.Errorf("invalid latest backup attempt: %w", err)
		}
		if journal.LatestAttempt.App != journal.App {
			return errors.New("latest backup attempt belongs to another application")
		}
		if journal.LatestAttemptOrder == 0 {
			return errors.New("latest backup attempt order is missing")
		}
		if journal.LatestAttemptReceived == "" {
			return errors.New("latest backup receipt timestamp is missing")
		}
	} else if journal.LatestAttemptOrder != 0 || journal.LatestAttemptReceived != "" {
		return errors.New("backup journal has latest-attempt metadata without an attempt")
	}
	if journal.LastSuccess != nil {
		if err := Validate(*journal.LastSuccess); err != nil || journal.LastSuccess.App != journal.App || journal.LastSuccess.State == StateFailed || !LocalArtifactSuccess(*journal.LastSuccess) {
			return errors.New("invalid last successful backup")
		}
		if journal.LastSuccessReceived == "" {
			return errors.New("last successful receipt timestamp is missing")
		}
	} else if journal.LastSuccessReceived != "" {
		return errors.New("backup journal has last-success metadata without a success")
	}
	if err := validateAdmittedAttempts(journal); err != nil {
		return err
	}
	if err := validateCompactedAttemptHashes(journal.CompactedAttemptHashes); err != nil {
		return err
	}
	if journal.LatestAttemptReceived != "" {
		if _, err := parseTimestamp(journal.LatestAttemptReceived); err != nil {
			return errors.New("invalid latest backup receipt timestamp")
		}
	}
	if journal.LastSuccessReceived != "" {
		if _, err := parseTimestamp(journal.LastSuccessReceived); err != nil {
			return errors.New("invalid last successful receipt timestamp")
		}
	}
	return nil
}

func validateAdmittedAttempts(journal Journal) error {
	if len(journal.AdmittedAttempts) == 0 {
		if journal.LatestAttempt != nil {
			return errors.New("latest backup attempt is missing durable identity history")
		}
		return nil
	}
	seen := make(map[string]uint64, len(journal.AdmittedAttempts))
	var previous uint64
	for _, admission := range journal.AdmittedAttempts {
		if !attemptPattern.MatchString(admission.AttemptID) || admission.Order == 0 || admission.Order <= previous {
			return errors.New("backup journal identity history is not monotonically ordered")
		}
		if _, exists := seen[admission.AttemptID]; exists {
			return errors.New("backup journal identity history repeats an attempt")
		}
		seen[admission.AttemptID] = admission.Order
		previous = admission.Order
	}
	if journal.LatestAttempt == nil {
		return errors.New("backup journal identity history has no latest attempt")
	}
	order, ok := seen[journal.LatestAttempt.AttemptID]
	if !ok {
		return errors.New("latest backup attempt is not in identity history")
	}
	if order != journal.LatestAttemptOrder || previous != journal.LatestAttemptOrder {
		return errors.New("latest backup attempt order does not match identity history")
	}
	return nil
}

func validateCompactedAttemptHashes(hashes []string) error {
	seen := map[string]bool{}
	for _, value := range hashes {
		if len(value) != compactedAttemptHashLen {
			return errors.New("backup journal compacted identity is malformed")
		}
		for _, r := range value {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				return errors.New("backup journal compacted identity is malformed")
			}
		}
		if seen[value] {
			return errors.New("backup journal compacted identity repeats an attempt")
		}
		seen[value] = true
	}
	return nil
}
