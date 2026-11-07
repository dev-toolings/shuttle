package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

const (
	helperMigrationSchema               = "shuttle.helper-migration/v1"
	helperMigrationPhaseReady           = "prepared"
	helperMigrationPhaseReplaced        = "replaced"
	helperMigrationPhaseComplete        = "completed"
	helperMigrationHistoryLimit         = 32
	helperMigrationOwnReservationKind   = "helper-update"
	helperMigrationOwnReservationSchema = "shuttle.helper-migration-own-reservation/v1"
)

var (
	helperMigrationIDPattern          = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	helperMigrationOperationIDPattern = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)
	helperMigrationPendingPattern     = regexp.MustCompile(`migration ([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}) is (prepared|replaced)`)
	helperMigrationDigestPattern      = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	helperMigrationFingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// helperMigrationIntent is the durable bridge between the legacy helper's
// signed replacement and the finalization understood by the new helper. It is
// deliberately small. In particular, it never carries a payload or a secret.
type helperMigrationIntent struct {
	Schema          string                       `json:"schema"`
	ID              string                       `json:"id"`
	Source          string                       `json:"source"`
	CandidateSHA256 string                       `json:"candidate_sha256"`
	Host            string                       `json:"host"`
	BootID          string                       `json:"boot_id"`
	Phase           string                       `json:"phase"`
	Probe           *helperMigrationProbeProof   `json:"probe,omitempty"`
	History         []helperMigrationHistoryItem `json:"history,omitempty"`
}

// helperMigrationProbeProof binds a retry to the exact process and lock
// context that created the intent. It is deliberately typed so a caller cannot
// turn a retry into an assertion based on a free-form proof string.
type helperMigrationProbeProof struct {
	CandidatePath    string   `json:"candidate_path"`
	CandidateArgv    []string `json:"candidate_argv"`
	ParentUID        uint32   `json:"parent_uid"`
	ParentPID        int      `json:"parent_pid"`
	ParentExecutable string   `json:"parent_executable"`
	ParentArgv       []string `json:"parent_argv"`
	ParentBirth      string   `json:"parent_birth"`
	LockDevice       uint64   `json:"lock_device"`
	LockInode        uint64   `json:"lock_inode"`
}

type helperMigrationHistoryItem struct {
	At     string `json:"at"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
}

func (proof *helperMigrationProbeProof) validate() error {
	if proof == nil {
		return nil
	}
	if !filepath.IsAbs(proof.CandidatePath) || filepath.Clean(proof.CandidatePath) != proof.CandidatePath || len(proof.CandidatePath) > 1024 {
		return errors.New("invalid helper migration candidate proof path")
	}
	if !helperMigrationSlicesEqual(proof.CandidateArgv, []string{"shuttle-root", "--help"}) {
		return errors.New("invalid helper migration candidate proof argv")
	}
	if proof.ParentUID != 0 || proof.ParentPID <= 0 || proof.ParentExecutable == "" || len(proof.ParentExecutable) > 1024 || filepath.Clean(proof.ParentExecutable) != proof.ParentExecutable || !helperMigrationSlicesEqual(proof.ParentArgv, []string{proof.ParentExecutable, "apply"}) {
		return errors.New("invalid helper migration parent proof")
	}
	if proof.ParentBirth == "" || len(proof.ParentBirth) > 64 || strings.ContainsAny(proof.ParentBirth, "\x00\r\n") || proof.LockDevice == 0 || proof.LockInode == 0 {
		return errors.New("invalid helper migration lock proof")
	}
	return nil
}

func helperMigrationSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (intent helperMigrationIntent) validate() error {
	if intent.Schema != helperMigrationSchema || !helperMigrationIDPattern.MatchString(intent.ID) {
		return errors.New("invalid helper migration intent identity")
	}
	if intent.Source == "" || len(intent.Source) > 1024 || strings.ContainsAny(intent.Source, "\x00\r\n") {
		return errors.New("invalid helper migration intent source")
	}
	separator := strings.LastIndexByte(intent.Source, '#')
	if separator <= 0 || !filepath.IsAbs(intent.Source[:separator]) || filepath.Clean(intent.Source[:separator]) != intent.Source[:separator] || !helperMigrationDigestPattern.MatchString(intent.Source[separator+1:]) {
		return errors.New("invalid helper migration intent source")
	}
	if !helperMigrationDigestPattern.MatchString(intent.CandidateSHA256) {
		return errors.New("invalid helper migration candidate digest")
	}
	if intent.Host == "" || len(intent.Host) > 256 || strings.ContainsAny(intent.Host, "\x00\r\n") {
		return errors.New("invalid helper migration host identity")
	}
	if intent.BootID == "" || len(intent.BootID) > 128 || strings.ContainsAny(intent.BootID, "\x00\r\n") {
		return errors.New("invalid helper migration boot identity")
	}
	switch intent.Phase {
	case helperMigrationPhaseReady, helperMigrationPhaseReplaced, helperMigrationPhaseComplete:
	default:
		return errors.New("invalid helper migration phase")
	}
	if err := intent.Probe.validate(); err != nil {
		return err
	}
	if len(intent.History) > helperMigrationHistoryLimit {
		return errors.New("helper migration history exceeds its bound")
	}
	for _, item := range intent.History {
		if item.At == "" || item.Action == "" || len(item.At) > 64 || len(item.Action) > 128 || len(item.Detail) > 512 || strings.ContainsAny(item.At+item.Action+item.Detail, "\x00\r\n") {
			return errors.New("invalid helper migration history item")
		}
	}
	return nil
}

func newHelperMigrationID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate helper migration ID: %w", err)
	}
	encoded := hex.EncodeToString(bytes)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

// helperMigrationFinalizeRequest is the small caller-to-parent contract. The
// parent owns the rootplan constructor and transport because that wire action
// is intentionally not part of this isolated migration worktree.
type helperMigrationFinalizeRequest struct {
	CandidateSHA256 string
	Host            string
	IntentID        string
	PlanExpiresAt   time.Time
	Validate        func() error
}

type helperMigrationFinalizer func(*shuttlessh.Client, trustedHostIdentity, helperMigrationFinalizeRequest) error

// helperMigrationOwnReservationProof is the narrow parent-to-candidate
// contract for a modern helper-update. The candidate may admit one active
// journal record only when every field matches this proof. An unsigned
// journal row is never enough: a second helper-update, a deploy, or a
// mismatched owner, host, boot, operation identity, or candidate digest
// must fail closed. The parent dispatcher has to supply this proof while it
// still holds the shared root-operation flock; this package does not infer
// a reservation from the journal alone.
type helperMigrationOwnReservationProof struct {
	Schema              string `json:"schema"`
	OperationID         string `json:"operation_id"`
	OperationKind       string `json:"operation_kind"`
	OwnerKeyFingerprint string `json:"owner_key_fingerprint"`
	HostFingerprint     string `json:"host_fingerprint"`
	BootID              string `json:"boot_id"`
	CandidateSHA256     string `json:"candidate_sha256"`
}

func (proof helperMigrationOwnReservationProof) isZero() bool {
	return proof == helperMigrationOwnReservationProof{}
}

func (proof helperMigrationOwnReservationProof) validate() error {
	if proof.Schema != "" && proof.Schema != helperMigrationOwnReservationSchema {
		return errors.New("helper-update own reservation proof is not the expected versioned contract")
	}
	if !helperMigrationOperationIDPattern.MatchString(proof.OperationID) {
		return errors.New("helper-update own reservation operation identity is invalid")
	}
	if proof.OperationKind != helperMigrationOwnReservationKind {
		return errors.New("helper-update own reservation kind is invalid")
	}
	if !helperMigrationFingerprintPattern.MatchString(proof.OwnerKeyFingerprint) {
		return errors.New("helper-update own reservation owner key is invalid")
	}
	if !helperMigrationFingerprintPattern.MatchString(proof.HostFingerprint) {
		return errors.New("helper-update own reservation host identity is invalid")
	}
	if proof.BootID == "" || len(proof.BootID) > 128 || strings.ContainsAny(proof.BootID, "\x00\r\n") {
		return errors.New("helper-update own reservation boot identity is invalid")
	}
	if !helperMigrationDigestPattern.MatchString(proof.CandidateSHA256) {
		return errors.New("helper-update own reservation candidate digest is invalid")
	}
	return nil
}

func canonicalHelperMigrationOwnReservationProof(proof helperMigrationOwnReservationProof) helperMigrationOwnReservationProof {
	if proof.Schema == "" {
		proof.Schema = helperMigrationOwnReservationSchema
	}
	return proof
}

// helperMigrationReconcileRequest is the signed parent adapter for a host boot
// change. Reconciliation is intentionally separate from finalization because a
// boot change invalidates the original probe context.
type helperMigrationReconcileRequest struct {
	CandidateSHA256 string
	Host            string
	IntentID        string
	PlanExpiresAt   time.Time
	Validate        func() error
}

type helperMigrationStatus struct {
	Schema          string
	ID              string
	CandidateSHA256 string
	Host            string
	BootID          string
	Phase           string
}

type helperMigrationStatusReader func(*shuttlessh.Client, trustedHostIdentity) (helperMigrationStatus, error)

var errHelperMigrationStatusUnavailable = errors.New("helper migration status is unavailable until the root helper status hook is integrated")

func unavailableHelperMigrationStatusReader(*shuttlessh.Client, trustedHostIdentity) (helperMigrationStatus, error) {
	return helperMigrationStatus{}, errHelperMigrationStatusUnavailable
}

func helperMigrationStatusFromIntent(intent *helperMigrationIntent) helperMigrationStatus {
	if intent == nil {
		return helperMigrationStatus{Schema: helperMigrationSchema}
	}
	return helperMigrationStatus{Schema: intent.Schema, ID: intent.ID, CandidateSHA256: intent.CandidateSHA256, Host: intent.Host, BootID: intent.BootID, Phase: intent.Phase}
}

func helperMigrationCapabilitiesWithheld(err error) bool {
	return err != nil && strings.Contains(err.Error(), "capability advertisement is withheld while migration")
}

func helperMigrationStatusFromCapabilityError(err error) (helperMigrationStatus, bool) {
	if !helperMigrationCapabilitiesWithheld(err) {
		return helperMigrationStatus{}, false
	}
	matches := helperMigrationPendingPattern.FindStringSubmatch(err.Error())
	if len(matches) != 3 {
		return helperMigrationStatus{}, false
	}
	return helperMigrationStatus{Schema: helperMigrationSchema, ID: matches[1], Phase: matches[2]}, true
}

var errHelperMigrationFinalizationUnavailable = errors.New("helper migration finalization is unavailable until the root helper hook is integrated")

func unavailableHelperMigrationFinalizer(*shuttlessh.Client, trustedHostIdentity, helperMigrationFinalizeRequest) error {
	return errHelperMigrationFinalizationUnavailable
}
