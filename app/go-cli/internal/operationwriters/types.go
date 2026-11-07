// Package operationwriters records the executable writers of a coordinated
// operation and turns their shutdown into durable, inspectable proof.
//
// The caller must hold the host-wide coordination lock while using Store. The
// package deliberately does not acquire that lock itself. This keeps the
// writer transition in the same critical section as the caller's signed
// operation transition and avoids nested flock deadlocks.
//
// client_origin writers live on the CLI host. Their PIDs must never be
// inspected or signaled as VPS PIDs. Closure of those writers is an
// authenticated SSH receipt produced by SignClientOriginReceipt after the
// caller has fenced its own groups.
package operationwriters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// Schema is the durable JSON schema written by this package.
	Schema = "shuttle.operation-writers/v1"

	// DefaultRoot is the root of the operation journal. A test root can be
	// supplied to NewStore; the file then lives below root/writers.
	DefaultRoot = "/var/lib/shuttle/operations"

	// MaxStateBytes bounds both reads and writes of a writer state file.
	MaxStateBytes = 256 << 10

	// DefaultReceiptMaxAge limits how old a closure observation may be.
	DefaultReceiptMaxAge = 10 * time.Minute

	// DefaultClockSkew permits a small amount of clock skew without accepting
	// a receipt from the future.
	DefaultClockSkew = 30 * time.Second

	// DefaultFenceTimeout bounds a fence when its caller did not provide a
	// deadline.
	DefaultFenceTimeout = 30 * time.Second
)

type Admissions string

const (
	AdmissionsOpen   Admissions = "open"
	AdmissionsClosed Admissions = "closed"
)

type WriterKind string

const (
	WriterKindLocalGroup   WriterKind = "local_group"
	WriterKindRemoteRunner WriterKind = "remote_runner"
	WriterKindClientOrigin WriterKind = "client_origin"
	LocalGroupWriter       WriterKind = WriterKindLocalGroup
	RemoteRunnerWriter     WriterKind = WriterKindRemoteRunner
	ClientOriginWriter     WriterKind = WriterKindClientOrigin
)

// Binding is the immutable identity of one operation generation. HostKey is
// the pinned SHA256 SSH host-key fingerprint, and BootID is the kernel boot
// identity observed by the caller.
type Binding struct {
	OperationID string `json:"operation_id"`
	Generation  uint64 `json:"generation"`
	HostKey     string `json:"host_key"`
	BootID      string `json:"boot_id"`
}

// LocalGroup identifies a process group and its leader's kernel birth time.
// Registration accepts only the invariant PGID == SID == LeaderPID.
type LocalGroup struct {
	LeaderPID        int    `json:"leader_pid"`
	LeaderStartTicks uint64 `json:"leader_start_ticks"`
	PGID             int    `json:"pgid"`
	SID              int    `json:"sid"`
}

// RemoteRunner identifies a runner authenticated by the caller's signed
// SHU1 request. This package never opens the SSH connection or verifies that
// request.
type RemoteRunner struct {
	HostKey  string `json:"host_key"`
	RunToken string `json:"run_token"`
}

// ClientOrigin identifies a writer that lives on the CLI host, not on the VPS.
// Its process group must never be treated as a VPS-local PID. Closure requires
// SignClientOriginReceipt: a signature over origin, operation binding, and the
// caller's own kernel fence, bound to machine, boot, SSH key, run token, group
// and generation.
type ClientOrigin struct {
	MachineID      string     `json:"machine_id"`
	BootID         string     `json:"boot_id"`
	KeyFingerprint string     `json:"key_fingerprint"`
	RunToken       string     `json:"run_token"`
	Group          LocalGroup `json:"group"`
}

type Writer struct {
	ID     string        `json:"id"`
	Kind   WriterKind    `json:"kind"`
	Local  *LocalGroup   `json:"local,omitempty"`
	Remote *RemoteRunner `json:"remote,omitempty"`
	Client *ClientOrigin `json:"client,omitempty"`
}

// BaselineArtifact records the complete digest and presence observed before
// any operation writer can mutate state.
type BaselineArtifact struct {
	Present    bool   `json:"present"`
	FullSHA256 string `json:"full_sha256"`
}

type Baseline struct {
	Current                   BaselineArtifact `json:"current"`
	Previous                  BaselineArtifact `json:"previous"`
	ConfiguredNativePGVersion string           `json:"configured_native_pg_version"`
	ConfiguredNativePGCluster string           `json:"configured_native_pg_cluster"`
}

// ProcessIdentity is a read-only kernel observation. It contains identity
// fields only and never command arguments or payload data.
type ProcessIdentity struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	PPID       int    `json:"ppid"`
	PGID       int    `json:"pgid"`
	SID        int    `json:"sid"`
	State      string `json:"state"`
}

type LocalGroupObservation struct {
	Group         LocalGroup        `json:"group"`
	LeaderPresent bool              `json:"leader_present"`
	Members       []ProcessIdentity `json:"members"`
}

type LocalInspection struct {
	ObservedAt     string                  `json:"observed_at"`
	Groups         []LocalGroupObservation `json:"groups"`
	EvidenceSHA256 string                  `json:"evidence_sha256"`
}

// LocalSnapshot is accepted by InspectLocalGroups. FenceLocalGroups also
// accepts State so that callers can derive the immutable local inventory from
// the state they just read under the coordination lock.
type LocalSnapshot struct {
	Binding          Binding
	Generation       uint64
	AdmissionsClosed bool
	Groups           []LocalGroup
	// ProcRoot is test-only plumbing for an isolated proc fixture. Production
	// callers leave it empty, which selects /proc.
	ProcRoot string
}

type LocalGroupSnapshot = LocalSnapshot

// LocalFenceReceipt contains the kernel-derived result of fencing a local
// group. KernelProof is a typed proof marker, rather than a caller supplied
// boolean. The exact observed inventory is included in the evidence hash.
type LocalFenceReceipt struct {
	Generation            uint64            `json:"generation"`
	ObservedAt            string            `json:"observed_at"`
	AdmissionsClosed      bool              `json:"admissions_closed"`
	ActualClosedAdmission bool              `json:"actual_closed_admission,omitempty"`
	ResourcesClosed       bool              `json:"resources_closed"`
	ResourceClosure       bool              `json:"resource_closure,omitempty"`
	EvidenceSHA256        string            `json:"evidence_sha256"`
	KernelProof           string            `json:"kernel_proof"`
	Groups                []LocalGroup      `json:"groups"`
	ObservedMembers       []ProcessIdentity `json:"observed_members"`
	EvidenceHash          string            `json:"evidence_hash,omitempty"`
}

// RemoteRunnerReceipt is supplied by a caller after it has received an
// authenticated, signed SHU1 Fence result. The fields are intentionally
// identifiers and hashes, never credentials or file payloads.
type RemoteRunnerReceipt struct {
	HostKey               string   `json:"host_key"`
	RunnerHostKey         string   `json:"runner_host_key,omitempty"`
	RunToken              string   `json:"run_token"`
	Generation            uint64   `json:"generation"`
	ObservedAt            string   `json:"observed_at"`
	AdmissionsClosed      bool     `json:"admissions_closed"`
	ActualClosedAdmission bool     `json:"actual_closed_admission,omitempty"`
	ResourcesClosed       bool     `json:"resources_closed"`
	ResourceClosure       bool     `json:"resource_closure,omitempty"`
	ResourceIDs           []string `json:"resource_ids"`
	TunnelID              string   `json:"tunnel_id"`
	EvidenceSHA256        string   `json:"evidence_sha256"`
	EvidenceHash          string   `json:"evidence_hash,omitempty"`
	AuthenticatedProof    string   `json:"authenticated_proof"`
}

// ClientOriginReceipt is the authenticated closure payload for a
// client_origin writer. PublicKey is SSH wire encoding from
// ssh.PublicKey.Marshal. SignatureFormat and Signature are the ssh.Signature
// fields produced by ssh.Signer.Sign over the canonical Origin+Binding+Local
// payload. A caller boolean or opaque proof string is not sufficient.
type ClientOriginReceipt struct {
	Origin          ClientOrigin      `json:"origin"`
	Binding         Binding           `json:"binding"`
	Local           LocalFenceReceipt `json:"local"`
	PublicKey       []byte            `json:"public_key"`
	SignatureFormat string            `json:"signature_format"`
	Signature       []byte            `json:"signature"`
}

// Receipt is one terminal proof for one registered writer. A receipt must
// have exactly one typed payload matching Kind.
type Receipt struct {
	WriterID              string               `json:"writer_id"`
	Kind                  WriterKind           `json:"kind"`
	Generation            uint64               `json:"generation"`
	ObservedAt            string               `json:"observed_at"`
	AdmissionsClosed      bool                 `json:"admissions_closed"`
	ResourcesClosed       bool                 `json:"resources_closed"`
	EvidenceSHA256        string               `json:"evidence_sha256"`
	ActualClosedAdmission bool                 `json:"actual_closed_admission,omitempty"`
	ResourceClosure       bool                 `json:"resource_closure,omitempty"`
	EvidenceHash          string               `json:"evidence_hash,omitempty"`
	Local                 *LocalFenceReceipt   `json:"local,omitempty"`
	Remote                *RemoteRunnerReceipt `json:"remote,omitempty"`
	Client                *ClientOriginReceipt `json:"client,omitempty"`
}

type ClosureReceipt = Receipt
type WriterReceipt = Receipt
type TerminalReceipt = Receipt

type Closure struct {
	Generation uint64    `json:"generation"`
	ClosedAt   string    `json:"closed_at"`
	Receipts   []Receipt `json:"receipts"`
	ProofHash  string    `json:"proof_hash"`
}

type State struct {
	Schema     string     `json:"schema"`
	Binding    Binding    `json:"binding"`
	Revision   uint64     `json:"revision"`
	Admissions Admissions `json:"admissions"`
	Writers    []Writer   `json:"writers"`
	Closure    *Closure   `json:"closure,omitempty"`
	Baseline   Baseline   `json:"baseline"`
	// Note is retained for compatibility with writer state written by an
	// earlier helper. It is informational and does not enter any proof hash.
	Note string `json:"note,omitempty"`
}

type StoreOptions struct {
	Root          string
	Now           func() time.Time
	Sync          func(*os.File) error
	MaxBytes      int
	ReceiptMaxAge time.Duration
	ClockSkew     time.Duration
}

type Store struct {
	root          string
	now           func() time.Time
	maxBytes      int
	receiptMaxAge time.Duration
	clockSkew     time.Duration
	sync          func(*os.File) error
}

var (
	ErrNotFound         = errors.New("operation writer state not found")
	ErrInvalidBinding   = errors.New("invalid operation writer binding")
	ErrInvalidState     = errors.New("invalid operation writer state")
	ErrInvalidWriter    = errors.New("invalid operation writer")
	ErrInvalidReceipt   = errors.New("invalid operation writer receipt")
	ErrAdmissionsClosed = errors.New("writer admissions are closed")
	ErrConflict         = errors.New("conflicting operation writer transition")
	ErrTooLarge         = errors.New("operation writer state is too large")
	ErrUnsupported      = errors.New("operation writer operation is unsupported on this platform")
	ErrFenceTimeout     = errors.New("operation writer fence timed out")
	ErrPIDReused        = errors.New("operation writer process identity was reused")
	ErrBootMismatch     = errors.New("operation writer boot identity changed")
	ErrProcessMissing   = errors.New("operation writer process is missing")
	ErrAmbiguousProcess = errors.New("operation writer process inventory is ambiguous")
)

var (
	canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	fingerprintPattern   = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	sha256Pattern        = regexp.MustCompile(`^(?:sha256:)?[a-f0-9]{64}$`)
	writerIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	resourceIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	tunnelIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$`)
)

func NewStore(root string) *Store {
	if root == "" {
		root = DefaultRoot
	}
	return &Store{root: root, now: time.Now, sync: syncFile, maxBytes: MaxStateBytes, receiptMaxAge: DefaultReceiptMaxAge, clockSkew: DefaultClockSkew}
}

// New is the options form of the constructor. It is convenient for callers
// that need a deterministic clock in tests. Invalid options are represented by
// the same bounded defaults as NewStore; OpenStore is available when callers
// need constructor errors.
func New(options StoreOptions) *Store {
	store, err := OpenStore(options)
	if err != nil {
		return NewStore(options.Root)
	}
	return store
}

func NewStoreWithOptions(options StoreOptions) *Store { return New(options) }

func OpenStore(options StoreOptions) (*Store, error) {
	s := NewStore(options.Root)
	if options.Now != nil {
		s.now = options.Now
	}
	if options.Sync != nil {
		s.sync = options.Sync
	}
	if options.MaxBytes > 0 {
		if options.MaxBytes > MaxStateBytes {
			return nil, fmt.Errorf("%w: configured limit exceeds %d bytes", ErrTooLarge, MaxStateBytes)
		}
		s.maxBytes = options.MaxBytes
	}
	if options.ReceiptMaxAge > 0 {
		s.receiptMaxAge = options.ReceiptMaxAge
	}
	if options.ClockSkew > 0 {
		s.clockSkew = options.ClockSkew
	}
	return s, nil
}

func syncFile(file *os.File) error { return file.Sync() }

func (s *Store) Root() string { return s.root }

func (s *Store) nowUTC() time.Time {
	now := time.Time{}
	if s.now != nil {
		now = s.now()
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.UTC()
}

func validateBinding(binding Binding) error {
	if !canonicalUUIDPattern.MatchString(binding.OperationID) || binding.Generation == 0 || !fingerprintPattern.MatchString(binding.HostKey) || boundedText(binding.BootID, 128) == "" {
		return fmt.Errorf("%w: operation_id must be canonical, generation positive, host_key SHA256 fingerprint, and boot_id bounded", ErrInvalidBinding)
	}
	if strings.ContainsAny(binding.BootID, "/\\") {
		return fmt.Errorf("%w: boot_id contains a forbidden character", ErrInvalidBinding)
	}
	return nil
}

func (binding Binding) Validate() error { return validateBinding(binding) }

func validateBaseline(baseline Baseline) error {
	for name, artifact := range map[string]BaselineArtifact{"current": baseline.Current, "previous": baseline.Previous} {
		if artifact.Present != (artifact.FullSHA256 != "") {
			return fmt.Errorf("%w: %s presence and digest disagree", ErrInvalidState, name)
		}
		if artifact.Present && !sha256Pattern.MatchString(artifact.FullSHA256) {
			return fmt.Errorf("%w: %s must contain a full sha256 digest", ErrInvalidState, name)
		}
	}
	if boundedText(baseline.ConfiguredNativePGVersion, 128) == "" || boundedText(baseline.ConfiguredNativePGCluster, 256) == "" {
		return fmt.Errorf("%w: configured native PostgreSQL version and cluster are required", ErrInvalidState)
	}
	return nil
}

func (baseline Baseline) Validate() error { return validateBaseline(baseline) }

func validateLocalGroup(group LocalGroup) error {
	if group.LeaderPID <= 0 || group.PGID <= 0 || group.SID <= 0 || group.LeaderStartTicks == 0 || group.PGID != group.LeaderPID || group.SID != group.LeaderPID {
		return fmt.Errorf("%w: local group must have positive exact leader identity and pgid=sid=leader pid", ErrInvalidWriter)
	}
	return nil
}

func validateClientOrigin(origin ClientOrigin) error {
	if boundedText(origin.MachineID, 128) == "" || strings.ContainsAny(origin.MachineID, "/\\") {
		return fmt.Errorf("%w: client origin machine_id is invalid", ErrInvalidWriter)
	}
	if boundedText(origin.BootID, 128) == "" || strings.ContainsAny(origin.BootID, "/\\") {
		return fmt.Errorf("%w: client origin boot_id is invalid", ErrInvalidWriter)
	}
	if !fingerprintPattern.MatchString(origin.KeyFingerprint) {
		return fmt.Errorf("%w: client origin key fingerprint is invalid", ErrInvalidWriter)
	}
	if boundedText(origin.RunToken, 256) == "" {
		return fmt.Errorf("%w: client origin run token is invalid", ErrInvalidWriter)
	}
	return validateLocalGroup(origin.Group)
}

func validateWriter(writer Writer) error {
	if !writerIDPattern.MatchString(writer.ID) || len(writer.ID) > 128 {
		return fmt.Errorf("%w: writer id is invalid", ErrInvalidWriter)
	}
	switch writer.Kind {
	case WriterKindLocalGroup:
		if writer.Local == nil || writer.Remote != nil || writer.Client != nil {
			return fmt.Errorf("%w: local_group requires only local", ErrInvalidWriter)
		}
		return validateLocalGroup(*writer.Local)
	case WriterKindRemoteRunner:
		if writer.Remote == nil || writer.Local != nil || writer.Client != nil || !fingerprintPattern.MatchString(writer.Remote.HostKey) || boundedText(writer.Remote.RunToken, 256) == "" {
			return fmt.Errorf("%w: remote_runner requires host key and bounded run token", ErrInvalidWriter)
		}
		return nil
	case WriterKindClientOrigin:
		if writer.Client == nil || writer.Local != nil || writer.Remote != nil {
			return fmt.Errorf("%w: client_origin requires only client", ErrInvalidWriter)
		}
		return validateClientOrigin(*writer.Client)
	default:
		return fmt.Errorf("%w: unknown writer kind %q", ErrInvalidWriter, writer.Kind)
	}
}

func (writer Writer) Validate() error { return validateWriter(writer) }

func validateState(state State) error {
	if state.Schema != Schema || state.Revision == 0 || state.Admissions != AdmissionsOpen && state.Admissions != AdmissionsClosed {
		return fmt.Errorf("%w: schema, revision, or admissions value is invalid", ErrInvalidState)
	}
	if state.Writers == nil {
		return fmt.Errorf("%w: writers inventory is missing", ErrInvalidState)
	}
	if err := validateBinding(state.Binding); err != nil {
		return err
	}
	if err := validateBaseline(state.Baseline); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(state.Writers))
	for _, writer := range state.Writers {
		if err := validateWriter(writer); err != nil {
			return err
		}
		if _, ok := seen[writer.ID]; ok {
			return fmt.Errorf("%w: duplicate writer id %q", ErrInvalidState, writer.ID)
		}
		seen[writer.ID] = struct{}{}
	}
	if state.Closure != nil {
		if state.Admissions != AdmissionsClosed || state.Closure.Generation != state.Binding.Generation || state.Closure.ClosedAt == "" || state.Closure.ProofHash == "" {
			return fmt.Errorf("%w: closure requires closed admissions and exact generation", ErrInvalidState)
		}
		if _, err := time.Parse(time.RFC3339Nano, state.Closure.ClosedAt); err != nil {
			return fmt.Errorf("%w: closure has invalid closed_at", ErrInvalidState)
		}
		if state.Closure.Receipts == nil {
			return fmt.Errorf("%w: closure receipts inventory is missing", ErrInvalidState)
		}
		if err := validateReceipts(state.Binding, state.Writers, state.Closure.Receipts, time.Time{}, 0, 0); err != nil {
			return err
		}
		want, err := canonicalProofHash(state.Binding, state.Baseline, state.Writers, state.Closure.Receipts)
		if err != nil || state.Closure.ProofHash != want {
			return fmt.Errorf("%w: closure proof hash does not match its inventory", ErrInvalidState)
		}
	}
	expectedRevision := uint64(1 + len(state.Writers))
	if state.Admissions == AdmissionsClosed {
		expectedRevision++
	}
	if state.Closure != nil {
		expectedRevision++
	}
	if state.Revision != expectedRevision {
		return fmt.Errorf("%w: revision %d does not match transition order %d", ErrInvalidState, state.Revision, expectedRevision)
	}
	return nil
}

func (state State) Validate() error { return validateState(state) }

func validateReceipts(binding Binding, writers []Writer, receipts []Receipt, now time.Time, maxAge, skew time.Duration) error {
	if len(receipts) != len(writers) {
		return fmt.Errorf("%w: terminal receipt inventory has %d entries, want %d", ErrInvalidReceipt, len(receipts), len(writers))
	}
	byID := make(map[string]Writer, len(writers))
	for _, writer := range writers {
		byID[writer.ID] = writer
	}
	seen := make(map[string]struct{}, len(receipts))
	for _, receipt := range receipts {
		writer, ok := byID[receipt.WriterID]
		if !ok {
			return fmt.Errorf("%w: receipt writer %q is not registered", ErrInvalidReceipt, receipt.WriterID)
		}
		if _, ok := seen[receipt.WriterID]; ok {
			return fmt.Errorf("%w: duplicate terminal receipt for %q", ErrInvalidReceipt, receipt.WriterID)
		}
		seen[receipt.WriterID] = struct{}{}
		evidence := proofEvidence(receipt.EvidenceSHA256, receipt.EvidenceHash)
		if receipt.Kind != writer.Kind || receipt.Generation != binding.Generation || receipt.ObservedAt == "" || !proofBool(receipt.AdmissionsClosed, receipt.ActualClosedAdmission) || !proofBool(receipt.ResourcesClosed, receipt.ResourceClosure) || !sha256Pattern.MatchString(evidence) {
			return fmt.Errorf("%w: receipt for %q is not an exact typed closure proof", ErrInvalidReceipt, receipt.WriterID)
		}
		observed, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
		if err != nil {
			return fmt.Errorf("%w: receipt for %q has invalid observed_at", ErrInvalidReceipt, receipt.WriterID)
		}
		if maxAge > 0 && !now.IsZero() && (observed.Before(now.Add(-maxAge)) || observed.After(now.Add(skew))) {
			return fmt.Errorf("%w: receipt for %q is stale or from the future", ErrInvalidReceipt, receipt.WriterID)
		}
		switch receipt.Kind {
		case WriterKindLocalGroup:
			if receipt.Local == nil || receipt.Remote != nil || receipt.Client != nil || writer.Local == nil || receipt.Local.ObservedAt != receipt.ObservedAt {
				return fmt.Errorf("%w: local receipt for %q lacks kernel-derived proof", ErrInvalidReceipt, receipt.WriterID)
			}
			if err := validateKernelLocalReceipt(binding, *writer.Local, receipt.Local, evidence, receipt.WriterID); err != nil {
				return err
			}
		case WriterKindRemoteRunner:
			remoteEvidence := ""
			remoteHostKey := ""
			if receipt.Remote != nil {
				remoteEvidence = proofEvidence(receipt.Remote.EvidenceSHA256, receipt.Remote.EvidenceHash)
				remoteHostKey = receipt.Remote.HostKey
				if remoteHostKey == "" {
					remoteHostKey = receipt.Remote.RunnerHostKey
				}
			}
			if receipt.Remote == nil || receipt.Local != nil || receipt.Client != nil || receipt.Remote.Generation != binding.Generation || writer.Remote == nil || remoteHostKey != writer.Remote.HostKey || receipt.Remote.RunToken != writer.Remote.RunToken || receipt.Remote.ObservedAt != receipt.ObservedAt || !proofBool(receipt.Remote.AdmissionsClosed, receipt.Remote.ActualClosedAdmission) || !proofBool(receipt.Remote.ResourcesClosed, receipt.Remote.ResourceClosure) || receipt.Remote.AuthenticatedProof != "SHU1-Fence/v1" || !sha256Pattern.MatchString(remoteEvidence) || remoteEvidence != evidence || len(receipt.Remote.ResourceIDs) == 0 || !tunnelIDPattern.MatchString(receipt.Remote.TunnelID) {
				return fmt.Errorf("%w: remote receipt for %q lacks authenticated runner/resource proof", ErrInvalidReceipt, receipt.WriterID)
			}
			seenResources := make(map[string]struct{}, len(receipt.Remote.ResourceIDs))
			for _, resourceID := range receipt.Remote.ResourceIDs {
				if !resourceIDPattern.MatchString(resourceID) {
					return fmt.Errorf("%w: remote resource id is invalid", ErrInvalidReceipt)
				}
				if _, exists := seenResources[resourceID]; exists {
					return fmt.Errorf("%w: remote resource inventory contains duplicate %q", ErrInvalidReceipt, resourceID)
				}
				seenResources[resourceID] = struct{}{}
			}
		case WriterKindClientOrigin:
			if receipt.Client == nil || receipt.Local != nil || receipt.Remote != nil || writer.Client == nil {
				return fmt.Errorf("%w: client receipt for %q lacks authenticated client-origin proof", ErrInvalidReceipt, receipt.WriterID)
			}
			if err := verifyClientOriginReceipt(binding, writer, receipt); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: unknown receipt kind %q", ErrInvalidReceipt, receipt.Kind)
		}
	}
	return nil
}

func proofBool(primary, alias bool) bool { return primary || alias }

func proofEvidence(primary, alias string) string {
	if primary != "" && alias != "" && primary != alias {
		return ""
	}
	if primary != "" {
		return primary
	}
	return alias
}

func validateKernelLocalReceipt(binding Binding, group LocalGroup, local *LocalFenceReceipt, evidence, writerID string) error {
	if local == nil {
		return fmt.Errorf("%w: local receipt for %q lacks kernel-derived proof", ErrInvalidReceipt, writerID)
	}
	localEvidence := proofEvidence(local.EvidenceSHA256, local.EvidenceHash)
	if local.Generation != binding.Generation || !proofBool(local.AdmissionsClosed, local.ActualClosedAdmission) || !proofBool(local.ResourcesClosed, local.ResourceClosure) || local.KernelProof != "linux-pidfd-v1" || !sha256Pattern.MatchString(localEvidence) || localEvidence != evidence || len(local.Groups) != 1 || local.Groups[0] != group {
		return fmt.Errorf("%w: local receipt for %q lacks kernel-derived proof", ErrInvalidReceipt, writerID)
	}
	wantEvidence, err := localEvidenceHash(local.Generation, local.Groups, local.ObservedMembers)
	if err != nil || localEvidence != wantEvidence {
		return fmt.Errorf("%w: local receipt for %q evidence hash does not match kernel inventory", ErrInvalidReceipt, writerID)
	}
	seenMembers := make(map[int]struct{}, len(local.ObservedMembers))
	for _, member := range local.ObservedMembers {
		if member.PID <= 0 || member.StartTicks == 0 || member.PGID != group.PGID || member.SID != group.SID || member.PID == group.LeaderPID && member.StartTicks != group.LeaderStartTicks || len(member.State) != 1 || !strings.ContainsRune("RSDZTtWKLPIXx", rune(member.State[0])) {
			return fmt.Errorf("%w: local receipt for %q contains an invalid observed member", ErrInvalidReceipt, writerID)
		}
		if _, exists := seenMembers[member.PID]; exists {
			return fmt.Errorf("%w: local receipt for %q repeats an observed member", ErrInvalidReceipt, writerID)
		}
		seenMembers[member.PID] = struct{}{}
	}
	return nil
}

func localEvidenceHash(generation uint64, groups []LocalGroup, observedMembers []ProcessIdentity) (string, error) {
	orderedGroups := append([]LocalGroup(nil), groups...)
	sort.Slice(orderedGroups, func(i, j int) bool { return orderedGroups[i].LeaderPID < orderedGroups[j].LeaderPID })
	orderedMembers := append([]ProcessIdentity(nil), observedMembers...)
	sort.Slice(orderedMembers, func(i, j int) bool { return orderedMembers[i].PID < orderedMembers[j].PID })
	payload := struct {
		Generation      uint64            `json:"generation"`
		KernelProof     string            `json:"kernel_proof"`
		Groups          []LocalGroup      `json:"groups"`
		ObservedMembers []ProcessIdentity `json:"observed_members"`
		MembersAbsent   bool              `json:"members_absent"`
	}{Generation: generation, KernelProof: "linux-pidfd-v1", Groups: orderedGroups, ObservedMembers: orderedMembers, MembersAbsent: true}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func boundedText(value string, limit int) string {
	if value == "" || len(value) > limit || strings.IndexByte(value, 0) >= 0 {
		return ""
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

func sameBinding(a, b Binding) bool { return a == b }

func sameBaseline(a, b Baseline) bool {
	return a == b
}

func sameWriter(a, b Writer) bool {
	if a.ID != b.ID || a.Kind != b.Kind {
		return false
	}
	return jsonEqual(a.Local, b.Local) && jsonEqual(a.Remote, b.Remote) && jsonEqual(a.Client, b.Client)
}

func jsonEqual(a, b any) bool {
	left, err1 := json.Marshal(a)
	right, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(left) == string(right)
}

type proofWriter struct {
	ID   string     `json:"id"`
	Kind WriterKind `json:"kind"`
}

type proofReceipt struct {
	WriterID       string              `json:"writer_id"`
	Kind           WriterKind          `json:"kind"`
	Generation     uint64              `json:"generation"`
	EvidenceSHA256 string              `json:"evidence_sha256"`
	Local          *proofLocalReceipt  `json:"local,omitempty"`
	Remote         *proofRemoteReceipt `json:"remote,omitempty"`
	Client         *proofClientReceipt `json:"client,omitempty"`
}

type proofLocalReceipt struct {
	Generation      uint64            `json:"generation"`
	EvidenceSHA256  string            `json:"evidence_sha256"`
	KernelProof     string            `json:"kernel_proof"`
	Groups          []LocalGroup      `json:"groups"`
	ObservedMembers []ProcessIdentity `json:"observed_members"`
}

type proofRemoteReceipt struct {
	HostKey        string   `json:"host_key"`
	RunToken       string   `json:"run_token"`
	Generation     uint64   `json:"generation"`
	ResourceIDs    []string `json:"resource_ids"`
	TunnelID       string   `json:"tunnel_id"`
	EvidenceSHA256 string   `json:"evidence_sha256"`
	Authenticated  string   `json:"authenticated_proof"`
}

type proofClientReceipt struct {
	Origin          ClientOrigin       `json:"origin"`
	Binding         Binding            `json:"binding"`
	Local           *proofLocalReceipt `json:"local,omitempty"`
	PublicKey       []byte             `json:"public_key"`
	SignatureFormat string             `json:"signature_format"`
}

func canonicalProofLocal(local *LocalFenceReceipt) *proofLocalReceipt {
	if local == nil {
		return nil
	}
	groups := append([]LocalGroup(nil), local.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].LeaderPID < groups[j].LeaderPID })
	item := &proofLocalReceipt{Generation: local.Generation, EvidenceSHA256: proofEvidence(local.EvidenceSHA256, local.EvidenceHash), KernelProof: local.KernelProof, Groups: groups}
	item.ObservedMembers = append([]ProcessIdentity{}, local.ObservedMembers...)
	sort.Slice(item.ObservedMembers, func(i, j int) bool { return item.ObservedMembers[i].PID < item.ObservedMembers[j].PID })
	return item
}

func canonicalProofHash(binding Binding, baseline Baseline, writers []Writer, receipts []Receipt) (string, error) {
	orderedWriters := make([]proofWriter, 0, len(writers))
	for _, writer := range writers {
		orderedWriters = append(orderedWriters, proofWriter{ID: writer.ID, Kind: writer.Kind})
	}
	sort.Slice(orderedWriters, func(i, j int) bool { return orderedWriters[i].ID < orderedWriters[j].ID })
	orderedReceipts := make([]proofReceipt, 0, len(receipts))
	for _, receipt := range receipts {
		item := proofReceipt{WriterID: receipt.WriterID, Kind: receipt.Kind, Generation: receipt.Generation, EvidenceSHA256: proofEvidence(receipt.EvidenceSHA256, receipt.EvidenceHash)}
		if receipt.Local != nil {
			item.Local = canonicalProofLocal(receipt.Local)
		}
		if receipt.Remote != nil {
			ids := append([]string(nil), receipt.Remote.ResourceIDs...)
			sort.Strings(ids)
			hostKey := receipt.Remote.HostKey
			if hostKey == "" {
				hostKey = receipt.Remote.RunnerHostKey
			}
			item.Remote = &proofRemoteReceipt{HostKey: hostKey, RunToken: receipt.Remote.RunToken, Generation: receipt.Remote.Generation, ResourceIDs: ids, TunnelID: receipt.Remote.TunnelID, EvidenceSHA256: proofEvidence(receipt.Remote.EvidenceSHA256, receipt.Remote.EvidenceHash), Authenticated: receipt.Remote.AuthenticatedProof}
		}
		if receipt.Client != nil {
			item.Client = &proofClientReceipt{
				Origin:          receipt.Client.Origin,
				Binding:         receipt.Client.Binding,
				Local:           canonicalProofLocal(&receipt.Client.Local),
				PublicKey:       append([]byte(nil), receipt.Client.PublicKey...),
				SignatureFormat: receipt.Client.SignatureFormat,
			}
		}
		orderedReceipts = append(orderedReceipts, item)
	}
	sort.Slice(orderedReceipts, func(i, j int) bool { return orderedReceipts[i].WriterID < orderedReceipts[j].WriterID })
	payload := struct {
		Binding  Binding        `json:"binding"`
		Baseline Baseline       `json:"baseline"`
		Writers  []proofWriter  `json:"writers"`
		Receipts []proofReceipt `json:"receipts"`
	}{Binding: binding, Baseline: baseline, Writers: orderedWriters, Receipts: orderedReceipts}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (s State) ClosedProofHash() (string, error) {
	if err := validateState(s); err != nil {
		return "", err
	}
	if s.Closure == nil {
		return "", fmt.Errorf("%w: state has no closure", ErrInvalidState)
	}
	return canonicalProofHash(s.Binding, s.Baseline, s.Writers, s.Closure.Receipts)
}

func CanonicalClosedProofHash(state State) (string, error) {
	return state.ClosedProofHash()
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// InspectLocalGroups is implemented in platform files. It reads only process
// identity metadata, and never searches command names or arguments.
// client_origin writers are skipped: their PIDs belong to the CLI host, not
// the VPS. A snapshot that contains only client-origin groups errors without
// probing local PIDs.
func InspectLocalGroups(ctx context.Context, snapshot any) (LocalInspection, error) {
	return inspectLocalGroups(ctx, snapshot)
}

// FenceLocalGroups is implemented in platform files. It returns local
// terminal receipts that can be passed to CommitClosureLocked.
// client_origin groups are never fenced here and never receive a VPS closure
// receipt. Genuine local_group writers keep VPS-local kernel fencing.
func FenceLocalGroups(ctx context.Context, snapshot any) ([]Receipt, error) {
	return fenceLocalGroups(ctx, snapshot)
}
