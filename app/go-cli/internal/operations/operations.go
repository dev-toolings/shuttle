// Package operations coordinates state changing Shuttle maintenance work.
//
// A reservation is durable before its caller starts work. A phase then keeps
// the same exclusive flock from identity validation through the phase-start
// fsync, the mutation callback and the durable outcome. This is intentionally
// a host wide fence: a caller that disappears cannot leave another caller free
// to infer that its mutation stopped.
//
// The one exception is a Concurrent phase of an application-scoped kind. It
// holds a per-application executor flock across the callback instead, and
// takes the host flock only for its journal transitions, so two applications
// on the same host can be promoted at the same time.
package operations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultRoot             = "/var/lib/shuttle/operations"
	DefaultLockPath         = "/run/shuttle-root.lock"
	Schema                  = "shuttle.operation/v1"
	DefaultLease            = 15 * time.Minute
	DefaultLockWait         = 30 * time.Second
	MaxReasonBytes          = 512
	MaxJournalBytes         = 256 << 10
	MaxJournalItems         = 128
	MaxEvidenceItems        = 32
	MaxRecoveryDetailsBytes = 64 << 10
	RecoveryRequired        = "recovery_required"

	// Event budgets keep an active record able to abandon and recover. After
	// reserve or a successful phase, three slots stay free: compact
	// abandonment plus one recovery attempt (start and outcome).
	activeIdleEventBudget       = 3
	recoveryAttemptEventBudget  = 2
	reserveEventBudget          = 1 + activeIdleEventBudget
	completedPhaseEventBudget   = 1 + activeIdleEventBudget
	executePhaseEventBudget     = 2 + activeIdleEventBudget
	recoveryRequiredEventBudget = 1 + recoveryAttemptEventBudget

	capacityProbeTime         = "9999-12-31T23:59:59.999999999Z"
	unrecordableRecoveryProof = "actions applied; post-action proof exceeds journal capacity"
)

var (
	identifierPattern  = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)
	kindPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	appPattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	servicePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	containerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// globalKinds mutate something every application on the host depends on (the
// registry catalogue, backups and restores, the helper, the machine itself), so
// each one excludes every other operation.
var globalKinds = map[string]bool{
	"backup": true, "restore": true, "registry-gc": true, "cache-prune": true,
	"helper-update": true, "reboot": true, "destroy": true,
}

// applicationKinds mutate one application's stack, secrets and tasks. They
// exclude a global operation and another mutation of the same application, and
// nothing else.
//
// Until 14-09-2026 deploy, rollback and run were global too. A host serving two
// applications then refused the second deploy outright ("operation ... is
// active for deploy (target web, age 49s); waited 0s") even though the two
// stacks share nothing a promotion writes except the edge reload and the
// registry collector, which are now serialised on their own locks by the helper.
var applicationKinds = map[string]bool{
	"secrets-sync": true,
	"deploy":       true, "rollback": true, "run": true,
}

// ErrOtherOperationsActive reports that WithSoleOperation found another live or
// unrecovered operation, or could not take the journal lock to prove there was
// none. Callers treat it as a deferral, not as a failure.
var ErrOtherOperationsActive = errors.New("another operation is active on this host")

// ErrOperationRequiresRecovery distinguishes durable failed operations from
// ordinary inactive records, so the CLI can point operators to recovery.
var ErrOperationRequiresRecovery = errors.New("operation requires recovery")

// PhaseWarning is what a phase callback returns when its own change is done
// and verified, and only housekeeping that follows it failed.
//
// Measured 2026-10-05 on api and 2026-10-08 on web: stack-apply
// converged, the route was loaded, the tasks ran the signed digests, and then
// one DELETE of a superseded registry manifest got "connection reset by peer".
// The phase returned that error like any other, the record became
// recovery_required, and every later deploy of the application was refused
// until someone edited /var/lib/shuttle/operations by hand. Recovery could not
// close it either: there was nothing to repair. A sweep that will run again on
// the next promotion is not a reason to stop the host.
//
// The phase therefore completes, the reason is kept in Phase.Warning, and
// ExecutePhase returns nil. Only a bare *PhaseWarning qualifies: one joined
// with a lease renewal failure, or wrapped by anything else, is an ordinary
// failure, because the coordinator can no longer tell what else went wrong.
// A callback must not use this for a failure that leaves the host in a state
// nobody has observed; that still needs recovery.
type PhaseWarning struct{ Err error }

// KnownOutcomeError marks a failed phase whose external command outcome was
// positively observed. Docker also uses non-zero codes for its own failures,
// so callers must prove the command cannot still run before using this. Unlike
// an ordinary phase error, it can release the executor fence after the client
// closes its writers and refuses the run.
type KnownOutcomeError struct{ Err error }

func (e *KnownOutcomeError) Error() string {
	if e == nil || e.Err == nil {
		return "command failed with a known outcome"
	}
	return e.Err.Error()
}

func (e *KnownOutcomeError) Unwrap() error { return e.Err }

// KnownOutcome wraps err as a KnownOutcomeError. A nil error stays nil.
func KnownOutcome(err error) error {
	if err == nil {
		return nil
	}
	return &KnownOutcomeError{Err: err}
}

func (w *PhaseWarning) Error() string {
	if w == nil || w.Err == nil {
		return "phase completed with an unspecified warning"
	}
	return w.Err.Error()
}

func (w *PhaseWarning) Unwrap() error { return w.Err }

// Warn wraps err as a PhaseWarning. A nil err stays nil.
func Warn(err error) error {
	if err == nil {
		return nil
	}
	return &PhaseWarning{Err: err}
}

type Request struct {
	ID                  string
	Kind                string
	App                 string
	Principal           string
	OwnerKeyFingerprint string
	Host                string
	Lease               time.Duration
	PlanExpiresAt       time.Time
	HostIdentity        string
	Validate            func() error
}

// PhaseRequest is the complete identity and freshness proof for one signed
// phase. Validate is called while the coordinator flock is held, after the
// record has been re-read and before phase-start is written.
type PhaseRequest struct {
	ID                  string
	Kind                string
	App                 string
	Principal           string
	OwnerKeyFingerprint string
	Host                string
	Name                string
	PlanExpiresAt       time.Time
	HostIdentity        string
	Validate            func(Record) error
	// Concurrent runs the callback under the application's executor flock
	// instead of the host journal flock. It is refused for a global kind. The
	// callback must not rely on the journal flock being held, and must take
	// its own lock for anything it shares with other applications.
	Concurrent bool
}

type Phase struct {
	Name      string `json:"name"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at,omitempty"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
	Known     bool   `json:"known,omitempty"`
	// Warning is housekeeping that failed after the phase's own change was
	// complete and verified. The phase still completed; see PhaseWarning.
	Warning string `json:"warning,omitempty"`
}

const (
	FirstReleaseConvergencePending   = "pending"
	FirstReleaseConvergenceFailed    = "not-converged"
	FirstReleaseConvergenceSucceeded = "converged"
)

type Event struct {
	At       string `json:"at"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Phase    string `json:"phase,omitempty"`
	Recovery bool   `json:"recovery_required,omitempty"`
	// Note is an operator's annotation on a record closed by hand before
	// `operations recover` could close it. Shuttle never writes one. It is
	// declared so the strict readers accept it: on 2026-09-15 the ohb-console
	// host got events[13].note on a hand-recovered deploy, and from then on
	// the helper-update preflight (decodeMigrationJournalRecord) refused the
	// whole journal with `json: unknown field "note"`. Every signed helper
	// update on that host failed before replacement and left a
	// recovery_required reservation, whatever the helper version (measured
	// again on 2026-10-08 with v0.0.27). Any other unknown field is still
	// refused there.
	Note string `json:"note,omitempty"`
}

// Record contains identifiers, digests and bounded outcomes only. It never
// carries request payloads or credentials.
type Record struct {
	Schema              string  `json:"schema"`
	ID                  string  `json:"id"`
	Revision            uint64  `json:"revision"`
	Kind                string  `json:"kind"`
	Scope               string  `json:"scope"`
	App                 string  `json:"app,omitempty"`
	Principal           string  `json:"principal"`
	OwnerKeyFingerprint string  `json:"owner_key_fingerprint,omitempty"`
	Host                string  `json:"host,omitempty"`
	HostBootID          string  `json:"host_boot_id"`
	StartedAt           string  `json:"started_at"`
	UpdatedAt           string  `json:"updated_at"`
	LeaseUntil          string  `json:"lease_until"`
	State               string  `json:"state"`
	RecoveryRequired    bool    `json:"recovery_required"`
	Result              string  `json:"result,omitempty"`
	Phases              []Phase `json:"phases,omitempty"`
	// CurrentManifestSHA256 is the full digest of the current.yml this
	// operation wrote, journaled before the file itself. Recovery reads it as
	// the operation's own proof for that artifact; see JournalCurrentManifest.
	CurrentManifestSHA256 string `json:"current_manifest_sha256,omitempty"`
	// RecoveryCurrentManifestSHA256 binds the exact current.yml produced by a
	// deploy recovery that keeps a newer infrastructure image. It is separate
	// from CurrentManifestSHA256, which remains the failed deploy's own proof.
	RecoveryCurrentManifestSHA256 string `json:"recovery_current_manifest_sha256,omitempty"`
	// FirstReleaseConvergenceState is durable evidence for whether the first
	// release passed its stack convergence wait. Recovery may remove a first
	// release only when this state is not-converged.
	FirstReleaseConvergenceState          string               `json:"first_release_convergence_state,omitempty"`
	FirstReleaseConvergenceManifestSHA256 string               `json:"first_release_convergence_manifest_sha256,omitempty"`
	RegistryReplacement                   *RegistryReplacement `json:"registry_replacement,omitempty"`
	RunTarget                             *RunTarget           `json:"run_target,omitempty"`
	RecoveryActions                       []string             `json:"recovery_actions,omitempty"`
	RecoveryPlanDigest                    string               `json:"recovery_plan_digest,omitempty"`
	RecoveryObservation                   RecoveryObservation  `json:"recovery_observation,omitempty"`
	RecoveryIntent                        *RecoveryIntent      `json:"recovery_intent,omitempty"`
	Events                                []Event              `json:"events,omitempty"`
}

// RunTarget is the exact task selected for one declared run command. The
// helper journals it before docker exec so recovery can prove whether that
// executor still exists without tracking an Engine API exec ID.
type RunTarget struct {
	Service   string `json:"service"`
	Container string `json:"container"`
}

type Options struct {
	Root     string
	LockPath string
	Now      func() time.Time
	BootID   func() (string, error)
	LockWait time.Duration
	Lease    time.Duration
	// Sync is injectable for disk and fsync failure tests. Production uses the
	// file's Sync method for both the temporary record and its parent directory.
	Sync func(*os.File) error
}

type Coordinator struct {
	root      string
	lockPath  string
	now       func() time.Time
	bootID    func() (string, error)
	lockWait  time.Duration
	lease     time.Duration
	sync      func(*os.File) error
	journalMu sync.Mutex
	// journalLockHook is a narrow synchronization seam for deterministic
	// contention tests. Production leaves it nil and uses journalMu directly.
	journalLockHook func(string)
}

type Handle struct {
	c     *Coordinator
	id    string
	key   string
	owner string
	host  string
	kind  string
	app   string
}

type BusyError struct {
	Active Record
	Waited time.Duration
	Now    time.Time
}

type lockBusyError struct {
	waited time.Duration
	path   string
}

func (e *lockBusyError) Error() string {
	return fmt.Sprintf("operation lock busy after waiting %s", e.waited.Round(time.Second))
}

// Error names the blocking operation. An unrecovered one is worded differently
// from a live one because waiting cannot clear it: the client queues behind "is
// active for" and stops at once on "requires recovery".
func (e *BusyError) Error() string {
	now := e.Now
	if now.IsZero() {
		now = time.Now()
	}
	age := ageOf(e.Active.UpdatedAt, now)
	target := e.Active.App
	if target == "" {
		target = "VPS"
	}
	if e.Active.RecoveryRequired {
		return fmt.Sprintf("operation %s requires recovery for %s (target %s, age %s); waited %s", e.Active.ID, e.Active.Kind, target, age, e.Waited.Round(time.Second))
	}
	return fmt.Sprintf("operation %s is active for %s (target %s, age %s); waited %s", e.Active.ID, e.Active.Kind, target, age, e.Waited.Round(time.Second))
}

// RecoveryObservation is the evidence needed to decide whether a recovery
// action can be applied. A healthy daemon or a nonzero replica count is not a
// fence proof, so the executor and version fields are mandatory for Safe.
type RecoveryObservation struct {
	Details          []string `json:"details,omitempty"`
	Safe             bool     `json:"safe"`
	ObservedAt       string   `json:"observed_at,omitempty"`
	ProcessVersion   string   `json:"process_version,omitempty"`
	BootVersion      string   `json:"boot_version,omitempty"`
	PhaseVersion     string   `json:"phase_version,omitempty"`
	ResourceVersion  string   `json:"resource_version,omitempty"`
	ExecutorCount    int      `json:"executor_count"`
	ExecutorProof    string   `json:"executor_proof,omitempty"`
	Freshness        string   `json:"freshness,omitempty"`
	PendingBackup    bool     `json:"pending_backup,omitempty"`
	OriginalReplicas int      `json:"original_replicas,omitempty"`
	ServiceState     string   `json:"service_state,omitempty"`
	RegistryState    string   `json:"registry_state,omitempty"`
	DataState        string   `json:"data_state,omitempty"`
	CurrentDigest    string   `json:"current_digest,omitempty"`
	PreviousDigest   string   `json:"previous_digest,omitempty"`
	ManifestProof    string   `json:"manifest_proof,omitempty"`
	MarkerProof      string   `json:"marker_proof,omitempty"`
	ResourceProof    string   `json:"resource_proof,omitempty"`
	ActionProof      string   `json:"action_proof,omitempty"`
	Actions          []string `json:"actions,omitempty"`
	MissingProof     []string `json:"missing_proof,omitempty"`
	Unresolved       []string `json:"unresolved,omitempty"`
}

// RecoveryIntent is durable evidence that the operator confirmed a recovery
// plan before the applier was allowed to mutate anything.
type RecoveryIntent struct {
	PlanDigest string   `json:"plan_digest"`
	StartedAt  string   `json:"started_at"`
	Actions    []string `json:"actions,omitempty"`
}

type RecoveryPlan struct {
	Schema     string              `json:"schema"`
	ID         string              `json:"id"`
	State      string              `json:"state"`
	Observed   RecoveryObservation `json:"observed"`
	Actions    []string            `json:"actions"`
	PlanDigest string              `json:"plan_digest"`
}

type Observer func(context.Context, Record) (RecoveryObservation, error)
type Applier func(context.Context, Record, RecoveryObservation) error

func New(options Options) *Coordinator {
	root := options.Root
	if root == "" {
		root = DefaultRoot
	}
	lockPath := options.LockPath
	if lockPath == "" {
		lockPath = DefaultLockPath
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	bootID := options.BootID
	if bootID == nil {
		bootID = hostBootID
	}
	wait := options.LockWait
	if wait <= 0 {
		wait = DefaultLockWait
	}
	lease := options.Lease
	if lease <= 0 {
		lease = DefaultLease
	}
	syncFile := options.Sync
	if syncFile == nil {
		syncFile = func(file *os.File) error { return file.Sync() }
	}
	return &Coordinator{root: root, lockPath: lockPath, now: now, bootID: bootID, lockWait: wait, lease: lease, sync: syncFile}
}

func NewDefault() *Coordinator { return New(Options{}) }

func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate operation id: %w", err)
	}
	value := hex.EncodeToString(b)
	return value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:], nil
}

// IsGlobal reports whether kind excludes every other operation on the host.
func IsGlobal(kind string) bool { return globalKinds[kind] }

// IsKnown reports whether kind is a supported operation kind of either scope.
func IsKnown(kind string) bool { return globalKinds[kind] || applicationKinds[kind] }

func (c *Coordinator) lockJournal(kind string) {
	if c.journalMu.TryLock() {
		return
	}
	// Signal only after TryLock failed, so a waiter has observed real
	// contention rather than a scheduling gap before Lock.
	if c.journalLockHook != nil {
		c.journalLockHook(kind)
	}
	c.journalMu.Lock()
}

func (c *Coordinator) unlockJournal() { c.journalMu.Unlock() }

func (c *Coordinator) Reserve(ctx context.Context, request Request) (*Handle, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if request.ID == "" {
		var err error
		request.ID, err = NewID()
		if err != nil {
			return nil, err
		}
	}
	if request.Lease <= 0 {
		request.Lease = c.lease
	}
	now := c.now().UTC()
	var result *Handle
	var waited time.Duration
	err := c.withLockWait(ctx, func() error {
		boot, err := c.bootID()
		if err != nil {
			return fmt.Errorf("read host boot id: %w", err)
		}
		now = c.now().UTC()
		if !request.PlanExpiresAt.IsZero() && !request.PlanExpiresAt.After(now) {
			return errors.New("signed operation reservation expired before the lock was acquired")
		}
		if request.HostIdentity != "" && request.HostIdentity != request.Host {
			return errors.New("signed operation host identity does not match the reservation")
		}
		if request.Validate != nil {
			if err := request.Validate(); err != nil {
				return err
			}
		}
		records, err := c.readRecords()
		if err != nil {
			return err
		}
		for i := range records {
			if records[i].State == "active" && stale(records[i], now, boot) {
				staleRecord, markErr := c.markStale(records[i], now)
				if markErr != nil {
					return markErr
				}
				records[i] = staleRecord
				if err := c.writeRecord(records[i]); err != nil {
					return err
				}
			}
		}
		for _, active := range records {
			if active.ID == request.ID {
				if !sameRequestRecord(request, active) {
					return errors.New("operation ID is already bound to a different principal, key, host, kind or application")
				}
				if active.State == "active" && !active.RecoveryRequired {
					result = handleFor(c, active)
					return nil
				}
				return fmt.Errorf("operation %s already exists in state %s and cannot be reused", request.ID, active.State)
			}
			if conflict(request, active) {
				return &BusyError{Active: active, Waited: waited, Now: now}
			}
		}
		record := Record{Schema: Schema, ID: request.ID, Kind: request.Kind, Scope: scopeFor(request), App: request.App, Principal: request.Principal, OwnerKeyFingerprint: request.OwnerKeyFingerprint, Host: request.Host, HostBootID: boot, StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), LeaseUntil: now.Add(request.Lease).Format(time.RFC3339Nano), State: "active", Events: []Event{}}
		if err := reserveEventCapacity(record, reserveEventBudget, "operation reservation"); err != nil {
			return err
		}
		c.appendEvent(&record, now, "reserved", "", false)
		if err := c.ensureReserveCapacity(record); err != nil {
			return err
		}
		if err := c.writeRecord(record); err != nil {
			return err
		}
		result = handleFor(c, record)
		return nil
	}, &waited)
	if err != nil {
		var lockBusy *lockBusyError
		if errors.As(err, &lockBusy) {
			// Records are atomically replaced, so this read can safely identify
			// the operation that held the lock even though it is not a mutation
			// path. Returning BusyError preserves the actual operation age and
			// the bounded wait context instead of an opaque lock timeout.
			if records, readErr := c.readRecords(); readErr == nil {
				for _, active := range records {
					if active.ID == request.ID && sameRequestRecord(request, active) || conflict(request, active) {
						return nil, &BusyError{Active: active, Waited: lockBusy.waited, Now: c.now().UTC()}
					}
				}
			}
		}
		return nil, err
	}
	return result, nil
}

// Attach validates the complete reservation identity while holding the flock.
// The preferred form is Attach(ctx, id, principal, ownerKey, host, kind, app).
// The legacy three-argument form is accepted only for records that predate
// owner-key and host binding; current records fail closed until the exact form
// is supplied.
func (c *Coordinator) Attach(ctx context.Context, id string, args ...string) (*Handle, error) {
	if !identifierPattern.MatchString(id) || (len(args) != 3 && len(args) != 5) {
		return nil, errors.New("invalid operation attachment")
	}
	principal, owner, host, kind, app := args[0], "", "", args[1], args[2]
	if len(args) == 5 {
		owner, host, kind, app = args[1], args[2], args[3], args[4]
	}
	if principal == "" || !kindPattern.MatchString(kind) || (app != "" && !appPattern.MatchString(app)) || (owner != "" && !fingerprintPattern.MatchString(owner)) {
		return nil, errors.New("invalid operation attachment")
	}
	var handle *Handle
	err := c.withLock(ctx, func() error {
		record, err := c.readRecord(id)
		if err != nil {
			return err
		}
		if record.Principal != principal || record.Kind != kind || record.App != app {
			return errors.New("operation identity does not match the reservation")
		}
		if record.OwnerKeyFingerprint != owner || record.Host != host {
			return errors.New("operation owner key does not match the principal")
		}
		if record.State != "active" || record.RecoveryRequired {
			return errors.New("operation is not active and cannot be attached")
		}
		boot, err := c.bootID()
		if err != nil {
			return fmt.Errorf("read host boot id: %w", err)
		}
		if stale(record, c.now().UTC(), boot) {
			return errors.New("operation lease or host boot is stale and cannot be attached")
		}
		handle = handleFor(c, record)
		return nil
	})
	return handle, err
}

func handleFor(c *Coordinator, record Record) *Handle {
	return &Handle{c: c, id: record.ID, key: record.Principal, owner: record.OwnerKeyFingerprint, host: record.Host, kind: record.Kind, app: record.App}
}

func (h *Handle) ID() string { return h.id }

// ExecutePhase is the safe public phase entrypoint for callers that already
// hold a reservation. The callback runs while the same exclusive flock is
// held as the phase journal writes, or, for a Concurrent request, while the
// application's executor flock is held.
func (c *Coordinator) ExecutePhase(ctx context.Context, request PhaseRequest, mutate func(context.Context, Record) error) error {
	if err := validatePhaseRequest(request); err != nil {
		return err
	}
	if mutate == nil {
		return errors.New("phase mutation callback is required")
	}
	return c.executePhase(ctx, request, mutate)
}

func (h *Handle) ExecutePhase(ctx context.Context, name string, mutate func(context.Context, Record) error) error {
	return h.c.ExecutePhase(ctx, PhaseRequest{ID: h.id, Kind: h.kind, App: h.app, Principal: h.key, OwnerKeyFingerprint: h.owner, Host: h.host, Name: name}, mutate)
}

func (c *Coordinator) executePhase(ctx context.Context, request PhaseRequest, mutate func(context.Context, Record) error) error {
	if request.Concurrent {
		return c.executeConcurrentPhase(ctx, request, mutate)
	}
	return c.withLock(ctx, func() error {
		record, err := c.beginPhaseLocked(request)
		if err != nil {
			return err
		}
		mutationErr := c.runPhaseMutation(ctx, request, record, mutate, holdJournalAlready)
		return c.finishPhaseLocked(request, mutationErr)
	})
}

// executeConcurrentPhase is ExecutePhase for one application's callback that
// may overlap another application's.
//
// The fence moves from the host flock to the application's executor flock,
// taken first and held until the outcome is durable. Journal transitions still
// happen under the host flock, briefly, so every read-modify-write of a record
// stays serialised with Reserve, Control and the other executor. The global
// fence is not lost: a global kind cannot be reserved while this application's
// record is active, and this record could not have been reserved while one was.
func (c *Coordinator) executeConcurrentPhase(ctx context.Context, request PhaseRequest, mutate func(context.Context, Record) error) error {
	if IsGlobal(request.Kind) || request.App == "" {
		return errors.New("only an application-scoped phase may run concurrently")
	}
	err := c.withFileLock(ctx, c.applicationLockPath(request.App), c.lockWait, func() error {
		var record Record
		if err := c.withLock(ctx, func() error {
			var beginErr error
			record, beginErr = c.beginPhaseLocked(request)
			return beginErr
		}); err != nil {
			return err
		}
		mutationErr := c.runPhaseMutation(ctx, request, record, mutate, c.holdJournalBriefly)
		// The outcome is worth waiting longer for than a reservation: giving up
		// here leaves an open phase that only lease expiry can turn into
		// recovery_required. Four ordinary waits cover any journal transition.
		return c.withLockPatiently(ctx, 4, func() error {
			return c.finishPhaseLocked(request, mutationErr)
		})
	})
	var busy *lockBusyError
	if errors.As(err, &busy) && busy.path == c.applicationLockPath(request.App) {
		return fmt.Errorf("an earlier executor of application %s still holds its lock: %w", request.App, err)
	}
	return err
}

// beginPhaseLocked validates a phase request against its durable record and
// writes phase-start. The caller holds the host journal flock.
func (c *Coordinator) beginPhaseLocked(request PhaseRequest) (Record, error) {
	record, err := c.readRecord(request.ID)
	if err != nil {
		return Record{}, err
	}
	if err := c.validatePhaseIdentity(record, request); err != nil {
		return Record{}, err
	}
	if hasKnownFailedCommand(record) {
		return Record{}, errors.New("a known failed operation permits only refuse, abort or a phase-less client renew")
	}
	boot, err := c.bootID()
	if err != nil {
		return Record{}, fmt.Errorf("read host boot id: %w", err)
	}
	now := c.now().UTC()
	if stale(record, now, boot) {
		staleRecord, markErr := c.markStale(record, now)
		if markErr != nil {
			return Record{}, markErr
		}
		record = staleRecord
		if writeErr := c.writeRecord(record); writeErr != nil {
			return Record{}, errors.Join(errors.New("operation lease or host boot is stale"), writeErr)
		}
		return Record{}, errors.New("operation lease or host boot is stale; recovery is required")
	}
	if !request.PlanExpiresAt.IsZero() && !request.PlanExpiresAt.After(now) {
		return Record{}, errors.New("signed operation phase expired before the mutation lock was acquired")
	}
	if request.HostIdentity != "" && request.HostIdentity != request.Host {
		return Record{}, errors.New("signed operation host identity does not match the reservation")
	}
	if request.Validate != nil {
		if err := request.Validate(record); err != nil {
			return Record{}, err
		}
	}
	// The SSH reply can be lost after success but before operation-finish.
	// Refuse a replay under the mutation lock, even after client progress
	// appended another phase: declared commands need not be idempotent.
	if record.Kind == "run" && request.Name == "run" {
		for _, phase := range record.Phases {
			if phase.Name == "run" && phase.EndedAt != "" && phase.Error == "" {
				return Record{}, errors.New("run already completed successfully; refusing to execute the command again")
			}
		}
	}
	if len(record.Phases) >= MaxJournalItems {
		return Record{}, errors.New("operation journal phase history is full")
	}
	if err := c.ensureExecutePhaseCapacity(record, request); err != nil {
		return Record{}, err
	}
	started := Phase{Name: request.Name, StartedAt: now.Format(time.RFC3339Nano)}
	record.Phases = append(record.Phases, started)
	record.UpdatedAt = now.Format(time.RFC3339Nano)
	c.appendEvent(&record, now, "phase-start", request.Name, false)
	if err := c.writeRecord(record); err != nil {
		return Record{}, fmt.Errorf("durably record phase start: %w", err)
	}
	return record, nil
}

// runPhaseMutation runs the callback while a heartbeat renews the lease. hold
// wraps each heartbeat write in whatever lock the phase mode requires.
func (c *Coordinator) runPhaseMutation(ctx context.Context, request PhaseRequest, record Record, mutate func(context.Context, Record) error, hold func(func() error) error) error {
	heartbeatDone := make(chan struct{})
	renewalErr := make(chan error, 1)
	go c.renewPhaseLease(record, request.Name, hold, heartbeatDone, renewalErr)
	ctx = context.WithValue(ctx, phaseJournalKey{}, &phaseJournal{c: c, request: request, hold: hold})
	mutationErr := invokeMutation(mutate, ctx, record)
	close(heartbeatDone)
	if err := <-renewalErr; err != nil {
		mutationErr = errors.Join(mutationErr, err)
	}
	return mutationErr
}

type phaseJournalKey struct{}

// phaseJournal is the running phase's handle on its own record. hold is the
// same lock discipline the heartbeat uses: nothing for a fenced phase, whose
// callback already runs under the host flock, and the host flock briefly for a
// concurrent one.
type phaseJournal struct {
	c       *Coordinator
	request PhaseRequest
	hold    func(func() error) error
}

type recoveryJournalKey struct{}

type recoveryJournal struct {
	c          *Coordinator
	id         string
	planDigest string
	mu         sync.Mutex
	active     bool
}

func (journal *recoveryJournal) close() {
	journal.mu.Lock()
	journal.active = false
	journal.mu.Unlock()
}

// JournalCurrentManifest durably records, from inside a running phase, the
// digest of the current.yml the phase is about to write. Call it before the
// file is written, and do not write the file if it fails.
//
// Recovery authorizes a retained manifest only against proof. Until this
// existed the only proof was the closed writer baseline, taken before the
// deploy, so it named the release that was serving, never the one being
// promoted. A deploy interrupted after stack-apply wrote current.yml left a
// file recovery called "unknown retained current artifact is not authorized"
// (web, 2026-10-08), even though this very operation had produced it
// from a signed payload. Journaling the digest first gives that file an owner:
// if the bytes on disk hash to what the operation recorded, they are the
// operation's own; anything else is still unknown and still refused. Written
// before the file, so a crash between the two leaves a digest naming a file
// that was never written, which proves nothing and authorizes nothing.
func JournalCurrentManifest(ctx context.Context, digest string) error {
	journal, ok := ctx.Value(phaseJournalKey{}).(*phaseJournal)
	if !ok || journal == nil {
		return errors.New("a current manifest can be journaled only from inside an executing phase")
	}
	if !digestPattern.MatchString(digest) {
		return errors.New("current manifest digest must be a full sha256 digest")
	}
	c := journal.c
	return journal.hold(func() error {
		c.lockJournal("current-manifest")
		defer c.unlockJournal()
		latest, err := c.readRecord(journal.request.ID)
		if err != nil {
			return fmt.Errorf("read operation journal for current manifest: %w", err)
		}
		if err := c.validatePhaseIdentity(latest, journal.request); err != nil {
			return err
		}
		if len(latest.Phases) == 0 || latest.Phases[len(latest.Phases)-1].Name != journal.request.Name || latest.Phases[len(latest.Phases)-1].EndedAt != "" {
			return errors.New("current manifest can be journaled only while its phase is open")
		}
		if latest.CurrentManifestSHA256 == digest {
			return nil
		}
		latest.CurrentManifestSHA256 = digest
		latest.UpdatedAt = c.now().UTC().Format(time.RFC3339Nano)
		if err := c.writeRecordLocked(latest); err != nil {
			return fmt.Errorf("durably record current manifest digest: %w", err)
		}
		return nil
	})
}

// JournalFirstReleaseConvergence records the first release's convergence
// lifecycle from inside stack-apply. Pending is written before Docker is
// called, then replaced with the terminal result after the convergence wait.
// A missing or pending result is deliberately not proof that removal is safe.
func JournalFirstReleaseConvergence(ctx context.Context, state string) error {
	journal, ok := ctx.Value(phaseJournalKey{}).(*phaseJournal)
	if !ok || journal == nil {
		return errors.New("first-release convergence can be journaled only from inside an executing phase")
	}
	if state != FirstReleaseConvergencePending && state != FirstReleaseConvergenceFailed && state != FirstReleaseConvergenceSucceeded {
		return errors.New("first-release convergence state is invalid")
	}
	c := journal.c
	return journal.hold(func() error {
		c.lockJournal("first-release-convergence")
		defer c.unlockJournal()
		latest, err := c.readRecord(journal.request.ID)
		if err != nil {
			return fmt.Errorf("read operation journal for first-release convergence: %w", err)
		}
		if err := c.validatePhaseIdentity(latest, journal.request); err != nil {
			return err
		}
		if journal.request.Kind != "deploy" || journal.request.Name != "stack-apply" ||
			len(latest.Phases) == 0 || latest.Phases[len(latest.Phases)-1].Name != journal.request.Name ||
			latest.Phases[len(latest.Phases)-1].EndedAt != "" {
			return errors.New("first-release convergence can be journaled only during deploy stack-apply")
		}
		digest := latest.CurrentManifestSHA256
		if digest == "" || !digestPattern.MatchString(digest) {
			return errors.New("first-release convergence requires the operation's journaled current manifest")
		}
		if latest.FirstReleaseConvergenceManifestSHA256 != "" && latest.FirstReleaseConvergenceManifestSHA256 != digest {
			return errors.New("first-release convergence is bound to a different current manifest")
		}
		current := latest.FirstReleaseConvergenceState
		switch {
		case current == "" && state == FirstReleaseConvergencePending:
		case current == FirstReleaseConvergencePending:
		case current == state && current != "":
		default:
			return errors.New("first-release convergence state transition is invalid")
		}
		latest.FirstReleaseConvergenceState = state
		latest.FirstReleaseConvergenceManifestSHA256 = digest
		latest.UpdatedAt = c.now().UTC().Format(time.RFC3339Nano)
		if err := c.writeRecordLocked(latest); err != nil {
			return fmt.Errorf("durably record first-release convergence: %w", err)
		}
		return nil
	})
}

// JournalRecoveryCurrentManifest durably records the current.yml digest
// produced by the active deploy recovery, before recovery publishes those
// bytes. It is bound to the recovery record and confirmed plan in the context
// supplied only to ApplyRecoveryWithProof's applier. The deploy's
// CurrentManifestSHA256 remains unchanged because it still proves the failed
// deploy's original artifact.
func JournalRecoveryCurrentManifest(ctx context.Context, digest string) error {
	journal, ok := ctx.Value(recoveryJournalKey{}).(*recoveryJournal)
	if !ok || journal == nil || journal.c == nil {
		return errors.New("a recovery current manifest can be journaled only from inside an executing recovery")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if !journal.active {
		return errors.New("a recovery current manifest can be journaled only from inside an executing recovery")
	}
	if !digestPattern.MatchString(digest) {
		return errors.New("recovery current manifest digest must be a full sha256 digest")
	}
	c := journal.c
	c.lockJournal("recovery-current-manifest")
	defer c.unlockJournal()
	latest, err := c.readRecord(journal.id)
	if err != nil {
		return fmt.Errorf("read operation journal for recovery current manifest: %w", err)
	}
	if latest.ID != journal.id || latest.State != RecoveryRequired || !latest.RecoveryRequired || latest.RecoveryIntent == nil || latest.RecoveryIntent.PlanDigest != journal.planDigest {
		return errors.New("recovery current manifest is not bound to the active recovery intent")
	}
	if latest.Kind != "deploy" {
		return errors.New("only deploy recovery can journal a recovery current manifest")
	}
	if latest.RecoveryCurrentManifestSHA256 == digest {
		return nil
	}
	if latest.RecoveryCurrentManifestSHA256 != "" {
		return errors.New("current.yml already rebound by this recovery; recover by hand")
	}
	latest.RecoveryCurrentManifestSHA256 = digest
	latest.UpdatedAt = c.now().UTC().Format(time.RFC3339Nano)
	if err := c.writeRecordLocked(latest); err != nil {
		return fmt.Errorf("durably record recovery current manifest digest: %w", err)
	}
	return nil
}

// JournalRunTarget durably records the container selected by the signed run
// plan before docker exec starts. A container ID is immutable and full length,
// so recovery can safely target only this executor even after a helper crash.
func JournalRunTarget(ctx context.Context, service, containerID string) error {
	journal, ok := ctx.Value(phaseJournalKey{}).(*phaseJournal)
	if !ok || journal == nil {
		return errors.New("a run target can be journaled only from inside an executing phase")
	}
	if !servicePattern.MatchString(service) {
		return errors.New("run target service name is invalid")
	}
	if !containerIDPattern.MatchString(containerID) {
		return errors.New("run target container must be a full 64-hex Docker container ID")
	}
	c := journal.c
	return journal.hold(func() error {
		c.lockJournal("run-target")
		defer c.unlockJournal()
		latest, err := c.readRecord(journal.request.ID)
		if err != nil {
			return fmt.Errorf("read operation journal for run target: %w", err)
		}
		if err := c.validatePhaseIdentity(latest, journal.request); err != nil {
			return err
		}
		if journal.request.Kind != "run" || journal.request.Name != "run" || len(latest.Phases) == 0 || latest.Phases[len(latest.Phases)-1].Name != journal.request.Name || latest.Phases[len(latest.Phases)-1].EndedAt != "" {
			return errors.New("run target can be journaled only while its run phase is open")
		}
		if latest.RunTarget != nil {
			if latest.RunTarget.Service == service && latest.RunTarget.Container == containerID {
				return nil
			}
			return errors.New("run target is already journaled for this operation")
		}
		latest.RunTarget = &RunTarget{Service: service, Container: containerID}
		latest.UpdatedAt = c.now().UTC().Format(time.RFC3339Nano)
		if err := c.writeRecordLocked(latest); err != nil {
			return fmt.Errorf("durably record run target: %w", err)
		}
		return nil
	})
}

// finishPhaseLocked records the phase outcome. The caller holds the host
// journal flock; a failed mutation leaves the record recovery_required.
func (c *Coordinator) finishPhaseLocked(request PhaseRequest, mutationErr error) error {
	c.lockJournal("phase-outcome")
	defer c.unlockJournal()
	ended := c.now().UTC()
	latest, readErr := c.readRecord(request.ID)
	if readErr != nil {
		return errors.Join(mutationErr, fmt.Errorf("read phase outcome journal: %w", readErr))
	}
	if latest.State != "active" || latest.RecoveryRequired {
		return errors.Join(mutationErr, errors.New("phase journal changed during mutation; recovery is required"))
	}
	if len(latest.Phases) == 0 || latest.Phases[len(latest.Phases)-1].Name != request.Name || latest.Phases[len(latest.Phases)-1].EndedAt != "" {
		return errors.Join(mutationErr, errors.New("phase journal changed during mutation; recovery is required"))
	}
	record := latest
	phase := &record.Phases[len(record.Phases)-1]
	phase.EndedAt = ended.Format(time.RFC3339Nano)
	record.UpdatedAt = phase.EndedAt
	// A direct type assertion, not errors.As: a warning joined with a lease
	// renewal failure, or wrapped by the caller, is not a phase that is known
	// to have completed.
	warning, warned := mutationErr.(*PhaseWarning)
	if warned && warning != nil {
		phase.Result = "phase completed with a warning"
		phase.Warning = cleanReason(warning.Error())
		record.LeaseUntil = ended.Add(c.lease).Format(time.RFC3339Nano)
		c.appendEvent(&record, ended, "phase-complete", request.Name, false)
		if err := c.writeRecordLocked(record); err != nil {
			return errors.Join(mutationErr, fmt.Errorf("record completed phase outcome: %w", err))
		}
		return nil
	}
	known, knownOutcome := mutationErr.(*KnownOutcomeError)
	if knownOutcome && known != nil {
		phase.Error = cleanReason(known.Error())
		phase.Known = true
		phase.Result = "phase failed with a known outcome"
		record.LeaseUntil = ended.Add(c.lease).Format(time.RFC3339Nano)
		c.appendEvent(&record, ended, "phase-known", request.Name, false)
		if err := c.writeRecordLocked(record); err != nil {
			return errors.Join(mutationErr, fmt.Errorf("record known phase outcome: %w", err))
		}
		return mutationErr
	}
	if mutationErr != nil {
		phase.Error = cleanReason(mutationErr.Error())
		record.State = RecoveryRequired
		record.RecoveryRequired = true
		record.Result = cleanReason(mutationErr.Error())
		record.LeaseUntil = ""
		c.appendEvent(&record, ended, "phase-failed", request.Name, true)
		journalErr := c.writeRecordLocked(record)
		if journalErr != nil {
			return errors.Join(mutationErr, fmt.Errorf("record failed phase outcome: %w", journalErr))
		}
		return mutationErr
	}
	phase.Result = "phase completed"
	record.LeaseUntil = ended.Add(c.lease).Format(time.RFC3339Nano)
	c.appendEvent(&record, ended, "phase-complete", request.Name, false)
	if err := c.writeRecordLocked(record); err != nil {
		return fmt.Errorf("record completed phase outcome: %w", err)
	}
	return nil
}

func hasKnownFailedCommand(record Record) bool {
	name := "run"
	if record.Kind == "destroy" {
		name = "stack-apply"
	} else if record.Kind != "run" {
		return false
	}
	if len(record.Phases) == 0 {
		return false
	}
	phase := record.Phases[len(record.Phases)-1]
	return phase.Name == name && phase.EndedAt != "" && phase.Error != "" && phase.Known
}

// holdJournalAlready is the heartbeat lock of a fenced phase, whose caller
// already holds the host flock for the whole callback.
func holdJournalAlready(fn func() error) error { return fn() }

// holdJournalBriefly is the heartbeat lock of a concurrent phase: the host
// flock, only for the duration of one renewal write.
func (c *Coordinator) holdJournalBriefly(fn func() error) error {
	return c.withLock(context.Background(), fn)
}

func invokeMutation(mutate func(context.Context, Record) error, ctx context.Context, record Record) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("phase mutation panicked: %v", recovered)
		}
	}()
	return mutate(ctx, record)
}

// renewPhaseLease keeps a long callback from looking abandoned while its
// coordinator flock is still held. For a fenced phase renewal is lock-free for
// the same reason as the watchdog evidence write: no other compliant operation
// can mutate the journal while ExecutePhase owns the flock. A concurrent phase
// passes a hold that takes the host flock for each write; a renewal that finds
// that flock busy is retried on the next tick, because the lease still has two
// thirds left. If a renewal write fails, the phase cannot claim success and its
// final outcome becomes recovery-required.
func (c *Coordinator) renewPhaseLease(record Record, phaseName string, hold func(func() error) error, done <-chan struct{}, result chan<- error) {
	interval := c.lease / 3
	if lease, err := time.Parse(time.RFC3339Nano, record.LeaseUntil); err == nil {
		if remaining := lease.Sub(c.now().UTC()); remaining > 0 && remaining/3 < interval {
			interval = remaining / 3
		}
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			result <- nil
			return
		case <-ticker.C:
			err := hold(func() error {
				c.lockJournal("heartbeat")
				defer c.unlockJournal()
				latest, err := c.readRecord(record.ID)
				if err != nil {
					return fmt.Errorf("read operation heartbeat: %w", err)
				}
				if latest.State != "active" || latest.RecoveryRequired {
					return errors.New("operation heartbeat stopped because recovery or a terminal outcome is recorded")
				}
				boot, err := c.bootID()
				if err != nil {
					return fmt.Errorf("read heartbeat host boot id: %w", err)
				}
				now := c.now().UTC()
				if stale(latest, now, boot) || latest.HostBootID != record.HostBootID {
					return errors.New("operation heartbeat stopped because the host boot or lease is stale")
				}
				if len(latest.Phases) == 0 || latest.Phases[len(latest.Phases)-1].Name != phaseName || latest.Phases[len(latest.Phases)-1].EndedAt != "" {
					return errors.New("operation heartbeat stopped because the phase is no longer active")
				}
				lease, err := time.Parse(time.RFC3339Nano, latest.LeaseUntil)
				if err != nil || !lease.After(now) {
					return errors.New("operation lease expired before it could be renewed; recovery is required")
				}
				latest.UpdatedAt = now.Format(time.RFC3339Nano)
				latest.LeaseUntil = now.Add(c.lease).Format(time.RFC3339Nano)
				if err := c.writeRecordLocked(latest); err != nil {
					return fmt.Errorf("renew operation lease: %w", err)
				}
				return nil
			})
			var busy *lockBusyError
			if errors.As(err, &busy) {
				continue
			}
			if err != nil {
				result <- err
				return
			}
		}
	}
}

func (c *Coordinator) validatePhaseIdentity(record Record, request PhaseRequest) error {
	if record.Principal != request.Principal || record.Kind != request.Kind || record.App != request.App || record.OwnerKeyFingerprint != request.OwnerKeyFingerprint || record.Host != request.Host {
		return errors.New("operation identity does not match the reservation")
	}
	if record.State != "active" || record.RecoveryRequired {
		if record.RecoveryRequired {
			return ErrOperationRequiresRecovery
		}
		return errors.New("operation is not active for this phase")
	}
	return nil
}

func (h *Handle) Phase(name, result string) error {
	if err := validateLabel(name); err != nil {
		return err
	}
	return h.c.withLock(context.Background(), func() error {
		record, err := h.c.readRecord(h.id)
		if err != nil {
			return err
		}
		if err := h.validateRecord(record); err != nil {
			return err
		}
		if record.State != "active" || record.RecoveryRequired {
			if record.RecoveryRequired {
				return ErrOperationRequiresRecovery
			}
			return errors.New("operation is not active for this phase")
		}
		if hasKnownFailedCommand(record) {
			return errors.New("a known failed operation permits only refuse, abort or a phase-less client renew")
		}
		if len(record.Phases) >= MaxJournalItems {
			return errors.New("operation journal phase history is full")
		}
		boot, err := h.c.bootID()
		if err != nil {
			return fmt.Errorf("read host boot id: %w", err)
		}
		if stale(record, h.c.now().UTC(), boot) {
			staleRecord, markErr := h.c.markStale(record, h.c.now().UTC())
			if markErr != nil {
				return markErr
			}
			record = staleRecord
			if writeErr := h.c.writeRecord(record); writeErr != nil {
				return errors.Join(errors.New("operation lease or host boot is stale"), writeErr)
			}
			return errors.New("operation lease or host boot is stale; recovery is required")
		}
		if err := h.c.ensureCompletedPhaseCapacity(record, name); err != nil {
			return err
		}
		now := h.c.now().UTC()
		record.Phases = append(record.Phases, Phase{Name: name, StartedAt: now.Format(time.RFC3339Nano), EndedAt: now.Format(time.RFC3339Nano), Result: cleanReason(result)})
		record.UpdatedAt = now.Format(time.RFC3339Nano)
		record.LeaseUntil = now.Add(h.c.lease).Format(time.RFC3339Nano)
		h.c.appendEvent(&record, now, "phase", name, false)
		return h.c.writeRecord(record)
	})
}

func (h *Handle) Complete(result string) error { return h.finish("completed", false, result, nil) }
func (h *Handle) Fail(result string) error     { return h.finish("failed", false, result, nil) }
func (h *Handle) NeedsRecovery(result string, actions ...string) error {
	return h.finish(RecoveryRequired, true, result, actions)
}

// MarkWatchdogRecovery is lock-free by design. The root helper calls it while
// its watchdog owns the coordinator flock, immediately before os.Exit(75).
// Atomic replace and fsync make the phase-start and recovery evidence survive
// the process exit and any child process that remains behind.
func (h *Handle) MarkWatchdogRecovery(result string, actions ...string) error {
	h.c.lockJournal("watchdog")
	defer h.c.unlockJournal()
	record, err := h.c.readRecord(h.id)
	if err != nil {
		return err
	}
	if err := h.validateRecord(record); err != nil {
		return err
	}
	if record.State != "active" || record.RecoveryRequired {
		if record.State == RecoveryRequired && record.RecoveryRequired {
			return nil
		}
		return errors.New("operation is not active for watchdog recovery")
	}
	if err := validateActionList(actions); err != nil {
		return err
	}
	if err := reserveEventCapacity(record, recoveryRequiredEventBudget, "watchdog recovery"); err != nil {
		return err
	}
	now := h.c.now().UTC()
	record.State = RecoveryRequired
	record.RecoveryRequired = true
	record.Result = cleanReason(result)
	record.RecoveryActions = append([]string(nil), actions...)
	record.UpdatedAt = now.Format(time.RFC3339Nano)
	record.LeaseUntil = ""
	h.c.appendEvent(&record, now, "watchdog", "", true)
	return h.c.writeRecordLocked(record)
}

// MarkWatchdogRecoveryForPhase is the lock-free watchdog hook used by a root
// helper while ExecutePhase owns the flock. It repeats the phase identity
// check, but deliberately does not acquire the flock or require the plan to
// remain unexpired: the phase-start record is already durable and the watchdog
// must be able to publish recovery evidence immediately before os.Exit(75).
func (c *Coordinator) MarkWatchdogRecoveryForPhase(request PhaseRequest, result string, actions ...string) error {
	if err := validatePhaseRequest(request); err != nil {
		return err
	}
	c.lockJournal("watchdog")
	defer c.unlockJournal()
	record, err := c.readRecord(request.ID)
	if err != nil {
		return err
	}
	if record.State == RecoveryRequired && record.RecoveryRequired {
		return nil
	}
	if err := c.validatePhaseIdentity(record, request); err != nil {
		return err
	}
	if len(record.Phases) == 0 || record.Phases[len(record.Phases)-1].Name != request.Name || record.Phases[len(record.Phases)-1].EndedAt != "" {
		return errors.New("operation phase is no longer active for watchdog recovery")
	}
	if err := validateActionList(actions); err != nil {
		return err
	}
	if err := reserveEventCapacity(record, recoveryRequiredEventBudget, "watchdog recovery"); err != nil {
		return err
	}
	now := c.now().UTC()
	record.State = RecoveryRequired
	record.RecoveryRequired = true
	record.Result = cleanReason(result)
	record.RecoveryActions = append([]string(nil), actions...)
	record.UpdatedAt = now.Format(time.RFC3339Nano)
	record.LeaseUntil = ""
	c.appendEvent(&record, now, "watchdog", "", true)
	return c.writeRecordLocked(record)
}

func (h *Handle) validateRecord(record Record) error {
	if record.Principal != h.key || record.OwnerKeyFingerprint != h.owner || record.Host != h.host || record.Kind != h.kind || record.App != h.app {
		return errors.New("operation identity does not match the reservation")
	}
	return nil
}

func (h *Handle) finish(state string, recovery bool, result string, actions []string) error {
	if err := validateActionList(actions); err != nil {
		return err
	}
	return h.c.withLock(context.Background(), func() error {
		record, err := h.c.readRecord(h.id)
		if err != nil {
			return err
		}
		if err := h.validateRecord(record); err != nil {
			return err
		}
		if state != RecoveryRequired && record.State == "active" {
			boot, bootErr := h.c.bootID()
			if bootErr != nil {
				return fmt.Errorf("read host boot id: %w", bootErr)
			}
			if stale(record, h.c.now().UTC(), boot) {
				staleRecord, markErr := h.c.markStale(record, h.c.now().UTC())
				if markErr != nil {
					return markErr
				}
				record = staleRecord
				if writeErr := h.c.writeRecord(record); writeErr != nil {
					return errors.Join(errors.New("operation lease or host boot is stale"), writeErr)
				}
				return errors.New("operation lease or host boot is stale; recovery is required")
			}
		}
		if record.State == state && record.RecoveryRequired == recovery {
			return nil
		}
		if record.State != "active" {
			return errors.New("operation is already terminal")
		}
		if hasKnownFailedCommand(record) && state != RecoveryRequired {
			return errors.New("a known failed operation cannot be completed without operation-refuse")
		}
		budget := 1
		purpose := "terminal operation"
		if state == RecoveryRequired {
			budget = recoveryRequiredEventBudget
			purpose = "recovery transition"
		}
		if err := reserveEventCapacity(record, budget, purpose); err != nil {
			return err
		}
		now := h.c.now().UTC()
		record.State, record.RecoveryRequired, record.Result = state, recovery, cleanReason(result)
		record.RecoveryActions = append([]string(nil), actions...)
		record.UpdatedAt = now.Format(time.RFC3339Nano)
		record.LeaseUntil = ""
		h.c.appendEvent(&record, now, state, "", recovery)
		return h.c.writeRecord(record)
	})
}

func (h *Handle) Close() error {
	return h.c.withLock(context.Background(), func() error {
		record, err := h.c.readRecord(h.id)
		if err != nil {
			return err
		}
		if err := h.validateRecord(record); err != nil {
			return err
		}
		if record.State != "active" {
			return nil
		}
		if err := reserveEventCapacity(record, recoveryRequiredEventBudget, "closed operation recovery"); err != nil {
			return err
		}
		now := h.c.now().UTC()
		record.State, record.RecoveryRequired = RecoveryRequired, true
		record.Result = "operation ended before a terminal result was recorded"
		record.UpdatedAt = now.Format(time.RFC3339Nano)
		record.LeaseUntil = ""
		h.c.appendEvent(&record, now, "closed-without-outcome", "", true)
		return h.c.writeRecord(record)
	})
}

func (c *Coordinator) List(ctx context.Context) ([]Record, error) {
	var records []Record
	err := c.withLock(ctx, func() error {
		var err error
		records, err = c.readRecords()
		if err != nil {
			return err
		}
		for i := range records {
			records[i], err = c.virtualRecoveryState(records[i])
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].StartedAt < records[j].StartedAt })
	return records, nil
}

func (c *Coordinator) Get(ctx context.Context, id string) (Record, error) {
	if !identifierPattern.MatchString(id) {
		return Record{}, errors.New("invalid operation id")
	}
	var record Record
	err := c.withLock(ctx, func() error {
		var err error
		record, err = c.readRecord(id)
		return err
	})
	return record, err
}

// RecoveryPlan is read-only. It does not refresh or rewrite an expired record.
// The plan instead carries the stale state virtually, so a dry-run cannot race
// a caller by changing the journal.
func (c *Coordinator) RecoveryPlan(ctx context.Context, id string, observer Observer) (RecoveryPlan, error) {
	record, err := c.Get(ctx, id)
	if err != nil {
		return RecoveryPlan{}, err
	}
	record, err = c.virtualRecoveryState(record)
	if err != nil {
		return RecoveryPlan{}, err
	}
	if record.State == "completed" || record.State == "failed" || record.State == "recovered" {
		if record.State == "recovered" && record.RecoveryPlanDigest != "" {
			stored := validateObservationFreshness(normalizeObservation(record.RecoveryObservation), c.now().UTC())
			plan := makeRecoveryPlan(record, stored)
			plan.PlanDigest = record.RecoveryPlanDigest
			return plan, nil
		}
		return makeRecoveryPlan(record, RecoveryObservation{Safe: true, ServiceState: "already terminal"}), nil
	}
	var observed RecoveryObservation
	if observer == nil {
		observed = RecoveryObservation{ServiceState: "not observed", RegistryState: "not observed", DataState: "not observed"}
	} else {
		observed, err = observer(ctx, record)
		if err != nil {
			return RecoveryPlan{}, fmt.Errorf("observe recovery state: %w", err)
		}
	}
	if err := validateObservationEvidence(observed); err != nil {
		return RecoveryPlan{}, fmt.Errorf("invalid recovery observation: %w", err)
	}
	observed = normalizeObservation(observed)
	observed = validateObservationFreshness(observed, c.now().UTC())
	if err := validateObservationEvidence(observed); err != nil {
		return RecoveryPlan{}, fmt.Errorf("invalid recovery observation: %w", err)
	}
	return makeRecoveryPlan(record, observed), nil
}

func (c *Coordinator) ApplyRecovery(ctx context.Context, id, planDigest string, observer Observer) (RecoveryPlan, error) {
	return c.ApplyRecoveryWith(ctx, id, planDigest, observer, nil)
}

// ApplyRecoveryWith holds the exclusive flock from record re-read through
// observation, confirmation, action and post-action verification. A free flock
// by itself is never treated as proof that an executor stopped.
func (c *Coordinator) ApplyRecoveryWith(ctx context.Context, id, planDigest string, observer Observer, applier Applier) (RecoveryPlan, error) {
	return c.ApplyRecoveryWithProof(ctx, id, planDigest, time.Time{}, "", nil, observer, applier)
}

// ApplyRecoveryWithProof is the root-helper entrypoint. Expiry, host identity
// and the validator are checked after the recovery flock is acquired, before
// any observation or action. This closes the gap where a signed request could
// expire while it waited behind another operation.
func (c *Coordinator) ApplyRecoveryWithProof(ctx context.Context, id, planDigest string, planExpiresAt time.Time, hostIdentity string, validate func() error, observer Observer, applier Applier) (RecoveryPlan, error) {
	if !identifierPattern.MatchString(id) || planDigest == "" {
		return RecoveryPlan{}, errors.New("recovery requires a valid operation ID and confirmation digest")
	}
	var result RecoveryPlan
	err := c.withLock(ctx, func() error {
		record, err := c.readRecord(id)
		if err != nil {
			return err
		}
		now := c.now().UTC()
		if !planExpiresAt.IsZero() && !planExpiresAt.After(now) {
			return errors.New("signed recovery request expired before the recovery lock was acquired")
		}
		if hostIdentity != "" && record.Host != "" && record.Host != hostIdentity {
			return errors.New("signed recovery host identity does not match the operation")
		}
		if validate != nil {
			if err := validate(); err != nil {
				return err
			}
		}
		if record.State == "recovered" {
			if record.RecoveryPlanDigest == "" || record.RecoveryPlanDigest != planDigest {
				return errors.New("recovery confirmation does not match the recorded recovery identity")
			}
			stored := validateObservationFreshness(normalizeObservation(record.RecoveryObservation), c.now().UTC())
			if !stored.Safe {
				return errors.New("recorded recovery proof is no longer fresh")
			}
			result = makeRecoveryPlan(record, stored)
			result.PlanDigest = record.RecoveryPlanDigest
			return nil
		}
		if record.State == "completed" || record.State == "failed" {
			return errors.New("terminal operation does not require recovery")
		}
		record, err = c.virtualRecoveryState(record)
		if err != nil {
			return err
		}
		boot, err := c.bootID()
		if err != nil {
			return fmt.Errorf("read host boot id: %w", err)
		}
		if record.State == "active" && !stale(record, c.now().UTC(), boot) {
			return errors.New("a live unexpired executor is still recorded; recovery is refused")
		}
		// Recovery restarts the registry and reloads the edge, which another
		// application's promotion may be using now that promotions overlap.
		// A live executor anywhere on the host therefore defers it.
		others, err := c.readRecords()
		if err != nil {
			return err
		}
		for _, other := range others {
			if other.ID != record.ID && other.State == "active" && !stale(other, c.now().UTC(), boot) {
				return &BusyError{Active: other, Now: c.now().UTC()}
			}
		}
		if observer == nil || applier == nil {
			return errors.New("recovery requires an observer and an applier")
		}
		observed, err := observer(ctx, record)
		if err != nil {
			return fmt.Errorf("observe recovery state: %w", err)
		}
		if err := validateObservationEvidence(observed); err != nil {
			return fmt.Errorf("invalid recovery observation: %w", err)
		}
		observed = normalizeObservation(observed)
		observed = validateObservationFreshness(observed, c.now().UTC())
		if err := validateObservationEvidence(observed); err != nil {
			return fmt.Errorf("invalid recovery observation: %w", err)
		}
		result = makeRecoveryPlan(record, observed)
		if result.PlanDigest != planDigest {
			return errors.New("recovery plan changed since dry-run; obtain a fresh confirmation")
		}
		if !observed.Safe {
			return fmt.Errorf("recovery observation is unsafe: %s", missingProofMessage(observed))
		}
		if err := c.ensureRecoveryAttemptCapacity(record, result, observed); err != nil {
			return err
		}
		recoveryNow := c.now().UTC()
		record.State = RecoveryRequired
		record.RecoveryRequired = true
		record.RecoveryIntent = &RecoveryIntent{PlanDigest: result.PlanDigest, StartedAt: recoveryNow.Format(time.RFC3339Nano), Actions: append([]string(nil), result.Actions...)}
		record.UpdatedAt = recoveryNow.Format(time.RFC3339Nano)
		record.LeaseUntil = ""
		c.appendEvent(&record, recoveryNow, "recovery-start", "", true)
		if err := c.writeRecord(record); err != nil {
			return fmt.Errorf("durably record recovery start: %w", err)
		}
		record, err = c.readRecord(id)
		if err != nil {
			return fmt.Errorf("read durable recovery start: %w", err)
		}
		recoveryBinding := &recoveryJournal{c: c, id: record.ID, planDigest: record.RecoveryIntent.PlanDigest, active: true}
		recoveryCtx := context.WithValue(ctx, recoveryJournalKey{}, recoveryBinding)
		applyErr := applier(recoveryCtx, record, observed)
		recoveryBinding.close()
		fresh, readErr := c.readRecord(id)
		if readErr != nil {
			if applyErr != nil {
				return errors.Join(fmt.Errorf("apply recovery actions: %w", applyErr), fmt.Errorf("read operation journal after recovery actions: %w", readErr))
			}
			return fmt.Errorf("read operation journal after recovery actions: %w", readErr)
		}
		if fresh.ID != record.ID || fresh.State != RecoveryRequired || !fresh.RecoveryRequired || fresh.RecoveryIntent == nil || fresh.RecoveryIntent.PlanDigest != record.RecoveryIntent.PlanDigest {
			return errors.New("operation recovery identity changed while recovery actions were applying")
		}
		record = fresh
		if applyErr != nil {
			wrappedApplyErr := fmt.Errorf("apply recovery actions: %w", applyErr)
			if journalErr := c.recordRecoveryFailure(record, applyErr); journalErr != nil {
				return errors.Join(wrappedApplyErr, fmt.Errorf("record recovery failure: %w", journalErr))
			}
			return wrappedApplyErr
		}
		verified, err := observer(ctx, record)
		if err != nil {
			verifyErr := fmt.Errorf("verify recovery result: %w", err)
			if journalErr := c.recordRecoveryFailure(record, err); journalErr != nil {
				return errors.Join(verifyErr, fmt.Errorf("record recovery failure: %w", journalErr))
			}
			return verifyErr
		}
		if err := validateObservationEvidence(verified); err != nil {
			if journalErr := c.recordRecoveryFailure(record, err); journalErr != nil {
				return errors.Join(err, fmt.Errorf("record recovery failure: %w", journalErr))
			}
			return fmt.Errorf("invalid recovery observation: %w", err)
		}
		verified = normalizeObservation(verified)
		verified = validateObservationFreshness(verified, c.now().UTC())
		if err := validateObservationEvidence(verified); err != nil {
			if journalErr := c.recordRecoveryFailure(record, err); journalErr != nil {
				return errors.Join(err, fmt.Errorf("record recovery failure: %w", journalErr))
			}
			return fmt.Errorf("invalid recovery observation: %w", err)
		}
		if err := validatePostRecoveryObservation(verified); err != nil {
			if journalErr := c.recordRecoveryFailure(record, err); journalErr != nil {
				return errors.Join(err, fmt.Errorf("record recovery failure: %w", journalErr))
			}
			return fmt.Errorf("recovery actions did not produce sufficient post-action proof: %w", err)
		}
		now = c.now().UTC()
		started := copyRecord(record)
		recovered := copyRecord(record)
		recovered.State = "recovered"
		recovered.RecoveryRequired = false
		recovered.Result = "explicit recovery reconciled observed host state"
		recovered.UpdatedAt = now.Format(time.RFC3339Nano)
		recovered.LeaseUntil = ""
		recovered.RecoveryActions = append([]string(nil), result.Actions...)
		recovered.RecoveryPlanDigest = result.PlanDigest
		recovered.RecoveryObservation = verified
		recovered.RecoveryIntent = nil
		if err := reserveEventCapacity(recovered, 1, "recovered outcome"); err != nil {
			return err
		}
		c.appendEvent(&recovered, now, "recovered", "", false)
		serialized, err := journalWritePayload(recovered)
		if err != nil {
			return err
		}
		if len(serialized) > MaxJournalBytes {
			if journalErr := c.recordUnrecordableRecoveryProof(started); journalErr != nil {
				return errors.Join(errors.New(unrecordableRecoveryProof), fmt.Errorf("record recovery outcome: %w", journalErr))
			}
			return errors.New(unrecordableRecoveryProof)
		}
		return c.writeRecord(recovered)
	})
	if err != nil {
		return result, err
	}
	return result, nil
}

func (c *Coordinator) virtualRecoveryState(record Record) (Record, error) {
	if record.State != "active" {
		return record, nil
	}
	boot, err := c.bootID()
	if err != nil {
		return Record{}, fmt.Errorf("read host boot id: %w", err)
	}
	if stale(record, c.now().UTC(), boot) {
		record.State = RecoveryRequired
		record.RecoveryRequired = true
		record.Result = "operation lease expired or host boot changed; executor fence is not proven"
		record.LeaseUntil = ""
	}
	return record, nil
}

func (c *Coordinator) recordRecoveryFailure(record Record, failure error) error {
	if err := reserveEventCapacity(record, 1, "recovery failure outcome"); err != nil {
		return err
	}
	now := c.now().UTC()
	record.State = RecoveryRequired
	record.RecoveryRequired = true
	record.Result = cleanReason(failure.Error())
	record.UpdatedAt = now.Format(time.RFC3339Nano)
	record.LeaseUntil = ""
	c.appendEvent(&record, now, "recovery-failed", "", true)
	return c.writeRecord(record)
}

func (c *Coordinator) recordUnrecordableRecoveryProof(record Record) error {
	if err := reserveEventCapacity(record, 1, "unrecordable recovery proof"); err != nil {
		return err
	}
	now := c.now().UTC()
	record.State = RecoveryRequired
	record.RecoveryRequired = true
	record.Result = unrecordableRecoveryProof
	record.UpdatedAt = now.Format(time.RFC3339Nano)
	record.LeaseUntil = ""
	c.appendEvent(&record, now, "recovery-failed", "", true)
	return c.writeRecord(record)
}

func normalizeObservation(observed RecoveryObservation) RecoveryObservation {
	missing := append([]string(nil), observed.MissingProof...)
	checks := []struct {
		name  string
		value string
	}{
		{"observed_at", observed.ObservedAt},
		{"process_version", observed.ProcessVersion},
		{"boot_version", observed.BootVersion},
		{"phase_version", observed.PhaseVersion},
		{"resource_version", observed.ResourceVersion},
		{"executor_proof", observed.ExecutorProof},
		{"freshness", observed.Freshness},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.value) == "" && !contains(missing, check.name) {
			missing = append(missing, check.name)
		}
	}
	if observed.ExecutorCount != 0 && !contains(missing, "executor_count=0") {
		missing = append(missing, "executor_count=0")
	}
	for _, unresolved := range observed.Unresolved {
		if !contains(missing, unresolved) {
			missing = append(missing, unresolved)
		}
	}
	observed.MissingProof = missing
	observed.Actions = append([]string(nil), observed.Actions...)
	observed.Details = append([]string(nil), observed.Details...)
	observed.Unresolved = append([]string(nil), observed.Unresolved...)
	if len(observed.MissingProof) > 0 {
		observed.Safe = false
	}
	return observed
}

func validateObservationFreshness(observed RecoveryObservation, now time.Time) RecoveryObservation {
	observedAt, observedErr := time.Parse(time.RFC3339Nano, observed.ObservedAt)
	freshness, freshnessErr := time.Parse(time.RFC3339Nano, observed.Freshness)
	if observedErr != nil || freshnessErr != nil || observedAt.After(now) || freshness.After(now) || now.Sub(freshness) > 5*time.Minute {
		if !contains(observed.MissingProof, "freshness_window") {
			observed.MissingProof = append(observed.MissingProof, "freshness_window")
		}
		observed.Safe = false
	}
	return observed
}

func validatePostRecoveryObservation(observed RecoveryObservation) error {
	if !observed.Safe {
		return errors.New(missingProofMessage(observed))
	}
	if len(observed.Actions) > 0 {
		return errors.New("recovery postcheck still has required actions")
	}
	if len(observed.Unresolved) > 0 {
		return errors.New("recovery postcheck still has unresolved evidence")
	}
	if len(observed.MissingProof) > 0 {
		return errors.New(missingProofMessage(observed))
	}
	return nil
}

func makeRecoveryPlan(record Record, observation RecoveryObservation) RecoveryPlan {
	actions := append([]string(nil), observation.Actions...)
	if record.Kind == "run" && observation.Safe && len(actions) == 0 {
		actions = []string{}
	} else if len(actions) == 0 {
		actions = append(actions, record.RecoveryActions...)
		if len(actions) == 0 {
			if len(observation.Unresolved) > 0 || len(observation.MissingProof) > 0 {
				actions = []string{"unresolved: retain operation markers and obtain the missing executor or resource proof"}
			} else {
				actions = []string{"verify the observed executor fence and retained current and previous release identities"}
			}
		}
	}
	plan := RecoveryPlan{Schema: "shuttle.recovery-plan/v1", ID: record.ID, State: record.State, Observed: observation, Actions: append([]string{}, actions...)}
	body, _ := json.Marshal(struct {
		Schema              string              `json:"schema"`
		ID                  string              `json:"id"`
		Revision            uint64              `json:"revision"`
		State               string              `json:"state"`
		RecoveryRequired    bool                `json:"recovery_required"`
		Kind                string              `json:"kind"`
		Scope               string              `json:"scope"`
		App                 string              `json:"app"`
		Principal           string              `json:"principal"`
		OwnerKeyFingerprint string              `json:"owner_key_fingerprint"`
		Host                string              `json:"host"`
		HostBootID          string              `json:"host_boot_id"`
		Phases              []Phase             `json:"phases"`
		Proof               stableRecoveryProof `json:"proof"`
		Actions             []string            `json:"actions"`
	}{Schema, record.ID, record.Revision, record.State, record.RecoveryRequired, record.Kind, record.Scope, record.App, record.Principal, record.OwnerKeyFingerprint, record.Host, record.HostBootID, append([]Phase(nil), record.Phases...), stableRecoveryProofFor(observation), append([]string(nil), plan.Actions...)})
	sum := sha256.Sum256(body)
	plan.PlanDigest = "sha256:" + hex.EncodeToString(sum[:])
	return plan
}

// stableRecoveryProof omits only volatile observation timestamps and freshness.
// Every other validated semantic field remains part of the confirmation.
type stableRecoveryProof struct {
	Details          []string `json:"details,omitempty"`
	Safe             bool     `json:"safe"`
	ProcessVersion   string   `json:"process_version"`
	BootVersion      string   `json:"boot_version"`
	PhaseVersion     string   `json:"phase_version"`
	ResourceVersion  string   `json:"resource_version"`
	ExecutorCount    int      `json:"executor_count"`
	ExecutorProof    string   `json:"executor_proof"`
	PendingBackup    bool     `json:"pending_backup"`
	OriginalReplicas int      `json:"original_replicas"`
	ServiceState     string   `json:"service_state"`
	RegistryState    string   `json:"registry_state"`
	DataState        string   `json:"data_state"`
	CurrentDigest    string   `json:"current_digest"`
	PreviousDigest   string   `json:"previous_digest"`
	ManifestProof    string   `json:"manifest_proof"`
	MarkerProof      string   `json:"marker_proof"`
	ResourceProof    string   `json:"resource_proof"`
	ActionProof      string   `json:"action_proof"`
	Actions          []string `json:"actions"`
	MissingProof     []string `json:"missing_proof"`
	Unresolved       []string `json:"unresolved"`
}

func stableRecoveryProofFor(observed RecoveryObservation) stableRecoveryProof {
	return stableRecoveryProof{
		Safe:           observed.Safe,
		ProcessVersion: observed.ProcessVersion, BootVersion: observed.BootVersion,
		PhaseVersion: observed.PhaseVersion, ResourceVersion: observed.ResourceVersion,
		ExecutorCount: observed.ExecutorCount, ExecutorProof: observed.ExecutorProof,
		PendingBackup: observed.PendingBackup, OriginalReplicas: observed.OriginalReplicas,
		ServiceState: observed.ServiceState, RegistryState: observed.RegistryState,
		DataState: observed.DataState, CurrentDigest: observed.CurrentDigest,
		PreviousDigest: observed.PreviousDigest, ManifestProof: observed.ManifestProof,
		MarkerProof: observed.MarkerProof, ResourceProof: observed.ResourceProof,
		ActionProof: observed.ActionProof, Actions: append([]string(nil), observed.Actions...), Details: append([]string(nil), observed.Details...),
		MissingProof: append([]string(nil), observed.MissingProof...), Unresolved: append([]string(nil), observed.Unresolved...),
	}
}

func validateRequest(request Request) error {
	if request.ID != "" && !identifierPattern.MatchString(request.ID) {
		return errors.New("operation id must be lowercase hexadecimal or a canonical UUID")
	}
	if !kindPattern.MatchString(request.Kind) {
		return errors.New("invalid operation kind")
	}
	if !IsKnown(request.Kind) {
		return errors.New("unsupported operation kind")
	}
	if request.App != "" && !appPattern.MatchString(request.App) {
		return errors.New("invalid operation application")
	}
	if request.Principal == "" || len(request.Principal) > 256 || strings.ContainsAny(request.Principal, "\r\n\x00") {
		return errors.New("operation principal is required")
	}
	if request.OwnerKeyFingerprint != "" && !fingerprintPattern.MatchString(request.OwnerKeyFingerprint) {
		return errors.New("invalid operation owner key fingerprint")
	}
	return nil
}

func validatePhaseRequest(request PhaseRequest) error {
	if !identifierPattern.MatchString(request.ID) || !kindPattern.MatchString(request.Kind) || !IsKnown(request.Kind) || request.Principal == "" || !fingerprintPattern.MatchString(request.OwnerKeyFingerprint) || request.Host == "" || request.Name == "" {
		return errors.New("incomplete operation phase identity")
	}
	if request.App != "" && !appPattern.MatchString(request.App) {
		return errors.New("invalid operation phase application")
	}
	return validateLabel(request.Name)
}

func sameRequestRecord(request Request, record Record) bool {
	return record.ID == request.ID && record.Kind == request.Kind && record.App == request.App && record.Principal == request.Principal && record.OwnerKeyFingerprint == request.OwnerKeyFingerprint && record.Host == request.Host
}

func scopeFor(request Request) string {
	if IsGlobal(request.Kind) || request.App == "" {
		return "global"
	}
	return "application"
}

func conflict(request Request, active Record) bool {
	if active.State != "active" && !active.RecoveryRequired {
		return false
	}
	// A helper update waits for a live operation, never for one that awaits
	// recovery. Recovery is executed by the installed helper, so when that
	// helper is the defect, replacing it is the remedy: on the preprod VPS
	// (2026-10-15) a v0.0.20 helper verified the Caddy route with a `caddy
	// config` command that does not exist, every recovery of the aborted deploy
	// failed, and `helper update` was refused because that same deploy was
	// recovery_required. Nothing but a hand-installed binary could break the
	// loop. A recovery_required record has no lease left to fence: the helper
	// migration still requires its writer inventory to be closed, drains every
	// process of the old helper before completing, and the record itself stays
	// recovery_required for the new helper to recover.
	if request.Kind == "helper-update" && active.State != "active" {
		return false
	}
	if IsGlobal(request.Kind) || active.Scope == "global" {
		return true
	}
	return request.App != "" && request.App == active.App
}

func stale(record Record, now time.Time, boot string) bool {
	if record.HostBootID != "" && boot != "" && record.HostBootID != boot {
		return true
	}
	lease, err := time.Parse(time.RFC3339Nano, record.LeaseUntil)
	return err == nil && !lease.After(now)
}

func (c *Coordinator) markStale(record Record, now time.Time) (Record, error) {
	if err := reserveEventCapacity(record, recoveryRequiredEventBudget, "stale recovery"); err != nil {
		return Record{}, err
	}
	record.State = RecoveryRequired
	record.RecoveryRequired = true
	record.Result = "operation lease expired or host boot changed; executor fence is not proven"
	record.UpdatedAt = now.Format(time.RFC3339Nano)
	record.LeaseUntil = ""
	c.appendEvent(&record, now, "stale", "", true)
	return record, nil
}

func (c *Coordinator) withLock(ctx context.Context, fn func() error) error {
	return c.withLockWait(ctx, fn, nil)
}

// withLockPatiently is withLock retried up to attempts times while the only
// failure is a busy host flock.
func (c *Coordinator) withLockPatiently(ctx context.Context, attempts int, fn func() error) error {
	for attempt := 1; ; attempt++ {
		err := c.withLock(ctx, fn)
		var busy *lockBusyError
		if !errors.As(err, &busy) || busy.path != c.lockPath || attempt >= attempts {
			return err
		}
	}
}

// applicationLockPath is the executor flock of one application, beside the
// host flock: /run/shuttle-root.lock gives /run/shuttle-root.app-<app>.lock.
// The application name is already constrained to [a-z0-9-] by appPattern.
func (c *Coordinator) applicationLockPath(app string) string {
	return strings.TrimSuffix(c.lockPath, ".lock") + ".app-" + app + ".lock"
}

// WithSoleOperation runs fn under the host journal flock, and only if no
// operation other than id is active or awaiting recovery. Holding the flock
// keeps a new reservation from starting while fn runs.
//
// It exists for work that is safe only when nothing else touches the host, the
// registry garbage collector above all: it stops the registry and deletes every
// blob no manifest references, which includes the layers another application is
// pushing at that moment. Anything else, including a journal flock that stays
// busy, is reported as ErrOtherOperationsActive so the caller can defer.
func (c *Coordinator) WithSoleOperation(ctx context.Context, id string, fn func() error) error {
	err := c.withLock(ctx, func() error {
		records, err := c.readRecords()
		if err != nil {
			return err
		}
		for _, record := range records {
			if record.ID != id && (record.State == "active" || record.RecoveryRequired) {
				target := record.App
				if target == "" {
					target = "VPS"
				}
				return fmt.Errorf("%w: operation %s %s (target %s)", ErrOtherOperationsActive, record.ID, record.Kind, target)
			}
		}
		return fn()
	})
	var busy *lockBusyError
	if errors.As(err, &busy) && busy.path == c.lockPath {
		return fmt.Errorf("%w: %v", ErrOtherOperationsActive, err)
	}
	return err
}

func (c *Coordinator) withLockWait(ctx context.Context, fn func() error, waitedOut ...*time.Duration) error {
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return fmt.Errorf("create operation journal: %w", err)
	}
	return c.withFileLock(ctx, c.lockPath, c.lockWait, fn, waitedOut...)
}

// withFileLock takes an exclusive flock on path, polling for up to wait, and
// runs fn while it is held. A timeout is a *lockBusyError that names the path.
func (c *Coordinator) withFileLock(ctx context.Context, path string, wait time.Duration, fn func() error, waitedOut ...*time.Duration) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create operation lock directory: %w", err)
		}
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open operation lock: %w", err)
	}
	defer lock.Close()
	started := time.Now()
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if len(waitedOut) > 0 && waitedOut[0] != nil {
				*waitedOut[0] = time.Since(started)
			}
			defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			return fn()
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("take operation lock: %w", err)
		}
		waited := time.Since(started)
		if waited >= wait {
			if len(waitedOut) > 0 && waitedOut[0] != nil {
				*waitedOut[0] = waited
			}
			return &lockBusyError{waited: waited, path: path}
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Coordinator) readRecords() ([]Record, error) {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return nil, fmt.Errorf("read operation journal: %w", err)
	}
	var records []Record
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("operation journal entry %s is a symlink", entry.Name())
		}
		record, err := c.readRecord(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (c *Coordinator) readRecord(id string) (Record, error) {
	if !identifierPattern.MatchString(id) {
		return Record{}, errors.New("invalid operation id")
	}
	path := filepath.Join(c.root, id+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return Record{}, fmt.Errorf("read operation %s: %w", id, err)
	}
	if !info.Mode().IsRegular() {
		return Record{}, fmt.Errorf("invalid operation journal record %s", id)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Record{}, fmt.Errorf("read operation %s: %w", id, err)
	}
	if len(body) > MaxJournalBytes {
		return Record{}, errors.New("operation journal record is too large")
	}
	var record Record
	if err := json.Unmarshal(body, &record); err != nil || record.Schema != Schema || record.ID != id {
		return Record{}, fmt.Errorf("invalid operation journal record %s", id)
	}
	if err := validateLoadedRecord(record); err != nil {
		return Record{}, fmt.Errorf("invalid operation journal record %s: %w", id, err)
	}
	return record, nil
}

func validateLoadedRecord(record Record) error {
	if record.Schema != Schema || !identifierPattern.MatchString(record.ID) {
		return errors.New("schema or operation identity is invalid")
	}
	if !kindPattern.MatchString(record.Kind) || !IsKnown(record.Kind) {
		return errors.New("operation kind is unknown")
	}
	if record.App != "" && !appPattern.MatchString(record.App) {
		return errors.New("operation application is invalid")
	}
	expectedScope := scopeFor(Request{Kind: record.Kind, App: record.App})
	// A deploy, rollback or run journaled before 14-09-2026 carries scope
	// "global". Refusing it would make every journal with history unreadable
	// after a helper update, which fails every operation closed. It is accepted
	// as written, and conflict() keeps honouring it as global while it is live.
	legacyGlobalApplication := record.Scope == "global" && applicationKinds[record.Kind]
	if record.Scope != expectedScope && !legacyGlobalApplication {
		return errors.New("operation scope is inconsistent with its kind and application")
	}
	if record.Principal == "" || len(record.Principal) > 256 || strings.ContainsAny(record.Principal, "\r\n\x00") {
		return errors.New("operation principal is invalid")
	}
	if len(record.Result) > MaxReasonBytes || strings.ContainsAny(record.Result, "\r\n\x00") {
		return errors.New("operation result is invalid")
	}
	if record.OwnerKeyFingerprint != "" && !fingerprintPattern.MatchString(record.OwnerKeyFingerprint) {
		return errors.New("operation owner key fingerprint is invalid")
	}
	if record.Host != "" && (len(record.Host) > 256 || strings.ContainsAny(record.Host, "\r\n\x00")) {
		return errors.New("operation host identity is invalid")
	}
	if (record.Principal == "backup-source" || record.Principal == "restore-python") && (record.OwnerKeyFingerprint != "" || record.Host != "") {
		return errors.New("legacy Python operation has a partial signed identity")
	}
	if record.HostBootID == "" || len(record.HostBootID) > 256 || strings.ContainsAny(record.HostBootID, "\r\n\x00") {
		return errors.New("operation host boot identity is invalid")
	}
	started, err := parseJournalTime(record.StartedAt, "started_at")
	if err != nil {
		return err
	}
	updated, err := parseJournalTime(record.UpdatedAt, "updated_at")
	if err != nil {
		return err
	}
	if updated.Before(started) {
		return errors.New("operation updated_at precedes started_at")
	}
	if record.State != "active" && record.State != "completed" && record.State != "failed" && record.State != RecoveryRequired && record.State != "recovered" {
		return errors.New("operation state is unknown")
	}
	if record.State == "active" && record.RecoveryRequired {
		return errors.New("active operation cannot require recovery")
	}
	if record.State == RecoveryRequired && !record.RecoveryRequired {
		return errors.New("recovery_required state must require recovery")
	}
	if (record.State == "completed" || record.State == "failed" || record.State == "recovered") && record.RecoveryRequired {
		return errors.New("terminal operation cannot require recovery")
	}
	if record.State == "active" {
		if _, err := parseJournalTime(record.LeaseUntil, "lease_until"); err != nil {
			return err
		}
	} else if record.LeaseUntil != "" {
		return errors.New("terminal operation has a lease")
	}
	if err := validateJournalBounds(record); err != nil {
		return err
	}
	for _, phase := range record.Phases {
		if err := validateLabel(phase.Name); err != nil {
			return err
		}
		if len(phase.Result) > MaxReasonBytes || len(phase.Error) > MaxReasonBytes || len(phase.Warning) > MaxReasonBytes || strings.ContainsAny(phase.Result+phase.Error+phase.Warning, "\r\n\x00") {
			return errors.New("operation phase result is invalid")
		}
		phaseStart, err := parseJournalTime(phase.StartedAt, "phase.started_at")
		if err != nil {
			return err
		}
		if phase.EndedAt != "" {
			phaseEnd, err := parseJournalTime(phase.EndedAt, "phase.ended_at")
			if err != nil {
				return err
			}
			if phaseEnd.Before(phaseStart) {
				return errors.New("phase ended before it started")
			}
		}
	}
	for _, event := range record.Events {
		if _, err := parseJournalTimeAllowLegacy(event.At, "event.at"); err != nil {
			return err
		}
		if !validState(event.State) || event.Kind == "" || strings.ContainsAny(event.Kind, "\r\n\x00") {
			return errors.New("operation event is invalid")
		}
	}
	if record.RegistryReplacement != nil {
		if record.Kind != "deploy" {
			return errors.New("registry replacement belongs only to a deploy operation")
		}
		if err := record.RegistryReplacement.Validate(); err != nil {
			return err
		}
	}
	if record.CurrentManifestSHA256 != "" && !digestPattern.MatchString(record.CurrentManifestSHA256) {
		return errors.New("current manifest digest is invalid")
	}
	if record.RecoveryCurrentManifestSHA256 != "" && !digestPattern.MatchString(record.RecoveryCurrentManifestSHA256) {
		return errors.New("recovery current manifest digest is invalid")
	}
	if record.FirstReleaseConvergenceState == "" {
		if record.FirstReleaseConvergenceManifestSHA256 != "" {
			return errors.New("first-release convergence manifest digest has no state")
		}
	} else {
		if record.FirstReleaseConvergenceState != FirstReleaseConvergencePending &&
			record.FirstReleaseConvergenceState != FirstReleaseConvergenceFailed &&
			record.FirstReleaseConvergenceState != FirstReleaseConvergenceSucceeded {
			return errors.New("first-release convergence state is invalid")
		}
		if !digestPattern.MatchString(record.FirstReleaseConvergenceManifestSHA256) ||
			record.CurrentManifestSHA256 != record.FirstReleaseConvergenceManifestSHA256 {
			return errors.New("first-release convergence manifest binding is invalid")
		}
	}
	if len(record.RecoveryPlanDigest) > 0 && !digestPattern.MatchString(record.RecoveryPlanDigest) {
		return errors.New("recovery plan digest is invalid")
	}
	if record.RecoveryIntent != nil {
		if !record.RecoveryRequired || record.State != RecoveryRequired {
			return errors.New("recovery intent is inconsistent with operation state")
		}
		if !digestPattern.MatchString(record.RecoveryIntent.PlanDigest) {
			return errors.New("recovery intent digest is invalid")
		}
		if _, err := parseJournalTime(record.RecoveryIntent.StartedAt, "recovery_intent.started_at"); err != nil {
			return err
		}
		if err := validateActionList(record.RecoveryIntent.Actions); err != nil {
			return fmt.Errorf("recovery intent actions are invalid: %w", err)
		}
	}
	if err := validateActionList(record.RecoveryActions); err != nil {
		return fmt.Errorf("recovery actions are invalid: %w", err)
	}
	if err := validateLoadedObservation(record.RecoveryObservation); err != nil {
		return err
	}
	return nil
}

func validateLoadedObservation(observed RecoveryObservation) error {
	return validateObservationEvidence(observed)
}

func validateObservationEvidence(observed RecoveryObservation) error {
	// Inventory is display evidence, not one executable action per object.
	// Bound its bytes independently so multi-database destroy stays recoverable.
	bytes := 0
	for _, detail := range observed.Details {
		bytes += len(detail)
		if detail == "" || len(detail) > MaxReasonBytes || strings.ContainsAny(detail, "\r\n\x00") || bytes > MaxRecoveryDetailsBytes {
			return errors.New("recovery observation contains invalid details")
		}
	}
	if err := validateObservationCounts(observed); err != nil {
		return err
	}
	if len(observed.Actions) > MaxEvidenceItems || len(observed.MissingProof) > MaxEvidenceItems || len(observed.Unresolved) > MaxEvidenceItems {
		return errors.New("recovery observation contains too many entries")
	}
	values := []string{
		observed.ObservedAt, observed.ProcessVersion, observed.BootVersion,
		observed.PhaseVersion, observed.ResourceVersion, observed.ExecutorProof,
		observed.Freshness, observed.ServiceState, observed.RegistryState,
		observed.DataState, observed.CurrentDigest, observed.PreviousDigest,
		observed.ManifestProof, observed.MarkerProof, observed.ResourceProof,
		observed.ActionProof,
	}
	for _, value := range values {
		if len(value) > MaxReasonBytes || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("recovery observation contains invalid text")
		}
	}
	for _, value := range append(append(append([]string{}, observed.Actions...), observed.MissingProof...), observed.Unresolved...) {
		if value == "" || len(value) > MaxReasonBytes || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("recovery observation contains invalid evidence")
		}
	}
	return nil
}

func validateActionList(actions []string) error {
	if len(actions) > MaxEvidenceItems {
		return errors.New("too many recovery actions")
	}
	for _, action := range actions {
		if action == "" || len(action) > MaxReasonBytes || strings.ContainsAny(action, "\r\n\x00") {
			return errors.New("recovery action is invalid")
		}
	}
	return nil
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validState(state string) bool {
	return state == "active" || state == "completed" || state == "failed" || state == RecoveryRequired || state == "recovered"
}

func parseJournalTime(value, field string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("operation %s is missing", field)
	}
	return parseJournalTimeAllowLegacy(value, field)
}

func parseJournalTimeAllowLegacy(value, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed, nil
	}
	// The Python v1 journal used strftime("%f"), which leaves the literal
	// marker in event timestamps. Preserve those valid legacy records.
	if strings.Contains(value, "%f") {
		if parsed, legacyErr := time.Parse(time.RFC3339Nano, strings.Replace(value, "%f", "000000", 1)); legacyErr == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("operation %s has invalid time", field)
}

func (c *Coordinator) writeRecord(record Record) error {
	c.lockJournal("write")
	defer c.unlockJournal()
	return c.writeRecordLocked(record)
}

func (c *Coordinator) writeRecordLocked(record Record) error {
	if err := validateLoadedRecord(record); err != nil {
		return fmt.Errorf("refuse invalid operation journal record: %w", err)
	}
	serialized, err := journalWritePayload(record)
	if err != nil {
		return err
	}
	if len(serialized) > MaxJournalBytes {
		return fmt.Errorf("operation journal record exceeds the size limit: %d bytes (maximum %d)", len(serialized), MaxJournalBytes)
	}
	tmp, err := os.CreateTemp(c.root, ".operation-*.tmp")
	if err != nil {
		return fmt.Errorf("create operation journal temporary: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(serialized); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := c.sync(tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync operation journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(c.root, record.ID+".json")); err != nil {
		return fmt.Errorf("publish operation journal: %w", err)
	}
	dir, err := os.Open(c.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return c.sync(dir)
}

func (c *Coordinator) appendEvent(record *Record, now time.Time, kind, phase string, recovery bool) {
	record.Events = append(record.Events, Event{At: now.Format(time.RFC3339Nano), Kind: kind, State: record.State, Phase: phase, Recovery: recovery})
}

func validateJournalBounds(record Record) error {
	if len(record.Phases) > MaxJournalItems {
		return errors.New("operation journal phase history is too large")
	}
	if len(record.Events) > MaxJournalItems {
		return errors.New("operation journal event history is too large")
	}
	return nil
}

func reserveEventCapacity(record Record, needed int, transition string) error {
	if needed < 0 || len(record.Events) > MaxJournalItems-needed {
		return fmt.Errorf("operation journal event history cannot reserve %d entries for %s (have %d, maximum %d)", needed, transition, len(record.Events), MaxJournalItems)
	}
	return nil
}

func nextJournalRevision(revision uint64) (uint64, error) {
	if revision == 0 {
		return 1, nil
	}
	if revision == ^uint64(0) {
		return 0, errors.New("operation journal revision is saturated")
	}
	return revision + 1, nil
}

func encodeJournalRecord(record Record) ([]byte, error) {
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func journalWritePayload(record Record) ([]byte, error) {
	next, err := nextJournalRevision(record.Revision)
	if err != nil {
		return nil, err
	}
	record.Revision = next
	return encodeJournalRecord(record)
}

func maxJSONEscapedReason() string {
	return strings.Repeat("<", MaxReasonBytes)
}

func maxRecoveryActionList() []string {
	reason := maxJSONEscapedReason()
	actions := make([]string, MaxEvidenceItems)
	for i := range actions {
		actions[i] = reason
	}
	return actions
}

func maxConfirmationDigest() string {
	return "sha256:" + strings.Repeat("f", 64)
}

// capacityProbeRevision returns max uint64 so in-memory probes budget all 20
// decimal digits a durable revision can occupy, including heartbeat writes.
// Probes encode this sentinel directly and must never increment it through
// journalWritePayload, which would wrap to zero.
func capacityProbeRevision(_ uint64) uint64 {
	return ^uint64(0)
}

func copyRecord(record Record) Record {
	out := record
	if record.RegistryReplacement != nil {
		intent := *record.RegistryReplacement
		out.RegistryReplacement = &intent
	}
	if record.Phases != nil {
		out.Phases = append([]Phase(nil), record.Phases...)
	}
	if record.Events != nil {
		out.Events = append([]Event(nil), record.Events...)
	}
	if record.RecoveryActions != nil {
		out.RecoveryActions = append([]string(nil), record.RecoveryActions...)
	}
	if record.RecoveryIntent != nil {
		intent := *record.RecoveryIntent
		if record.RecoveryIntent.Actions != nil {
			intent.Actions = append([]string(nil), record.RecoveryIntent.Actions...)
		}
		out.RecoveryIntent = &intent
	}
	out.RecoveryObservation = copyObservation(record.RecoveryObservation)
	return out
}

func copyObservation(observed RecoveryObservation) RecoveryObservation {
	out := observed
	if observed.Actions != nil {
		out.Actions = append([]string(nil), observed.Actions...)
	}
	if observed.Details != nil {
		out.Details = append([]string(nil), observed.Details...)
	}
	if observed.MissingProof != nil {
		out.MissingProof = append([]string(nil), observed.MissingProof...)
	}
	if observed.Unresolved != nil {
		out.Unresolved = append([]string(nil), observed.Unresolved...)
	}
	return out
}

func (c *Coordinator) appendCapacityEvent(record *Record, kind, phase string, recovery bool) {
	record.Events = append(record.Events, Event{At: capacityProbeTime, Kind: kind, State: record.State, Phase: phase, Recovery: recovery})
}

func ensureCapacityProbeFits(record Record, transition string) error {
	if record.Revision == ^uint64(0) {
		return errors.New("operation journal revision is saturated")
	}
	record.Revision = capacityProbeRevision(record.Revision)
	serialized, err := encodeJournalRecord(record)
	if err != nil {
		return err
	}
	if len(serialized) > MaxJournalBytes {
		return fmt.Errorf("operation journal record exceeds the size limit for %s: %d bytes (maximum %d)", transition, len(serialized), MaxJournalBytes)
	}
	return nil
}

func compactAbandonment(record Record, kind string) Record {
	abandoned := copyRecord(record)
	abandoned.State = RecoveryRequired
	abandoned.RecoveryRequired = true
	abandoned.Result = maxJSONEscapedReason()
	abandoned.UpdatedAt = capacityProbeTime
	abandoned.LeaseUntil = ""
	abandoned.RecoveryActions = maxRecoveryActionList()
	abandoned.Events = append(abandoned.Events, Event{At: capacityProbeTime, Kind: kind, State: abandoned.State, Recovery: true})
	return abandoned
}

func futureRecoveryFailure(record Record) Record {
	failed := copyRecord(record)
	failed.State = RecoveryRequired
	failed.RecoveryRequired = true
	failed.Result = maxJSONEscapedReason()
	failed.UpdatedAt = capacityProbeTime
	failed.LeaseUntil = ""
	failed.RecoveryIntent = &RecoveryIntent{PlanDigest: maxConfirmationDigest(), StartedAt: capacityProbeTime, Actions: maxRecoveryActionList()}
	failed.Events = append(failed.Events,
		Event{At: capacityProbeTime, Kind: "recovery-start", State: failed.State, Recovery: true},
		Event{At: capacityProbeTime, Kind: "recovery-failed", State: failed.State, Recovery: true},
	)
	return failed
}

func ensureAbandonmentRecoveryCapacity(record Record, kind, transition string) error {
	abandoned := compactAbandonment(record, kind)
	if err := ensureCapacityProbeFits(abandoned, transition); err != nil {
		return err
	}
	return ensureCapacityProbeFits(futureRecoveryFailure(abandoned), transition+" recovery")
}

func (c *Coordinator) ensureReserveCapacity(record Record) error {
	if err := ensureCapacityProbeFits(record, "operation reservation"); err != nil {
		return err
	}
	return ensureAbandonmentRecoveryCapacity(record, "closed-without-outcome", "reservation abandonment")
}

func (c *Coordinator) ensureCompletedPhaseCapacity(record Record, name string) error {
	if err := reserveEventCapacity(record, completedPhaseEventBudget, "completed phase and recovery"); err != nil {
		return err
	}
	phase := copyRecord(record)
	phase.Phases = append(phase.Phases, Phase{Name: name, StartedAt: capacityProbeTime, EndedAt: capacityProbeTime, Result: maxJSONEscapedReason()})
	phase.UpdatedAt = capacityProbeTime
	phase.LeaseUntil = capacityProbeTime
	c.appendCapacityEvent(&phase, "phase", name, false)
	if err := ensureCapacityProbeFits(phase, "completed phase"); err != nil {
		return err
	}
	return ensureAbandonmentRecoveryCapacity(phase, "closed-without-outcome", "completed phase abandonment")
}

func (c *Coordinator) ensureExecutePhaseCapacity(record Record, request PhaseRequest) error {
	if err := reserveEventCapacity(record, executePhaseEventBudget, "phase start, outcome and recovery"); err != nil {
		return err
	}
	start := copyRecord(record)
	start.Phases = append(start.Phases, Phase{Name: request.Name, StartedAt: capacityProbeTime})
	start.UpdatedAt = capacityProbeTime
	// The callback may journal its current manifest digest; every probe derived
	// from start carries it, so that write can never be the one that overflows.
	start.CurrentManifestSHA256 = maxConfirmationDigest()
	if request.Kind == "deploy" && request.Name == "stack-apply" {
		start.RegistryReplacement = &RegistryReplacement{Image: strings.Repeat("x", 256), VolumeSHA256: maxConfirmationDigest()}
	}
	c.appendCapacityEvent(&start, "phase-start", request.Name, false)
	if err := ensureCapacityProbeFits(start, "phase start"); err != nil {
		return err
	}

	success := copyRecord(start)
	success.Phases[len(success.Phases)-1].EndedAt = capacityProbeTime
	success.Phases[len(success.Phases)-1].Result = "phase completed with a warning"
	success.Phases[len(success.Phases)-1].Warning = maxJSONEscapedReason()
	success.UpdatedAt = capacityProbeTime
	success.LeaseUntil = capacityProbeTime
	c.appendCapacityEvent(&success, "phase-complete", request.Name, false)
	if err := ensureCapacityProbeFits(success, "phase outcome"); err != nil {
		return err
	}
	if err := ensureAbandonmentRecoveryCapacity(success, "closed-without-outcome", "phase abandonment"); err != nil {
		return err
	}
	if err := ensureAbandonmentRecoveryCapacity(start, "watchdog", "phase watchdog"); err != nil {
		return err
	}

	failed := copyRecord(start)
	failed.Phases[len(failed.Phases)-1].EndedAt = capacityProbeTime
	failed.Phases[len(failed.Phases)-1].Error = maxJSONEscapedReason()
	failed.State = RecoveryRequired
	failed.RecoveryRequired = true
	failed.Result = maxJSONEscapedReason()
	failed.UpdatedAt = capacityProbeTime
	failed.LeaseUntil = ""
	c.appendCapacityEvent(&failed, "phase-failed", request.Name, true)
	if err := ensureCapacityProbeFits(failed, "phase failure"); err != nil {
		return err
	}
	return ensureCapacityProbeFits(futureRecoveryFailure(failed), "phase failure recovery")
}

func (c *Coordinator) ensureRecoveryAttemptCapacity(record Record, plan RecoveryPlan, observed RecoveryObservation) error {
	if err := reserveEventCapacity(record, recoveryAttemptEventBudget, "recovery start and outcome"); err != nil {
		return err
	}
	start := copyRecord(record)
	start.RecoveryCurrentManifestSHA256 = maxConfirmationDigest()
	start.State = RecoveryRequired
	start.RecoveryRequired = true
	start.RecoveryIntent = &RecoveryIntent{PlanDigest: plan.PlanDigest, StartedAt: capacityProbeTime, Actions: append([]string(nil), plan.Actions...)}
	start.UpdatedAt = capacityProbeTime
	start.LeaseUntil = ""
	c.appendCapacityEvent(&start, "recovery-start", "", true)
	if err := ensureCapacityProbeFits(start, "recovery start"); err != nil {
		return err
	}

	failed := copyRecord(start)
	failed.Result = maxJSONEscapedReason()
	failed.UpdatedAt = capacityProbeTime
	c.appendCapacityEvent(&failed, "recovery-failed", "", true)
	if err := ensureCapacityProbeFits(failed, "recovery failure"); err != nil {
		return err
	}

	recovered := copyRecord(start)
	recovered.State = "recovered"
	recovered.RecoveryRequired = false
	recovered.Result = "explicit recovery reconciled observed host state"
	recovered.UpdatedAt = capacityProbeTime
	recovered.LeaseUntil = ""
	recovered.RecoveryActions = append([]string(nil), plan.Actions...)
	recovered.RecoveryPlanDigest = plan.PlanDigest
	recovered.RecoveryObservation = copyObservation(observed)
	recovered.RecoveryIntent = nil
	c.appendCapacityEvent(&recovered, "recovered", "", false)
	return ensureCapacityProbeFits(recovered, "recovered outcome")
}

func validateObservationCounts(observed RecoveryObservation) error {
	if observed.ExecutorCount < 0 || observed.OriginalReplicas < 0 {
		return errors.New("recovery observation contains a negative count")
	}
	return nil
}

func hostBootID() (string, error) {
	body, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func validateLabel(value string) error {
	if value == "" || len(value) > 64 || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("invalid operation phase")
	}
	return nil
}

func cleanReason(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if len(value) > MaxReasonBytes {
		return value[:MaxReasonBytes]
	}
	return value
}

func ageOf(value string, now time.Time) string {
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || at.After(now) {
		return "unknown"
	}
	return now.Sub(at).Round(time.Second).String()
}

func missingProofMessage(observed RecoveryObservation) string {
	if len(observed.MissingProof) == 0 {
		return "the executor or resource fence proof is insufficient"
	}
	return "missing recovery proof: " + strings.Join(observed.MissingProof, ", ")
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func unique(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}
