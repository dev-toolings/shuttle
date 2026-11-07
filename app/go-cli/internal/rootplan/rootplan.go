package rootplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	Schema  = "shuttle.root-operation/v2"
	MaxSize = 256 << 10
	// MaxHelperPayload bounds a signed helper replacement. Release binaries are
	// currently about 12 MiB; 32 MiB leaves headroom without turning the root
	// operation channel into an unbounded upload surface.
	MaxHelperPayload = 32 << 20

	// MinPromotionSLOSeconds and MaxPromotionSLOSeconds mirror the deploy budget
	// bounds enforced on the configuration side. They are restated here rather
	// than imported because this package is the wire contract the privileged
	// helper validates against, and it must stay independent of whatever the
	// unprivileged caller believes its configuration says.
	MinPromotionSLOSeconds = 10
	MaxPromotionSLOSeconds = 600

	// MinRegistryCacheBytes and MaxRegistryCacheBytes mirror the retention
	// bounds enforced on the configuration side, for the same reason as the
	// promotion budget: the helper deletes registry content on the strength of
	// this figure, so it range-checks it itself rather than trusting whatever
	// the unprivileged caller claims its configuration says. A budget below the
	// floor would make the helper evict the build cache on every deploy.
	MinRegistryCacheBytes = 3 << 30
	MaxRegistryCacheBytes = 512 << 30
)

var (
	sshFingerprint = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	contentDigest  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	appName        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	serviceName    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	operationName  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	operationID    = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)
	registryImage  = regexp.MustCompile(`^registry:[0-9][A-Za-z0-9._-]*@sha256:[0-9a-f]{64}$`)
	// unixAccount is deliberately narrower than what useradd tolerates. The
	// value ends up inside an sshd AllowUsers directive, where a space or a
	// pattern character does not fail : it silently widens who may log in.
	unixAccount = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// secretKey restates the environment-variable spelling the CLI accepts for
	// a declared secret. The helper looks this name up in a file it reads as
	// root, so it re-checks the charset itself.
	secretKey = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
)

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

type StackOperation struct {
	App           string `json:"app"`
	PayloadSHA256 string `json:"payload_sha256"`
	Remove        bool   `json:"remove,omitempty"`
	// Database destruction and preview are signed: an unsigned client flag
	// must never authorize a privileged drop or bypass mutation coordination.
	DropDatabases bool `json:"drop_databases,omitempty"`
	DryRun        bool `json:"dry_run,omitempty"`
	// PromotionSLOSeconds carries the operator's promotion budget to the root
	// helper, which sizes its own waits (stack convergence, shared-edge reload)
	// from it. It travels inside the signed plan because the helper trusts
	// nothing else on its command line, and it is range-checked here so that a
	// signed plan can never make a privileged operation hold the
	// root-operation lock longer than a bounded, recoverable time.
	PromotionSLOSeconds int `json:"promotion_slo_seconds,omitempty"`
	// RegistryCacheBudgetBytes carries retention.registry_cache to the root
	// helper, which is the only side that can measure the registry volume: the
	// registry lives on the VPS and the unprivileged client cannot read it. The
	// helper reclaims the build cache once the volume exceeds this figure, so
	// the value travels signed and range-checked, exactly like the promotion
	// budget above.
	RegistryCacheBudgetBytes int64  `json:"registry_cache_budget_bytes,omitempty"`
	RegistryImage            string `json:"registry_image,omitempty"`
}

type AuditOperation struct {
	Mode       string `json:"mode"`
	App        string `json:"app,omitempty"`
	Service    string `json:"service,omitempty"`
	Lines      int    `json:"lines,omitempty"`
	Domain     string `json:"domain,omitempty"`
	HealthPath string `json:"health_path,omitempty"`
	SSHPort    int    `json:"ssh_port,omitempty"`
	Runtime    string `json:"runtime,omitempty"`
	Redis      bool   `json:"redis,omitempty"`
	// AllowedPublicTCPPorts is the public listening policy the audit is meant
	// to hold the host to. It travels signed because the helper has no access
	// to config.json: without it the audit assumed 80 and 443 and nothing
	// else, so a host that legitimately publishes another port failed its own
	// audit while the firewall Shuttle generated was opening that very port.
	// An audit that contradicts the policy it verifies teaches the operator to
	// ignore it. Empty means the historical [80, 443].
	AllowedPublicTCPPorts []int `json:"allowed_public_tcp_ports,omitempty"`
	// AllowedSSHUsers is the exact signed AllowUsers policy expected by a
	// readiness audit. Empty preserves the historical deploy-only policy.
	AllowedSSHUsers []string `json:"allowed_ssh_users,omitempty"`
}

// RunOperation names a maintenance command to execute inside a deployed
// service. It carries a *name*, never a command line: the command itself is
// read by the helper from the deployed stack's own labels, which is the payload
// that was signed at deploy time. An unprivileged caller can therefore choose
// among the operations an operator already approved, and cannot invent one.
type RunOperation struct {
	App           string `json:"app"`
	Operation     string `json:"operation"`
	RequireBackup bool   `json:"require_backup,omitempty"`
	SkipBackup    bool   `json:"skip_backup,omitempty"`
}

type RunOptions struct {
	RequireBackup bool
	SkipBackup    bool
}

// SecretsOperation asks the helper to publish application secrets as Docker
// Secrets.
//
// It carries a digest, never a value: the material travels in the payload, the
// same way a stack does, so the signature covers exactly the bytes the helper
// will write and nothing about them appears in the plan : which is the part
// that gets logged, audited and printed.
type SecretsOperation struct {
	App           string `json:"app"`
	PayloadSHA256 string `json:"payload_sha256"`
}

// MaxHostSecretKeys bounds how many keys one host-secrets operation may name.
// It mirrors the application-secret ceiling enforced on the configuration side,
// restated here because this package is the wire contract the privileged helper
// validates against and must not depend on what the caller believes.
const MaxHostSecretKeys = 32

// MaxHostSecretsEnvFile bounds the path the helper is asked to open.
const MaxHostSecretsEnvFile = 512

// HostSecretsOperation asks the helper to read the declared secrets from a file
// that already exists on the VPS and publish them as Docker Secrets.
//
// It carries no value and no digest of one: the material never leaves the host,
// so there is nothing for the client to hash. What travels is the coordinates :
// which file, which keys : and those are exactly what the signature must cover,
// because they are what decides which bytes become a credential.
//
// The helper answers with the version of each key it found, never with a value.
// The client needs those versions before it can name the Docker Secret objects
// its stack will mount, and a hash of a value is not a value.
type HostSecretsOperation struct {
	App     string   `json:"app"`
	EnvFile string   `json:"env_file"`
	Keys    []string `json:"keys"`
}

// HashvaultOperation authorizes a metadata-only request. Enrollment paths
// and machine credentials are supplied by the manager, never by this plan.
type HashvaultOperation struct {
	App           string `json:"app"`
	Target        string `json:"target"`
	PayloadSHA256 string `json:"payload_sha256"`
}

// HelperOperation authorises replacing the privileged helper with exactly one
// signed Linux executable. The bytes travel in the envelope payload; only their
// digest, size and rollback consent are part of the signed plan.
type HelperOperation struct {
	PayloadSHA256 string `json:"payload_sha256"`
	Size          int64  `json:"size"`
	// An unsigned CLI option must never bypass the installed helper's version
	// guard and restore older destroy rules (DEV-DEPL-102).
	AllowDowngrade bool `json:"allow_downgrade,omitempty"`
}

// OperationsOperation is the typed, read-only status request handled by the
// root helper on the VPS. It carries no path or command.
type OperationsOperation struct {
	Format string `json:"format,omitempty"`
}

// RecoveryOperation identifies one durable journal record. The confirmation
// digest is present only for recovery-apply and is the complete observed plan
// fingerprint printed by recovery-plan.
type RecoveryOperation struct {
	OperationID string `json:"operation_id"`
	PlanDigest  string `json:"plan_digest,omitempty"`
}

type Plan struct {
	Schema                  string                `json:"schema"`
	Digest                  string                `json:"digest,omitempty"`
	Action                  string                `json:"action"`
	GeneratedAt             string                `json:"generated_at"`
	ExpiresAt               string                `json:"expires_at"`
	OperatorUser            string                `json:"operator_user"`
	OperatorKeyFingerprint  string                `json:"operator_key_fingerprint"`
	RequiredHostFingerprint string                `json:"required_host_fingerprint"`
	Stack                   *StackOperation       `json:"stack,omitempty"`
	Secrets                 *SecretsOperation     `json:"secrets,omitempty"`
	HostSecrets             *HostSecretsOperation `json:"host_secrets,omitempty"`
	Hashvault               *HashvaultOperation   `json:"hashvault,omitempty"`
	Audit                   *AuditOperation       `json:"audit,omitempty"`
	Run                     *RunOperation         `json:"run,omitempty"`
	Baseline                *BaselineOperation    `json:"baseline,omitempty"`
	Helper                  *HelperOperation      `json:"helper,omitempty"`
	Operations              *OperationsOperation  `json:"operations,omitempty"`
	Recovery                *RecoveryOperation    `json:"recovery,omitempty"`
	// OperationID binds a signed root action to the durable host journal. It is
	// optional on old read-only plans so status and audit remain wire-compatible;
	// every state-changing operation generated by the current CLI sets it.
	Control         *OperationControl         `json:"control,omitempty"`
	HelperMigration *HelperMigrationOperation `json:"helper_migration,omitempty"`
	Writers         *OperationWriters         `json:"writers,omitempty"`
	Monitoring      *MonitoringOperation      `json:"monitoring,omitempty"`
	BackupStatus    *BackupStatusOperation    `json:"backup_status,omitempty"`
	OperationID     string                    `json:"operation_id,omitempty"`
	OperationKind   string                    `json:"operation_kind,omitempty"`
	OperationApp    string                    `json:"operation_app,omitempty"`
	Signature       *Signature                `json:"signature,omitempty"`
}

// BaselineOperation carries the parameters of the SSH hardening transaction.
//
// It exists for one value. The baseline used to write `AllowUsers deploy` as a
// literal, which is right for a VPS Shuttle converged from scratch and wrong
// for one it adopts: an adopted host is reached through an operator account
// that already exists, and locking that account out is how the operator loses
// the session they are converging from : along with whatever else on the host
// depended on it. The account has to be nameable, so it travels in the signed
// plan, which is the only channel the helper trusts.
type BaselineOperation struct {
	// AllowedSSHUsers is the exact, ordered AllowUsers list. It must contain
	// the deploy user; extra accounts are the operator's explicit decision,
	// signed like everything else.
	AllowedSSHUsers []string `json:"allowed_ssh_users,omitempty"`
}

func NewBaseline(operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return NewBaselineWithSSHUsers(operatorKeyFingerprint, hostFingerprint, nil, now, validity)
}

// NewBaselineWithSSHUsers signs a baseline that keeps additional accounts able
// to log in. Passing none is identical to NewBaseline, so a converged-from-
// scratch host produces the same plan it always did.
func NewBaselineWithSSHUsers(operatorKeyFingerprint, hostFingerprint string, extraUsers []string, now time.Time, validity time.Duration) (Plan, error) {
	if len(extraUsers) == 0 {
		return newPlan("baseline", operatorKeyFingerprint, hostFingerprint, nil, now, validity)
	}
	users := append([]string{"deploy"}, extraUsers...)
	slices.Sort(users)
	users = slices.Compact(users)
	// Sealed once, with the payload already in place: the digest has to cover
	// the account list, or the one value this exists to carry would be the one
	// value the signature does not protect.
	plan := Plan{
		Schema: Schema, Action: "baseline",
		GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339),
		OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint,
		Baseline: &BaselineOperation{AllowedSSHUsers: users},
	}
	return seal(plan)
}

func NewBaselineRollback(operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newPlan("baseline-rollback", operatorKeyFingerprint, hostFingerprint, nil, now, validity)
}

func NewBaselineCommit(operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newPlan("baseline-commit", operatorKeyFingerprint, hostFingerprint, nil, now, validity)
}

func NewAudit(operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "audit", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Audit: &AuditOperation{Mode: "baseline"}}
	return seal(plan)
}

// NewCapabilitiesAudit asks the installed helper to identify its protocol and
// feature set. Older helpers reject the new mode, which is itself the reliable
// signal that they cannot safely interpret a configuration requiring it.
func NewCapabilitiesAudit(operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "audit", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Audit: &AuditOperation{Mode: "capabilities"}}
	return seal(plan)
}

// NewHelperUpdate seals an exact helper binary replacement.
func NewHelperUpdate(payloadDigest string, size int64, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "helper-update", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Helper: &HelperOperation{PayloadSHA256: payloadDigest, Size: size}}
	return seal(plan)
}

func NewStackAudit(mode, app, service string, lines int, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "audit", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Audit: &AuditOperation{Mode: mode, App: app, Service: service, Lines: lines}}
	return seal(plan)
}

// NewRun seals a request to execute one declared maintenance operation.
func NewRun(app, operation string, options RunOptions, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "run", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Run: &RunOperation{App: app, Operation: operation, RequireBackup: options.RequireBackup, SkipBackup: options.SkipBackup}}
	return seal(plan)
}

func NewReadinessAudit(app, domain, healthPath, runtime string, sshPort int, redis bool, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return NewReadinessAuditWithPorts(app, domain, healthPath, runtime, sshPort, redis, nil, operatorKeyFingerprint, hostFingerprint, now, validity)
}

// NewReadinessAuditWithPorts signs an audit that holds the host to the public
// listening policy the operator declared. Passing none keeps the historical
// [80, 443], so a configuration that declares nothing signs what it always did.
func NewReadinessAuditWithPorts(app, domain, healthPath, runtime string, sshPort int, redis bool, publicPorts []int, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return NewReadinessAuditWithAccess(app, domain, healthPath, runtime, sshPort, redis, publicPorts, nil, operatorKeyFingerprint, hostFingerprint, now, validity)
}

func NewReadinessAuditWithAccess(app, domain, healthPath, runtime string, sshPort int, redis bool, publicPorts []int, allowedSSHUsers []string, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	ports := append([]int(nil), publicPorts...)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	if slices.Equal(ports, []int{80, 443}) {
		ports = nil
	}
	users := append([]string(nil), allowedSSHUsers...)
	if slices.Equal(users, []string{"deploy"}) {
		users = nil
	}
	plan := Plan{Schema: Schema, Action: "audit", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Audit: &AuditOperation{Mode: "readiness", App: app, Domain: domain, HealthPath: healthPath, SSHPort: sshPort, Runtime: runtime, Redis: redis, AllowedPublicTCPPorts: ports, AllowedSSHUsers: users}}
	return seal(plan)
}

func NewStackAction(action, app, payloadDigest string, promotionSLOSeconds int, registryCacheBudgetBytes int64, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration, registryImage ...string) (Plan, error) {
	if action != "stack-apply" && action != "stack-rollback" {
		return Plan{}, errors.New("unsupported stack operation")
	}
	image := ""
	if len(registryImage) > 0 {
		image = registryImage[0]
	}
	return newPlan(action, operatorKeyFingerprint, hostFingerprint, &StackOperation{App: app, PayloadSHA256: payloadDigest, PromotionSLOSeconds: promotionSLOSeconds, RegistryCacheBudgetBytes: registryCacheBudgetBytes, RegistryImage: image}, now, validity)
}

// WithOperationID binds a signed plan to the host operation journal. Keeping
// this as a separate step preserves deterministic legacy constructors while
// making the coordination binding explicit at each mutating call site.
func WithOperationID(plan Plan, id, kind, app string) (Plan, error) {
	if !operationID.MatchString(id) || !operationName.MatchString(kind) {
		return Plan{}, errors.New("invalid signed operation identity")
	}
	if app != "" && !appName.MatchString(app) {
		return Plan{}, errors.New("invalid signed operation application")
	}
	plan.OperationID, plan.OperationKind, plan.OperationApp = id, kind, app
	return seal(plan)
}

// NewOperationReserve is the first signed phase of a coordinated operation.
// It has no payload and only creates the durable reservation on the host. The
// actual mutation is authorized by a later signed plan carrying the same ID.
func NewOperationReserve(id, kind, app, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "operation-reserve", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, OperationID: id, OperationKind: kind, OperationApp: app}
	return seal(plan)
}

// NewOperationsStatus asks the installed helper for the durable operation
// records on the VPS. The output is one JSON document and has no helper trailer.
func NewOperationsStatus(operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "operations-status", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Operations: &OperationsOperation{Format: "json"}}
	return seal(plan)
}

func NewRecoveryPlan(id, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "recovery-plan", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Recovery: &RecoveryOperation{OperationID: id}}
	return seal(plan)
}

func NewRecoveryApply(id, planDigest, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "recovery-apply", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Recovery: &RecoveryOperation{OperationID: id, PlanDigest: planDigest}}
	return seal(plan)
}

// NewStackReclaim seals a request to reclaim, on the host, the images of the
// releases an application has moved past : before a deploy, so the free-disk
// guard measures a host that has already been cleaned rather than one that
// is blocked by its own leftovers.
//
// It carries the application name and nothing else. No payload: what to keep
// is derived on the host from the retained stacks it already holds, each of
// which was signed when it was applied. No budget: the sweep deletes only what
// no retained release references, and there is no cap for it to enforce. Any
// other field on a reclaim is refused by validate, so this action can never
// grow into a second way to promote a stack.
//
// The pre-deploy helper also sweeps the host image store: it removes stopped
// task containers only when a newer task of the same service and replicated
// slot is running on this node. For a global service, that newer task must run
// on the same node. Missing slot or creation-time evidence keeps the stopped
// task. The helper then removes old dangling images and superseded tags from
// repositories used by current Swarm services. It keeps every image referenced
// by a retained release or service spec, every image held by a container,
// loopback-registry images, and images created in the last 24 hours. The pass
// is host-wide because the deploy disk guard measures the whole root filesystem,
// but its bounded scope leaves repositories no service currently runs untouched.
//
// The helper also pins the Swarm task history to the fixed value it ships,
// cluster-wide, because without that the existing release sweep reclaims
// nothing. Nothing in the plan chooses that value; a signed reclaim cannot set
// it.
func NewStackReclaim(app, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newPlan("stack-reclaim", operatorKeyFingerprint, hostFingerprint, &StackOperation{App: app}, now, validity)
}

// NewSecretsAction seals a request to publish application secrets. The names
// are derived by the client and re-derived by the helper from the application
// in this plan, so no signed request can create a secret another application
// would read.
func NewSecretsAction(app, payloadDigest, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "secrets-apply", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Secrets: &SecretsOperation{App: app, PayloadSHA256: payloadDigest}}
	return seal(plan)
}

func NewHashvaultAction(app, target, payloadDigest, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "secrets-hashvault", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Hashvault: &HashvaultOperation{App: app, Target: target, PayloadSHA256: payloadDigest}}
	return seal(plan)
}

func NewHashvaultSyncAction(app, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "hashvault-sync", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Hashvault: &HashvaultOperation{App: app}}
	return seal(plan)
}

// NewHostSecretsAction seals a request to publish, as Docker Secrets, the
// declared keys read from a file the VPS already holds.
//
// The keys are sorted so the same configuration always produces the same signed
// plan, and therefore the same digest in the helper's journal: an operator
// comparing two deploys should not have to decide whether a reordered list is a
// different request.
func NewHostSecretsAction(app, envFile string, keys []string, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	ordered := append([]string(nil), keys...)
	slices.Sort(ordered)
	ordered = slices.Compact(ordered)
	plan := Plan{Schema: Schema, Action: "secrets-host", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, HostSecrets: &HostSecretsOperation{App: app, EnvFile: envFile, Keys: ordered}}
	return seal(plan)
}

func NewStackRemove(app, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "stack-apply", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Stack: &StackOperation{App: app, Remove: true}}
	return seal(plan)
}

func newPlan(action, operatorKeyFingerprint, hostFingerprint string, stack *StackOperation, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: action, GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Stack: stack}
	return seal(plan)
}

func Sign(plan Plan, privateKey ed25519.PrivateKey) (Plan, error) {
	sealed, err := seal(plan)
	if err != nil {
		return Plan{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Plan{}, errors.New("root-operation signing key must be Ed25519")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	sealed.Signature = &Signature{Algorithm: "ed25519", KeyID: KeyID(publicKey), Value: hex.EncodeToString(ed25519.Sign(privateKey, []byte(sealed.Digest)))}
	return sealed, nil
}

func Verify(plan Plan, publicKey ed25519.PublicKey, now time.Time) error {
	if err := validate(plan, true); err != nil {
		return err
	}
	unsigned := plan
	unsigned.Digest, unsigned.Signature = "", nil
	sealed, err := seal(unsigned)
	if err != nil || sealed.Digest != plan.Digest {
		return errors.New("root-operation content digest mismatch")
	}
	if plan.Signature.KeyID != KeyID(publicKey) {
		return errors.New("root-operation signer is not trusted")
	}
	signature, err := hex.DecodeString(plan.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(plan.Digest), signature) {
		return errors.New("root-operation signature verification failed")
	}
	generated, _ := time.Parse(time.RFC3339, plan.GeneratedAt)
	expires, _ := time.Parse(time.RFC3339, plan.ExpiresAt)
	if now.Before(generated.Add(-time.Minute)) || !now.Before(expires) {
		return errors.New("root-operation is not currently valid")
	}
	return nil
}

func Decode(reader io.Reader) (Plan, error) {
	body, err := io.ReadAll(io.LimitReader(reader, MaxSize+1))
	if err != nil || len(body) > MaxSize {
		return Plan{}, errors.New("root-operation exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, errors.New("decode root-operation plan")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Plan{}, errors.New("root-operation must contain exactly one JSON document")
	}
	return plan, nil
}

func Marshal(plan Plan) ([]byte, error) {
	if err := validate(plan, true); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(plan, "", "  ")
	return append(body, '\n'), err
}

func PayloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func seal(plan Plan) (Plan, error) {
	plan.Schema, plan.Digest, plan.Signature = Schema, "", nil
	if err := validate(plan, false); err != nil {
		return Plan{}, err
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, err
	}
	plan.Digest = PayloadDigest(body)
	return plan, nil
}

func validate(plan Plan, signed bool) error {
	if plan.Hashvault != nil && plan.Action != "secrets-hashvault" && plan.Action != "hashvault-sync" {
		return errors.New("root-operation action does not accept a hashvault request")
	}
	if plan.Schema != Schema || plan.OperatorUser != "deploy" {
		return errors.New("unsupported root-operation contract")
	}
	if plan.OperationID != "" || plan.OperationKind != "" || plan.OperationApp != "" {
		if !operationID.MatchString(plan.OperationID) || !operationName.MatchString(plan.OperationKind) || (plan.OperationApp != "" && !appName.MatchString(plan.OperationApp)) {
			return errors.New("invalid signed operation identity")
		}
	}
	// One action accepts secret material. Restating it here rather than in every
	// branch means a new action cannot inherit the right to publish credentials
	// by forgetting to refuse it.
	if plan.Secrets != nil && plan.Action != "secrets-apply" {
		return errors.New("root-operation action does not accept a secrets payload")
	}
	if plan.Helper != nil && plan.Action != "helper-update" {
		return errors.New("root-operation action does not accept a helper payload")
	}
	// Same reasoning as the secrets guard above, for the action that names a
	// file the helper will read as root: no other action may inherit the right
	// to point the helper at a path by forgetting to refuse the field.
	if plan.HostSecrets != nil && plan.Action != "secrets-host" {
		return errors.New("root-operation action does not accept host secret coordinates")
	}
	if plan.Operations != nil && plan.Action != "operations-status" {
		return errors.New("root-operation action does not accept an operations status request")
	}
	if plan.Recovery != nil && plan.Action != "recovery-plan" && plan.Action != "recovery-apply" {
		return errors.New("root-operation action does not accept a recovery request")
	}
	if plan.HelperMigration != nil && plan.Action != "helper-migration-finalize" && plan.Action != "helper-migration-reconcile" {
		return errors.New("root-operation action does not accept helper migration")
	}
	if plan.Writers != nil && plan.Action != "operation-writer-register" && plan.Action != "operation-writers-close" && plan.Action != "operation-writers-commit" {
		return errors.New("root-operation action does not accept a writer inventory")
	}
	if plan.Control != nil && plan.Action != "operation-renew" && plan.Action != "operation-finish" && plan.Action != "operation-abort" && plan.Action != "operation-refuse" {
		return errors.New("root-operation action does not accept operation control")
	}
	if plan.Monitoring != nil && plan.Action != "monitor-install" && plan.Action != "monitor-remove" && plan.Action != "monitor-run" && plan.Action != "monitor-status" && plan.Action != "monitor-maintenance" {
		return errors.New("root-operation action does not accept monitoring coordinates")
	}
	if plan.BackupStatus != nil && plan.Action != "backup-status" {
		return errors.New("root-operation action does not accept backup status")
	}
	switch plan.Action {
	case "operation-writer-register", "operation-writers-close", "operation-writers-commit":
		if err := validateWriterOperation(plan); err != nil {
			return err
		}

	case "helper-migration-finalize", "helper-migration-reconcile":
		if plan.HelperMigration == nil || !contentDigest.MatchString(plan.HelperMigration.CandidateSHA256) || plan.OperationID != "" || plan.OperationKind != "" || plan.OperationApp != "" || plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || plan.Recovery != nil || plan.Operations != nil || plan.Control != nil {
			return errors.New("helper migration requires only its candidate identity")
		}
		if plan.HelperMigration.IntentID != "" && !operationID.MatchString(plan.HelperMigration.IntentID) {
			return errors.New("invalid helper migration intent identity")
		}

	case "operation-renew", "operation-finish", "operation-abort", "operation-refuse":
		if plan.Control == nil || plan.OperationID == "" || plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || plan.Recovery != nil || plan.Operations != nil {
			return errors.New("operation control requires only its complete signed identity and outcome")
		}
		if plan.Control.Phase != "" && (plan.Action != "operation-renew" || (plan.Control.Phase != "client-promotion" && plan.Control.Phase != "client-cleanup")) {
			return errors.New("invalid client outcome phase")
		}
		if len(plan.Control.Result) > 512 || strings.ContainsAny(plan.Control.Result, "\r\n\x00") {
			return errors.New("operation outcome must be bounded single-line text")
		}
		if plan.Action != "operation-renew" && plan.Control.Result == "" {
			return errors.New("operation completion requires an explicit outcome")
		}
	case "operation-reserve":
		if plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || !operationID.MatchString(plan.OperationID) || !operationName.MatchString(plan.OperationKind) {
			return errors.New("operation reservation is incomplete")
		}
		if plan.OperationApp != "" && !appName.MatchString(plan.OperationApp) {
			return errors.New("invalid operation reservation application")
		}
	case "operations-status":
		if plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || plan.Recovery != nil || plan.Operations == nil || plan.Operations.Format != "json" {
			return errors.New("operations status request is incomplete")
		}
	case "recovery-plan", "recovery-apply":
		if plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || plan.Operations != nil || plan.Recovery == nil || !operationID.MatchString(plan.Recovery.OperationID) {
			return errors.New("recovery request is incomplete")
		}
		if plan.Action == "recovery-plan" && plan.Recovery.PlanDigest != "" {
			return errors.New("recovery plan observation does not accept confirmation")
		}
		if plan.Action == "recovery-apply" && !contentDigest.MatchString(plan.Recovery.PlanDigest) {
			return errors.New("recovery apply requires a SHA256 plan confirmation")
		}
	case "baseline", "baseline-rollback", "baseline-commit":
		if plan.Stack != nil {
			return errors.New("root-operation action does not accept a stack payload")
		}
		if plan.Audit != nil || plan.Run != nil || plan.Helper != nil {
			return errors.New("baseline operation does not accept audit parameters")
		}
		if plan.Baseline != nil {
			if plan.Action != "baseline" {
				return errors.New("only the baseline action accepts baseline parameters")
			}
			if err := validateAllowedSSHUsers(plan.Baseline.AllowedSSHUsers); err != nil {
				return err
			}
		}
	case "audit":
		if plan.Stack != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || plan.Audit == nil {
			return errors.New("audit operation is incomplete")
		}
		switch plan.Audit.Mode {
		case "baseline", "capabilities":
			if plan.Audit.App != "" || plan.Audit.Service != "" || plan.Audit.Lines != 0 || plan.Audit.Domain != "" || plan.Audit.HealthPath != "" || plan.Audit.SSHPort != 0 || plan.Audit.Runtime != "" || plan.Audit.Redis || len(plan.Audit.AllowedPublicTCPPorts) != 0 || len(plan.Audit.AllowedSSHUsers) != 0 {
				return errors.New("baseline audit does not accept stack parameters")
			}
		case "status":
			if !appName.MatchString(plan.Audit.App) || plan.Audit.Service != "" || plan.Audit.Lines != 0 || plan.Audit.Domain != "" || plan.Audit.HealthPath != "" || plan.Audit.SSHPort != 0 || plan.Audit.Runtime != "" || plan.Audit.Redis || len(plan.Audit.AllowedPublicTCPPorts) != 0 || len(plan.Audit.AllowedSSHUsers) != 0 {
				return errors.New("invalid stack status audit")
			}
		case "infra-images":
			if !appName.MatchString(plan.Audit.App) || plan.Audit.Service != "" || plan.Audit.Lines != 0 || plan.Audit.Domain != "" || plan.Audit.HealthPath != "" || plan.Audit.SSHPort != 0 || plan.Audit.Runtime != "" || plan.Audit.Redis || len(plan.Audit.AllowedPublicTCPPorts) != 0 || len(plan.Audit.AllowedSSHUsers) != 0 {
				return errors.New("invalid retained infrastructure image audit")
			}
		case "logs":
			if !appName.MatchString(plan.Audit.App) || !serviceName.MatchString(plan.Audit.Service) || plan.Audit.Lines < 1 || plan.Audit.Lines > 1000 || plan.Audit.Domain != "" || plan.Audit.HealthPath != "" || plan.Audit.SSHPort != 0 || plan.Audit.Runtime != "" || plan.Audit.Redis || len(plan.Audit.AllowedPublicTCPPorts) != 0 || len(plan.Audit.AllowedSSHUsers) != 0 {
				return errors.New("invalid stack logs audit")
			}
		case "debug-ps", "debug-services", "debug-network":
			if !appName.MatchString(plan.Audit.App) || plan.Audit.Service != "" || plan.Audit.Lines != 0 || plan.Audit.Domain != "" || plan.Audit.HealthPath != "" || plan.Audit.SSHPort != 0 || plan.Audit.Runtime != "" || plan.Audit.Redis || len(plan.Audit.AllowedPublicTCPPorts) != 0 || len(plan.Audit.AllowedSSHUsers) != 0 {
				return errors.New("invalid stack debug audit")
			}
		case "debug-tasks", "debug-inspect":
			if !appName.MatchString(plan.Audit.App) || !serviceName.MatchString(plan.Audit.Service) || plan.Audit.Lines != 0 || plan.Audit.Domain != "" || plan.Audit.HealthPath != "" || plan.Audit.SSHPort != 0 || plan.Audit.Runtime != "" || plan.Audit.Redis || len(plan.Audit.AllowedPublicTCPPorts) != 0 || len(plan.Audit.AllowedSSHUsers) != 0 {
				return errors.New("invalid service debug audit")
			}
		case "debug-logs":
			if !appName.MatchString(plan.Audit.App) || !serviceName.MatchString(plan.Audit.Service) || plan.Audit.Lines < 1 || plan.Audit.Lines > 1000 || plan.Audit.Domain != "" || plan.Audit.HealthPath != "" || plan.Audit.SSHPort != 0 || plan.Audit.Runtime != "" || plan.Audit.Redis || len(plan.Audit.AllowedPublicTCPPorts) != 0 || len(plan.Audit.AllowedSSHUsers) != 0 {
				return errors.New("invalid debug logs audit")
			}
		case "readiness":
			// Only an internal app omits both public values. Non-empty domains
			// stay behind the same helper trust-boundary validation as before.
			invalidDomainOrPath := (plan.Audit.Domain == "" && plan.Audit.HealthPath != "") || (plan.Audit.Domain != "" && (!validDomain(plan.Audit.Domain) || !strings.HasPrefix(plan.Audit.HealthPath, "/")))
			if !appName.MatchString(plan.Audit.App) || invalidDomainOrPath || len(plan.Audit.HealthPath) > 256 || plan.Audit.SSHPort < 1 || plan.Audit.SSHPort > 65535 || (plan.Audit.Runtime != "" && plan.Audit.Runtime != "node" && plan.Audit.Runtime != "php") || plan.Audit.Service != "" || plan.Audit.Lines != 0 {
				return errors.New("invalid readiness audit")
			}
			if err := validateAuditPublicPorts(plan.Audit.AllowedPublicTCPPorts, plan.Audit.SSHPort); err != nil {
				return err
			}
			if len(plan.Audit.AllowedSSHUsers) > 0 {
				if err := validateAllowedSSHUsers(plan.Audit.AllowedSSHUsers); err != nil {
					return err
				}
			}
		default:
			return errors.New("unsupported audit operation")
		}
	case "run":
		// A run mutates state, so it is not folded into "audit": an audit stays
		// something an operator can authorise without reading further.
		if plan.Stack != nil || plan.Audit != nil || plan.Baseline != nil || plan.Run == nil {
			return errors.New("run operation is incomplete")
		}
		if !appName.MatchString(plan.Run.App) || !operationName.MatchString(plan.Run.Operation) {
			return errors.New("invalid run operation")
		}
		if plan.Run.SkipBackup && !plan.Run.RequireBackup {
			return errors.New("skip_backup requires require_backup")
		}
	case "secrets-apply":
		if plan.Stack != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Secrets == nil {
			return errors.New("secrets operation is incomplete")
		}
		if !appName.MatchString(plan.Secrets.App) || !contentDigest.MatchString(plan.Secrets.PayloadSHA256) {
			return errors.New("invalid secrets operation")
		}
	case "secrets-host":
		if plan.Stack != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Secrets != nil || plan.Helper != nil || plan.HostSecrets == nil {
			return errors.New("host secrets operation is incomplete")
		}
		if err := validateHostSecrets(plan.HostSecrets); err != nil {
			return err
		}
	case "secrets-hashvault":
		if plan.Hashvault == nil || plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Run != nil || plan.Audit != nil || plan.Baseline != nil || plan.Helper != nil || !appName.MatchString(plan.Hashvault.App) || !appName.MatchString(plan.Hashvault.Target) || !contentDigest.MatchString(plan.Hashvault.PayloadSHA256) {
			return errors.New("invalid hashvault operation")
		}
	case "hashvault-sync":
		if plan.Hashvault == nil || !appName.MatchString(plan.Hashvault.App) || plan.Hashvault.Target != "" || plan.Hashvault.PayloadSHA256 != "" || plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Run != nil || plan.Audit != nil || plan.Baseline != nil || plan.Helper != nil {
			return errors.New("invalid hashvault sync operation")
		}
	case "helper-update":
		if plan.Stack != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Secrets != nil || plan.Helper == nil {
			return errors.New("helper update operation is incomplete")
		}
		if !contentDigest.MatchString(plan.Helper.PayloadSHA256) || plan.Helper.Size < 1 || plan.Helper.Size > MaxHelperPayload {
			return errors.New("invalid helper update operation")
		}
	case "stack-apply", "stack-rollback":
		if plan.Run != nil || plan.Audit != nil || plan.Baseline != nil {
			return errors.New("stack operation does not accept unrelated operation parameters")
		}
		if plan.Stack == nil || !appName.MatchString(plan.Stack.App) {
			return errors.New("invalid typed stack operation")
		}
		if plan.Action == "stack-apply" && !plan.Stack.Remove && !contentDigest.MatchString(plan.Stack.PayloadSHA256) {
			return errors.New("invalid typed stack operation")
		}
		if plan.Stack.Remove && (plan.Action != "stack-apply" || plan.Stack.PayloadSHA256 != "") {
			return errors.New("invalid typed stack removal")
		}
		if (plan.Stack.DropDatabases || plan.Stack.DryRun) && !plan.Stack.Remove {
			return errors.New("destroy options require stack removal")
		}
		if plan.Stack.DryRun && plan.OperationID != "" {
			return errors.New("destroy dry-run does not accept a mutation reservation")
		}
		if plan.Stack.RegistryImage != "" {
			if plan.Action != "stack-apply" || plan.Stack.Remove {
				return errors.New("only a stack promotion may carry a registry image")
			}
			if !registryImage.MatchString(plan.Stack.RegistryImage) {
				return errors.New("stack registry image must be an official registry image pinned by sha256 digest")
			}
		}
		// Zero means "the helper picks its shipped default"; any stated budget
		// must be inside the same range the configuration accepts, so no signed
		// plan can stretch a privileged wait beyond a recoverable duration.
		if plan.Stack.PromotionSLOSeconds != 0 && (plan.Stack.PromotionSLOSeconds < MinPromotionSLOSeconds || plan.Stack.PromotionSLOSeconds > MaxPromotionSLOSeconds) {
			return errors.New("root-operation promotion budget is out of range")
		}
		// Same rule for the registry budget: zero means "no cap stated, keep
		// everything the tags still reference". Registry maintenance only runs
		// after a promotion, so no other action may carry a budget that would
		// authorise deletions it never performs.
		if plan.Stack.RegistryCacheBudgetBytes != 0 {
			if plan.Stack.RegistryCacheBudgetBytes < MinRegistryCacheBytes || plan.Stack.RegistryCacheBudgetBytes > MaxRegistryCacheBytes {
				return errors.New("root-operation registry cache budget is out of range")
			}
			if plan.Action != "stack-apply" || plan.Stack.Remove {
				return errors.New("only a stack promotion may carry a registry cache budget")
			}
		}
		if plan.Action == "stack-rollback" && plan.Stack.PayloadSHA256 != "" {
			return errors.New("stack rollback does not accept a payload digest")
		}
	case "stack-reclaim":
		// A reclaim names an application and nothing more. Every other field of
		// a stack operation authorises something a reclaim never does : a
		// payload to apply, a removal, a wait, a registry deletion budget : so
		// each one present is refused rather than ignored.
		if plan.Run != nil || plan.Audit != nil || plan.Baseline != nil {
			return errors.New("stack reclaim accepts only an application name")
		}
		if plan.Stack == nil || !appName.MatchString(plan.Stack.App) {
			return errors.New("invalid typed stack operation")
		}
		if plan.Stack.PayloadSHA256 != "" || plan.Stack.Remove || plan.Stack.DropDatabases || plan.Stack.DryRun || plan.Stack.PromotionSLOSeconds != 0 || plan.Stack.RegistryCacheBudgetBytes != 0 || plan.Stack.RegistryImage != "" {
			return errors.New("stack reclaim accepts only an application name")
		}
	case "monitor-install", "monitor-remove", "monitor-run", "monitor-status", "monitor-maintenance":
		if !monitoringFieldsOnly(plan) {
			return errors.New("monitoring operation accepts only monitoring coordinates")
		}
		if err := validateMonitoringOperation(plan.Monitoring, plan.Action); err != nil {
			return err
		}
	case "backup-status":
		if plan.BackupStatus == nil || plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || plan.Monitoring != nil || !appName.MatchString(plan.BackupStatus.App) || !operationName.MatchString(plan.BackupStatus.OperationID) || !contentDigest.MatchString(plan.BackupStatus.PayloadSHA256) {
			return errors.New("invalid backup status operation")
		}
	default:
		return errors.New("unsupported root-operation contract")
	}
	if plan.OperationID != "" {
		if plan.OperationKind == "operation-reserve" {
			return errors.New("operation reservation kind is invalid")
		}
		if plan.Action != "operation-reserve" && !operationBindingMatches(plan.Action, plan.OperationKind) {
			return errors.New("signed operation kind does not match its action")
		}
		if plan.OperationApp != "" {
			var expected string
			switch {
			case plan.Stack != nil:
				expected = plan.Stack.App
			case plan.Secrets != nil:
				expected = plan.Secrets.App
			case plan.HostSecrets != nil:
				expected = plan.HostSecrets.App
			case plan.Hashvault != nil:
				expected = plan.Hashvault.App
			case plan.Run != nil:
				expected = plan.Run.App
			case plan.Audit != nil:
				expected = plan.Audit.App
			}
			if expected != "" && expected != plan.OperationApp {
				return errors.New("signed operation application does not match its action")
			}
		}
	}
	if !sshFingerprint.MatchString(plan.OperatorKeyFingerprint) || !sshFingerprint.MatchString(plan.RequiredHostFingerprint) {
		return errors.New("root-operation requires canonical SSH fingerprints")
	}
	generated, err := time.Parse(time.RFC3339, plan.GeneratedAt)
	if err != nil {
		return errors.New("invalid root-operation generated_at")
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil || !expires.After(generated) || expires.Sub(generated) > 15*time.Minute {
		return errors.New("root-operation validity must be positive and at most 15 minutes")
	}
	if signed {
		if !contentDigest.MatchString(plan.Digest) || plan.Signature == nil || plan.Signature.Algorithm != "ed25519" {
			return errors.New("signed root-operation envelope is incomplete")
		}
	} else if plan.Digest != "" || plan.Signature != nil {
		return errors.New("unsealed root-operation contains signing fields")
	}
	return nil
}

func operationBindingMatches(action, kind string) bool {
	switch action {
	case "operation-writer-register", "operation-writers-close", "operation-writers-commit":
		return operationName.MatchString(kind)

	case "operation-renew", "operation-finish", "operation-abort", "operation-refuse":
		return operationName.MatchString(kind)
	case "stack-apply":
		return kind == "deploy" || kind == "destroy"
	case "stack-rollback":
		return kind == "rollback" || kind == "deploy"
	case "stack-reclaim":
		return kind == "deploy" || kind == "cache-prune"
	case "secrets-apply", "secrets-host", "secrets-hashvault":
		return kind == "deploy"
	case "hashvault-sync":
		return kind == "secrets-sync"
	case "helper-update":
		return kind == "helper-update"
	case "run":
		return kind == "run"
	default:
		return false
	}
}

func validDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(label) {
			return false
		}
	}
	return true
}

func GenerateKeyPair(privatePath, publicPath string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	if err := writeExclusive(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		return err
	}
	if err := writeExclusive(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o444); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	body, err := readRegular(path, 0o077)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("invalid private signing key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	privateKey, ok := key.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("private signing key is not Ed25519")
	}
	return privateKey, nil
}

func ReadTrustedKey(path string) (ed25519.PublicKey, error) {
	body, err := readRegular(path, 0o222)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("invalid public trust key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey, ok := key.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("public trust key is not Ed25519")
	}
	return publicKey, nil
}

func readRegular(path string, forbidden os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&forbidden != 0 || info.Size() > MaxSize {
		return nil, errors.New("key must be a bounded regular file with safe permissions")
	}
	return os.ReadFile(path)
}

func writeExclusive(path string, body []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) {
		return errors.New("key path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

// maxAllowedSSHUsers bounds the AllowUsers list. A baseline naming dozens of
// accounts is not a hardened host, and the bound keeps a malformed plan from
// producing an sshd directive nobody would read to the end.
const maxAllowedSSHUsers = 8

// validateAllowedSSHUsers refuses anything the helper would have to clean
// before writing it. The list is emitted verbatim into AllowUsers, so it must
// already be exactly what belongs there: sorted, deduplicated, every entry a
// plain account name, and the deploy user present : a baseline that could lock
// out the account Shuttle itself uses is not a baseline.
// validateHostSecrets holds the one action that names a path to a shape the
// helper can refuse cheaply, before it opens anything.
//
// Absolute and traversal-free are the two properties that make the path mean
// the same thing to the operator who signed it and to the helper that resolves
// it. A relative path would resolve against whatever directory the helper
// happens to run in, which is not a decision anybody made.
func validateHostSecrets(operation *HostSecretsOperation) error {
	if !appName.MatchString(operation.App) {
		return errors.New("invalid host secrets operation")
	}
	path := operation.EnvFile
	if path == "" || len(path) > MaxHostSecretsEnvFile || !strings.HasPrefix(path, "/") {
		return errors.New("host secrets env_file must be an absolute path")
	}
	if strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("host secrets env_file must not contain control characters")
	}
	for _, element := range strings.Split(path, "/") {
		if element == ".." {
			return errors.New("host secrets env_file must not traverse directories")
		}
	}
	if len(operation.Keys) == 0 || len(operation.Keys) > MaxHostSecretKeys {
		return fmt.Errorf("host secrets operation must name between 1 and %d keys", MaxHostSecretKeys)
	}
	if !slices.IsSorted(operation.Keys) {
		return errors.New("host secrets keys must be sorted, so the same intent cannot produce two different signed plans")
	}
	if len(slices.Compact(append([]string(nil), operation.Keys...))) != len(operation.Keys) {
		return errors.New("host secrets keys must not repeat a key")
	}
	for _, key := range operation.Keys {
		if !secretKey.MatchString(key) {
			return fmt.Errorf("host secrets keys contain invalid key %q", key)
		}
	}
	return nil
}

func validateAllowedSSHUsers(users []string) error {
	if len(users) == 0 || len(users) > maxAllowedSSHUsers {
		return fmt.Errorf("baseline allowed_ssh_users must name between 1 and %d accounts", maxAllowedSSHUsers)
	}
	if !slices.IsSorted(users) {
		return errors.New("baseline allowed_ssh_users must be sorted, so the same intent cannot produce two different directives")
	}
	if len(slices.Compact(append([]string(nil), users...))) != len(users) {
		return errors.New("baseline allowed_ssh_users must not repeat an account")
	}
	for _, user := range users {
		if !unixAccount.MatchString(user) {
			return fmt.Errorf("baseline allowed_ssh_users contains invalid account %q", user)
		}
	}
	if !slices.Contains(users, "deploy") {
		return errors.New("baseline allowed_ssh_users must include the deploy user")
	}
	return nil
}

// validateAuditPublicPorts refuses a listening policy the helper would have to
// clean. The list drives what the audit calls legitimate, so an unsorted or
// duplicated list would let the same intent produce two different verdicts,
// and the SSH port is excluded because it is already covered by its own rule :
// naming it twice is how a widened rule hides in plain sight.
func validateAuditPublicPorts(ports []int, sshPort int) error {
	if len(ports) == 0 {
		return nil
	}
	if len(ports) > 16 || !slices.IsSorted(ports) {
		return errors.New("audit allowed_public_tcp_ports must be a sorted list of at most 16 ports")
	}
	if len(slices.Compact(append([]int(nil), ports...))) != len(ports) {
		return errors.New("audit allowed_public_tcp_ports must not repeat a port")
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("audit allowed_public_tcp_ports contains invalid port %d", port)
		}
		if port == sshPort {
			return fmt.Errorf("audit allowed_public_tcp_ports must not include SSH port %d", port)
		}
	}
	if !slices.Contains(ports, 80) || !slices.Contains(ports, 443) {
		return errors.New("audit allowed_public_tcp_ports must contain 80 and 443")
	}
	return nil
}
