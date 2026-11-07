# Root helper migration integration

This document is the operator and parent integration boundary for the bounded
legacy migration module. The Linux migration code and its focused tests are in
this worktree. The root plan, root dispatcher, capability response, operation
writer implementation, and release changelog remain parent-owned.

```text
+------------------------------------------------------------+
| Legacy strict signed helper update                         |
+-----------------------------+------------------------------+
                              |
                              v
+-----------------------------+------------------------------+
| Candidate help probe, intent fsync, exact parent and flock |
+-----------------------------+------------------------------+
                              |
                              v
+-----------------------------+------------------------------+
| Existing atomic replacement and durable replaced phase    |
+-----------------------------+------------------------------+
                              |
                              v
+-----------------------------+------------------------------+
| Signed finalize or signed boot-change reconcile            |
+-----------------------------+------------------------------+
                              |
                              v
+-----------------------------+------------------------------+
| Archived history and completed migration                   |
+------------------------------------------------------------+
```

## Implemented caller behavior

`updateSignedRootHelperWithFinalizer` keeps the first legacy exchange
operation-free. It sends the existing `rootplan.NewHelperUpdate` plan after a
capability audit. It never adds an operation ID to that plan. A helper that
reports `signed-helper-update` but not `helper-migration` is treated as legacy,
because it cannot safely receive the finalization action.

After the candidate has created the durable intent, the caller invokes:

```go
type helperMigrationFinalizer func(
    *shuttlessh.Client,
    trustedHostIdentity,
    helperMigrationFinalizeRequest,
) error

type helperMigrationFinalizeRequest struct {
    CandidateSHA256 string
    Host            string
    IntentID        string
    PlanExpiresAt   time.Time
    Validate        func() error
}
```

The default finalizer returns an explicit unavailable error. The parent must
wire a signed `helper-migration-finalize` transport before an update can report
success. If the capability response is withheld because a migration is
pending, the caller reports the pending ID and phase and may call the finalizer
directly with the candidate digest. It does not send the legacy update again.

The status command preserves this read-only pending state even while ordinary
capability advertisement is withheld. A parent status hook may use the typed
adapter already declared in the migration package:

```go
type helperMigrationStatusReader func(
    *shuttlessh.Client,
    trustedHostIdentity,
) (helperMigrationStatus, error)
```

Modern helpers must use an exact parent adapter that reserves the operation
with the current typed coordinator context. The legacy first hop must remain
operation-free. The old helper is never inferred to understand a new command.

## Root plan hook

The parent adds a typed `HelperMigration` field and constructor to
`app/go-cli/internal/rootplan/rootplan.go`:

```go
type HelperMigrationOperation struct {
    CandidateSHA256 string `json:"candidate_sha256"`
}

func NewHelperMigrationFinalize(
    candidateDigest,
    operatorKeyFingerprint,
    hostFingerprint string,
    now time.Time,
    validity time.Duration,
) (Plan, error)
```

The action is `helper-migration-finalize`. It has no payload, no normal
operation ID, and no unrelated typed operation fields. The parent validates the
candidate digest and rejects unknown fields, an operation ID, and unrelated
payloads. The signed reconcile action uses the same typed candidate and an
explicit reconciliation action:

```go
type helperMigrationReconcileRequest struct {
    CandidateSHA256 string
    Host            string
    IntentID        string
    PlanExpiresAt   time.Time
    Validate        func() error
}

func reconcileRootHelperMigration(
    context.Context,
    helperMigrationReconcileRequest,
) error
```

The root dispatcher verifies the signature first. It then calls the migration
guard. The guard must be checked again inside the acquired root-operation flock
before every mutation. `audit`, `operations-status`, `recovery-plan`, signed
`helper-migration-finalize`, and signed `helper-migration-reconcile` are the
only actions that may inspect or complete a pending migration. In particular,
`recovery-apply`, helper update, stack actions, secrets actions, baseline
actions, and arbitrary runs remain blocked.

The helper-update reservation exception is narrow. It is allowed only when the
caller identity was verified as the exact root helper process and the candidate
digest is linked to the pending intent. An arbitrary active `helper-update`
record is never ignored.

## Candidate and finalization proof

The staged candidate `init` path runs only for the exact root lifecycle:

- uid 0;
- argv `shuttle-root --help`;
- the exact root-helper staging directory and `.shuttle-root.next-*` name;
- a root-owned regular mode 0755 candidate;
- the installed root helper as the parent with argv `path apply`;
- the parent effective UID, stable process birth value, and exact lock proof.

The lock proof reads `/proc/PID/fdinfo/FD`. It requires the exact lock device and
inode and a `FLOCK` record owned by the parent PID. A free lock acquired by a
different process is not evidence. Process capture filters the exact helper
executable before hashing, bounds every proc read, and checks process birth
before and after the executable read. Permission and ambiguous relevant errors
are returned rather than treated as an absent process.

The first candidate probe writes a root-owned durable intent before the old
helper renames the candidate. Ordinary help remains pure. A prepared or
replaced retry is accepted only when source, candidate digest, host identity,
probe fields, lock device, and lock inode all match. A replaced retry also
revalidates the installed candidate, journal, and writers under the lock.

Completed intents are written once to the bounded history directory using their
immutable ID, then removed from the active intent path before a new generation
is initialized. Existing history with different content is refused.

## Operation journal and writer proof hook

The migration reader recognizes `/var/lib/shuttle/operations` and its exact
`writers` child. Journal filenames accept both UUID operation IDs and valid
historic 32 hexadecimal operation IDs. Records must use the shared
`shuttle.operation/v1` schema, match their filename, and be terminal. Active,
recovery-required, corrupt, unsafe, and unexpected records refuse migration.

The operation-writers implementation is parent-owned and is not imported by
this worktree. The owned runtime exposes this narrow adapter:

```go
const helperMigrationWriterProofSchema = "shuttle.operation-writer/v1"

type helperMigrationWriterRecord struct {
    OperationID string `json:"operation_id"`
    State       string `json:"state"`
    Origin      string `json:"origin"`
}

type helperMigrationWriterProof struct {
    Schema  string                        `json:"schema"`
    Writers []helperMigrationWriterRecord `json:"writers"`
}

type helperMigrationWriterProofReader func(
    string,
) (helperMigrationWriterProof, error)
```

The default reader refuses any nonempty writers directory. A supplied reader
must prove the versioned contract, a legitimate operation ID, and `closed` for
every writer. `local-vps` and `client-origin` are distinct origin values and
must not be collapsed. Free-form `KernelProof` and `AuthenticatedProof` text
is not accepted as proof.

## Boot-change reconcile

Finalization refuses a boot ID change. The signed reconcile path acquires the
flock first, re-reads the immutable intent, checks expiry and the signed
validator, reads the real current boot ID, verifies the installed candidate,
and inspects the coordinator journal and typed writers proof under that lock.
It drains matching old executors with bounded proc reads, records the explicit
`reconcile-boot-change` history item, and only then advances the durable phase.
Any missing proof leaves the intent pending. There is no blanket auto-accept
and no named recovery command is claimed here.

## Parent integration status

This worktree provides the migration implementation, focused tests, the caller
fallback, and these exact typed hooks. Parent work remains for the root plan
constructor and validation, dispatcher branches, signed finalize and reconcile
transport, capability/status response, replacement callback, coordinator
writer proof reader, and the final changelog entry. Until those hooks are wired,
the default finalizer remains unavailable and this document does not claim that
the overall migration is complete.

## Changelog text for the parent

**Legacy root-helper updates now have a bounded signed migration path.** A
legacy helper receives the historical strict signed update first. The candidate
proves the exact root-helper parent and lock context, writes a root-owned
durable intent before replacement, and the new helper waits for old executors
before signed finalization revalidates the host and closes the intent. Existing
strict decoding stays compatible, interrupted fsync transitions remain
resumable, and uncoordinated historical registry clients still require
explicit drainage.
