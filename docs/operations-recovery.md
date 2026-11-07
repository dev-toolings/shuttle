# VPS recovery reconciler

This document is the wiring contract for the SHU3 recovery reconciler that
runs inside `shuttle-root` on Linux. It replaces process-table substring
scans and current-digest heuristics. It is not a new orchestration platform.
ROOT B owns writer implementation, migration, Control, reboot, and the
helper caller that prints JSON on a nonzero exit.

Deploy recovery keeps a running official, digest-pinned Redis or RabbitMQ
image when local `Config.Env` versions prove it has the same major and is no
older than the selected retained image. When the selected manifest is the
on-disk `current.yml`, recovery journals the exact rewritten file digest in
`recovery_current_manifest_sha256`, replaces only the kept image value bytes,
and syncs the parent directory. `previous.yml` stays unchanged. The failed
deploy's `current_manifest_sha256` remains its original proof. A mismatch with
all exact journaled and baseline digests stays unknown and refused. If the
selected bytes came from the baseline archive instead of on-disk current,
recovery resolves as before without rewriting the slot. A same-major recovery
that must reapply a retained image missing from the local daemon blocks with an
administrator pull message.

The journal entry is written before the rename, so a crash in between plans the
same action again. After rename, the recovery digest authorizes the rewritten
current slot and the next observation plans no rewrite. The rewrite protects a
rollback only after the next deploy rotates current into `previous.yml`, since
rollback deploys that previous slot. A concurrent `docker service update`
between the final inspect and the current file write remains an accepted race
window under the 2026-10-27 operator decision. Rollback records keep their
existing recovery behavior.

The new journal field remains subject to strict decoding. Downgrading the
helper to a version that predates this field is unsupported. An older CLI also
cannot decode a newer helper's `operations status` record. Use a CLI at least
this release before `operations status` or recovery against an updated helper.
Older records without this field remain readable.

## Disk reserve for an explicit stack rollback

`shuttle rollback` submits the existing signed `stack-rollback` action. The
helper requires at least 1% available space on `/` before reapplying the
retained stack. This reserve leaves room for journal, manifest and runtime
metadata writes while allowing recovery below the 20% new-deployment floor.
It is a minimum reserve, not a prediction of application writes or a check
of a separate Docker partition. Filesystem inspection errors and a reported
zero capacity still refuse the operation.

The client disk preflight and both helper deployment checks retain their 20%
threshold. The helper's early stack and PostgreSQL ownership preflights apply
only to `stack-apply`; rollback reaches its reserve check inside the coordinated
phase, after identity validation. Coordination and journal writes must still
succeed, and the stateful-image protections remain in force. This change does
not alter the separate `operations recover` reconciler or any signed payload
or journal format.

## Root B hook

Production recovery never opens the writer store itself and never assumes
`Record.Revision` or a generation. The only closed-writer seam is this
exact name and signature in package `cli`:

```go
type rootRecoveryWriterReadFunc func(context.Context, coord.Record) (operationwriters.State, error)

var rootRecoveryWriterReader rootRecoveryWriterReadFunc = readCoordinatedRootWriterState
```

ROOT B binds `rootRecoveryWriterReader` to `readCoordinatedRootWriterState`,
which returns the verified generation, host-key and boot binding, and the
signed closed inventory for that operation. A nil function is still an
authentic missing integration dependency: observation then fails closed with:

`closed writer reader is not bound: ROOT B must assign rootRecoveryWriterReader`

The reconciler validates the returned `operationwriters.State`:

- `Binding.OperationID` matches `record.ID`
- `Binding.HostKey` matches `record.Host` when the record carries a host key
- `Binding.BootID` matches `record.HostBootID` when the record carries a boot id
- admissions are closed and `State.ClosedProofHash()` equals the stored closure
- `ExecutorProof` is that canonical hash
- `ExecutorCount` is 0 only when that proof is valid

Baseline identity is `state.Baseline`: current and previous full SHA-256
presence plus the configured native PostgreSQL version and cluster. After a
reboot, recovery still requires that proven closed inventory. A healthy VPS
is not proof.

Observation is read-only. It does not fence, kill, start, scale, deploy, or
delete.

## Supported kinds

This reconciler owns `deploy`, `rollback`, `backup`, `registry-gc`, `destroy`,
and the narrow failed-before-replacement `helper-update` case below.

| Kind | Recovery action |
|---|---|
| `deploy` / `rollback` | Reapply the selected allowlisted retained manifest, then apply and verify the Caddy route and wait for convergence. For a first `deploy`, a closed empty baseline with no current or previous manifest and no app services is released without host mutation. If that deploy's own current manifest exists, confirmed recovery removes its services and then its stack-labelled networks only when a readable, manifest-bound convergence marker says `pending` or `not-converged`. The helper writes `pending` before Docker stack apply and changes it to `converged` only after success. A converged or unmarked legacy release follows normal reapply recovery; an unreadable recovery journal blocks mutation. Removal retains volumes and every secret, including stack-owned secrets. It removes the route and reloads shared Caddy only when that app's route file exists. After unlinking the route, recovery syncs the Caddy configuration directory before reloading Caddy and clearing the pending flag. It journals `current.yml` removal and retries the parent directory sync after failure or restart before releasing the record. The removal requires `--yes --plan-digest`. For deploy only, keep a running official, digest-pinned Redis or RabbitMQ image when its local declared version is the same major and at least the retained version. Substitute the materialized copy; when on-disk `current.yml` is selected, also bind and rewrite only those kept image values in that file. `previous.yml` stays byte-identical. Rollback keeps its existing reapply behavior. No infrastructure install apart from the proven missing-registry recreation described below, no registry GC, and no purge of staging or data. |
| `backup` | Restore the original replica map, wait for actual running tasks with the expected digest and container health, reread the full marker including `Work`, unlink only that marker, fsync the parent. Staging and data stay on failure. |
| `registry-gc` | Restart the existing pinned loopback registry if it is stopped. Never garbage-collect as a side effect. |
| `destroy` | Complete the operator-signed destroy by rerunning the idempotent stack removal from its root-only cleanup journal. The confirmed plan binds the remaining owned services, networks, containers, volumes, application state directory, Caddy route and journal. Recovery keeps cleanup pending through credential removal and the Caddy reload, even after application state or the route has been removed. If no resource or cleanup journal remains, release the operation without another mutation. |
| `helper-update` | Verification only when the reservation failed before helper replacement. Apply confirms the dry-run digest and writes the journal `recovered` transition. No helper rewrite, no writer mutation, no registry/stack/Caddy repair. |

Refusals:

- `reboot` -> use `operations reboot --resume`
- `run`, `restore` require their own reconciler
- unknown kinds fail closed
- any `helper-update` that is still active, has a present unclosed writer, still has a prepared/replaced/unknown migration intent, or whose own-reservation proof names this operation

## Helper-update before replacement

A signed `helper-update` reservation can fail in phase `helper-update` before
any helper replacement. There is then no writer state file, the helper binary
is unchanged, and `/var/lib/shuttle/helper-migration/intent.json` is absent or
a leftover completed intent from another operation. That global record used to
stay unresolved forever (`kind helper-update requires its own reconciler`,
`closed writer proof is missing: operation writer state not found`,
`native PostgreSQL is not configured in the closed baseline`), which blocked
every later deploy, reboot, and helper update.

This reconciler recovers that exact case:

- kind is `helper-update` only
- writer state is absent (`operation writer state not found`); a present writer
  state is still validated as a closed proof
- helper-migration intent is absent, or present with the terminal phase
  `completed`; prepared, replaced, unknown, invalid, or unreadable stays
  unresolved. The intent id is a random migration id, not an operation id,
  so a completed intent alone never proves which operation it belongs to.
- `own-reservation.json` next to the intent is absent or names another
  operation. It is written before the candidate probe, before
  `replaceRootHelper` can rename the new helper. A failed probe with an absent or completed intent
  clears only its matching proof once the leader has been reaped and the
  output pipes have closed, then syncs the directory; successful completion also clears it. A remaining proof naming
  this operation leaves replacement uncertain, so recovery is refused.
  A reaped leader and closed pipes do not exclude a silent detached descendant.
- the record is not active (`recovery_required`); executor proof reuses the
  existing journal lease and staleness evidence, not a process scan
- PostgreSQL and application manifests are not applicable (no app)
- planned action is verification only; apply mutates only the journal
  `recovered` transition through the existing apply path and digest
  confirmation

The intent path is injected on `rootRecoveryRuntime` so tests never open the
host file. Dry-run digest and apply TOCTOU behavior stay the same as for the
other owned kinds.

## Helper rollback and destroy journals

`shuttle helper update` compares the staged candidate's `shuttle --version`
output with the running installed helper's embedded version, numerically as
`vMAJOR.MINOR.PATCH`. On this signed update path, a filename or the local CLI
version cannot authorize a downgrade. The installed helper checks the
operator-signed `allow_downgrade` field before replacement. `shuttle setup`
installs the selected helper directly without a version comparison or a signed
update: it refuses to replace an installed helper while cleanup evidence remains,
in a dedicated first safety stage, before uploads or any host convergence
and, in adoption mode, before writing the adoption claim. Manual root replacement bypasses both
paths and must only follow completed destroy recovery. Install this guard before
relying on it: an older installed helper cannot acquire a new rule merely from
a newer CLI.

For a legitimate rollback to an older, compatible helper release:

1. Use `shuttle operations status --config ./config.json --json` and complete
   pending recovery with the installed helper. Follow the signed recovery
   procedure above for each unfinished destroy. Do not delete or move cleanup
   journals to bypass the guard.
2. Select the trusted Linux binary for that host's architecture. The target
   must support the existing helper migration/finalization protocol and the
   retained operation/writer formats. The explicit flag bypasses release age
   only; it does not bypass migration checks or make incompatible formats
   readable. Older helpers may lack capabilities required by the current CLI,
   and final capability verification can report that after replacement.
3. Review the proposal, then apply it with explicit signed rollback consent:

   ```sh
   shuttle helper update --config ./config.json --binary ./shuttle-linux --allow-downgrade --dry-run
   shuttle helper update --config ./config.json --binary ./shuttle-linux --allow-downgrade --yes
   shuttle helper status --config ./config.json
   ```

The dry run prints a local proposal only. During apply, under the normal helper
lock, any entry in `/var/lib/shuttle/operations/destroy-cleanup` refuses the
replacement, including an unreadable or unknown journal. The only exception is
a root-owned regular file with exactly mode 0600 and name `.shuttle-root-`
followed by decimal digits: this is an uncommitted journal-write temporary,
which stays in place unchanged. Wrong types, owners, permissions and names
still block. Setup applies the same exception. A missing or empty directory is
allowed. The flag is blocked even if the selected candidate is the same release
or newer. Same-release updates and release upgrades can repair a helper while
retaining pending destroy evidence only when both installed and candidate
versions are releases and the downgrade flag is absent. An installed development
helper refuses even a real release candidate until destroy recovery completes.
All other migration, active-operation and writer checks remain in force.

Development builds retain the `make install` workflow. Plain `dev`, tagged
`git describe` output (including dirty builds), and bare commit hashes cannot
prove release ordering. They are accepted without `--allow-downgrade` only when
no destroy cleanup journal remains, whether the installed helper or candidate
has that development version. Missing or malformed versions fail closed.
A confirmed version-policy refusal happens before replacement: the update
reservation ends as `failed` without requiring recovery and a later deploy can
reserve normally. An unconfirmed probe or timeout still requires signed recovery
as described above; a pending migration intent or failure to clear admission
also retains the recovery fence.
This guard does not change `make install` itself, which installs the local CLI.

New destroy journals and every persisted recovery update now use
`shuttle.destroy-cleanup/v2`, including the retain-databases case. The new helper
still reads v1 without inventing consent: absent `drop_databases` means false,
and an existing true value is preserved. Unknown schemas fail before cleanup.

Historical source evidence in `app/go-cli/internal/cli/root_helper_linux.go`:

| Release | Unknown-schema refusal | Cleanup stops on the read error |
| --- | --- | --- |
| v0.0.62 and v0.0.63 | `validateDestroyCleanupJournal`, line 3748 | `removeRootStack`, lines 3884-3886 |
| v0.0.64 | `validateDestroyCleanupJournal`, line 3761 | `removeRootStack`, lines 3897-3899 |
| v0.0.65 | `validateDestroyCleanupJournal`, line 3828 | `removeRootStackWithRuntime`, read at line 4099 |

Those releases compare the schema to exactly `shuttle.destroy-cleanup/v1`, so
they refuse every newly written v2 journal. Releases through v0.0.61 have no
cleanup-journal reader; a schema bump alone cannot protect against their
destroy implementation. The version guard and pending-journal rollback refusal
cover that path once the corrected helper is installed.

Already-written v1 journals do not gain protection from changing the constant.
In v0.0.62 through v0.0.64, `DisallowUnknownFields` already refuses a present
`drop_databases` field, rather than silently ignoring it. However, the false
value was omitted by `omitempty`, so a v1 journal recording no drop consent
could still be accepted under older rules. v0.0.65 understands consent but
still writes v1. Keep the corrected helper installed until recovery completes;
its next persisted journal update writes v2. No bulk journal rewrite or loss
of evidence is part of helper update. A manual root replacement is outside the
signed update guard and must not be used to bypass these constraints.

## Old helper refuses destroy-cleanup

The installed helper calls `admitHelperMigrationOwnReservation` before it
executes the staged candidate. That admission scans the operation journal.
The candidate scans it again, and the parent validates it after replacement.
Therefore a corrected release alone cannot pass the first scan on a host
whose installed helper still rejects `destroy-cleanup`. This applies to every
such host, including production, after any destroy created that directory.

The journal root inventory is: operation-ID `.json` records, operation-ID
`.reboot` companions, `writers`, `baselines`, `destroy-cleanup`, Go journal
temporaries `.operation-N.tmp`, and Python reboot temporaries `.reboot-XXXXXXXX`.
The writer store can also retain `writers/.<operation-id>.<24-lowercase-hex>.tmp`
when a process dies before its atomic rename. The corrected helper checks the
regular-file type, root ownership, 0600 mode and state-size bound, leaves these
bytes untouched and never counts them as committed writer or closure evidence.
Directories must be real root-owned directories with mode 0700; records,
companions and temporaries must be root-owned regular files with mode 0600.
Records and reboot companions retain their identity and state checks; writers
retain closed-inventory validation. Temporary files are never authoritative
records and are left intact. All unknown entries still fail closed. The regression suite runs the coordinator, destroy journal, baseline archive
and writer store against one isolated journal root, then scans their output.
Additional cases cover temporary files and generated Python reboot companions.

An older installed helper that predates these temporary-file checks rejects
`.operation-N.tmp` and `.reboot-XXXXXXXX` as unexpected journal entries, and
rejects `writers/.<operation-id>.<hex>.tmp` as an unexpected writer inventory
entry. Its admission runs before the candidate, so a corrected candidate does
not bypass that refusal. The empty-directory procedure below does not apply
to these files: never rename partial bytes into authoritative records or delete
them just to pass migration. Stop retries and have an administrator reconcile
the abandoned writes with the committed journal and writer state under the
helper lock before choosing a recovery action; preserve unresolved evidence.

The corrected helper accepts a private `destroy-cleanup` directory containing a
pending destroy journal when its operation requires recovery, leaves that journal
and operation record unchanged for the new helper to recover, and still requires
any writer inventory to be closed. This differs from the old-helper procedure
below, which stops on any remaining cleanup journal and never moves or removes it.

For the exact refusal `operation journal contains an unexpected entry
"destroy-cleanup"`, use this procedure. Do not move a nonempty directory out of
the journal, remove its contents, or edit any operation JSON to bypass the scan.

1. Stop new Shuttle commands on the host during this maintenance. The first
   check, under the normal helper lock, is that `destroy-cleanup` is absent or
   an empty private directory. Any entry, including a completed-looking or
   unreadable journal, stops the procedure before mutation. A pending destroy
   must be recovered through its signed recovery flow first; if the installed
   helper cannot recover it, stop and investigate without moving its evidence.
2. Run the following administrator command on the host. It also refuses active
   operations, unresolved destroys, malformed records, pending migration
   intents and admission proofs. It removes only an empty directory, with
   `rmdir`, then syncs its parent. It never removes a journal or a data file.

```sh
sudo flock -n /run/shuttle-root.lock python3 - <<'PYDESTROYCLEANUP'
import json, os, pathlib, stat, syslog
root = pathlib.Path('/var/lib/shuttle/operations')
cleanup = root / 'destroy-cleanup'
migration = pathlib.Path('/var/lib/shuttle/helper-migration')
def private(path, directory):
    info = path.lstat()
    assert info.st_uid == 0, 'refused: entry is not root-owned'
    assert stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), 'refused: unsafe permissions'
    assert (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)), 'refused: unexpected entry type'
    return info
def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
def read_record(path, limit):
    assert private(path, False).st_size <= limit, 'refused: oversized record'
    value = json.loads(path.read_text())
    assert isinstance(value, dict), 'refused: malformed record'
    return value
# Check cleanup evidence before examining or changing anything else.
private(root, True)
has_cleanup = present(cleanup)
if has_cleanup:
    private(cleanup, True)
    assert not any(cleanup.iterdir()), 'refused: destroy-cleanup contains a journal; recover destroy first'
for path in sorted(root.glob('*.json')):
    record = read_record(path, 256 << 10)
    assert record.get('schema') == 'shuttle.operation/v1' and record.get('id') == path.stem, 'refused: invalid journal identity'
    assert record.get('state') in ('active', 'completed', 'failed', 'recovered', 'recovery_required'), 'refused: unknown state'
    assert isinstance(record.get('kind'), str) and isinstance(record.get('recovery_required'), bool), 'refused: malformed state'
    assert record['recovery_required'] == (record['state'] == 'recovery_required'), 'refused: inconsistent state'
    assert record['state'] != 'active', 'refused: an operation is still active'
    assert not (record['kind'] == 'destroy' and record['recovery_required']), 'refused: unresolved destroy'
if present(migration):
    private(migration, True)
    assert not present(migration / 'own-reservation.json'), 'refused: admission proof remains; use interrupted-helper-probe procedure'
    if present(migration / 'intent.json'):
        intent = read_record(migration / 'intent.json', 16 << 10)
        assert intent.get('phase') == 'completed', 'refused: migration is not completed'
if has_cleanup:
    cleanup.rmdir()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    syslog.syslog(syslog.LOG_NOTICE, 'Shuttle administrator removed empty destroy-cleanup directory for old-helper update')
print('Empty destroy-cleanup checked; no cleanup journal removed')
PYDESTROYCLEANUP
```

3. On the CLI machine, inspect `shuttle operations status --config
   ./config.json --json`. If the old scan failure left a helper-update record
   requiring recovery, set `OPERATION_ID` to that exact ID and run the existing
   signed before-replacement recovery flow. Do not substitute another operation
   or manually change its state. If recovery refuses, stop and follow the
   reported proof requirements; do not continue to another update.

```sh
shuttle operations recover "$OPERATION_ID" --config ./config.json --dry-run --json
shuttle operations recover "$OPERATION_ID" --config ./config.json --yes --plan-digest sha256:PLAN_DIGEST_FROM_DRY_RUN
shuttle helper update --config ./config.json --yes
```

If no helper-update record requires recovery, run only the last command.
Inspect operation status again after the update. A refused scan on the corrected
helper is checked before its mutation phase and the phase-less reservation is
refused, with state `failed` and no recovery requirement. The client also asks
for that refusal if the reply leaves a live reservation with no phase; the
helper rechecks this under its lock. Any started phase, pending migration,
unknown outcome or failed refusal retains its evidence and is not reported as
cleanly released. No VM validation is implied by the fixture tests.

## Interrupted helper probe

`shuttle helper update --dry-run` only prints the local installation proposal;
it does not inspect the host or recover a migration. A failed finalization does
not prove that the helper was replaced. Use the procedure below after a probe
failure, including a signal, timeout, or an unreadable intent diagnostic.

1. On the CLI machine, identify the failed helper-update operation and retain
   its ID from `shuttle operations status --config ./config.json --json`.
   Stop retries until recovery is complete. If no intent exists, try the signed
   recovery commands in step 4 first; they will refuse an unexplained admission
   proof or a live executor.
2. On the host, an administrator must establish that the failed candidate and
   its descendants have stopped, including any detached process reported by
   the probe. Use `sudo ps -eo pid,ppid,pgid,sid,lstart,args` and the operation's
   logs; verify executable identity through `/proc/PID/exe` before stopping an
   identified leftover. Do not kill a reused PID or a group inferred only from
   an old number. If termination or absence of partial host mutations cannot
   be established, keep the evidence and investigate; do not unlink it.
3. If the intent is absent or `completed` but the admission proof remains
   after step 2, inspect
   `own-reservation.json` against the operation journal and set `OPERATION_ID`
   to that operation's ID and `INTENT_ID=""`. The command below clears only
   that operation's proof, and only if the installed helper's digest differs
   from the candidate's digest. Equal digests, a missing or mismatched proof,
   and unreadable state are refused; retain the evidence and investigate.
   For a readable `prepared` intent, inspect its `id`, `source`,
   `candidate_sha256`, `host`, and `boot_id` with the operation journal. Set
   `OPERATION_ID` and `INTENT_ID` to those reviewed IDs. The following command
   holds the helper lock and, for a prepared intent, verifies that the source
   helper is still installed before removing that reviewed intent and its
   matching admission proof. It does not cover `replaced`, malformed, or mismatched state: leave
   those files intact and diagnose the migration before retrying. A completed
   intent is kept unchanged while only its admission proof is removed; if no
   proof remains, use step 4 directly. This is an explicit
   administrator recovery action, never an automatic update side effect.

```sh
sudo flock -n /run/shuttle-root.lock python3 - "$OPERATION_ID" "$INTENT_ID" <<'PYRECOVERY'
import hashlib, json, os, pathlib, re, sys, syslog
root = pathlib.Path('/var/lib/shuttle/helper-migration')
intent_path = root / 'intent.json'
own_path = root / 'own-reservation.json'
intent = json.loads(intent_path.read_text()) if intent_path.exists() else None
record = json.loads((pathlib.Path('/var/lib/shuttle/operations') / (sys.argv[1] + '.json')).read_text())
assert record['id'] == sys.argv[1] and record['kind'] == 'helper-update'
assert record['state'] != 'active' and record['recovery_required']
own = json.loads(own_path.read_text()) if own_path.exists() else None
installed = pathlib.Path('/usr/local/libexec/shuttle-root')
installed_digest = 'sha256:' + hashlib.sha256(installed.read_bytes()).hexdigest()
if own is not None:
    assert own['operation_id'] == record['id']
    assert own['host_fingerprint'] == record['host']
if intent is None or intent['phase'] == 'completed':
    assert sys.argv[2] == '' and own is not None
    assert own['schema'] == 'shuttle.helper-migration-own-reservation/v1'
    assert own['operation_kind'] == 'helper-update'
    assert re.fullmatch(r'sha256:[a-f0-9]{64}', own['candidate_sha256'])
    assert installed_digest != own['candidate_sha256']
    detail = 'candidate admission without a pending intent'
else:
    assert intent['id'] == sys.argv[2] and intent['phase'] == 'prepared'
    source, digest = intent['source'].rsplit('#', 1)
    assert source == str(installed) and installed_digest == digest
    assert intent['host'] == record['host']
    if own is not None:
        assert own['candidate_sha256'] == intent['candidate_sha256']
        assert own['boot_id'] == intent['boot_id']
    detail = 'prepared migration ' + intent['id']
syslog.syslog(syslog.LOG_NOTICE, 'Shuttle administrator abandons ' + detail + ' for operation ' + record['id'])
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    if own is not None:
        own_path.unlink()
        os.fsync(directory)
    if intent is not None and intent['phase'] == 'prepared':
        intent_path.unlink()
        os.fsync(directory)
finally:
    os.close(directory)
PYRECOVERY
```

4. Release the root lock (the command above releases it on exit). From the CLI
   machine, run the signed recovery dry-run and inspect its proposed actions;
   use the exact returned plan digest for confirmation. Then retry the update:

```sh
shuttle operations recover "$OPERATION_ID" --config ./config.json --dry-run --json
shuttle operations recover "$OPERATION_ID" --config ./config.json --yes --plan-digest sha256:PLAN_DIGEST_FROM_DRY_RUN
shuttle helper update --config ./config.json --yes
```

An unreadable or mismatched intent is not evidence of a failed-before-replacement
update. This procedure deliberately refuses it instead of guessing or discarding
migration evidence. No data, application manifest, installed helper, or journal
record is manually rewritten by the procedure.

## Manifests, markers, and actions

Confirmed plans bind an allowlisted retained path (`current.yml` or
`previous.yml` under the application state root) and the full file SHA-256
of the selected authorized artifact. After rotation the current slot may
hold an unknown C1 while C0 remains in `previous.yml`. Recovery resolves
authorized hashes across both slots and binds the chosen path and hash.
Unknown hashes are never authorized. First release may have no previous
file when the closed baseline says previous is absent.

C1 is not unknown when the record carries `current_manifest_sha256` and
`current.yml` hashes to exactly that value: `stack-apply` journals it through
`coord.JournalCurrentManifest` before writing the file. A deploy recovery may
also authorize the current slot when its full digest equals this record's
`recovery_current_manifest_sha256`, written through
`coord.JournalRecoveryCurrentManifest` before the recovery rename. For a
`deploy`, either exact current-slot proof selects that file. The recovery field
does not authorize `previous.yml`; the original field remains the proof for the
failed deploy's artifact. Any current digest matching neither proof nor a
closed baseline stays unknown and refused.

For `deploy` records, each Redis or RabbitMQ service declared in the selected
manifest is inspected through `docker service inspect`. An absent service
keeps the existing behavior. Other service inspection errors make the plan
unresolved. If live and retained references differ, recovery accepts keeping
the live reference only when both references identify official images pinned
by digest, both images are present locally, their `REDIS_VERSION` or
`RABBITMQ_VERSION` values from `Config.Env` parse, their majors match, and the
live version is not lower. The image lookup removes the tag and uses the
repository digest. It never contacts a registry during planning.

A live version older than the retained version in the same major continues to
reapply the retained image. Any major change in either direction, unofficial
or unpinned live image, missing version metadata, or non-absence service
inspection error blocks the reapply and requests manual service recovery. A
missing local retained image reports that an administrator must pull it and
rerun recovery. Kept references are included in the action proof and displayed
as their declared versions. When current.yml is selected on disk, the final
`record-kept-infrastructure` action follows reapply and Caddy repair. It
recomputes the decision, constructs the prospective bytes by exact scalar byte
spans, checks that only kept image values differ, validates the root stack,
journals the prospective digest, atomically writes current.yml, and syncs its
parent directory. The same action can replay if the journal write succeeded
but the rename did not. It refuses a second, different recovery digest for the
same record. The rename alone never completes recovery: while current.yml
matches the recovery digest and its directory sync has not succeeded, recovery
plans a final `sync-current-directory` action bound to that digest, so a failed
sync or a crash between rename and sync keeps the record recovery_required
until a later attempt syncs the directory. The executor repeats the decision immediately before deployment
and again before the current file rewrite. A concurrent `docker service update`
between the last inspect and the rewrite remains an accepted interval.

If baseline still names P0 and those bytes are gone from both live slots,
recovery reads the operation baseline archive via
`readRootOperationBaselineArtifact`. A missing archive entry reports
`authorized baseline artifact is absent after rotation; ROOT B must persist
baseline bytes before slot replacement` and stays unsafe. Unknown live
hashes such as C1 are unresolved, never authorized, and never used as a
substitute. A missing, unknown, or changed required manifest refuses
before effects.

The pending backup marker is a bounded regular anchored file. Unknown or
trailing JSON is refused. App, operation id, replica map, and optional
staging `Work` path are validated. `MarkerProof` covers those fields, so
the same map size with changed counts invalidates confirmation. Replica
maps compare keys and values: a zero-count key is not the same as a
missing key. Restore writes a durable replica proof under the operation
baseline archive before unlinking the marker, then scales and verifies
the captured original replica map, not the manifest-declared counts. A
crash after marker removal can still re-scale from that proof.

Typed internal actions (`restore-backup-replicas`,
`restart-loopback-registry`, `recreate-loopback-registry`, `reapply-retained-current`,
`apply-caddy-route`, `record-kept-infrastructure`,
`sync-current-directory`) produce `ActionProof`.
Display strings on
`coord.RecoveryObservation.Actions` stay for operators. Apply rederives
the action struct under the recovery lock and checks the proof. It never
selects work with `strings.Contains` on those sentences.

`ResourceVersion` hashes closed proof, full manifests, marker proof, action
proof, and semantic identities (image, restart policy, loopback bindings,
configured PostgreSQL version/cluster, actual task/container identity and
health). Task states are normalized to the first word, so `Running 3 seconds
ago` aging does not change confirmation. Docker health-log timestamps are
excluded.

Apply reobserves before any effect. The fresh observation must stay Safe,
carry no MissingProof, and keep ExecutorProof, ResourceVersion,
ActionProof, ManifestProof, MarkerProof, and boot/process/phase versions
unchanged. A writer-reader failure on that second look refuses the action.

## Runtime proof, not readiness theatre

Service restore requires actual task `Running`, the expected image digest, and
container health. A deploy reapply may expect an infrastructure image kept by
the verified rule above, using that image's digest for both task and container
checks. Desired replica counts are not enough. The
reconciler reuses `rootStackServices`, `evaluateRootServiceConvergence`,
and `waitRootStack`, then inspects the live container. Stopped, scaled-zero,
or unhealthy tasks are repairable when identity proof is present. Missing
authorization, unknown hashes, or a failed writer read stay unsafe.
Post-repair observation still requires strict convergence.

The loaded Caddy configuration is observed independently of task
convergence. A matching task set with a stale loaded route still plans
`apply-caddy-route`. The on-disk fragment is not proof of a successful
reload. Post-apply verify uses the same loaded-route match as observation
(`caddy adapt` JSON versus fragment addresses), not byte-equal Caddyfile
comparison. Manifests, markers, and retained files are opened with anchored
no-follow descriptors; the byte limit is enforced on the opened file.

PostgreSQL is checked only as the configured native version and cluster
from the closed baseline. Both fields exactly `not-configured` means the
check is not applicable, not a missing proof. Recovery does not install,
start, or migrate a cluster, does not run PostgreSQL in Docker, and does
not treat `pg_isready` as data-persistence proof.

The existing registry must keep the pinned image, restart policy `always`,
and every binding on loopback port 5000. Any additional public binding
fails closed. Health wait is bounded by the request context.

A deploy can also recreate a registry removed during image replacement. Before
stop/rm, the helper durably records the validated signed target image and an
SHA256 proof of the existing `shuttle-registry` volume's stable metadata
(name, driver, scope, mountpoint, creation time, options and labels). This is the
optional `registry_replacement` field on the existing operation journal schema;
the signed root-operation protocol is unchanged. Older records without this
proof remain readable and cannot authorize recreation of a missing registry.
Status and operation-control responses omit this helper-only field from a copy
of the record, preserving the established response shape for strict older CLI
readers. The durable journal retains it for recovery.

**CLI requirement for writer recovery:** when an operation journal contains
`registry_replacement`, both `operations writers <operation-id> --dry-run` and
`operations writers <operation-id> --yes --plan-digest <digest>` require a CLI
from this release (the release introducing registry proof support)
or newer. Upgrade the CLI that executes these commands before inspecting or
closing the writers, then obtain a fresh confirmation digest with `--dry-run`.
Updating only the VPS helper does not satisfy this requirement.

Unlike status and operation-control, `operations writers` uses an
administrator-side Python reader embedded in the invoking CLI. That program
returns the full on-disk record inside a `record`/`writers` snapshot. The older
CLI's strict nested decoder fails with
`json: unknown field "registry_replacement"` before writer observation or
closure. Helper response projection cannot repair that already-shipped reader.
Snapshots whose records lack the field remain readable by the older decoder;
the frozen nested-snapshot regression test covers both cases and acceptance by
the current CLI. Do not remove the journal proof to accommodate an older CLI.

An older helper that strictly decodes the full journal record rejects
`registry_replacement`. The normal candidate admission scan in c762f5f reads
those full records through the retained closed writer inventories and therefore
refuses that candidate before replacement. The default release-version check
also refuses a downgrade without `--allow-downgrade`; that flag does not bypass
the candidate admission scan. The dedicated pending-destroy guard does not
inspect registry proof. The inventory-based scan is not an unconditional guard
for journals whose writer inventories are absent, nor does it protect an
out-of-band binary replacement. This change does not alter downgrade policy.


Recovery requires Docker to confirm container absence, the same existing local
volume, and a locally available official registry image matching the recorded
repository digest. An unavailable daemon, missing volume, changed volume or
missing image refuses recovery. Planning does not pull an image or create a
volume. The confirmed resource proof includes the image and volume identities;
apply checks them again under recovery exclusion before running the existing
ownership repair and hardened creation commands. Creation always uses the fixed
`127.0.0.1:5000:5000` binding, named data volume, non-root user and `always`
restart policy, then waits for health. A partially recreated container keeps
its existing restart path, with the journaled volume checked as well.

Registry replacement during deploy holds the shared-resource lock and rereads
container identity there. Actual replacement additionally requires
`WithSoleOperation`, because an active push holds a reservation rather than the
shared-resource lock. If another operation is active, replacement is deferred,
the requested and observed images are logged, and follow-up registry commands
use the observed image. The signed target remains the requested target; the
application manifest is unchanged. A deferred attempt may retain an unused
replacement intent, which alone never proves container absence or volume identity.


## Apply JSON

`recoveryRootApply` returns a JSON body and, on failed steps, also an
error. Invalid `ExpiresAt` uses the same structured apply-report path.
The body is never nil unless JSON encoding itself failed. Schema
`shuttle.recovery-apply/v1` carries the plan fields plus
`completed_steps`, `error`, and `remaining_recovery`. The helper caller in
this B worktree already writes that body on stdout through
`emitRootHelperResult` and keeps the nonzero exit. The parent decoder stays
strict.

## Tests and host isolation

Go tests inject a per-call runtime (reader, filesystem, docker, clock,
executors). They do not race the production global, do not call real
Docker, SSH, PostgreSQL or shared `/var`, and do not brute-force unsafe
helpers. Live VPS and VM recipes stay exclusive to ROOT.

## Honest remaining boundary

`rootRecoveryWriterReader` is bound to `readCoordinatedRootWriterState` in
this B worktree. Helper apply JSON on a nonzero exit is already emitted
outside these owned files.

Production recovery still stays fail-closed for missing baseline bytes:
closed baseline only stores C0/P0 hashes, and after slot rotation the disk
can be C1/C0 with P0 gone. This reconciler selects C0 if those bytes remain
in a slot and will not authorize unknown C1, but it cannot invent P0. When
baseline.Previous is still present and the bytes are absent, observation is
unsafe with `authorized baseline artifact is absent after rotation; ROOT B
must persist baseline bytes before slot replacement`. Full pre/post-rotation
recovery needs B to fsync baseline artifacts and the signed candidate
identity before replacing slots.

The pending backup marker is not a B-owned durable recovery proof. If B
deletes the marker before a crash, captured replica targets are lost and
later observation can fall back to manifest counts. This lane restores from
the live marker only.

Writer package implementation, migration, Control, reboot, and caller
changes outside these three owned files stay out of this lane. No live
VPS/PVE/install proof is claimed here.
