# Monitoring runtime guarantees

The monitoring cycle has one deadline derived from `timeout_seconds` and
`interval_seconds`. It is capped at two minutes. Collection receives four
fifths of that budget. Installed local and external entry points pass this
same context through collection and incident processing. A timed out collector
becomes `unavailable`, and the dated partial report remains available to the
caller.

Collector reads are separate from Shuttle-owned runtime files. The default
collector reader opens an ordinary host path with `O_NOFOLLOW|O_NONBLOCK`,
accepts a regular file at its existing mode and owner, reads a bounded body,
and never creates, chmods or repairs the parent directory or the file. Private
`0700` directories and `0600` files apply only to paths Shuttle owns and
writes: incident state, its lock, the delivery log, maintenance, the episode
archive, and approved root secret files.

Runtime ancestors must be owned by root or the process EUID. Group or world
writable ancestors are rejected even when owned by root or the EUID. Trusted
root or EUID ancestors that are not group or world writable, including `0755`
intermediates, are accepted. Only the Shuttle-owned runtime directory itself
must be EUID-owned mode `0700`. The only writable-ancestor exception is a
descriptor-verified root-owned sticky temporary directory. That exception does
not apply to its descendants, and it does not accept an arbitrary sticky
`01777` directory. The next components after that sticky root must still be
EUID or root owned and not group or world writable. Foreign-owned directories
are rejected, including a replaceable `0755` parent. Operations stay on opened
`os.OpenRoot` descriptors for the whole lock, read, write, rename and sync
sequence, so an ancestor swap cannot redirect another process onto the held
lock identity. FIFO, socket and device paths fail promptly for state, lock,
secret, maintenance and log files.

Incident processing for a canonical `incidents.json` path admits at most one
in-process transaction. The worker owns begin, open, flock, load, transitions,
authorized notifications, persistence and `session.Close`. The caller waits for
a buffered result or its context. A timeout returns an independent copy of the
collected report and a typed `transaction_timeout` or
`persistence_unconfirmed` error. It does not unlock or close the worker
descriptors. The worker keeps the flock until I/O and cleanup finish, starts
no new notifications after cancel, and persists already delivered
acknowledgements. Durability is unconfirmed when a rename may have succeeded.
This bound is in-process: it does not promise a goroutine survives CLI exit.

Incident state is protected by an application-specific `incidents.json.lock`.
The lock covers the complete read, state transition, notification delivery, and
state save sequence. It waits for at most 30 seconds. Each successful
notification acknowledgement is saved before the next event is attempted, so
an interruption can replay only the event whose acknowledgement was not saved.
Every incident and recovery event carries its episode ID. The notification ID
is stable for the application, check, event kind, and episode ID. Receivers must
deduplicate by that ID because the crash window between acknowledgement and
persistence is intentionally at-least-once.

A missing maintenance file means there is no window. An unsafe path, oversized
file, FIFO, corrupt JSON document or I/O error is not treated as a cleared
window. The installed entry point returns the collected report with a
sanitized error and does not start notifications.

A failure must remain debounced across cycles. A healthy observation records a
recovery candidate but does not discard it before the positive debounce ends.
An incident is persisted and delivered before its recovery. A maintenance
window suppresses expected delivery while retaining the candidate, and clearing
or expiring the window allows the pending incident and recovery to proceed.
After a recovery is acknowledged, later healthy cycles preserve the completed
transition and do not enqueue it again. Starting a new failure episode retains
unacknowledged events for the old episode and creates an independent episode
identity. An acknowledgement for one episode cannot update another episode.

Active incident state stays readable. Status shares `schema`, `updated_at`,
`incidents`, `pending`, `maintenance_until` and `last_report`. Fully
acknowledged recovered historical episodes are appended to
`incidents-archive.jsonl` in the same private directory, idempotently by
`check_id` and `episode_id`, then removed from the active `episodes` map.
The archive is a readable JSONL file of the shared status fields `check_id`,
`episode_id`, `state`, `first_seen`, `last_seen`, `incident_sent` and
`recovery_sent`. Duplicate archive records are not rewritten. Unacknowledged
events and the current per-check incident stay in `incidents.json`. A save
that would exceed the 1 MiB reader limit, including the trailing newline,
fails before commit. There is no destructive purge.

Runtime state and delivery failure paths are absolute, private paths. Existing
symlinks, unsafe ancestors, reserved state names, and writable foreign
ancestors are rejected. State, maintenance and secret reads are bounded and
reject FIFOs, sockets, devices and directories after descriptor metadata is
checked. Failure logs contain only event metadata and a generic delivery
error. URLs, credentials, command output, and raw configuration errors are not
written to reports or logs.
