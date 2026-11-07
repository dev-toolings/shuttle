# Backup lifecycle monitoring

Backup creation records the source capture, encrypted archive, signed receipt
and optional cloud export as one versioned lifecycle document. The signed root
helper validates the same document before it is stored, so a collector can
distinguish a missing status, an in-progress attempt, a failed stage and a
fresh local archive.

The root-owned journal is stored at
`/var/lib/shuttle/backups/<app>/status.json`. Collectors always read that
path, even when monitoring uses a custom `StateDir`. Tests inject a reader
for that production path; a workstation sidecar is never treated as VPS
proof. The journal is independent of monitoring installation. Directory
creation walks every ancestor from `/` with `O_NOFOLLOW`, rejects writable
or foreign-owned ancestors, and retries parent `fsync` so a failed first
BEGIN cannot be acknowledged without durability. Encryption is recorded
when the archive is closed and synced, before receipt signing. Admitted
attempt history is compacted so the active journal cannot fill with
BEGIN records that later block a receipt update.

A new attempt is accepted only as `phase: source` (BEGIN). The helper assigns
a monotonic `latest_attempt_order` under the existing VPS flock. Client
timestamps and lexicographic IDs do not order attempts. An exact duplicate
BEGIN is idempotent; any other change to that BEGIN is rejected. A later
phase for an unknown or already superseded attempt is rejected.

`last_success` is the last verified local encrypted archive and signed
receipt. It is set at `receipt_verified` and kept if a later configured
cloud export fails. That cloud failure stays visible on `latest_attempt`
and degrades the backup check. No S3/R2 configuration is not a failure.

Cloud export is optional. With no bucket configured, `cloud` is
`not_configured` and a fresh encrypted archive is healthy. If a configured
cloud export fails after the local archive and receipt succeed, the collector
reports the local success and the cloud failure separately. A required cloud
export must finish with `cloud: complete` before the check is healthy.

Before capture, the CLI negotiates the `backup-lifecycle` helper capability. A
current helper publishes remote lifecycle evidence even when monitoring is
disabled. A helper that supports the required operation coordination but lacks this
lifecycle capability keeps a local-only outcome when remote backup proof is
not expected, and reports that limitation explicitly. When
remote proof is expected, capture stops before it starts and the error directs
the operator to update the signed helper.

The attempt ID matches the coordinated backup reservation. Terminal lifecycle
publication follows lease renewal shutdown, local temporary-file cleanup and
operation finalization. A failure after the archive and receipt were verified
marks the attempt failed while retaining those completed stages and the local
archive. Directory fsync and any requested cloud verification remain required;
a requested cloud failure is returned to the caller.
