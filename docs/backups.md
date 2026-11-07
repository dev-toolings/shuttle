# Application backups and isolated recovery

`shuttle backup` backs up applications deployed with the managed Swarm strategy.
PostgreSQL always runs natively under systemd. No PostgreSQL container is used
for backup, restore, or recovery testing.

Cloud export is optional. With no `--bucket`, the encrypted archive stays in
`--output` on the workstation running Shuttle. When that workstation is outside
the source VPS, this already provides a copy outside the VPS. AWS S3 and
Cloudflare R2 are supported optional destinations.

## Access and prerequisites

Backup and restore use an explicitly named SSH administrator with passwordless
sudo. Creation uses `setup.operator_user`; recovery uses `--target`. The
restricted `deploy` account receives no new Docker or general sudo privilege.
Both connections verify the host's pinned ED25519 identity.

The source needs the existing native PostgreSQL major, Python 3 and Docker.
The recovery target needs Debian/Ubuntu with Python 3, Docker, `postgresql-common`
and the same native PostgreSQL major as the archive. Versions 16, 17 and 18
remain recoverable. A restore does not silently migrate a database major.

Keep the private recovery identity and the independent signing verification key
outside the VPS and outside Git. Losing the private identity makes decryption
impossible. The verification key is the public
`~/.config/shuttle/v2/root-operations.pub.pem` used by the creating workstation
(or the equivalent path under `XDG_CONFIG_HOME`). A key included with an unknown
archive is not an independent trust anchor.

## Create and verify

```sh
shuttle backup keygen --output /private/offsite/shuttle-recovery.agekey
# The command prints the public age recipient, never the private identity.

shuttle backup create --config config.json \
  --recipient age1... --output /private/offsite/backups \
  --volume demo_redis_data --dry-run

shuttle backup create --config config.json \
  --recipient age1... --output /private/offsite/backups \
  --volume demo_redis_data --yes

shuttle backup verify /private/offsite/backups/demo-TIMESTAMP-ID.tar.age \
  --identity /private/offsite/shuttle-recovery.agekey \
  --verify-key /private/offsite/root-operations.pub.pem
```

`--volume` is repeatable or comma-separated. The list must exactly cover the
volumes mounted by the application's deployed services. An omitted volume,
a bind mount, a volume shared with another running application, a nonlocal
volume driver, links and special files are refused. Global Swarm services and
multinode hosts are outside this backup contract.

**Creation has a maintenance window.** After read-only preflight and image
capture, Shuttle records the original replica counts, stops this application's
services, waits for their containers to stop, dumps the databases and snapshots
the volumes. It restores the replica counts and checks application health
before publishing the archive. The shared root lock serializes journal
transitions and the durable reservation excludes concurrent signed operations
during the snapshot. The source Python program
also creates a durable `backup` operation under
`/var/lib/shuttle/operations` before quiescing services, using the same
`/run/shuttle-root.lock` journal protocol as the Go helper. An interrupted
source remains visible as active or `recovery_required` until the actual
service state is checked. External writers using the same databases or volumes
must also be stopped by the operator.

The archive includes:

- Custom-format native PostgreSQL dumps of the configured application databases.
- Cluster role definitions, including password hashes, to recover database owners
  and grants. This role inventory includes roles outside the application, while
  only the declared application databases are dumped.
- Counts of restored user tables, checked during recovery.
- Explicit application volumes, with file contents and numeric ownership/modes.
- Current application images, saved by content ID, and their reference inventory.
- Current/previous Shuttle state, generated configuration, mounted Swarm secrets,
  managed infrastructure credentials and native PostgreSQL configuration files.

Data travels over verified SSH and is age-encrypted before it reaches the local
archive file. Temporary plaintext exists in a private staging directory on the
source during capture and is removed after transfer. The `.receipt.json` file
binds the ciphertext digest, size, source and application to an Ed25519 signature.
It is published only after successful capture, encryption and local file sync.

A failure never commits a partial archive. If restarting the source cannot be
verified, `/var/lib/shuttle/backup-staging/<app>.pending.json` records the original
replica counts and private staging path. Creation refuses another backup while
that marker exists. Use the administrator to inspect the application, restore
those replica counts, verify health, and only then remove that exact marker.
No command automatically removes a marker whose recovery has not been verified.

Restore uses the same journal schema and short lock before creating its isolated
native PostgreSQL cluster or recovery volumes. It never replaces the live
cluster, live volumes or live service. A restore failure leaves its isolated
recovery directory and operation record available for inspection.

## Optional AWS S3 or Cloudflare R2

Add the cloud flags to `backup create`. Credentials use the standard AWS SDK
credential chain, including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, profiles and workload roles. Do not place credentials in
`config.json` or command arguments.

```sh
# AWS S3
shuttle backup create --config config.json --recipient age1... \
  --output /private/offsite/backups --volume demo_redis_data --yes \
  --bucket my-backups --region eu-west-3 --prefix shuttle/demo

# Cloudflare R2
shuttle backup create --config config.json --recipient age1... \
  --output /private/offsite/backups --volume demo_redis_data --yes \
  --bucket my-backups --region auto --prefix shuttle/demo \
  --endpoint https://ACCOUNT_ID.r2.cloudflarestorage.com
```

Large archives use multipart upload with bounded concurrency. Every upload owns
a random object namespace. Shuttle downloads the uploaded ciphertext and checks
its digest and size before publishing the signed receipt last. A cloud failure
keeps the local encrypted copy and returns a failure; an object without a valid
receipt is not a restore candidate.

Download an exact object key printed by creation:

```sh
shuttle backup fetch --bucket my-backups --region auto \
  --endpoint https://ACCOUNT_ID.r2.cloudflarestorage.com \
  --key shuttle/demo/RANDOM/demo-TIMESTAMP-ID.tar.age \
  --output /private/offsite/downloaded \
  --verify-key /private/offsite/root-operations.pub.pem
```

Fetching verifies the receipt's signature before downloading the archive and
checks the full ciphertext before committing local files. Existing files are
not overwritten. Configure retention and deletion rights in the storage provider;
Shuttle does not delete cloud backups or grant itself deletion permissions.

## Restore into isolated native resources

```sh
shuttle backup restore /private/offsite/backups/demo-TIMESTAMP-ID.tar.age \
  --identity /private/offsite/shuttle-recovery.agekey \
  --verify-key /private/offsite/root-operations.pub.pem \
  --target ops@RECOVERY_HOST --host-key SHA256:... --dry-run

# Same arguments, with --yes instead of --dry-run.
```

Before contacting the target, Shuttle authenticates the receipt, checks the full
ciphertext, decrypts to a private temporary file and verifies every archive entry.
Links, special files, path traversal and duplicate entries are refused. That
local plaintext file is removed when the command ends.

The target creates a uniquely named **native PostgreSQL cluster** owned by a
separate nonlogin Unix account. It uses a private Unix socket and has no TCP
listener. A systemd drop-in points to its private PID file. Database import stops
on SQL errors, and every recorded table count is compared. The cluster is stopped
at the end of the drill, with its data retained for inspection.

Volume copies use new recovery names. Contents, owners and permissions are
compared after copying. Images are loaded under separate recovery tags and their
content IDs are checked. The JSON report gives the cluster, account, socket,
volumes, image references and private recovery directory.

**A verified restore does not switch live traffic.** Start the recovered cluster
with the command named by its report, validate the application against its restored
data, and prepare the target configuration, secret publication and routing cutover.
The original application, its database and its volumes remain in service. Recovery
resources are intentionally retained; remove only the exact cluster, systemd
drop-in, account, volumes, tags and recovery directory named in that report after
inspection. This initial command does not automate a public production cutover.

## Verification performed during development

The local and cloud archive paths have tests for tampering, truncation, wrong
signers, unsafe archives, ownership preservation and interrupted cloud publication.
S3/R2 request ordering is tested with an isolated HTTP service using the AWS SDK.
Actual provider credentials are not needed for the local path and were not used
in that test.

The VPS acceptance exercise additionally restores a native PostgreSQL database,
a Redis volume and the application's images into separate resources. Application
health and witness data are checked independently of archive checksum validation.
