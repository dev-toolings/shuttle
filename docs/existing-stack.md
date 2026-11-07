# Update a platform-owned Swarm stack

`shuttle deploy existing-stack --config deploy/shuttle-staging.json` is an
explicit operator mode for an existing, single-node Swarm that another platform
owns. It builds the declared images locally, runs an optional project-owned
image verifier, streams the images over SSH, proves their image IDs on the host,
and publishes them to the host's existing loopback registry. A fresh tag per run
and digest-pinned manifest preserve the identities needed by rollback.

The declared `apply` executable receives `{{manifest}}` and `{{version}}` as
quoted arguments. It must own backups, migrations, health checks, persistence and
rollback. Shuttle verifies every declared service runs the resolved image digest
after that command succeeds. An SSH failure during apply leaves an uncertain
platform outcome: inspect the platform's recovery state before retrying.

This mode neither runs setup nor renders a replacement stack. It changes no
PostgreSQL installation, host mounts, edge configuration or signed-helper policy.
The configured existing non-root account must already have Docker access, or
`server.sudo: true` must name an operator with passwordless sudo. That operator
is the authority for the declared apply command. This is separate from the
restricted `deploy` account and signed helper used by managed Shuttle deployments.

The JSON format is deliberately separate from managed `config.json` and rejects
unknown fields. Version 1 requires:

- `app` and `stack`: application identity and the existing Swarm namespace.
- `server`: `host`, `user`, `port`, `host_key`, `identity_file`, `sudo`.
  The ED25519 fingerprint must be verified independently before configuration.
- `registry`: an existing IPv4 loopback registry with an explicit port.
- `build.services`: the existing build definitions (`context`, `dockerfile`,
  `args`, `services`). Each service must already belong to the named stack.
- `manifest`: one environment-variable key per build, mapped to its build name.
- `apply`: an argument array beginning with an absolute host executable, containing
  `{{manifest}}`. `{{version}}` is optional.
- `verify_image`: optional local argument array, with `{{image}}` substituted.
  A project can use this for its own artifact acceptance policy. No scanner is
  selected implicitly.
- `timeout_seconds`: remote transfer/apply budget, 30 to 3600 (default 900).
- `retention.build_cache`: maximum size of the persistent local BuildKit cache,
  default `20GB`.
- `retention.keep_releases`: number of releases retained per published repository,
  default 1, minimum 1. For example: `"retention": {"keep_releases": 2}`.
  The newly verified release is always retained; additional releases are selected
  by their UTC tag timestamp, independently of the Git SHA.

Run from the application source directory. `--dry-run` verifies the pinned SSH
host, active single-node manager and existing service ownership, then prints the
build and transfer plan without building, uploading or applying anything.
Local images are removed on success, failure or operator interruption. The
BuildKit builder `shuttle-<app>-existing` persists between runs so unchanged
layers are reused; its process is stopped after each run and its cache is
capped by `retention.build_cache` (default `20GB`). Runs of one app on the same
workstation are serialized.

Before transferring, Shuttle compares each fresh image with what its services
already run (layers, runtime config and platform; not the creation time). An
identical image is not transferred: the running image is tagged for this
release and its digest stays in the manifest, so Swarm leaves the service
untouched. This matters most for an ingress publishing host ports, which cannot
start its replacement first and drops traffic on every restart.

After apply succeeds and every declared digest is verified, Shuttle removes older
release tags from the host Docker image store with `docker image rm` and deletes
superseded registry manifests through the registry API. The default retains only
the running release, including its reusable layers for the next transfer. There
is no global `docker image prune`. Failure and dry-run paths skip host retention.
Cleanup errors are warnings and do not invalidate a verified upgrade. Output
includes bytes freed (host filesystem free-space delta) and disk usage before and
after cleanup; concurrent writes can affect the reported delta.

This follows AGENTS.md's requirement to preserve rollback images: the platform
must finish any rollback inside apply, before returning success. Shuttle cleans
only after that rollback boundary and digest verification. To retain historical
releases for later platform-initiated rollbacks, increase `keep_releases`.

Only exact repositories published by the configured builds are eligible. Shuttle
re-checks all Swarm service images, desired-running task specs and running or
restarting containers before deleting, so a still-used older digest survives
regardless of the count, including references from another stack. Stopped
containers protect their host images only; their history does not keep a
registry manifest. An unreadable initial live-state snapshot stops cleanup. A
failed live-state recheck is reported for that tag, and later tags retry with a
fresh snapshot before any deletion. A failed host image inventory is reported
once at repository level, even when there are no superseded tags, while registry
cleanup continues using retained digests and verified active references. An
unreadable superseded tag blocks its own manifest deletion;
if that tag is active or is a retained alias, deletions that depend on its
unknown digest are blocked too. Unrelated repositories, platform data images
and tags outside Shuttle's timestamped release format are preserved. A digest
shared with a retained or non-release tag is never deleted; registry deletion
is by digest and cannot remove just one alias. A refusal for one tag is reported
without stopping independent cleanup steps or other repositories. HTTP 405
skips later registry deletions in that repository. The output includes a
per-repository summary of host image and registry manifest removals, skips,
failures and unattempted steps.

The existing platform registry must have `REGISTRY_STORAGE_DELETE_ENABLED=true`.
A refusal produces an explicit warning; Shuttle does not reconfigure the registry.
Deleting manifests makes blobs eligible for collection, but does not reclaim those
bytes. The platform must trigger its registry's offline `garbage-collect` in a
maintenance window with writes stopped, using the registry's own image, config
and volume. Follow that registry version's rules for OCI indexes and manifest
lists; do not enable untagged-manifest deletion without preserving their child
manifests. This operation is platform-owned because Shuttle does not own this
registry's lifecycle or storage. Shuttle's existing `registry-gc`, `cache-prune`
and `retention.registry_cache` budget apply to its managed registry and volume;
they must not be redirected at an existing platform registry. This mode exports
no separate registry build cache, so that budget is not part of its configuration.
