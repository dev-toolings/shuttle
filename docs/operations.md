# Shuttle operations

## Scope of this implementation

The durable coordinator records signed host phases and writer closure for
long-running operations. `operations status` and `operations recover` load the
selected `--config`, connect through the configured pinned SSH host key, and
send typed Ed25519-signed requests to the VPS helper. Recovery collects fresh
evidence and applies only the actions derived from that evidence. Deploy
reserves its operation before building, records reclaim and secret phases, and
opens the stack promotion phase only after deterministic helper checks pass.

The Go tests use temporary journal roots and mocked or local
process seams. They prove locking, identity, freshness, fsync ordering, plan
confirmation, and JSON protocol behavior. They do not prove full data-content
persistence, external availability, real SSH reachability, or a live VPS
recovery. Those require the separate integration lot and the parent-owned live
recipe.

## Coordinated maintenance and recovery

State changing host work uses a durable journal under
`/var/lib/shuttle/operations`. Each record has an operation ID, kind, target,
owner key fingerprint, host boot ID, timestamps, phases, bounded results and
the recovery actions still required. Journal writes use a temporary file,
`fsync`, an atomic rename and a directory sync. The cross process journal lock
is the existing `/run/shuttle-root.lock`.

Backup, restore, registry garbage collection, cache pruning, helper update,
reboot and destroy are VPS global operations: each one excludes every other
operation. Deploy, rollback and run are application scoped: they exclude a
global operation and another mutation of the same application, so two
applications on one host deploy at the same time. A refused operation names
the active ID, kind, target and age. The client waits up to ten minutes for a
live conflicting operation to finish, and stops at once on one that requires
recovery. A missing coordination capability fails closed, so an older helper
cannot mutate state outside the journal.

An application phase holds `/run/shuttle-root.app-<app>.lock` across its
Docker work and takes `/run/shuttle-root.lock` only for its journal writes.
What applications share is serialised on `/run/shuttle-shared.lock`: the edge
fragment write and Caddy reload, and the registry and image store sweeps. The
registry garbage collector runs only when its operation is alone on the host,
because it deletes blobs another application may be pushing; otherwise it is
deferred to the next promotion that runs alone, and the deferral is logged.
Recovery is refused while another operation is live. A global operation keeps
`/run/shuttle-root.lock` across its whole callback.

The signed operation ID and the operator key fingerprint are checked together
with the action and application. An ID copied into another signed request has
no authority. Secrets and arbitrary command payloads are never written to the
journal.

### Deploy refused before stack promotion

A deploy that fails before the helper can mutate a service or stack ends in
`failed` without `recovery_required`, so another operation for the application
can proceed. The journal must contain a completed writer initialization and
may contain the completed `stack-reclaim` phase. Reclaim can remove superseded
images and set Swarm task history, but makes no service or stack mutation. A
deterministic stack pre-flight refusal also leaves a bounded helper reason in
the signed refusal result. A client-side build failure uses the fixed result
`client failed before promotion`; local build output is not copied into the
journal.

The coordinator checks its own phase journal before accepting this outcome.
Published secret phases, an open or failed reclaim, any stack promotion phase,
an attempted promotion without the helper refusal marker, or failed writer
cleanup keep the operation on the normal abort and recovery path. This also
lets recovery release an older aborted deploy when its journal proves that no
helper mutation phase opened. Recovery still requires the closed-writer proof,
reads the Docker version, and computes the normal phase and resource proofs, but
does not inspect or change the registry, PostgreSQL, application services or
retained manifests for that no-mutation record. A deploy with a `stack-apply`
phase keeps the regular host observation and recovery behavior.

Inspect records through the pinned VPS helper with:

```sh
shuttle operations status --config ./config.json
shuttle operations status --config ./config.json --json
```

An interrupted process, expired lease or changed boot ID remains
`recovery_required`, even when `/run/shuttle-root.lock` is free. Review a
read-only plan first:

```sh
shuttle operations recover OPERATION_ID --config ./config.json --dry-run
shuttle operations recover OPERATION_ID --config ./config.json --dry-run --json
```

The plan observes Docker, the registry, native PostgreSQL and retained release
files when run as root on the VPS. Applying re-observes under the recovery lock
and refuses if the plan digest or semantic evidence changed since dry-run:

```sh
shuttle operations recover OPERATION_ID --config ./config.json --yes \
  --plan-digest sha256:...
```

The command never deletes a lock or marker blindly. A failed observation keeps
the record recoverable and nonzero. Repeating a successful recovery is a
no-op.

A deploy journals the full digest of the `current.yml` it is about to write
(`current_manifest_sha256`) before writing the file. When that deploy is
interrupted afterwards, recovery accepts a `current.yml` whose digest is
exactly the one this operation journaled, selects it, and compares the live
tasks with its digests: a match needs no repair, a mismatch reapplies that
same file and proves convergence. A `current.yml` the operation did not
journal, or whose bytes hash to anything else, is still an unknown artifact
and recovery refuses it. Records written before this field existed are read
and recovered as before.

For `deploy` recovery, Redis and RabbitMQ are checked against the running
Swarm service before a reapply is planned. When local image metadata proves
that the live official image with a valid digest is the same major and no older
than the retained image, recovery keeps the live reference and uses its digest
for convergence. Versions come from each image's `Config.Env`; dry-run never
pulls from a registry. Major changes, unofficial or missing-digest references, and
unreadable local image versions block reapply for manual recovery. The
substitution changes the materialized recovery copy. When the selected retained
manifest is the on-disk `current.yml`, recovery also records the exact rewritten
file digest in `recovery_current_manifest_sha256` before atomically replacing
only the kept image value bytes in `current.yml`, then syncs its directory.
`previous.yml` is not changed. The deploy's `current_manifest_sha256` remains
the proof for the artifact written by the failed deploy. Recovery accepts the
rewritten current slot only when its full digest matches either that original
proof or the same record's recovery proof. Another digest, including a
one-byte difference, remains unknown and refused. A baseline manifest loaded
from its archive instead of the on-disk current slot is not copied into that
slot.

The action journals its digest before rename and replays the same rewrite after
a crash in that interval. Once the rename completes, a new observation selects
the rewritten current manifest and plans no rewrite. The executor repeats the
infrastructure decision before writing. A concurrent `docker service update`
between the last inspect and the write remains an accepted race window. The
rewritten current manifest protects a later rollback only after the next deploy
rotates it into `previous.yml`, because rollback applies `previous.yml`.
Rollback recovery itself keeps its existing behavior.

The new journal field is decoded strictly. Downgrading the helper to a version
that predates this field is unsupported. An older CLI also cannot decode the
new helper's `operations status` record; use a CLI at least this release before
running `operations status` or recovery against an updated helper. Existing
records without the field remain readable.

### Cleanup after a promotion

The registry and image store sweep that follows a converged promotion is
housekeeping. If it fails (a manifest DELETE reset by the registry, an image
the daemon still holds, the shared lock held too long), the phase completes
with a `warning` in the journal, the CLI prints it as `shuttle-root warning:`,
and the operation finishes. The leftovers are deleted by the next sweep, which
recomputes its plan from the retained stacks. The one sweep failure that still
ends `recovery_required` is a loopback registry the collector stopped and
could not prove running again. The image store sweep that runs before a deploy
(`stack-reclaim`) follows the same rule: its failure is a warning, not a
blocked application. This behavior lives in the helper: run
`shuttle helper update` on each VPS, outside any active operation, to get it.

The pre-deploy reclaim also makes a bounded host-wide pass because the disk
guard measures the whole root filesystem. It removes a stopped Swarm task
container only when a newer running task of the same service and replicated
slot exists on this node. For a global service, that newer task must be on the
same node. If the slot or task creation time cannot be established, the
container is kept. Removal also requires that no retained release or service
spec needs its image and no live container uses it. Swarm task records remain
available to `docker service ps`.

It then removes genuinely dangling images and superseded references older than
24 hours, grouped by image ID. Tagged and digest-only images are eligible only
when every referenced repository belongs to a current Swarm service. Previous
service specs protect their exact images for rollback but do not make an old
repository eligible. An image is kept if any container in any state holds it,
any retained `current.yml` or `previous.yml` references it, a current or
previous Swarm service spec references its digest or tag, or any row belongs to
the loopback registry. Repositories no current service runs are outside this
pass and remain for the explicit-consent disk cleanup flow.
Images created in the last 24 hours are kept so a host-side build or a pull
racing a deployment is not swept. Every removal uses `docker container rm` or
`docker image rm` without `--force`; the sweep never prunes volumes, networks,
build cache, or the Docker system. Each removed reference and each batch of
removed containers is printed to the deploy operator. A failed or uncertain
listing defers the sweep as a warning. The helper must be updated on each host
with `shuttle helper update` before this host pass is available.

The existing release and infrastructure sweeps retain their own scopes. The
loopback registry images remain exclusively under the release sweep, which
keeps every image referenced by the applications' retained stacks for rollback.
Those sweeps re-read their keep sets before removal and run under the shared
resource lock, so a concurrent promotion or rollback cannot lose its release.

## First setup

This workflow targets an isolated Ubuntu 24.04 or Debian 13 host. Keep provider
console access working before changing SSH. Point the application's A/AAAA
records at the actual host and allow the selected SSH port plus public TCP
80/443. The workstation needs Docker/BuildKit for deploy and an SSH private key
available through its agent or SSH configuration. A public-key file alone
cannot authenticate. Capacity must cover the configured service limits during
a start-first promotion, the host services and at least 20% free disk space.

On Linux of the target architecture, setup can use its running binary as the
helper. Otherwise obtain the Linux binary for the target architecture from the
same verified release as the CLI, then pass its absolute path with
`--helper-binary` to both the dry run and confirmed setup. Do not assume a local
`dist` directory exists. `doctor` runs only after configuration, independent
host attestation and helper installation have completed.

1. Reset the VPS and install the root public key.
2. Obtain the ED25519 fingerprint from the provider console.
3. Run `shuttle setup ... --dry-run`.
4. Run the same command with `--yes` and a Linux helper binary when needed.
5. Run `shuttle doctor --strict`.

For fresh setup, supply both `--operator-user ops` and
`--operator-public-key ~/.ssh/ops_ed25519.pub` to the dry run and confirmed
setup, or declare them under `setup` in the configuration. They are required.
The operator receives its own SSH key and unrestricted passwordless sudo.
Shuttle verifies SSH and sudo before closing root SSH and again afterwards;
a failed post-hardening proof triggers rollback. The private key must be
available through `ssh-agent` or local SSH configuration and must be distinct
from deploy's key. See [Setup access accounts](configuration.md#setup-access-accounts).

After setup succeeds, root SSH is intentionally closed. Re-running fresh setup
as `root` therefore fails its first SSH preflight. When this workstation has
the trusted identity for that VPS, Shuttle says that setup already ran and
prints the `shuttle setup --adopt --target ops@HOST` command with the configured
operator, host, fingerprint and required key options. Review it with
`--dry-run` before applying it with `--yes`.

No Linux password is generated. Use the administrator command printed by setup
(`ssh -p PORT ops@HOST`), followed by `sudo -i`. A `passwd` prompt from deploy
is not evidence that Shuttle generated a password; deploy cannot reset a
forgotten password or grant itself general sudo access.

Adoption retains an existing non-root administrator by default. When arriving
as root, or using `--lock-out-first-contact-user`, provide the same operator
options to create and verify a replacement. Refusal happens before remote
mutation if no administrator would survive. Do not rerun fresh setup as a
recovery procedure on a production host that only permits deploy: use a
remaining administrator or the provider's root console to restore access.

On a host other people log in to, name their accounts with `--retain-user`
(repeatable) or `setup.retained_users`. They stay in `AllowUsers` with their
existing keys, groups and sudo rules; every account not named loses SSH when
the baseline commits. A retained account with no public key is refused before
anything changes. See
[Accounts that must survive setup](configuration.md#accounts-that-must-survive-setup).

### Deploying without setup

A host nobody may change is deployed with `deploy.strategy: compose`: an
existing account, its docker access, and nothing installed. Before the first
deploy:

1. Put the host's ED25519 fingerprint in `server.host_key` and the account in
   `server.user`; `shuttle init --strategy compose --user <account>
   --host-key SHA256:…` writes that shape.
2. Check that the account can run `docker info` and `docker compose version`
   (v2.20 or later), and can read `secrets.host.env_file`.
3. Make sure nothing else on the host publishes the ports the compose file
   publishes, in particular 80 for the origin proof. A project that already
   runs by hand on the same host is stopped by you, not by Shuttle.
4. `shuttle deploy --dry-run`: it connects read-only, prints the rendered
   project, the image tags, the release directory, the remote commands and
   what already runs under the project name.

Then `shuttle deploy`. The images built here are removed when the command
ends; `shuttle rollback --yes` re-applies the previous release; `shuttle
destroy --yes` takes the project down and removes the releases, keeping the
named volumes unless `--volumes` is given. Destroy leaves the empty release
root available for lock coordination. See
[Deploy strategies](configuration.md#deploy-strategies).

Compose deploy, rollback and destroy reserve a per-project lock before changing
remote state. A second operation refuses and reports the holder, attempt,
command and age. An interrupted operation or a lost SSH result can leave the
lock in place; it is never cleared by age. Before manual recovery, check on the
host that no `docker compose` or build process for the project is running and
that uploads and the previous operation have stopped. Run `shuttle deploy --break-lock` (or the same
flag on `rollback` or `destroy`), inspect the displayed holder and type its
attempt id to confirm removal. The command only clears the lock; run the desired
operation separately afterwards. An interrupted lock preparation can leave a
`.lock-<attempt>` temporary file under the release root; it does not block
a new operation and can be removed after checking that its operation stopped.
An older directory-form `.lock` requires manual inspection and removal after
the same checks.


### Adopting a host Shuttle never installed

`--adopt` converges a host a previous Shuttle generation set up, and refuses
one it cannot recognise: no `/opt/shuttle/<app>/state.json`, no adoption. A
host in service that Shuttle never touched: a Compose stack somebody deploys
by hand, with its own accounts and its own Docker configuration. It is a
different decision, so it is asked for by name:

```sh
shuttle setup --adopt --unmanaged --cutover-edge \
  --target alice@203.0.113.3 --expected-host-key 'SHA256:...' \
  --public-key ~/.ssh/demo_deploy_ed25519.pub \
  --operator-user alice --operator-public-key ~/.ssh/id_ed25519.pub \
  --retain-user bob --helper-binary ./dist/shuttle-linux-x64 --dry-run
```

Read the plan before `--yes`. It is written from what the survey found on the
host, not from the flags, and on such a host it says:

- that the host was never set up by Shuttle and `--unmanaged` claims it;
  once the first stage has run the host carries `/etc/shuttle/setup-state`,
  and later runs resume without the flag;
- whether Docker and Swarm are active. If so, adoption skips 20-docker and
  leaves Docker configuration alone. It refuses if live-restore is enabled,
  the Docker gateway or its MTU cannot support the host network, or the
  `caddy_network` overlay is missing. If Shuttle already claimed the host and
  20-docker has no checkpoint, adoption instead plans creation of that missing
  overlay to resume an interrupted setup. The separate 21-registry-nonroot step
  converges the loopback registry, including creating it when absent;
- when 20-docker is needed to initialize Swarm, whether dockerd runs with
  `live-restore`. Swarm refuses it, so that stage turns it off in
  `/etc/docker/daemon.json`, keeps the other keys, and reloads dockerd. No
  container restarts during the run. A later dockerd restart or reboot restarts
  containers per their restart policies;
- which ports containers publish today that 40-runtime will close. The
  firewall keeps SSH and `access.allowed_public_tcp_ports` only; declare the
  others there if the host still needs them;
- which container holds 80/443 and what `--cutover-edge` does to it: it is
  stopped, set to `restart: no` so a later dockerd restart cannot hand it the
  ports back, and started again with its policy restored if the edge fails.
  A foreign Swarm service publishing 80 or 443 in ingress or host mode is
  named and refused before host changes: remove or scale it, then re-run setup.
  Until the first `shuttle deploy`, the edge serves no site on those ports,
  so run the deploy right after;
- whether PostgreSQL is active. If it is, adoption skips 30-postgres and does
  not edit `postgresql.conf` or `pg_hba.conf`. The survey must find the Docker
  gateway and subnet and a `listen_addresses` entry for the gateway or `*`.
  It does not prove PostgreSQL access from containers. The plan shows an
  example `host all all <Docker gateway subnet> scram-sha-256` rule; the
  operator must check the effective rule order and reload PostgreSQL if needed.
  The first deploy only proves this access when the application healthcheck
  actually checks PostgreSQL; a deploy with a database-blind healthcheck can
  succeed while database access is broken. Shuttle separately installs its
  backup script, service and timer, and its systemd boot-order drop-in.
  Existing files at those paths are replaced only if they match a known Shuttle
  file. The plan names the current and requested per-app backup retention
  values. A valid existing retention file is replaced atomically with the
  requested value; malformed or foreign files are refused. The drop-in takes
  effect at the next PostgreSQL or host restart; adoption does not restart
  PostgreSQL for it. If PostgreSQL is not active, 30-postgres installs it
  whether or not the application uses it.

For an existing Shuttle edge, adoption also compares the running container spec
with this release and announces any re-convergence in the dry-run plan. Applying
it updates the shared Caddy service stop-first, so ports 80/443 can be down for a
few seconds. The `/data` certificate volume and `/config` volume sources must
match the declared configuration. If the certificate volume has a nondefault
name, set `caddy.data_volume` to that name; adoption refuses a mismatch before
changing the host. Before any host write, adoption probes the effective HTTPS
domains against loopback. If none answers, it refuses without applying host
stages or persisting trusted identity. The domains that answer this early probe
remain the coverage baseline for the whole adoption. After host stages and
again immediately before replacement, every domain in that set must still
answer; otherwise adoption refuses before replacing the edge. After replacement,
setup verifies HTTP on port 80, HTTPS on port 443 for every domain in the early
set, the task's effective user, read-only root filesystem, capabilities and
image. Docker's stack deploy path
does not carry `security_opt` into the Swarm service's `NoNewPrivileges` field,
so adoption does not detect or claim that property. Domain probes come from
Caddy's adapted effective configuration, including expanded imports. A drifting
edge is refused before mutation if the configuration has no verifiable HTTPS
domain. If `docker stack deploy` returns an error, setup inspects the service
spec: it reports the error without rollback when the spec is unchanged, and
enters recovery when the spec changed or could not be inspected. Any failed
post-update check also enters rollback. Setup reports that rollback recovered
the edge only after the restored task passes HTTP 80 and HTTPS 443 for every
domain in the early set, using `curl --resolve`; otherwise it reports an
explicit recovery failure. Each traffic probe has a bounded timeout.

### Swarm no-new-privileges

`docker stack deploy` ignores `security_opt`. Shuttle no longer treats its
presence in signed YAML as proof of protection. New Docker installations write
`{"no-new-privileges":true}` to `/etc/docker/daemon.json` before installing the
package, provided that file does not already exist. Existing installations and
operator configuration are preserved; setup does not restart Docker for this
setting. No service API update is appended to deploy: that would cause a second
rollout after every stack deployment, changing promotion and rollback behavior.
The signed stack remains the only application deployment input to the helper.

Docker documents the daemon flag as "Set no-new-privileges by default for new
containers": [dockerd reference](https://docs.docker.com/reference/cli/dockerd/).
The flag first appears in [Docker 17.06.0-ce config_unix.go, line 49](https://github.com/moby/moby/blob/v17.06.0-ce/cmd/dockerd/config_unix.go#L49)
(absent in 17.05). This is the mechanism's minimum version, not a supported
Shuttle installation target; setup resolves the current stable package.
Verified against official Docker 29.9.3 source on 05-11-2026:

- [Swarm executor adapter.go:328](https://github.com/moby/moby/blob/docker-v29.9.3/daemon/cluster/executor/container/adapter.go#L328)
  calls `CreateManagedContainer`; [create.go:44](https://github.com/moby/moby/blob/docker-v29.9.3/daemon/create.go#L44)
  uses the same container creation path as ordinary containers.
- [container.go:207](https://github.com/moby/moby/blob/docker-v29.9.3/daemon/container.go#L207)
  parses the security options; [daemon_unix.go:198](https://github.com/moby/moby/blob/docker-v29.9.3/daemon/daemon_unix.go#L198)
  initializes `NoNewPrivileges` from daemon configuration, and
  [oci_linux.go:1050](https://github.com/moby/moby/blob/docker-v29.9.3/daemon/oci_linux.go#L1050)
  applies it to the runtime specification.
- [info.go:225](https://github.com/moby/moby/blob/docker-v29.9.3/daemon/info.go#L225)
  exposes the effective default as `name=no-new-privileges` in `SecurityOptions`.
  `doctor --strict` checks this live value, never the YAML or daemon.json.
- [reload.go:94](https://github.com/moby/moby/blob/docker-v29.9.3/daemon/reload.go#L94)
  copies the current configuration and only updates reloadable settings;
  `NoNewPrivileges` is not among them. A daemon restart is required.

For an existing host, schedule maintenance: merge the setting into the existing
Docker configuration, validate it with `dockerd --validate --config-file
/etc/docker/daemon.json`, restart Docker explicitly, and recreate existing
application and edge tasks. Check each Swarm node. A reload alone is insufficient,
and the daemon default is not proof for containers created before the change.
Doctor reports this limited scope even when its daemon check passes.

The daemon default does not set `Spec.TaskTemplate.ContainerSpec.Privileges`:
`docker service inspect` can still show `NoNewPrivileges:false`. The runtime
acceptance check is `NoNewPrivs: 1` in `/proc/<task-pid>/status` on the task's
node, after resolving the running container's `.State.Pid`. Verify app tasks
and `shuttle-edge_caddy`, including after redeploy and edge reconvergence.
VM runtime verification remains required; a service-spec drift
check would be wrong for this mechanism.

Compatibility: no-new-privileges prevents gaining privileges through setuid,
setgid or file capabilities on exec. Custom application images or custom Caddy
images that use `sudo`, `su`, setuid launchers or file capabilities need a
runtime check before enabling the daemon default. The stock Caddy edge runs as
10001:10001 with explicit `NET_BIND_SERVICE`; PHP production presets run as
www-data and remove the FrankenPHP file capability. These declarations avoid
relying on an exec-time privilege gain, but do not replace testing the resolved
image digest. Redis, RabbitMQ, Node and other operator images also need that
check if their entrypoints depend on such a gain. No image compatibility or
running-task protection is claimed solely from the daemon setting.

Two prerequisites the run checks and does not create. The first-contact
account needs `sudo -n` without a password; the refusal prints the sudoers
line to write. And every account that must keep SSH is named with
`--retain-user`, since the signed baseline closes the rest.

Reverting the cutover is the recipe the completion report prints:
`docker stack rm shuttle-edge`, then `docker update --restart <policy> <web>`
and `docker start <web>`. A Compose path that still declares the stopped
service will fail to recreate it on "port is already allocated": drop the
service, or its 80/443 publication, from that path once the edge holds the
ports.

Setup checkpoints under `/etc/shuttle/setup.d` make interrupted runs resumable.
If package updates require a reboot, setup schedules exactly one, waits for the
same attested host key to return, and refuses to continue if the reboot is not
observed. The root login is disabled only after that reboot and a separate
`deploy` login both succeed. Before SSH hardening, setup also proves the local
registry endpoint, Caddy validation and replicas, PostgreSQL, Fail2ban, UFW's
Docker forwarding policy, link-local name-resolution policy, and the absence of
failed units or another pending reboot.

SSH hardening is transactional. Setup signs the baseline, audit, rollback and
commit envelopes before changing sshd. The root helper retains the previous SSH
drop-in until the post-hardening audit succeeds; any failure before commit uses
the least-privilege `deploy` path to restore and reload that previous config.
Application data volumes are also initialized by the signed root helper with
the fixed non-root UID/GID of the selected Redis and RabbitMQ images; application
stacks never receive a host mount or a general-purpose ownership operation.

## Root helper lifecycle

Fresh setup installs the release's Linux binary as
`/usr/local/libexec/shuttle-root`. Check its protocol and explicit feature set
from the unprivileged operator account:

```sh
shuttle helper status
```

Helpers that advertise `signed-helper-update` can update themselves without a
general sudo rule or a root SSH login:

```sh
shuttle helper update --dry-run
shuttle helper update --yes
```

The replacement is carried by a short-lived Ed25519-signed operation that fixes
its SHA-256 digest and size. The installed helper bounds the payload, verifies
that it is a Linux ELF for the host architecture, probes its `shuttle-root`
interface, preserves the current executable as `shuttle-root.previous`, and
renames the new file atomically in the same directory.

A helper installed before capability negotiation cannot authorize a new action
it does not understand. It therefore needs one final root bootstrap, using a
binary obtained from the same verified Shuttle release used by the operator:

```sh
install -o root -g root -m 0755 ./shuttle-linux-x64 \
  /usr/local/libexec/shuttle-root
```

Use the provider's root console when SSH root has already been disabled. Run
`shuttle helper status` immediately afterwards; all later helper upgrades use
the signed command above.

## Fresh-VPS acceptance test

The repository ships one destructive acceptance path for a VPS that has just
been reset. It generates `tmp/vps-e2e/config.json`, converges the host, performs
a strict audit, deploys a minimal application twice, records the cold-cache
duration and rejects a warm-cache source-to-production deploy that overruns the
budget declared by the generated configuration.

```sh
mkdir -p tmp
install -m 600 /dev/null tmp/vps-e2e.env
${EDITOR:-vi} tmp/vps-e2e.env
sh scripts/e2e-vps.sh
```

`tmp/vps-e2e.env` is Git-ignored, must be owned by the current user with mode
`0600`, and contains the exports below. The harness loads it automatically.

```sh
export DEPLOYSHUTTLE_E2E_HOST='203.0.113.10'
export DEPLOYSHUTTLE_E2E_DOMAIN='recette.example.com'
export DEPLOYSHUTTLE_E2E_BINARY='/absolute/path/to/verified/shuttle'
# Required when the local CLI is not a compatible Linux helper:
export DEPLOYSHUTTLE_E2E_HELPER_BINARY='/absolute/path/to/verified/shuttle-linux'
export DEPLOYSHUTTLE_EXPECTED_HOST_KEY='SHA256:...from-provider-console...'
export DEPLOYSHUTTLE_PUBLIC_KEY="$HOME/.ssh/id_ed25519.pub"
```

The harness has no default server, hostname or compilation step. Supply a
verified CLI and a hostname pointing directly at this disposable host. It still
runs application builds through `shuttle deploy`: do not execute it when builds
are not authorized. A LAN-only address or tunnel is not public DNS/ACME proof.

Its evidence records source-content and supplied-artifact hashes separately,
as well as the last phase, exit code and measured durations, including failure.
A release binary's successful run does not certify modified local sources.
The warm-budget assertion is an acceptance requirement of this harness; the CLI
itself warns, rather than failing, when a healthy deployment exceeds its budget.

Never obtain `DEPLOYSHUTTLE_EXPECTED_HOST_KEY` from the same unauthenticated SSH
connection being tested. After a successful first setup, set
`DEPLOYSHUTTLE_SKIP_SETUP=1` to repeat only the audit and deployment measurement.

## Deploy

`shuttle deploy` first negotiates every privileged feature required by the
configuration with the installed helper. A missing capability fails before any
build, push or edge change. It then checks disk policy, builds and pushes
through an SSH tunnel to the VPS registry bound to `127.0.0.1:5000`, resolves
digests, applies a signed stack, waits for convergence, reads back which images
are running, then proves that DNS targets this VPS and that the public HTTPS
endpoint is healthy. A health failure rolls back. A healthy release that only
overruns its budget is kept and the command succeeds, reporting the measured
duration and which budget to raise.

Convergence means the tasks Swarm wants running are running and carry the images
the applied stack declares, rather than `running == desired`, which a `start-first`
rolling update satisfies before it has begun. The wait is therefore the only one
that covers real work (pull, container start, healthcheck), and it is where a
promotion Swarm rolled back is caught, with the service named.

## Docker diagnostics

The normal incident path does not require exposing the Docker socket to
`deploy`. `shuttle debug` sends a short-lived signed, read-only request to the
root helper and offers six bounded views:

```sh
shuttle debug ps
shuttle debug services
shuttle debug tasks web
shuttle debug inspect web
shuttle debug network
shuttle debug logs web --lines 200
```

`ps` lists this application's running containers; `services` summarizes its Swarm
services; `tasks <service>` shows the selected service's task history and
errors; `inspect <service>` returns its useful runtime and deployment state;
`network` reports the application's networks and attachments; and `logs
<service>` returns a tail of 200 lines by default. A service argument must resolve
to a service carrying the current application's Swarm namespace label.
`--lines` accepts 1 through 1000 and controls only that bounded log tail, not an
arbitrary Docker argument. Every Docker diagnostic is also limited to 15 seconds
and 1 MiB of output.

The helper derives Docker object names and selectors from the signed
application identity. It does not accept a container ID, stack name, label
selector, Docker command line or shell fragment from the caller. The `inspect`
view is built from a positive allow-list: it omits environment variables,
secrets, labels, commands, arguments and mounts instead of returning raw Docker
JSON and trying to recognize every possible credential afterwards. Control
characters are neutralized in every textual result. Application logs are opaque
application output and cannot be reliably scrubbed, so an application must
still never log credentials or secret values. The debug contract has no `exec`,
`run`, `update`, `rm`, raw inspect, or write operation; it therefore does not
turn `deploy` into a Docker administrator. Requests and refusals remain visible
in the host's `shuttle-root` journal.

The installed helper must advertise the `readonly-docker-debug` capability. A
legacy helper is refused before the diagnostic; update it with `shuttle helper
update --dry-run` followed by `shuttle helper update --yes`.

For an investigation that genuinely requires arbitrary Docker commands, use the
administrator account configured during setup or retained during adoption:

```sh
ssh ops@203.0.113.10
sudo -i
```

Or keep the operator shell and elevate only each diagnostic:

```sh
sudo docker ps
sudo docker service ps demo_web --no-trunc
sudo docker inspect demo_web
```

That account has unrestricted passwordless sudo, so these commands are
root-equivalent. Adding `deploy` to either `sudo` or `docker` is not an
alternative: the Docker group can mount the host filesystem and is effectively
root too, while it would also defeat Shuttle's least-privilege checks. Keep the
automation identity restricted and reserve the operator key for human incident
response.

## Runtime boundaries

- Caddy is the only public Swarm stack.
- PostgreSQL (18 by default, 16 and 17 kept for existing hosts) is native and uses SCRAM on loopback plus `docker_gwbridge`.
- The cluster unit is ordered after `docker.service` (checkpoint `32-postgres-boot-order`): the `docker_gwbridge` address only exists once Docker has recreated the bridge, so without that edge PostgreSQL bound loopback only after every reboot and containers got "connection refused" until a manual restart.
- Redis and optional RabbitMQ are private, persistent and authenticated.
- The `deploy` account has neither general sudo nor Docker socket access.
- All privileged operations are short Ed25519-signed requests.
- A separately keyed operator is deliberately root-equivalent; it is
  never the identity used by Shuttle deployments.

## Retention and recovery

The current and previous stacks are retained. `rollback --yes` swaps them through
the helper. It does not reverse schema migrations or restore PostgreSQL, Redis,
RabbitMQ or uploaded application data. Use backward-compatible migrations for
rolling updates and validate a separate restore procedure before a destructive
schema change. Restoring an old backup may discard newer writes and must be a
separate recovery decision. Registry and log cleanup must target Shuttle-owned objects only;
`docker system prune` is forbidden. Seven local PostgreSQL backups are retained.

When a deploy does not converge, the helper restores `current.yml` from
`previous.yml` and redeploys the previous release (the emergency rollback). It
never downgrades a running Redis or RabbitMQ with it. For each of these
services declared in `previous.yml`, the helper reads the image the service
runs now and applies the `previous.yml` image only when both are official
images resolved by digest, of the same major, and the `previous.yml` version is
strictly newer. In every other case (live image equal or newer, major change,
unofficial or missing-digest image, unreadable version) the running image is kept in
a temporary 0600 manifest in the application state directory, removed after
the attempt, and the reason is written to the `shuttle-root` journal. A major
change is therefore refused and journaled, never applied silently; `previous.yml`
and `current.yml` are not rewritten. If the running image of one of these
services cannot be established, the temporary manifest cannot be built, or
`previous.yml` itself cannot be read or parsed (it is always a copy of a
validated `current.yml`, so this means corruption), the emergency rollback is
skipped and logged, and the failing release keeps serving: use `shuttle operations recover` or redeploy once the service is
readable. When every running image already matches `previous.yml`, the rollback
is exactly the one described above.

Operations marked `backup_before` also keep verified per-database archives in
`/var/backups/shuttle-postgres/pre-run/<app>/`, separate from the seven daily
`pg_dumpall` archives. Five newest operation timestamps are retained per
application. After reviewing the data-loss consequences, restore a selected
archive with `pg_restore --dbname=<target-database> <archive>` into the intended
target as a separate operator decision; pre-run archives do not change the
application database automatically.

A declared command whose non-zero exit is observed to have finished ends in
`failed` without `recovery_required`, so another operation for the application
can proceed. If the outcome is unknown, including a watchdog exit (status 75),
a lost Docker connection or a helper crash, `shuttle operations recover` uses
the journaled service and container. A stopped or missing container can be
released after the shared safety checks pass. If it is still running, recovery
forces a service task replacement, proves that the journaled container stopped
and that the service returned to its declared replica count with healthy tasks,
then releases the operation. Recovery never restores application data. Any
restore from a pre-run archive remains an explicit operator decision.

PostgreSQL archives contain `pg_dumpall` SQL, including roles and all databases;
they can contain password hashes and must stay private. For a recovery drill,
restore into a separate empty PostgreSQL instance of the same major version,
using a temporary bootstrap superuser whose name is absent from the archive.
Verify the gzip archive before importing it, and use `psql -X -v ON_ERROR_STOP=1`
with shell `pipefail` so an SQL or decompression failure stops the procedure.
Check database contents, role ownership and grants, rather than only the import
exit code. Keep the live source untouched while verifying the recovered instance;
switching application connections is a separate operator action.

After every promotion the helper prunes the VPS registry: it deletes the
manifests of releases neither retained stack references, then garbage-collects
with `--delete-untagged`. That second half matters because each deploy rewrites
the `:buildcache` tag, and the manifest it previously pointed at would otherwise
stay on disk forever with its blobs, at 1 to 2 GB per release for a PHP image. The
manifest the tag currently points at is always preserved, so the next build stays
warm.

`retention.registry_cache` is the cap on that volume, enforced on the VPS: if it
is still exceeded once the collector has run, the build cache is dropped (the
retained release manifests are not, because `rollback` needs them) and the
collector runs again. The next build is cold once and re-exports a fresh cache.
`shuttle setup` also reports `setup.slo_seconds` as a measured budget: a
converged, hardened host always exits zero, with a warning when the run overran.

Local backups do not protect against total VPS loss; configure an independent
offsite backup before treating the service as disaster-recoverable.

A single-node start-first rollout is conditional on healthy checks, sufficient
capacity and compatibility between old and new application versions. It does
not cover VPS failure or guarantee uninterrupted service in every failure mode.
