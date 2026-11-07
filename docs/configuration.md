# Shuttle configuration

Shuttle reads one `config.json`. `version: 2` is mandatory and incompatible
with previous releases.

```json
{
  "version": 2,
  "app": "demo",
  "domain": "demo.example.com",
  "server": {
    "host": "203.0.113.10",
    "user": "deploy",
    "port": 22,
    "access": {"allowed_public_tcp_ports": [80, 443]}
  },
  "setup": {"slo_seconds": 600},
  "deploy": {
    "strategy": "swarm",
    "timeout": 30,
    "total_slo_seconds": 30,
    "promotion_slo_seconds": 30,
    "availability_url": "https://demo.example.com/health",
    "availability_interval_ms": 250,
    "retain": 2,
    "prune_build_cache": "capped",
    "build_cache_keep": "5GB",
    "prune_local_images": true,
    "compose_files": ["docker-compose.yml"]
  },
  "retention": {
    "registry_cache": "5GB",
    "postgres_backups": 7,
    "min_free_percent": 20
  },
  "production": {"redis": true, "rabbitmq": false},
  "services": {
    "web": {"port": 3000, "healthcheck": {"type": "http", "path": "/health"}}
  },
  "database": {
    "version": 16,
    "backup": {"mode": "local", "retention": 7},
    "roles": [{"name": "demo"}],
    "databases": [{"name": "demo", "owner": "demo"}]
  },
  "readiness": {"preset": "node-api", "healthcheck_path": "/health"},
  "caddy": {
    "image": "caddy:2",
    "conf_dir": "/opt/shuttle/caddy/conf.d",
    "routes": {"demo.example.com": "web:3000"}
  }
}
```

`caddy.image` may select another official Caddy tag. Setup resolves that tag to
an immutable digest before installing the shared edge. Leaving the field out
tracks Caddy 2 automatically.

Only one host is accepted. `retention.postgres_backups` controls how many of the
newest local PostgreSQL backup files the host keeps, from 1 to 7. It counts
files, not days. Omitting it, or setting it to 0, keeps the default of 7, which
preserves existing configurations. Because the backup timer is shared by all
apps on a host, the host keeps the largest retention value declared by any app.
The value is applied by every `shuttle setup`, so a change takes effect at the
next setup of that app, including on a host installed before this setting.
`retention.min_free_percent` remains fixed at 20. Which account connects, and
what runs on the host, depends on the strategy.

### Redis image selection

`production.redis` resolves the latest official Redis release within the major
already retained on the host. A fresh host starts on Redis 8. To keep an older
major, set `production.redis_image` to an official tag in that major. Shuttle
resolves the major tag to a digest before generating the signed stack:

```json
"production": {
  "redis": true,
  "redis_image": "redis:7-alpine"
}
```

The signed stack records `redis:<major>-alpine@sha256:<digest>`. The helper
rechecks the official repository and digest, then compares the image versions
before changing a retained data volume. A major-version change requires a
separate, tested data migration.

### Managed RabbitMQ credentials

With `production.rabbitmq: true`, Shuttle mounts the generated broker password
as the `RABBITMQ_PASSWORD` Docker Secret. A startup wrapper reads that file and
writes `default_user = shuttle` and the password into a configuration file on
the service's writable `/tmp` tmpfs, then starts RabbitMQ with that config
directory. The password is not passed through the deprecated
`RABBITMQ_DEFAULT_PASS_FILE` variable, the stack environment or the broker's
command line. The Docker Secret remains named `<app>_rabbitmq_password_v1` and
applications that mount `RABBITMQ_PASSWORD` keep receiving the same value.

## Deploy strategies

`deploy.strategy: swarm` is the product: `setup` hardens a host you own, and
every deploy is a signed stack the root helper applies as a single-node Swarm
behind the shared edge. The account is `deploy`, always, and PostgreSQL 16, 17 or 18
is managed on the host.

Every generated application service uses `deploy.restart_policy` with
`condition: any`, a 5-second delay and `max_attempts: 0`. Enabled Redis and
RabbitMQ services use the same policy. This restarts tasks after a clean host
shutdown, when SIGTERM can produce a successful exit, and keeps retrying while
host dependencies such as PostgreSQL become ready. A crash loop remains visible
in Swarm task history, `shuttle status` and monitoring. Job-mode services retain
`on-failure` so a successful job stays complete.

`deploy.strategy: compose` exists for a host nobody may change. No `setup`, no
root helper, no Swarm: Shuttle builds the images on this machine, streams them
over SSH with `docker save` and `docker load`, uploads a rendered compose
project under the account's home and runs `docker compose up` as an account
that already exists and may use docker. It was written for a shared
pre-production where the only setting the team would accept was the name of
the user allowed to deploy.

```json
{
  "app": "demo",
  "domain": "app.staging.example.com",
  "server": { "host": "203.0.113.3", "user": "bob", "port": 22,
              "host_key": "SHA256:PN6Mtv/scCozb87ZBUr24B/HMDTR6PdM+5O7KT4RTlQ" },
  "deploy": { "strategy": "compose", "compose_files": ["deploy/compose.yml"],
              "primary_service": "web", "edge_proxy": true,
              "prune_build_cache": "all", "compose": { "project": "shuttle-demo" } },
  "caddy": { "tls_mode": "off" },
  "secrets": { "backend": "host", "host": { "env_file": "/opt/demo/.env" },
               "items": { "JWT_SECRET_KEY": { "services": ["api"], "expose": "env" } } }
}
```

What it keeps: the local build pipeline, an immutable tag per image whose
identity is proven on the host by image ID before and after `up`, the per-service
hardening rendered into the file (read-only root filesystem, every capability
dropped, no-new-privileges, tmpfs on `/tmp`, capped logging, resource limits,
a healthcheck required on every service, third-party images pinned by digest),
the origin proof and the availability probe, `current` and `previous` releases
on the host for `shuttle rollback`, `status`, `logs`, `run` and `destroy` over
`docker compose`, and the measured budgets.

What it gives up, and says so: nothing privileged enforces the hardening. The
account can run anything on the daemon anyway, so there is no `start-first`
switch. `compose up` recreates a service in place and the availability probe
reports the gap without rolling back. There are no Docker Secrets or shared
edge. Only a service whose image changed is recreated: a built
service whose new image has the ID the project already runs keeps the
reference it runs in the rendered file, so Compose finds the same
configuration and leaves the container alone.

`server.host_key` is required: the host's ED25519 key fingerprint, obtained out
of band (provider console, or `ssh-keyscan` checked against it), kept in
`config.json` with the rest of the configuration. It is what replaces the first
contact of `setup`. The first deploy records it; a later `config.json` whose key
differs is refused rather than trusted. Under `swarm` the key is refused, since
`setup` records it.

`server.user` is any existing non-root account of the host. It must be able to
reach the Docker socket (typically the `docker` group), which Shuttle checks and
never grants, and it must be able to read `secrets.host.env_file`. It needs
`docker compose` v2.20 or later, for `up --wait`.

`deploy.compose.build` says where the images are built. `local` builds on this
machine with buildx and streams the archive over SSH; `host` drives the host's
own daemon through the docker CLI's SSH transport (`DOCKER_HOST=ssh://`), so the
build runs natively there and nothing travels. Shuttle still owns the
arguments, tags, labels and the dry-run, the host only lends its CPU. `auto`,
the default, is `local` when the two share an architecture and `host` when they
do not: an Apple-silicon laptop cannot build a Bun front end for an x86 host
under emulation, and an image built for the wrong architecture loads without a
word and fails at exec. A host build checks first that `~/.ssh/known_hosts`
holds the ED25519 fingerprint `server.host_key` pins, since that transport
trusts OpenSSH's file rather than Shuttle's own client. Every build targets the
host's architecture whatever the location.

`deploy.compose.project` names the Compose project, `shuttle-<app>` by default.
The name matters: `--remove-orphans` is scoped by it, so a name shared with a
project somebody runs by hand on the same host would make a deploy delete that
project's containers. The preflight refuses a name whose project runs from files
Shuttle did not write.

Secrets: `secrets.backend: host` is the only backend, and the default. The
declared keys are read from `secrets.host.env_file` **on the host, as the deploy
account**, and written into the release directory: an env file for `expose:
env`, one file per key for `expose: file`, mounted at `/run/secrets/<KEY>`. A
declared key the file does not set, or sets empty, stops the deploy with the
key named. `uid`/`gid` are refused: Compose does not apply an owner to a file
secret.

Refused under `compose`, because nothing would enforce or provide them:
`production.redis`, `production.rabbitmq`, `database`, the managed credentials
(`REDIS_PASSWORD`, `RABBITMQ_PASSWORD`, `POSTGRES_PASSWORD`), every `caddy` key
but `tls_mode` (routes, host routes, path routes, basic auth, headers, mounts,
env, secret env, data volume, TLS snippet, IP allow-list, health path, image,
trusted CIDRs), `deploy.swarm`, `setup.operator_user` and
`setup.retained_users`. `caddy.tls_mode` stays: `off` makes the origin proof
dial the VPS over plain HTTP on port 80, which the published service must
therefore publish; `acme` dials 443.

Interpolation happens on this machine. Every `${VAR}` in the compose file is
resolved from the environment after `deploy.env_file` is loaded, `${VAR:?}`
with an unset variable is an error naming it, and every literal `$` is escaped
so the host's Compose reads values as written. A rendered file never carries
`${`.

Local cleanup is the strategy's rule, not an option: the images built for a
deploy are removed from this machine when it ends, whatever the outcome.
`deploy.prune_build_cache` decides what else goes: `capped` (the default here)
keeps the builder's cache under `build_cache_keep`, `all` removes the builder
and the volume BuildKit keeps for it, so nothing the deploy created remains,
at the cost of a cold build next time.

On the host, `~/.shuttle/<app>/releases/<version>/` holds each release, with
`current` and `previous` links; older releases and the images only they
referenced are removed after every deploy, filtered by the label Shuttle puts
on the images it builds, never a bare `docker system prune`. A failed `up`,
origin proof or availability wait re-applies `current` (or takes the project
down on a first deploy) when `deploy.auto_rollback` is on.

`shuttle setup`, `helper`, `debug` and the host audit of `doctor` do not apply
to such a host and say so; `doctor` runs the checks observable from this
machine (TLS, HSTS, DNS, health) and nothing else.

## Setup access accounts

Fresh setup requires a separate administrator before closing SSH root access.
Declare the account and its local public-key file together:

```json
"setup": {
  "slo_seconds": 600,
  "operator_user": "ops",
  "operator_public_key": "/home/alice/.ssh/ops_ed25519.pub"
}
```

`setup.operator_user` and `setup.operator_public_key` form one pair: providing
either without the other is refused. Their command-line equivalents are
`shuttle setup --operator-user ops --operator-public-key
~/.ssh/ops_ed25519.pub`. The operator name must be distinct from both `root` and
`deploy`, and its key must be distinct from the key supplied by `--public-key`
for `deploy`. In `config.json`, a relative key path is resolved beside that
configuration file; a flag's relative path is resolved from the current working
directory. Both forms accept `~/`.

`setup` authorizes the public key, then opens a new SSH session as this account
before closing root, then verifies SSH and root-equivalent sudo again after
hardening. Its matching private key must therefore be available to
Shuttle through `ssh-agent` or the local SSH configuration; a public-key file
alone cannot perform that proof.

This is not a restricted troubleshooting role. The operator receives
unrestricted passwordless sudo and can therefore run `sudo docker ps`, `sudo
docker inspect ...`, open a root shell, change SSH policy, or read every secret
on the host. Membership in the `docker` group is neither needed nor safer:
control of the Docker daemon is itself effectively root access. Keep the
operator key outside automation and limit who holds it. No Linux password is
generated; use the operator SSH login followed by `sudo -i`. Existing operator
keys and console passwords are preserved. New operator accounts have locked
passwords and use SSH keys. Each operator receives a separate managed sudoers
file; legacy operator rules are preserved.

Under `shuttle setup --adopt`, Shuttle preserves the sudo-capable first-contact
account when it is distinct from root and deploy. These operator fields can
also declare a new administrator during adoption. They are required when
adopting from root or when `--lock-out-first-contact-user` removes the original
account; a replacement must be a different account. SSH and sudo are verified
for every retained administrator before and after hardening. A failed
post-hardening proof restores the previous SSH policy rather than committing.

When adopting through the declared operator itself, `--public-key` remains the
key for deploy, while `setup.operator_public_key` attests that operator's
existing authorized key. This keeps a host with separate ops and deploy keys
adoptable without copying the administrator key into automation. Without a
declared operator, the legacy adoption path still checks `--public-key` against
the first-contact account.

Omitting these fields remains valid for deployments to an already configured
host; setup alone requires the administrator. Invalid existing operator
accounts or unsafe SSH paths are refused during read-only preflight, before
remote changes. An existing managed rule for that operator must match the
expected sudo policy.

### Accounts that must survive setup

The signed SSH baseline names exactly who may log in, and by default that is
`deploy`, the operator, and under adoption the account the run arrived on.
Every other account on the host loses SSH the moment `setup` commits. On a
host that is not one person's, such as a shared pre-production or a server
colleagues still deploy to through another path, that is a lockout nobody asked
for.
Declare the accounts to keep:

```json
"setup": {
  "operator_user": "ops",
  "operator_public_key": "~/.ssh/ops_ed25519.pub",
  "retained_users": ["bob", "alice"]
}
```

`shuttle setup --retain-user bob --retain-user alice` is the command-line
form; flags and the configured list are merged. A retained account is signed
into `AllowUsers` and nothing else happens to it: Shuttle creates none, installs
no key, writes no sudo rule and leaves group memberships alone. A `docker` or
`sudo` membership it holds today is root-equivalent access, and it stays so.
That is your decision, and the plan says it rather than hiding it. To have an
account *changed* (given the managed sudo rule, with its groups reduced), declare it
as the operator instead; an account cannot be both.

Before anything is changed, a read-only preflight refuses an account that does
not exist, is a system account, has no login shell, or has no
`~/.ssh/authorized_keys` holding a key `ssh-keygen` can read. The last one is
the case worth knowing: the baseline closes password logins, so an account with
no key would be signed into `AllowUsers` and still be locked out. Each refusal
names the account and the reason.

What is proven afterwards is the directive, not the login. The post-hardening
audit checks that `sshd` enforces the signed list; nobody's private key but
the operator's is held on the machine running `setup`, so a retained login is
not opened. `root` and `deploy` cannot be retained, the operator cannot be
retained, and the whole list (`deploy`, the operator and the retained accounts)
fits the root helper's bound of 8. Under adoption, retaining the
first-contact account and `--lock-out-first-contact-user` contradict each
other and are refused together.

In both modes, root SSH and password authentication stay disabled. A known
root password does not bypass that policy. The provider console remains the
recovery path if every authorized key is lost. Setup prints both automation
and administrator SSH commands, including the configured port.

### `database.version`

The declared version is the one `setup` installs, or adopts if the host already
has it. On a host that already carries a cluster, declare that cluster's version:
Shuttle then configures it in place instead of installing a second server beside
it. Two clusters cannot both listen on 5432, and 5432 is the only port Shuttle
addresses the managed database on. A second cluster would land on 5433 and the
application would keep talking to the first one. `setup` refuses a target
cluster that is not on 5432 rather than configuring the wrong database.

Declaring `database.version` does more than pick a major: it makes the
application's database **managed**. Shuttle records the PostgreSQL roles and
databases it creates in `/var/lib/shuttle/apps/<app>/postgres.json`, and
`shuttle destroy --yes` keeps PostgreSQL databases and roles, including objects
in that ledger. It reports kept objects and database sizes when available, and
preserves their ledger and credentials for later use. To delete ledger-owned
objects, use `shuttle destroy --yes --drop-databases`. The helper prints the exact
list and checks free space while the app is still running: complete database
sizes plus 10% of the filesystem must remain available, using the same rule as
pre-run backups. A failed check refuses the operation without changing the app
or leaving a cleanup journal or a recovery-required reservation.

The helper then drains the stack before taking native `pg_dump` snapshots as the
`postgres` uid. Every dump must finish before the first database or role drop.
Archives are synced, verified with `pg_restore --list`, and renamed from a
private temporary file to mode `0600` files under
`/var/backups/shuttle-postgres/pre-destroy/<app>/<operation-id>-<generation>-<database>.dump`.
Each path is printed. A crash during the dump leaves a temporary filename, not
an apparent final archive. Recovery always takes a fresh dump under a new
generation name, preserving earlier archives and capturing writes made since
an interrupted cleanup. This also applies when a drop intent was recorded:
the command may not have started and the same database may have received writes.
Absent databases are skipped; the OID check still keeps a recreated database.
Final archives are never reused or automatically pruned. Each generation checks
free space again after drain, including recovery. The dump budget uses the measured
database sizes at an estimated 1 MiB/s plus 30 seconds per archive for startup and
verification. All archives share that budget. It must fit before the actual phase
watchdog, reserving two minutes for cleanup; final cleanup stops 30 seconds before
the watchdog. If the size cannot fit, the helper keeps the pending objects and
reports the budget refusal instead of starting a dump that would exhaust the phase.

If a dump fails after the drain, all still-pending databases and roles remain,
with their ledger and credentials. Before the journal loses its completed-drop
history, those confirmed completed objects are pruned from the ownership ledger.
Pending and explicitly kept objects remain owned, including when the dump failure
could not be recorded. A ledger write or directory sync failure preserves the
journal; recovery must make the pruning durable before discarding its proof.
A same-name database created outside Shuttle cannot inherit the removed ownership.
The rest of the application cleanup finishes, the operation closes, and destroy exits nonzero with the kept objects and the retry
command: `shuttle destroy --drop-databases --yes` using the same app config.
That retry works with only the kept ledger and no running stack.
A refused database or role drop also preserves the remaining owned objects and
credentials, completes cleanup, and closes with a nonzero known outcome so the
same normal retry works. Successfully removed objects stay removed; unrelated
applications are not blocked by the refused drop. A native exit 1 is reconciled
against a fresh OID read: absence records the drop as complete, the same OID clears its in-flight intent so later databases can still
be removed, and a changed OID or failed read preserves the original intent.
A timeout, signal or unknown command result preserves the intent and requires
recovery to check the OID. Recovery after a refused drop and a later cleanup
failure preserves the ledger and credentials. It cannot turn a failed dump
back into permission to drop data. Dump start is durable before execution; if
completion or the failure record cannot be written, recovery conservatively
keeps the objects. Roles are also kept while any database is
kept, because a login dependency need not prevent PostgreSQL from dropping a role.

`shuttle destroy --dry-run` previews the Swarm stack, owned volumes, state,
PostgreSQL objects, secrets and credential filenames without reserving an
operation or writing host state. Add `--drop-databases` to preview the opt-in
PostgreSQL deletions; `--yes` is unnecessary for a preview. Roles are marked
`size=n/a`; failed size queries are marked `size=unknown`. Recovery previews keep one executable cleanup action, with the complete database,
role and dump-target inventory in a separate confirmation-bound field. Large
inventories do not consume action slots. Recovery reports include emitted archive
paths and retained objects, and their PostgreSQL reads remain bounded. A kept ledger alone is settled cleanup. If
no cleanup journal exists, recovery releases the operation without starting
destroy or changing a still-running app.

These options require an updated helper with `destroy-safe-options`; older
helpers without it are refused before either destroy recovery planning or apply as
well. Run `shuttle helper update --dry-run`, then `shuttle helper update --yes`;
helper update is permitted for an operation awaiting recovery. Compose has no
managed PostgreSQL or signed destroy and refuses these two flags. There is no automatic ledger migration
based on names: missing ownership proof means kept, even when the name matches
the app. Existing fleet ownership must be checked from provisioning evidence;
`doctor` does not yet certify that history. Helper replacement currently checks
the candidate interface and migration proof rather than a minimum version, so
this client capability check is not a general protection against downgrading a
helper and invoking its older recovery implementation through an older client.

A managed deploy refuses to change an existing role or database derived from the
application name when that object is not recorded. There is no automatic
adoption. If Shuttle created either derived object before ownership tracking,
record only those objects in the file, using this exact format:

```json
{
  "version": 1,
  "roles": ["<role-created-by-shuttle>"],
  "databases": ["<database-created-by-shuttle>"]
}
```

Use empty arrays or omit `roles` or `databases` when there are no objects of
that kind to record. Do not add an object merely because its name matches the
application. A recorded derived role still has its password re-synchronised on
every deploy. On an adopted host whose PostgreSQL you manage yourself, that
would reset a live credential, so leave the `database` block out entirely.
`setup` still converges the cluster: with no declared version it adopts the
single supported cluster it finds under `/etc/postgresql`, installs 16 if it
finds none, and refuses to guess if it finds several, asking you to name one
with `database.version`.

`retention.registry_cache` caps the VPS registry volume and is enforced there by
the root helper after every promotion: stale release manifests are deleted, the
collector runs with `--delete-untagged` so the cache manifests each deploy
orphans are actually reclaimed, and if the volume is still over budget the build
cache is dropped and rebuilt on the next deploy. Any size from 3GB to 512GB is
accepted so the cap can follow the disk you bought; units are binary multiples,
like `deploy.build_cache_keep`.

`deploy.build_cache_mode` picks the BuildKit mode of the registry cache a Swarm
build exports: `max` (the default, also when the field is absent) exports every
intermediate stage, so a compiled dependency stage stays restorable after a
local cache eviction; `min` exports only the layers of the final image. Choose
`min` when the intermediate stage is rebuilt on every commit anyway (`COPY . .`
then a framework build): max mode then compresses and uploads that whole stage
through the tunnel on each deploy for a cache no later build can hit.

`setup.slo_seconds` is the budget `shuttle setup` measures itself against, not a
gate. A host that converges exits zero whatever the clock says, with a warning
naming the field to raise; only a real convergence failure fails the command.
Any value from 120 to 7200 seconds is accepted.

`deploy.total_slo_seconds` and `deploy.promotion_slo_seconds` are measured
budgets, not gates: a promoted, healthy, proven release that overruns them still
exits zero, with a warning naming the field to raise. The individual checks
still fail when their allotted wait expires. Under Compose, and for the first
release of a Swarm app or a release whose domain has no valid certificate yet
(missing, expired or inside Caddy's renewal window), `promotion_slo_seconds`
assigns 55 % to stack convergence, 15 % to the Caddy reload, 20 % to the
origin proof and 10 % to public availability, with a 120 s convergence floor
on a first release. These are the legacy shares. The helper picks them again
whenever it cannot prove the cheaper mode: if it cannot read the shared edge's
certificate store (the edge is not running, its `/data` mount is missing or
unreadable), it falls back to the legacy shares rather than guess.

Later Swarm releases use the capped mode, and only when every hostname of the
app (the primary domain and each `caddy.host_routes` host) has a matching,
unexpired certificate in the edge's store that is outside Caddy's renewal
window, or when the app is internal or serves plain HTTP (`caddy.tls_mode:
off`). The capped mode caps the Caddy reload, origin proof and availability at
10 s each (at most 15 %, 20 % and 10 % of the SLO) and gives convergence the
rest, up to 410 s. At SLO 90 that is 10 s, 10 s and 9 s after a 61 s
convergence window, instead of 49.5 s. With `deploy.edge_proxy` the single
public request of the origin proof keeps at least 6 s, taken from the direct
proof's share and never from convergence. At SLO 90 the origin proof is
therefore 10 s of direct proof without an edge, and 4 s of direct proof plus
6 s for the edge request with `edge_proxy`. The legacy figures at SLO 90 are
18 s, split 12 s direct and 6 s edge.

Up to an SLO of 440 s the four capped waits add up to the SLO itself. Above
440 s convergence reaches its 410 s ceiling, so convergence plus the three
shares total 440 s and stay under the SLO. `deploy.update_monitor_seconds`
(default 5, 2 to 60) sets Swarm's update monitor and a service's
`update_parallelism` (default 1, 0 for all tasks) how many tasks it replaces at
once. Convergence waits for the release to be
running, including its healthcheck, rather than for a replica count.
`shuttle init` writes the
default for the chosen `readiness.preset`: 45 for `laravel` and `symfony`,
which pay for a PHP runtime that only answers once warm, and 30 for every other
preset. Any value from 10 to 600 seconds is accepted, and the promotion budget
must not exceed the total one, because every internal wait a promotion performs
(stack convergence, shared-edge reload, origin proof, public availability)
is sized as a share of it. Passwords are never valid JSON
values; managed credentials are generated on the VPS and stored as secrets.

Under the `laravel` preset, `APP_KEY` is not an ordinary secret: it must reach
the primary service as an environment variable, because that is the only form
the framework boots with, and anything else is refused. Under every other preset
(for example, a TanStack front end published as the primary service with Laravel
as a secondary `api` service), `APP_KEY` is an application secret like any
other: you name the services that mount it and whether it travels as a file or
an environment variable.

`shuttle init` writes `secrets.backend: host` for Laravel, with
`secrets.host.env_file` at `/opt/<app>/.env` on the VPS. Create that file on
the server (mode 0600) and put `APP_KEY` there. Do not copy a workstation
`.env`. Shuttle does not generate the key.

```sh
sudo install -m 600 -o root -g root /dev/null /opt/demo/.env
sudo sh -c 'openssl rand -base64 32 | sed "s/^/APP_KEY=base64:/" >> /opt/demo/.env'
```

An existing configuration that still uses `secrets.backend: swarm` keeps the
encrypted local store: `openssl rand -base64 32 | sed 's/^/base64:/' | shuttle secrets set APP_KEY --stdin`.
Retain an existing key; generating a replacement can invalidate sessions and
prevent decryption of previously encrypted application data.

The application domain must resolve directly to the VPS before deployment.
Caddy obtains and renews certificates through standard ACME HTTP validation.
The first deployment of a hostname also waits for certificate issuance during
the origin proof. At the default 30-second promotion budget, that proof has
only 6 seconds; a valid ACME challenge can take longer. For an initial
deployment, explicitly budget for issuance, for example
`"promotion_slo_seconds": 120` (24 seconds for a direct origin proof), with
`total_slo_seconds` at least as large. This is a bounded allowance, not an ACME
completion guarantee. DNS, challenge connectivity, certificate validation and
application health must still pass; Shuttle does not automatically extend the
deadline or accept an unverified certificate. Record the chosen budget with
the result, and measure subsequent deployments separately before choosing a
smaller steady-state budget.

When a CDN or WAF fronts the origin (a proxied Cloudflare record, for example),
public DNS resolves to the edge instead of the VPS. Declare it so the promotion
proof stays truthful:

```json
"deploy": {
  "edge_proxy": true,
  "edge_ranges": ["104.16.0.0/13", "172.64.0.0/13"]
}
```

`edge_proxy` replaces the single public call by two: one dialled straight at the
VPS IP carrying the domain's SNI and `Host` header, which proves this VPS serves
the promoted release, and one through the public edge with a cache-busting query
so a stale CDN response cannot pass for the new one. `edge_ranges` is optional;
when set, every address the domain resolves to must fall inside one of the CIDRs,
so a domain that drifts elsewhere fails the proof instead of passing on an
unrelated 200. Both requests carry the `shuttle-origin-proof/2` user agent so the
healthcheck path can be exempted from bot or rate-limiting rules at the edge.

The two requests do not necessarily speak the same protocol, and which one the
pinned request speaks is decided by `caddy.tls_mode`:

- `"acme"` (the default): the edge reaches the origin over HTTPS with a
  publicly trusted certificate (Cloudflare SSL mode "Full (strict)"): Caddy keeps
  its own ACME certificate, and the pinned proof validates it.
- `"off"`: the edge terminates TLS and the origin serves plain HTTP. The pinned
  proof then speaks HTTP to the VPS, while the public proof still speaks HTTPS,
  because the edge terminates TLS publicly whatever the origin serves behind it.

### `caddy.tls_mode`

With `"off"`, the edge serves HTTP only, but `shuttle doctor` still checks HTTPS
health and HSTS after a deploy: `doctor --strict` fails on those checks by design.
Use this mode for a private network, not for a public site.

`"acme"` obtains and renews a certificate for every hostname of the application.
`"off"` renders the sites as `http://` only, which is what a CDN or a tunnel in
front of the origin requires: that edge already terminated TLS, and no inbound
path exists for an ACME challenge to arrive on, so requesting a certificate can
only fail while breaking the hop that does work.

The mode is a property of the application and applies to every hostname alike:
`caddy.host_routes` has no `tls_mode` of its own, and one value renders the
domain's site and every host route. The origin proof reads that same value to
decide what to dial, so the rendered route and the proof of it cannot disagree.

Two consequences worth knowing before choosing `"off"`:

- The shared edge still publishes port 443 for the other applications on the
  host, so a TCP connection to it is accepted and then reset rather than refused.
  A plaintext origin therefore looks, from the outside, like a broken TLS
  listener; it is not, there is simply no site bound there.
- If the origin serves the other protocol because `config.json` changed but is
  not rendered onto the host, or the rendered config has not been reloaded, the
  proof probes the other endpoint inside its existing budget and passes with a
  warning naming both, instead of rolling back a healthy release.
  That warning means `config.json` and the host disagree: the next deploy renders
  the configured value, so fix the mode rather than living with the drift.

### `caddy.trusted_cidrs`

`caddy.trusted_cidrs` restricts the sites to these client networks, which is how
an access control an operator already had in front of the origin survives the
move to the shared edge. Everything outside them is answered `403` before any
request reaches the application.

The origin proof measures where it stands before it judges a `403`, because the
allow-list usually names the edge host and not the machine the deploy runs from:

- from **inside** the declared networks, the gate should have let the proof
  through, so a `403` is a real failure and the release is rolled back;
- from **outside** them, a `403` is accepted as proof that the hostname reaches a
  site of this application that is up and enforcing the declared policy, but
  only when a public proof follows to observe the promoted release itself, which
  means only under `deploy.edge_proxy`. The deploy log says in that case what was
  proven and what was not;
- with **no** `caddy.trusted_cidrs` declared, a `403` fails the proof, since
  nothing but the application explains it.

"Inside" is measured from the address this machine dialled from, so behind NAT,
such as a home or office LAN or a CI runner in a container, it reads as "outside" even
when the origin sees an allow-listed address. That is the conservative direction:
"inside" is the only verdict the measurement can assert.

## Naming the published service

Shuttle publishes one Compose service: it gets the Caddy route, the domain and
port labels, and the managed PostgreSQL password. It is called `web` by default,
which is what the generated presets emit. An application that already has a
service name does not have to rename it:

```json
"deploy": { "primary_service": "api" },
"services": {
  "api": { "port": 8000, "healthcheck": { "type": "http", "path": "/api/v1/health" } }
}
```

The name stays yours everywhere it is visible, including your compose file and logs,
the Swarm service DNS name `<app>_<service>` the route proxies to. `shuttle logs`
defaults to this service.

## Several hostnames on one application

A domain publishes one site. A monorepo whose front end, API and back office
answer on their own hostnames is still one deployable: one stack, one edge
network and one set of secrets. `caddy.host_routes` adds further hostnames to
the same application, each proxied to a service of that stack:

```json
"domain": "domebao.com",
"deploy": { "primary_service": "frontend" },
"caddy": {
  "host_routes": [
    { "host": "api.domebao.com", "service": "api", "port": 8005, "health_path": "/api/v1/health" },
    { "host": "bo.domebao.com", "service": "api", "port": 8005,
      "path_routes": [ { "path": "/app/*", "service": "reverb", "port": 8086 } ] },
    { "host": "umami.example.com", "service": "umami", "port": 3000,
      "headers": { "X-Robots-Tag": "noindex" } }
  ]
}
```

Here `domebao.com` reaches `frontend:3011` as the domain always did, while
`api.domebao.com` and `bo.domebao.com` reach `api:8005`; on the back office,
`/app/*` goes to `reverb:8086` first and everything else falls through to the
API. Each host has its own `path_routes` and `headers`, with the same rules as
`caddy.path_routes` and `caddy.headers`; the domain's do not carry over. The TLS
mode, the trusted client networks and the trusted proxies are properties of the
application, and apply to every host alike. Up to 16 hosts, each distinct from
the domain and from one another; every service named must exist in the compose
file, which is checked before anything is built, and every one of them joins the
edge network so the route resolves.

**Each extra hostname must resolve to the VPS, exactly like the domain.** The
shared edge requests a certificate for it, and the origin proof after promotion
resolves every host: one that points elsewhere fails the deploy by name (or,
with `deploy.edge_proxy`, must fall inside `deploy.edge_ranges` like the domain).
`health_path`, when set, is then requested on that host over the scheme the
origin serves, with the same budget and the same direct-or-edge proof as the
domain's healthcheck path. The TLS mode is a property of the application, so
every hostname is proven over the same scheme.
Without it, DNS is all that is proven for that host: nothing says which path
answers 200 there, so nothing is requested.

### Basic authentication on the shared edge

`caddy.basic_auth` puts the domain behind a login prompt, which is how a
pre-production stays reachable to the team and to nobody else. The route the
root helper writes renders it as a Caddy `basic_auth` block, so the gate is a
property of the signed stack rather than of a file someone once edited on the
host. Without that signed property, a "protected" pre-production was public in
silence.

The primary domain imports that gate by default. Set
`caddy.domain_basic_auth` to `false` when the public primary domain and a
separately protected host route belong to the same application; the host route
must still set `basic_auth: true` to import the shared users.

```json
"caddy": {
  "basic_auth": {
    "users": [
      { "username": "domebao", "hash": "$2a$14$k3Z7GEBmEg8Go2bSKa6pHeI6zP6Y2kYq6E3gYsO4Q0ZK0KZ6mQ9pW" }
    ]
  },
  "domain_basic_auth": false,
  "host_routes": [
    { "host": "bo.domebao.com", "service": "api", "port": 8005, "basic_auth": true },
    { "host": "api.domebao.com", "service": "api", "port": 8005 }
  ]
}
```

Hashes are bcrypt (`caddy hash-password` produces one); a clear-text password,
anything but `$2a$`/`$2b$`/`$2y$`, or more than 8 users is refused, at the desk
and again by the root helper, and one malformed entry refuses the whole route
rather than writing a half-gated site. Usernames match `[a-z0-9_.-]{1,64}`.

A host route carries the same gate when it says `"basic_auth": true`; it cannot
declare users of its own, and asking for the gate when `caddy.basic_auth` has
no user is refused. Here `bo.domebao.com` prompts for the same login as the
domain while `api.domebao.com` stays open.

`caddy.basic_auth.public_paths` lists paths served without the gate, for the
files a browser fetches without credentials whatever the page holds: a PWA
manifest, a service worker's precache (`credentials: "omit"`). Behind the gate
those requests get a `401` with a `WWW-Authenticate` challenge, and Safari
answers each one with a new password prompt, so a gated PWA prompts in a loop.

```json
"basic_auth": {
  "users": [{ "username": "hdv", "hash": "$2a$10$..." }],
  "public_paths": ["/manifest.webmanifest", "/sw.js", "/offline", "/_next/static/*"]
}
```

Each entry is a Caddy path matcher (`/exact` or `/prefix/*`), at most 16. `/`
and `/*` are refused because they would open the whole site, and the list is
refused without users. Only public build output belongs here; the pages and
the API stay behind the gate. The list needs a root helper that reports
`caddy-basic-auth-public-paths`; an older helper is refused before the build.

A gated site answers the origin proof with `401`. That proves the edge is
serving that hostname with the gate in place, only where the gate is declared
(the domain and the host routes that import it), and only when
the response carries a `Basic` `WWW-Authenticate` challenge. An application's
own `401` on an open site still fails the proof, as it always did.

## Applications with no public route

A background worker or a private API is deployed with `expose: internal`:
Generate that configuration directly with `shuttle init --expose internal`.

```json
{ "expose": "internal", "deploy": { "primary_service": "agent-next" } }
```

No domain is required, no Caddy fragment is written, no origin proof runs and the
service is not attached to the edge network: it is reachable only from the other
services on the node. Because the route is derived from a label the stack either
carries or does not, "publishes nothing" is a property of the signed stack rather
than a promise made by the CLI. Declaring a `domain`, `caddy.routes` or
`deploy.availability_url` alongside it is refused rather than ignored. A
configuration that says two different things about where an application is
reachable is a configuration whose answer you cannot trust.

Every other hardening still applies: read-only root filesystem, dropped
capabilities, resource limits, healthchecks and digest-pinned images.

## Task limits

Every service gets `cpus: 1.0` and `memory: 768M` unless it says otherwise. That
default suits a small stateless app; a PHP worker pool and a JavaScript server
that prerenders thousands of pages do not fit the same box, and a limit below the
runtime's own heap setting is an OOM kill on a timer rather than a safety net.

```json
"services": {
  "api":    { "port": 8000, "resources": { "cpus": "1.5", "memory": "1G" } },
  "worker-high": { "resources": { "memory": "384M" } }
}
```

Values use Compose's own syntax, so they can be copied straight out of a compose
file. Setting one field leaves the other at its default. A memory limit below
Docker's own 6MiB floor is refused here rather than by the daemon halfway
through a promotion.

### Update order

Shuttle rolls every service `start-first`: the replacement task must be healthy
before the outgoing one is stopped, which is what buys zero downtime on a single
node. One kind of service cannot survive it: a task holding an **exclusive lock
on a mounted volume**. Its replacement starts while it still owns the file, fails
to take the lock, and exits; Swarm then rolls the whole stack back, and the
release fails on a service nobody was changing.

A Mercure hub on a BoltDB file is the case this exists for. Measured on a real
promotion:

```text
provision http.handlers.mercure.bolt: "": invalid transport: timeout
```

```json
"services": {
  "mercure": { "update_order": "stop-first" }
}
```

Two values only, `start-first` (the default, and what you get by saying nothing)
and `stop-first`. The same order is applied to `rollback_config`: reversing it
during a rollback would recreate the overlap at the worst possible moment.

**The published service may not opt out.** It is the one behind Caddy, and
stop-first there creates a window with nothing answering. Configuration is
refused rather than discovered mid-promotion.

## Where the secret values live

For managed Swarm deployments, the root helper inspects existing volumes before
applying a new stack. A volume must belong to the
application namespace or be a shared edge volume, and its Docker driver must be
`local` with no driver options. An adopted certificate volume used by the running
edge is also allowed. Existing application-namespaced secrets remain usable without
an owner label; a secret outside that namespace must have the Docker label
`dev.shuttle.owner` set to the application name. A conflicting owner label is
refused. The helper labels newly created Redis and RabbitMQ secrets. Retained
stacks used for rollback and recovery keep the checks in force when applied.

`secrets.items` names the credentials an application mounts; `secrets.backend`
says where their values are read from. A third backend, `hashvault`, keeps the
values in a vault on the Swarm manager and replaces `secrets.items` with a
committed `hashvault.json` manifest: see [hashvault.md](hashvault.md). The two
described here end the same way, with a Docker Secret mounted under
`/run/secrets/<KEY>`.

In Swarm, `expose: env` also lists the key in `SHUTTLE_ENV_SECRETS`; Docker
itself does not export the file into the application's environment. The Shuttle
PHP presets export those allowlisted files through their generated entrypoint
before executing the application. Keep that entrypoint when using those images.
For another image, provide an entrypoint that reads each listed file, fails if
it is missing, exports its value and then executes the application, or choose
`expose: file` and have the application read `/run/secrets/<KEY>` directly.
Shuttle does not inject an entrypoint or put secret values into the stack's
`environment` section.

The workstation preflight warns for `expose: env`, naming the secret and its
services before contacting the host. It cannot verify an arbitrary image's
runtime export behaviour, even from a preset name or a local Dockerfile, so
this warning does not refuse deployment. It also appears for working presets;
no change is needed if their generated secrets entrypoint remains active.

`swarm` remains the default when `secrets.items` is declared and no backend is
named. It reads the encrypted local store (`.shuttle/secrets.enc`, or
`secrets.file`). It suits an application deployed from the machine that owns
its credentials. `shuttle secrets set` is how values get in, and the operator
holds a copy of each one.

`host` reads them on the VPS and the workstation never holds one. `shuttle init`
writes this backend whenever the generated configuration declares an
application secret (Laravel `APP_KEY`). Agents follow the same rule through
the bundled `shuttle-host-env` skill: `shuttle --install skills` or
`shuttle skills install` copies it into every local coding harness, user-level
and project-level.

```json
"secrets": {
  "backend": "host",
  "host": {"env_file": "/opt/example/.env"},
  "items": {
    "JWT_SECRET_KEY": {"services": ["api"], "expose": "env"},
    "STRIPE_SECRET_KEY": {"services": ["api"], "expose": "file"}
  }
}
```

`secrets.host.env_file` is an absolute path **on the server**, not on your
machine. The root helper opens it, takes only the keys `secrets.items` declares,
and publishes them. A real environment file holds far more than an
application's secrets, and none of the rest is read. The CLI never sees a value:
the signed plan carries the path and the key names, and the answer carries a
truncated digest per key so the client can name the objects its stack mounts.

Use it when the credentials already exist on the server and copying them to a
workstation, so that Shuttle could send them back, would be the only reason they
ever left it.

Rotation is an edit. The object name embeds a hash of the value, so changing a
line in the file publishes a new secret and Swarm rolls the services that mount
it. Nothing else has to be told.

Requirements and refusals:

- The path must be absolute and must not traverse directories.
- The file must be a regular file, must not be a symlink, must not be
  world-writable, and must be under 1 MiB.
- A declared key the file does not set, or sets to an empty value, stops the
  deploy, naming the keys and the path to fix. It does not reach convergence.
- The installed root helper must advertise `secrets-host`. An older one refuses
  before the first build; run `shuttle helper update`.
- `shuttle secrets` still manages a local store only. Under this backend it
  declines rather than showing an empty listing, because the values are on the
  server: edit them there.

`deploy.env_push` is accepted and does nothing. No code path uploads or
preserves an environment file on the host; a `env_file` named in a compose file
is read on the workstation and materialised into the stack. Use this backend for
values that must not be.

## Maintenance operations

`deploy` has no shell, no sudo and no Docker socket on the host. Shared services
an application depends on, such as a search engine on an overlay network, are
not reachable from outside the node at all. Without a declared
operation there is no way to run a migration or a reindex after `setup`, which
is a gap rather than a posture. Declare them once:

```json
"operations": {
  "migrate": { "service": "api", "command": ["php", "bin/console", "doctrine:migrations:migrate", "--no-interaction"], "backup_before": true },
  "reindex": { "service": "api", "command": ["php", "bin/console", "app:search:reindex-listings"] }
}
```

```sh
shuttle run migrate
shuttle run reindex
```

`shuttle run` sends a **name**, never a command line. The commands ride on the
published service's labels, so what the privileged helper executes is part of
the stack that was signed and applied; the helper reads them back from the
running service rather than from any file on disk. An unprivileged caller can
choose among the operations an operator already approved, but cannot compose a
new one. That is what keeps this from being a remote shell.

`command` is an argv passed to `docker exec` as separate arguments. There is no
shell, so nothing to quote against and no way for an argument to become a second
command; a metacharacter in an argument is just a character.

`backup_before: true` opts that operation into a PostgreSQL safety dump. It
requires a managed `database` block and the Swarm root helper capability
`pre-run-backup`; deploy and `shuttle run` check that capability before handing
the operation to the helper. Each existing application database is written as
a verified custom-format archive under
`/var/backups/shuttle-postgres/pre-run/<app>/`. Five newest backup timestamps
are retained in that directory, separately from the seven daily cluster
archives. Use `shuttle run migrate --skip-backup` only when an operator has
decided to proceed without the declared safety dump.

The signed request is valid for fifteen minutes, which bounds when the operation
may start. The privileged helper also bounds every operation to ten minutes
(`rootOperationBudget`). A longer declared command is killed and must be
reconciled with `shuttle operations recover`. Long jobs belong in a service in
the stack, not in a declared operation.

## The shared edge

Caddy runs as the only public stack. Four optional keys let it adopt an existing
deployment instead of replacing it:

```json
"caddy": {
  "image": "ghcr.io/example/caddy-cloudflare@sha256:…",
  "data_volume": "existing_caddy_data",
  "mounts": [
    { "source": "/opt/caddy/maintenance", "target": "/srv" },
    { "source": "/opt/caddy/logs", "target": "/var/log/caddy", "read_only": false }
  ],
  "env": { "MAINTENANCE_MODE": "false" },
  "secret_env": { "CLOUDFLARE_API_TOKEN": "cloudflare_api_token" }
}
```

`data_volume` mounts an existing volume at `/data`, where the ACME account and
every issued certificate live. Adopting a host that already serves traffic
without it means re-issuing every hostname at once, against a certificate
authority that rate-limits during the cutover. The volume is declared
external and Shuttle never creates an empty one in its place.

`mounts` are extra host paths for files the edge serves but does not generate: a
maintenance page, a media root. They are read-only unless you say otherwise, a
path that would hand the edge the host's identity or its control plane
(`/`, `/etc`, `/root`, `/run`, `/var/lib/docker`, …) is refused, and so is a
target that would shadow what the edge already owns (`/data`, `/etc/caddy`,
`/run/secrets`, …).

`env` holds plain variables a Caddyfile reads as `{env.NAME}`. Never put a
credential there: use `secret_env`, which maps a variable name to an existing
Docker Swarm secret. The secret stays a file under `/run/secrets`, and a
generated entrypoint exports it and `exec`s Caddy, so the credential never
touches disk unencrypted and no shell stays as PID 1. This is what a DNS-01
challenge needs. Mounting the secret without exporting it is the failure worth
naming: the placeholder expands to an empty string, existing certificates keep
serving, and the problem only surfaces at renewal, weeks later. A missing secret
file stops the container instead.

The Docker build manifest may describe application services, but it is converted
to a hardened Swarm stack. Public application ports, privileged containers,
host mounts, the Docker socket and images without a digest are refused by the
root helper.

## Recovery contract

`deploy.retain` keeps application stack versions for rollback; it is not data
retention. Rollback changes the deployed images and configuration without
reversing database migrations or persistent writes. Keep schema changes
compatible with the retained release and test backup restoration separately.
Local PostgreSQL retention cannot recover a destroyed VPS; an independent
backup destination and a tested restore procedure are required for that case.

## PostgreSQL password and non-root images

The generated `POSTGRES_PASSWORD` secret is mounted for root, mode 0400. An image
that runs as another user cannot read it, and the first deploy fails with `EACCES`
on `/run/secrets/POSTGRES_PASSWORD`, without promoting the release. Declare the
user of your image so the secret is mounted for it:

```json
"secrets": { "items": { "POSTGRES_PASSWORD": { "services": ["web"], "uid": 1000 } } }
```
