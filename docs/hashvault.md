# Hashvault secrets backend

The `hashvault` backend keeps application secret values in Hashvault (backed by
OpenBao) on the Swarm manager. The workstation never holds a value: it sends
only the committed manifest that says which service gets which secret. The
signed root helper asks the local vault to create immutable Swarm secret
objects, the stack mounts them, and once the release is actually serving them
the helper records that release in the vault.

## When to use it

| Backend     | Values live in                            | Pick it when                                                                 |
|-------------|-------------------------------------------|------------------------------------------------------------------------------|
| `swarm`     | encrypted local store on the workstation  | one operator deploys from one machine that owns the credentials             |
| `host`      | an env file on the VPS                    | the values already sit in a file on the server and that is good enough      |
| `hashvault` | Hashvault/OpenBao on the Swarm manager    | you want versioned values, an audit trail, a sealed vault at rest, and rollback that brings back the matching secret versions |

Requirements: `deploy.strategy: swarm`, a Hashvault daemon on the manager, and
a root helper that advertises `secrets-hashvault` (`shuttle helper update`).
Docker Compose, plain Docker and SSH releases are not wired natively: use
Hashvault's own `prepare`, `render` and `confirm` commands in those workflows.

## How a deploy flows

```text
 workstation                      Swarm manager
 +------------------+   signed    +--------------------+  socket  +-----------+
 | shuttle deploy   |------------>| shuttle-root       |--------->| hashvaultd|
 | hashvault.json   |  manifest   |  (root helper)     |<---------| + OpenBao |
 | (HEAD bytes)     |  digest     |                    | names,   +-----------+
 +------------------+             |                    | modes         |
          ^                       |  1 prepare         |               | creates
          | object names,         |  2 stack deploy    |               v
          | uid/gid/mode only     |  3 wait convergence|        +-------------+
          +-----------------------|  4 wait mounts     |------->| Swarm       |
                                  |  5 confirm release |        | secrets     |
                                  +--------------------+        | hv_*_v<N>   |
                                                                +-------------+
```

1. **Prepare.** The helper sends the manifest to the vault over the local unix
   socket. Hashvault resolves the latest version of each key and creates
   `hv_<app>_<target>_v<N>` Swarm secrets (an identical existing object is
   reused). The answer carries object names and file permissions, never values.
2. **Stack deploy.** The generated stack declares those objects as external and
   mounts them with the manifest's target, uid, gid and mode. Older mounts on
   the same targets are replaced; unrelated secrets are kept. Every service
   gets `io.hashvault.*` labels naming the preparation.
3. **Convergence.** The usual image and replica wait.
4. **Mount check.** Each service must have its replicas Running on the applied
   image, and every task must mount exactly the declared secret objects with
   the declared target, owner and mode. A rotation usually keeps every image,
   so without this step the old tasks would pass step 3.
5. **Confirm.** The helper records the release in the vault (a
   compare-and-swap on the previous publication). This is bookkeeping: a
   failure here never takes a healthy release down, it leaves the confirmation
   pending (see below).

Steps 4 and 5 share a 45 second budget during a promotion, counted in the SSH
session deadline. A release that needs longer keeps a pending confirmation,
which `shuttle secrets sync` finishes later.

## One-time setup on the manager

Hashvault's own documentation (`docs/operations.md` in the Hashvault
repository) is the reference for these steps. In order:

1. Install OpenBao (`/usr/local/bin/bao`) and Hashvault
   (`sh scripts/install.sh --prefix /usr/local --services`), then bootstrap
   once with `hashvaultd init` (admin key, age recipients for the unseal
   bundle). Run it on the Swarm manager: the daemon needs the local Docker
   socket.
2. Unseal from your workstation through an SSH tunnel to
   `/run/hashvault/api.sock` with `hashvault unseal` and the hardware key. The
   daemon seals itself after `idle_seal_minutes` (60 by default) without an
   authenticated request.
3. Register the Swarm target, for example `swarm-main`:
   `hashvault target put swarm-main.json` with
   `{"name":"swarm-main","kind":"swarm","env":"prod","config":{"docker":"unix:///var/run/docker.sock","stack":"<app>"}}`.
4. Create the helper's machine identity. Generate an ed25519 key with no
   passphrase, owned by root, then
   `hashvault principal create machine/shuttle-helper --key helper.pub` and
   attach a policy derived from Hashvault's
   `examples/policies/shuttle-helper.json`. That example hard-codes the app,
   the target and the `prod` environment: edit them. It allows only
   `secret:Publish` over the local socket and denies value reads, writes,
   deletes, policy and principal management, and unseal.
5. Install `/etc/shuttle/hashvault.json`, owned by root, mode 0600:

   ```json
   {
     "socket": "/run/hashvault/api.sock",
     "principal": "machine/shuttle-helper",
     "key_file": "/etc/shuttle/hashvault.key"
   }
   ```

   The key file must also be a root-owned regular file, mode 0600, not a
   symlink. Project configuration cannot choose these paths. The helper signs
   a short SSHSIG login challenge, keeps the session bearer in memory and logs
   out after each request.
6. Update the helper: `shuttle helper update`. A helper without the
   `secrets-hashvault` capability is refused before the first build.

## Project setup

Write the values into the vault first, from your workstation through the
tunnel, for example `hashvault secret put prod/acme-api/DATABASE_URL < file`
(or `hashvault import dotenv .env --env prod --app acme-api --dry-run`, then
without `--dry-run`).

Commit a `hashvault.json` manifest. It holds key names, consuming services and
file permissions, never values:

```json
{
  "version": "hv-manifest-1",
  "app": "acme-api",
  "items": {
    "DATABASE_URL": {
      "expose": "env",
      "services": ["api", "worker"],
      "uid": "1000",
      "gid": "1000",
      "mode": "0400"
    }
  }
}
```

- `app` is the vault application. It may differ from Shuttle's stack name.
- `services` are the compose service names.
- `expose: env` still mounts a file, named after the lowercase key, under
  `/run/secrets/`. Your image's entrypoint must export it, or the application
  must read the file. Shuttle does not rename it.
- `uid`/`gid` default to `0`, `mode` to `0400`. Set the owner your process
  runs as, or it will not be able to read the file.

Point the configuration at it and remove `secrets.items` (the manifest is the
single contract):

```json
"secrets": {
  "backend": "hashvault",
  "hashvault": {"target": "swarm-main", "manifest": "hashvault.json"}
}
```

Shuttle signs the manifest **as committed at `HEAD`**. A deploy refuses an
untracked manifest, or one whose working copy differs from `HEAD`, before the
build starts: commit or revert first.

## Day to day

**Deploy.** Unseal the vault if it has sealed itself, then `shuttle deploy` as
usual. Nothing else changes.

**Rotate a secret.** `hashvault secret put` the new value (it becomes a new
version), then `shuttle deploy`. The new preparation creates `_v<N+1>`, Swarm
rolls the services that mount it, and the confirmation waits until every task
mounts the new object.

**Add a secret or a consumer.** Put the value in the vault, edit
`hashvault.json`, commit, deploy.

**Roll back.** `shuttle rollback --yes` redeploys the retained previous stack, which
still names its own secret objects, so images and secret versions move back
together. The confirmation then records that earlier preparation.

**Redeploy while the vault is sealed.** Export a preparation while it is
unsealed (`hashvault prepare --target swarm-main --manifest hashvault.json
--output release-artifacts/preparation.json`, or `hashvault preparation get
<id>`), and name it in the configuration:

```json
"secrets": {
  "backend": "hashvault",
  "hashvault": {
    "target": "swarm-main",
    "manifest": "hashvault.json",
    "preparation": "release-artifacts/preparation.json"
  }
}
```

The descriptor holds no values. It must match the manifest, consumers and
permissions included, and every object it names must still exist on the
manager. No new preparation happens in this mode. A dry run without a saved
descriptor only reports the preparation it would request.

## Pending confirmations and `shuttle secrets sync`

When the deploy succeeds but the confirmation cannot complete (vault sealed in
the meantime, tasks still rolling after 45 s), the helper keeps a metadata-only
record, `hashvault-confirm.json`, beside the current stack and prints:

```text
warning: hashvault release confirmation is pending; unseal the vault, then run shuttle secrets sync
```

The release keeps serving. Unseal if needed, then:

```sh
shuttle secrets sync
```

It rechecks the current stack's convergence, waits up to 3 min 30 for the
declared mounts, and confirms. It ends in one of four ways:

| Outcome     | Meaning                                                                 | Next step                                   |
|-------------|-------------------------------------------------------------------------|---------------------------------------------|
| synchronized| the vault records the serving release                                   | nothing                                      |
| pending     | vault sealed or unreachable, or tasks not serving the mounts yet         | unseal or wait, run `secrets sync` again     |
| no release  | the current release has no Hashvault preparation (never deployed with it, or rolled back before it) | deploy with the backend first |
| failed      | the stack is unreadable or does not converge, or the enrollment is broken | fix the cause, then `shuttle operations recover <operation-id>` |

Pending and no release exit non-zero but end the operation cleanly: they
never block the next deploy, rollback or sync. A failure, or a sync
interrupted by the helper's watchdog, leaves the operation for recovery, which
only observes: a sync never changes the stack, the registry or the edge.

## Troubleshooting

| Message                                                              | Cause and fix                                                                                 |
|----------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `hashvault manifest ... is not committed`                            | `hashvault.json` is untracked: `git add` and commit it.                                        |
| `hashvault manifest ... differs from HEAD`                           | Uncommitted edit: commit it, or `git checkout -- hashvault.json`.                             |
| `secrets.backend: hashvault requires deploy.strategy: swarm`         | Native integration is Swarm only; use Hashvault's render hooks elsewhere.                      |
| `... uses hashvault.json as its service contract; remove secrets.items` | Delete `secrets.items` from the configuration.                                              |
| `hashvault enrollment must be a root-owned regular file with mode 0600` | Fix `/etc/shuttle/hashvault.json` ownership and mode (also the key file).                  |
| `preparing hashvault secrets failed: ...`                            | Vault sealed, unknown target, or the helper policy does not cover the app or a key.           |
| `the release is not serving the prepared secrets yet: ...`           | Tasks still rolling, or a task mounts another object. It names the task; run `secrets sync` later. |
| `hashvault confirmation is still pending`                            | Vault sealed or unreachable, or tasks still rolling. Unseal, wait, retry `shuttle secrets sync`. |
| `the current release carries no Hashvault preparation`               | Deploy once with `secrets.backend: hashvault`; a rollback to an older release has nothing to confirm. |
| `hashvault sync failed: ...`                                         | A real failure (stack, convergence, enrollment). Fix it, then `shuttle operations recover <operation-id>`. |

`shuttle secrets set` and `shuttle secrets list` manage the local store only.
For a Hashvault project, manage values with `hashvault secret ...`.

## Retention and limits

- Prepared Swarm objects are never garbage collected, by Shuttle or by
  Hashvault. Keep each generation for as long as a release or rollback may
  mount it, then remove old `hv_*` objects by hand. Old values stay in the
  vault until `hashvault secret destroy --version N`.
- Revoking a credential is a provider-side action: an old version cannot
  authenticate once its provider has revoked it, rollback included.
- The helper's policy cannot read values, list versions, or unseal. Unsealing
  stays a human ceremony with the hardware key.
