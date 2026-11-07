---
name: shuttle-host-env
description: Keep production .env values on the VPS only (Shuttle secrets.backend: host). Use when deploying with Shuttle, editing config.json secrets, touching .env / .env.production / env_file / deploy.env_file / secrets.enc, running shuttle init or shuttle secrets, or when asked to copy production credentials onto a workstation. Slash command: /shuttle-host-env.
---

# Production secrets stay on the VPS

A production credential that exists on a workstation has already leaked: disk
image, agent, zip, CI log. Shuttle's host backend is the fix. The CLI never
sees a value. The signed plan carries a path and key names. The root helper
reads only the declared keys from a file that already lives on the server.

```text
+--------------------------+     +--------------------------+
| Workstation              |     | Git                      |
| config.json names        |     | .env.example (keys)      |
| never production values  |     | .gitignore: .env*        |
+------------+-------------+     +--------------------------+
             |
             | plan: path + key names
             v
+------------+-------------+
| VPS /opt/<app>/.env      |
| root-owned, mode 0600    |
+------------+-------------+
             |
             v
+------------+-------------+
| Container /run/secrets   |
+--------------------------+
```

## Configure

```json
"secrets": {
  "backend": "host",
  "host": {"env_file": "/opt/<app>/.env"},
  "items": {
    "JWT_SECRET_KEY": {"services": ["api"], "expose": "env"},
    "STRIPE_SECRET_KEY": {"services": ["api"], "expose": "file"}
  }
}
```

`secrets.host.env_file` is an absolute path **on the VPS**. Create it there,
never by copying a laptop file:

```sh
sudo install -m 600 -o root -g root /dev/null /opt/<app>/.env
sudo $EDITOR /opt/<app>/.env
```

Declare only the keys the application mounts. A real `.env` holds much more;
the helper ignores the rest. A declared key that is missing or empty stops the
deploy and names the key.

Infrastructure credentials Shuttle generates (`REDIS_PASSWORD`,
`RABBITMQ_PASSWORD`, `POSTGRES_PASSWORD`) stay generated on the host. They
may appear in `secrets.items` next to application keys; they are not read
from this file.

`shuttle init` already writes this backend when the preset declares an
application secret (Laravel `APP_KEY`). Add the block the first time any
other application secret appears.

## Refuse these

- A production `.env`, `.env.production`, or `.env.local` on the workstation.
- `env_file:` in a compose file for secrets: Compose reads it on the laptop
  and bakes the values into the stack.
- `deploy.env_push`: declared, accepted, and implemented by nothing.
- `secrets.backend: swarm` / `shuttle secrets set` when the values already
  exist on the server. That store is a local copy.
- Committing `.env*` (keep `.env.example`). Same names in `.dockerignore`.
- Putting values in `config.json`, CI logs, or chat.

`secrets.backend: swarm` remains valid for an app whose credentials were
born on the machine that deploys it. It is not this policy.

## Local development

Commit `.env.example` with keys and empty or dummy values. Local Mailpit,
`infra-postgres`, and throwaway JWT keys are not production. Never reuse a
VPS value "just for a test".

## Rotate

Edit the line on the VPS. The object name embeds a hash of the value, so the
next deploy publishes a new secret and Swarm rolls the services that mount
it. `shuttle secrets` under this backend refuses: the values are not here.

## Install this skill

Once per workstation, every harness (Claude, Grok, Cursor, Codex, OpenCode,
Agents), user-level so every project sees it, and project-level so teammates
do:

```sh
shuttle --install skills
shuttle skills install
```

`shuttle init` already drops it into the generated project. Re-run install
after a Shuttle upgrade to refresh the bundled text.
