# Continuous monitoring

Monitoring is opt-in. A configuration without `monitoring.enabled: true` does
not install a timer and does not claim that the VPS was checked.

## Configuration

The following example enables a local cycle every minute. Timeouts and stale
deadlines are in seconds. The stale deadline must be at least the interval and
is bounded to seven days.

The default `monitoring.security.expected_ssh_users` is `deploy` plus
`setup.operator_user` when configured. An explicit list replaces that default.
This is the minimal monitoring block when the root secret file already exists:

```yaml
monitoring:
  enabled: true
  notifications:
    webhook_secret_file: /etc/shuttle/monitoring-webhook
```

```yaml
monitoring:
  enabled: true
  interval_seconds: 60
  timeout_seconds: 10
  stale_after_seconds: 300
  disk:
    data:
      path: /var/lib/shuttle
      min_free_percent: 20
      min_free_inodes_percent: 20
    images_registry:
      path: /var/lib/docker
      min_free_percent: 20
      min_free_inodes_percent: 20
    cache:
      path: /var/cache
      min_free_percent: 20
      min_free_inodes_percent: 20
    backups:
      path: /var/backups/shuttle-postgres
      min_free_percent: 20
      min_free_inodes_percent: 20
  backup:
    expected: true
    path: /var/backups/shuttle-postgres
    max_age_seconds: 86400
    cloud_enabled: false
    cloud_required: false
  tls:
    url: https://app.example.com/health
    min_days: 14
  security:
    require_ssh_key_only: true
    require_ufw: true
    require_docker_user: true
    require_fail2ban: true
  notifications:
    webhook_env: SHUTTLE_MONITOR_WEBHOOK
    retries: 3
    retry_delay_seconds: 2
    debounce_seconds: 30
```

The default local checks inspect application replicas, Docker, Caddy, the
loopback registry, native PostgreSQL, and configured Redis and RabbitMQ. An
unconfigured Redis or RabbitMQ is `not_applicable`. Compose applications are
not covered by Swarm inventory: `services.application` (and Redis/RabbitMQ
derived from that inventory) is `not_applicable` with reason `unmanaged`.
Disk checks measure both blocks and inodes for the four independent paths.
Registry storage is the mount whose destination is `/var/lib/registry`; if
that destination cannot be observed the registry-storage check is
`unavailable`, not omitted. Inventory commands run inside each check timeout.
They never run a purge.

Security checks read effective `sshd -T`, `ufw status`, the `DOCKER-USER`
iptables chain, and `fail2ban-client status`. They never add firewall rules or
ban an address. The Docker check does not replace the image security scanner.
Missing or failed CVE evidence is not converted into a healthy result.

Notification credentials are not configuration values. A configured channel
must resolve to an HTTPS URL on the VPS before installation writes or enables
the timer. The recommended option is a root-owned 0600 file with
`notifications.webhook_secret_file`; it contains only the HTTPS webhook URL.
For `notifications.webhook_env`, install checks the systemd manager environment
and the service passes that variable through with `PassEnvironment`. Neither
value is written to the report, incident state, or delivery failure log.
If install cannot resolve the channel, put the URL in the root secret file or
configure the variable in the systemd manager environment, then rerun install.

The webhook body carries every notification field (`id`, `kind`, `app`,
`check_id`, `episode_id`, `state`, `summary`) plus `content` and `text`, one
readable line, so a Discord, Slack or Mattermost incoming webhook URL works
as is.

## CLI and systemd

The monitoring commands are available through the `monitoring` alias of the
status command:

```sh
shuttle monitoring status --format text
shuttle monitoring run --format json
shuttle monitoring install --yes
shuttle monitoring remove --yes
shuttle monitoring maintenance start --duration 2h --yes
shuttle monitoring maintenance clear --yes
```

Use `--dry-run` with installation, removal, and maintenance before applying the
change. A `shuttle helper update` does not rewrite installed units: after
updating the helper, run `shuttle monitoring install --yes` again to pick up
sandbox changes (repeating it is safe). The service runs with
`ProtectSystem=strict` and can write only its state directory, the failure
log directory, `/run/shuttle-root.lock` and `/run/ufw.lock`. Installation writes one root-owned configuration and one service and
timer pair per application. The timer is enabled only after the signed
configuration has been validated. Removal disables the exact timer and removes
only that application's units and configuration. Repeating either operation is
safe.

`monitoring run` returns exit code 1 for degraded, unavailable, or stale
checks. JSON reports use schema `shuttle.monitoring/v1` and include the check
scope, check time, freshness deadline, and one of `healthy`, `degraded`,
`unavailable`, or `not_applicable`.

## Incident and recovery behavior

The root helper stores incident state below the configured `state_dir`, using a
temporary file, `fsync`, atomic rename, and directory `fsync`. A failed webhook
delivery leaves the event pending and appends a metadata-only record to
`delivery-failures.jsonl`. Retries are bounded to five attempts per cycle.
If the channel becomes unavailable after installation, the oneshot still exits
with failure and status reports `notifications.delivery` as unavailable.

Failures are debounced before an incident is emitted. A recovery is deduplicated
and cannot be delivered before its incident, including after a reboot or a
webhook outage. A declared maintenance window keeps collecting checks and
updates the history, but suppresses expected notification delivery only until
its bounded deadline. An unreadable or invalid maintenance file is unknown: it
never counts as cleared, notifications stay suppressed, and the collected
report is still persisted.

The optional `operations_state_dir` is read-only. A shared operation record with
`recovery_required: true` becomes a degraded monitoring check. Monitoring does
not acquire, clear, or otherwise control the operation state.

## Independent external probe

Local monitoring deliberately reports the external probe as
`not_applicable`. It never uses a request from the VPS as proof that a different
network can reach the VPS.

On an independent machine, schedule:

```sh
shuttle monitoring external --config /etc/shuttle/config.json --format json
```

Set `monitoring.external.url` to the public HTTPS health URL. Set either
`monitoring.external.webhook_env` or
`monitoring.external.webhook_secret_file` for the independent notification
channel. Keep `monitoring.external.state_dir` on that machine, below
`/var/lib/shuttle/monitoring-external`, so its incident and recovery history has an
independent scheduler and durable state. The URL must be HTTPS.

For an app named `demo`, a minimal monitoring block in `config.json` is:

```json
"monitoring": {
  "enabled": true,
  "external": {
    "url": "https://app.example.com/health",
    "webhook_env": "SHUTTLE_EXTERNAL_WEBHOOK"
  }
}
```

Set `SHUTTLE_EXTERNAL_WEBHOOK` in the probe service environment. Before running
the probe as the non-root account `probe`, create its default state directory:

```sh
sudo install -d -o probe -m 0700 /var/lib/shuttle/monitoring-external/demo
```

Replace `probe` and `demo` with the service account and configured app name.
The default state path includes the app name. The final directory must be owned
by the service account and private. Its parent directories must be owned by
root or the service account and not writable by group or others.

For a minimal systemd installation on the probe host, create a service that
runs the command as a non-root account and a timer with the same interval as
the local policy. The probe only needs outbound HTTPS and write access to its
own state directory. It does not need Docker, PostgreSQL, SSH credentials, or
the VPS configuration secrets.

## Backup freshness

An expected backup is degraded when no artifact is present, when the newest
artifact is older than `max_age_seconds`, or when an encrypted archive lacks a
committed receipt. The backup lifecycle sidecar records source capture,
encryption, receipt publication, and optional cloud read-back separately. A
cloud failure preserves the local encrypted archive and remains visible when
cloud export was explicitly enabled. An unconfigured cloud destination does
not alert.

The existing native PostgreSQL backup timer remains native and is not replaced
by this monitor. PostgreSQL is never run in Docker.
