# Monitoring collectors

The collectors run read-only checks against the state retained by the root
helper and the live host. A result is `healthy` only when the required evidence
was collected and matched the expected configuration. Malformed, empty,
missing, timed out or unsupported evidence is `unavailable`. An observed
configuration or health mismatch is `degraded`. A dependency that is absent
from the expected configuration is `not_applicable`.

Application expectations come from the root-owned
`/var/lib/shuttle/apps/<app>/current.yml`. The file is parsed with the existing
YAML parser and read with a bounded adapter. Every expected service must appear
in the live service roster. The collector compares desired and running
replicas, the task state, the exact retained image, and container health when a
healthcheck is declared. An explicit `replicas: 0` is the only case where
`0/0` is healthy. Redis and RabbitMQ are not applicable only when their service
is absent from this expected inventory.

PostgreSQL is always treated as a native host service. The configured major and
cluster name are matched against `pg_lsclusters --no-header`, whose columns are
`version cluster port status owner datadir logfile`. The collector then checks
the reported port with `pg_isready` and uses the `datadir` column as the
PostgreSQL filesystem target; it never starts a PostgreSQL container or changes
a cluster version.

The shared edge service is exactly `shuttle-edge_caddy` and must report restart
condition `any`, converged tasks and healthy containers. The registry must be
running and healthy, use restart policy `always`, and expose exactly
`127.0.0.1:5000`. Docker port bindings and host listener evidence are both
checked, so an extra public IPv4, IPv6 or host listener fails the check.

Security requirements activate their corresponding collectors. The collectors
reuse readiness semantics for Docker-USER, UFW, private SSH rules, effective
SSH ports and Fail2ban. Installed configuration materializes expected `ops` and
`deploy` accounts, the SSH listen address and the allowed public TCP ports from
trusted project settings and the host group. Explicit monitoring settings
override those defaults. Each required account is probed with one
comma-separated `sshd -T -C` context (`user`, and `laddr`/`lport` when known).
The collector does not invent a loopback peer (`host=localhost,addr=127.0.0.1`)
and does not append `laddr`/`lport` as extra positional arguments. Missing
client peer identity is reported as not observed. A deploy context cannot
certify a different operator context. Public SSH operator access is preserved
and no collector inserts firewall rules, removes bans or changes host services.

UFW evidence must be verbose and complete: `Status: active` plus an explicit
`Default: deny (incoming), allow (outgoing), deny (routed)` line. Active without
`Default`, or a permissive `allow (routed)` third field, is not a safe policy.
Expected public TCP ports come from the access baseline (HTTPS and SSH unless
SSH is private-interface only). Custom `allowed_tcp_ports` are preserved.

Application task health compares more than the live service spec. Each Running
task is inspected (JSON `Spec.ContainerSpec.Image`) and must carry the retained
manifest digest. A service spec that already matches a new digest while an old
task still runs is degraded. Missing image identity is unavailable, not healthy.

Disk paths are observed filesystems, not labels. `disk.data` keeps the
application data path and adds the native PostgreSQL data directory from the
matching `pg_lsclusters --no-header` row when that directory is on a separate
mount. `disk.images_registry` uses `DockerRootDir` when the images path is
the default. Registry storage is selected only by destination
`/var/lib/registry`; a preceding config bind is ignored. Failed or missing
mount inspection emits `disk.images_registry.volume` as `unavailable` instead
of dropping the target. Those inventory commands run inside `runCheck` so a
stalled `pg_lsclusters` or Docker inspect cannot outlive the check timeout.
BuildKit laptop and remote cache are outside VPS scope: `disk.cache` is
`not_applicable` with not-observed evidence, never healthy because
`/var/cache` has free space. Custom explicit disk paths and thresholds are
preserved. An unknown path is unavailable.

Managed-host monitoring is the Swarm VPS installed by setup. Compose remains
an unmanaged scope and does not gain `sudo` or root-helper operations. Parent
ROOT still owns managed-scope arbitration, recipes and unit/tmpfiles/netlink
behavior; this collector module does not claim Compose coverage.

For example, this configuration collects all four security checks because each
requirement also enables its matching collector:

```yaml
monitoring:
  enabled: true
  security:
    require_ssh_key_only: true
    require_ufw: true
    require_docker_user: true
    require_fail2ban: true
```
