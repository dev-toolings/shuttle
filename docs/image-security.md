# Stable versions and optional vulnerability diagnostics

PostgreSQL runs natively under systemd. New configurations use the latest
supported stable PostgreSQL major. Existing clusters keep their declared major
until an explicit, tested migration.

Setup and deploy resolve official Docker Hub infrastructure tags over HTTPS.
Redis and RabbitMQ track their retained major using `<major>-alpine` tags. Caddy
and the loopback registry track their configured major tags. A fresh host uses
Redis 8, RabbitMQ 4, Caddy 2 and registry 3. The CLI records each resolved
reference as `<repository>:<tag>@sha256:<digest>` in the signed stack. That
identity is used by rollback, recovery and image cleanup. Major changes to a
stateful service require an explicit, tested migration.

Docker Engine comes from its signed official package repository. Infrastructure
resolution uses no Docker CLI and does not require Buildx. If Docker Hub cannot
be reached, a retained host keeps its running infrastructure digest and reports
that fallback. A fresh host fails with the resolution error.

`setup`, `setup --adopt` and `deploy` do not require Trivy or CVE reports. Scanner
availability and vulnerability findings do not block these commands. An
operator can request a separate diagnostic:

```sh
shuttle doctor --config config.json --scan-images
```

Only this optional flag requires Trivy. It uses the existing signed audit to select
retained infrastructure digests from the VPS without changing it. A retained
application stack is evidence of the deployed selection, not a check of each
running task. If the audit fails or an identity is missing, that image uses the
local selection and the output says `local-selection`. Each report includes
`ShuttleScan` with its reference, scanned repository digest, scope and VPS
provenance. Reports and scanner/database metadata are saved under
`.shuttle/security/`; a report without a repository digest is not accepted. A failed scan, database older than 24 hours,
mismatched image identity, or HIGH/CRITICAL finding returns a diagnostic error.
That result does not authorize or refuse a later installation or deployment.

The diagnostic covers infrastructure images, not all custom application
packages or the host operating system. The ordinary doctor checks host posture
and pending security updates independently.
