#!/bin/sh
set -eu
umask 077

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
env_file=${DEPLOYSHUTTLE_E2E_ENV_FILE:-$root/tmp/vps-e2e.env}
if [ -f "$env_file" ]; then
  [ "$(stat -c '%a' "$env_file")" = 600 ] || {
    printf 'e2e-vps: environment file must have mode 600: %s\n' "$env_file" >&2
    exit 1
  }
  [ "$(stat -c '%u' "$env_file")" = "$(id -u)" ] || {
    printf 'e2e-vps: environment file must be owned by the current user: %s\n' "$env_file" >&2
    exit 1
  }
  set -a
  # This file is an explicit local operator input and remains ignored by Git.
  . "$env_file"
  set +a
fi
host=${DEPLOYSHUTTLE_E2E_HOST:-}
domain=${DEPLOYSHUTTLE_E2E_DOMAIN:-}
expected_host_key=${DEPLOYSHUTTLE_EXPECTED_HOST_KEY:-}
public_key=${DEPLOYSHUTTLE_PUBLIC_KEY:-$HOME/.ssh/id_ed25519.pub}
work=${DEPLOYSHUTTLE_E2E_WORKDIR:-$root/tmp/vps-e2e}

die() { printf 'e2e-vps: %s\n' "$*" >&2; exit 1; }
require_value() { eval "value=\${$1:-}"; [ -n "$value" ] || die "$1 is required"; }

require_value DEPLOYSHUTTLE_E2E_HOST
require_value DEPLOYSHUTTLE_E2E_DOMAIN
require_value DEPLOYSHUTTLE_E2E_BINARY
require_value DEPLOYSHUTTLE_EXPECTED_HOST_KEY
for command in jq sha256sum git; do
  command -v "$command" >/dev/null || die "$command is required"
done
case "$host" in *[!A-Za-z0-9.:-]*|-*) die 'invalid target host' ;; esac
case "$domain" in *[!A-Za-z0-9.-]*|-*) die 'invalid public domain' ;; esac
binary=$DEPLOYSHUTTLE_E2E_BINARY
[ -x "$binary" ] || die "supplied CLI is not executable: $binary"
binary=$(CDPATH='' cd -- "$(dirname "$binary")" && pwd)/$(basename "$binary")
helper=${DEPLOYSHUTTLE_E2E_HELPER_BINARY:-$binary}
[ -f "$helper" ] || die "supplied Linux helper not found: $helper"
helper=$(CDPATH='' cd -- "$(dirname "$helper")" && pwd)/$(basename "$helper")
[ -f "$public_key" ] || die "public key not found: $public_key"
public_key=$(CDPATH='' cd -- "$(dirname "$public_key")" && pwd)/$(basename "$public_key")
printf '%s\n' "$expected_host_key" | grep -Eq '^SHA256:[A-Za-z0-9+/]{43}$' || die 'DEPLOYSHUTTLE_EXPECTED_HOST_KEY must be an ED25519 SHA256 fingerprint'

mkdir -p "$work"
work=$(CDPATH='' cd -- "$work" && pwd)
log=$work/e2e.log
evidence=$work/evidence.json

# Source and artifact identities are separate: a supplied release binary is not
# proof that the working tree was compiled. The acceptance report must bind both.
source_commit=$(git -C "$root" rev-parse HEAD)
source_sha256=$(cd "$root" && git ls-files -z --cached --others --exclude-standard app/go-cli scripts/e2e-vps.sh | sort -z | xargs -0 sha256sum | sha256sum | cut -d ' ' -f 1)
binary_sha256=$(sha256sum "$binary" | cut -d ' ' -f 1)
helper_sha256=$(sha256sum "$helper" | cut -d ' ' -f 1)
phase=init
record_evidence() {
  result=$?
  trap - EXIT
  jq -n --arg status "$([ "$result" -eq 0 ] && printf passed || printf failed)" \
    --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg phase "$phase" \
    --arg host "$host" --arg domain "$domain" --arg source_commit "$source_commit" \
    --arg source_sha256 "$source_sha256" --arg binary_sha256 "$binary_sha256" \
    --arg helper_sha256 "$helper_sha256" --argjson exit_code "$result" \
    --argjson cold "${cold_milliseconds:-null}" --argjson warm "${warm_milliseconds:-null}" \
    --argjson warm_budget "${warm_budget_milliseconds:-null}" \
    '{schema:"deployshuttle-vps-e2e/v2",status:$status,created_at:$created_at,phase:$phase,host:$host,domain:$domain,source_commit:$source_commit,source_sha256:$source_sha256,binary_sha256:$binary_sha256,helper_sha256:$helper_sha256,exit_code:$exit_code,cold_deploy_milliseconds:$cold,warm_deploy_milliseconds:$warm,warm_budget_milliseconds:$warm_budget}' >"$evidence"
  exit "$result"
}
trap record_evidence EXIT
printf 'e2e-vps: using supplied CLI %s\n' "$binary"

printf 'e2e-vps: generating %s/config.json\n' "$work"
(cd "$work" && "$binary" init --preset node-api --app shuttle-smoke --domain "$domain" --host "$host" --port 22 --email "" --with-db postgres --with-redis --force)

cat >"$work/Dockerfile" <<'EOF'
FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
WORKDIR /app
COPY --chown=node:node server.mjs release.txt ./
USER node
EXPOSE 3000
CMD ["node", "server.mjs"]
EOF

cat >"$work/server.mjs" <<'EOF'
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'

const release = readFileSync(new URL('./release.txt', import.meta.url), 'utf8').trim()
createServer((request, response) => {
  if (request.url === '/' || request.url === '/health') {
    response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
    response.end(`deploy-shuttle:${release}\n`)
    return
  }
  response.writeHead(404).end('not found\n')
}).listen(3000, '0.0.0.0')
EOF

printf 'cold-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" >"$work/release.txt"

phase=setup
if [ "${DEPLOYSHUTTLE_SKIP_SETUP:-0}" != 1 ]; then
  printf 'e2e-vps: verified setup preflight\n'
  (cd "$work" && "$binary" setup --target "root@$host" --expected-host-key "$expected_host_key" --public-key "$public_key" --helper-binary "$helper" --dry-run)
  printf 'e2e-vps: converging fresh VPS\n'
  (cd "$work" && "$binary" setup --target "root@$host" --expected-host-key "$expected_host_key" --public-key "$public_key" --helper-binary "$helper" --yes)
fi

phase=doctor
printf 'e2e-vps: strict post-setup audit\n'
(cd "$work" && "$binary" doctor --strict)

# The deploy budget is a measurement the CLI reports, not a gate it fails on: a
# healthy release that overruns it exits 0 with a warning. Any non-zero exit here
# is therefore a real failure, which also removes the cold-deploy exemption that
# used to grep for an SLO error string — an exemption that never fired anyway,
# because the promotion budget returned before the total one was ever compared.
deploy_and_measure() {
  label=$1
  phase=deploy-$label
  budget_milliseconds=$2
  started_nanoseconds=$(date +%s%N)
  if (cd "$work" && "$binary" deploy) >"$log.$label" 2>&1; then
    result=0
  else
    result=$?
  fi
  cat "$log.$label"
  finished_nanoseconds=$(date +%s%N)
  deploy_milliseconds=$(((finished_nanoseconds - started_nanoseconds) / 1000000))
  [ "$result" -eq 0 ] || die "$label deploy failed after ${deploy_milliseconds}ms"
  if [ "$budget_milliseconds" -gt 0 ] && [ "$deploy_milliseconds" -gt "$budget_milliseconds" ]; then
    die "$label deploy exceeded its ${budget_milliseconds}ms budget (${deploy_milliseconds}ms)"
  fi
}

# The harness asserts the budget the generated configuration actually declares,
# so this stays correct when a preset ships a different figure.
budget_seconds=$(sed -n 's/.*"total_slo_seconds"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$work/config.json" | head -n 1)
[ -n "$budget_seconds" ] || die 'generated config.json declares no deploy.total_slo_seconds'
warm_budget_milliseconds=$((budget_seconds * 1000))

printf 'e2e-vps: cold source-to-production deploy\n'
deploy_and_measure cold 0
cold_milliseconds=$deploy_milliseconds
printf 'warm-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" >"$work/release.txt"
expected_body=$(tr -d '\n' <"$work/release.txt")
printf 'e2e-vps: warm source-to-production deploy\n'
deploy_and_measure warm "$warm_budget_milliseconds"
warm_milliseconds=$deploy_milliseconds

actual_body=$(curl -fsS --max-time 10 "https://$domain/health" | tr -d '\n')
[ "$actual_body" = "deploy-shuttle:$expected_body" ] || die "public response does not match the promoted release"
(cd "$work" && "$binary" status)

phase=completed
printf 'e2e-vps: PASS (evidence: %s)\n' "$evidence"
