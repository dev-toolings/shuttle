#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
script=$root/scripts/e2e-vps.sh

sh -n "$script"
rg -F 'tmp/vps-e2e.env' "$script" >/dev/null
rg -F "stat -c '%a'" "$script" >/dev/null
rg -F "stat -c '%u'" "$script" >/dev/null
rg -F 'DEPLOYSHUTTLE_EXPECTED_HOST_KEY' "$script" >/dev/null
if rg -i 'cloudflare' "$script" >/dev/null; then
  echo 'VPS E2E must not depend on Cloudflare' >&2
  exit 1
fi
for required in DEPLOYSHUTTLE_E2E_HOST DEPLOYSHUTTLE_E2E_DOMAIN DEPLOYSHUTTLE_E2E_BINARY; do
  rg -F "require_value $required" "$script" >/dev/null
done
if rg 'go build|31\.97\.197\.110' "$script" >/dev/null; then
  echo 'VPS E2E must require an explicit target and supplied binary' >&2
  exit 1
fi
rg -F 'binary_sha256' "$script" >/dev/null
rg -F 'source_sha256' "$script" >/dev/null
rg -F 'trap record_evidence EXIT' "$script" >/dev/null
# Missing target must fail before invoking the supplied executable.
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
printf '#!/bin/sh\nexit 99\n' >"$fixture/shuttle"
chmod +x "$fixture/shuttle"
if env -u DEPLOYSHUTTLE_E2E_HOST DEPLOYSHUTTLE_E2E_ENV_FILE="$fixture/missing.env" DEPLOYSHUTTLE_E2E_BINARY="$fixture/shuttle" sh "$script" >"$fixture/output" 2>&1; then
  echo 'VPS E2E accepted a missing target' >&2
  exit 1
fi
rg -F 'DEPLOYSHUTTLE_E2E_HOST is required' "$fixture/output" >/dev/null
rg -F -- '--port 22 --email ""' "$script" >/dev/null
rg -F 'setup --target "root@$host"' "$script" >/dev/null
rg -F 'doctor --strict' "$script" >/dev/null
[ "$(rg -c 'deploy_and_measure ' "$script")" -eq 2 ]

# The budget is no longer a hard-coded 30s: it now depends on the framework
# preset and is read from the generated config.json, so the harness must assert
# the budget the configuration actually declares rather than a literal.
rg -F 'total_slo_seconds' "$script" >/dev/null
if rg -F 'gt 30000' "$script" >/dev/null; then
  echo 'VPS E2E must read the deploy budget from config.json, not hard-code 30s' >&2
  exit 1
fi
rg -F 'date +%s%N' "$script" >/dev/null
rg -F '/ 1000000' "$script" >/dev/null
if rg -F 'date +%s%3N' "$script" >/dev/null; then
  echo 'VPS E2E must not rely on unsupported date precision truncation' >&2
  exit 1
fi
rg -F 'https://$domain/health' "$script" >/dev/null
if rg -F 'StrictHostKeyChecking=no' "$script" >/dev/null; then
  echo 'VPS E2E must never disable host-key verification' >&2
  exit 1
fi

echo 'VPS E2E contract passed'
