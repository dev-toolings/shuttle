#!/usr/bin/env sh
# Run a vulnerability audit, retrying only when it could not reach its database.
#
# Usage: sh scripts/audit-retry.sh <command> [args...]
#
# Both audits this repository runs call a remote advisory database, and both
# report an unreachable database with the exit code they use for a real
# finding. Observed on 2026-09-04: `bun audit` spent 4m32s against the npm
# advisory endpoint and exited 1 on "ConnectionClosed: audit request failed".
# The Security Audit job went red without having said anything at all about
# this repository's dependencies.
#
# Retrying every failure would be the wrong fix twice over: it would burn the
# same minutes again on a genuine finding, and it would blur the line between
# "no vulnerability" and "no answer". So a retry happens only when the captured
# output names a transport failure, and the LAST attempt's exit code is always
# this script's own. An audit that never reached its database still fails the
# job — not knowing is not a pass, it is the one thing an audit may never
# report as one.

set -eu

ATTEMPTS="${AUDIT_RETRY_ATTEMPTS:-3}"
DELAY="${AUDIT_RETRY_DELAY:-15}"

# Every pattern here describes a connection that did not complete. None of them
# can appear in a finding: `bun audit` prints advisory ids and package names,
# govulncheck prints "Vulnerability #n: GO-...". Widening this list is how a
# real finding would start being retried, so it is kept to transport wording.
TRANSPORT='ConnectionClosed|audit request failed|connection reset|connection refused|broken pipe|i/o timeout|TLS handshake timeout|no such host|[Tt]emporary failure in name resolution|network is unreachable|unexpected EOF|server misbehaving|context deadline exceeded|502 Bad Gateway|503 Service|504 Gateway'

[ "$#" -gt 0 ] || { echo "audit-retry: a command is required" >&2; exit 2; }

log="$(mktemp)"
trap 'rm -f "$log"' EXIT INT TERM

attempt=1
while :; do
  set +e
  "$@" >"$log" 2>&1
  status=$?
  set -e
  cat "$log"
  [ "$status" -eq 0 ] && exit 0

  if [ "$attempt" -ge "$ATTEMPTS" ] || ! grep -Eq "$TRANSPORT" "$log"; then
    exit "$status"
  fi

  printf 'audit-retry: attempt %d/%d could not reach the vulnerability database; retrying in %ss\n' \
    "$attempt" "$ATTEMPTS" "$DELAY" >&2
  sleep "$DELAY"
  attempt=$((attempt + 1))
done
