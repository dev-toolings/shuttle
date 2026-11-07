#!/usr/bin/env sh
# Run .github/workflows/ci.yml on this machine before pushing, through ci-local
# (ci-local), so a red CI costs a local run instead of GitHub
# Actions minutes.
#
# Usage:
#   sh scripts/ci-local.sh              # every CI job, as on a push
#   sh scripts/ci-local.sh --no-deps    # extra flags go to `ci-local run`
#   CI_LOCAL='bun ci-local/src/cli.ts' sh scripts/ci-local.sh
#
# The golang job image is not the hosted Ubuntu runner, and two differences
# failed jobs that pass on GitHub (measured 2026-10-08):
#   - no /etc/machine-id: every client-writer test failed with "open
#     /etc/machine-id: no such file or directory". The host's file is mounted
#     read-only; a host without one gets a random throwaway id.
#   - no sudo: the contracts job's `sudo apt-get install ripgrep` exited 127.
#     scripts/ci-local/sudo is mounted as a passwordless sudo.
#
# Force jobs because branch filters skip every job from a feature branch
# (measured 2026-10-23). Pin both Linux images from app/go-cli/go.mod: the
# golang:1.23 default is too old, and golang:1.27.2 reports GO-2026-6809.
# A run with zero executed jobs is a failure.
#
# The macOS job cannot run in a Linux container. It is replaced by
# `GOOS=darwin go vet ./...`, which type-checks every package and its tests for
# darwin. It does not run them: a macOS-only runtime failure is still only
# caught by GitHub.

set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

die() { printf 'ci-local: %s\n' "$*" >&2; exit 2; }

if [ -z "${CI_LOCAL:-}" ]; then
  if command -v ci-local >/dev/null 2>&1; then
    CI_LOCAL=ci-local
  elif [ -f "$HOME/ci-local/src/cli.ts" ] && command -v bun >/dev/null 2>&1; then
    CI_LOCAL="bun $HOME/ci-local/src/cli.ts"
  else
    die "ci-local not found: run 'bun install && bun link' in ci-local, or set CI_LOCAL"
  fi
fi

machine_id=/etc/machine-id
cleanup=""
if [ ! -r "$machine_id" ]; then
  machine_id="$(mktemp)"
  cleanup="$machine_id"
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > "$machine_id"
  printf '\n' >> "$machine_id"
fi
output="$(mktemp)"
status_file="$(mktemp)"
trap '[ -z "$cleanup" ] || rm -f -- "$cleanup"; rm -f -- "$output" "$status_file"' EXIT

go_version=$(awk '$1 == "toolchain" && $2 ~ /^go[0-9]+\.[0-9]+\.[0-9]+$/ { sub(/^go/, "", $2); version=$2 } $1 == "go" && $2 ~ /^[0-9]+\.[0-9]+$/ { directive=$2 } END { if (version != "") print version; else print directive }' app/go-cli/go.mod)
[ -n "$go_version" ] || die "could not read Go version from app/go-cli/go.mod"

# The output is streamed and kept: tee shows it live, the file lets the run be
# checked afterwards. The exit status of ci-local travels through a file
# because a POSIX pipeline only reports tee's; `|| rc=$?` keeps set -e from
# ending the group before the status is written.
# shellcheck disable=SC2086 # CI_LOCAL may be a command with arguments.
{
  rc=0
  $CI_LOCAL run 'ci/*' --force \
    --image "ubuntu-latest=golang:$go_version" \
    --image "macos-latest=golang:$go_version" \
    --docker-arg "--volume=$machine_id:/etc/machine-id:ro" \
    --docker-arg "--volume=$ROOT/scripts/ci-local/sudo:/usr/local/bin/sudo:ro" \
    "$@" 2>&1 || rc=$?
  echo "$rc" > "$status_file"
} | tee "$output"
status=$(cat "$status_file")
# ci-local marks an executed job with a check mark or a cross and a skipped
# one with a circle. A run where no ci/ job got a mark tested nothing.
if ! grep -Eq '^[[:space:]]*(✔|✖)[[:space:]]+ci/' "$output"; then
  printf 'ci-local: no ci/ job was executed; a pipeline that skipped every job is not a pass\n' >&2
  status=1
fi

printf '\n-> macOS job substitute: GOOS=darwin go vet ./...\n'
if (cd app/go-cli && GOOS=darwin go vet ./...); then
  printf '   darwin type-check passed\n'
else
  status=1
fi

exit "$status"
