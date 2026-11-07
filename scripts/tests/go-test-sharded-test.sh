#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/go-test-sharded-contract.XXXXXX")
trap 'rm -rf -- "$tmpdir"' EXIT

if output=$(XDG_CACHE_HOME="$tmpdir/cache" \
  "$repo_root/scripts/go-test-sharded.sh" -j 4 ./internal/version ./internal/config 2>&1); then
  :
else
  status=$?
  printf '%s\n' "$output" >&2
  echo "sharded test script failed with status $status" >&2
  exit 1
fi
if ! rg '^summary packages=1 tests=[1-9][0-9]* shards=[1-4] wall=[0-9]+\.[0-9]{2}s$' <<< "$output" >/dev/null; then
  printf '%s\n' "$output" >&2
  echo "sharded test script did not report the expected summary" >&2
  exit 1
fi

if output=$(XDG_CACHE_HOME="$tmpdir/cache" \
  GO_TEST_SHARDED_RUN_EXTRA='-test.run=^TestDoesNotExist$' \
  "$repo_root/scripts/go-test-sharded.sh" -j 4 ./internal/version ./internal/config 2>&1); then
  printf '%s\n' "$output" >&2
  echo "sharded test script accepted a run that skipped listed tests" >&2
  exit 1
fi
if ! rg 'shard failed for .*: ran 0 of [1-9][0-9]* listed tests' <<< "$output" >/dev/null; then
  printf '%s\n' "$output" >&2
  echo "sharded test script did not report the forced failure" >&2
  exit 1
fi

echo "sharded test contract passed"
