#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
go_root="$repo_root/app/go-cli"

jobs=$(nproc)
if (( jobs > 16 )); then
  jobs=16
fi
packages=()
while (($#)); do
  case "$1" in
    -j)
      if (($# < 2)); then
        echo "missing value for -j" >&2
        exit 2
      fi
      jobs=$2
      shift 2
      ;;
    -*)
      echo "unknown option: $1" >&2
      exit 2
      ;;
    *)
      packages+=("$1")
      shift
      ;;
  esac
done
if [[ ! $jobs =~ ^[0-9]+$ ]] || (( jobs < 1 )); then
  echo "-j must be a positive integer" >&2
  exit 2
fi
if (( jobs > 16 )); then
  jobs=16
fi
if ((${#packages[@]} == 0)); then
  packages=(./...)
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/go-test-sharded.XXXXXX")
timing_tmp=
cleanup() {
  rm -rf -- "$tmpdir"
  if [[ -n $timing_tmp ]]; then
    rm -f -- "$timing_tmp"
  fi
}
trap cleanup EXIT

timing_file="${XDG_CACHE_HOME:-${HOME}/.cache}/deploy-shuttle/test-timings"
declare -A timing_ms=()
if [[ -f $timing_file ]]; then
  while read -r seconds test_name extra; do
    [[ -n ${seconds:-} && -n ${test_name:-} && -z ${extra:-} ]] || continue
    if [[ $seconds =~ ^([0-9]+)([.]([0-9]+))?$ ]]; then
      whole=${BASH_REMATCH[1]}
      fraction=${BASH_REMATCH[3]:-}
      fraction="${fraction}000"
      fraction=${fraction:0:3}
      weight=$((10#$whole * 1000 + 10#$fraction))
      (( weight > 0 )) || weight=1
      timing_ms["$test_name"]=$weight
    fi
  done < "$timing_file"
fi

run_extra=()
if [[ -n ${GO_TEST_SHARDED_RUN_EXTRA:-} ]]; then
  read -r -a run_extra <<< "$GO_TEST_SHARDED_RUN_EXTRA"
fi

start_ns=$(date +%s%N)
if ! go -C "$go_root" list \
  -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' \
  "${packages[@]}" > "$tmpdir/packages.list"; then
  exit 1
fi

package_count=0
test_count=0
shard_count_total=0
package_index=0
while IFS= read -r package; do
  [[ -n $package ]] || continue
  package_count=$((package_count + 1))
  package_index=$((package_index + 1))
  package_dir=$(go -C "$go_root" list -f '{{.Dir}}' "$package")
  binary="$tmpdir/package-$package_index.test"
  compile_log="$tmpdir/package-$package_index.compile.log"
  if ! go -C "$go_root" test -c -o "$binary" "$package" >"$compile_log" 2>&1; then
    cat "$compile_log" >&2
    exit 1
  fi

  test_list="$tmpdir/package-$package_index.tests"
  if ! (cd "$package_dir" && "$binary" -test.list '.*') > "$test_list"; then
    echo "could not list tests for $package" >&2
    exit 1
  fi
  mapfile -t listed_names < "$test_list"
  tests=()
  for test_name in "${listed_names[@]}"; do
    if [[ $test_name =~ ^(Test|Example|Fuzz) ]]; then
      tests+=("$test_name")
    fi
  done
  ((${#tests[@]})) || continue

  test_count=$((test_count + ${#tests[@]}))
  package_shards=$jobs
  if (( package_shards > ${#tests[@]} )); then
    package_shards=${#tests[@]}
  fi
  shard_count_total=$((shard_count_total + package_shards))

  shard_tests=()
  shard_expected=()
  shard_load=()
  for ((shard = 0; shard < package_shards; shard++)); do
    shard_tests[shard]=
    shard_expected[shard]=0
    shard_load[shard]=0
  done

  has_timing=0
  for test_name in "${tests[@]}"; do
    if [[ -n ${timing_ms[$test_name]+known} ]]; then
      has_timing=1
      break
    fi
  done

  if (( has_timing )); then
    # Assign the slowest known tests first to the shard with the least work.
    order_file="$tmpdir/package-$package_index.order"
    : > "$order_file"
    for test_index in "${!tests[@]}"; do
      test_name=${tests[test_index]}
      weight=${timing_ms[$test_name]:-1000}
      printf '%s %s\n' "$weight" "$test_index" >> "$order_file"
    done
    sort -k1,1nr -k2,2n "$order_file" > "$order_file.sorted"
    while read -r weight test_index; do
      least_loaded=0
      for ((shard = 1; shard < package_shards; shard++)); do
        if (( shard_load[shard] < shard_load[least_loaded] )); then
          least_loaded=$shard
        fi
      done
      test_name=${tests[test_index]}
      if [[ -n ${shard_tests[least_loaded]} ]]; then
        shard_tests[least_loaded]+="|$test_name"
      else
        shard_tests[least_loaded]=$test_name
      fi
      shard_expected[least_loaded]=$((shard_expected[least_loaded] + 1))
      shard_load[least_loaded]=$((shard_load[least_loaded] + weight))
    done < "$order_file.sorted"
  else
    for test_index in "${!tests[@]}"; do
      shard=$((test_index % package_shards))
      test_name=${tests[test_index]}
      if [[ -n ${shard_tests[shard]} ]]; then
        shard_tests[shard]+="|$test_name"
      else
        shard_tests[shard]=$test_name
      fi
      shard_expected[shard]=$((shard_expected[shard] + 1))
    done
  fi

  shard_pids=()
  shard_outputs=()
  for ((shard = 0; shard < package_shards; shard++)); do
    output="$tmpdir/package-$package_index-shard-$shard.out"
    shard_outputs+=("$output")
    run_pattern="^(${shard_tests[shard]})$"
    (
      # Tests open fixtures by relative path, so match go test's package cwd.
      cd "$package_dir"
      "$binary" "-test.run=$run_pattern" -test.count=1 -test.v "${run_extra[@]}"
    ) > "$output" 2>&1 &
    shard_pids+=("$!")
  done

  package_failed=0
  for ((shard = 0; shard < package_shards; shard++)); do
    shard_failed=0
    if ! wait "${shard_pids[shard]}"; then
      shard_failed=1
    fi
    # A successful process can still have skipped tests due to a bad selector.
    actual=$(awk '/^--- (PASS|FAIL|SKIP): [^/[:space:]]+ \([0-9]+([.][0-9]+)?s\)$/ { count++ } END { print count+0 }' "${shard_outputs[shard]}")
    if (( actual != shard_expected[shard] )); then
      shard_failed=1
      printf 'shard failed for %s: ran %s of %s listed tests\n' \
        "$package" "$actual" "${shard_expected[shard]}" >&2
    fi
    if (( shard_failed )); then
      package_failed=1
      printf '%s shard %d output:\n' "$package" "$shard" >&2
      cat "${shard_outputs[shard]}" >&2
    fi
  done

  for output in "${shard_outputs[@]}"; do
    while IFS= read -r line; do
      if [[ $line =~ ^---\ (PASS|FAIL|SKIP):\ ([^/[:space:]]+)\ \(([0-9]+([.][0-9]+)?)s\)$ ]]; then
        test_name=${BASH_REMATCH[2]}
        seconds=${BASH_REMATCH[3]}
        whole=${seconds%%.*}
        fraction=0
        if [[ $seconds == *.* ]]; then
          fraction=${seconds#*.}
          fraction="${fraction}000"
          fraction=${fraction:0:3}
        fi
        weight=$((10#$whole * 1000 + 10#$fraction))
        (( weight > 0 )) || weight=1
        timing_ms["$test_name"]=$weight
      fi
    done < "$output"
  done

  cache_dir=${timing_file%/*}
  mkdir -p -- "$cache_dir"
  timing_tmp="$timing_file.tmp.$$"
  : > "$timing_tmp"
  for test_name in "${!timing_ms[@]}"; do
    weight=${timing_ms[$test_name]}
    printf '%d.%03d %s\n' "$((weight / 1000))" "$((weight % 1000))" \
      "$test_name" >> "$timing_tmp"
  done
  mv -f -- "$timing_tmp" "$timing_file"
  timing_tmp=

  if (( package_failed )); then
    exit 1
  fi
done < "$tmpdir/packages.list"

end_ns=$(date +%s%N)
elapsed_ns=$((end_ns - start_ns))
seconds=$((elapsed_ns / 1000000000))
centiseconds=$(((elapsed_ns % 1000000000) / 10000000))
printf 'summary packages=%d tests=%d shards=%d wall=%d.%02ds\n' \
  "$package_count" "$test_count" "$shard_count_total" "$seconds" "$centiseconds"
