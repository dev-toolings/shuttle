#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
for test_file in "$root"/scripts/tests/*.sh; do
  printf '\n== %s ==\n' "${test_file#"$root"/}"
  # Honour each script's own shebang. Some contracts need bash builtins such as
  # `set -o pipefail`, which the POSIX /bin/sh on CI runners does not implement.
  case "$(head -n 1 "$test_file")" in
    *bash) bash "$test_file" ;;
    *) sh "$test_file" ;;
  esac
done
