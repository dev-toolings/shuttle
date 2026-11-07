package cli

import (
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
)

// composeSecretsScript is the program the deploy account runs on the host to
// turn the declared keys of the host's own environment file into what the
// release mounts.
//
// It is the compose strategy's counterpart of the root helper's secrets-host
// action, with the same contract and without the privilege: only the declared
// keys are read, a key that is absent or empty stops the run and is named,
// and nothing is left behind on failure. The values never travel — the file is
// read on the host and written on the host, into the release directory, under
// the account that runs the containers.
//
// The env file is 0600 and the per-key files are 0444 rather than 0400: the
// containers run as an unprivileged user Shuttle does not know, and a file
// only the deploy account can read is a file the application cannot read.
// The release directory itself is 0700, so nothing outside the account sees
// them on the host.
func composeSecretsScript(sourceEnvFile, releaseDir string, keys []string, envFileKeys []string, fileKeys []string) string {
	quote := func(values []string) string {
		quoted := make([]string, 0, len(values))
		for _, value := range values {
			quoted = append(quoted, shell.Escape(value))
		}
		return strings.Join(quoted, " ")
	}
	return `set -eu
umask 077
source=` + shell.Escape(sourceEnvFile) + `
release=` + shell.Escape(releaseDir) + `
if [ ! -f "$source" ] || [ -L "$source" ]; then
  echo "secrets.host.env_file $source is not a regular file readable by $(id -un)" >&2
  exit 1
fi
work=$(mktemp -d "$release.secrets.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
install -d -m 0700 "$work/` + composeSecretsDir + `"
: >"$work/` + composeSecretsEnvFile + `"
missing=""
read_key() {
  line=$(grep -E "^(export[[:space:]]+)?$1=" "$source" | tail -n 1 || true)
  [ -n "$line" ] || return 1
  value=${line#*=}
  case "$value" in
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*\') value=${value#\'}; value=${value%\'} ;;
  esac
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}
for key in ` + quote(keys) + `; do
  if ! value=$(read_key "$key"); then
    missing="$missing $key"
    continue
  fi
  for envKey in ` + quote(envFileKeys) + `; do
    if [ "$envKey" = "$key" ]; then
      printf '%s=%s\n' "$key" "$value" >>"$work/` + composeSecretsEnvFile + `"
    fi
  done
  for fileKey in ` + quote(fileKeys) + `; do
    if [ "$fileKey" = "$key" ]; then
      printf '%s' "$value" >"$work/` + composeSecretsDir + `/$key"
      chmod 0444 "$work/` + composeSecretsDir + `/$key"
    fi
  done
done
if [ -n "$missing" ]; then
  echo "secrets.host.env_file $source does not set (or sets empty):$missing" >&2
  exit 1
fi
chmod 0600 "$work/` + composeSecretsEnvFile + `"
chmod 0755 "$work/` + composeSecretsDir + `"
install -d -m 0700 "$release"
rm -rf -- "$release/` + composeSecretsDir + `" "$release/` + composeSecretsEnvFile + `"
mv -- "$work/` + composeSecretsEnvFile + `" "$release/` + composeSecretsEnvFile + `"
mv -- "$work/` + composeSecretsDir + `" "$release/` + composeSecretsDir + `"
`
}
