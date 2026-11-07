package templates

// SecretsEntrypoint returns the opt-in bridge used by generated PHP images.
// Only comma-separated keys named by SHUTTLE_ENV_SECRETS become environment
// variables; every other Docker Secret remains file-only under /run/secrets.
func SecretsEntrypoint() string {
	return `#!/bin/sh
set -eu
# Export only the explicitly allowlisted Docker Secrets.
old_ifs=$IFS
IFS=,
for key in ${SHUTTLE_ENV_SECRETS:-}; do
	case "$key" in
		""|[0-9]*|*[!A-Z0-9_]* ) echo "invalid SHUTTLE_ENV_SECRETS key" >&2; exit 64 ;;
		* ) ;;
	esac
	secret_file="/run/secrets/$key"
	[ -f "$secret_file" ] || { echo "missing Docker Secret: $key" >&2; exit 66; }
	export "$key=$(cat "$secret_file")"
done
IFS=$old_ifs
exec "$@"
`
}
