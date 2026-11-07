#!/bin/sh
set -eu

# Release builds replace both placeholders with the validated public key and ID.
key_id='@RELEASE_KEY_ID@'
public_key='@RELEASE_PUBLIC_KEY@'
case "$key_id:$public_key" in *'@'*) echo 'installer has no pinned release key' >&2; exit 1;; esac
for tool in curl jq openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done
if command -v sha256sum >/dev/null 2>&1; then hash=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash=shasum
else echo 'sha256sum or shasum is required' >&2; exit 1; fi
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) asset=shuttle-linux-x64;; Linux:aarch64|Linux:arm64) asset=shuttle-linux-arm64;;
  Darwin:x86_64) asset=shuttle-darwin-x64;; Darwin:arm64) asset=shuttle-darwin-arm64;;
  *) echo 'unsupported platform' >&2; exit 1;;
esac
work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM
base=https://github.com/dev-toolings/shuttle/releases/latest/download
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/latest.json" -o "$work/manifest"
# Validate all fields before constructing the exact canonical signed payload.
jq -e --arg id "$key_id" '.version | test("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")' "$work/manifest" >/dev/null
jq -e --arg id "$key_id" '.key_id == $id and (.signature | type == "string") and (.assets | type == "object" and length > 0) and ([.assets | to_entries[] | (.key | test("^[A-Za-z0-9._-]+$")) and (.value | test("^[A-Fa-f0-9]{64}$"))] | all)' "$work/manifest" >/dev/null
{
  printf 'deployshuttle-release-manifest-v1\nversion=%s\nkey_id=%s\n' "$(jq -r .version "$work/manifest")" "$key_id"
  LC_ALL=C jq -r '.assets | to_entries | sort_by(.key)[] | "sha256.\(.key)=\(.value | ascii_downcase)"' "$work/manifest"
} > "$work/payload"
printf '%s' "$public_key" | openssl base64 -d -A > "$work/raw-key"
[ "$(wc -c < "$work/raw-key" | tr -d ' ')" = 32 ] || { echo 'invalid pinned key' >&2; exit 1; }
printf '\060\052\060\005\006\003\053\145\160\003\041\000' > "$work/key.der"
cat "$work/raw-key" >> "$work/key.der"
jq -r .signature "$work/manifest" | tr -d '\n' | openssl base64 -d -A > "$work/signature"
openssl pkeyutl -verify -pubin -inkey "$work/key.der" -keyform DER -rawin -in "$work/payload" -sigfile "$work/signature" >/dev/null || { echo 'invalid release signature' >&2; exit 1; }
expected=$(jq -er --arg asset "$asset" '.assets[$asset] | select(type == "string") | ascii_downcase' "$work/manifest")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/$asset" -o "$work/shuttle"
if [ "$hash" = sha256sum ]; then actual=$(sha256sum "$work/shuttle"); else actual=$(shasum -a 256 "$work/shuttle"); fi
actual=${actual%% *}
[ "$actual" = "$expected" ] || { echo 'release checksum mismatch' >&2; exit 1; }
prefix=${SHUTTLE_INSTALL_PREFIX:-"$HOME/.local"}
# A signed older release is still a downgrade; compare each decimal component
# as text so large version numbers do not overflow shell or jq numeric types.
if [ "${SHUTTLE_INSTALL_ALLOW_DOWNGRADE:-}" != 1 ] && [ -x "$prefix/bin/shuttle" ] &&
   installed_version=$("$prefix/bin/shuttle" --version 2>/dev/null) &&
   jq -en --arg current "$installed_version" --arg candidate "$(jq -r .version "$work/manifest")" '
     ($current | capture("^shuttle version v?(?<v>(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*))$").v | split(".")) as $old |
     ($candidate[1:] | split(".")) as $new |
     reduce range(0; 3) as $i (0;
       if . != 0 then .
       elif ($new[$i] | length) < ($old[$i] | length) then -1
       elif ($new[$i] | length) > ($old[$i] | length) then 1
       elif $new[$i] < $old[$i] then -1
       elif $new[$i] > $old[$i] then 1
       else 0 end) < 0' >/dev/null; then
  echo 'refusing installer downgrade; set SHUTTLE_INSTALL_ALLOW_DOWNGRADE=1 to allow it' >&2
  exit 1
fi
mkdir -p "$prefix/bin"
chmod 755 "$work/shuttle"
# Copy into the destination filesystem before the atomic replacement.
install_tmp=$(mktemp "$prefix/bin/.shuttle.XXXXXXXX")
trap 'rm -rf "$work"; rm -f "$install_tmp"' EXIT HUP INT TERM
cat "$work/shuttle" > "$install_tmp"
chmod 755 "$install_tmp"
mv -f "$install_tmp" "$prefix/bin/shuttle"
printf 'Installed %s/bin/shuttle\n' "$prefix"
