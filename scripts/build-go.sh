#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

cd "$ROOT/app/go-cli"

# Version: prefer env var, then `git describe`, else "dev".
VERSION="${SHUTTLE_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
fi

if [ "${SHUTTLE_RELEASE_REQUIRE_SIGNATURE:-}" = "1" ]; then
  printf '%s\n' "$VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || { echo "release version must be vMAJOR.MINOR.PATCH" >&2; exit 1; }

  # A release build must be reproducible from the exact revision that is
  # published.  An explicit SHUTTLE_VERSION must not be usable to disguise a
  # dirty working tree as a trusted release (especially for local operator
  # installs).  The CI checkout is clean; local development builds keep the
  # existing unsigned path below this guard.
  if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]; then
    echo "signed release build requires a clean git working tree" >&2
    exit 1
  fi
fi

LDPKG="github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
LDFLAGS="-s -w -X ${LDPKG}.Version=${VERSION}"

# CI release jobs must provide both halves of the public/private signing
# configuration. Local development builds remain possible, but unsigned
# artefacts are never accepted by a release job.
if [ "${SHUTTLE_RELEASE_REQUIRE_SIGNATURE:-}" = "1" ]; then
  : "${DEPLOYSHUTTLE_RELEASE_KEY_ID:?missing release key id}"
  : "${DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY:?missing release public key}"
  : "${DEPLOYSHUTTLE_RELEASE_SIGNING_KEY:?missing release signing key}"
  : "${DEPLOYSHUTTLE_RELEASE_TRUSTED_KEYS:?missing trusted release keyring}"
  go run ./cmd/release-keyring-check "$DEPLOYSHUTTLE_RELEASE_TRUSTED_KEYS" "$DEPLOYSHUTTLE_RELEASE_KEY_ID" "$DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY"
	LDFLAGS="$LDFLAGS -X ${LDPKG}.ReleaseKeyID=${DEPLOYSHUTTLE_RELEASE_KEY_ID} -X ${LDPKG}.ReleasePublicKey=${DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY} -X ${LDPKG}.ReleaseTrustedKeys=${DEPLOYSHUTTLE_RELEASE_TRUSTED_KEYS} -X ${LDPKG}.ReleaseRevokedKeyIDs=${DEPLOYSHUTTLE_RELEASE_REVOKED_KEY_IDS:-}"
fi

# Release outputs are owned by this script. Clean them only after every signed
# build preflight has succeeded: an invalid version, dirty tree, or bad keyring
# must not destroy a previously valid local build.
rm -f \
	"$DIST/shuttle" \
	"$DIST/shuttle-linux-x64" \
	"$DIST/shuttle-linux-arm64" \
	"$DIST/shuttle-darwin-arm64" \
	"$DIST/shuttle-darwin-x64" \
	"$DIST/checksums.txt" \
	"$DIST/latest.json" \
	"$DIST/dockerfile-optimizer.tar.gz"

build() {
  goos="$1"
  goarch="$2"
  out="$3"
  cgo=0
  if [ "$goos" = darwin ]; then cgo=1; fi
  CGO_ENABLED="$cgo" GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$LDFLAGS" -o "$DIST/$out" ./cmd/shuttle
}

build linux  amd64 shuttle-linux-x64
build linux  arm64 shuttle-linux-arm64
build darwin arm64 shuttle-darwin-arm64
build darwin amd64 shuttle-darwin-x64

cd "$DIST"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum shuttle-linux-x64 shuttle-linux-arm64 shuttle-darwin-arm64 shuttle-darwin-x64 > checksums.txt
else
  shasum -a 256 shuttle-linux-x64 shuttle-linux-arm64 shuttle-darwin-arm64 shuttle-darwin-x64 > checksums.txt
fi

# Release manifest consumed by the website (/releases/latest) and by
# `shuttle update`: {"version":..., "assets":{name:sha256}}.
{
  printf '{"version":"%s","assets":{' "$VERSION"
  first=1
  while read -r sum name; do
    [ "$first" -eq 1 ] || printf ','
    printf '"%s":"%s"' "$name" "$sum"
    first=0
  done < checksums.txt
  printf '}}\n'
} > latest.json

if [ "${SHUTTLE_RELEASE_REQUIRE_SIGNATURE:-}" = "1" ]; then
  # The private key is read by this short-lived CI process only; it is neither
  # written to dist nor passed to the compiler.
  cd "$ROOT/app/go-cli"
  go run ./cmd/release-sign "$DIST/latest.json"
  # A release installer pins the same validated public key as the binary.
  case "$DEPLOYSHUTTLE_RELEASE_KEY_ID" in *[!A-Za-z0-9._-]*|'') echo 'installer key id has unsupported characters' >&2; exit 1;; esac
  sed -e "s|@RELEASE_KEY_ID@|$DEPLOYSHUTTLE_RELEASE_KEY_ID|g" \
      -e "s|@RELEASE_PUBLIC_KEY@|$DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY|g" \
      "$ROOT/scripts/install.sh" > "$DIST/install.sh"

fi
