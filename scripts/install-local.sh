#!/usr/bin/env sh
# Install the shuttle CLI built from this working tree into the local PATH.
#
# `shuttle update` is the user path: it downloads a signed release. A maintainer
# working in this repository has no reason to round-trip through a release to
# run the code they just wrote, and `scripts/release.sh` deliberately does not touch an installed
# binary. Without this script the only way to run a new version locally was to
# retype a `go build` invocation with four -ldflags, and getting one wrong
# produces a binary that silently cannot verify a future update.
#
# The release verification keys are embedded exactly as a release build embeds
# them, so a binary installed this way can still `shuttle update` later. They
# are public: only the signing key is secret, and it lives in CI. They are read
# from the GitHub Actions variables when `gh` is authenticated, so this script
# has no copy of its own to drift.
#
# Usage:
#   sh scripts/install-local.sh              # → ~/.local/bin/shuttle
#   PREFIX=/usr/local/bin sh scripts/install-local.sh
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local/bin}"
TARGET="$PREFIX/shuttle"
LDPKG="github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"

die() { printf 'install-local: %s\n' "$*" >&2; exit 1; }

VERSION="${SHUTTLE_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
fi

LDFLAGS="-s -w -X ${LDPKG}.Version=${VERSION}"

# Without the keyring the binary works but fails closed on `shuttle update`,
# which is a trap worth naming rather than discovering months later.
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  KEY_ID="$(gh variable list --json name,value -q '.[]|select(.name=="DEPLOYSHUTTLE_RELEASE_KEY_ID")|.value' 2>/dev/null || true)"
  PUBLIC_KEY="$(gh variable list --json name,value -q '.[]|select(.name=="DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY")|.value' 2>/dev/null || true)"
  TRUSTED_KEYS="$(gh variable list --json name,value -q '.[]|select(.name=="DEPLOYSHUTTLE_RELEASE_TRUSTED_KEYS")|.value' 2>/dev/null || true)"
  REVOKED_KEY_IDS="$(gh variable list --json name,value -q '.[]|select(.name=="DEPLOYSHUTTLE_RELEASE_REVOKED_KEY_IDS")|.value' 2>/dev/null || true)"
  if [ -n "$KEY_ID" ] && [ -n "$PUBLIC_KEY" ] && [ -n "$TRUSTED_KEYS" ]; then
    ( cd "$ROOT/app/go-cli" && go run ./cmd/release-keyring-check "$TRUSTED_KEYS" "$KEY_ID" "$PUBLIC_KEY" ) \
      || die "release keyring is inconsistent; refusing to embed it"
    LDFLAGS="$LDFLAGS -X ${LDPKG}.ReleaseKeyID=${KEY_ID} -X ${LDPKG}.ReleasePublicKey=${PUBLIC_KEY} -X ${LDPKG}.ReleaseTrustedKeys=${TRUSTED_KEYS} -X ${LDPKG}.ReleaseRevokedKeyIDs=${REVOKED_KEY_IDS}"
    echo "→ embedding release keyring ($KEY_ID)"
  else
    echo "! release keyring unavailable; the installed binary will refuse 'shuttle update'"
  fi
else
  echo "! gh not authenticated; the installed binary will refuse 'shuttle update'"
fi

echo "→ building $VERSION for $(go env GOOS)/$(go env GOARCH)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
( cd "$ROOT/app/go-cli" && go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/shuttle" ./cmd/shuttle )

mkdir -p "$PREFIX"
# Replace by rename so a running shuttle is never a half-written file. Exactly
# one shuttle is installed: a kept generation drifts from the sources and gets
# run by mistake. Undo a bad install by running this script from the previous
# commit. A generation left by older versions of this script is removed.
mv "$STAGE/shuttle" "$TARGET"
rm -f "$TARGET.previous"
chmod 755 "$TARGET"

echo "  ✓ installed $("$TARGET" --version) → $TARGET"
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo "  ! $PREFIX is not on PATH" ;;
esac
