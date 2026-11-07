#!/usr/bin/env sh
# Release script for shuttle
#
# Usage:
#   sh scripts/release.sh patch    # v2.0.0 → v2.0.1
#   sh scripts/release.sh minor    # v2.0.1 → v2.1.0
#   sh scripts/release.sh major    # v2.1.0 → v3.0.0
#   sh scripts/release.sh v2.5.0   # explicit version
#
# What it does:
#   1. Validates working tree is clean
#   2. Runs tests
#   3. Computes next version from latest git tag
#   4. Runs the complete local Go/audit release gate
#   5. Creates a git tag (it does not alter a locally installed shuttle)
#   6. Prints the commands to push the tag
#
# Release distribution requires a separate signing and publication workflow.

set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

# --- Helpers ---
die() { printf 'release: %s\n' "$*" >&2; exit 1; }

# --- Validate working tree ---
if [ -n "$(git status --porcelain)" ]; then
  die "working tree is dirty — commit or stash first"
fi

# --- Get bump type ---
BUMP="${1:-}"
if [ -z "$BUMP" ]; then
  die "usage: release.sh <patch|minor|major|vX.Y.Z>"
fi

# --- Compute version ---
LATEST_TAG="$(git tag -l 'v*' --sort=-v:refname | head -1)"
if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="v0.0.0"
fi

# Strip leading 'v'
CURRENT="${LATEST_TAG#v}"

# Parse major.minor.patch
IFS='.' read -r MAJOR MINOR PATCH <<EOF
$CURRENT
EOF

case "$BUMP" in
  patch)
    PATCH=$((PATCH + 1))
    NEXT="v${MAJOR}.${MINOR}.${PATCH}"
    ;;
  minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    NEXT="v${MAJOR}.${MINOR}.${PATCH}"
    ;;
  major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    NEXT="v${MAJOR}.${MINOR}.${PATCH}"
    ;;
  v[0-9]*)
    NEXT="$BUMP"
    ;;
  *)
    die "invalid bump type: $BUMP (use patch, minor, major, or vX.Y.Z)"
    ;;
esac

printf '%s\n' "$NEXT" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || die "release version must be vMAJOR.MINOR.PATCH"

echo "Release: ${LATEST_TAG} → ${NEXT}"
echo ""

# --- Run tests ---
echo "→ Running tests..."
cd "$ROOT/app/go-cli"
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
sh "$ROOT/scripts/audit-retry.sh" go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
echo "  ✓ Go checks pass"

cd "$ROOT"
git diff --check

# --- Create tag ---
cd "$ROOT"
git tag -a "$NEXT" -m "Release ${NEXT}"
echo "  ✓ Tag created: ${NEXT}"

echo ""
echo "Ready to publish. Run:"
echo ""
echo "  git push origin main && git push origin ${NEXT}"
echo ""
echo "Publish signed release artifacts with your release workflow."
