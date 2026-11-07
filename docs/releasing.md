# Releasing

Internal runbook for cutting a `shuttle` release.

---

## Cutting a release

```bash
sh scripts/release.sh patch     # v0.0.1 -> v0.0.2
sh scripts/release.sh minor     # v0.0.1 -> v0.1.0
sh scripts/release.sh major     # v0.0.1 -> v1.0.0
sh scripts/release.sh v0.2.3    # explicit version
```

The script runs, in order:

1. `gofmt`, `go vet ./...`, `go test ./...` and `govulncheck`, aborting on failure.
2. `git diff --check`.
3. An annotated git tag for the new version.

It builds nothing and leaves the installed `shuttle` alone (`make install` does
that). It stops there and prints the push command. Nothing is published until
you run it:

```bash
git push origin main && git push origin <tag>
```

---

## Signed releases

The release build signs its manifest with an Ed25519 key. Keep the private key
outside the repository and verify the public key through an independent trusted
channel. Development builds without a trusted keyring cannot verify updates.

---

## Local builds

`scripts/build-go.sh` cross-compiles every target into `dist/` without tagging
anything. It takes the version from `SHUTTLE_VERSION`, falls back to `git describe
--tags --always --dirty`, and finally to `dev`. Use it to test the build matrix
before a real release.

When `SHUTTLE_RELEASE_REQUIRE_SIGNATURE=1` is set, the script also refuses a
dirty Git tree before reading the protected signing configuration. An explicit
`SHUTTLE_VERSION` therefore cannot turn uncommitted changes into a trusted
operator binary. The signed path is intended for a clean, reviewed tag in CI;
development builds must remain explicitly acknowledged with
`--allow-development-build` and are not suitable for destructive missions.

```bash
make build
```

## Publishing to the public repository

The signing key stays in the private repository's workflow, so the public release is
copied from it. After the workflow of a tag succeeds:

```sh
sh scripts/publish-public.sh --push Shuttle shuttle@users.noreply.github.com
gh release download vX.Y.Z -D /tmp/release
gh release create vX.Y.Z -R dev-toolings/shuttle /tmp/release/* --title vX.Y.Z --latest --notes "..."
```

The export refuses to run if it matches `tmp/public-denylist`. The public tag must point
at the commit pushed by the export: create it before `gh release create`.
