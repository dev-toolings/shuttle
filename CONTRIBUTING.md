# Contributing

## Repository layout

| Path | Contents |
|---|---|
| `app/go-cli` | The `shuttle` CLI (Go 1.27, Cobra) |
| `scripts` | Build, release, and contract test scripts |
| `docs` | Check catalog, configuration reference, runbooks |

Run `make help` for the categorized list of every available target.

---

## Go CLI

```bash
cd app/go-cli

gofmt -w .        # format
go vet ./...      # lint
go test ./...     # test
go run ./cmd/shuttle --help
```

Or through the Makefile from the repository root: `make go-fmt`, `make go-vet`,
`make go-test`, `make go-run`.

To run the version you are working on as the installed `shuttle`, use
`make install`. It builds for the current platform and replaces the binary on
your PATH. No previous generation is kept: to undo, run it from the previous
commit. `shuttle update`
is the user path (signed GitHub Releases once DEV-DEPL-10 lands). Maintainers
do not use it: a config that just gained a key will fail to load against an
older installed binary. The CLI is Apache-2.0.

`make install` embeds the release verification keyring, read from the GitHub
Actions variables when `gh` is authenticated, so a binary installed this way can
still verify a future `shuttle update`. Those keys are public; only the signing
key is secret and it stays in CI. Without `gh` the build still works and says so,
but the binary will fail closed on `shuttle update`.

Cross-compile every release target into `dist/`:

```bash
make build
```

---

## Before opening a pull request

Run the CI parity target, which mirrors the jobs in
`.github/workflows/ci.yml`:

```bash
make test
```

That runs, in order:

1. **go**: `gofmt` check, then `go vet ./...`, then `go test ./...`
2. **contracts**: `sh scripts/test.sh`, the shell contracts under `scripts/tests`
   (they need `rg`)

A `gofmt` diff fails the build, so format before committing.

---

## Conventions

- Commits and code are written in English.
- Never commit `.env` files, credentials, or production hostnames. Runbooks read the
  target host from the environment; see [`docs/operations.md`](docs/operations.md).
- Release tags are cut by `scripts/release.sh`; see
  [`docs/releasing.md`](docs/releasing.md).
