# Release trust and update recovery

`latest.json` is signed outside the VPS with Ed25519. Its canonical bytes are
`deployshuttle-release-manifest-v1`, then the version, key id, and every asset
checksum sorted by asset name. Signed URLs are intentionally excluded: they are
short-lived delivery URLs, and the updater accepts them only
after signature verification and only from the configured site origin.

The release job requires `DEPLOYSHUTTLE_RELEASE_SIGNING_KEY` (base64 Ed25519
seed/private key), `DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY` (base64 raw public key),
`DEPLOYSHUTTLE_RELEASE_KEY_ID`, and
`DEPLOYSHUTTLE_RELEASE_TRUSTED_KEYS` (comma-separated
`key-id=base64-public-key` entries). The keyring is validated before building:
it has unique ids/keys and contains the active signing key with the matching
public key. Missing or invalid material fails the release before upload. The
keyring, key id, and revocation list are embedded in each released CLI with
linker flags; the private key is never embedded.

Rotation is a two-release bridge: first publish a client embedding both
`old=...` and `new=...`, while manifests may still be signed by old; then sign
the next manifest with new. A following client can embed only `new=...` and
set `DEPLOYSHUTTLE_RELEASE_REVOKED_KEY_IDS=old`. A revoked id is rejected even
if it appears in a keyring. Existing pre-bridge clients cannot be remotely
reconfigured safely, so an operator must retain the old signer until the bridge
client is sufficiently deployed and follow the incident/recovery process for a
compromised old key.

The updater bounds manifest/download size, uses a 30-second HTTP timeout,
requires HTTPS and the configured host, downloads and hashes before execution.
It writes and fsyncs an `O_EXCL` sibling temporary executable, then creates a
hard-link recovery artifact at `<binary>.recovery`, fsyncs its directory, and
atomically replaces `<binary>` with the staged file. The recovery artifact is
kept until the published directory is durable, then removed and the directory
is fsynced again. It is not a `.old` rename and it is not promised to survive a
successful update.

If a failure occurs before recovery cleanup, the command returns an error and
does not hide the retained recovery artifact. Do not retry over it: run
`shuttle update --recover`, which atomically restores `<binary>.recovery` and
fsyncs the directory, then investigate the reported filesystem error. A
recovery artifact already present also blocks a new update.

There is one deliberately different post-cleanup case: when removal of
`<binary>.recovery` succeeds but the following directory fsync fails, the new
binary was already published and durably fsynced, while the recovery artifact
is absent. The updater exits successfully with an explicit warning that
`shuttle update --recover` is unavailable; it never labels that state as
recoverable. Repeating cleanup is idempotent (an absent artifact is accepted
and the directory is fsynced again). This gives one-file crash recovery; it
does not claim an atomic transaction across download, filesystem, and network
operations.

The release workflow gates Go formatting/vet/tests/vulnerability scan and Bun
install/typecheck/tests/build/audit before signing/upload. It has no SBOM or
SLSA provenance publisher yet: that is an explicit current limitation, not a
claim of supply-chain attestation. This repository also has no generated
third-party license notice bundle yet; releases therefore do not claim one.
GitHub production environment protection,
tag protection, release SSH host key, and the signing secret/public key/key-id
must be configured by an operator; repository code cannot prove those external
controls.
