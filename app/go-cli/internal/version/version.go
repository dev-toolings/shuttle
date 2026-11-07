// Package version exposes build-time metadata. Values are injected via
// `-ldflags "-X github.com/dev-toolings/deploy-shuttle/go-cli/internal/version.Version=..."` at build time.
package version

// Version is the CLI release. Defaults to "dev" when not injected.
var Version = "dev"

// ReleasePublicKey and ReleaseKeyID are injected by the release build. They
// are public material, but embedding them makes the updater independent from a
// compromised release server. An empty value intentionally fails closed.
var ReleasePublicKey = ""
var ReleaseKeyID = ""
var ReleaseTrustedKeys = ""
var ReleaseRevokedKeyIDs = ""
