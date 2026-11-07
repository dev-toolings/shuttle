// release-verify verifies the canonical Ed25519 fields returned by the VPS.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/release"
)

type manifest struct {
	Version string            `json:"version"`
	SHA256  map[string]string `json:"sha256"`
	// Assets is the same map under the name scripts/build-go.sh writes into
	// latest.json. On 28-10-2026 this tool rejected the signed v0.0.58 and
	// v0.0.59 manifests as "invalid canonical release manifest" because it
	// only read the site's `sha256` form.
	Assets    map[string]string `json:"assets"`
	KeyID     string            `json:"key_id"`
	Signature string            `json:"signature"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: release-verify <manifest.json>")
	}
	public := os.Getenv("DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY")
	if public == "" {
		fail("DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY is required")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err.Error())
	}
	var item manifest
	if err := json.Unmarshal(data, &item); err != nil {
		fail(err.Error())
	}
	checksums := item.SHA256
	if len(checksums) == 0 {
		checksums = item.Assets
	}
	if err := release.Verify(item.Version, item.KeyID, checksums, item.Signature, public); err != nil {
		fail(err.Error())
	}
}

func fail(message string) { fmt.Fprintln(os.Stderr, "release-verify:", message); os.Exit(1) }
