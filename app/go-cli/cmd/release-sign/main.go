// release-sign signs a release manifest using the CI-provided Ed25519 key.
// The signing key is intentionally read only from the environment.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/release"
)

type manifest struct {
	Version   string            `json:"version"`
	Assets    map[string]string `json:"assets"`
	KeyID     string            `json:"key_id,omitempty"`
	Signature string            `json:"signature,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: release-sign <latest.json>")
	}
	keyID, privateKey, publicKey := os.Getenv("DEPLOYSHUTTLE_RELEASE_KEY_ID"), os.Getenv("DEPLOYSHUTTLE_RELEASE_SIGNING_KEY"), os.Getenv("DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY")
	if keyID == "" || privateKey == "" || publicKey == "" {
		fail("DEPLOYSHUTTLE_RELEASE_KEY_ID, DEPLOYSHUTTLE_RELEASE_SIGNING_KEY and DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY are required")
	}
	private, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || (len(private) != ed25519.PrivateKeySize && len(private) != ed25519.SeedSize) {
		fail("DEPLOYSHUTTLE_RELEASE_SIGNING_KEY must be base64 Ed25519 seed or private key")
	}
	if len(private) == ed25519.SeedSize {
		private = ed25519.NewKeyFromSeed(private)
	}
	public, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		fail("DEPLOYSHUTTLE_RELEASE_PUBLIC_KEY must be a base64 Ed25519 public key")
	}
	if !ed25519.PublicKey(public).Equal(ed25519.PrivateKey(private).Public()) {
		fail("release public key does not match signing key")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err.Error())
	}
	var item manifest
	if err := json.Unmarshal(data, &item); err != nil {
		fail(err.Error())
	}
	payload, err := release.CanonicalManifestBytes(item.Version, keyID, item.Assets)
	if err != nil {
		fail(err.Error())
	}
	item.KeyID = keyID
	item.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(private), payload))
	encoded, err := json.Marshal(item)
	if err != nil {
		fail(err.Error())
	}
	if err := os.WriteFile(os.Args[1], append(encoded, '\n'), 0o644); err != nil {
		fail(err.Error())
	}
}

func fail(message string) { fmt.Fprintln(os.Stderr, "release-sign:", message); os.Exit(1) }
