// Package release defines the canonical signed release manifest contract.
package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CanonicalManifestBytes is deliberately small and stable across Go, shell and
// TypeScript consumers. URLs are excluded because a release origin may mint
// short-lived URLs for an immutable release, and must not change its signature.
func CanonicalManifestBytes(version, keyID string, checksums map[string]string) ([]byte, error) {
	if !validVersion(version) || keyID == "" || len(checksums) == 0 {
		return nil, fmt.Errorf("invalid canonical release manifest")
	}
	assets := make([]string, 0, len(checksums))
	for asset, checksum := range checksums {
		if !validAsset(asset) || !validChecksum(checksum) {
			return nil, fmt.Errorf("invalid release asset %q", asset)
		}
		assets = append(assets, asset)
	}
	sort.Strings(assets)
	var out strings.Builder
	out.WriteString("deployshuttle-release-manifest-v1\n")
	out.WriteString("version=")
	out.WriteString(version)
	out.WriteByte('\n')
	out.WriteString("key_id=")
	out.WriteString(keyID)
	out.WriteByte('\n')
	for _, asset := range assets {
		out.WriteString("sha256.")
		out.WriteString(asset)
		out.WriteByte('=')
		out.WriteString(strings.ToLower(checksums[asset]))
		out.WriteByte('\n')
	}
	return []byte(out.String()), nil
}

func Verify(version, keyID string, checksums map[string]string, signature, publicKeyBase64 string) error {
	if signature == "" || publicKeyBase64 == "" {
		return fmt.Errorf("unsigned release manifest")
	}
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid embedded release public key")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid release manifest signature")
	}
	payload, err := CanonicalManifestBytes(version, keyID, checksums)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, sig) {
		return fmt.Errorf("release manifest signature verification failed")
	}
	return nil
}

// ValidateTrustedKeys validates the build-time keyring format. It deliberately
// lives next to manifest verification so the release build and updater share
// one definition of a trustworthy key. Entries are comma-separated
// "key-id=base64-ed25519-public-key" pairs; IDs and keys must be unique.
// The active signing key is required to be present and equal to the supplied
// public key, preventing a release from producing a manifest its own binary
// cannot verify.
func ValidateTrustedKeys(keyring, signingKeyID, signingPublicKey string) error {
	if keyring == "" || signingKeyID == "" || signingPublicKey == "" {
		return fmt.Errorf("trusted release keyring, signing key id and public key are required")
	}
	seenIDs := make(map[string]struct{})
	seenKeys := make(map[string]struct{})
	foundSigningKey := false
	for _, raw := range strings.Split(keyring, ",") {
		if raw == "" || strings.TrimSpace(raw) != raw {
			return fmt.Errorf("invalid trusted release key entry")
		}
		keyID, publicKey, ok := strings.Cut(raw, "=")
		if !ok || !validKeyID(keyID) || publicKey == "" {
			return fmt.Errorf("invalid trusted release key entry")
		}
		decoded, err := base64.StdEncoding.DecodeString(publicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid public key for release key %q", keyID)
		}
		if _, duplicate := seenIDs[keyID]; duplicate {
			return fmt.Errorf("duplicate trusted release key id %q", keyID)
		}
		if _, duplicate := seenKeys[publicKey]; duplicate {
			return fmt.Errorf("duplicate trusted release public key")
		}
		seenIDs[keyID] = struct{}{}
		seenKeys[publicKey] = struct{}{}
		if keyID == signingKeyID {
			if publicKey != signingPublicKey {
				return fmt.Errorf("trusted key %q does not match active signing public key", signingKeyID)
			}
			foundSigningKey = true
		}
	}
	if !foundSigningKey {
		return fmt.Errorf("trusted release keyring omits active signing key %q", signingKeyID)
	}
	return nil
}

func validVersion(value string) bool {
	return releaseVersionPattern.MatchString(value)
}

var releaseVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func validAsset(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "/\\\r\n\x00=")
}

func validChecksum(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') && !(r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func validKeyID(value string) bool {
	return value != "" && len(value) <= 64 && !strings.ContainsAny(value, "=, \t\r\n\\/\x00")
}
