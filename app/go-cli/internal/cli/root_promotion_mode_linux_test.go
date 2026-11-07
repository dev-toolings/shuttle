//go:build linux

package cli

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

const promotionTestIssuer = "acme-v02.api.letsencrypt.org-directory"

// writeCaddyCertificate stores a certificate where CertMagic does:
// <root>/<issuer>/<subject>/<subject>.crt.
func writeCaddyCertificate(t *testing.T, root, subject string, certificate *x509.Certificate) string {
	t.Helper()
	directory := filepath.Join(root, promotionTestIssuer, subject)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, subject+".crt")
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// storeMode is the mode a later release of the published stack gets from the
// certificates really present under root.
func storeMode(t *testing.T, root string, hostRoutes bool) config.PromotionMode {
	t.Helper()
	read := func() ([]*x509.Certificate, error) { return readCaddyCertificateStore(root) }
	return selectRootPromotionMode(false, promotionPublishedStack(t, hostRoutes), read, promotionTestNow)
}

func TestCaddyCertificateStoreReturnsTheLeafOfEveryStoredHostname(t *testing.T) {
	root := t.TempDir()
	writeCaddyCertificate(t, root, promotionTestDomain, promotionValidCertificate(t, promotionTestDomain))
	writeCaddyCertificate(t, root, promotionTestAdminHost, promotionValidCertificate(t, promotionTestAdminHost))
	certificates, err := readCaddyCertificateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, certificate := range certificates {
		for _, name := range certificate.DNSNames {
			names[name] = true
		}
	}
	if len(certificates) != 2 || !names[promotionTestDomain] || !names[promotionTestAdminHost] {
		t.Fatalf("store read %d certificates naming %v", len(certificates), names)
	}
}

func TestCaddyCertificateStoreOfAnEdgeThatIssuedNothingIsEmptyAndLegacy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-there-yet")
	certificates, err := readCaddyCertificateStore(root)
	if err != nil || len(certificates) != 0 {
		t.Fatalf("a missing store is an empty one, got %d certificates and %v", len(certificates), err)
	}
	if got := storeMode(t, root, false); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy: no certificate for %s", got, promotionTestDomain)
	}
}

func TestCaddyCertificateStoreThatCannotBeListedIsAnErrorAndLegacy(t *testing.T) {
	// A regular file where the store directory should be: it exists, so it is not
	// an empty store, and it cannot be listed.
	root := filepath.Join(t.TempDir(), "certificates")
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCaddyCertificateStore(root); err == nil {
		t.Fatal("a store that cannot be listed must be an error, not an empty store")
	}
	if got := storeMode(t, root, false); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestCaddyCertificateStoreWithEveryValidCertificateSelectsCapped(t *testing.T) {
	root := t.TempDir()
	writeCaddyCertificate(t, root, promotionTestDomain, promotionValidCertificate(t, promotionTestDomain))
	writeCaddyCertificate(t, root, promotionTestAdminHost, promotionValidCertificate(t, promotionTestAdminHost))
	if got := storeMode(t, root, true); got != config.PromotionModeCapped {
		t.Fatalf("mode = %q, want capped", got)
	}
}

func TestCaddyCertificateStoreWithAnExpiredCertificateSelectsLegacy(t *testing.T) {
	root := t.TempDir()
	writeCaddyCertificate(t, root, promotionTestDomain, promotionExpiredCertificate(t, promotionTestDomain))
	if got := storeMode(t, root, false); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestCaddyCertificateStoreWithACertificateInsideTheRenewalWindowSelectsLegacy(t *testing.T) {
	root := t.TempDir()
	writeCaddyCertificate(t, root, promotionTestDomain, promotionRenewingCertificate(t, promotionTestDomain))
	if got := storeMode(t, root, false); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestCaddyCertificateStoreMissingAHostRouteHostnameSelectsLegacy(t *testing.T) {
	root := t.TempDir()
	writeCaddyCertificate(t, root, promotionTestDomain, promotionValidCertificate(t, promotionTestDomain))
	if got := storeMode(t, root, true); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy: %s has no certificate", got, promotionTestAdminHost)
	}
}

// One unreadable file leaves its own hostname uncovered, which is the safe
// direction, and does not hide the certificates of the others.
func TestCaddyCertificateStoreSkipsAFileThatHoldsNoCertificate(t *testing.T) {
	root := t.TempDir()
	writeCaddyCertificate(t, root, promotionTestDomain, promotionValidCertificate(t, promotionTestDomain))
	broken := filepath.Join(root, promotionTestIssuer, promotionTestAdminHost)
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, promotionTestAdminHost+".crt"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	certificates, err := readCaddyCertificateStore(root)
	if err != nil || len(certificates) != 1 {
		t.Fatalf("store read %d certificates, %v; want the one good certificate", len(certificates), err)
	}
	if got := storeMode(t, root, true); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy: %s has no readable certificate", got, promotionTestAdminHost)
	}
}

// The store belongs to the edge's account, not to root: a link the edge wrote
// must not make the helper read a file outside it.
func TestCaddyCertificateStoreDoesNotFollowSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	outside := writeCaddyCertificate(t, t.TempDir(), promotionTestDomain, promotionValidCertificate(t, promotionTestDomain))
	directory := filepath.Join(root, promotionTestIssuer, promotionTestDomain)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, promotionTestDomain+".crt")); err != nil {
		t.Fatal(err)
	}
	certificates, err := readCaddyCertificateStore(root)
	if err != nil || len(certificates) != 0 {
		t.Fatalf("a linked certificate was read: %d certificates, %v", len(certificates), err)
	}
	if got := storeMode(t, root, false); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}
