package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// promotionTestNow is the instant every mode decision of these tests is taken at.
var promotionTestNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

const (
	promotionTestDomain    = "app.example.com"
	promotionTestAdminHost = "admin.example.com"
	promotionTestDay       = 24 * time.Hour
)

// promotionTestCertificate is a self-signed certificate naming the given hosts.
// Only its names and its validity period matter to the mode decision.
func promotionTestCertificate(t *testing.T, notBefore, notAfter time.Time, names ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// A 90-day certificate issued ten days ago: well outside Caddy's renewal window,
// which opens when a third of the lifetime (30 days) is left.
func promotionValidCertificate(t *testing.T, names ...string) *x509.Certificate {
	t.Helper()
	return promotionTestCertificate(t, promotionTestNow.Add(-10*promotionTestDay), promotionTestNow.Add(80*promotionTestDay), names...)
}

func promotionExpiredCertificate(t *testing.T, names ...string) *x509.Certificate {
	t.Helper()
	return promotionTestCertificate(t, promotionTestNow.Add(-100*promotionTestDay), promotionTestNow.Add(-10*promotionTestDay), names...)
}

// Ten days left of 90: still served, but Caddy renews it next.
func promotionRenewingCertificate(t *testing.T, names ...string) *x509.Certificate {
	t.Helper()
	return promotionTestCertificate(t, promotionTestNow.Add(-80*promotionTestDay), promotionTestNow.Add(10*promotionTestDay), names...)
}

// promotionTestStack is a signed stack of one published service and one worker.
// The published service carries the given labels, the way swarm_stack.go renders
// them; none at all is an internal application.
func promotionTestStack(t *testing.T, labels map[string]any) []byte {
	t.Helper()
	web := map[string]any{"image": "registry.example/app-web@sha256:" + strings.Repeat("a", 64)}
	if labels != nil {
		web["deploy"] = map[string]any{"labels": labels}
	}
	payload, err := yaml.Marshal(map[string]any{"services": map[string]any{
		"web":    web,
		"worker": map[string]any{"image": "registry.example/app-worker@sha256:" + strings.Repeat("b", 64)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func promotionPublishedStack(t *testing.T, hostRoutes bool) []byte {
	t.Helper()
	labels := map[string]any{"dev.shuttle.domain": promotionTestDomain, "dev.shuttle.port": "8080"}
	if hostRoutes {
		labels["dev.shuttle.host_routes"] = `[{"host":"` + promotionTestAdminHost + `","service":"admin","port":8081}]`
	}
	return promotionTestStack(t, labels)
}

func promotionStore(certificates ...*x509.Certificate) func() ([]*x509.Certificate, error) {
	return func() ([]*x509.Certificate, error) { return certificates, nil }
}

func TestPromotionModeOfAFirstReleaseIsLegacyEvenWithEveryCertificate(t *testing.T) {
	store := promotionStore(promotionValidCertificate(t, promotionTestDomain, promotionTestAdminHost))
	if got := selectRootPromotionMode(true, promotionPublishedStack(t, true), store, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("first release mode = %q, want legacy", got)
	}
}

// The 120 s floor protects cold starts, and a cold start does not depend on a
// certificate: an internal application and a TLS-off one keep it too.
func TestPromotionModeOfAFirstReleaseIsLegacyForInternalAndTLSOffApplications(t *testing.T) {
	for name, labels := range map[string]map[string]any{
		"internal": nil,
		"tls off":  {"dev.shuttle.domain": promotionTestDomain, "dev.shuttle.tls": config.TLSModeOff},
	} {
		t.Run(name, func(t *testing.T) {
			forbidden := func() ([]*x509.Certificate, error) {
				t.Fatal("a first release must not read the certificate store")
				return nil, nil
			}
			if got := selectRootPromotionMode(true, promotionTestStack(t, labels), forbidden, promotionTestNow); got != config.PromotionModeLegacy {
				t.Fatalf("first release mode = %q, want legacy", got)
			}
		})
	}
}

func TestPromotionModeIsLegacyWithoutACertificate(t *testing.T) {
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, false), promotionStore(), promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy: the edge has nothing for %s", got, promotionTestDomain)
	}
}

func TestPromotionModeIsLegacyForAnExpiredCertificate(t *testing.T) {
	store := promotionStore(promotionExpiredCertificate(t, promotionTestDomain))
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, false), store, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestPromotionModeIsLegacyForACertificateNotYetValid(t *testing.T) {
	store := promotionStore(promotionTestCertificate(t, promotionTestNow.Add(promotionTestDay), promotionTestNow.Add(91*promotionTestDay), promotionTestDomain))
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, false), store, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

// Still valid, but the edge's next move is an ACME renewal, which is exactly the
// exchange the capped budget has no room for.
func TestPromotionModeIsLegacyInsideTheRenewalWindow(t *testing.T) {
	store := promotionStore(promotionRenewingCertificate(t, promotionTestDomain))
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, false), store, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestPromotionModeLeavesTheRenewalWindowOpenOnlyForTheLastThird(t *testing.T) {
	// Of a 90-day lifetime the window is the last 30 days: a certificate with 31
	// days left is covered, one with 29 left is not.
	outside := promotionTestCertificate(t, promotionTestNow.Add(-59*promotionTestDay), promotionTestNow.Add(31*promotionTestDay), promotionTestDomain)
	inside := promotionTestCertificate(t, promotionTestNow.Add(-61*promotionTestDay), promotionTestNow.Add(29*promotionTestDay), promotionTestDomain)
	if !rootCertificateCovers(outside, promotionTestDomain, promotionTestNow) {
		t.Fatal("a certificate with 31 of 90 days left is outside the renewal window")
	}
	if rootCertificateCovers(inside, promotionTestDomain, promotionTestNow) {
		t.Fatal("a certificate with 29 of 90 days left is inside the renewal window")
	}
}

func TestPromotionModeIsLegacyWhenAHostRouteHostnameHasNoCertificate(t *testing.T) {
	store := promotionStore(promotionValidCertificate(t, promotionTestDomain))
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, true), store, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy: %s has no certificate", got, promotionTestAdminHost)
	}
}

func TestPromotionModeIsLegacyWhenAHostRouteCertificateIsExpired(t *testing.T) {
	store := promotionStore(
		promotionValidCertificate(t, promotionTestDomain),
		promotionExpiredCertificate(t, promotionTestAdminHost),
	)
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, true), store, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestPromotionModeIsCappedWhenEveryHostnameHasAValidCertificate(t *testing.T) {
	store := promotionStore(
		promotionValidCertificate(t, promotionTestDomain),
		promotionValidCertificate(t, promotionTestAdminHost),
	)
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, true), store, promotionTestNow); got != config.PromotionModeCapped {
		t.Fatalf("mode = %q, want capped", got)
	}
}

func TestPromotionModeIsCappedWhenOneCertificateNamesEveryHostname(t *testing.T) {
	store := promotionStore(promotionValidCertificate(t, promotionTestDomain, promotionTestAdminHost))
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, true), store, promotionTestNow); got != config.PromotionModeCapped {
		t.Fatalf("mode = %q, want capped", got)
	}
}

// A certificate that names another host covers nothing, however valid it is.
func TestPromotionModeIgnoresACertificateForAnotherHostname(t *testing.T) {
	store := promotionStore(promotionValidCertificate(t, "other.example.com"))
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, false), store, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestPromotionModeOfALaterInternalReleaseIsCappedWithoutReadingTheStore(t *testing.T) {
	forbidden := func() ([]*x509.Certificate, error) {
		t.Fatal("an internal application has no certificate to look for")
		return nil, nil
	}
	if got := selectRootPromotionMode(false, promotionTestStack(t, nil), forbidden, promotionTestNow); got != config.PromotionModeCapped {
		t.Fatalf("mode = %q, want capped", got)
	}
}

func TestPromotionModeOfALaterTLSOffReleaseIsCappedWithoutReadingTheStore(t *testing.T) {
	forbidden := func() ([]*x509.Certificate, error) {
		t.Fatal("a TLS-off application needs no certificate")
		return nil, nil
	}
	labels := map[string]any{
		"dev.shuttle.domain":      promotionTestDomain,
		"dev.shuttle.tls":         config.TLSModeOff,
		"dev.shuttle.host_routes": `[{"host":"` + promotionTestAdminHost + `"}]`,
	}
	if got := selectRootPromotionMode(false, promotionTestStack(t, labels), forbidden, promotionTestNow); got != config.PromotionModeCapped {
		t.Fatalf("mode = %q, want capped", got)
	}
}

func TestPromotionModeIsLegacyWhenTheCertificateStoreCannotBeRead(t *testing.T) {
	unreadable := func() ([]*x509.Certificate, error) { return nil, errors.New("permission denied") }
	if got := selectRootPromotionMode(false, promotionPublishedStack(t, true), unreadable, promotionTestNow); got != config.PromotionModeLegacy {
		t.Fatalf("mode = %q, want legacy", got)
	}
}

func TestPromotionModeIsLegacyForAStackItCannotReadHostnamesFrom(t *testing.T) {
	for name, payload := range map[string][]byte{
		"not yaml":              []byte("services: [unterminated"),
		"published without one": promotionTestStack(t, map[string]any{"dev.shuttle.domain": " "}),
		"route list not json":   promotionTestStack(t, map[string]any{"dev.shuttle.domain": promotionTestDomain, "dev.shuttle.host_routes": "{"}),
	} {
		t.Run(name, func(t *testing.T) {
			forbidden := func() ([]*x509.Certificate, error) {
				t.Fatal("no hostname was read, so there is nothing to look up")
				return nil, nil
			}
			if got := selectRootPromotionMode(false, payload, forbidden, promotionTestNow); got != config.PromotionModeLegacy {
				t.Fatalf("mode = %q, want legacy", got)
			}
		})
	}
}

func TestStackCertificateHostnamesAreTheDomainThenEveryHostRoute(t *testing.T) {
	got, err := rootStackCertificateHostnames(promotionPublishedStack(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{promotionTestDomain, promotionTestAdminHost}; !slices.Equal(got, want) {
		t.Fatalf("hostnames = %v, want %v", got, want)
	}
}

func TestStackCertificateHostnamesAreEmptyForInternalAndTLSOffStacks(t *testing.T) {
	for name, labels := range map[string]map[string]any{
		"internal": nil,
		"tls off":  {"dev.shuttle.domain": promotionTestDomain, "dev.shuttle.tls": config.TLSModeOff},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := rootStackCertificateHostnames(promotionTestStack(t, labels))
			if err != nil || len(got) != 0 {
				t.Fatalf("hostnames = %v, %v; want none", got, err)
			}
		})
	}
}
