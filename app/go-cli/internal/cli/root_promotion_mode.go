package cli

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// This file decides, on the helper, which promotion mode a stack-apply runs in
// (config.PromotionMode). It is in the shared half of the helper because the
// decision is pure and tested on every platform; reading the edge's certificate
// store is the Linux half's job (root_promotion_mode_linux.go).

// caddyRenewalWindowDivisor: Caddy (CertMagic) starts renewing a certificate
// when the last third of its lifetime begins. A certificate inside that window is
// still served, but its renewal is an ACME exchange the edge will make next, and
// an ACME exchange is exactly what the capped mode has no budget for.
const caddyRenewalWindowDivisor = 3

// rootCertificateCovers reports whether a certificate from the edge's store lets
// the edge serve hostname without asking an ACME server for anything: it names
// the host (wildcards included), it is valid now, and it is not inside Caddy's
// renewal window.
func rootCertificateCovers(certificate *x509.Certificate, hostname string, now time.Time) bool {
	if certificate == nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return false
	}
	lifetime := certificate.NotAfter.Sub(certificate.NotBefore)
	if now.After(certificate.NotAfter.Add(-lifetime / caddyRenewalWindowDivisor)) {
		return false
	}
	return certificate.VerifyHostname(hostname) == nil
}

// rootStackCertificateHostnames lists the hostnames a signed stack asks the edge
// to serve over TLS: the primary domain, then every caddy.host_routes host, read
// from the labels of the published service like the Caddy fragment is. An
// internal application publishes nothing, and an application with
// caddy.tls_mode: off is served over plain HTTP by an edge that needs no
// certificate for it, so both return an empty list.
func rootStackCertificateHostnames(payload []byte) ([]string, error) {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, err
	}
	service, labels, err := serviceWithLabel(document, "dev.shuttle.domain")
	if err != nil {
		return nil, err
	}
	if service == "" {
		return nil, nil
	}
	if strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.tls"])) == config.TLSModeOff {
		return nil, nil
	}
	domain := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.domain"]))
	if domain == "" || domain == "<nil>" {
		return nil, errors.New("the published service declares no domain")
	}
	hostnames := []string{domain}
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.host_routes"]))
	if raw == "" || raw == "<nil>" {
		return hostnames, nil
	}
	var routes []struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal([]byte(raw), &routes); err != nil {
		return nil, errors.New("route host list is not valid JSON")
	}
	for _, route := range routes {
		if host := strings.TrimSpace(route.Host); host != "" {
			hostnames = append(hostnames, host)
		}
	}
	return hostnames, nil
}

// selectRootPromotionMode chooses the mode of one stack-apply, before the stack
// is deployed.
//
// Legacy is the answer unless the cheaper mode is proven safe:
//   - every first release of an application, internal or not, TLS or not. The
//     120 s convergence floor protects cold image pulls and first starts (a
//     RabbitMQ still Starting at 16.5 s on 2026-10-28), and those do not depend
//     on certificates at all;
//   - a stack the helper cannot read hostnames from;
//   - an edge store that cannot be read;
//   - any hostname of the stack without a covering certificate in the store: the
//     edge will request one from an ACME server when the route is loaded, and
//     the origin proof is what waits for it.
//
// Capped is the answer for a later release when the stack publishes nothing over
// TLS, or when every hostname has a covering certificate.
func selectRootPromotionMode(firstRelease bool, payload []byte, readCertificates func() ([]*x509.Certificate, error), now time.Time) config.PromotionMode {
	if firstRelease {
		return config.PromotionModeLegacy
	}
	hostnames, err := rootStackCertificateHostnames(payload)
	if err != nil {
		return config.PromotionModeLegacy
	}
	if len(hostnames) == 0 {
		return config.PromotionModeCapped
	}
	certificates, err := readCertificates()
	if err != nil {
		return config.PromotionModeLegacy
	}
	for _, hostname := range hostnames {
		covered := false
		for _, certificate := range certificates {
			if rootCertificateCovers(certificate, hostname, now) {
				covered = true
				break
			}
		}
		if !covered {
			return config.PromotionModeLegacy
		}
	}
	return config.PromotionModeCapped
}
