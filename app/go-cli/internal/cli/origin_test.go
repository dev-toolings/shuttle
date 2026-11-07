package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

type originRoundTripper func(*http.Request) (*http.Response, error)

func (fn originRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestDirectOriginRequiresDNSPointingToVPS(t *testing.T) {
	originalLookup := lookupDomainIPs
	originalClient := publicOriginClient
	t.Cleanup(func() { lookupDomainIPs, publicOriginClient = originalLookup, originalClient })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.11")}, nil }
	cfg := &config.Config{Domain: "demo.example.com", Readiness: config.ReadinessConfig{HealthcheckPath: "/health"}}
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err == nil || !strings.Contains(err.Error(), "does not resolve directly") {
		t.Fatalf("expected DNS mismatch, got %v", err)
	}
}

func TestDirectOriginProvesPublicHTTPS(t *testing.T) {
	originalLookup := lookupDomainIPs
	originalClient := publicOriginClient
	t.Cleanup(func() { lookupDomainIPs, publicOriginClient = originalLookup, originalClient })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://demo.example.com/health" {
			t.Fatalf("unexpected public proof URL: %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})}
	cfg := &config.Config{Domain: "demo.example.com", Readiness: config.ReadinessConfig{HealthcheckPath: "/health"}}
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
}

func okResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}
}

func TestProxiedOriginFailsWithoutEdgeProxyOptIn(t *testing.T) {
	originalLookup := lookupDomainIPs
	t.Cleanup(func() { lookupDomainIPs = originalLookup })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	cfg := &config.Config{Domain: "api.example.com", Readiness: config.ReadinessConfig{HealthcheckPath: "/health"}}
	err := proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "deploy.edge_proxy") {
		t.Fatalf("expected an edge_proxy hint, got %v", err)
	}
}

func TestProxiedOriginProvesVPSAndEdge(t *testing.T) {
	originalLookup, originalClient, originalPinned, originalNonce := lookupDomainIPs, publicOriginClient, pinnedOriginClient, originProofNonce
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient, originProofNonce = originalLookup, originalClient, originalPinned, originalNonce
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	originProofNonce = func() string { return "cafe" }

	pinnedCalls, edgeCalls := 0, 0
	pinnedOriginClient = func(host string, endpoint originEndpoint) *pinnedOrigin {
		if host != "203.0.113.10" {
			t.Fatalf("pinned proof must dial the VPS, got %s", host)
		}
		// This configuration leaves caddy.tls_mode empty, which is the ACME
		// default, so the endpoint the proof derives must be the HTTPS one.
		// Together with the two URL assertions below, that is the guard that the
		// derived-endpoint change did not move the default topology.
		if endpoint != httpsOrigin {
			t.Fatalf("a default configuration must derive the HTTPS endpoint, got %+v", endpoint)
		}
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
			pinnedCalls++
			if request.URL.String() != "https://api.example.com/health" {
				t.Fatalf("pinned proof must keep the domain URL, got %s", request.URL)
			}
			return okResponse(), nil
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
		edgeCalls++
		if request.URL.String() != "https://api.example.com/health?shuttle_origin_proof=cafe" {
			t.Fatalf("edge proof must bust the CDN cache, got %s", request.URL)
		}
		if request.Header.Get("Cache-Control") != "no-cache" {
			t.Fatal("edge proof must ask the CDN to revalidate")
		}
		return okResponse(), nil
	})}

	cfg := &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Deploy:    config.Deploy{EdgeProxy: true, EdgeRanges: []string{"104.21.0.0/16"}},
	}
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if pinnedCalls != 1 || edgeCalls != 1 {
		t.Fatalf("expected one pinned and one edge call, got %d and %d", pinnedCalls, edgeCalls)
	}
}

func TestProxiedOriginRejectsAddressOutsideEdgeRanges(t *testing.T) {
	originalLookup := lookupDomainIPs
	t.Cleanup(func() { lookupDomainIPs = originalLookup })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.7")}, nil }
	cfg := &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Deploy:    config.Deploy{EdgeProxy: true, EdgeRanges: []string{"104.21.0.0/16"}},
	}
	err := proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "outside the declared") {
		t.Fatalf("expected an edge range rejection, got %v", err)
	}
}

func TestProxiedOriginFailsWhenVPSDoesNotServeTheDomain(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	// Counted, because a 502 is an HTTP answer: it proves the origin speaks this
	// scheme on this port, so the reality check must not build a second client
	// and go looking for a friendlier one. One construction, and only one.
	builds := 0
	pinnedOriginClient = func(string, originEndpoint) *pinnedOrigin {
		builds++
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("edge proof must not run once the VPS proof failed")
		return nil, nil
	})}
	cfg := &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		// The proof budget is a share of the promotion budget, so the floor
		// keeps this test fast without touching a package-level timeout.
		Deploy: config.Deploy{EdgeProxy: true, PromotionSLOSeconds: config.MinDeploySLOSeconds},
	}
	start := time.Now()
	err := proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "does not serve api.example.com") {
		t.Fatalf("expected a pinned origin failure, got %v", err)
	}
	if builds != 1 {
		t.Fatalf("an HTTP status must not send the proof to the other endpoint, got %d clients", builds)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("pinned proof exceeded its budget")
	}
}

// siteResponse is an answer from a site the shared edge rendered for the
// application: it carries the security baseline every generated fragment
// imports, which is what tells it apart from the edge's own catch-all answer.
func siteResponse(status int, statusText string, headers map[string]string) *http.Response {
	response := &http.Response{StatusCode: status, Status: statusText, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}
	response.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	response.Header.Set("X-Content-Type-Options", "nosniff")
	response.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	response.Header.Set("X-Frame-Options", "SAMEORIGIN")
	for name, value := range headers {
		response.Header.Set(name, value)
	}
	return response
}

// refusedDial is what a port nothing listens on produces, with the chain net
// and os build around the errno rather than a bare constant, because that chain
// is what the classification has to survive.
func refusedDial() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
}

// The endpoint a leg speaks is derived from caddy.tls_mode and from nothing
// else, and the public leg through an edge never follows it: that edge
// terminates TLS publicly whatever the origin serves behind it.
func TestOriginEndpointsFollowTheDeclaredTLSMode(t *testing.T) {
	for _, mode := range []string{"", "acme", "off", "  off  ", "  acme  "} {
		for _, edge := range []bool{false, true} {
			cfg := &config.Config{
				Caddy:  config.Caddy{TLSMode: mode},
				Deploy: config.Deploy{EdgeProxy: edge},
			}
			want := httpsOrigin
			if strings.TrimSpace(mode) == "off" {
				want = httpOrigin
			}
			if got := directOriginEndpoint(cfg); got != want {
				t.Errorf("tls_mode %q with edge_proxy %v must derive %+v, got %+v", mode, edge, want, got)
			}
			if got := edgeOriginEndpoint(); got != httpsOrigin {
				t.Errorf("tls_mode %q with edge_proxy %v: the public leg stays HTTPS, got %+v", mode, edge, got)
			}
			if got := alternateOriginEndpoint(want); got == want {
				t.Errorf("the reality check must probe the other endpoint, got %+v twice", got)
			}
		}
	}
}

// caddy.tls_mode "off" with public DNS on the VPS is a tunnel or an internal
// deployment: the origin serves plain HTTP and the proof has to speak it.
func TestDirectOriginProvesAPlaintextOriginOverHTTP(t *testing.T) {
	originalLookup, originalClient := lookupDomainIPs, publicOriginClient
	t.Cleanup(func() { lookupDomainIPs, publicOriginClient = originalLookup, originalClient })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "http://demo.example.com/health" {
			t.Fatalf("a plaintext origin must be proven over HTTP, got %s", request.URL)
		}
		return okResponse(), nil
	})}
	cfg := &config.Config{
		Domain:    "demo.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Caddy:     config.Caddy{TLSMode: config.TLSModeOff},
	}
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
}

// The reported failure, as a test. A plaintext origin behind a CDN was promoted
// and then declared dead because the pinned proof dialled the TLS port, on which
// Docker publishes but Caddy binds no listener. The two legs must now speak
// different protocols: the VPS its own, the edge HTTPS.
func TestProxiedOriginProvesAPlaintextVPSOverHTTP(t *testing.T) {
	originalLookup, originalClient, originalPinned, originalNonce := lookupDomainIPs, publicOriginClient, pinnedOriginClient, originProofNonce
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient, originProofNonce = originalLookup, originalClient, originalPinned, originalNonce
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	originProofNonce = func() string { return "cafe" }

	pinnedCalls, edgeCalls := 0, 0
	pinnedOriginClient = func(host string, endpoint originEndpoint) *pinnedOrigin {
		if endpoint != httpOrigin {
			t.Fatalf("caddy.tls_mode off must pin the HTTP endpoint, got %+v", endpoint)
		}
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
			pinnedCalls++
			if request.URL.String() != "http://api.example.com/health" {
				t.Fatalf("the VPS leg must speak the origin's own scheme, got %s", request.URL)
			}
			return okResponse(), nil
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
		edgeCalls++
		if request.URL.String() != "https://api.example.com/health?shuttle_origin_proof=cafe" {
			t.Fatalf("the public leg stays HTTPS whatever the origin speaks, got %s", request.URL)
		}
		return okResponse(), nil
	})}

	cfg := &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Caddy:     config.Caddy{TLSMode: config.TLSModeOff, TrustedCIDRs: []string{"192.0.2.222/32"}},
		Deploy:    config.Deploy{EdgeProxy: true, EdgeRanges: []string{"104.21.0.0/16"}},
	}
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if pinnedCalls != 1 || edgeCalls != 1 {
		t.Fatalf("expected one pinned and one edge call, got %d and %d", pinnedCalls, edgeCalls)
	}
}

// The configuration is a claim about what the origin serves, and reality gets to
// contradict it: a mode changed in config.json but never rendered onto the host
// leaves the origin speaking the other protocol, which is a drift to report and
// not a release to roll back.
func TestPinnedProofFallsBackWhenTheDeclaredSchemeIsRefused(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	builds := 0
	pinnedOriginClient = func(_ string, endpoint originEndpoint) *pinnedOrigin {
		builds++
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			if endpoint == httpsOrigin {
				return nil, refusedDial()
			}
			return siteResponse(http.StatusOK, "200 OK", nil), nil
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		return okResponse(), nil
	})}
	cfg := &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Caddy:     config.Caddy{TLSMode: config.TLSModeACME},
		Deploy:    config.Deploy{EdgeProxy: true, PromotionSLOSeconds: config.MinDeploySLOSeconds},
	}
	var err error
	warning := captureStderr(t, func() { err = proveDirectOrigin(cfg, "203.0.113.10") })
	if err != nil {
		t.Fatalf("an origin that answers the other scheme is a drift, not a dead release: %v", err)
	}
	if builds != 2 {
		t.Fatalf("expected the declared endpoint and one probe of the other, got %d clients", builds)
	}
	for _, want := range []string{"caddy.tls_mode", httpsOrigin.Scheme, httpOrigin.Scheme} {
		if !strings.Contains(warning, want) {
			t.Fatalf("the drift must name %q: %s", want, warning)
		}
	}
}

// The shared edge answers 200 with an empty body for every Host that matches no
// site, so a 2xx from a port the configuration did not name proves nothing on
// its own. The fallback has to see this application's own site or refuse.
func TestPinnedProofFallbackRefusesTheSharedEdgeCatchAll(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	pinnedOriginClient = func(_ string, endpoint originEndpoint) *pinnedOrigin {
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			if endpoint == httpsOrigin {
				return nil, refusedDial()
			}
			// Caddy's default handler: a bare 200, no site headers at all.
			return okResponse(), nil
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("the edge leg must not run once the VPS leg failed")
		return nil, nil
	})}
	cfg := &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Deploy:    config.Deploy{EdgeProxy: true, PromotionSLOSeconds: config.MinDeploySLOSeconds},
	}
	err := proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "matches no site") {
		t.Fatalf("a route fragment that was never written must still fail the proof, got %v", err)
	}
}

// The probe spends what the first attempt did not, never a share of its own:
// originProofBudgets already told the promotion what this leg costs.
func TestPinnedProofFallbackStaysInsideTheDirectBudget(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	builds := 0
	attempts := map[string]int{}
	pinnedOriginClient = func(_ string, endpoint originEndpoint) *pinnedOrigin {
		builds++
		scheme := endpoint.Scheme
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			attempts[scheme]++
			return nil, refusedDial()
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("the edge leg must not run once the VPS leg failed")
		return nil, nil
	})}
	cfg := &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Deploy:    config.Deploy{EdgeProxy: true, PromotionSLOSeconds: config.MinDeploySLOSeconds},
	}
	directBudget, _ := originProofBudgets(cfg, config.PromotionModeLegacy)
	start := time.Now()
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err == nil {
		t.Fatal("an origin that answers on neither endpoint must fail the proof")
	}
	// The wall clock alone cannot see the defect: at the smallest accepted
	// promotion budget the retry interval is a large fraction of the share, so
	// any slack wide enough to be stable is also wide enough to hide a doubled
	// budget. The attempt counts are what actually pin the invariant — the
	// fallback spends what the first leg left, so it can never outlast it.
	derived, alternate := directOriginEndpoint(cfg), alternateOriginEndpoint(directOriginEndpoint(cfg))
	if attempts[derived.Scheme] == 0 || attempts[alternate.Scheme] == 0 {
		t.Fatalf("both endpoints must be attempted, got %v", attempts)
	}
	if attempts[alternate.Scheme] > attempts[derived.Scheme] {
		t.Fatalf("the fallback got a share of its own instead of the remainder: %d attempts on %s against %d on %s", attempts[alternate.Scheme], alternate.Scheme, attempts[derived.Scheme], derived.Scheme)
	}
	if elapsed := time.Since(start); elapsed > directBudget+originProofRetryInterval {
		t.Fatalf("the pair must fit in the %s reserved for the direct proof, took %s", directBudget, elapsed)
	}
	if builds != 2 {
		t.Fatalf("expected exactly two clients, got %d", builds)
	}
}

// Without an edge, real clients speak the configured scheme: falling back would
// turn a genuine outage into a green deploy.
func TestDirectDNSProofNeverProbesTheOtherScheme(t *testing.T) {
	originalLookup, originalClient := lookupDomainIPs, publicOriginClient
	t.Cleanup(func() { lookupDomainIPs, publicOriginClient = originalLookup, originalClient })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	var seen []string
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
		seen = append(seen, request.URL.Scheme)
		return nil, refusedDial()
	})}
	cfg := &config.Config{
		Domain:    "demo.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Caddy:     config.Caddy{TLSMode: config.TLSModeOff},
		Deploy:    config.Deploy{PromotionSLOSeconds: config.MinDeploySLOSeconds},
	}
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err == nil {
		t.Fatal("a refused origin with no edge in front of it must fail the proof")
	}
	if len(seen) == 0 {
		t.Fatal("the proof must have made at least one attempt")
	}
	for _, scheme := range seen {
		if scheme != httpOrigin.Scheme {
			t.Fatalf("every attempt must speak the configured scheme, saw %q in %v", scheme, seen)
		}
	}
}

// gatedProxiedConfig is an edge-fronted application whose site restricts its
// clients, which is the shape that turns the operator's own access policy into
// the answer the proof collects.
func gatedProxiedConfig() *config.Config {
	return &config.Config{
		Domain:    "api.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/health"},
		Caddy: config.Caddy{
			TrustedCIDRs: []string{"192.0.2.0/24"},
			Headers:      map[string]string{"Content-Security-Policy": "default-src 'self'"},
		},
		Deploy: config.Deploy{EdgeProxy: true, PromotionSLOSeconds: config.MinDeploySLOSeconds},
	}
}

// The allow-list names the edge host, not the machine the operator deploys
// from, so the normal case is a 403. It proves the hostname reaches a site of
// this application that is up and enforcing the declared policy — and the public
// leg that follows proves the release itself.
func TestOriginProofAcceptsA403FromOutsideTheTrustedCIDRs(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	pinnedOriginClient = func(string, originEndpoint) *pinnedOrigin {
		// No address stored: the stub never dials, which is also what a proof
		// behind NAT cannot rule out, and both read as "outside".
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			return siteResponse(http.StatusForbidden, "403 Forbidden", map[string]string{"Content-Security-Policy": "default-src 'self'"}), nil
		})}}
	}
	edgeCalls := 0
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		edgeCalls++
		return okResponse(), nil
	})}
	var err error
	detail := captureStdout(t, func() { err = proveDirectOrigin(gatedProxiedConfig(), "203.0.113.10") })
	if err != nil {
		t.Fatalf("the operator's own allow-list refusing this machine is not a failed release: %v", err)
	}
	if edgeCalls != 1 {
		t.Fatalf("the public leg carries what the 403 could not prove, so it must run: %d calls", edgeCalls)
	}
	for _, want := range []string{"caddy.trusted_cidrs", "Proven", "Not proven"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("the acceptance must say what it proved and what it did not, %q missing from: %s", want, detail)
		}
	}
}

// Inside the declared networks the gate should have admitted the request, so a
// 403 is the release or the rendered route genuinely refusing.
func TestOriginProofFailsOnA403FromInsideTheTrustedCIDRs(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	pinnedOriginClient = func(string, originEndpoint) *pinnedOrigin {
		origin := &pinnedOrigin{}
		origin.localAddr.Store(&net.TCPAddr{IP: net.ParseIP("192.0.2.5")})
		origin.client = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			return siteResponse(http.StatusForbidden, "403 Forbidden", map[string]string{"Content-Security-Policy": "default-src 'self'"}), nil
		})}
		return origin
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("the edge leg must not run once the VPS leg failed")
		return nil, nil
	})}
	err := proveDirectOrigin(gatedProxiedConfig(), "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a 403 from inside the allow-list must roll the release back, got %v", err)
	}
	if !strings.Contains(err.Error(), "inside caddy.trusted_cidrs") {
		t.Fatalf("the error must name why this 403 was not the gate, got %v", err)
	}
}

// No allow-list declared, so nothing but the application explains a 403.
func TestOriginProofFailsOnA403WithoutTrustedCIDRs(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	pinnedOriginClient = func(string, originEndpoint) *pinnedOrigin {
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			return siteResponse(http.StatusForbidden, "403 Forbidden", nil), nil
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("the edge leg must not run once the VPS leg failed")
		return nil, nil
	})}
	cfg := gatedProxiedConfig()
	cfg.Caddy.TrustedCIDRs = nil
	cfg.Caddy.Headers = nil
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("an undeclared 403 must fail the proof exactly as it always has, got %v", err)
	}
}

// With no public leg to observe the release, accepting a 403 would leave nothing
// looking at the promoted release at all: the gate answers before every
// reverse_proxy, so a stack that never converged returns the same 403.
func TestOriginProofFailsOnA403WhenNoPublicProofFollows(t *testing.T) {
	originalLookup, originalClient := lookupDomainIPs, publicOriginClient
	t.Cleanup(func() { lookupDomainIPs, publicOriginClient = originalLookup, originalClient })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		return siteResponse(http.StatusForbidden, "403 Forbidden", map[string]string{"Content-Security-Policy": "default-src 'self'"}), nil
	})}
	cfg := gatedProxiedConfig()
	cfg.Deploy.EdgeProxy = false
	err := proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a 403 with nothing to compensate it must fail the proof, got %v", err)
	}
	if !strings.Contains(err.Error(), "caddy.trusted_cidrs") {
		t.Fatalf("the failure must name the setting that produced the answer, got %v", err)
	}
}

// "Inside" is the only branch the local address can assert. Everything else,
// including having observed no address at all, is "outside" — which is why
// "outside" is the tolerant branch and not the trusting one.
func TestOriginVantageNeedsEvidenceToClaimInside(t *testing.T) {
	gated := &config.Config{Caddy: config.Caddy{TrustedCIDRs: []string{"192.0.2.0/24", "not-a-cidr"}}}
	ungated := &config.Config{}
	if got := originVantageFor(ungated, net.ParseIP("192.0.2.5")); got != vantageUngated {
		t.Errorf("no allow-list declared is the ungated verdict, got %v", got)
	}
	// The NAT case: this machine's side of the socket is a private address the
	// origin never sees, and a proof that never dialled has no address at all.
	// Neither can claim to be inside.
	if got := originVantageFor(gated, nil); got != vantageOutside {
		t.Errorf("no observed address cannot claim to be inside, got %v", got)
	}
	if got := originVantageFor(gated, net.ParseIP("192.0.2.5")); got != vantageInside {
		t.Errorf("an address in the allow-list is inside, got %v", got)
	}
	if got := originVantageFor(gated, net.ParseIP("198.51.100.9")); got != vantageOutside {
		t.Errorf("an address outside the allow-list is outside, got %v", got)
	}
}

// The reality check is an allow-list of failures that mean "nothing speaks this
// scheme on this port". Everything else answers false, because the fallback's
// success is a pass.
func TestOriginUnreachableIsNarrow(t *testing.T) {
	certErr := &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"refused", &url.Error{Op: "Get", Err: refusedDial()}, true},
		{"reset", &url.Error{Op: "Get", Err: &net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}}, true},
		{"broken pipe", &url.Error{Op: "Get", Err: &net.OpError{Op: "write", Err: &os.SyscallError{Syscall: "write", Err: syscall.EPIPE}}}, true},
		{"plaintext answer to a TLS request", &url.Error{Op: "Get", Err: http.ErrSchemeMismatch}, true},
		{"an HTTP status", &originProofError{Endpoint: httpsOrigin, Status: "502 Bad Gateway"}, false},
		{"a 403 the operator declared", &originProofError{Endpoint: httpOrigin, Status: "403 Forbidden"}, false},
		{"the proof's own deadline", &url.Error{Op: "Get", Err: context.DeadlineExceeded}, false},
		{"a dial timeout", &url.Error{Op: "Get", Err: &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}}, false},
		// A certificate that does not validate is evidence the origin does speak
		// the configured scheme. Downgrading to plaintext there would hide a
		// certificate a strict CDN would refuse too.
		{"a certificate that does not validate", &url.Error{Op: "Get", Err: certErr}, false},
		{"a transport error nothing classifies", &url.Error{Op: "Get", Err: errors.New("unexpected EOF")}, false},
		{"a routing failure", &url.Error{Op: "Get", Err: &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.EHOSTUNREACH}}}, false},
	}
	for _, testCase := range cases {
		if got := originUnreachable(testCase.err); got != testCase.want {
			t.Errorf("%s: want %v, got %v (%v)", testCase.name, testCase.want, got, testCase.err)
		}
	}
	// The transport error survives structured, so a caller can still reach the
	// errno the classification used.
	wrapped := &originProofError{Endpoint: httpOrigin, Transport: refusedDial()}
	if !errors.Is(wrapped, syscall.ECONNREFUSED) {
		t.Error("the proof error must keep the transport chain reachable")
	}
	if !strings.Contains(wrapped.Error(), httpOrigin.Scheme) {
		t.Errorf("the failure must name the scheme actually spoken, got %q", wrapped.Error())
	}
}

// The opposite drift to the one the reality check catches: an origin configured
// plaintext but serving ACME answers the plain port with a redirect the client
// silently follows, so no transport error is ever raised and a perfectly healthy
// 200 arrives from somewhere else.
func TestOriginProofReportsASchemeRedirectAsDrift(t *testing.T) {
	served, err := url.Parse("https://demo.example.com/health")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		response := okResponse()
		response.Request = &http.Request{URL: served}
		return response, nil
	})}
	proof := originProof{Endpoint: httpOrigin, Hostname: "demo.example.com", Path: "/health", Budget: time.Second}
	var proofErr error
	warning := captureStderr(t, func() { proofErr = runOriginProof(client, proof) })
	if proofErr != nil {
		t.Fatalf("a redirect to the other scheme is a drift to report, not a failure: %v", proofErr)
	}
	for _, want := range []string{httpOrigin.Scheme, httpsOrigin.Scheme, "caddy.tls_mode"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("the drift must name %q: %s", want, warning)
		}
	}

	// net/http populates Response.Request in its own transport and nowhere else,
	// so every stubbed RoundTripper in this package returns nil there. Reading it
	// unguarded would panic the whole package.
	bare := &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) { return okResponse(), nil })}
	if err := runOriginProof(bare, proof); err != nil {
		t.Fatalf("an answer with no Request attached must still pass: %v", err)
	}
}

// The derived endpoint binds the first hop only unless the redirect policy says
// otherwise: this transport dials the VPS whatever the URL says, so an absolute
// "Location: https://..." — what every framework forcing HTTPS behind a CDN
// emits — would send the next hop to the port a plaintext origin refuses.
func TestPinnedClientKeepsTheDerivedEndpointAcrossRedirects(t *testing.T) {
	pinned := pinnedOriginClient("203.0.113.10", httpOrigin)
	target, err := url.Parse("https://demo.example.com:443/app")
	if err != nil {
		t.Fatal(err)
	}
	first, err := url.Parse("http://demo.example.com/?shuttle_origin_proof=cafe")
	if err != nil {
		t.Fatal(err)
	}
	hop := &http.Request{URL: target}
	if err := pinned.Client().CheckRedirect(hop, []*http.Request{{URL: first}}); err != nil {
		t.Fatal(err)
	}
	if hop.URL.String() != "http://demo.example.com/app?shuttle_origin_proof=cafe" {
		t.Fatalf("every hop must stay on the derived endpoint and keep the nonce, got %s", hop.URL)
	}
	if pinned.LocalIP() != nil {
		t.Fatal("a client that never dialled must report no address")
	}
}

// The cache-busting guarantee holds for the first hop only unless the nonce is
// carried across the chain: the 200 that satisfies the proof would otherwise be
// fetched from a URL the CDN was free to answer from cache.
func TestEdgeProofKeepsTheCacheBusterAcrossRedirects(t *testing.T) {
	first, err := url.Parse("https://demo.example.com/?shuttle_origin_proof=cafe")
	if err != nil {
		t.Fatal(err)
	}
	next, err := url.Parse("https://demo.example.com/login")
	if err != nil {
		t.Fatal(err)
	}
	hop := &http.Request{URL: next}
	if err := keepOriginProofNonce(hop, []*http.Request{{URL: first}}); err != nil {
		t.Fatal(err)
	}
	if hop.URL.Query().Get("shuttle_origin_proof") != "cafe" {
		t.Fatalf("the nonce must survive the redirect, got %s", hop.URL)
	}
	via := make([]*http.Request, 10)
	if err := keepOriginProofNonce(&http.Request{URL: next}, via); err == nil {
		t.Fatal("the redirect chain must still be bounded")
	}
}

// Every other test in this file replaces the pinned client with a RoundTripper,
// which never opens a socket — so the recording dialler, and the classification
// that reads real operating-system errors, would otherwise be the only code here
// with no coverage at all. These two use a real listener for exactly that.
func TestPinnedClientRecordsTheAddressItDialledFrom(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pinned := pinnedOriginClient(address.Hostname(), httpOrigin)
	// The hostname stays in the URL and in the Host header while the transport
	// dials the address it was pinned to, which is the whole point of this
	// client; the explicit port is what lets a test stand in for the endpoint's.
	request, err := http.NewRequest(http.MethodGet, "http://demo.example.com:"+address.Port()+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := pinned.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	local := pinned.LocalIP()
	if local == nil {
		t.Fatal("a completed dial must leave the address the vantage is measured from")
	}
	inside := &config.Config{Caddy: config.Caddy{TrustedCIDRs: []string{"127.0.0.0/8", "::1/128"}}}
	if got := originVantageFor(inside, local); got != vantageInside {
		t.Fatalf("an allow-list containing the address we dialled from is inside, got %v (%s)", got, local)
	}
	outside := &config.Config{Caddy: config.Caddy{TrustedCIDRs: []string{"192.0.2.0/24"}}}
	if got := originVantageFor(outside, local); got != vantageOutside {
		t.Fatalf("an allow-list that excludes it is outside, got %v (%s)", got, local)
	}
}

func TestPinnedClientReportsARefusedPortAsUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	// Closed before the request: this is the shape of the reported failure, a
	// port that is published and answers nothing.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	pinned := pinnedOriginClient("127.0.0.1", httpOrigin)
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://demo.example.com:%d/health", port), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := pinned.Client().Do(request)
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("a closed port must not answer")
	}
	if !originUnreachable(err) {
		t.Fatalf("a refused port is the one condition that justifies probing the other endpoint, got %v", err)
	}
	if pinned.LocalIP() != nil {
		t.Fatal("a dial that never completed records no address, which reads as the conservative vantage")
	}
}

// The permissive branches of the proof stand on this: the shared edge answers
// 200 with an empty body for every Host that matches no site, so a status alone
// cannot tell "the fragment we wrote is serving" from "the edge is up and this
// hostname reached nothing".
func TestOriginSiteEvidenceSeparatesTheSiteFromTheCatchAll(t *testing.T) {
	declared := []string{"Content-Security-Policy", "Permissions-Policy"}
	catchAll := &http.Response{Header: make(http.Header)}
	catchAll.Header.Set("Server", "Caddy")
	if originSiteEvidence(catchAll, declared) || originSiteEvidence(catchAll, nil) {
		t.Fatal("the edge's own answer must never pass as this application's site")
	}
	if !originSiteEvidence(siteResponse(http.StatusOK, "200 OK", nil), nil) {
		t.Fatal("the baseline every rendered fragment imports is evidence on its own")
	}
	onlyDeclared := &http.Response{Header: make(http.Header)}
	onlyDeclared.Header.Set("Content-Security-Policy", "default-src 'self'")
	onlyDeclared.Header.Set("Permissions-Policy", "camera=()")
	if !originSiteEvidence(onlyDeclared, declared) {
		t.Fatal("this hostname's own declared headers are evidence on their own")
	}
	partial := &http.Response{Header: make(http.Header)}
	partial.Header.Set("Content-Type", "text/plain")
	if originSiteEvidence(partial, declared) {
		t.Fatal("an unrelated header proves nothing about which site answered")
	}
}

// The whole reported failure, end to end and in one place: a plaintext origin
// behind a CDN, restricted to the edge host's network, proven from a machine
// that network does not contain. Before this file was rewritten the deploy died
// twice over — first dialling the TLS port of an origin that binds no listener
// there, then, had the scheme been fixed alone, on the 403 the operator's own
// allow-list produces. Both legs, in the order the promotion runs them.
func TestPlaintextOriginBehindAnEdgeWithATrustedClientListDeploys(t *testing.T) {
	originalLookup, originalClient, originalPinned, originalNonce := lookupDomainIPs, publicOriginClient, pinnedOriginClient, originProofNonce
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient, originProofNonce = originalLookup, originalClient, originalPinned, originalNonce
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	originProofNonce = func() string { return "cafe" }

	builds, pinnedURL := 0, ""
	pinnedOriginClient = func(_ string, endpoint originEndpoint) *pinnedOrigin {
		builds++
		origin := &pinnedOrigin{}
		// The operator's workstation, which the allow-list does not contain: the
		// declared network is the edge host's, as it is meant to be.
		origin.localAddr.Store(&net.TCPAddr{IP: net.ParseIP("192.0.2.2")})
		origin.client = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
			if endpoint != httpOrigin {
				t.Fatalf("a plaintext origin must be dialled over HTTP, got %+v", endpoint)
			}
			pinnedURL = request.URL.String()
			return siteResponse(http.StatusForbidden, "403 Forbidden", map[string]string{
				"Content-Security-Policy": "default-src 'self'",
				"Permissions-Policy":      "camera=()",
			}), nil
		})}
		return origin
	}
	edgeURL := ""
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
		edgeURL = request.URL.String()
		return okResponse(), nil
	})}

	cfg := &config.Config{
		Domain:    "app.example.com",
		Readiness: config.ReadinessConfig{HealthcheckPath: "/"},
		Caddy: config.Caddy{
			TLSMode:      config.TLSModeOff,
			TrustedCIDRs: []string{"198.51.100.222/32"},
			Headers: map[string]string{
				"Content-Security-Policy": "default-src 'self'",
				"Permissions-Policy":      "camera=()",
			},
		},
		Deploy: config.Deploy{EdgeProxy: true, PromotionSLOSeconds: 120},
	}
	var err error
	detail := captureStdout(t, func() { err = proveDirectOrigin(cfg, "203.0.113.10") })
	if err != nil {
		t.Fatalf("this topology is documented as supported and must promote: %v", err)
	}
	if builds != 1 {
		t.Fatalf("the derived endpoint answered, so nothing must probe the other one: %d clients", builds)
	}
	if pinnedURL != "http://app.example.com/" {
		t.Fatalf("the VPS leg speaks the origin's own scheme, got %q", pinnedURL)
	}
	if edgeURL != "https://app.example.com/?shuttle_origin_proof=cafe" {
		t.Fatalf("the public leg stays HTTPS and busts the cache, got %q", edgeURL)
	}
	if !strings.Contains(detail, "over http") {
		t.Fatalf("the log must name the scheme it proved the VPS over: %s", detail)
	}
}

// The site-evidence guard is the only thing standing between an accepted 403
// and any other 403 answered on that port — the shared edge's catch-all, a
// neighbouring application, an intermediate appliance. Without it, declaring
// caddy.trusted_cidrs would turn "something refused us" into a green deploy.
func TestOriginProofRefusesA403WithoutThisSitesHeaders(t *testing.T) {
	originalLookup, originalClient, originalPinned := lookupDomainIPs, publicOriginClient, pinnedOriginClient
	t.Cleanup(func() {
		lookupDomainIPs, publicOriginClient, pinnedOriginClient = originalLookup, originalClient, originalPinned
	})
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("104.21.85.98")}, nil }
	pinnedOriginClient = func(string, originEndpoint) *pinnedOrigin {
		// Outside the allow-list, like the accepted case — but the answer
		// carries none of the headers the shared edge renders, so it did not
		// come from the fragment written for this application.
		return &pinnedOrigin{client: &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden",
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		})}}
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("the edge leg must not run once the VPS leg failed")
		return nil, nil
	})}
	err := proveDirectOrigin(gatedProxiedConfig(), "203.0.113.10")
	if err == nil {
		t.Fatal("a 403 carrying none of this site's headers is not the gate answering and must roll the release back")
	}
	if !strings.Contains(err.Error(), "headers the shared edge renders") {
		t.Fatalf("the error must name why this 403 was not accepted, got %v", err)
	}
}

// keepOriginProofNonce is wired onto publicOriginClient and nowhere else, and
// the public leg is the only one that busts the cache — so testing the helper in
// isolation leaves the wiring itself unguarded. This drives the real client
// through a real redirect.
func TestPublicOriginClientCarriesTheNonceThroughARealRedirect(t *testing.T) {
	var landed string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" {
			// A Location without the query, which is what an application's own
			// redirect answers and what silently drops the nonce.
			http.Redirect(writer, request, "/landed", http.StatusFound)
			return
		}
		landed = request.URL.RawQuery
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	response, err := publicOriginClient.Get(cacheBustedURL(server.URL+"/", true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if landed == "" {
		t.Fatal("the redirect target was reached without the cache buster: publicOriginClient lost its CheckRedirect")
	}
	if !strings.Contains(landed, "shuttle_origin_proof=") {
		t.Fatalf("the nonce must survive the hop the client follows, got %q", landed)
	}
}
