package cli

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
)

const originProofUserAgent = "shuttle-origin-proof/2"

// originProofRetryInterval is how long a leg waits between two attempts, and it
// is clamped to whatever is left of that leg's deadline so a retry can never
// outlive the share the promotion budget reserved for it. Named rather than
// inlined because the fallback's budget is the remainder of the pair's deadline:
// the interval is the granularity at which that remainder is spent, so a test
// that bounds the pair has to bound it in the same unit.
const originProofRetryInterval = 500 * time.Millisecond

// originProofNonceParam is the query key that makes an edge attempt a cache
// miss. It is named once because the redirect policy has to recognise it again
// on every hop; see keepOriginProofNonce.
const originProofNonceParam = "shuttle_origin_proof"

// originEndpoint is the (scheme, port) pair one leg of the proof speaks.
//
// It exists so that httpsOrigin and httpOrigin below are the only two places in
// this package where a scheme or a port is written down at all. Everything else
// carries an endpoint value, which means the answer to "what does this origin
// serve" is derived from configuration exactly once. Before this type, the
// scheme was a literal inside a URL builder shared by every leg and the port was
// a literal inside a dialler, so an origin the operator had declared plaintext
// was proven on the TLS port: the promotion succeeded, the proof dialled a port
// Caddy had bound no listener for, and a healthy release was rolled back with a
// message blaming HTTPS.
type originEndpoint struct {
	Scheme string
	Port   string
}

var (
	httpsOrigin = originEndpoint{Scheme: "https", Port: "443"}
	httpOrigin  = originEndpoint{Scheme: "http", Port: "80"}
)

func (endpoint originEndpoint) url(hostname, path string) string {
	return endpoint.Scheme + "://" + hostname + path
}

// String renders the scheme, so every %s in an error or a log line names the
// protocol that was actually spoken rather than the one this file used to
// assume.
func (endpoint originEndpoint) String() string { return endpoint.Scheme }

// directOriginEndpoint is the hop the VPS itself serves for this application:
// the one the pinned proof dials, and the one public DNS reaches when no edge
// fronts the origin.
//
// It takes the whole configuration and not a hostname deliberately.
// caddy.host_routes has no tls_mode field and the root helper renders one scheme
// for the domain's site and for every host route alike, so the effective mode is
// a property of the application. Accepting a hostname here would advertise a
// per-hostname mode the renderer cannot produce, and the proof would then be
// testing a topology that does not exist.
func directOriginEndpoint(cfg *config.Config) originEndpoint {
	if cfg.EffectiveTLSMode() == config.TLSModeOff {
		return httpOrigin
	}
	return httpsOrigin
}

// edgeOriginEndpoint is the hop the public hostname serves when a CDN, a WAF or
// a tunnel fronts the origin. It is unconditional: that edge terminates TLS
// publicly whatever the origin speaks behind it, which is precisely why
// caddy.tls_mode "off" is a supported topology. The direct and the public legs
// therefore cannot share one endpoint, and this package offers no single builder
// that could be pointed at both by accident.
func edgeOriginEndpoint() originEndpoint { return httpsOrigin }

// alternateOriginEndpoint is the other member of the pair. It exists only for
// the reality check in proveOriginFromVPS: a derived endpoint that answers
// nothing below the HTTP layer is a claim about the origin that reality can
// contradict, and the contradiction is worth measuring rather than reporting as
// a dead release.
func alternateOriginEndpoint(endpoint originEndpoint) originEndpoint {
	if endpoint == httpOrigin {
		return httpsOrigin
	}
	return httpOrigin
}

// shuttleSecurityHeaders are the response headers every site the shared edge
// renders for an application carries, because every generated site fragment
// opens with `import shuttle_security` and that snippet is a header block (see
// caddyfileContent). The shared edge's own catch-all — the empty 200 Caddy
// answers for a Host that matches no site — carries none of them.
//
// That difference is the only application-agnostic evidence available to tell
// "this hostname is served by the fragment we just wrote" from "the edge is up
// and this hostname matched nothing", and the two are indistinguishable by
// status code alone: both are 200. Any permissive branch added below has to
// stand on it, or the proof would accept the exact failure it was built to
// catch — a route fragment that was never written, or written and never loaded.
var shuttleSecurityHeaders = []string{
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"X-Frame-Options",
}

// publicOriginClient reaches the hostname the way a visitor does: ordinary DNS,
// the operator's proxy environment, and whatever sits in front of the origin.
var publicOriginClient = &http.Client{Timeout: 4 * time.Second, CheckRedirect: keepOriginProofNonce}
var lookupDomainIPs = net.LookupIP

// keepOriginProofNonce carries the cache-busting query across a redirect chain.
//
// Without it the guarantee cacheBustedURL states is void for any health path
// that redirects: the first hop carries the nonce, the Location the application
// answers with does not, and the 200 that satisfies the proof is fetched from a
// URL a CDN was free to serve from cache — which is exactly the stale response
// from the previous release the nonce exists to exclude.
func keepOriginProofNonce(request *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) == 0 {
		return nil
	}
	nonce := via[0].URL.Query().Get(originProofNonceParam)
	if nonce == "" {
		return nil
	}
	query := request.URL.Query()
	if query.Get(originProofNonceParam) != "" {
		return nil
	}
	query.Set(originProofNonceParam, nonce)
	request.URL.RawQuery = query.Encode()
	return nil
}

// pinnedOrigin is the client that dials one VPS address, together with the
// address this machine ended up dialling from. The second half is what lets the
// proof measure where it stands relative to caddy.trusted_cidrs instead of
// assuming it; see originVantageFor.
type pinnedOrigin struct {
	client    *http.Client
	localAddr atomic.Pointer[net.TCPAddr]
}

func (origin *pinnedOrigin) Client() *http.Client {
	if origin == nil {
		return nil
	}
	return origin.client
}

// LocalIP is the address of the last connection this client actually opened, or
// nil when no dial was observed. Nil is not an error: it is the honest answer
// for a connection that never got past the SYN, and every caller has to treat it
// as "we could not establish where we stand".
func (origin *pinnedOrigin) LocalIP() net.IP {
	if origin == nil {
		return nil
	}
	local := origin.localAddr.Load()
	if local == nil {
		return nil
	}
	return local.IP
}

// pinnedOriginClient dials the VPS address for every request while keeping the
// application hostname in the Host header — and in the TLS SNI when the derived
// endpoint is an HTTPS one. Behind a CDN it is the only way to prove that this
// VPS, and not an edge cache, serves the promoted release for that hostname.
//
// The endpoint travels in rather than being decided here: the dial fallback used
// to be a literal 443, which net/http rarely reaches because it fills the
// scheme's default port first, but which silently dialled the TLS port on an
// origin the operator had declared plaintext when it did. A safety net that
// contradicts the configuration is not a safety net.
var pinnedOriginClient = func(host string, endpoint originEndpoint) *pinnedOrigin {
	origin := &pinnedOrigin{}
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil || port == "" {
				port = endpoint.Port
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
			if err != nil {
				return nil, err
			}
			// Recorded here, after the connection is established and before the
			// TLS handshake runs, because the two failures either side of this
			// line have to read differently. A refused or reset port fails above
			// and leaves the address nil, which the vantage code reads as "we
			// cannot claim to be inside the allow-list" — the conservative
			// answer. An HTTPS endpoint that turns out to be plaintext fails
			// below, during the handshake, and the address is still worth having.
			//
			// atomic.Pointer and not a captured variable: net/http dials on a
			// goroutine of its own while the proof's retry loop reads from the
			// caller's, so a plain field is a data race the race detector would
			// fail — for a value whose only useful semantics are "the most
			// recent dial", which is what last-writer-wins gives, every dial in
			// one proof having the same destination.
			if local, ok := conn.LocalAddr().(*net.TCPAddr); ok {
				origin.localAddr.Store(local)
			}
			return conn, nil
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 4 * time.Second,
		// Proxy stays nil, unlike the public client's: a proxy between this
		// process and the VPS would defeat the pinning outright, and a proof
		// that measured the proxy would be a proof of nothing.
		Proxy: nil,
	}
	origin.client = &http.Client{
		Timeout:   6 * time.Second,
		Transport: transport,
		// The derived endpoint would otherwise bind the first hop only. This
		// transport dials the VPS whatever the URL says, so it is the URL's
		// scheme that picks the port: an application answering the proof with an
		// absolute "Location: https://<host>/" — the default posture of every
		// framework that forces HTTPS when it sits behind a CDN — would send the
		// next hop to the TLS port, which on a plaintext origin is the port that
		// refuses, and the proof would produce the very failure it exists to
		// prevent. Every hop is therefore rewritten back onto the endpoint the
		// configuration derived, on the same address the first hop was pinned to.
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if err := keepOriginProofNonce(request, via); err != nil {
				return err
			}
			request.URL.Scheme = endpoint.Scheme
			request.URL.Host = request.URL.Hostname()
			return nil
		},
	}
	return origin
}

// originProofBudgets splits the share of the promotion budget reserved for the
// origin proof between the two calls that make it up.
//
// It is derived instead of constant because the proof runs inside a promotion
// the command is timing: a fixed 30 s direct proof plus a fixed 20 s edge proof
// authorised more waiting here alone than the whole 30 s budget the deploy
// advertised. When no edge fronts the origin the direct proof gets the entire
// share; with an edge, two thirds go to the VPS — the call that actually proves
// the promoted release — and one third to the single uncached edge request. The
// reality-check probe of proveOriginFromVPS is spent inside the direct share,
// never beside it, so this split remains the whole cost of the proof.
//
// Compose keeps DeployWaits and the two-thirds split. A Swarm promotion spends the
// share of the mode the helper reported (see config.SwarmWaits): in the capped
// mode the share is at most 10 s, so the edge request is not left a third of
// it. It keeps at least 6 s, taken from the direct share (config.EdgeRequestFloor).
func originProofBudgets(cfg *config.Config, mode config.PromotionMode) (direct, edge time.Duration) {
	waits := promotionWaitsFor(cfg, mode)
	if cfg.UsesCompose() {
		share := waits.OriginProof
		if !cfg.Deploy.EdgeProxy {
			return share, 0
		}
		return share * 2 / 3, share / 3
	}
	return config.SwarmOriginProofSplit(waits, mode, cfg.Deploy.EdgeProxy)
}

// promotionWaitsFor is how the client spends the promotion budget once the
// stack is applied: DeployWaits under Compose, whose behaviour DEV-DEPL-83 does
// not touch, and the shares of the helper's promotion mode under Swarm.
func promotionWaitsFor(cfg *config.Config, mode config.PromotionMode) config.DeployWaitBudget {
	if cfg.UsesCompose() {
		return config.DeployWaits(cfg.Deploy.PromotionSLOSeconds)
	}
	return config.SwarmWaits(cfg.Deploy.PromotionSLOSeconds, mode)
}

var originProofNonce = func() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

// proveDirectOrigin verifies that the promoted release is the one answering on
// the application domain. When public DNS points at the VPS the proof is a
// single call over the scheme the origin serves. When a CDN/WAF fronts the
// origin (deploy.edge_proxy), the proof becomes two calls that deliberately do
// not speak the same protocol: the VPS itself, dialled by IP over the endpoint
// caddy.tls_mode derives, and the public edge over HTTPS with a cache-busting
// request, because the edge terminates TLS publicly whatever the origin speaks.
func proveDirectOrigin(cfg *config.Config, host string) error {
	return proveDirectOriginInMode(cfg, host, config.PromotionModeLegacy)
}

// proveDirectOriginInMode is proveDirectOrigin for a Swarm promotion that ran in
// the given mode: the proof's budget is the origin-proof share of that mode.
func proveDirectOriginInMode(cfg *config.Config, host string, mode config.PromotionMode) error {
	if cfg.IsInternal() {
		// Nothing is published, so there is no origin to prove. Returning early
		// is what keeps an internal deploy from failing on a check whose premise
		// — a public hostname — the operator deliberately did not accept.
		return nil
	}
	domain := domainString(cfg.Domain)
	originIP := net.ParseIP(host)
	if domain == "" || originIP == nil {
		return errors.New("origin proof requires a literal VPS IP and one application domain")
	}
	path := cfg.Readiness.HealthcheckPath
	if path == "" {
		path = "/"
	}
	directBudget, edgeBudget := originProofBudgets(cfg, mode)
	// A gated site answers the proof with 401, which is the edge speaking:
	// only the hosts that carry the gate may take that answer as healthy.
	gated := len(cfg.Caddy.BasicAuth.Users) > 0 && cfg.DomainBasicAuthEnabled()
	if err := proveOriginHostname(cfg, host, originIP, "domain", domain, path, true, gated, directBudget, edgeBudget); err != nil {
		return err
	}
	// Every extra hostname is a site the edge will request a certificate for,
	// so it must point at the VPS like the domain does. Its health path, when
	// declared, is proven the same way; without one, DNS is all that is
	// checked, because nothing says which path on that host answers 200.
	for _, route := range cfg.Caddy.HostRoutes {
		probe := strings.TrimSpace(route.HealthPath) != ""
		if err := proveOriginHostname(cfg, host, originIP, "host route", route.Host, route.HealthPath, probe, len(cfg.Caddy.BasicAuth.Users) > 0 && route.BasicAuth, directBudget, edgeBudget); err != nil {
			return err
		}
	}
	return nil
}

// proveOriginHostname runs the DNS proof, and optionally the HTTP proof, for
// one hostname of the application. kind names the hostname's role in errors so
// an operator reads which of several sites failed.
func proveOriginHostname(cfg *config.Config, host string, originIP net.IP, kind, hostname, path string, probe, gated bool, directBudget, edgeBudget time.Duration) error {
	resolved, err := lookupDomainIPs(hostname)
	if err != nil {
		return fmt.Errorf("resolve application %s %s: %w", kind, hostname, err)
	}
	siteHeaders := originSiteHeaders(cfg, hostname)
	if containsIP(resolved, originIP) {
		if !probe {
			return nil
		}
		// Public DNS points straight at the VPS, so this call is itself the
		// direct hop and speaks the origin's own scheme. It gets no reality
		// check: real clients arrive here exactly as this request does, so
		// probing the other scheme would hide a genuine outage behind a green
		// proof.
		//
		// The vantage is asked with a nil address, deliberately. This leg uses
		// the ordinary client, which has no recording dialler, so no address is
		// observed — the most extreme form of "we could not establish that we
		// are inside", and therefore the conservative branch. It changes no
		// verdict here, because no public proof follows to observe the release
		// and EdgeProofFollows is false: a 403 still fails, exactly as it always
		// has. What it buys is the message. An operator whose own allow-list
		// excludes the machine they deploy from reads which setting refused
		// them, instead of an unexplained 403 on a release that is serving.
		return runOriginProof(publicOriginClient, originProof{
			Endpoint:    directOriginEndpoint(cfg),
			Hostname:    hostname,
			Path:        path,
			Gated:       gated,
			SiteHeaders: siteHeaders,
			Vantage:     func() originVantage { return originVantageFor(cfg, nil) },
			Budget:      directBudget,
		})
	}
	if !cfg.Deploy.EdgeProxy {
		return fmt.Errorf("%s %s does not resolve directly to VPS %s (resolved to %s); set deploy.edge_proxy: true when a CDN or WAF fronts the origin", kind, hostname, host, joinIPs(resolved))
	}
	if err := assertEdgeRanges(cfg.Deploy.EdgeRanges, resolved); err != nil {
		return fmt.Errorf("%s %s: %w", kind, hostname, err)
	}
	if !probe {
		return nil
	}
	direct := directOriginEndpoint(cfg)
	output.Detail("Origin proof: %s is fronted by an edge (%s), proving VPS %s directly over %s", hostname, joinIPs(resolved), host, direct)
	if err := proveOriginFromVPS(cfg, host, hostname, path, gated, true, siteHeaders, directBudget); err != nil {
		return fmt.Errorf("VPS %s does not serve %s over %s: %w", host, hostname, direct, err)
	}
	// The public leg travels through the edge, whose address is the one the
	// operator allow-listed. A 403 here is real users being refused, so it is
	// left strict: Vantage stays nil, which is the ungated verdict.
	if err := runOriginProof(publicOriginClient, originProof{
		Endpoint:    edgeOriginEndpoint(),
		Hostname:    hostname,
		Path:        path,
		BustCache:   true,
		Gated:       gated,
		SiteHeaders: siteHeaders,
		Budget:      edgeBudget,
	}); err != nil {
		return fmt.Errorf("edge in front of %s: %w", hostname, err)
	}
	return nil
}

// proveOriginFromVPS proves one hostname against the VPS itself, over the
// endpoint caddy.tls_mode derives, and checks that derivation against reality.
//
// The reality check exists because the configuration is a claim about what the
// origin serves, and a claim can be wrong: a mode changed in config.json but not
// yet rendered onto the host, or rendered and not reloaded, leaves the origin
// speaking the other protocol. Reporting that as a dead release costs a healthy
// rollback; discovering it costs one probe inside a budget already reserved.
func proveOriginFromVPS(cfg *config.Config, host, hostname, path string, gated, edgeProofFollows bool, siteHeaders []string, budget time.Duration) error {
	// One deadline for the pair. The fallback spends what the first attempt did
	// not, never a share of its own: originProofBudgets already told the
	// promotion what this leg costs, and a second full attempt beside the first
	// would make that figure a fiction — the defect the whole derived-budget
	// design exists to prevent.
	deadline := time.Now().Add(budget)
	derived := directOriginEndpoint(cfg)
	first := budget
	if cfg.Deploy.EdgeProxy {
		// Halved rather than run to exhaustion: runOriginProof retries until its
		// own deadline, so handing the derived endpoint the whole share means a
		// refused port burns every millisecond of it and the fallback is reached
		// with nothing to spend. Halving is what makes the second attempt real.
		first = budget / 2
	}
	pinned := pinnedOriginClient(host, derived)
	err := runOriginProof(pinned.Client(), originProof{
		Endpoint:    derived,
		Hostname:    hostname,
		Path:        path,
		Gated:       gated,
		SiteHeaders: siteHeaders,
		// Asked as a function and not as a value because the address only exists
		// once a dial has happened: computing the vantage before the first
		// request would ask the question while the answer was still nil, and nil
		// reads as "outside".
		Vantage:          func() originVantage { return originVantageFor(cfg, pinned.LocalIP()) },
		EdgeProofFollows: edgeProofFollows,
		Budget:           first,
	})
	if err == nil {
		return nil
	}
	// The fallback is restricted to edge topologies, and the condition is
	// written here rather than left implicit in the call site so that moving
	// this call later cannot silently widen it. When public DNS points straight
	// at the VPS, real clients speak the configured scheme; probing another one
	// would turn a genuine outage into a green deploy.
	if !cfg.Deploy.EdgeProxy || !originUnreachable(err) {
		return err
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return err
	}
	alternate := alternateOriginEndpoint(derived)
	probe := pinnedOriginClient(host, alternate)
	probeErr := runOriginProof(probe.Client(), originProof{
		Endpoint:    alternate,
		Hostname:    hostname,
		Path:        path,
		Gated:       gated,
		SiteHeaders: siteHeaders,
		// RequireSite, unlike the configured leg above: this answer is being
		// accepted from a port the configuration did not name, so it has to
		// prove it came from this application's own site and not from the shared
		// edge's catch-all, which answers 200 with an empty body for every Host
		// that matches no site. Without it the fallback would pass on precisely
		// the failures the origin proof exists to catch.
		RequireSite:      true,
		Vantage:          func() originVantage { return originVantageFor(cfg, probe.LocalIP()) },
		EdgeProofFollows: edgeProofFollows,
		Budget:           remaining,
	})
	if probeErr != nil {
		// The first error leads, because it is the endpoint the operator's own
		// configuration pointed at and therefore the answer to the question they
		// asked; the second rides along so the log shows the whole probe.
		return fmt.Errorf("%w (and the origin answered nothing usable over %s either: %v)", err, alternate, probeErr)
	}
	output.Attn("Origin proof: caddy.tls_mode is %q, so %s was dialled over %s on the VPS and nothing answered there — the VPS serves it over %s. The release is proven and the promotion stands, but set caddy.tls_mode to match: the shared edge's route for this application is rendered from that same value, so the next deploy renders the configured one and takes this hostname down.",
		cfg.EffectiveTLSMode(), hostname, derived, alternate)
	return nil
}

// originVantage is where this machine stands relative to caddy.trusted_cidrs.
type originVantage int

const (
	// vantageUngated is the zero value on purpose: it is the verdict for a site
	// that declares no allow-list, where a 403 fails exactly as it always has.
	// Making it the zero value is what lets any leg that must not soften a 403 —
	// the public one through the edge, the direct-DNS one — leave the field
	// unset and inherit the strict behaviour rather than opt into it.
	vantageUngated originVantage = iota
	vantageInside
	vantageOutside
)

// originVantageFor places the prover inside or outside the client allow-list the
// operator declared, from the address the pinned dialler actually bound.
//
// Be honest about what that address is: conn.LocalAddr() is this machine's side
// of the socket, not the address the origin observes. Behind NAT — an operator
// on a home or office LAN, a CI runner in a container, a CGNAT'd connection —
// it is a private address the origin never sees, while Caddy's remote_ip matcher
// tests the peer address that NAT rewrote. So "inside" is the only branch this
// function can assert, and "outside" is a guess that NAT gets wrong in the
// permissive direction. That asymmetry is why "outside" is the branch that
// merely tolerates a 403 — and why, at the call site, tolerating one is further
// conditioned on a public proof following that does observe the release.
func originVantageFor(cfg *config.Config, local net.IP) originVantage {
	entries := cfg.TrustedCIDRs()
	if len(entries) == 0 {
		return vantageUngated
	}
	if local == nil {
		return vantageOutside
	}
	for _, entry := range entries {
		// An unparseable entry is skipped rather than fatal: configuration
		// refuses those at load, so reaching one here means the list changed
		// underneath us, and "cannot place ourselves" is "outside".
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if network.Contains(local) {
			return vantageInside
		}
	}
	return vantageOutside
}

// originProofError is what a leg of the proof failed with, kept structured.
//
// Exactly one of Status and Transport is set, and it describes the last attempt:
// an HTTP answer of any status means the origin speaks this scheme on this port,
// while a transport error means nothing there answered at all. Flattening both
// into a string — which this file used to do — left the caller pattern-matching
// English produced by net/http, and the reality check needs the difference.
type originProofError struct {
	Endpoint  originEndpoint
	Status    string
	Transport error
	// Hint names the configuration that produced an answer, when the answer is
	// one an operator will otherwise read as unexplained.
	Hint string
}

func (e *originProofError) Error() string {
	detail := e.Status
	if detail == "" && e.Transport != nil {
		detail = strings.TrimSpace(e.Transport.Error())
	}
	message := fmt.Sprintf("%s origin did not become healthy: %s", e.Endpoint, detail)
	if e.Hint != "" {
		message += " (" + e.Hint + ")"
	}
	return message
}

func (e *originProofError) Unwrap() error { return e.Transport }

// originUnreachable reports whether a failed proof is evidence that nothing
// speaks this scheme on this port — the only condition under which trying the
// other endpoint tells us anything.
//
// It is an allow-list, so every error it does not name answers false. That is
// the safe default: the fallback's success is a pass, and inferring "the scheme
// must be wrong" from any transport error would let a firewall change, a banned
// source address, a restarting edge or an HTTP/3-only listener all be "fixed" by
// probing another port.
func originUnreachable(err error) bool {
	// First, and before anything is unwrapped: an HTTP answer of any status —
	// 502, 403, 500 — proves the origin speaks this scheme on this port. There
	// is nothing to fall back from, and a broken release must roll back rather
	// than send the proof hunting for a friendlier port.
	var proofErr *originProofError
	if errors.As(err, &proofErr) && proofErr.Status != "" {
		return false
	}
	// A deadline is this command's own budget, not evidence about the origin,
	// and a firewall that drops packets is ambiguous and expensive to guess at.
	// This covers Client.Timeout, the request context's deadline and the
	// dialler's own i/o timeout alike.
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return false
	}
	// A certificate that does not validate is evidence the origin *does* speak
	// the configured scheme — it is speaking it badly. Falling back to plaintext
	// there would mask a certificate a strict CDN would refuse too, and turn an
	// operator's move from "off" to "acme" into a silent downgrade.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}
	// net/http converts a plaintext answer to a TLS request into this, so it,
	// and not tls.RecordHeaderError, is what the https-on-a-plaintext-origin
	// drift actually surfaces as.
	if errors.Is(err, http.ErrSchemeMismatch) {
		return true
	}
	// Refused is nothing listening. Reset and broken pipe are the signature of a
	// published port whose container binds no listener behind it — a proxy
	// accepts the connection and the peer tears it down, which is what an origin
	// serving one scheme looks like on the port of the other.
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EPIPE} {
		if errors.Is(err, errno) {
			return true
		}
	}
	// Deliberately absent: EHOSTUNREACH and ENETUNREACH. A host that cannot be
	// routed to is unreachable on every port, so probing a second one proves
	// nothing and only spends the budget the first attempt left.
	return false
}

// originProof is one leg of the proof: what to request, and which answers count
// as proof of what.
type originProof struct {
	Endpoint  originEndpoint
	Hostname  string
	Path      string
	BustCache bool
	// Gated says this hostname carries caddy.basic_auth, which is what makes a
	// 401 with a Basic challenge the edge speaking rather than the application.
	Gated bool
	// SiteHeaders are the response headers this hostname's site must carry to be
	// the site the shared edge rendered for this application.
	SiteHeaders []string
	// RequireSite demands that evidence on a 2xx as well. It is set only on legs
	// whose success would otherwise be indistinguishable from the shared edge's
	// catch-all answer.
	RequireSite bool
	// Vantage is a function because the address it reads only exists after a
	// dial. A nil Vantage is the strict verdict.
	Vantage func() originVantage
	// EdgeProofFollows says a public proof runs after this one and observes the
	// promoted release itself. Only that makes it honest to accept an answer
	// which proves the site is up without proving what it serves.
	EdgeProofFollows bool
	Budget           time.Duration
}

func (proof originProof) vantage() originVantage {
	if proof.Vantage == nil {
		return vantageUngated
	}
	return proof.Vantage()
}

// runOriginProof requests one hostname until it answers healthily or the budget
// runs out.
//
// A site behind caddy.basic_auth answers an unauthenticated probe with 401, and
// that answer is the proof: it is the edge, with the gate in place, serving that
// hostname. A site behind caddy.trusted_cidrs answers a client outside the
// allow-list with 403, and the same reasoning applies to it — with the extra
// conditions spelled out in judge, because the vantage that decides it is
// measured with a ruler NAT can bend.
func runOriginProof(client *http.Client, proof originProof) error {
	deadline := time.Now().Add(proof.Budget)
	failure := &originProofError{Endpoint: proof.Endpoint}
	attempted := false
	for time.Now().Before(deadline) {
		attempted = true
		target := cacheBustedURL(proof.Endpoint.url(proof.Hostname, proof.Path), proof.BustCache)
		// The request carries the proof's own deadline. Without it the client's
		// 6 s timeout and the dialler's 4 s one outlive the slice this leg was
		// given — at the smallest accepted promotion budget the direct share is
		// under a second — and one hung request overruns the phase the whole
		// derived-budget design exists to bound.
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			cancel()
			return fmt.Errorf("build origin proof request for %s: %w", target, err)
		}
		// A stable, identifiable agent lets an operator whitelist the proof in
		// their WAF instead of having a bot rule roll the release back.
		request.Header.Set("User-Agent", originProofUserAgent)
		if proof.BustCache {
			request.Header.Set("Cache-Control", "no-cache")
			request.Header.Set("Pragma", "no-cache")
		}
		response, err := client.Do(request)
		if err != nil {
			cancel()
			failure.Status, failure.Hint, failure.Transport = "", "", err
		} else {
			accepted, hint := proof.judge(response)
			status := response.Status
			_ = response.Body.Close()
			cancel()
			if accepted {
				return nil
			}
			failure.Status, failure.Hint, failure.Transport = status, hint, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if remaining > originProofRetryInterval {
			remaining = originProofRetryInterval
		}
		time.Sleep(remaining)
	}
	if !attempted {
		failure.Transport = errors.New("no attempt fitted inside the budget reserved for this proof")
	}
	return failure
}

// judge decides what one answer proves. hint travels into the terminal error so
// the operator reads which declared setting produced the status.
func (proof originProof) judge(response *http.Response) (accepted bool, hint string) {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if proof.RequireSite && !originSiteEvidence(response, proof.SiteHeaders) {
			return false, "the answer carries none of the headers the shared edge renders for this application, so it is the edge answering for a hostname that matches no site rather than this site answering"
		}
		proof.reportSchemeDrift(response)
		return true, ""
	}
	if proof.Gated && response.StatusCode == http.StatusUnauthorized && basicChallenge(response) {
		return true, ""
	}
	if response.StatusCode == http.StatusForbidden {
		return proof.judgeForbidden(response)
	}
	return false, ""
}

// judgeForbidden applies the caddy.trusted_cidrs rule to a 403.
//
// The gate is rendered before every reverse_proxy in the site, so its 403 says
// the hostname reaches a site of this application that is up and enforcing the
// declared policy — and says nothing at all about the release behind it. That is
// worth accepting only when three things hold at once, and each one of them is
// load-bearing:
//
//   - the allow-list is declared and this machine measured itself outside it,
//     so the 403 is the operator's own policy rather than the application
//     refusing its own health path;
//   - a public proof follows, which does observe the promoted release, so the
//     half this answer cannot prove is proven by something. Without that
//     condition, declaring caddy.trusted_cidrs would silently disable the origin
//     proof for the topology where nothing else looks at the release at all;
//   - the answer carries this site's headers, so it comes from the fragment
//     written for this application rather than from anything else that may
//     answer 403 on that port.
func (proof originProof) judgeForbidden(response *http.Response) (accepted bool, hint string) {
	switch proof.vantage() {
	case vantageInside:
		// The declared allow-list contains this machine, so the gate should have
		// let this request through. A 403 here is the release, or the rendered
		// route, genuinely refusing — the failure a rollback exists for.
		return false, "this machine is inside caddy.trusted_cidrs, so the declared allow-list should have admitted this request"
	case vantageOutside:
		if !proof.EdgeProofFollows {
			return false, "caddy.trusted_cidrs excludes this machine and no public proof follows to observe the release; deploy from inside the declared networks, or front the origin with an edge so the public leg can carry that proof"
		}
		if !originSiteEvidence(response, proof.SiteHeaders) {
			return false, "the 403 carries none of the headers the shared edge renders for this application, so it is not this site's caddy.trusted_cidrs gate answering"
		}
		output.Detail("Origin proof: %s answered 403 from the VPS, which is this site's caddy.trusted_cidrs gate refusing this machine. Proven: the hostname reaches a site of this application that is up and enforcing the declared policy. Not proven here: the promoted release's own answer, which the public proof below observes.", proof.Hostname)
		return true, ""
	default:
		// No allow-list declared, so nothing explains a 403 but the application.
		return false, ""
	}
}

// reportSchemeDrift names a healthy answer that arrived over a scheme other than
// the one requested.
//
// It is the only detector for the opposite drift to the one the reality check
// catches: an origin configured plaintext but actually serving ACME answers the
// plain port with a redirect, the client follows it, and the proof sees a
// perfectly healthy 200 that came from somewhere else. No transport error is
// ever raised, so nothing below the HTTP layer would notice.
func (proof originProof) reportSchemeDrift(response *http.Response) {
	// Response.Request is populated by net/http's own transport and by nothing
	// else: a stubbed RoundTripper leaves it nil, so this is guarded rather than
	// assumed.
	if response.Request == nil || response.Request.URL == nil {
		return
	}
	served := response.Request.URL.Scheme
	if served == "" || served == proof.Endpoint.Scheme {
		return
	}
	output.Attn("Origin proof: %s was requested over %s and answered over %s — the origin redirected the proof onto another scheme. Check caddy.tls_mode against what the shared edge renders for this application.", proof.Hostname, proof.Endpoint, served)
}

// originSiteHeaders is the evidence a response has to carry to be this
// hostname's site rather than the shared edge answering for a Host it has no
// site for. It is the security baseline every rendered fragment imports, plus
// whatever headers the operator declared for this hostname — a host route
// declares its own, and the domain's do not carry over to it.
func originSiteHeaders(cfg *config.Config, hostname string) []string {
	declared := cfg.Caddy.Headers
	for _, route := range cfg.Caddy.HostRoutes {
		if strings.EqualFold(strings.TrimSpace(route.Host), strings.TrimSpace(hostname)) {
			declared = route.Headers
			break
		}
	}
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	return names
}

// originSiteEvidence reports whether a response came from a site the shared edge
// rendered for this application.
//
// Either signal suffices, and they are deliberately not required together: this
// hostname's own declared headers, all present, name this site specifically, and
// a header of the baseline every rendered fragment imports names a site the edge
// rendered — which, on a request pinned to the VPS with this Host, is this one.
// The catch-all carries neither, which is the distinction being drawn, so
// demanding both would only add ways for a healthy site to be disbelieved.
func originSiteEvidence(response *http.Response, declared []string) bool {
	if len(declared) > 0 {
		matched := true
		for _, name := range declared {
			if response.Header.Get(name) == "" {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	for _, name := range shuttleSecurityHeaders {
		if response.Header.Get(name) != "" {
			return true
		}
	}
	return false
}

// assertEdgeRanges keeps the edge honest: when the operator declares the CIDRs
// their CDN publishes, a domain that drifted to any other network fails the
// proof instead of silently passing on somebody else's 200.
func assertEdgeRanges(ranges []string, resolved []net.IP) error {
	if len(ranges) == 0 {
		return nil
	}
	networks := make([]*net.IPNet, 0, len(ranges))
	for _, entry := range ranges {
		_, network, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil {
			return fmt.Errorf("deploy.edge_ranges: %q is not a CIDR", entry)
		}
		networks = append(networks, network)
	}
	for _, address := range resolved {
		inside := false
		for _, network := range networks {
			if network.Contains(address) {
				inside = true
				break
			}
		}
		if !inside {
			return fmt.Errorf("resolved address %s is outside the declared deploy.edge_ranges", address)
		}
	}
	return nil
}

func containsIP(addresses []net.IP, wanted net.IP) bool {
	for _, address := range addresses {
		if address.Equal(wanted) {
			return true
		}
	}
	return false
}

func joinIPs(addresses []net.IP) string {
	rendered := make([]string, 0, len(addresses))
	for _, address := range addresses {
		rendered = append(rendered, address.String())
	}
	if len(rendered) == 0 {
		return "no address"
	}
	return strings.Join(rendered, ", ")
}

// basicChallenge reports whether a 401 carries a Basic challenge, which is
// what the edge's basic_auth emits and what an application's own 401 does not.
func basicChallenge(response *http.Response) bool {
	for _, challenge := range response.Header.Values("WWW-Authenticate") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(challenge)), "basic") {
			return true
		}
	}
	return false
}

// cacheBustedURL makes each edge attempt a cache miss: a CDN keys its cache on
// the query string, so a stale 200 from the previous release cannot pass for
// the promoted one. keepOriginProofNonce carries it across redirects, without
// which the guarantee holds for the first hop only.
func cacheBustedURL(target string, bustCache bool) string {
	if !bustCache {
		return target
	}
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return target + separator + originProofNonceParam + "=" + originProofNonce()
}
