package cli

import (
	"strings"
	"testing"
)

func cdnRouteStack(t *testing.T, extra string) []byte {
	t.Helper()
	return []byte(`services:
  web:
    image: 127.0.0.1:5000/demo-web@sha256:` + strings.Repeat("a", 64) + `
    deploy:
      labels:
        dev.shuttle.domain: demo.example.com
        dev.shuttle.port: "3000"
` + extra)
}

// Invariant 4: a stack that says nothing about TLS must produce the fragment it
// always produced, byte for byte.
func TestCaddyRouteDefaultIsUnchanged(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, ""))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	want := "demo.example.com {\n  import shuttle_security\n  reverse_proxy demo_web:3000\n}\n"
	if fragment != want {
		t.Errorf("fragment =\n%q\nwant\n%q", fragment, want)
	}
}

// An origin behind a CDN or a tunnel is reached over plain HTTP: the edge in
// front terminated TLS, and no inbound path exists for an ACME challenge. A
// bare site address makes Caddy redirect that leg and chase certificates it can
// never obtain, breaking the one hop that worked.
func TestCaddyRouteServesPlainHTTPBehindAnEdge(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, "        dev.shuttle.tls: \"off\"\n"))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	if !strings.HasPrefix(fragment, "http://demo.example.com {") {
		t.Errorf("fragment does not pin the HTTP scheme:\n%s", fragment)
	}
}

// The restriction an operator had in front of their origin has to survive the
// move to the shared edge. Dropping it silently publishes, wide open, something
// that was not.
func TestCaddyRouteKeepsTheClientRestriction(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t,
		"        dev.shuttle.allow_cidrs: \"10.0.0.0/8,192.168.1.222/32\"\n"))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	if !strings.Contains(fragment, "@untrusted not remote_ip 10.0.0.0/8 192.168.1.222/32") {
		t.Errorf("fragment does not restrict clients:\n%s", fragment)
	}
	if !strings.Contains(fragment, "respond @untrusted 403") {
		t.Errorf("an untrusted client must be refused, not served:\n%s", fragment)
	}
	// The allow-list is a condition on the site, not a branch of its routing.
	// Rendered as `handle @trusted { }` beside a `handle { respond 403 }` it
	// became one: handle blocks are mutually exclusive, so a trusted client
	// matched the empty block and every path route below it was unreachable —
	// /api, /graphql and /auth were all answered by the published front end.
	if strings.Contains(fragment, "handle @trusted") {
		t.Errorf("the allow-list must not consume the routing that follows it:\n%s", fragment)
	}
}

// The two features together are what broke: an allow-list rendered as a routing
// branch swallowed every path route declared beside it, so /api, /graphql and
// /auth were answered by the published front end — a 404 page where the API was
// supposed to be, on a deployment reporting every service healthy.
func TestCaddyRouteKeepsPathRoutesUnderAClientRestriction(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t,
		"        dev.shuttle.allow_cidrs: \"192.168.1.222/32\"\n"+
			"        dev.shuttle.path_routes: '[{\"path\":\"/api/*\",\"service\":\"api\",\"port\":8000}]'\n"))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	for _, want := range []string{"respond @untrusted 403", "handle /api/*", "reverse_proxy demo_api:8000", "reverse_proxy demo_web:3000"} {
		if !strings.Contains(fragment, want) {
			t.Errorf("missing %q in:\n%s", want, fragment)
		}
	}
}

// The value is written into a Caddyfile the root-owned edge loads, so anything
// that is not plainly a CIDR is refused inside the signed operation rather than
// emitted for Caddy to interpret.
func TestCaddyRouteRefusesMalformedRoutingInput(t *testing.T) {
	for name, extra := range map[string]string{
		"unknown tls mode": "        dev.shuttle.tls: \"internal\"\n",
		"not a cidr":       "        dev.shuttle.allow_cidrs: \"192.168.1.222\"\n",
		"injected brace":   "        dev.shuttle.allow_cidrs: \"10.0.0.0/8}\\nrespond 200 {\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := caddyRouteFragment("demo", cdnRouteStack(t, extra)); err == nil {
				t.Error("accepted; it would have reached the shared edge as written")
			}
		})
	}
}

// Determinism: the same allow-list must render the same fragment, or every
// deploy reloads the shared edge for a change nobody made.
func TestCaddyRouteAllowListIsDeterministic(t *testing.T) {
	first, err := caddyRouteFragment("demo", cdnRouteStack(t, "        dev.shuttle.allow_cidrs: \"10.0.0.0/8,172.16.0.0/12\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := caddyRouteFragment("demo", cdnRouteStack(t, "        dev.shuttle.allow_cidrs: \"172.16.0.0/12,10.0.0.0/8,10.0.0.0/8\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("the same networks rendered two fragments:\n%q\nvs\n%q", first, second)
	}
}

// A domain that reaches exactly one service describes a single-process
// application, not the monorepos Shuttle is asked to deploy: an API and a front
// end behind one hostname had no expressible shape at all.
func TestCaddyRouteSendsPathsToOtherServices(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t,
		`        dev.shuttle.path_routes: '[{"path":"/api/*","service":"api","port":8000},{"path":"/health","service":"api","port":8000}]'`+"\n"))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	for _, want := range []string{
		"handle /api/* {\n    reverse_proxy demo_api:8000\n  }",
		"handle /health {\n    reverse_proxy demo_api:8000\n  }",
		"reverse_proxy demo_web:3000",
	} {
		if !strings.Contains(fragment, want) {
			t.Errorf("fragment lacks %q:\n%s", want, fragment)
		}
	}
	// The published service is the fall-through and must come last: first, it
	// would shadow every route behind it.
	if strings.Index(fragment, "demo_api:8000") > strings.Index(fragment, "demo_web:3000") {
		t.Errorf("the fall-through is not last, so the path routes can never match:\n%s", fragment)
	}
}

// Order is what Caddy matches on, so it has to survive the trip through the
// signed stack exactly as the operator wrote it.
func TestCaddyRoutePathOrderIsPreserved(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t,
		`        dev.shuttle.path_routes: '[{"path":"/api/v2/*","service":"api","port":8000},{"path":"/api/*","service":"legacy","port":9000}]'`+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(fragment, "demo_api:8000") > strings.Index(fragment, "demo_legacy:9000") {
		t.Errorf("the more specific path was reordered behind the general one:\n%s", fragment)
	}
}

// Written into a Caddyfile the root-owned edge loads, so anything that would
// open a block nobody wrote is refused inside the signed operation.
func TestCaddyRouteRefusesUnsafePathRoutes(t *testing.T) {
	for name, payload := range map[string]string{
		"brace in path":     `[{"path":"/api/*}\nrespond 200 {","service":"api","port":8000}]`,
		"relative path":     `[{"path":"api/*","service":"api","port":8000}]`,
		"bad service":       `[{"path":"/api/*","service":"Api Gateway","port":8000}]`,
		"port out of range": `[{"path":"/api/*","service":"api","port":70000}]`,
		"duplicate path":    `[{"path":"/api/*","service":"api","port":8000},{"path":"/api/*","service":"other","port":9000}]`,
		"not json":          `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := caddyRouteFragment("demo", cdnRouteStack(t,
				"        dev.shuttle.path_routes: '"+payload+"'\n")); err == nil {
				t.Error("accepted; it would have reached the shared edge as written")
			}
		})
	}
}

// The baseline the shared edge sets is universal, so it stops where a value
// would have to be guessed: a Content-Security-Policy chosen for an application
// Shuttle did not build either breaks every app with a CDN or an inline script,
// or permits enough to protect nothing. caddy.headers is how the party that
// knows declares it.
func TestCaddyRouteCarriesDeclaredHeaders(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t,
		"        dev.shuttle.headers: '{\"Content-Security-Policy\":\"default-src https:\",\"Permissions-Policy\":\"camera=()\"}'\n"))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	for _, want := range []string{
		"  header {\n",
		"    Content-Security-Policy \"default-src https:\"\n",
		"    Permissions-Policy \"camera=()\"\n",
	} {
		if !strings.Contains(fragment, want) {
			t.Errorf("missing %q in:\n%s", want, fragment)
		}
	}
	// After the baseline import, so a declared header overrides the shared one
	// by name instead of sitting beside it as a duplicate.
	if strings.Index(fragment, "import shuttle_security") > strings.Index(fragment, "header {") {
		t.Errorf("declared headers must follow the baseline:\n%s", fragment)
	}
}

// The value is written into a Caddyfile the root-owned edge loads, so anything
// that could open a block is refused inside the signed operation.
func TestCaddyRouteRefusesUnsafeHeaders(t *testing.T) {
	for name, label := range map[string]string{
		"brace in value": "        dev.shuttle.headers: '{\"X-Demo\":\"a} respond 200 {\"}'\n",
		"newline":        "        dev.shuttle.headers: '{\"X-Demo\":\"a\\nrespond 200\"}'\n",
		"not a name":     "        dev.shuttle.headers: '{\"X Demo\":\"a\"}'\n",
		"not json":       "        dev.shuttle.headers: 'nope'\n",
	} {
		if _, err := caddyRouteFragment("demo", cdnRouteStack(t, label)); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// Invariant 4: a configuration declaring no header produces the fragment it
// always produced.
func TestCaddyRouteWithoutDeclaredHeadersIsUnchanged(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, ""))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	if strings.Contains(fragment, "header {") {
		t.Errorf("no header block may appear when none was declared:\n%s", fragment)
	}
}

// Caddy overwrites X-Forwarded-Proto with the scheme of the leg it served, and
// behind a CDN or a tunnel that leg is plain HTTP. The application then learns
// "http" for a request the client made over HTTPS, and every absolute URL it
// builds comes out wrong — a redirect from https to http makes any HTTP client
// drop the Authorization header, so an API answers "missing or expired token"
// on a token that is neither.
func TestCaddyRouteTrustsTheProxyItAlreadyAdmits(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t,
		"        dev.shuttle.tls: \"off\"\n"+
			"        dev.shuttle.allow_cidrs: \"192.168.1.222/32\"\n"+
			"        dev.shuttle.path_routes: '[{\"path\":\"/api/*\",\"service\":\"api\",\"port\":8000}]'\n"))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	// Both legs, or the published service and a path route would disagree about
	// the scheme of the same request.
	if strings.Count(fragment, "trusted_proxies 192.168.1.222/32") != 2 {
		t.Errorf("every reverse_proxy must trust the admitted peer:\n%s", fragment)
	}
	if !strings.Contains(fragment, "reverse_proxy demo_api:8000 {\n      trusted_proxies") {
		t.Errorf("a path route must carry it too:\n%s", fragment)
	}
}

// Invariant 4: the peers whose headers may be believed are exactly the peers
// allowed to reach the site, so an application that admits everyone trusts
// nobody's headers — and produces the fragment it always produced.
func TestCaddyRouteWithoutAnAllowListTrustsNoProxy(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, ""))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	if strings.Contains(fragment, "trusted_proxies") {
		t.Errorf("no allow-list means no trusted proxy:\n%s", fragment)
	}
	want := "demo.example.com {\n  import shuttle_security\n  reverse_proxy demo_web:3000\n}\n"
	if fragment != want {
		t.Errorf("fragment =\n%q\nwant\n%q", fragment, want)
	}
}
