//go:build linux

package cli

import (
	"strings"
	"testing"
)

const hostRoutesLabel = `        dev.shuttle.host_routes: '[{"host":"api.domebao.com","service":"api","port":8005,"headers":{"X-Robots-Tag":"noindex"}},{"host":"bo.domebao.com","service":"api","port":8005,"path_routes":[{"path":"/app/*","service":"reverb","port":8086}]}]'` + "\n"

// One application, several sites: each extra host is a block of the same
// shape as the domain's, carrying its own headers and path handles.
func TestCaddyRouteRendersOneBlockPerHost(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, hostRoutesLabel))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	want := "demo.example.com {\n  import shuttle_security\n  reverse_proxy demo_web:3000\n}\n" +
		"api.domebao.com {\n  import shuttle_security\n  header {\n    X-Robots-Tag \"noindex\"\n  }\n  reverse_proxy demo_api:8005\n}\n" +
		"bo.domebao.com {\n  import shuttle_security\n  handle /app/* {\n    reverse_proxy demo_reverb:8086\n  }\n  reverse_proxy demo_api:8005\n}\n"
	if fragment != want {
		t.Errorf("fragment =\n%s\nwant\n%s", fragment, want)
	}
}

// The scheme, the client guard and the trusted proxies describe what fronts
// the application, so every host gets them alike.
func TestCaddyRouteHostsShareTheApplicationGuard(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t,
		"        dev.shuttle.tls: \"off\"\n        dev.shuttle.allow_cidrs: \"10.0.0.0/8\"\n"+hostRoutesLabel))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	if strings.Count(fragment, "respond @untrusted 403") != 3 {
		t.Errorf("every site must carry the client guard:\n%s", fragment)
	}
	if strings.Count(fragment, "trusted_proxies 10.0.0.0/8") != 4 {
		t.Errorf("every reverse_proxy, including the host's path handle, must trust the same peers:\n%s", fragment)
	}
	if !strings.Contains(fragment, "http://api.domebao.com {") || !strings.Contains(fragment, "http://bo.domebao.com {") {
		t.Errorf("hosts must follow the application's TLS mode:\n%s", fragment)
	}
}

func TestCaddyRouteWithoutHostRoutesIsUnchanged(t *testing.T) {
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, ""))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	if fragment != "demo.example.com {\n  import shuttle_security\n  reverse_proxy demo_web:3000\n}\n" {
		t.Errorf("a stack without host routes must render as before:\n%s", fragment)
	}
}

// The helper trusts nothing the CLI checked: each of these is a label a
// compromised or older CLI could emit, and each must be refused rather than
// written into the edge configuration.
func TestCaddyRouteRefusesUnsafeHostRoutes(t *testing.T) {
	cases := map[string]string{
		"invalid JSON":         `[{"host":"api.domebao.com"`,
		"empty list":           `[]`,
		"host equal to domain": `[{"host":"demo.example.com","service":"api","port":8005}]`,
		"duplicated host":      `[{"host":"api.domebao.com","service":"api","port":8005},{"host":"api.domebao.com","service":"api","port":8006}]`,
		"uppercase host":       `[{"host":"API.domebao.com","service":"api","port":8005}]`,
		"host opening a block": `[{"host":"api.domebao.com {","service":"api","port":8005}]`,
		"bad service":          `[{"host":"api.domebao.com","service":"Api/x","port":8005}]`,
		"bad port":             `[{"host":"api.domebao.com","service":"api","port":70000}]`,
		"bad path route":       `[{"host":"api.domebao.com","service":"api","port":8005,"path_routes":[{"path":"app","service":"reverb","port":8086}]}]`,
		"bad header":           `[{"host":"api.domebao.com","service":"api","port":8005,"headers":{"X-Robots-Tag":"no{index}"}}]`,
	}
	for name, payload := range cases {
		if _, err := caddyRouteFragment("demo", cdnRouteStack(t, "        dev.shuttle.host_routes: '"+payload+"'\n")); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

const basicAuthLabel = `        dev.shuttle.basic_auth: '[{"username":"domebao","hash":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}]'` + "\n"

// The gate is rendered on the domain and on each host that imports it, right
// after the baseline import; a host without the flag stays open.
func TestCaddyRouteRendersBasicAuthWhereDeclared(t *testing.T) {
	hosts := `        dev.shuttle.host_routes: '[{"host":"api.domebao.com","service":"api","port":8005},{"host":"bo.domebao.com","service":"api","port":8005,"basic_auth":true,"headers":{"X-Robots-Tag":"noindex"}}]'` + "\n"
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, basicAuthLabel+hosts))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	gate := "  basic_auth {\n    domebao $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy\n  }\n"
	want := "demo.example.com {\n  import shuttle_security\n" + gate + "  reverse_proxy demo_web:3000\n}\n" +
		"api.domebao.com {\n  import shuttle_security\n  reverse_proxy demo_api:8005\n}\n" +
		"bo.domebao.com {\n  import shuttle_security\n" + gate + "  header {\n    X-Robots-Tag \"noindex\"\n  }\n  reverse_proxy demo_api:8005\n}\n"
	if fragment != want {
		t.Errorf("fragment =\n%s\nwant\n%s", fragment, want)
	}
}

// A public primary site may coexist with a gated host route. The explicit
// false is carried in the signed stack so the root helper makes the same
// decision as the operator's config.
func TestCaddyRouteCanLeavePrimaryDomainPublic(t *testing.T) {
	hosts := `        dev.shuttle.domain_basic_auth: "false"
        dev.shuttle.host_routes: '[{"host":"bo.domebao.com","service":"api","port":8005,"basic_auth":true}]'` + "\n"
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, basicAuthLabel+hosts))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	if strings.Contains(fragment, "demo.example.com {\n  import shuttle_security\n  basic_auth") {
		t.Fatalf("primary domain must remain public:\n%s", fragment)
	}
	if !strings.Contains(fragment, "bo.domebao.com {\n  import shuttle_security\n  basic_auth") {
		t.Fatalf("gated host route lost its Basic Auth gate:\n%s", fragment)
	}
}

// One bad entry refuses the whole fragment: a site gated for some users and
// open for a typo is worse than a deploy that stops.
func TestCaddyRouteRefusesUnsafeBasicAuth(t *testing.T) {
	cases := map[string]string{
		"invalid JSON":        `[{"username":"domebao"`,
		"empty list":          `[]`,
		"clear-text password": `[{"username":"domebao","hash":"hunter2"}]`,
		"truncated hash":      `[{"username":"domebao","hash":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p9"}]`,
		"hash opening block":  `[{"username":"domebao","hash":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZ{"}]`,
		"uppercase username":  `[{"username":"Domebao","hash":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}]`,
		"duplicated username": `[{"username":"domebao","hash":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"},{"username":"domebao","hash":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}]`,
	}
	for name, payload := range cases {
		if _, err := caddyRouteFragment("demo", cdnRouteStack(t, "        dev.shuttle.basic_auth: '"+payload+"'\n")); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	// A host that imports a gate the stack never declared would be published
	// open while the operator believes otherwise.
	if _, err := caddyRouteFragment("demo", cdnRouteStack(t,
		`        dev.shuttle.host_routes: '[{"host":"bo.domebao.com","service":"api","port":8005,"basic_auth":true}]'`+"\n")); err == nil || !strings.Contains(err.Error(), "does not declare") {
		t.Errorf("a gated host without a declared gate must be refused, got %v", err)
	}
}

// Public paths leave the gate through a named matcher defined inside the gate
// itself, so a gated host route that imports it gets the same exemptions.
func TestCaddyRouteRendersBasicAuthPublicPaths(t *testing.T) {
	public := `        dev.shuttle.basic_auth_public_paths: '["/manifest.webmanifest","/sw.js","/_next/static/*"]'` + "\n"
	fragment, err := caddyRouteFragment("demo", cdnRouteStack(t, basicAuthLabel+public))
	if err != nil {
		t.Fatalf("caddyRouteFragment: %v", err)
	}
	gate := "  @shuttle_gated not path /manifest.webmanifest /sw.js /_next/static/*\n" +
		"  basic_auth @shuttle_gated {\n    domebao $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy\n  }\n"
	want := "demo.example.com {\n  import shuttle_security\n" + gate + "  reverse_proxy demo_web:3000\n}\n"
	if fragment != want {
		t.Errorf("fragment =\n%s\nwant\n%s", fragment, want)
	}
}

func TestCaddyRouteRefusesUnsafeBasicAuthPublicPaths(t *testing.T) {
	cases := map[string]string{
		"invalid JSON":     `["/sw.js"`,
		"empty list":       `[]`,
		"whole site":       `["/"]`,
		"whole site glob":  `["/*"]`,
		"relative path":    `["sw.js"]`,
		"block opening":    `["/sw.js {"]`,
		"parent traversal": `["/static/../api"]`,
		"duplicated path":  `["/sw.js","/sw.js"]`,
	}
	for name, payload := range cases {
		if _, err := caddyRouteFragment("demo", cdnRouteStack(t, basicAuthLabel+"        dev.shuttle.basic_auth_public_paths: '"+payload+"'\n")); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}
