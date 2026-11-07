package cli

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func caddyfileContent(email string) string {
	var b strings.Builder
	b.WriteString("{\n")
	if email != "" {
		fmt.Fprintf(&b, "    email %s\n", email)
	}
	b.WriteString("}\n")
	b.WriteString("(shuttle_security) {\n")
	// HSTS is a property of the domain, not of one application: the edge
	// always sets it, whatever the upstream sent.
	b.WriteString("    header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n")
	// The three below are defaults (the `?` prefix): written only when the
	// application did not send the header itself. They used to be set
	// unconditionally, which silently replaced an application's stricter
	// choice: example.com, pro and bo sent `X-Frame-Options: DENY` and a
	// `no-referrer` policy on their token-bearing routes, and visitors received
	// the edge's SAMEORIGIN and strict-origin-when-cross-origin instead
	// (measured at the origin and through the edge on 2026-10-12). An app that
	// sends nothing keeps exactly the previous protection, and the route proof
	// in origin.go still sees these headers on every generated site.
	//
	// One `header` directive per default, never a block: inside one block,
	// Caddy folds every `?` field into a single condition that holds only when
	// none of them exists, so an app sending X-Frame-Options alone lost the
	// nosniff default too (reproduced with caddy v2.11.7).
	b.WriteString("    header ?X-Content-Type-Options \"nosniff\"\n")
	b.WriteString("    header ?Referrer-Policy \"strict-origin-when-cross-origin\"\n")
	// SAMEORIGIN rather than DENY: it stops a third-party page from framing the
	// application, which is the clickjacking case, without breaking an app that
	// frames its own pages. DENY would silently break those, and a header that
	// breaks working applications is one operators disable wholesale. An app
	// that wants DENY now gets it by sending it.
	//
	// Content-Security-Policy is deliberately absent. There is no value for it
	// that is both useful and safe for an application Shuttle did not build:
	// a restrictive default breaks every app with a CDN or an inline script, and
	// a permissive one protects nothing. It is declared per application through
	// caddy.headers, by the only party who knows what the app loads.
	b.WriteString("    header ?X-Frame-Options \"SAMEORIGIN\"\n")
	// reverse_proxy adds `Via: 1.1 Caddy` to every proxied response, which
	// tells any visitor which proxy and protocol sit in front of the app and
	// serves no client. A deletion is deferred by Caddy, so it also removes
	// the header the proxy adds after the upstream answered (verified with
	// caddy v2.11.7 on 2026-10-12, the other headers unchanged).
	b.WriteString("    header -Via\n")
	b.WriteString("}\n")
	// Keep the fresh edge reachable before the first application is deployed.
	// Host-specific imported routes and automatic HTTPS redirects take precedence.
	b.WriteString(":80 {\n    respond 404\n}\n")
	b.WriteString("import /etc/caddy/conf.d/*.caddy\n")
	return b.String()
}

// Swarm configs are immutable. A content-derived name permits upgrades without
// overwriting a config still mounted by the old task during a rolling update.
func caddyfileConfigName(email string) string {
	digest := sha256.Sum256([]byte(caddyfileContent(email)))
	return fmt.Sprintf("shuttle_caddyfile_%x", digest[:16])
}

func caddyCheckpointReconcile(email string) string {
	return fmt.Sprintf(`set -eu
if docker service inspect shuttle-edge_caddy >/dev/null 2>&1; then
  current_user=$(docker service inspect shuttle-edge_caddy --format '{{.Spec.TaskTemplate.ContainerSpec.User}}')
  current_config=$(docker service inspect shuttle-edge_caddy --format '{{range .Spec.TaskTemplate.ContainerSpec.Configs}}{{if eq .File.Name "/etc/caddy/Caddyfile"}}{{.ConfigName}}{{end}}{{end}}')
  if [ "$current_user" != 10001:10001 ] || [ "$current_config" != %s ]; then
    rm -f /etc/shuttle/setup.d/50-caddy-direct
  fi
else
  rm -f /etc/shuttle/setup.d/50-caddy-direct
fi
`, caddyfileConfigName(email))
}
