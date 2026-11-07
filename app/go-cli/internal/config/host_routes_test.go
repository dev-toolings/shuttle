package config

import (
	"fmt"
	"strings"
	"testing"
)

// hostRoutesYAML is the shape the feature exists for: one Laravel stack whose
// front end, API and back office answer on their own hostnames.
func hostRoutesYAML(routes string) string {
	return validConfig + "caddy:\n  host_routes:\n" + routes
}

const threeHostRoutes = `    - host: api.demo.example.com
      service: api
      port: 8005
      health_path: /api/v1/health
    - host: bo.demo.example.com
      service: api
      port: 8005
      path_routes:
        - { path: /app/*, service: reverb, port: 8086 }
    - host: umami.example.com
      service: umami
      port: 3000
      headers: { X-Robots-Tag: noindex }
`

func TestHostRoutesAcceptSeveralHostnames(t *testing.T) {
	cfg, err := loadYAML(t, hostRoutesYAML(threeHostRoutes))
	if err != nil {
		t.Fatalf("three well-formed host routes must be accepted, got %v", err)
	}
	routes := cfg.Caddy.HostRoutes
	if len(routes) != 3 || routes[0].HealthPath != "/api/v1/health" || routes[1].PathRoutes[0].Service != "reverb" || routes[2].Headers["X-Robots-Tag"] != "noindex" {
		t.Fatalf("host routes did not load as written: %#v", routes)
	}
}

func TestHostRoutesAreRefusedWhenMalformed(t *testing.T) {
	var seventeen strings.Builder
	for i := 0; i < 17; i++ {
		fmt.Fprintf(&seventeen, "    - { host: h%d.demo.example.com, service: api, port: 8005 }\n", i)
	}
	cases := map[string]struct{ body, want string }{
		"an internal application": {
			body: strings.Replace(hostRoutesYAML(threeHostRoutes), "domain: demo.example.com\n", "expose: internal\n", 1),
			want: "internal application must not declare caddy.host_routes",
		},
		"a host equal to the domain": {
			body: hostRoutesYAML("    - { host: demo.example.com, service: api, port: 8005 }\n"),
			want: `caddy.host_routes[0].host "demo.example.com" is already the application domain`,
		},
		"a duplicated host": {
			body: hostRoutesYAML("    - { host: api.demo.example.com, service: api, port: 8005 }\n    - { host: api.demo.example.com, service: api, port: 8006 }\n"),
			want: `caddy.host_routes[1].host "api.demo.example.com" is declared twice`,
		},
		"an uppercase host": {
			body: hostRoutesYAML("    - { host: API.demo.example.com, service: api, port: 8005 }\n"),
			want: `caddy.host_routes[0].host "API.demo.example.com" must be one lowercase DNS hostname`,
		},
		"port zero": {
			body: hostRoutesYAML("    - { host: api.demo.example.com, service: api, port: 0 }\n"),
			want: "caddy.host_routes[0].port 0",
		},
		"an invalid service": {
			body: hostRoutesYAML("    - { host: api.demo.example.com, service: Api/x, port: 8005 }\n"),
			want: `caddy.host_routes[0].service "Api/x" is not a valid Compose service name`,
		},
		"seventeen entries": {
			body: hostRoutesYAML(seventeen.String()),
			want: "caddy.host_routes is limited to 16 entries",
		},
		"a relative health path": {
			body: hostRoutesYAML("    - { host: api.demo.example.com, service: api, port: 8005, health_path: health }\n"),
			want: "caddy.host_routes[0].health_path must be an absolute HTTP path",
		},
		"a bad path route": {
			body: hostRoutesYAML("    - { host: api.demo.example.com, service: api, port: 8005, path_routes: [{ path: app, service: reverb, port: 8086 }] }\n"),
			want: `caddy.host_routes[0].path_routes path "app"`,
		},
		"a bad header": {
			body: hostRoutesYAML("    - { host: api.demo.example.com, service: api, port: 8005, headers: { X-Robots-Tag: 'no{index}' } }\n"),
			want: "caddy.host_routes[0].headers value for X-Robots-Tag",
		},
	}
	for name, tc := range cases {
		_, err := loadYAML(t, tc.body)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s must be refused with %q, got %v", name, tc.want, err)
		}
	}
}

// The existing spellings keep their exact error text: nothing that already
// parsed a message from the CLI may see it change.
func TestPathRoutesAndHeadersKeepTheirFieldNames(t *testing.T) {
	if err := validateCaddyPathRoutes([]CaddyPathRoute{{Path: "api", Service: "api", Port: 1}}); err == nil || !strings.HasPrefix(err.Error(), "caddy.path_routes path") {
		t.Fatalf("unexpected path route error: %v", err)
	}
	if err := validateCaddyHeaders(map[string]string{"bad name": "x"}); err == nil || !strings.HasPrefix(err.Error(), "caddy.headers name") {
		t.Fatalf("unexpected header error: %v", err)
	}
}

const testBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

func basicAuthYAML(users, routes string) string {
	return validConfig + "caddy:\n  basic_auth:\n    users:\n" + users + "  host_routes:\n" + routes
}

func TestBasicAuthAcceptsBcryptUsersAndGatedHostRoutes(t *testing.T) {
	cfg, err := loadYAML(t, basicAuthYAML(
		"      - { username: domebao, hash: '"+testBcryptHash+"' }\n",
		"    - { host: bo.demo.example.com, service: api, port: 8005, basic_auth: true }\n    - { host: api.demo.example.com, service: api, port: 8005 }\n"))
	if err != nil {
		t.Fatalf("a bcrypt user and a gated host route must be accepted, got %v", err)
	}
	if !cfg.Caddy.HostRoutes[0].BasicAuth || cfg.Caddy.HostRoutes[1].BasicAuth {
		t.Fatalf("basic_auth flag did not load as written: %#v", cfg.Caddy.HostRoutes)
	}
}

func TestBasicAuthIsRefusedWhenMalformed(t *testing.T) {
	user := "      - { username: domebao, hash: '" + testBcryptHash + "' }\n"
	var nine strings.Builder
	for i := 0; i < 9; i++ {
		fmt.Fprintf(&nine, "      - { username: u%d, hash: '%s' }\n", i, testBcryptHash)
	}
	cases := map[string]struct{ body, want string }{
		"a gated host route without users": {
			body: validConfig + "caddy:\n  host_routes:\n    - { host: bo.demo.example.com, service: api, port: 8005, basic_auth: true }\n",
			want: "caddy.host_routes[0].basic_auth requires caddy.basic_auth.users",
		},
		"nine users": {
			body: basicAuthYAML(nine.String(), ""),
			want: "caddy.basic_auth.users is limited to 8 entries",
		},
		"an uppercase username": {
			body: basicAuthYAML("      - { username: Domebao, hash: '"+testBcryptHash+"' }\n", ""),
			want: "caddy.basic_auth.users[0].username \"Domebao\" must match",
		},
		"a duplicated username": {
			body: basicAuthYAML(user+user, ""),
			want: "caddy.basic_auth.users[1].username \"domebao\" is declared twice",
		},
		"a clear-text password": {
			body: basicAuthYAML("      - { username: domebao, hash: 'hunter2' }\n", ""),
			want: "caddy.basic_auth.users[0].hash is not a bcrypt hash",
		},
		"a truncated hash": {
			body: basicAuthYAML("      - { username: domebao, hash: '"+testBcryptHash[:40]+"' }\n", ""),
			want: "caddy.basic_auth.users[0].hash is not a bcrypt hash",
		},
		"a missing username": {
			body: basicAuthYAML("      - { hash: '"+testBcryptHash+"' }\n", ""),
			want: "caddy.basic_auth.users[0].username is required",
		},
	}
	for name, tc := range cases {
		_, err := loadYAML(t, tc.body)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s must be refused with %q, got %v", name, tc.want, err)
		}
	}
}

func TestBasicAuthPublicPaths(t *testing.T) {
	user := "      - { username: domebao, hash: '" + testBcryptHash + "' }\n"
	cfg, err := loadYAML(t, validConfig+"caddy:\n  basic_auth:\n    users:\n"+user+"    public_paths: [/manifest.webmanifest, /sw.js, /_next/static/*]\n")
	if err != nil {
		t.Fatalf("public paths behind a declared gate must be accepted, got %v", err)
	}
	if len(cfg.Caddy.BasicAuth.PublicPaths) != 3 {
		t.Fatalf("public_paths did not load as written: %#v", cfg.Caddy.BasicAuth.PublicPaths)
	}
	cases := map[string]struct{ body, want string }{
		"without users": {
			body: validConfig + "caddy:\n  basic_auth:\n    public_paths: [/sw.js]\n",
			want: "caddy.basic_auth.public_paths needs caddy.basic_auth.users",
		},
		"the whole site": {
			body: validConfig + "caddy:\n  basic_auth:\n    users:\n" + user + "    public_paths: ['/*']\n",
			want: "would remove the gate from the whole site",
		},
		"a relative path": {
			body: validConfig + "caddy:\n  basic_auth:\n    users:\n" + user + "    public_paths: [sw.js]\n",
			want: "must be an absolute path matcher",
		},
	}
	for name, tc := range cases {
		if _, err := loadYAML(t, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
}
