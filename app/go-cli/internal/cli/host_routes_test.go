package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func hostRoutesConfig() *config.Config {
	return &config.Config{
		Version: 2, App: "domebao", Domain: "domebao.com",
		Deploy: config.Deploy{PrimaryService: "web"},
		Caddy: config.Caddy{
			Network: "caddy_network",
			HostRoutes: []config.CaddyHostRoute{
				{Host: "api.domebao.com", Service: "api", Port: 8005},
				{Host: "bo.domebao.com", Service: "api", Port: 8005, PathRoutes: []config.CaddyPathRoute{{Path: "/app/*", Service: "reverb", Port: 8086}}},
			},
		},
	}
}

// securedHostRoutesStack runs the compose-to-stack conversion and then the
// hardening pass, which is where the routing labels are written.
func securedHostRoutesStack(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	cf := parseComposeString(t, `
services:
  web:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  api:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  reverb:
    build: .
    healthcheck: {test: ["CMD", "true"]}
`)
	images := map[string]string{}
	for _, name := range []string{"web", "api", "reverb"} {
		images[name] = "registry/" + name + "@sha256:" + strings.Repeat("a", 64)
	}
	generated, err := generateSwarmStackWithSecrets(cf, cfg, images, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "3011")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}
	return root
}

// The helper derives every site from the published service's labels, so the
// host list has to ride there and nowhere else.
func TestHostRoutesLabelThePrimaryServiceOnly(t *testing.T) {
	cfg := hostRoutesConfig()
	doc := securedHostRoutesStack(t, cfg)
	web := generatedService(t, doc, "web")
	deploy, _ := web["deploy"].(map[string]any)
	labels, _ := deploy["labels"].(map[string]any)
	raw, ok := labels["dev.shuttle.host_routes"].(string)
	if !ok {
		t.Fatalf("the published service must carry dev.shuttle.host_routes, got %#v", labels)
	}
	var decoded []config.CaddyHostRoute
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("label is not JSON: %v", err)
	}
	if len(decoded) != 2 || decoded[0].Host != "api.domebao.com" || decoded[1].PathRoutes[0].Service != "reverb" {
		t.Fatalf("label does not carry the declared hosts in order: %s", raw)
	}
	api := generatedService(t, doc, "api")
	apiDeploy, _ := api["deploy"].(map[string]any)
	if apiLabels, present := apiDeploy["labels"]; present {
		t.Fatalf("a routed service must carry no routing labels: %#v", apiLabels)
	}
}

func TestHostRoutesLabelIsAbsentWithoutHostRoutes(t *testing.T) {
	cfg := hostRoutesConfig()
	cfg.Caddy.HostRoutes = nil
	doc := securedHostRoutesStack(t, cfg)
	web := generatedService(t, doc, "web")
	deploy, _ := web["deploy"].(map[string]any)
	labels, _ := deploy["labels"].(map[string]any)
	if _, present := labels["dev.shuttle.host_routes"]; present {
		t.Fatalf("a configuration without host routes must not emit the label: %#v", labels)
	}
}

func TestHostRoutesLabelIsAbsentOnAnInternalStack(t *testing.T) {
	cfg := hostRoutesConfig()
	cfg.Expose = config.ExposeInternal
	doc := securedHostRoutesStack(t, cfg)
	web := generatedService(t, doc, "web")
	deploy, _ := web["deploy"].(map[string]any)
	labels, _ := deploy["labels"].(map[string]any)
	if _, present := labels["dev.shuttle.host_routes"]; present {
		t.Fatalf("an internal application must publish no host: %#v", labels)
	}
}

// A host whose service never joined the edge network answers a bad gateway,
// exactly like a path route did before it was attached.
func TestNetworkTargetsIncludeHostRouteServices(t *testing.T) {
	got := caddyNetworkTargets(hostRoutesConfig())
	want := []string{"api", "reverb", "web"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("caddyNetworkTargets = %v, want %v", got, want)
	}
	internal := hostRoutesConfig()
	internal.Expose = config.ExposeInternal
	if got := caddyNetworkTargets(internal); len(got) != 0 {
		t.Fatalf("an internal application must join nothing, got %v", got)
	}
}

func TestDeployRefusesAHostRouteToAnAbsentService(t *testing.T) {
	parsed := parseComposeString(t, "services:\n  web:\n    build: .\n  api:\n    build: .\n")
	cfg := hostRoutesConfig()
	err := validateHostRouteServices(parsed, cfg)
	if err == nil || err.Error() != `caddy.host_routes[1].path_routes[0].service "reverb" is not in the compose file` {
		t.Fatalf("a path route to an absent service must be refused, got %v", err)
	}
	cfg.Caddy.HostRoutes[1].PathRoutes = nil
	cfg.Caddy.HostRoutes[0].Service = "umami"
	err = validateHostRouteServices(parsed, cfg)
	if err == nil || err.Error() != `caddy.host_routes[0].service "umami" is not in the compose file` {
		t.Fatalf("a host route to an absent service must be refused, got %v", err)
	}
	cfg.Caddy.HostRoutes[0].Service = "api"
	if err := validateHostRouteServices(parsed, cfg); err != nil {
		t.Fatalf("host routes to present services must pass, got %v", err)
	}
}

// Every extra hostname is a certificate the edge will request: a host that
// points elsewhere fails the proof and names itself.
func TestOriginProofCoversHostRoutes(t *testing.T) {
	originalLookup, originalClient := lookupDomainIPs, publicOriginClient
	t.Cleanup(func() { lookupDomainIPs, publicOriginClient = originalLookup, originalClient })
	var probed []string
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(request *http.Request) (*http.Response, error) {
		probed = append(probed, request.URL.String())
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})}
	cfg := hostRoutesConfig()
	cfg.Readiness.HealthcheckPath = "/health"
	cfg.Caddy.HostRoutes[0].HealthPath = "/api/v1/health"

	lookupDomainIPs = func(name string) ([]net.IP, error) {
		if name == "bo.domebao.com" {
			return []net.IP{net.ParseIP("198.51.100.7")}, nil
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}
	err := proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "host route bo.domebao.com does not resolve directly") {
		t.Fatalf("a host route pointing elsewhere must fail by name, got %v", err)
	}

	probed = nil
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	want := []string{"https://domebao.com/health", "https://api.domebao.com/api/v1/health"}
	if fmt.Sprint(probed) != fmt.Sprint(want) {
		t.Fatalf("only the domain and the hosts with a health_path are probed: got %v, want %v", probed, want)
	}
}

const testBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// The gate rides on the published service as bcrypt hashes: what Caddy reads,
// and nothing a label could leak.
func TestBasicAuthLabelsThePrimaryService(t *testing.T) {
	cfg := hostRoutesConfig()
	cfg.Caddy.BasicAuth = config.CaddyBasicAuth{Users: []config.CaddyBasicAuthUser{{Username: "domebao", Hash: testBcryptHash}}}
	cfg.Caddy.HostRoutes[1].BasicAuth = true
	doc := securedHostRoutesStack(t, cfg)
	web := generatedService(t, doc, "web")
	deploy, _ := web["deploy"].(map[string]any)
	labels, _ := deploy["labels"].(map[string]any)
	raw, ok := labels["dev.shuttle.basic_auth"].(string)
	if !ok || raw != `[{"username":"domebao","hash":"`+testBcryptHash+`"}]` {
		t.Fatalf("the published service must carry the basic auth users, got %#v", labels["dev.shuttle.basic_auth"])
	}
	hosts, _ := labels["dev.shuttle.host_routes"].(string)
	if !strings.Contains(hosts, `"host":"bo.domebao.com","service":"api","port":8005,"path_routes":[{"path":"/app/*","service":"reverb","port":8086}],"basic_auth":true`) {
		t.Fatalf("the gated host must carry its flag: %s", hosts)
	}
	if strings.Contains(hosts, `"host":"api.domebao.com","service":"api","port":8005,"basic_auth"`) {
		t.Fatalf("an ungated host must not carry the flag: %s", hosts)
	}
}

func TestBasicAuthLabelIsAbsentWithoutUsers(t *testing.T) {
	doc := securedHostRoutesStack(t, hostRoutesConfig())
	web := generatedService(t, doc, "web")
	deploy, _ := web["deploy"].(map[string]any)
	labels, _ := deploy["labels"].(map[string]any)
	if _, present := labels["dev.shuttle.basic_auth"]; present {
		t.Fatalf("a configuration without basic auth must not emit the label: %#v", labels)
	}
}

func TestBasicAuthLabelIsAbsentOnAnInternalStack(t *testing.T) {
	cfg := hostRoutesConfig()
	cfg.Expose = config.ExposeInternal
	cfg.Caddy.BasicAuth = config.CaddyBasicAuth{Users: []config.CaddyBasicAuthUser{{Username: "domebao", Hash: testBcryptHash}}}
	doc := securedHostRoutesStack(t, cfg)
	web := generatedService(t, doc, "web")
	deploy, _ := web["deploy"].(map[string]any)
	labels, _ := deploy["labels"].(map[string]any)
	if _, present := labels["dev.shuttle.basic_auth"]; present {
		t.Fatalf("an internal application publishes no gate: %#v", labels)
	}
}

// A gated site answers the proof with 401 from the edge itself. That is a
// valid proof only where the gate is declared; an open site's 401 still fails.
func TestOriginProofAcceptsTheBasicAuthChallengeOnlyWhereGated(t *testing.T) {
	originalLookup, originalClient := lookupDomainIPs, publicOriginClient
	t.Cleanup(func() { lookupDomainIPs, publicOriginClient = originalLookup, originalClient })
	lookupDomainIPs = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	challenge := func(*http.Request) (*http.Response, error) {
		response := &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}
		response.Header.Set("WWW-Authenticate", `Basic realm="restricted"`)
		return response, nil
	}
	publicOriginClient = &http.Client{Transport: originRoundTripper(challenge)}

	cfg := hostRoutesConfig()
	cfg.Readiness.HealthcheckPath = "/health"
	cfg.Deploy.PromotionSLOSeconds = 1
	cfg.Caddy.HostRoutes[0].HealthPath = "/api/v1/health"
	err := proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("an open domain answering 401 must fail the proof, got %v", err)
	}

	cfg.Caddy.BasicAuth = config.CaddyBasicAuth{Users: []config.CaddyBasicAuthUser{{Username: "domebao", Hash: testBcryptHash}}}
	err = proveDirectOrigin(cfg, "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a host route without the gate answering 401 must still fail, got %v", err)
	}

	cfg.Caddy.HostRoutes[0].BasicAuth = true
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err != nil {
		t.Fatalf("a gated domain and a gated host answering a Basic challenge are healthy, got %v", err)
	}

	// A 401 without a Basic challenge is the application, not the edge.
	publicOriginClient = &http.Client{Transport: originRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if err := proveDirectOrigin(cfg, "203.0.113.10"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a bare 401 must not pass as the edge's gate, got %v", err)
	}
}
