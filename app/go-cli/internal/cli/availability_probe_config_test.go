package cli

import (
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestAvailabilityURLIsGatedOnlyForConfiguredHostname(t *testing.T) {
	disabled := false
	cfg := &config.Config{
		Domain: "example.com",
		Deploy: config.Deploy{AvailabilityURL: "https://example.com/health"},
		Caddy: config.Caddy{
			BasicAuth: config.CaddyBasicAuth{Users: []config.CaddyBasicAuthUser{{Username: "operator"}}},
			HostRoutes: []config.CaddyHostRoute{
				{Host: "admin.example.com", BasicAuth: true},
				{Host: "api.example.com"},
			},
		},
	}

	if !availabilityURLIsGated(cfg) {
		t.Fatal("the gated primary domain was not recognised")
	}
	cfg.Caddy.DomainBasicAuth = &disabled
	if availabilityURLIsGated(cfg) {
		t.Fatal("domain_basic_auth: false must leave the primary domain ungated")
	}
	cfg.Deploy.AvailabilityURL = "https://ADMIN.example.com./health"
	if !availabilityURLIsGated(cfg) {
		t.Fatal("a gated host route was not recognised")
	}
	cfg.Deploy.AvailabilityURL = "https://api.example.com/health"
	if availabilityURLIsGated(cfg) {
		t.Fatal("an ungated host route must not accept a 401")
	}
	cfg.Deploy.AvailabilityURL = "https://unrelated.example/health"
	if availabilityURLIsGated(cfg) {
		t.Fatal("an unrelated hostname must not inherit the application's gate")
	}
}
