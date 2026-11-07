package config

import (
	"strings"
	"testing"
)

func internalFixture() *Config {
	return &Config{
		Version: 2,
		App:     "demo-agent",
		Expose:  ExposeInternal,
		Deploy:  Deploy{PrimaryService: "agent-next"},
		Services: map[string]Service{
			"agent-next": {Port: 3300, Healthcheck: Healthcheck{Path: "/health"}},
		},
	}
}

func TestInternalApplicationNeedsNoDomain(t *testing.T) {
	// validate() continues past the exposure block and fails later on the server
	// block, which this fixture deliberately omits. What matters is that it no
	// longer stops on the domain.
	err := validate(internalFixture())
	if err != nil && strings.Contains(err.Error(), "domain") {
		t.Fatalf("an internal application must not require a domain, got %v", err)
	}
}

func TestPublicApplicationStillRequiresADomain(t *testing.T) {
	cfg := internalFixture()
	cfg.Expose = ""
	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "domain is required") {
		t.Fatalf("the default exposure must still require a domain, got %v", err)
	}
}

// Each of these is a configuration that says two different things about where
// the application is reachable. Refuse rather than silently honour one.
func TestInternalApplicationRejectsPublicSettings(t *testing.T) {
	cases := map[string]func(*Config){
		"a domain":              func(c *Config) { c.Domain = "agent.example.com" },
		"a caddy route":         func(c *Config) { c.Caddy = Caddy{Routes: map[string]string{"agent.example.com": "agent-next:3300"}} },
		"an availability probe": func(c *Config) { c.Deploy.AvailabilityURL = "https://agent.example.com/health" },
	}
	for name, mutate := range cases {
		cfg := internalFixture()
		mutate(cfg)
		if err := validate(cfg); err == nil || !strings.Contains(err.Error(), "internal application") {
			t.Fatalf("an internal application declaring %s must be refused, got %v", name, err)
		}
	}
}

func TestExposeRejectsUnknownValues(t *testing.T) {
	cfg := internalFixture()
	cfg.Expose = "private"
	if err := validate(cfg); err == nil || !strings.Contains(err.Error(), "invalid expose") {
		t.Fatalf("an unknown exposure must be refused, got %v", err)
	}
}

func TestIsInternalDefaultsToPublic(t *testing.T) {
	if (&Config{}).IsInternal() || (*Config)(nil).IsInternal() || (&Config{Expose: ExposePublic}).IsInternal() {
		t.Fatal("only expose: internal may report as internal")
	}
}
