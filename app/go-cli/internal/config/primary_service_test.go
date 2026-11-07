package config

import (
	"strings"
	"testing"
)

func primaryServiceFixture() *Config {
	return &Config{
		Version: 2,
		App:     "demo-core",
		Domain:  "api.example.com",
		Deploy:  Deploy{PrimaryService: "api"},
		Services: map[string]Service{
			"api": {Port: 8000, Healthcheck: Healthcheck{Path: "/api/v1/health"}},
		},
	}
}

func TestPrimaryServiceNameDefaultsToWeb(t *testing.T) {
	if name := (&Config{}).PrimaryServiceName(); name != DefaultPrimaryService {
		t.Fatalf("an unset deploy.primary_service must stay %q, got %q", DefaultPrimaryService, name)
	}
	if name := (*Config)(nil).PrimaryServiceName(); name != DefaultPrimaryService {
		t.Fatalf("a nil config must resolve to %q, got %q", DefaultPrimaryService, name)
	}
	if name := (&Config{Deploy: Deploy{PrimaryService: "  api  "}}).PrimaryServiceName(); name != "api" {
		t.Fatalf("surrounding whitespace must be trimmed, got %q", name)
	}
}

// The port and healthcheck requirements must follow the configured service, and
// say its name: an operator reading "services.web.port is required" while their
// compose file has no `web` has been told nothing useful.
func TestValidateRequiresThePrimaryServiceByName(t *testing.T) {
	cfg := primaryServiceFixture()
	cfg.Services = map[string]Service{"web": {Port: 3000, Healthcheck: Healthcheck{Path: "/health"}}}
	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "services.api.port") {
		t.Fatalf("expected the error to name the configured service, got %v", err)
	}

	cfg = primaryServiceFixture()
	cfg.Services["api"] = Service{Port: 8000}
	err = validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "services.api.healthcheck.path") {
		t.Fatalf("expected the healthcheck error to name the configured service, got %v", err)
	}
}

func TestValidateRejectsAnUnusableServiceName(t *testing.T) {
	for _, name := range []string{"Api", "api core", "-api", "api/core", strings.Repeat("a", 64)} {
		cfg := primaryServiceFixture()
		cfg.Deploy.PrimaryService = name
		err := validate(cfg)
		if err == nil || !strings.Contains(err.Error(), "deploy.primary_service") {
			t.Fatalf("service name %q must be rejected, got %v", name, err)
		}
	}
}

func TestServiceLimitsFallBackToTheShippedDefaults(t *testing.T) {
	limits := (&Config{}).ServiceLimits("absent")
	if limits.CPUs != DefaultServiceCPUs || limits.Memory != DefaultServiceMemory {
		t.Fatalf("a service with no entry must keep the shipped defaults, got %#v", limits)
	}
	partial := Service{Resources: Resources{Memory: "2G"}}.Limits()
	if partial.CPUs != DefaultServiceCPUs || partial.Memory != "2G" {
		t.Fatalf("one overridden field must not reset the other, got %#v", partial)
	}
}

func TestValidateRejectsUnusableResourceLimits(t *testing.T) {
	cases := map[string]Resources{
		"non-numeric cpus":              {CPUs: "one"},
		"zero cpus":                     {CPUs: "0"},
		"negative cpus":                 {CPUs: "-1"},
		"unitless memory":               {Memory: "768"},
		"memory below the Docker floor": {Memory: "4M"},
	}
	for name, resources := range cases {
		cfg := primaryServiceFixture()
		service := cfg.Services["api"]
		service.Resources = resources
		cfg.Services["api"] = service
		if err := validate(cfg); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestValidateAcceptsRealisticLimits(t *testing.T) {
	// Values taken from the stack this key exists for: a FrankenPHP API that
	// needs more than the default, and a worker that needs less.
	for name, resources := range map[string]Resources{
		"api":         {CPUs: "1.5", Memory: "1G"},
		"worker-high": {Memory: "384M"},
		"mercure":     {CPUs: "0.25", Memory: "256M"},
		"web":         {Memory: "2GB"},
	} {
		if err := validateServiceResources(name, Service{Resources: resources}); err != nil {
			t.Fatalf("%s limits %#v must validate, got %v", name, resources, err)
		}
	}
}

// Map iteration order is random, so the same invalid configuration must not
// produce a different message on each run.
func TestResourceValidationIsDeterministic(t *testing.T) {
	services := map[string]Service{
		"zebra": {Resources: Resources{CPUs: "nope"}},
		"alpha": {Resources: Resources{CPUs: "nope"}},
	}
	names := sortedServiceNames(services)
	if len(names) != 2 || names[0] != "alpha" || names[1] != "zebra" {
		t.Fatalf("service names must be sorted, got %v", names)
	}
}
