package config

import (
	"strings"
	"testing"
)

func TestValidateServiceUpdateOrderAcceptsBothOrdersOnASecondaryService(t *testing.T) {
	for _, order := range []string{"", UpdateOrderStartFirst, UpdateOrderStopFirst, "  stop-first  "} {
		if err := validateServiceUpdateOrder("mercure", Service{UpdateOrder: order}, "api"); err != nil {
			t.Fatalf("update_order %q on a non-published service: %v", order, err)
		}
	}
}

func TestValidateServiceUpdateOrderRejectsAnUnknownValue(t *testing.T) {
	for _, order := range []string{"startfirst", "rolling", "STOP-FIRST", "first-stop"} {
		err := validateServiceUpdateOrder("mercure", Service{UpdateOrder: order}, "api")
		if err == nil || !strings.Contains(err.Error(), "services.mercure.update_order") {
			t.Fatalf("update_order %q must be rejected, got %v", order, err)
		}
	}
}

// The published service is the one behind Caddy. stop-first there is not a
// slower rolling update, it is a window with nothing answering — exactly what
// Shuttle exists to avoid. Refuse it at validation rather than discover it in
// the middle of a promotion.
func TestValidateRejectsStopFirstOnThePublishedService(t *testing.T) {
	cfg := primaryServiceFixture()
	service := cfg.Services["api"]
	service.UpdateOrder = UpdateOrderStopFirst
	cfg.Services["api"] = service

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "services.api.update_order") {
		t.Fatalf("expected the published service to be refused, got %v", err)
	}
	if err := validateServiceUpdateOrder("api", service, "api"); err == nil {
		t.Fatal("the rule itself must refuse stop-first on the published service")
	}
	// Spelling out the default on the published service stays legal.
	service.UpdateOrder = UpdateOrderStartFirst
	if err := validateServiceUpdateOrder("api", service, "api"); err != nil {
		t.Fatalf("explicit start-first on the published service: %v", err)
	}
}

// The override is an exception, not a knob: unset means the zero-downtime
// default, including for services with no entry in the configuration at all.
func TestUpdateOrderResolvesTheDefault(t *testing.T) {
	var cfg *Config
	if got := cfg.UpdateOrder("anything"); got != UpdateOrderStartFirst {
		t.Fatalf("nil config resolved %q", got)
	}
	cfg = &Config{Services: map[string]Service{
		"web":     {Port: 3000},
		"mercure": {UpdateOrder: "  " + UpdateOrderStopFirst + "  "},
	}}
	if got := cfg.UpdateOrder("web"); got != UpdateOrderStartFirst {
		t.Fatalf("unset update_order resolved %q", got)
	}
	if got := cfg.UpdateOrder("absent"); got != UpdateOrderStartFirst {
		t.Fatalf("undeclared service resolved %q", got)
	}
	if got := cfg.UpdateOrder("mercure"); got != UpdateOrderStopFirst {
		t.Fatalf("surrounding whitespace must be trimmed, got %q", got)
	}
}
