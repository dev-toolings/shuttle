package cli

import (
	"testing"
)

func TestSiteBaseURLNormalisesConfiguredOrigin(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", " https://releases.example.com/ ")
	if got := siteBaseURL(); got != "https://releases.example.com" {
		t.Fatalf("expected a trimmed origin, got %q", got)
	}
}
