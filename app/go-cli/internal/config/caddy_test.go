package config

import (
	"strings"
	"testing"
)

func TestValidateCaddyImagesAcceptsOfficialTagOrDigest(t *testing.T) {
	if err := validateCaddyImages(Caddy{Image: "caddy:2"}); err != nil {
		t.Fatalf("official Caddy tag rejected: %v", err)
	}
	if err := validateCaddyImages(Caddy{Image: "caddy@sha256:" + strings.Repeat("a", 64)}); err != nil {
		t.Fatalf("valid Caddy digest rejected: %v", err)
	}
}
