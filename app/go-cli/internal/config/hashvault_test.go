package config

import (
	"strings"
	"testing"
)

func TestHashvaultBackendHasOneManifestAndNoLocalValues(t *testing.T) {
	cfg, err := loadYAML(t, validConfig+`secrets:
  backend: hashvault
  hashvault:
    target: swarm-main
`)
	if err != nil || !cfg.UsesHashvaultSecrets() || cfg.Secrets.Hashvault.Manifest != "hashvault.json" {
		t.Fatal(cfg, err)
	}
	if _, err := loadYAML(t, validConfig+`secrets:
  backend: hashvault
  hashvault:
    target: swarm-main
  items:
    KEY:
      services: [web]
`); err == nil || !strings.Contains(err.Error(), "remove secrets.items") {
		t.Fatal(err)
	}
	if _, err := loadYAML(t, validConfig+`secrets:
  backend: hashvault
`); err == nil {
		t.Fatal("target not required")
	}
}
