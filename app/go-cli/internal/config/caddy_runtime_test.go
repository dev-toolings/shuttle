package config

import (
	"strings"
	"testing"
)

// The edge terminates public TLS as root. A host path that hands it the host's
// identity or its control plane must be refused by name, not by review.
func TestCaddyMountsRejectDangerousHostPaths(t *testing.T) {
	for _, source := range []string{"/", "/etc", "/root", "/run", "/var/run", "/var/lib/docker", "/proc", "/sys", "/usr"} {
		err := validateCaddyRuntime(Caddy{Mounts: []CaddyMount{{Source: source, Target: "/srv"}}})
		if err == nil || !strings.Contains(err.Error(), "must never mount") {
			t.Fatalf("mounting %q must be refused, got %v", source, err)
		}
	}
}

func TestCaddyMountsRejectPathsTheEdgeAlreadyOwns(t *testing.T) {
	for _, target := range []string{"/data", "/config", "/etc/caddy", "/etc/caddy/conf.d", "/run/secrets", "/tmp"} {
		err := validateCaddyRuntime(Caddy{Mounts: []CaddyMount{{Source: "/opt/media", Target: target}}})
		if err == nil || !strings.Contains(err.Error(), "already owns") {
			t.Fatalf("shadowing %q must be refused, got %v", target, err)
		}
	}
}

// A path that has to be rewritten to be safe is not a path the operator meant
// to write, so it is refused rather than cleaned.
func TestCaddyMountsRejectNonCanonicalPaths(t *testing.T) {
	for _, value := range []string{"opt/media", "/opt/media/", "/opt/../etc", "/opt//media", "/opt/media\n"} {
		err := validateCaddyRuntime(Caddy{Mounts: []CaddyMount{{Source: value, Target: "/srv"}}})
		if err == nil {
			t.Fatalf("source %q must be refused", value)
		}
	}
}

func TestCaddyMountsAcceptTheRealDeploymentPaths(t *testing.T) {
	err := validateCaddyRuntime(Caddy{
		DataVolume: "demo_caddy_data",
		Mounts: []CaddyMount{
			{Source: "/opt/caddy/maintenance", Target: "/srv"},
			{Source: "/opt/media", Target: "/opt/media"},
			{Source: "/opt/engram/releases", Target: "/var/engram-releases"},
			{Source: "/opt/caddy/logs", Target: "/var/log/caddy"},
		},
		Env:       map[string]string{"MAINTENANCE_MODE": "false"},
		SecretEnv: map[string]string{"CLOUDFLARE_API_TOKEN": "cloudflare_api_token"},
	})
	if err != nil {
		t.Fatalf("the deployment this key exists for must validate, got %v", err)
	}
}

func TestCaddyEnvAndSecretEnvAreValidated(t *testing.T) {
	cases := map[string]Caddy{
		"lowercase variable":     {Env: map[string]string{"maintenance_mode": "false"}},
		"newline in a value":     {Env: map[string]string{"MODE": "false\nevil"}},
		"invalid secret name":    {SecretEnv: map[string]string{"TOKEN": "not a secret"}},
		"invalid volume name":    {DataVolume: "not a volume"},
		"variable defined twice": {Env: map[string]string{"TOKEN": "x"}, SecretEnv: map[string]string{"TOKEN": "token"}},
	}
	for name, cfg := range cases {
		if err := validateCaddyRuntime(cfg); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

func TestCaddyMountsDefaultToReadOnly(t *testing.T) {
	writable := false
	if !(CaddyMount{}).IsReadOnly() {
		t.Fatal("a mount must default to read-only")
	}
	if (CaddyMount{ReadOnly: &writable}).IsReadOnly() {
		t.Fatal("an explicit read-write mount must stay writable")
	}
}
