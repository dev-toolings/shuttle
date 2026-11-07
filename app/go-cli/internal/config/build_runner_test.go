package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func sshBuildConfig() string {
	return strings.Replace(validConfig, "domain: demo.example.com\n", "domain: demo.example.com\nbuild:\n  runner: ssh\n  host: 192.0.2.40\n  user: build\n  host_key: "+testHostKey+"\n  identity_file: ~/.ssh/build\n  registry_identity_file: /home/build/.ssh/registry-tunnel\n", 1)
}

func TestSSHBuildRunnerDefaultsPortAndKeepsIdentityPaths(t *testing.T) {
	cfg, err := loadYAML(t, sshBuildConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Build.UsesSSH() || cfg.Build.Port != 22 {
		t.Fatalf("unexpected SSH build runner defaults: %+v", cfg.Build)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"~/.ssh/build", "/home/build/.ssh/registry-tunnel", "-----BEGIN"} {
		if value == "-----BEGIN" {
			if strings.Contains(string(encoded), value) {
				t.Fatal("private key content appeared in serialized configuration")
			}
			continue
		}
		if !strings.Contains(string(encoded), value) {
			t.Fatalf("serialized configuration lost identity path %q: %s", value, encoded)
		}
	}
}

func TestBuildRunnerRefusesIncompleteAndAmbiguousSettings(t *testing.T) {
	base := validConfig
	cases := []struct {
		name string
		body string
		want string
	}{
		{"missing host", strings.Replace(base, "domain: demo.example.com\n", "domain: demo.example.com\nbuild:\n  runner: ssh\n  user: build\n  host_key: "+testHostKey+"\n  identity_file: ~/.ssh/build\n  registry_identity_file: /home/build/.ssh/registry\n", 1), "build.host is required"},
		{"missing user", strings.Replace(base, "domain: demo.example.com\n", "domain: demo.example.com\nbuild:\n  runner: ssh\n  host: 192.0.2.40\n  host_key: "+testHostKey+"\n  identity_file: ~/.ssh/build\n  registry_identity_file: /home/build/.ssh/registry\n", 1), "build.user must name"},
		{"missing host key", strings.Replace(base, "domain: demo.example.com\n", "domain: demo.example.com\nbuild:\n  runner: ssh\n  host: 192.0.2.40\n  user: build\n  identity_file: ~/.ssh/build\n  registry_identity_file: /home/build/.ssh/registry\n", 1), "build.host_key"},
		{"inline identity", strings.Replace(sshBuildConfig(), "~/.ssh/build", "-----BEGIN PRIVATE KEY-----", 1), "not key content"},
		{"deploy identity", strings.Replace(sshBuildConfig(), "~/.ssh/build", "~/.ssh/id_shuttle", 1), "separate from the deploy SSH identity"},
		{"same identities", strings.Replace(sshBuildConfig(), "/home/build/.ssh/registry-tunnel", "~/.ssh/build", 1), "separate credentials"},
		{"local with SSH fields", strings.Replace(sshBuildConfig(), "runner: ssh", "runner: local", 1), "local is the default"},
		{"production host", strings.Replace(sshBuildConfig(), "192.0.2.40", "203.0.113.10", 1), "targets production"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadYAML(t, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestSSHBuildRunnerIsExplicitlyRejectedByCompose(t *testing.T) {
	body := strings.Replace(sshBuildConfig(), "strategy: swarm", "strategy: compose", 1)
	body = strings.Replace(body, "user: deploy", "user: bob", 1)
	body = strings.Replace(body, "  port: 22\n", "  port: 22\n  host_key: "+testHostKey+"\n", 1)
	if _, err := loadYAML(t, body); err == nil || !strings.Contains(err.Error(), "supported only with deploy.strategy: swarm") {
		t.Fatalf("expected explicit compose runner refusal, got %v", err)
	}
}
