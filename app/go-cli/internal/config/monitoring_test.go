package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMonitoringIsOptInAndDefaultsStayBounded(t *testing.T) {
	cfg, err := loadYAML(t, validConfig)
	if err != nil || cfg.Monitoring != nil {
		t.Fatalf("monitoring must remain absent by default: cfg=%#v err=%v", cfg, err)
	}
	body := validConfig + `
monitoring:
  enabled: true
  interval_seconds: 30
  notifications:
    webhook_env: SHUTTLE_MONITOR_WEBHOOK
  backup:
    expected: true
`
	cfg, err = loadYAML(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Monitoring.IntervalSeconds != 30 || cfg.Monitoring.TimeoutSeconds != DefaultMonitoringTimeout || cfg.Monitoring.StaleAfterSeconds < cfg.Monitoring.IntervalSeconds {
		t.Fatalf("unexpected monitoring defaults: %#v", cfg.Monitoring)
	}
	if cfg.Monitoring.Disk.Data.Path == "" || cfg.Monitoring.Backup.Path == "" || !cfg.Monitoring.Security.RequireSSHKeyOnly {
		t.Fatalf("monitoring defaults did not materialize its bounded posture: %#v", cfg.Monitoring)
	}
}

func TestMonitoringRejectsUnboundedOrUnsafeValues(t *testing.T) {
	tests := map[string]string{
		"disabled settings":        validConfig + "\nmonitoring:\n  interval_seconds: 30\n",
		"short interval":           validConfig + "\nmonitoring:\n  enabled: true\n  interval_seconds: 1\n",
		"stale before interval":    validConfig + "\nmonitoring:\n  enabled: true\n  interval_seconds: 60\n  stale_after_seconds: 30\n",
		"relative disk path":       validConfig + "\nmonitoring:\n  enabled: true\n  disk:\n    data:\n      path: relative\n",
		"HTTP TLS URL":             validConfig + "\nmonitoring:\n  enabled: true\n  tls:\n    url: http://service.example/health\n    min_days: 14\n",
		"webhook secret in config": validConfig + "\nmonitoring:\n  enabled: true\n  notifications:\n    webhook_env: BAD-NAME\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err == nil {
				t.Fatal("unsafe monitoring configuration was accepted")
			}
		})
	}
}

func TestMonitoringAcceptsSeparateDiskThresholdsAndExternalHTTPS(t *testing.T) {
	body := validConfig + "\nmonitoring:\n  enabled: true\n  disk:\n    data:\n      path: /srv/shuttle\n      min_free_percent: 12\n      min_free_inodes_percent: 8\n  external:\n    url: https://probe.example/health\n    webhook_env: SHUTTLE_EXTERNAL_WEBHOOK\n"
	cfg, err := loadYAML(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Monitoring.Disk.Data.MinFreePercent != 12 || cfg.Monitoring.Disk.Data.MinFreeInodesPercent != 8 || cfg.Monitoring.External.URL == "" {
		t.Fatalf("monitoring values did not survive loading: %#v", cfg.Monitoring)
	}
	if strings.Contains(string(stringMustMarshal(cfg)), "https://secret") {
		t.Fatal("notification secret value must not be serialized")
	}
}

func TestMonitoringDoesNotDefaultCacheToHostVarCache(t *testing.T) {
	value := MonitoringConfig{Enabled: true}
	value.NormalizeMonitoring()
	if value.Disk.Cache.Path != "" {
		t.Fatalf("cache path was defaulted to %q; BuildKit remote cache is not a VPS target", value.Disk.Cache.Path)
	}
	if !DiskCachePathInVPSScope("/srv/build-cache") || DiskCachePathInVPSScope("/var/cache") || DiskCachePathInVPSScope("") {
		t.Fatal("cache VPS-scope classification is wrong")
	}
}

func TestTrustedAccessDefaultsFillEmptyFieldsAndPreserveExplicitSettings(t *testing.T) {
	value := MonitoringConfig{Enabled: true}
	value.ApplyTrustedAccessDefaults(MonitoringAccessDefaults{
		Users:           []string{"deploy", "ops"},
		AllowedTCPPorts: []string{"22", "80", "443"},
		SSHPort:         22,
		ListenAddress:   "203.0.113.10",
		PeerAddress:     "",
	})
	if got := strings.Join(value.Security.ExpectedSSHUsers, " "); got != "deploy ops" {
		t.Fatalf("expected SSH users were not materialized: %#v", value.Security)
	}
	if got := strings.Join(value.Security.AllowedTCPPorts, ","); got != "22,80,443" {
		t.Fatalf("expected TCP ports were not materialized: %#v", value.Security)
	}
	if value.Security.SSHListenAddress != "203.0.113.10" || value.Security.SSHPeerAddress != "" {
		t.Fatalf("listen address must come from inventory and peer must stay unobserved: %#v", value.Security)
	}
	value.Security.ExpectedSSHUsers = []string{"alice"}
	value.Security.AllowedTCPPorts = []string{"443"}
	value.Security.SSHListenAddress = "198.51.100.10"
	value.ApplyTrustedAccessDefaults(MonitoringAccessDefaults{
		Users:           []string{"deploy", "ops"},
		AllowedTCPPorts: []string{"22", "80", "443"},
		ListenAddress:   "203.0.113.10",
	})
	if got := strings.Join(value.Security.ExpectedSSHUsers, " "); got != "alice" {
		t.Fatalf("explicit SSH users were overwritten: %#v", value.Security)
	}
	if got := strings.Join(value.Security.AllowedTCPPorts, ","); got != "443" {
		t.Fatalf("explicit TCP ports were overwritten: %#v", value.Security)
	}
	if value.Security.SSHListenAddress != "198.51.100.10" || value.Security.SSHPeerAddress != "" {
		t.Fatalf("explicit listen/peer settings were not preserved: %#v", value.Security)
	}
	if MonitoringSSHListenAddress("vps.example.com") != "" || MonitoringSSHListenAddress("203.0.113.10") != "203.0.113.10" {
		t.Fatal("hostname listen addresses must not be invented as IPs")
	}
}

func TestRequiredSecurityPoliciesActivateTheirCollectors(t *testing.T) {
	body := validConfig + `
monitoring:
  enabled: true
  notifications:
    webhook_env: SHUTTLE_MONITOR_WEBHOOK
  security:
    require_ssh_key_only: true
    require_ufw: true
    require_docker_user: true
    require_fail2ban: true
`
	cfg, err := loadYAML(t, body)
	if err != nil {
		t.Fatal(err)
	}
	security := cfg.Monitoring.Security
	if !security.CheckSSH || !security.CheckUFW || !security.CheckDockerUser || !security.CheckFail2ban {
		t.Fatalf("required security policies did not activate all collectors: %#v", security)
	}
}

func stringMustMarshal(cfg *Config) []byte {
	body, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	return body
}
