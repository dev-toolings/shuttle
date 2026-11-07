//go:build linux

package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/monitoring"
)

func TestMonitoringUnitsAreBoundedAndReadOnly(t *testing.T) {
	service := monitoringServiceUnit("demo")
	for _, want := range []string{
		"ExecStart=/usr/local/libexec/shuttle-root apply monitor-run demo",
		"Type=oneshot",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/shuttle/monitoring",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("monitoring service is missing %q:\n%s", want, service)
		}
	}
	if strings.Contains(service, "docker system prune") || strings.Contains(service, "systemctl restart") {
		t.Fatal("monitoring service contains a destructive or restart command")
	}
	timer := monitoringTimerUnit("demo", 60)
	if !strings.Contains(timer, "OnUnitActiveSec=60s") || !strings.Contains(timer, "Persistent=true") {
		t.Fatalf("timer does not preserve the bounded interval: %s", timer)
	}
}

func TestMonitoringPathsArePerApplication(t *testing.T) {
	if rootMonitoringConfigPath("demo") == rootMonitoringConfigPath("other") {
		t.Fatal("monitoring configuration paths are not application scoped")
	}
	if monitoringServiceName("demo") != "shuttle-monitoring@demo.service" || monitoringTimerName("demo") != "shuttle-monitoring@demo.timer" {
		t.Fatal("unexpected systemd monitoring unit names")
	}
}

func TestMonitoringSandboxSharesHostLockAndAllowsFirewallReads(t *testing.T) {
	service := monitoringServiceUnitForPaths("demo", "/var/lib/shuttle/monitoring/demo", "/var/log/shuttle/failed.jsonl")
	for _, want := range []string{
		"After=docker.service postgresql.service systemd-tmpfiles-setup.service\n",
		"Requires=systemd-tmpfiles-setup.service\n",
		"ReadWritePaths=/var/lib/shuttle/monitoring/demo /var/log/shuttle /run/shuttle-root.lock -/run/ufw.lock\n",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("missing sandbox requirement %q in %s", want, service)
		}
	}
	if rootMonitoringTmpfiles != "f /run/shuttle-root.lock 0600 root root -\nf /run/ufw.lock 0600 root root -\n" {
		t.Fatalf("tmpfiles must create the shared root-only lock and ufw's lock without truncating or replacing them: %q", rootMonitoringTmpfiles)
	}
}

// Every lock a monitoring check writes is writable inside the sandbox and
// created by tmpfiles before the sandbox is built.
func TestMonitoringSandboxCoversEveryCheckLock(t *testing.T) {
	service := monitoringServiceUnitForPaths("demo", "/var/lib/shuttle/monitoring/demo", "")
	var writable []string
	for _, line := range strings.Split(service, "\n") {
		if strings.HasPrefix(line, "ReadWritePaths=") {
			for _, path := range strings.Fields(strings.TrimPrefix(line, "ReadWritePaths=")) {
				writable = append(writable, strings.TrimPrefix(path, "-"))
			}
		}
	}
	for _, lock := range rootMonitoringLockPaths {
		if !slices.Contains(writable, lock) {
			t.Fatalf("lock %s is not in ReadWritePaths %v", lock, writable)
		}
		if !strings.Contains(rootMonitoringTmpfiles, "f "+lock+" ") {
			t.Fatalf("lock %s is not created by tmpfiles: %q", lock, rootMonitoringTmpfiles)
		}
	}
}

func TestMonitoringInstallRejectsUnresolvableChannelBeforeTimerActivation(t *testing.T) {
	name := "SHUTTLE_MONITORING_TEST_WEBHOOK"
	oldEnvironment := rootMonitoringSystemdEnvironment
	t.Cleanup(func() { rootMonitoringSystemdEnvironment = oldEnvironment })

	for _, value := range []string{"", "not-a-url", "http://notify.example.test/hook"} {
		t.Run(value, func(t *testing.T) {
			rootMonitoringSystemdEnvironment = func(got string) (string, error) {
				if got != name {
					t.Fatalf("systemd environment lookup used %q, want %q", got, name)
				}
				return value, nil
			}
			installed := monitoring.InstalledConfig{
				App:        "demo",
				Monitoring: config.MonitoringConfig{Notifications: config.MonitoringNotifications{WebhookEnv: name}},
			}
			timerEnabled := false
			err := installRootMonitoringWithChannelProof(installed, func() error {
				timerEnabled = true
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "webhook_secret_file") || !strings.Contains(err.Error(), "monitoring install --yes") {
				t.Fatalf("missing channel did not include the fix: %v", err)
			}
			if strings.Contains(err.Error(), value) && value != "" {
				t.Fatalf("channel value leaked in the error: %v", err)
			}
			if timerEnabled {
				t.Fatal("timer activation ran despite an unresolved notification channel")
			}
		})
	}
}

func TestMonitoringInstallValidatesAndPassesSystemdWebhookEnvironment(t *testing.T) {
	name := "SHUTTLE_MONITORING_TEST_WEBHOOK"
	oldEnvironment := rootMonitoringSystemdEnvironment
	rootMonitoringSystemdEnvironment = func(got string) (string, error) {
		if got != name {
			t.Fatalf("systemd environment lookup used %q, want %q", got, name)
		}
		return "https://notify.example.test/hook", nil
	}
	t.Cleanup(func() { rootMonitoringSystemdEnvironment = oldEnvironment })
	installed := monitoring.InstalledConfig{
		App:        "demo",
		Monitoring: config.MonitoringConfig{Notifications: config.MonitoringNotifications{WebhookEnv: name}},
	}
	if err := validateRootMonitoringNotification(installed); err != nil {
		t.Fatalf("valid systemd HTTPS channel was rejected: %v", err)
	}
	unit := monitoringServiceUnitForInstalled(installed)
	if !strings.Contains(unit, "PassEnvironment="+name+"\n") {
		t.Fatalf("monitoring service does not pass its configured environment: %s", unit)
	}
}
