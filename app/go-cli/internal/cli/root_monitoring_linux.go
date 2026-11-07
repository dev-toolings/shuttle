//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/monitoring"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

const rootMonitoringConfigDir = "/etc/shuttle/monitoring"
const rootMonitoringTmpfilesPath = "/etc/tmpfiles.d/shuttle-root.conf"
const rootMonitoringChannelFix = "monitoring notification channel must resolve to an HTTPS URL; set monitoring.notifications.webhook_secret_file to a root-owned 0600 file containing the URL, or configure monitoring.notifications.webhook_env in the systemd manager environment if supported, then rerun `shuttle monitoring install --yes`"

var rootMonitoringSystemdEnvironment = readRootMonitoringSystemdEnvironment

// The shared flock must exist before systemd builds the read-only mount namespace.
// A tmpfiles f entry creates it after reboot without replacing an existing inode.
// /run/ufw.lock is ufw's own lock: `ufw status` opens it for writing, and under
// ProtectSystem=strict a missing or read-only lock made security.ufw report
// `unavailable` on every timer cycle while the same check was healthy through
// the unsandboxed helper (demo prod, 2026-10-27, DEV-DEPL-58).
const rootMonitoringTmpfiles = "f /run/shuttle-root.lock 0600 root root -\n" +
	"f /run/ufw.lock 0600 root root -\n"

// rootMonitoringLockPaths are the files a monitoring check writes outside its
// state directory; each must be writable in the unit and created by tmpfiles.
var rootMonitoringLockPaths = []string{"/run/shuttle-root.lock", "/run/ufw.lock"}

func rootMonitoringConfigPath(app string) string {
	return filepath.Join(rootMonitoringConfigDir, app+".json")
}

func rootMonitoringStatePath(installed monitoring.InstalledConfig) string {
	return filepath.Join(installed.Monitoring.StateDir, "maintenance.json")
}

func monitoringServiceName(app string) string { return "shuttle-monitoring@" + app + ".service" }
func monitoringTimerName(app string) string   { return "shuttle-monitoring@" + app + ".timer" }

func monitoringServiceUnit(app string) string {
	return monitoringServiceUnitForState(app, "/var/lib/shuttle/monitoring")
}

func monitoringServiceUnitForState(app, stateDir string) string {
	return monitoringServiceUnitForPaths(app, stateDir, "")
}

func monitoringServiceUnitForPaths(app, stateDir, failureLog string) string {
	return monitoringServiceUnitForEnvironment(app, stateDir, failureLog, "")
}

func monitoringServiceUnitForInstalled(installed monitoring.InstalledConfig) string {
	failureLog := installed.Monitoring.Notifications.FailureLog
	if failureLog == "" {
		failureLog = filepath.Join(installed.Monitoring.StateDir, "delivery-failures.jsonl")
	}
	return monitoringServiceUnitForEnvironment(installed.App, installed.Monitoring.StateDir, failureLog, installed.Monitoring.Notifications.WebhookEnv)
}

func monitoringServiceUnitForEnvironment(app, stateDir, failureLog, webhookEnv string) string {
	paths := stateDir
	if failureLog != "" && filepath.Dir(failureLog) != stateDir {
		paths += " " + filepath.Dir(failureLog)
	}
	passEnvironment := ""
	if webhookEnv != "" {
		passEnvironment = "PassEnvironment=" + webhookEnv + "\n"
	}
	return "[Unit]\n" +
		"Description=Shuttle read-only monitoring for " + app + "\n" +
		"After=docker.service postgresql.service systemd-tmpfiles-setup.service\n" +
		"Requires=systemd-tmpfiles-setup.service\n" +
		"Wants=docker.service postgresql.service\n\n" +
		"[Service]\n" +
		"Type=oneshot\n" +
		passEnvironment +
		"User=root\n" +
		"ExecStart=/usr/local/libexec/shuttle-root apply monitor-run " + app + "\n" +
		"NoNewPrivileges=yes\n" +
		"PrivateTmp=yes\n" +
		"ProtectHome=yes\n" +
		"ProtectSystem=strict\n" +
		// The "-" prefix keeps the unit starting on a host without ufw.
		"ReadWritePaths=" + paths + " /run/shuttle-root.lock -/run/ufw.lock\n" +
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
}

func monitoringTimerUnit(app string, interval int) string {
	return "[Unit]\n" +
		"Description=Periodic Shuttle monitoring for " + app + "\n\n" +
		"[Timer]\n" +
		"Unit=" + monitoringServiceName(app) + "\n" +
		"OnBootSec=1min\n" +
		fmt.Sprintf("OnUnitActiveSec=%ds\n", interval) +
		"Persistent=true\n" +
		"AccuracySec=1s\n\n" +
		"[Install]\n" +
		"WantedBy=timers.target\n"
}

func validateRootInstalledMonitoring(plan rootplan.Plan, payload []byte) (monitoring.InstalledConfig, error) {
	if plan.Monitoring == nil {
		return monitoring.InstalledConfig{}, errors.New("monitoring operation is incomplete")
	}
	if rootplan.PayloadDigest(payload) != plan.Monitoring.PayloadSHA256 {
		return monitoring.InstalledConfig{}, errors.New("monitoring payload does not match the signed digest")
	}
	installed, err := monitoring.DecodeInstalledConfig(payload)
	if err != nil {
		return installed, err
	}
	if installed.App != plan.Monitoring.App {
		return installed, errors.New("monitoring payload application differs from signed operation")
	}
	return installed, nil
}

func installRootMonitoring(plan rootplan.Plan, payload []byte) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		installed, err := validateRootInstalledMonitoring(plan, payload)
		if err != nil {
			return err
		}
		return installRootMonitoringWithChannelProof(installed, func() error {
			if err := ensureRootMonitoringOutput(installed); err != nil {
				return err
			}
			if err := ensureRootDirectoryBelow(rootMonitoringConfigDir, "/etc/shuttle"); err != nil {
				return err
			}
			if err := writeRootFile(rootMonitoringConfigPath(installed.App), payload, 0o600); err != nil {
				return err
			}
			if err := writeRootFile(rootMonitoringTmpfilesPath, []byte(rootMonitoringTmpfiles), 0o644); err != nil {
				return err
			}
			// Apply the rule now, not only at the next boot. The unit's
			// "-/run/ufw.lock" is skipped silently when the file is missing, and
			// only ufw's Python frontend ever creates it, so a host installed after
			// boot kept security.ufw `unavailable` until a reboot. tmpfiles `f`
			// creates a missing file and never truncates or replaces one.
			if err := runFixed("/usr/bin/systemd-tmpfiles", "--create", rootMonitoringTmpfilesPath); err != nil {
				return fmt.Errorf("create monitoring locks: %w", err)
			}
			if err := writeRootFile("/etc/systemd/system/"+monitoringServiceName(installed.App), []byte(monitoringServiceUnitForInstalled(installed)), 0o644); err != nil {
				return err
			}
			if err := writeRootFile("/etc/systemd/system/"+monitoringTimerName(installed.App), []byte(monitoringTimerUnit(installed.App, installed.Monitoring.IntervalSeconds)), 0o644); err != nil {
				return err
			}
			if err := runFixed("/usr/bin/systemctl", "daemon-reload"); err != nil {
				return err
			}
			if err := runFixed("/usr/bin/systemctl", "enable", "--now", monitoringTimerName(installed.App)); err != nil {
				return err
			}
			rootLog("monitoring app=%s installed interval=%ds", installed.App, installed.Monitoring.IntervalSeconds)
			return nil
		})
	})
}

// Channel resolution is a precondition for every install mutation. The timer
// can start the oneshot immediately, so accepting an absent webhook would
// create the failed unit that status cannot otherwise distinguish from a
// healthy install. The systemd service passes a validated manager variable
// through on each run; runtime removal remains a real and reportable failure.
func installRootMonitoringWithChannelProof(installed monitoring.InstalledConfig, install func() error) error {
	if err := validateRootMonitoringNotification(installed); err != nil {
		return err
	}
	return install()
}

func validateRootMonitoringNotification(installed monitoring.InstalledConfig) error {
	notifications := installed.Monitoring.Notifications
	if notifications.WebhookEnv == "" && notifications.WebhookSecretFile == "" {
		return nil
	}
	if notifications.WebhookEnv != "" {
		value, err := rootMonitoringSystemdEnvironment(notifications.WebhookEnv)
		if err != nil || strings.TrimSpace(value) == "" {
			return errors.New(rootMonitoringChannelFix)
		}
		previous, existed := os.LookupEnv(notifications.WebhookEnv)
		if err := os.Setenv(notifications.WebhookEnv, value); err != nil {
			return errors.New(rootMonitoringChannelFix)
		}
		defer func() {
			if existed {
				_ = os.Setenv(notifications.WebhookEnv, previous)
			} else {
				_ = os.Unsetenv(notifications.WebhookEnv)
			}
		}()
	}
	if _, err := monitoring.ConfiguredNotifier(installed.Monitoring, nil); err != nil {
		return errors.New(rootMonitoringChannelFix)
	}
	return nil
}

// readRootMonitoringSystemdEnvironment reads one variable from the systemd
// manager environment, the one PassEnvironment= hands to the unit.
// `systemctl show-environment` takes no argument and prints NAME=value lines;
// a value systemd had to escape ($'...') is not a plain HTTPS URL and is
// treated as absent.
func readRootMonitoringSystemdEnvironment(name string) (string, error) {
	output, err := runFixedOutput(10*time.Second, "/usr/bin/systemctl", "show-environment")
	if err != nil {
		return "", errors.New("unable to inspect systemd manager environment")
	}
	for _, line := range strings.Split(output, "\n") {
		if value, ok := strings.CutPrefix(line, name+"="); ok {
			if strings.HasPrefix(value, "$'") {
				return "", nil
			}
			return value, nil
		}
	}
	return "", nil
}

func removeRootMonitoring(plan rootplan.Plan) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		app := plan.Monitoring.App
		if err := stopMonitoringUnit(monitoringTimerName(app)); err != nil {
			return err
		}
		if err := stopMonitoringUnit(monitoringServiceName(app)); err != nil {
			return err
		}
		if err := os.Remove("/etc/systemd/system/" + monitoringTimerName(app)); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove("/etc/systemd/system/" + monitoringServiceName(app)); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove(rootMonitoringConfigPath(app)); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := runFixed("/usr/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
		// Keep the shared tmpfiles rule: other apps and root operations use this lock.
		rootLog("monitoring app=%s removed", app)
		return nil
	})
}

func stopMonitoringUnit(name string) error {
	state, err := runFixedOutput(10*time.Second, "/usr/bin/systemctl", "show", name, "--property=LoadState", "--value")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil
		}
		return fmt.Errorf("inspect monitoring unit %s: %w", name, err)
	}
	if strings.TrimSpace(state) == "not-found" || strings.TrimSpace(state) == "" {
		return nil
	}
	return runFixed("/usr/bin/systemctl", "disable", "--now", name)
}

func readTrustedRootMonitoring(app string) (monitoring.InstalledConfig, error) {
	path := rootMonitoringConfigPath(app)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return monitoring.InstalledConfig{}, errors.New("installed monitoring configuration is missing or has unsafe permissions")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return monitoring.InstalledConfig{}, errors.New("installed monitoring configuration is not root-owned")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return monitoring.InstalledConfig{}, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 256<<10))
	if err != nil {
		return monitoring.InstalledConfig{}, err
	}
	return monitoring.DecodeInstalledConfig(body)
}

func runInstalledRootMonitoring(app string, output io.Writer) error {
	if !rootAppName.MatchString(app) {
		return errors.New("invalid monitoring application")
	}
	installed, err := readTrustedRootMonitoring(app)
	if err != nil {
		return err
	}
	if !installed.Monitoring.Enabled {
		return errors.New("monitoring is disabled in the trusted installed configuration")
	}
	report, runErr := monitoring.RunInstalled(context.Background(), installed, monitoring.Adapters{})
	if _, err := fmt.Fprintln(output, monitoring.JSON(report)); err != nil {
		return err
	}
	return runErr
}

func runSignedRootMonitoring(plan rootplan.Plan, output io.Writer) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		return runInstalledRootMonitoring(plan.Monitoring.App, output)
	})
}

func runSignedRootMonitoringStatus(plan rootplan.Plan, output io.Writer) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		if !rootAppName.MatchString(plan.Monitoring.App) {
			return errors.New("invalid monitoring application")
		}
		installed, err := readTrustedRootMonitoring(plan.Monitoring.App)
		if err != nil {
			return err
		}
		report, readErr := monitoring.ReadLatest(installed, nil, time.Now().UTC())
		if _, err := fmt.Fprintln(output, monitoring.JSON(report)); err != nil {
			return err
		}
		return readErr
	})
}

func runDirectRootMonitoring(app string, output io.Writer) error {
	return withRootOperationLock(func() error { return runInstalledRootMonitoring(app, output) })
}

func setRootMonitoringMaintenance(plan rootplan.Plan) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		installed, err := readTrustedRootMonitoring(plan.Monitoring.App)
		if err != nil {
			return err
		}
		if err := ensureRootMonitoringOutput(installed); err != nil {
			return err
		}
		until, err := time.Parse(time.RFC3339Nano, plan.Monitoring.Until)
		if err != nil {
			return err
		}
		body, err := json.Marshal(map[string]string{"until": until.UTC().Format(time.RFC3339Nano)})
		if err != nil {
			return err
		}
		if err := writeRootFile(rootMonitoringStatePath(installed), append(body, '\n'), 0o600); err != nil {
			return err
		}
		rootLog("monitoring app=%s maintenance until=%s", installed.App, until.UTC().Format(time.RFC3339))
		return nil
	})
}

func validBackupHostKey(value string) bool {
	return strings.HasPrefix(value, "SHA256:") && len(value) == len("SHA256:")+43
}

func ensureRootMonitoringOutput(installed monitoring.InstalledConfig) error {
	root := filepath.Join("/var/lib/shuttle/monitoring", installed.App)
	if err := ensureRootDirectoryBelow(installed.Monitoring.StateDir, root); err != nil {
		return err
	}
	if installed.Monitoring.Notifications.FailureLog != "" {
		if err := ensureRootDirectoryBelow(filepath.Dir(installed.Monitoring.Notifications.FailureLog), root); err != nil {
			return err
		}
	}
	if installed.Monitoring.External.URL != "" {
		if err := ensureRootDirectoryBelow(installed.Monitoring.External.StateDir, filepath.Join("/var/lib/shuttle/monitoring-external", installed.App)); err != nil {
			return err
		}
	}
	return nil
}

func ensureRootDirectoryBelow(path, root string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("monitoring output directory escapes its application root")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	current := fd
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			syscall.Close(current)
			return errors.New("monitoring output directory contains an unsafe ancestor")
		}
		next, openErr := syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			if mkdirErr := syscall.Mkdirat(current, part, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				syscall.Close(current)
				return mkdirErr
			}
			next, openErr = syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		}
		syscall.Close(current)
		if openErr != nil {
			return errors.New("monitoring output directory contains an unsafe ancestor")
		}
		var stat syscall.Stat_t
		if statErr := syscall.Fstat(next, &stat); statErr != nil || (stat.Mode&syscall.S_IFMT) != syscall.S_IFDIR || stat.Uid != 0 {
			syscall.Close(next)
			return errors.New("monitoring output directory is not root-owned")
		}
		current = next
	}
	return syscall.Close(current)
}
