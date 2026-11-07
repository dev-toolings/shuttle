package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/monitoring"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/spf13/cobra"
)

var monitoringRemoteOperation = runSignedMonitoringOperation
var monitoringExternalRun = monitoring.RunExternalInstalled

func newMonitoringCommand() *cobra.Command {
	root := &cobra.Command{Use: "monitoring", Aliases: []string{"monitor"}, Short: "Run opt-in service, backup and security monitoring"}
	root.AddCommand(monitoringSubcommands()...)
	return root
}

func monitoringSubcommands() []*cobra.Command {
	return []*cobra.Command{newMonitoringStatusCommand(), newMonitoringRunCommand(), newMonitoringInstallCommand(), newMonitoringRemoveCommand(), newMonitoringMaintenanceCommand(), newMonitoringExternalCommand()}
}

type monitoringFlags struct {
	configFlags
	format string
	local  bool
}

func addMonitoringFlags(command *cobra.Command, flags *monitoringFlags) {
	addConfigFlags(command, &flags.configFlags)
	command.Flags().StringVar(&flags.format, "format", "text", "output format: text or json")
	command.Flags().BoolVar(&flags.local, "local", false, "run read-only checks in this process instead of through the VPS helper")
}

func newMonitoringStatusCommand() *cobra.Command {
	var flags monitoringFlags
	command := &cobra.Command{Use: "status", Short: "Show the latest monitoring result", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return executeMonitoringRead(cmd, flags, false)
	}}
	addMonitoringFlags(command, &flags)
	return command
}

func newMonitoringRunCommand() *cobra.Command {
	var flags monitoringFlags
	command := &cobra.Command{Use: "run", Short: "Run one bounded monitoring cycle", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return executeMonitoringRead(cmd, flags, true)
	}}
	addMonitoringFlags(command, &flags)
	return command
}

func executeMonitoringRead(cmd *cobra.Command, flags monitoringFlags, forceRun bool) error {
	if flags.format != "text" && flags.format != "json" {
		return errors.New("--format must be text or json")
	}
	cfg, err := loadWithFlags(flags.configFlags)
	if err != nil {
		return err
	}
	monitoringConfig := configMonitoring(cfg)
	installed := monitoring.InstalledConfig{Schema: monitoring.InstalledSchema, App: cfg.App, Monitoring: monitoringConfig, RedisConfigured: cfg.Production.Redis, RabbitMQConfigured: cfg.Production.RabbitMQ, PostgresVersion: cfg.Database.Version, PostgresCluster: "main", DeployStrategy: cfg.Deploy.Strategy}
	if !forceRun && (!monitoringConfig.Enabled || flags.local) {
		report, readErr := monitoring.ReadLatest(installed, nil, time.Now().UTC())
		writeMonitoringReport(cmd, report, flags.format)
		if readErr != nil {
			return readErr
		}
		return monitoringReportError(report)
	}
	if !monitoringConfig.Enabled || flags.local {
		engine := monitoring.New(cfg.App, monitoringConfig, monitoring.Adapters{})
		engine.RedisConfigured = cfg.Production.Redis
		engine.RabbitMQConfigured = cfg.Production.RabbitMQ
		engine.PostgresVersion = cfg.Database.Version
		engine.PostgresCluster = "main"
		engine.DeployStrategy = cfg.Deploy.Strategy
		report := engine.Run(cmd.Context())
		writeMonitoringReport(cmd, report, flags.format)
		return monitoringReportError(report)
	}
	action := "run"
	if !forceRun {
		action = "status"
	}
	body, runErr := monitoringRemoteOperation(cfg, action, nil, time.Time{})
	if body == "" && runErr != nil {
		report := monitoring.UnavailableReport(cfg.App, "Signed monitoring helper returned no JSON report")
		writeMonitoringReport(cmd, report, flags.format)
		return runErr
	}
	report, err := decodeMonitoringReport(body)
	if err != nil {
		if runErr != nil {
			return runErr
		}
		return err
	}
	writeMonitoringReport(cmd, report, flags.format)
	if runErr != nil {
		return runErr
	}
	return monitoringReportError(report)
}

func newMonitoringExternalCommand() *cobra.Command {
	var flags monitoringFlags
	command := &cobra.Command{Use: "external", Short: "Run the independent HTTPS probe from this host", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if flags.format != "text" && flags.format != "json" {
			return errors.New("--format must be text or json")
		}
		cfg, err := loadWithFlags(flags.configFlags)
		if err != nil {
			return err
		}
		installed := monitoring.InstalledConfig{Schema: monitoring.InstalledSchema, App: cfg.App, Monitoring: configMonitoring(cfg), RedisConfigured: cfg.Production.Redis, RabbitMQConfigured: cfg.Production.RabbitMQ}
		report, err := monitoringExternalRun(cmd.Context(), installed, monitoring.Adapters{})
		// Notification failure must not discard the independently collected report.
		if report.Schema != "" {
			writeMonitoringReport(cmd, report, flags.format)
		}
		if err != nil {
			return err
		}
		return monitoringReportError(report)
	}}
	addMonitoringFlags(command, &flags)
	return command
}

func newMonitoringInstallCommand() *cobra.Command {
	var flags configFlags
	var yes, dryRun bool
	var format string
	command := &cobra.Command{Use: "install", Short: "Install and enable the root-owned monitoring timer", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateMonitoringFormat(format); err != nil {
			return err
		}
		cfg, err := loadWithFlags(flags)
		if err != nil {
			return err
		}
		monitoringConfig := configMonitoring(cfg)
		if !monitoringConfig.Enabled {
			return errors.New("monitoring is disabled; set monitoring.enabled: true before installation")
		}
		group, _, err := singleVPS(cfg)
		if err != nil {
			return err
		}
		payload, err := monitoring.MarshalInstalledConfigWithInventory(cfg.App, monitoringConfig, cfg.Production.Redis, cfg.Production.RabbitMQ, cfg.Database.Version, "main", group.Port)
		if err != nil {
			return err
		}
		if dryRun {
			if err := validateMonitoringFormat(format); err != nil {
				return err
			}
			if format == "json" {
				writeMonitoringOperationResult(cmd, format, "install", cfg.App, map[string]any{"dry_run": true, "interval_seconds": monitoringConfig.IntervalSeconds})
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Would install monitoring for %s every %ds with a %ds timeout.\n", cfg.App, monitoringConfig.IntervalSeconds, monitoringConfig.TimeoutSeconds)
			}
			return nil
		}
		if !yes {
			return errors.New("monitoring install requires --yes (use --dry-run first)")
		}
		if _, err := runSignedMonitoringOperation(cfg, "install", payload, time.Time{}); err != nil {
			return err
		}
		writeMonitoringOperationResult(cmd, format, "install", cfg.App, map[string]any{"enabled": true, "interval_seconds": monitoringConfig.IntervalSeconds})
		return nil
	}}
	addConfigFlags(command, &flags)
	command.Flags().BoolVar(&yes, "yes", false, "confirm installation and timer activation")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "show the installation without changing the VPS")
	command.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return command
}

func newMonitoringRemoveCommand() *cobra.Command {
	var flags configFlags
	var yes, dryRun bool
	var format string
	command := &cobra.Command{Use: "remove", Short: "Disable and remove the root-owned monitoring timer", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateMonitoringFormat(format); err != nil {
			return err
		}
		cfg, err := loadWithFlags(flags)
		if err != nil {
			return err
		}
		if dryRun {
			if err := validateMonitoringFormat(format); err != nil {
				return err
			}
			if format == "json" {
				writeMonitoringOperationResult(cmd, format, "remove", cfg.App, map[string]any{"dry_run": true})
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Would remove monitoring units and configuration for %s.\n", cfg.App)
			}
			return nil
		}
		if !yes {
			return errors.New("monitoring remove requires --yes (use --dry-run first)")
		}
		if _, err := runSignedMonitoringOperation(cfg, "remove", nil, time.Time{}); err != nil {
			return err
		}
		writeMonitoringOperationResult(cmd, format, "remove", cfg.App, map[string]any{"enabled": false})
		return nil
	}}
	addConfigFlags(command, &flags)
	command.Flags().BoolVar(&yes, "yes", false, "confirm removal")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "show the removal without changing the VPS")
	command.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return command
}

func newMonitoringMaintenanceCommand() *cobra.Command {
	var flags configFlags
	var duration string
	var yes, dryRun bool
	var format string
	command := &cobra.Command{Use: "maintenance <start|clear>", Short: "Declare bounded maintenance without hiding monitoring history", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateMonitoringFormat(format); err != nil {
			return err
		}
		if args[0] != "start" && args[0] != "clear" {
			return errors.New("maintenance action must be start or clear")
		}
		cfg, err := loadWithFlags(flags)
		if err != nil {
			return err
		}
		until := time.Now().UTC()
		if args[0] == "start" {
			parsed, parseErr := time.ParseDuration(duration)
			if parseErr != nil || parsed < time.Minute || parsed > 7*24*time.Hour {
				return errors.New("--duration must be between 1m and 168h")
			}
			until = until.Add(parsed)
		}
		if dryRun {
			if err := validateMonitoringFormat(format); err != nil {
				return err
			}
			if format == "json" {
				writeMonitoringOperationResult(cmd, format, "maintenance", cfg.App, map[string]any{"dry_run": true, "until": until.Format(time.RFC3339Nano)})
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Would set monitoring maintenance for %s until %s.\n", cfg.App, until.Format(time.RFC3339))
			}
			return nil
		}
		if !yes {
			return errors.New("monitoring maintenance requires --yes (use --dry-run first)")
		}
		if _, err := runSignedMonitoringOperation(cfg, "maintenance", nil, until); err != nil {
			return err
		}
		writeMonitoringOperationResult(cmd, format, "maintenance", cfg.App, map[string]any{"until": until.Format(time.RFC3339Nano)})
		return nil
	}}
	addConfigFlags(command, &flags)
	command.Flags().StringVar(&duration, "duration", "1h", "maintenance duration, bounded to seven days")
	command.Flags().BoolVar(&yes, "yes", false, "confirm the maintenance declaration")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "show the maintenance deadline without changing the VPS")
	command.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return command
}

func runSignedMonitoringOperation(cfg *config.Config, action string, payload []byte, until time.Time) (string, error) {
	if cfg.UsesCompose() {
		return "", errors.New("monitoring root operations require deploy.strategy: swarm")
	}
	group, host, err := singleVPS(cfg)
	if err != nil {
		return "", err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return "", err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return "", err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return "", err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	var plan rootplan.Plan
	switch action {
	case "install":
		plan, err = rootplan.NewMonitoringInstall(cfg.App, rootplan.PayloadDigest(payload), identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 5*time.Minute)
	case "remove":
		plan, err = rootplan.NewMonitoringRemove(cfg.App, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 5*time.Minute)
	case "run":
		plan, err = rootplan.NewMonitoringRun(cfg.App, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 2*time.Minute)
	case "status":
		plan, err = rootplan.NewMonitoringStatus(cfg.App, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 2*time.Minute)
	case "maintenance":
		plan, err = rootplan.NewMonitoringMaintenance(cfg.App, until, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 5*time.Minute)
	default:
		return "", fmt.Errorf("unsupported monitoring operation %q", action)
	}
	if err != nil {
		return "", err
	}
	plan, err = rootplan.Sign(plan, privateKey)
	if err != nil {
		return "", err
	}
	envelope, err := encodeRootHelperEnvelope(plan, payload)
	if err != nil {
		return "", err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		return stripRootOperationFooter(result.Stdout), fmt.Errorf("signed monitoring operation failed: %s", strings.TrimSpace(result.Stderr))
	}
	return stripRootOperationFooter(result.Stdout), nil
}

func stripRootOperationFooter(body string) string {
	lines := strings.Split(body, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "operation=") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

func decodeMonitoringReport(body string) (monitoring.Report, error) {
	var report monitoring.Report
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		return report, errors.New("decode monitoring report")
	}
	if report.Schema != monitoring.Schema || report.State == "" {
		return report, errors.New("invalid monitoring report")
	}
	return report, nil
}

func writeMonitoringReport(cmd *cobra.Command, report monitoring.Report, format string) {
	if format == "json" {
		fmt.Fprintln(cmd.OutOrStdout(), monitoring.JSON(report))
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), "monitoring=%s checked_at=%s freshness=%s\n", report.State, report.CheckedAt, report.Freshness)
	for _, check := range report.Checks {
		fmt.Fprintf(cmd.OutOrStdout(), "%s [%s] %s\n", check.ID, check.State, check.Summary)
	}
}

func monitoringReportError(report monitoring.Report) error {
	if report.State == monitoring.StateDegraded || report.State == monitoring.StateUnavailable {
		return errors.New("monitoring policy failed")
	}
	return nil
}

func validateMonitoringFormat(format string) error {
	if format != "text" && format != "json" {
		return errors.New("--format must be text or json")
	}
	return nil
}

func writeMonitoringOperationResult(cmd *cobra.Command, format, operation, app string, values map[string]any) {
	if format == "json" {
		result := map[string]any{"schema": monitoring.Schema, "operation": operation, "app": app, "state": monitoring.StateHealthy}
		for key, value := range values {
			result[key] = value
		}
		body, _ := json.Marshal(result)
		fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return
	}
	switch operation {
	case "install":
		fmt.Fprintf(cmd.OutOrStdout(), "Monitoring installed for %s.\n", app)
	case "remove":
		fmt.Fprintf(cmd.OutOrStdout(), "Monitoring removed for %s.\n", app)
	default:
		fmt.Fprintf(cmd.OutOrStdout(), "Monitoring maintenance for %s updated.\n", app)
	}
}

func configMonitoring(cfg *config.Config) config.MonitoringConfig {
	if cfg == nil || cfg.Monitoring == nil {
		return config.MonitoringConfig{}
	}
	// The installed runtime only knows what this copy carries. Without the
	// project access inventory the recette VPS reported its own 80/tcp and
	// 443/tcp rules as unexpected on every cycle, a permanent false incident.
	value := *cfg.Monitoring
	value.ApplyTrustedAccessDefaults(trustedMonitoringAccess(cfg))
	return value
}

// monitoringRecordedSSHUsers returns the SSH users setup recorded for the
// config's first host (groups and hosts in sorted order), or nothing when no
// identity was recorded yet.
var monitoringRecordedSSHUsers = func(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		group := cfg.Servers[name]
		hosts := append([]string(nil), group.Hosts...)
		sort.Strings(hosts)
		for _, host := range hosts {
			port := group.Port
			if port == 0 {
				port = 22
			}
			identity, err := loadTrustedHostIdentity(strings.TrimSpace(host), port)
			if err != nil {
				continue
			}
			return identity.AllowedSSHUsers
		}
	}
	return nil
}

func trustedMonitoringAccess(cfg *config.Config) config.MonitoringAccessDefaults {
	if cfg == nil {
		return config.MonitoringAccessDefaults{}
	}
	// The config names the accounts it declares, but setup also creates the
	// ones passed by flag (`--operator-user ops`) and records the full list
	// in the trusted host identity. On the 2026-10-28 VM e2e the operator
	// existed only as a flag, so security.ssh reported the mandatory `ops`
	// account as drift on a healthy host. The recorded identity is what the
	// host really has; the config list stays, so nothing declared is lost.
	users := cfg.AllowedSSHUsers()
	users = append(users, monitoringRecordedSSHUsers(cfg)...)
	sort.Strings(users)
	defaults := config.MonitoringAccessDefaults{Users: slices.Compact(users)}
	for _, port := range cfg.AllowedPublicTCPPorts() {
		defaults.AllowedTCPPorts = append(defaults.AllowedTCPPorts, strconv.Itoa(port))
	}
	for _, group := range cfg.Servers {
		if defaults.SSHPort == 0 && group.Port > 0 {
			defaults.SSHPort = group.Port
		}
		if defaults.PrivateInterface == "" {
			if strings.TrimSpace(group.Access.Interface) != "" {
				defaults.PrivateInterface = strings.TrimSpace(group.Access.Interface)
			} else if strings.TrimSpace(group.VPN.Interface) != "" {
				defaults.PrivateInterface = strings.TrimSpace(group.VPN.Interface)
			}
		}
		if defaults.ListenAddress == "" {
			for _, host := range group.Hosts {
				if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
					defaults.ListenAddress = strings.TrimSpace(host)
					break
				}
			}
		}
	}
	if defaults.PrivateInterface == "" && defaults.SSHPort > 0 {
		port := strconv.Itoa(defaults.SSHPort)
		seen := false
		for _, existing := range defaults.AllowedTCPPorts {
			if existing == port {
				seen = true
				break
			}
		}
		if !seen {
			defaults.AllowedTCPPorts = append(defaults.AllowedTCPPorts, port)
		}
	}
	return defaults
}
