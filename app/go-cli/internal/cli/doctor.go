package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/readiness"
	"github.com/spf13/cobra"
)

func newDoctorCommand() *cobra.Command {
	var target string
	var format string
	var failBelow string
	var configPath string
	var outputPath string
	var strict bool
	var showSkipped bool
	var scanImages bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run a VPS production readiness audit",
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "" && format != "console" && format != "json" {
				return fmt.Errorf("unsupported format %q", format)
			}
			threshold := -1
			if failBelow != "" {
				value, err := strconv.Atoi(failBelow)
				if err != nil || value < 0 || value > 100 {
					return errors.New("--fail-below must be a number between 0 and 100")
				}
				threshold = value
			}
			_, resolvedConfigPath, err := readiness.LoadConfig(configPath)
			if err != nil {
				return err
			}
			resolved, err := config.Load(resolvedConfigPath, "")
			if err != nil {
				return err
			}
			if scanImages {
				return scanDoctorImages(resolved, readRetainedInfrastructureImages)
			}
			group, host, err := singleVPS(resolved)
			if err != nil {
				return err
			}
			var report readiness.Report
			if resolved.UsesCompose() {
				// No helper, no signed audit: only what can be observed from
				// here is reported, and the report says so.
				if target != "" {
					return errors.New("--target does not apply to deploy.strategy: compose: the host audit needs shuttle setup, and only the public checks (TLS, DNS, health) run")
				}
				report = readiness.RunPublicOnly(net.JoinHostPort(host, strconv.Itoa(group.Port)), readinessDomainString(resolved.Domain), resolved.Readiness.HealthcheckPath, resolvedConfigPath)
				fmt.Fprintln(os.Stderr, "deploy.strategy: compose installs no root helper, so the host audit did not run; the checks below are the ones observable from this machine")
			} else {
				report, err = runSignedReadinessAuditWithTarget(resolved, group, host, target)
				if err != nil {
					return err
				}
			}
			report.ConfigPath = resolvedConfigPath
			interactive := format != "json" && doctorOutputIsTerminal()
			rendered := ""
			switch format {
			case "", "console":
				rendered = readiness.ConsoleWithOptions(report, interactive, showSkipped)
			case "json":
				rendered = readiness.JSON(report) + "\n"
			}
			if interactive {
				fmt.Fprintln(os.Stderr)
			}
			if outputPath != "" {
				if err := writeDoctorOutput(outputPath, readiness.JSON(report)); err != nil {
					return err
				}
			}
			fmt.Print(rendered)
			critical := false
			for _, check := range report.Checks {
				if check.Severity == readiness.Critical && check.Status == readiness.Failed {
					critical = true
				}
			}
			if critical || (strict && doctorHasBlockingChecks(report.Checks)) || (threshold >= 0 && report.Score < threshold) {
				return errors.New("doctor policy failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "remote SSH target user@host")
	cmd.Flags().StringVar(&format, "format", "console", "output format: console or json")
	cmd.Flags().StringVar(&failBelow, "fail-below", "", "exit with code 1 when score is below threshold")
	cmd.Flags().StringVar(&configPath, "config", "", "path to Shuttle config.json")
	cmd.Flags().StringVar(&outputPath, "output", "", "write doctor JSON report to a file")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit with code 1 when any applicable check fails, lacks evidence, or has an exception")
	cmd.Flags().BoolVar(&scanImages, "scan-images", false, "run optional infrastructure CVE diagnostics with Trivy, without changing the VPS")
	cmd.Flags().BoolVar(&showSkipped, "show-skipped", false, "show checks with no evidence or an inapplicable target")
	return cmd
}

// runSignedReadinessAuditWithTarget is the swarm-strategy audit as it always
// ran: the target must be the configured deploy@VPS endpoint, and the checks
// execute inside the signed root helper.
func runSignedReadinessAuditWithTarget(resolved *config.Config, group config.ServerGroup, host, target string) (readiness.Report, error) {
	if target == "" {
		target = "deploy@" + net.JoinHostPort(host, strconv.Itoa(group.Port))
	}
	sshTarget, err := parseSSHTarget(target)
	if err != nil {
		return readiness.Report{}, err
	}
	if sshTarget.User != "deploy" || sshTarget.Host != host || sshTarget.Port != group.Port {
		return readiness.Report{}, errors.New("--target must match the configured deploy@VPS endpoint")
	}
	return runSignedReadinessAudit(resolved)
}

func readinessDomainString(value any) string { return domainString(value) }

func doctorOutputIsTerminal() bool {
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func doctorHasBlockingChecks(checks []readiness.CheckResult) bool {
	return !readiness.ChecksValidated(checks)
}

func writeDoctorOutput(path string, content string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(content+"\n"), 0o600)
}

type sshTarget struct {
	User string
	Host string
	Port int
}

func parseSSHTarget(value string) (sshTarget, error) {
	if strings.TrimSpace(value) == "" {
		return sshTarget{}, errors.New("--target cannot be empty")
	}
	user := ""
	hostPort := value
	if strings.Count(value, "@") > 1 {
		return sshTarget{}, fmt.Errorf("invalid SSH target %q", value)
	}
	if before, after, ok := strings.Cut(value, "@"); ok {
		if before == "" || after == "" {
			return sshTarget{}, fmt.Errorf("invalid SSH target %q; expected user@host or user@host:port", value)
		}
		user = before
		hostPort = after
	}
	host := hostPort
	port := 22
	if parsedHost, parsedPort, err := net.SplitHostPort(hostPort); err == nil {
		host = parsedHost
		parsed, err := strconv.Atoi(parsedPort)
		if err != nil || parsed < 1 || parsed > 65535 {
			return sshTarget{}, fmt.Errorf("invalid SSH port %q", parsedPort)
		}
		port = parsed
	} else if strings.Contains(hostPort, ":") && strings.Count(hostPort, ":") == 1 {
		parts := strings.Split(hostPort, ":")
		if parts[0] == "" || parts[1] == "" {
			return sshTarget{}, fmt.Errorf("invalid SSH target %q; expected host:port", value)
		}
		parsed, err := strconv.Atoi(parts[1])
		if err != nil || parsed < 1 || parsed > 65535 {
			return sshTarget{}, fmt.Errorf("invalid SSH port %q", parts[1])
		}
		host = parts[0]
		port = parsed
	} else if strings.Contains(hostPort, ":") && !strings.HasPrefix(hostPort, "[") {
		host = hostPort
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return sshTarget{}, fmt.Errorf("invalid SSH target %q; host is required", value)
	}
	return sshTarget{User: user, Host: host, Port: port}, nil
}
