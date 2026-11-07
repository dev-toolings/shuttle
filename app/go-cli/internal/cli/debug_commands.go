package cli

import (
	"fmt"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/spf13/cobra"
)

// newDebugCommand exposes a deliberately closed diagnostic vocabulary. None
// of the subcommands accepts Docker flags or a command line: the signed plan
// carries a mode and, where needed, one validated Compose service name.
func newDebugCommand() *cobra.Command {
	var flags configFlags
	command := &cobra.Command{
		Use:   "debug",
		Short: "Inspect the application's Docker state through the signed helper",
	}
	command.PersistentFlags().StringVar(&flags.path, "config", "", "path to config.json (legacy shuttle.yml is accepted)")
	command.PersistentFlags().StringVarP(&flags.env, "env", "e", "", "environment overlay")
	command.AddCommand(
		newDebugSimpleCommand(&flags, "ps", "List the application's running containers", "debug-ps"),
		newDebugSimpleCommand(&flags, "services", "List the application's Swarm services", "debug-services"),
		newDebugServiceCommand(&flags, "tasks <service>", "Show the tasks of one declared service", "debug-tasks"),
		newDebugServiceCommand(&flags, "inspect <service>", "Show a redacted inspect view of one declared service", "debug-inspect"),
		newDebugSimpleCommand(&flags, "network", "Show only networks attached to the application's services", "debug-network"),
		newDebugLogsCommand(&flags),
	)
	return command
}

func newDebugSimpleCommand(flags *configFlags, use, short, mode string) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return executeDebugAudit(cmd, *flags, mode, "", 0)
		},
	}
}

func newDebugServiceCommand(flags *configFlags, use, short, mode string) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeDebugAudit(cmd, *flags, mode, args[0], 0)
		},
	}
}

func newDebugLogsCommand(flags *configFlags) *cobra.Command {
	var lines int
	command := &cobra.Command{
		Use: "logs <service>", Short: "Read bounded logs from one declared service", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeDebugAudit(cmd, *flags, "debug-logs", args[0], lines)
		},
	}
	command.Flags().IntVar(&lines, "lines", 200, "number of lines (1-1000)")
	return command
}

func executeDebugAudit(cmd *cobra.Command, flags configFlags, mode, service string, lines int) error {
	if mode == "debug-logs" && (lines < 1 || lines > 1000) {
		return fmt.Errorf("--lines must be between 1 and 1000")
	}
	cfg, err := loadWithFlags(flags)
	if err != nil {
		return err
	}
	if err := requireReadonlyDebugCapability(cfg); err != nil {
		return err
	}
	body, err := runSignedStackAudit(cfg, mode, service, lines)
	if body != "" {
		fmt.Fprint(cmd.OutOrStdout(), body)
	}
	return err
}

func requireReadonlyDebugCapability(cfg *config.Config) error {
	report, err := queryRootHelperCapabilities(cfg)
	if err != nil {
		if rootHelperLacksCapabilities(err) {
			return fmt.Errorf("installed root helper predates read-only Docker diagnostics; bootstrap or update the helper first: %w", err)
		}
		return fmt.Errorf("cannot negotiate read-only Docker diagnostics: %w", err)
	}
	if err := requireRootHelperCapabilities(report, []string{capabilityReadonlyDockerDebug}); err != nil {
		return fmt.Errorf("%w; run `shuttle helper update --dry-run`, then `shuttle helper update --yes`", err)
	}
	if strings.TrimSpace(report.Version) == "" {
		return fmt.Errorf("root helper returned no version for read-only Docker diagnostics")
	}
	return nil
}
