package cli

import (
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	var installTarget string
	root := &cobra.Command{
		Use:     "shuttle",
		Short:   "Set up, audit and deploy one Docker Swarm VPS",
		Version: version.Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			recordRecoveryInvocation(cmd)
			checkForUpdateAsync()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return installBundled(cmd, installTarget)
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	// Cobra's default template always prints a command literally named "help",
	// even when hidden. Keep -h/--help while withholding an extra public
	// command from the public surface.
	root.SetHelpCommand(&cobra.Command{Use: "__help", Hidden: true})
	root.PersistentFlags().BoolVarP(&output.Verbose, "verbose", "v", false, "enable verbose output")
	// Root-only: `shuttle --install skills` is the same action as
	// `shuttle skills install`. A persistent flag would leak onto deploy.
	root.Flags().StringVar(&installTarget, "install", "", "install a bundled resource (skills)")
	status := newStatusCommand()
	status.Aliases = []string{"monitoring", "monitor"}
	status.AddCommand(monitoringSubcommands()...)
	root.AddCommand(
		newBackupCommand(),
		newInitCommand(),
		newDebugCommand(),
		newDeployCommand(),
		newSetupCommand(),
		newDoctorCommand(),
		newHelperCommand(),
		newInfraCommand(),
		status,
		newLogsCommand(),
		newSecretsCommand(),
		newSkillsCommand(),
		newRunCommand(),
		newOperationsCommand(),
		newRollbackCommand(),
		newDestroyCommand(),
		newUpdateCommand(),
	)
	return root
}
