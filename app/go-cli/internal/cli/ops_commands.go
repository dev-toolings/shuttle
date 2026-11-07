package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"

	"github.com/spf13/cobra"
)

func newDeployCommand() *cobra.Command {
	var flags configFlags
	var skipBuild bool
	var breakLock bool
	var dryRun bool
	var memoryBudget string
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Build and deploy the application to the VPS",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Failed deploys should show their actionable error without Cobra's unrelated usage block.
			cmd.SilenceUsage = true
			// main prints the returned error once; cobra printing it too showed every
			// recovery line twice.
			cmd.SilenceErrors = true
			startedAt := time.Now()
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			policy, err := parseMemoryBudgetPolicy(memoryBudget)
			if err != nil {
				return err
			}
			if breakLock {
				if !cfg.UsesCompose() || dryRun {
					return errors.New("--break-lock requires Compose and cannot be combined with --dry-run")
				}
				return composeBreakLock(cfg, cmd.InOrStdin(), cmd.OutOrStdout())
			}
			if cfg.UsesCompose() {
				return deployCompose(cfg, skipBuild, dryRun, startedAt)
			}
			return deploySwarm(cfg, skipBuild, dryRun, policy, startedAt)
		},
	}
	addConfigFlags(cmd, &flags)
	cmd.Flags().BoolVar(&skipBuild, "skip-build", false, "skip Docker build")
	cmd.Flags().BoolVar(&breakLock, "break-lock", false, "inspect and manually remove a Compose lock")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show planned deployment without mutating")
	cmd.AddCommand(newExistingStackDeployCommand())
	cmd.Flags().StringVar(&memoryBudget, "memory-budget", string(memoryBudgetStrict), "swarm memory guard when the rolling-update overlap ceiling exceeds available memory: strict refuses, warn reports and deploys")
	return cmd
}

func newStatusCommand() *cobra.Command {
	var flags configFlags
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the application stack status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			var body string
			if cfg.UsesCompose() {
				body, err = composeStatus(cfg)
			} else {
				body, err = runSignedStackAudit(cfg, "status", "", 0)
			}
			if err == nil {
				fmt.Fprint(cmd.OutOrStdout(), body)
			}
			return err
		},
	}
	addConfigFlags(cmd, &flags)
	return cmd
}

func newLogsCommand() *cobra.Command {
	var flags configFlags
	var service string
	var lines int
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Read application service logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if lines < 1 || lines > 1000 {
				cmd.SilenceUsage = true
				return fmt.Errorf("--lines must be between 1 and 1000")
			}
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			if strings.TrimSpace(service) == "" {
				service = cfg.PrimaryServiceName()
			}
			var body string
			if cfg.UsesCompose() {
				body, err = composeLogs(cfg, service, lines)
			} else {
				body, err = runSignedStackAudit(cfg, "logs", service, lines)
			}
			if err == nil {
				fmt.Fprint(cmd.OutOrStdout(), body)
			}
			return err
		},
	}
	addConfigFlags(cmd, &flags)
	// Empty default, resolved from the configuration inside RunE: flags are
	// registered before config.json is read, so "web" as a literal default would
	// silently target the wrong service on an app that publishes another one.
	cmd.Flags().StringVar(&service, "service", "", "service name (default: deploy.primary_service)")
	cmd.Flags().IntVar(&lines, "lines", 100, "number of lines per task stream (1-1000)")
	return cmd
}

// newRunCommand exposes the declared maintenance operations.
//
// It is not a remote shell and cannot become one: the argument is the *name* of
// an operation the deployed stack declares, and the command it maps to was
// fixed when that stack was signed. It exists because `deploy` has no shell, no
// sudo and no Docker socket, so without it there is no way to run a migration
// or a search reindex after setup, and the shared services an application
// needs are not reachable from outside the node at all.
func newRunCommand() *cobra.Command {
	var flags configFlags
	var skipBackup bool
	cmd := &cobra.Command{
		Use:   "run <operation>",
		Short: "Run a declared maintenance operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			if len(cfg.Operations) == 0 {
				return errors.New("no operations are declared; add an `operations` block to config.json")
			}
			if _, ok := cfg.Operations[args[0]]; !ok {
				return fmt.Errorf("operation %q is not declared: %s", args[0], strings.Join(sortedOperationNames(cfg.Operations), ", "))
			}
			operation := cfg.Operations[args[0]]
			if skipBackup && !operation.BackupBefore {
				return errors.New("--skip-backup applies only to an operation that declares backup_before")
			}
			var body string
			var runErr error
			if cfg.UsesCompose() {
				body, runErr = composeRun(cfg, args[0])
			} else {
				body, runErr = runSignedOperation(cfg, args[0], rootplan.RunOptions{RequireBackup: operation.BackupBefore, SkipBackup: skipBackup})
			}
			if body != "" {
				fmt.Fprint(cmd.OutOrStdout(), body)
			}
			return runErr
		},
	}
	cmd.Flags().BoolVar(&skipBackup, "skip-backup", false, "skip the declared pre-run database backup")
	addConfigFlags(cmd, &flags)
	return cmd
}

func sortedOperationNames(operations map[string]config.Operation) []string {
	names := make([]string, 0, len(operations))
	for name := range operations {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func newRollbackCommand() *cobra.Command {
	var breakLock bool
	var flags configFlags
	var yes bool
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback the application to the previous release",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			if breakLock {
				if !cfg.UsesCompose() || dryRun {
					return errors.New("--break-lock requires Compose and cannot be combined with --dry-run")
				}
				return composeBreakLock(cfg, cmd.InOrStdin(), cmd.OutOrStdout())
			}
			if !dryRun && !yes {
				return fmt.Errorf("pass --yes to confirm rollback (or use --dry-run to preview)")
			}
			if cfg.UsesCompose() {
				return composeRollback(cfg, dryRun)
			}
			return rollbackStack(cfg, dryRun)
		},
	}
	addConfigFlags(cmd, &flags)
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm rollback execution")
	cmd.Flags().BoolVar(&breakLock, "break-lock", false, "inspect and manually remove a Compose lock")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would happen without executing")
	return cmd
}

func newDestroyCommand() *cobra.Command {
	var breakLock bool
	var flags configFlags
	var yes bool
	var volumes, dropDatabases, dryRun bool
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Remove an application deployment",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			if breakLock {
				if !cfg.UsesCompose() || dryRun {
					return errors.New("--break-lock requires Compose and cannot be combined with --dry-run")
				}
				return composeBreakLock(cfg, cmd.InOrStdin(), cmd.OutOrStdout())
			}
			if !yes && !dryRun {
				return fmt.Errorf("pass --yes to confirm destroy")
			}
			if cfg.UsesCompose() {
				if dropDatabases || dryRun {
					return errors.New("--drop-databases and --dry-run require the signed Swarm destroy")
				}
				return composeDestroy(cfg, volumes)
			}
			if volumes {
				return errors.New("--volumes only applies to deploy.strategy: compose; a Swarm stack's volumes are removed by the signed destroy")
			}
			return destroyStack(cfg, cmd.OutOrStdout(), dropDatabases, dryRun)
		},
	}
	addConfigFlags(cmd, &flags)
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deletion (PostgreSQL objects are kept by default)")
	cmd.Flags().BoolVar(&breakLock, "break-lock", false, "inspect and manually remove a Compose lock")
	cmd.Flags().BoolVar(&dropDatabases, "drop-databases", false, "with --yes, dump then drop only ledger-owned PostgreSQL databases and roles")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview the signed Swarm destroy on the host without changing resources or state")
	cmd.Flags().BoolVar(&volumes, "volumes", false, "with deploy.strategy: compose, also remove the project's named volumes (data)")
	return cmd
}
