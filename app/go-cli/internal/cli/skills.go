package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/skills"
	"github.com/spf13/cobra"
)

func newSkillsCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "skills",
		Short: "Install the bundled agent skill for host-backed production secrets",
	}
	root.AddCommand(newSkillsInstallCommand())
	return root
}

func newSkillsInstallCommand() *cobra.Command {
	var scope string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install shuttle-host-env into every local coding harness",
		Long: "Write the bundled shuttle-host-env skill so agents never copy a production .env onto a workstation.\n\n" +
			"User scope lands in every harness under $HOME (Claude, Grok, Cursor, Codex, OpenCode, Agents),\n" +
			"so every project this operator opens sees it. Project scope lands in the current checkout,\n" +
			"so teammates get it. The default is both.\n\n" +
			"Same action: shuttle --install skills",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSkillsInstall(cmd, scope)
		},
	}
	cmd.Flags().StringVar(&scope, "scope", skills.ScopeAll, "install tree: all, user, or project")
	return cmd
}

func runSkillsInstall(cmd *cobra.Command, scope string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("skills install: %w", err)
	}
	project, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("skills install: %w", err)
	}
	result, err := skills.Install(skills.Request{Home: home, ProjectDir: project, Scope: strings.TrimSpace(scope)})
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	for _, path := range result.Written {
		fmt.Fprintf(out, "installed %s\n", path)
	}
	fmt.Fprintf(out, "skill=%s files=%d\n", skills.HostEnvName, len(result.Written))
	return nil
}

func installProjectHostEnvSkill(dir string) error {
	_, err := skills.Install(skills.Request{ProjectDir: dir, Scope: skills.ScopeProject})
	return err
}

func installBundled(cmd *cobra.Command, target string) error {
	switch target {
	case "skills":
		return runSkillsInstall(cmd, skills.ScopeAll)
	case "":
		return cmd.Help()
	default:
		return fmt.Errorf("unknown install target %q; supported: skills", target)
	}
}
