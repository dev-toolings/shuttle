package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
)

type infraProject struct {
	configPath string
	root       string
	cfg        *config.Config
}

func newInfraCommand() *cobra.Command {
	var flags configFlags
	cmd := &cobra.Command{Use: "infra", Short: "Plan, create, or recreate project-owned infrastructure"}
	cmd.PersistentFlags().StringVar(&flags.path, "config", "", "path to config.json (legacy shuttle.yml is accepted)")
	cmd.PersistentFlags().StringVarP(&flags.env, "env", "e", "", "environment overlay")
	cmd.AddCommand(newInfraPlanCommand(&flags), newInfraApplyCommand(&flags), newInfraConfigureCommand(&flags), newInfraRecreateCommand(&flags))
	return cmd
}

func newInfraPlanCommand(flags *configFlags) *cobra.Command {
	return &cobra.Command{
		Use: "plan", Short: "Plan the declared infrastructure without changing it", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			project, err := loadInfraProject(*flags)
			if err != nil {
				return err
			}
			return runPVECLI(cmd, project, nil, "iac", "plan")
		},
	}
}

func newInfraApplyCommand(flags *configFlags) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use: "apply", Short: "Apply the declared Terraform infrastructure", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				return errors.New("infrastructure apply requires explicit --yes confirmation (use infra plan first)")
			}
			project, err := loadInfraProject(*flags)
			if err != nil {
				return err
			}
			return runPVECLI(cmd, project, nil, "iac", "apply", "--yes")
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the Terraform apply")
	return cmd
}

func newInfraConfigureCommand(flags *configFlags) *cobra.Command {
	return &cobra.Command{
		Use: "configure", Short: "Run the declared Ansible bootstrap with a verified SSH host key", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			project, err := loadInfraProject(*flags)
			if err != nil {
				return err
			}
			fingerprint, knownHosts, err := attestInfraHost(cmd, project)
			if err != nil {
				return err
			}
			defer os.Remove(knownHosts)
			fmt.Fprintf(cmd.OutOrStdout(), "PVE attested SSH host key %s.\n", fingerprint)
			return configureInfra(cmd, project, knownHosts)
		},
	}
}

func newInfraRecreateCommand(flags *configFlags) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use: "recreate", Short: "Destroy exactly the declared guest, rebuild it, configure it, and deploy", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				return errors.New("infrastructure recreation requires explicit --yes confirmation (use infra plan first)")
			}
			project, err := loadInfraProject(*flags)
			if err != nil {
				return err
			}
			infra := project.cfg.Infrastructure
			if !infra.AllowRecreate {
				return errors.New("infrastructure.allow_recreate must be true before the destructive recreate workflow is available")
			}

			setup, err := prepareInfraRecreate(project)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Recreating only %s (PVE %s %d).\n", infra.TerraformResource, infra.GuestType, infra.GuestID)
			target := "-target=" + infra.TerraformResource
			if err := runPVECLI(cmd, project, nil, "iac", "apply", "--yes", "--", "-destroy", target); err != nil {
				exists, verifyErr := infraGuestExists(cmd, project)
				if verifyErr != nil {
					return fmt.Errorf("%w; could not verify the destructive postcondition: %v", err, verifyErr)
				}
				if exists {
					return fmt.Errorf("%w; PVE still reports %s %d", err, infra.GuestType, infra.GuestID)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "PVE confirms the targeted guest is absent; continuing after pvecli's empty-state postflight.")
			}
			if err := runPVECLI(cmd, project, nil, "iac", "apply", "--yes", "--", target); err != nil {
				return err
			}

			fingerprint, knownHosts, err := attestInfraHost(cmd, project)
			if err != nil {
				return err
			}
			defer os.Remove(knownHosts)
			fmt.Fprintf(cmd.OutOrStdout(), "PVE attested SSH host key %s.\n", fingerprint)
			if err := configureInfra(cmd, project, knownHosts); err != nil {
				return err
			}

			setup.expectedHostKey = fingerprint
			if err := runSetup(cmd, setup); err != nil {
				return err
			}
			if err := deploySwarm(project.cfg, false, false, memoryBudgetStrict, time.Now()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Infrastructure recreated and application deployment proven healthy.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm exact guest destruction and complete recreation")
	return cmd
}

// prepareInfraRecreate runs the deploy's own local checks, then the helper's
// policy on the stack the deploy would apply, because a refusal after the
// destruction leaves the application down with no retained stack to roll back
// to. What only the replacement guest can answer stays out of reach.
func prepareInfraRecreate(project infraProject) (setupOptions, error) {
	options, err := prepareInfraSetup(project)
	if err != nil {
		return setupOptions{}, err
	}
	// The environment schema reads .env, but pvecli and Ansible inherit this
	// process's environment: application values must not reach them.
	defer restoreEnvironment(os.Environ())
	loadDeployDotenv(project.cfg)
	inputs, err := checkDeployInputs(project.cfg)
	if err != nil {
		return setupOptions{}, err
	}
	plan, err := createConfiguredBuildPlan(inputs.parsed, project.cfg.Build, "127.0.0.1:5000", project.cfg.App, detectVersion())
	if err != nil {
		return setupOptions{}, err
	}
	stack, err := renderPlaceholderStack(project.cfg, inputs.parsed, plan.ServiceImages, inputs.secretNames, detectWebPort(inputs.parsed, project.cfg))
	if err != nil {
		return setupOptions{}, err
	}
	if stack == "" {
		return options, nil
	}
	if err := validateRootStack([]byte(stack)); err != nil {
		return setupOptions{}, fmt.Errorf("stack cannot be deployed through the root helper: %w", err)
	}
	return options, nil
}

func restoreEnvironment(environment []string) {
	os.Clearenv()
	for _, entry := range environment {
		if key, value, ok := strings.Cut(entry, "="); ok {
			os.Setenv(key, value)
		}
	}
}

// Check all locally declared setup keys before recreate destroys the guest.
// Host-key attestation is filled in only after the replacement guest exists.
func prepareInfraSetup(project infraProject) (setupOptions, error) {
	group, host, err := singleVPS(project.cfg)
	if err != nil {
		return setupOptions{}, err
	}
	publicKey, err := resolveInfraPublicKey(project)
	if err != nil {
		return setupOptions{}, err
	}
	body, err := os.ReadFile(publicKey)
	if err != nil {
		return setupOptions{}, err
	}
	key, _, _, rest, err := gossh.ParseAuthorizedKey(bytes.TrimSpace(body))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return setupOptions{}, errors.New("infrastructure.public_key must contain exactly one OpenSSH public key")
	}
	options := setupOptions{config: configFlags{path: project.configPath}, target: fmt.Sprintf("root@%s:%d", host, group.Port), publicKeyPath: publicKey, yes: true}
	options.operator, err = resolveSetupOperatorAccess(project.cfg, options, gossh.FingerprintSHA256(key))
	if err != nil {
		return setupOptions{}, err
	}
	if err := requireSetupAdministrator(setupIdentity{user: "root"}, options); err != nil {
		return setupOptions{}, fmt.Errorf("infra recreate requires setup.operator_user and setup.operator_public_key before destroying the guest: %w", err)
	}
	return options, nil
}

type pveGuestInventoryEntry struct {
	VMID int `json:"vmid"`
}

func infraGuestExists(cmd *cobra.Command, project infraProject) (bool, error) {
	body, err := capturePVECLI(cmd, project, "lxc", "ls", "-o", "json")
	if err != nil {
		return false, err
	}
	return inventoryContainsGuest(body, project.cfg.Infrastructure.GuestID)
}

func inventoryContainsGuest(body string, guestID int) (bool, error) {
	var guests []pveGuestInventoryEntry
	if err := json.Unmarshal([]byte(body), &guests); err != nil {
		return false, fmt.Errorf("decode PVE LXC inventory: %w", err)
	}
	for _, guest := range guests {
		if guest.VMID == guestID {
			return true, nil
		}
	}
	return false, nil
}

func loadInfraProject(flags configFlags) (infraProject, error) {
	path := flags.path
	if path == "" {
		found, err := config.FindDefault()
		if err != nil {
			return infraProject{}, err
		}
		path = found
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return infraProject{}, err
	}
	cfg, err := config.Load(abs, flags.env)
	if err != nil {
		return infraProject{}, err
	}
	if cfg.Infrastructure.Driver == "" {
		return infraProject{}, errors.New("config.json does not declare infrastructure")
	}
	return infraProject{configPath: abs, root: filepath.Dir(abs), cfg: cfg}, nil
}

func runPVECLI(cmd *cobra.Command, project infraProject, env []string, args ...string) error {
	configPath := filepath.Join(project.root, project.cfg.Infrastructure.PVECLIConfig)
	argv := append([]string{"--config", configPath}, args...)
	call := exec.CommandContext(cmd.Context(), "pvecli", argv...)
	call.Dir = project.root
	call.Env = append(os.Environ(), env...)
	call.Stdout, call.Stderr = cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := call.Run(); err != nil {
		return fmt.Errorf("pvecli %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func capturePVECLI(cmd *cobra.Command, project infraProject, args ...string) (string, error) {
	configPath := filepath.Join(project.root, project.cfg.Infrastructure.PVECLIConfig)
	argv := append([]string{"--config", configPath}, args...)
	call := exec.CommandContext(cmd.Context(), "pvecli", argv...)
	call.Dir = project.root
	var stdout, stderr bytes.Buffer
	call.Stdout, call.Stderr = &stdout, &stderr
	if err := call.Run(); err != nil {
		return stdout.String(), fmt.Errorf("pvecli %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

var sshFingerprintPattern = regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`)

func attestInfraHost(cmd *cobra.Command, project infraProject) (string, string, error) {
	group, host, err := singleVPS(project.cfg)
	if err != nil {
		return "", "", err
	}
	deadline := time.Now().Add(3 * time.Minute)
	var apiFingerprint string
	for time.Now().Before(deadline) {
		body, callErr := capturePVECLI(cmd, project, "lxc", "exec", fmt.Sprint(project.cfg.Infrastructure.GuestID), "--", "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256")
		if match := sshFingerprintPattern.FindString(body); callErr == nil && match != "" {
			apiFingerprint = match
			break
		}
		if callErr != nil && strings.Contains(callErr.Error(), "PVE_LXC_PASSWORD") {
			return "", "", errors.New("the LXC console requires a password; declare console type shell so pvecli can attest the SSH key without storing a password")
		}
		time.Sleep(2 * time.Second)
	}
	if apiFingerprint == "" {
		return "", "", errors.New("PVE did not return the LXC ED25519 host fingerprint within three minutes")
	}

	var scanned []byte
	for time.Now().Before(deadline) {
		call := exec.CommandContext(cmd.Context(), "ssh-keyscan", "-T", "3", "-p", fmt.Sprint(group.Port), "-t", "ed25519", host)
		scanned, _ = call.Output()
		if len(bytes.TrimSpace(scanned)) > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(bytes.TrimSpace(scanned)) == 0 {
		return "", "", errors.New("the recreated guest did not expose an ED25519 SSH host key")
	}
	_, _, key, _, _, err := gossh.ParseKnownHosts(scanned)
	if err != nil {
		return "", "", fmt.Errorf("parse scanned SSH host key: %w", err)
	}
	if scannedFingerprint := gossh.FingerprintSHA256(key); scannedFingerprint != apiFingerprint {
		return "", "", fmt.Errorf("SSH host key does not match PVE attestation: network=%s PVE=%s", scannedFingerprint, apiFingerprint)
	}
	file, err := os.CreateTemp("", "shuttle-known-hosts-*")
	if err != nil {
		return "", "", err
	}
	name := file.Name()
	if _, err = file.Write(scanned); err == nil {
		err = file.Chmod(0o600)
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", "", err
	}
	return apiFingerprint, name, nil
}

func configureInfra(cmd *cobra.Command, project infraProject, knownHosts string) error {
	infra := project.cfg.Infrastructure
	if infra.AnsiblePlaybook == "" {
		return nil
	}
	args := []string{"iac", "configure", "--playbook", infra.AnsiblePlaybook, "--user", "root", "--idempotence"}
	if infra.InventoryTag != "" {
		args = append(args, "--tag", infra.InventoryTag)
	}
	env := []string{"ANSIBLE_HOST_KEY_CHECKING=True", "ANSIBLE_SSH_ARGS=-o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + knownHosts}
	return runPVECLI(cmd, project, env, args...)
}

func resolveInfraPublicKey(project infraProject) (string, error) {
	value := project.cfg.Infrastructure.PublicKey
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
	} else if !filepath.IsAbs(value) {
		value = filepath.Join(project.root, value)
	}
	if info, err := os.Stat(value); err != nil || info.IsDir() {
		return "", fmt.Errorf("infrastructure public key is not readable: %s", value)
	}
	return value, nil
}
