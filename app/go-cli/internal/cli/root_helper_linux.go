//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/readiness"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
	gossh "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func rootHelperSupported() bool { return true }

var (
	rootLogOnce   sync.Once
	rootLogWriter io.Writer
)

var (
	rootRegistryBaseURL  = "http://127.0.0.1:5000"
	rootRegistryKeepRead = func(stateRoot, current, previous string) (map[string]bool, error) {
		return rootRegistryKeepDigests(stateRoot, current, previous)
	}
	rootRegistryVolumeMeasure = rootRegistryVolumeBytes
	rootRegistrySoleOperation = func(operationID string, fn func() error) error {
		return coord.NewDefault().WithSoleOperation(context.Background(), operationID, fn)
	}
	rootRegistryLog           = rootLog
	rootRegistryDockerValue   = runFixedValue
	rootRegistryDockerCommand = runFixed
	rootRegistryJournal       = coord.JournalRegistryReplacement
)

// rootLog writes one line of the helper's account of itself to the system
// journal, tagged shuttle-root, so `journalctl -t shuttle-root` answers what the
// helper did on this host and when.
//
// The helper had no voice before this. It runs as root through sudo from the
// deploy user's SSH session, its stdout is discarded by the caller and its
// stderr surfaces only when the operation fails : so a promotion that succeeded
// but whose maintenance quietly did nothing, or a rollback that swapped two
// identical files, left no trace anywhere on the host. Every decision that
// deletes, restores or skips something is logged here, and every error that a
// recovery path has to swallow to keep going is logged instead of vanishing.
//
// Logging must never be the reason an operation fails: if the journal cannot be
// reached the lines go to a file under /var/log, and a failure to write is
// ignored.
func rootLog(format string, args ...any) {
	rootLogOnce.Do(func() {
		if writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "shuttle-root"); err == nil {
			rootLogWriter = writer
			return
		}
		// Not stderr. The helper's stderr is the protocol's return channel:
		// the CLI shows it verbatim as the reason an operation failed, and a
		// journal poured into it would bury that reason under its own
		// history. A host without a journal gets a plain file instead, and a
		// host where even that cannot be opened gets no log rather than a
		// broken error message.
		if file, err := os.OpenFile("/var/log/shuttle-root.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			rootLogWriter = file
			return
		}
		rootLogWriter = io.Discard
	})
	_, _ = fmt.Fprintf(rootLogWriter, format+"\n", args...)
}
func runningAsRoot() bool { return os.Geteuid() == 0 }

const (
	rootSSHDMainPath         = "/etc/ssh/sshd_config"
	rootSSHDDropInDir        = "/etc/ssh/sshd_config.d"
	rootSSHDHardeningPath    = rootSSHDDropInDir + "/00-shuttle.conf"
	rootSSHDRecoveryState    = "/etc/shuttle/sshd-baseline-recovery-state"
	rootSSHDRecoveryFile     = "/etc/shuttle/sshd-baseline.previous"
	rootSSHDMainRecoveryFile = "/etc/shuttle/sshd-config.previous"
	rootSSHDIncludeLine      = "Include " + rootSSHDDropInDir + "/*.conf"

	// rootAppStateRoot holds one directory per application deployed on this
	// host: the signed stacks the helper applied, which are what tells it what
	// is still live. It is a host-wide directory on purpose : a decision that
	// affects every application, such as which registry manifests may be
	// deleted, has to be able to see all of them.
	rootAppStateRoot = "/var/lib/shuttle/apps"

	// rootRegistryImagePrefix is how an image published to the host's loopback
	// registry is spelled in a stack.
	rootRegistryImagePrefix = "127.0.0.1:5000/"
)

var rootRegistryImage = rootRegistryImageForSecurity

// hardenedSSHDDirectives is the effective configuration the signed baseline
// guarantees, as reported by `sshd -T`. The AllowUsers line is not here: it
// depends on the plan, so it is checked against the plan.
var hardenedSSHDDirectives = []string{
	"permitrootlogin no",
	"passwordauthentication no",
	"kbdinteractiveauthentication no",
	"pubkeyauthentication yes",
	"x11forwarding no",
}

// baselineSSHUsers returns the accounts the signed plan allows to log in, and
// refuses anything it would have to clean before writing.
//
// The plan was validated when it was decoded, and it is validated again here
// on purpose: the helper runs as root and the value goes verbatim into an sshd
// directive where a stray space does not fail, it widens who may connect. A
// plan carrying nothing means the historical baseline, so a host converged
// from scratch produces the same directive it always did.
func baselineSSHUsers(plan rootplan.Plan) ([]string, error) {
	if plan.Baseline == nil || len(plan.Baseline.AllowedSSHUsers) == 0 {
		return []string{"deploy"}, nil
	}
	users := plan.Baseline.AllowedSSHUsers
	if len(users) > 8 || !slices.IsSorted(users) || !slices.Contains(users, "deploy") {
		return nil, errors.New("baseline allowed_ssh_users is not a sorted list including the deploy user")
	}
	for i, user := range users {
		if !rootUnixAccount.MatchString(user) {
			return nil, fmt.Errorf("baseline allowed_ssh_users contains invalid account %q", user)
		}
		if i > 0 && users[i-1] == user {
			return nil, errors.New("baseline allowed_ssh_users repeats an account")
		}
	}
	return users, nil
}

// rootUnixAccount is narrower than useradd tolerates, for the same reason the
// CLI-side pattern is: this value is written into AllowUsers.
var rootUnixAccount = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// sshdBaselineKeywords are the directives the signed baseline owns. sshd keeps
// the first value it reads for each of them, so the drop-in include has to come
// before any of them in the main configuration file.
var sshdBaselineKeywords = []string{
	"permitrootlogin",
	"passwordauthentication",
	"kbdinteractiveauthentication",
	"challengeresponseauthentication",
	"pubkeyauthentication",
	"x11forwarding",
	"maxauthtries",
	"allowusers",
	"allowgroups",
	"denyusers",
	"denygroups",
}

func applyRootBaseline(plan rootplan.Plan) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		if err := runFixed("/usr/sbin/groupadd", "-f", "shuttle-operators"); err != nil {
			return err
		}
		if err := runFixed("/usr/sbin/usermod", "-a", "-G", "shuttle-operators", "deploy"); err != nil {
			return err
		}
		sudoers := "%shuttle-operators ALL=(root) NOPASSWD: /usr/local/libexec/shuttle-root apply\n"
		if err := writeRootFile("/etc/sudoers.d/90-shuttle-root", []byte(sudoers), 0o440); err != nil {
			return err
		}
		if err := runFixed("/usr/sbin/visudo", "-cf", "/etc/sudoers.d/90-shuttle-root"); err != nil {
			return err
		}

		if err := preserveRootSSHDBaseline(); err != nil {
			return err
		}
		if err := ensureSSHDDropInInclude(); err != nil {
			restoreRootSSHDBaselineOrLog()
			return err
		}
		allowedUsers, err := baselineSSHUsers(plan)
		if err != nil {
			restoreRootSSHDBaselineOrLog()
			return err
		}
		allowUsers := strings.Join(allowedUsers, " ")
		sshd := "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nX11Forwarding no\nMaxAuthTries 3\nAllowUsers " + allowUsers + "\n"
		if err := writeRootFile(rootSSHDHardeningPath, []byte(sshd), 0o644); err != nil {
			return err
		}
		if err := runFixed("/usr/sbin/sshd", "-t"); err != nil {
			restoreRootSSHDBaselineOrLog()
			return err
		}
		if err := verifyHardenedSSHD(); err != nil {
			restoreRootSSHDBaselineOrLog()
			return err
		}
		if err := runFixed("/usr/bin/systemctl", "reload", "ssh"); err != nil {
			restoreRootSSHDBaselineOrLog()
			return err
		}
		groups, err := exec.Command("/usr/bin/id", "-nG", "deploy").Output()
		if err != nil {
			return fmt.Errorf("inspect deploy groups: %w", err)
		}
		for _, group := range []string{"sudo", "docker"} {
			if containsWord(string(groups), group) {
				if err := runFixed("/usr/bin/gpasswd", "-d", "deploy", group); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func rollbackRootBaseline(plan rootplan.Plan) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		return restoreRootSSHDBaseline()
	})
}

func commitRootBaseline(plan rootplan.Plan) error {
	return withRootOperationLock(func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		if err := verifyHardenedSSHD(); err != nil {
			return err
		}
		if err := os.Remove(rootSSHDRecoveryState); err != nil && !os.IsNotExist(err) {
			return err
		}
		// The state file is the transaction marker. A stale 0600 backup is
		// harmless and will be replaced by the next baseline transaction.
		_ = os.Remove(rootSSHDRecoveryFile)
		_ = os.Remove(rootSSHDMainRecoveryFile)
		return nil
	})
}

func preserveRootSSHDBaseline() error {
	if _, err := os.Stat(rootSSHDRecoveryState); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	main, err := os.ReadFile(rootSSHDMainPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", rootSSHDMainPath, err)
	}
	if err := writeRootFile(rootSSHDMainRecoveryFile, main, 0o600); err != nil {
		return err
	}
	previous, err := os.ReadFile(rootSSHDHardeningPath)
	state := "present\n"
	if os.IsNotExist(err) {
		state = "absent\n"
		if removeErr := os.Remove(rootSSHDRecoveryFile); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
	} else if err != nil {
		return err
	} else if err := writeRootFile(rootSSHDRecoveryFile, previous, 0o600); err != nil {
		return err
	}
	return writeRootFile(rootSSHDRecoveryState, []byte(state), 0o600)
}

func restoreRootSSHDBaseline() error {
	stateBody, err := os.ReadFile(rootSSHDRecoveryState)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	hardened, hardenedErr := os.ReadFile(rootSSHDHardeningPath)
	hardenedMain, hardenedMainErr := os.ReadFile(rootSSHDMainPath)
	state := strings.TrimSpace(string(stateBody))
	switch state {
	case "present":
		previous, readErr := os.ReadFile(rootSSHDRecoveryFile)
		if readErr != nil {
			return fmt.Errorf("read previous SSH baseline: %w", readErr)
		}
		if err := writeRootFile(rootSSHDHardeningPath, previous, 0o644); err != nil {
			return err
		}
	case "absent":
		if err := os.Remove(rootSSHDHardeningPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	default:
		return errors.New("invalid SSH baseline recovery state")
	}
	if err := restoreRootSSHDMain(); err != nil {
		reinstateHardenedSSHD(hardened, hardenedErr, hardenedMain, hardenedMainErr)
		return err
	}
	if err := runFixed("/usr/sbin/sshd", "-t"); err != nil {
		reinstateHardenedSSHD(hardened, hardenedErr, hardenedMain, hardenedMainErr)
		return fmt.Errorf("validate restored SSH configuration: %w", err)
	}
	if err := runFixed("/usr/bin/systemctl", "reload", "ssh"); err != nil {
		reinstateHardenedSSHD(hardened, hardenedErr, hardenedMain, hardenedMainErr)
		return fmt.Errorf("reload restored SSH configuration: %w", err)
	}
	if err := os.Remove(rootSSHDRecoveryState); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(rootSSHDRecoveryFile)
	_ = os.Remove(rootSSHDMainRecoveryFile)
	return nil
}

// restoreRootSSHDMain puts back the provider's own sshd_config when the
// baseline had to add the drop-in include to it.
func restoreRootSSHDMain() error {
	previous, err := os.ReadFile(rootSSHDMainRecoveryFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read previous %s: %w", rootSSHDMainPath, err)
	}
	return writeRootFile(rootSSHDMainPath, previous, 0o644)
}

// restoreRootSSHDBaselineOrLog is the recovery path of the SSH hardening
// transaction. The error being returned to the operator is the one that made
// the transaction fail; whether the restore succeeded decides whether they can
// still log in, so it goes to the journal rather than nowhere.
func restoreRootSSHDBaselineOrLog() {
	if err := restoreRootSSHDBaseline(); err != nil {
		rootLog("sshd: baseline could not be restored after a failed hardening, host access may be degraded: %v", err)
		return
	}
	rootLog("sshd: baseline restored after a failed hardening")
}

func reinstateHardenedSSHD(dropIn []byte, dropInErr error, main []byte, mainErr error) {
	if dropInErr == nil {
		if err := writeRootFile(rootSSHDHardeningPath, dropIn, 0o644); err != nil {
			rootLog("sshd: hardening drop-in could not be reinstated: %v", err)
		}
	} else if os.IsNotExist(dropInErr) {
		if err := os.Remove(rootSSHDHardeningPath); err != nil && !os.IsNotExist(err) {
			rootLog("sshd: stale hardening drop-in could not be removed: %v", err)
		}
	}
	if mainErr == nil {
		if err := writeRootFile(rootSSHDMainPath, main, 0o644); err != nil {
			rootLog("sshd: main configuration could not be reinstated: %v", err)
		}
	}
	if err := runFixed("/usr/bin/systemctl", "reload", "ssh"); err != nil {
		rootLog("sshd: reload after reinstating the hardening failed: %v", err)
	}
}

// ensureSSHDDropInInclude guarantees that the signed drop-in actually takes
// effect. Provider images (and console-driven "reset SSH" actions) ship an
// sshd_config that either omits the drop-in include entirely or places it after
// its own PermitRootLogin/PasswordAuthentication lines; sshd keeps the first
// value it reads, so in both cases the baseline would be written to disk and
// silently ignored. The include is prepended, never appended, so the drop-in
// always wins, and preserveRootSSHDBaseline already snapshotted the original.
func ensureSSHDDropInInclude() error {
	body, err := os.ReadFile(rootSSHDMainPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", rootSSHDMainPath, err)
	}
	if sshdDropInIncludeWins(body) {
		return nil
	}
	header := "# Added by Shuttle: the signed SSH baseline lives in " + rootSSHDDropInDir + ".\n" + rootSSHDIncludeLine + "\n"
	return writeRootFile(rootSSHDMainPath, append([]byte(header), body...), 0o644)
}

// sshdDropInIncludeWins reports whether sshd_config pulls in the Shuttle drop-in
// directory before setting any directive the baseline owns.
func sshdDropInIncludeWins(body []byte) bool {
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		keyword := strings.ToLower(strings.TrimSuffix(fields[0], "="))
		if keyword == "include" {
			for _, pattern := range fields[1:] {
				switch strings.Trim(pattern, `"`) {
				case rootSSHDDropInDir + "/*.conf", rootSSHDDropInDir + "/*", "sshd_config.d/*.conf", "sshd_config.d/*":
					return true
				}
			}
			continue
		}
		for _, owned := range sshdBaselineKeywords {
			if keyword == owned {
				return false
			}
		}
	}
	return false
}

// installedAllowUsers reads the AllowUsers line back out of the drop-in that
// was written. Verification compares the effective configuration against the
// file on disk rather than against a value held in memory, so the check keeps
// meaning at commit time : when the value that was signed is long gone, and
// the only question left is whether what is installed is what is in effect.
func installedAllowUsers() (string, error) {
	body, err := os.ReadFile(rootSSHDHardeningPath)
	if err != nil {
		return "", fmt.Errorf("read the installed SSH baseline: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "AllowUsers "); ok {
			if users := strings.TrimSpace(rest); users != "" {
				return users, nil
			}
		}
	}
	return "", errors.New("the installed SSH baseline declares no AllowUsers")
}

func verifyHardenedSSHD() error {
	effective, err := exec.Command("/usr/sbin/sshd", "-T").Output()
	if err != nil {
		return errors.New("cannot inspect effective sshd configuration")
	}
	allowUsers, err := installedAllowUsers()
	if err != nil {
		return err
	}
	// AllowUsers is checked like the rest : a drop-in that is installed but
	// inert must fail here for the account list too, since that is the
	// directive whose silent failure locks an operator out of their own host :
	// but it cannot be compared as a single line. `sshd -T` prints one
	// `allowusers` line per account, so looking for the joined list finds
	// nothing as soon as there is more than one, and a two-account baseline
	// failed against a configuration that was in fact exactly right.
	if err := verifyEffectiveAllowUsers(effective, allowUsers); err != nil {
		return err
	}
	for _, directive := range hardenedSSHDDirectives {
		if !hasSSHDDirective(effective, directive) {
			return fmt.Errorf("effective sshd configuration does not match the signed baseline: %q is not in effect; confirm that %s reads %q before setting that directive itself", directive, rootSSHDMainPath, rootSSHDIncludeLine)
		}
	}
	return nil
}

func auditRootOperation(plan rootplan.Plan) (string, error) {
	if err := verifyRootOperationIdentity(plan); err != nil {
		return "", err
	}
	if plan.Audit != nil && plan.Audit.Mode == "capabilities" {
		return encodeRootHelperCapabilities()
	}
	if plan.Audit != nil && plan.Audit.Mode == "status" {
		command := exec.Command("/usr/bin/docker", "stack", "services", plan.Audit.App, "--format", rootStackStatusFormat)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		body, err := command.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("inspect stack status: %s", strings.TrimSpace(string(body)))
		}
		return string(body), nil
	}
	if plan.Audit != nil && plan.Audit.Mode == "infra-images" {
		images := map[string]string{}
		path := filepath.Join(rootAppStateRoot, plan.Audit.App, "current.yml")
		if body, err := os.ReadFile(path); err == nil {
			var document map[string]any
			if err := yaml.Unmarshal(body, &document); err != nil {
				return "", fmt.Errorf("read retained infrastructure images: %w", err)
			}
			services, _ := document["services"].(map[string]any)
			for _, name := range []string{"redis", "rabbitmq"} {
				if service, ok := services[name].(map[string]any); ok {
					images[name] = strings.TrimSpace(fmt.Sprint(service["image"]))
				}
			}
		} else if !os.IsNotExist(err) {
			return "", err
		}
		caddy, err := runFixedValue(10*time.Second, "/usr/bin/docker", "service", "inspect", "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}", "shuttle-edge_caddy")
		if err == nil {
			caddy = strings.TrimSpace(caddy)
			match := officialInfrastructureImage.FindStringSubmatch(caddy)
			if match != nil && match[1] == "caddy" {
				images["caddy"] = caddy
			}
		} else if !dockerObjectAbsent("service", "shuttle-edge_caddy", caddy, err.Error()) {
			return "", err
		}
		registry, err := runFixedValue(10*time.Second, "/usr/bin/docker", "container", "inspect", "--format", "{{.Config.Image}}", rootRegistryContainer)
		if err == nil {
			registry = strings.TrimSpace(registry)
			match := officialInfrastructureImage.FindStringSubmatch(registry)
			if match != nil && match[1] == "registry" {
				images["registry"] = registry
			}
		} else if !dockerObjectNotFound(err.Error()) {
			return "", err
		}
		body, err := json.Marshal(images)
		if err != nil {
			return "", err
		}
		return string(body) + "\n", nil
	}
	if plan.Audit != nil && plan.Audit.Mode == "logs" {
		service := plan.Audit.App + "_" + plan.Audit.Service
		return collectRootServiceTaskLogs(func(ctx context.Context) *exec.Cmd {
			command := exec.CommandContext(ctx, "/usr/bin/docker", "service", "ps", "--quiet", service)
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			return command
		}, func(ctx context.Context, task string) *exec.Cmd {
			command := exec.CommandContext(ctx, "/usr/bin/docker", "service", "logs", "--raw", "--tail", strconv.Itoa(plan.Audit.Lines), task)
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			return command
		})
	}
	if plan.Audit != nil && strings.HasPrefix(plan.Audit.Mode, "debug-") {
		return debugRootOperation(*plan.Audit)
	}
	if plan.Audit != nil && plan.Audit.Mode == "readiness" {
		profile := []string{"system", "security", "filesystem", "docker", "firewall", "secrets", "reverse-proxy", "ssh", "access", "backups", "postgresql"}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stack := exec.CommandContext(ctx, "/usr/bin/docker", "service", "ls", "--filter", "label=com.docker.stack.namespace="+plan.Audit.App, "--format", "{{.ID}}")
		stack.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		stackBody, stackErr := stack.Output()
		if stackErr != nil {
			return "", fmt.Errorf("cannot determine readiness coverage: inspect application stack: %w", stackErr)
		}
		serviceIDs := strings.Fields(string(stackBody))
		if plan.Audit.Domain == "" {
			if err := validateReadinessPublication(plan.Audit.App, plan.Audit.Domain, serviceIDs, func(id string) (string, error) {
				return rootImageStoreDockerValue(5*time.Second, "/usr/bin/docker", "service", "inspect", id)
			}); err != nil {
				return "", err
			}
		}
		if len(serviceIDs) > 0 {
			if plan.Audit.Domain != "" {
				profile = append(profile, "tls", "dns", "monitoring")
			}
			if plan.Audit.Redis {
				profile = append(profile, "redis")
			}
		}
		if plan.Audit.Runtime != "" {
			profile = append(profile, plan.Audit.Runtime)
		}
		dockerAccess := false
		// The policy comes from the plan, which is what was signed and therefore
		// approved. Falling back to 80/443 keeps a configuration that declares
		// nothing producing exactly the audit it produced before.
		declared := plan.Audit.AllowedPublicTCPPorts
		if len(declared) == 0 {
			declared = []int{80, 443}
		}
		allowedPublicPorts := []string{strconv.Itoa(plan.Audit.SSHPort)}
		for _, port := range declared {
			allowedPublicPorts = append(allowedPublicPorts, strconv.Itoa(port))
		}
		allowedSSHUsers := plan.Audit.AllowedSSHUsers
		if len(allowedSSHUsers) == 0 {
			allowedSSHUsers = []string{"deploy"}
		}
		cfg := readiness.Config{
			// The signed helper applies application releases only as Swarm stacks.
			// Host PostgreSQL and all Docker workload checks remain applicable.
			ContainerizedApplication: true,
			Version:                  2,
			App:                      readiness.AppConfig{Domain: plan.Audit.Domain, HealthcheckPath: plan.Audit.HealthPath},
			Checks:                   readiness.CheckConfig{Profile: profile},
			Access:                   readiness.AccessConfig{Mode: "public", SSHPort: plan.Audit.SSHPort, DeployUser: "deploy", AllowedSSHUsers: allowedSSHUsers, AllowedPublicTCPPorts: allowedPublicPorts, DockerAccess: &dockerAccess},
		}
		report := readiness.RunWithConfig(execx.Local{}, "local", profile, cfg, "")
		if plan.Audit.Domain == "" {
			readiness.MarkPublicChecksNotApplicable(&report)
		}
		return readiness.JSON(report) + "\n", nil
	}
	sshd, err := exec.Command("/usr/sbin/sshd", "-T").Output()
	if err != nil {
		return "", errors.New("cannot inspect effective sshd configuration")
	}
	for _, directive := range hardenedSSHDDirectives {
		if !hasSSHDDirective(sshd, directive) {
			return "", fmt.Errorf("effective sshd directive is missing: %s", directive)
		}
	}
	groups, err := exec.Command("/usr/bin/id", "-nG", "deploy").Output()
	if err != nil || containsWord(string(groups), "sudo") || containsWord(string(groups), "docker") || !containsWord(string(groups), "shuttle-operators") {
		return "", errors.New("deploy privilege groups do not match the least-privilege baseline")
	}
	return "ssh=key-only-root-disabled\noperator_groups=deploy,shuttle-operators\nhelper=signature-required\n", nil
}

func validateReadinessPublication(app, domain string, serviceIDs []string, inspect func(string) (string, error)) error {
	if domain != "" {
		return nil
	}
	for _, id := range serviceIDs {
		payload, err := inspect(id)
		if err != nil {
			return fmt.Errorf("cannot determine readiness publication: inspect service %s: %w", id, err)
		}
		// Fail closed on anything that is not one real service object: `[{}]`,
		// `[null]` or a null Spec would otherwise read as "no publication
		// label" and turn the public checks into not_applicable without
		// evidence. An absent Labels map is legitimate (an internal service).
		var services []*struct {
			ID   string `json:"ID"`
			Spec *struct {
				Name   string            `json:"Name"`
				Labels map[string]string `json:"Labels"`
			} `json:"Spec"`
		}
		if err := json.Unmarshal([]byte(payload), &services); err != nil || len(services) != 1 || services[0] == nil || services[0].Spec == nil || services[0].Spec.Name == "" || services[0].ID == "" || !strings.HasPrefix(services[0].ID, id) {
			return fmt.Errorf("cannot determine readiness publication: invalid service inspection for %s", id)
		}
		if label := services[0].Spec.Labels["dev.shuttle.domain"]; label != "" {
			service := services[0].Spec.Name
			if service == "" {
				service = id
			}
			return fmt.Errorf("app %s publishes %s on %s, but the readiness audit has no domain: the config and the deployed stack disagree", app, service, label)
		}
	}
	return nil
}

const rootHelperExecutable = "/usr/local/libexec/shuttle-root"

// Keep the installed path injectable so refusal tests exercise the real apply
// callback and admission cleanup without replacing the host executable.
var rootHelperUpdateExecutable = rootHelperExecutable

func applyRootHelperUpdate(plan rootplan.Plan, payload []byte) error {
	runtime := normalizeHelperMigrationRuntime(rootHelperUpdatePreflightRuntime())
	var proof helperMigrationOwnReservationProof
	err := withCoordinatedRootOperation(plan, true, func() error {
		if err := rootCoordinatedIdentityVerifier(plan); err != nil {
			return err
		}
		if err := validateRootHelperELF(payload); err != nil {
			return err
		}
		boot, err := runtime.bootID()
		if err != nil {
			return err
		}
		proof = helperMigrationOwnReservationProof{OperationID: plan.OperationID, OperationKind: plan.OperationKind, OwnerKeyFingerprint: plan.OperatorKeyFingerprint, HostFingerprint: plan.RequiredHostFingerprint, BootID: boot, CandidateSHA256: plan.Helper.PayloadSHA256}
		if err := replaceRootHelper(rootHelperUpdateExecutable, payload, func(path string) error {
			if err := admitHelperMigrationOwnReservationWithRuntime(proof, path, runtime); err != nil {
				return err
			}
			if err := probeRootHelperCandidate(path, plan.Helper.AllowDowngrade); err != nil {
				return helperProbeFailureBeforeReplacement(proof, err, runtime.fs, runtime.paths)
			}
			return nil
		}); err != nil {
			return err
		}
		rootLog("helper updated digest=%s size=%d", plan.Helper.PayloadSHA256, len(payload))
		return nil
	})
	if err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		return err
	}
	c := coord.NewDefault()
	request := coord.PhaseRequest{ID: plan.OperationID, Kind: plan.OperationKind, App: plan.OperationApp, Principal: plan.OperatorKeyFingerprint, OwnerKeyFingerprint: plan.OperatorKeyFingerprint, Host: plan.RequiredHostFingerprint, HostIdentity: plan.RequiredHostFingerprint, Name: "helper-update-complete", PlanExpiresAt: expires, Validate: func(coord.Record) error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		return validateHelperMigrationOwnReservation(proof)
	}}
	return c.ControlWithLockedCompletion(context.Background(), request, "finish", "helper replacement synced; migration finalization still required", func(coord.Record) error {
		return clearHelperMigrationOwnReservation(proof)
	})
}

func validateRootHelperELF(payload []byte) error {
	binary, err := elf.NewFile(bytes.NewReader(payload))
	if err != nil {
		return errors.New("helper payload is not an ELF executable")
	}
	defer binary.Close()
	var expected elf.Machine
	switch runtime.GOARCH {
	case "amd64":
		expected = elf.EM_X86_64
	case "arm64":
		expected = elf.EM_AARCH64
	default:
		return fmt.Errorf("helper updates are unsupported on %s", runtime.GOARCH)
	}
	if binary.Class != elf.ELFCLASS64 || binary.Machine != expected || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
		return fmt.Errorf("helper payload does not target linux/%s", runtime.GOARCH)
	}
	return nil
}

// Policy checks run after a confirmed version probe and before the interface
// probe can create migration intent. Their refusals have no replacement outcome
// to recover; execution failures and timeouts still require signed recovery.
var rootHelperCandidateFS = newOSHelperMigrationFS

// Only process execution is substituted in apply tests; version policy and
// admission settlement must still run in their production call sites.
var rootHelperCandidateCommand = runHelperCandidateCommandContext

func probeRootHelperCandidate(path string, allowDowngrade bool) error {
	// Probe the exact staged executable in CLI mode, before --help can create
	// a migration intent. Interface compatibility alone let older releases
	// regain destroy rules that ignored the operator's durable consent.
	ctx, cancel := context.WithTimeout(context.Background(), rootHelperProbeTimeout)
	defer cancel()
	body, truncated, err := runHelperProbeWithRetries(ctx, path, func(ctx context.Context, path string) ([]byte, bool, error) {
		return rootHelperCandidateCommand(ctx, path, "shuttle", "--version")
	})
	if err != nil {
		return helperProbeFailure(err, body)
	}
	candidate, ok := strings.CutPrefix(strings.TrimSpace(string(body)), "shuttle version ")
	if !ok || truncated {
		return coord.KnownOutcome(errors.New("replacement binary did not report a valid Shuttle version"))
	}
	development := false
	for _, value := range []string{candidate, version.Version} {
		if validReleaseVersion(value) {
			continue
		}
		if !helperDevelopmentVersion.MatchString(value) {
			return coord.KnownOutcome(fmt.Errorf("cannot compare helper version %q", boundedHelperProbeDetail(value)))
		}
		development = true
	}
	if !development {
		comparison, err := compareReleaseVersions(candidate, version.Version)
		if err != nil {
			return coord.KnownOutcome(err)
		}
		if comparison < 0 && !allowDowngrade {
			return coord.KnownOutcome(fmt.Errorf("helper downgrade from %s to %s refused; use --allow-downgrade only after completing pending destroys", version.Version, candidate))
		}
	}
	// make install uses dev or git describe, which cannot establish release
	// ordering. Preserve that workflow without letting it bypass pending data
	// cleanup, just like an explicitly authorized release rollback.
	if allowDowngrade || development {
		if err := refuseHelperRollbackWithPendingDestroy(rootDestroyCleanupRoot, rootHelperCandidateFS()); err != nil {
			return coord.KnownOutcome(err)
		}
	}
	// Version and interface probes share the same overall deadline.
	body, _, err = runHelperProbeWithRetries(ctx, path, runHelperProbeCommandContext)
	if err != nil {
		return helperProbeFailure(err, body)
	}
	if !bytes.Contains(body, []byte("Apply signed Shuttle root operations")) {
		return fmt.Errorf("replacement binary does not expose the shuttle-root interface: %s", boundedHelperProbeDetail(string(body)))
	}
	return nil
}

var helperDevelopmentVersion = regexp.MustCompile(`^(dev|v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[1-9][0-9]*-g[0-9a-f]+(?:-dirty)?|-dirty)|[0-9a-f]{7,40}(?:-dirty)?)$`)

// A failed update previously reported only an interface mismatch even when the
// candidate's stderr named the real cause, such as a size-limit rejection.
// Keep combined output bounded because the candidate is untrusted, and preserve
// argv[0] and PATH so the same root-helper command surface is inspected.
func runHelperProbeCommand(path string) (body []byte, truncated bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), rootHelperProbeTimeout)
	defer cancel()
	return runHelperProbeWithRetries(ctx, path, runHelperProbeCommandContext)
}

func replaceRootHelper(path string, payload []byte, probe func(string) error) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".shuttle-root.next-*")
	if err != nil {
		return fmt.Errorf("create helper replacement: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return fmt.Errorf("write helper replacement: %w", err)
	}
	if err := temporary.Chmod(0o755); err != nil {
		temporary.Close()
		return fmt.Errorf("chmod helper replacement: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync helper replacement: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close helper replacement: %w", err)
	}
	if err := probe(temporaryPath); err != nil {
		return err
	}
	previous := path + ".previous"
	_ = os.Remove(previous)
	if err := os.Link(path, previous); err != nil {
		return fmt.Errorf("preserve previous root helper: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install root helper atomically: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open helper directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync helper directory: %w", err)
	}
	return nil
}

const rootStackPreflightBudget = 30 * time.Second

// Rollback reuses retained images: requiring the deployment's 20% headroom
// blocked recovery at 19% free (DEV-DEPL-109). Keep 1% for journal, manifest
// and runtime metadata writes (about 102 MiB on a 10 GiB root filesystem),
// rather than reserving space for a new release. This is still a floor:
// saturation must refuse recovery before it mutates the retained stack.
const rootRollbackMinFreeDiskPercent = 1

var rootStackPhase = withCoordinatedRootPhase

// Tests inspect the exact manifest submitted by either rollback path without
// contacting Docker or mutating a host.
var rootStackWait = waitRootStack
var rootStackRollbackTemp = os.CreateTemp
var rootStackRegistryImage = runningRootRegistryImage

var rootStackDeployOutput = func(command *exec.Cmd) ([]byte, error) { return command.CombinedOutput() }

var rootStackPreflightCurrentPath = func(app string) string {
	return filepath.Join(rootAppStateRoot, app, "current.yml")
}
var rootStackApplyPreflight = preflightRootStack
var rootPostgresOwnershipPreflight = preflightManagedPostgresOwnership

func preflightRootStackPostgresOwnership(plan rootplan.Plan, payload []byte) error {
	if plan.Action != "stack-apply" || plan.Stack == nil || plan.Stack.Remove {
		return nil
	}
	return rootPostgresOwnershipPreflight(plan.Stack.App, payload)
}

func preflightRootStackApply(plan rootplan.Plan, payload []byte) error {
	if plan.Action == "stack-apply" && plan.Stack != nil && !plan.Stack.Remove {
		if err := rootStackApplyPreflight(plan, payload); err != nil {
			return emitPreflightRefusal(err)
		}
		if err := withRootStackPreflightWatchdog(func() error {
			return preflightRootStackPostgresOwnership(plan, payload)
		}); err != nil {
			return emitPreflightRefusal(err)
		}
	}
	return nil
}

func preflightRootStack(plan rootplan.Plan, payload []byte) error {
	if plan.Action != "stack-apply" || plan.Stack == nil || plan.Stack.Remove {
		return nil
	}
	return withRootStackPreflightWatchdog(func() error {
		if err := preRunMutationGuard(plan.Action); err != nil {
			return err
		}
		if err := preRunVerifyIdentity(plan); err != nil {
			return err
		}
		expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
		if err != nil || time.Until(expires) < rootStackPreflightBudget {
			return errors.New("stack plan expires before the pre-flight budget can complete")
		}
		if err := preRunReservation(context.Background(), plan); err != nil {
			return err
		}
		available, total, err := preRunFilesystem("/")
		if err != nil {
			return fmt.Errorf("inspect disk capacity: %w", err)
		}
		if total == 0 || available*100/total < rootMinFreeDiskPercent {
			return rootDiskSpaceRefusal()
		}
		if err := validateRootStack(payload); err != nil {
			return err
		}
		if err := validateRootStackObjects(context.Background(), plan.Stack.App, payload, rootStackObjectRead); err != nil {
			return err
		}
		current := rootStackPreflightCurrentPath(plan.Stack.App)
		var retainedStack []byte
		if existing, err := os.ReadFile(current); err == nil {
			retainedStack = existing
			if err := rejectImplicitInfrastructureMajorChange(existing, payload); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		return validateInfrastructureImagesBeforeMutation(payload, retainedStack)
	})
}

func withRootStackPreflightWatchdog(run func() error) error {
	watchdog := time.AfterFunc(rootStackPreflightBudget, func() {
		fmt.Fprintf(os.Stderr, "root stack pre-flight exceeded %s and was aborted so the host stays operable\n", rootStackPreflightBudget)
		os.Exit(75)
	})
	defer watchdog.Stop()
	return run()
}

func applyRootStack(plan rootplan.Plan, payload []byte) error {
	if isDestroyDryRun(plan) {
		if err := rootCoordinatedIdentityVerifier(plan); err != nil {
			return err
		}
		return rootDestroyPreview(*plan.Stack, os.Stdout)
	}
	if plan.Action == "stack-apply" && plan.Stack != nil && !plan.Stack.Remove && plan.Stack.RegistryImage == "" {
		image, err := rootStackRegistryImage()
		if err != nil {
			return err
		}
		rootRegistryImage = image
	}
	if plan.Stack != nil && plan.Stack.RegistryImage != "" {
		if err := validateOfficialRegistryImage(plan.Stack.RegistryImage); err != nil {
			return err
		}
		rootRegistryImage = plan.Stack.RegistryImage
	}
	if err := preflightRootStackApply(plan, payload); err != nil {
		return err
	}
	err := rootStackPhase(plan, func(phase context.Context) error {
		if err := preRunVerifyIdentity(plan); err != nil {
			return err
		}
		if plan.Action == "stack-apply" && plan.Stack != nil && !plan.Stack.Remove && plan.Stack.RegistryImage != "" {
			if err := convergeRootRegistryImage(phase, plan.OperationID, plan.Stack.RegistryImage); err != nil {
				return err
			}
		}
		if plan.Stack.Remove {
			return removeRootStackWithConsent(plan.Stack.App, plan.OperationID, &plan.Stack.DropDatabases, os.Stdout)
		}
		// Through preRunFilesystem, as the pre-flight above: a direct Statfs made
		// the helper tests depend on the free space of whatever disk ran them.
		available, total, err := preRunFilesystem("/")
		if err != nil {
			return fmt.Errorf("inspect disk capacity: %w", err)
		}
		minimumFreePercent := uint64(rootMinFreeDiskPercent)
		if plan.Action == "stack-rollback" {
			minimumFreePercent = rootRollbackMinFreeDiskPercent
		}
		if total == 0 || available*100/total < minimumFreePercent {
			if total == 0 {
				rootLog("app=%s action=%s refused: root filesystem reports no blocks", plan.Stack.App, plan.Action)
			} else {
				rootLog("app=%s action=%s refused: disk has %d%% free, minimum is %d%%", plan.Stack.App, plan.Action, available*100/total, minimumFreePercent)
			}
			if plan.Action == "stack-rollback" {
				return fmt.Errorf("rollback refused: less than %d percent disk space remains", rootRollbackMinFreeDiskPercent)
			}
			return rootDiskSpaceRefusal()
		}
		root := filepath.Dir(rootStackPreflightCurrentPath(plan.Stack.App))
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
		current := filepath.Join(root, "current.yml")
		previous := filepath.Join(root, "previous.yml")
		deployFile := current
		var retainedStack []byte
		if plan.Action == "stack-apply" {
			if err := validateRootStack(payload); err != nil {
				return err
			}
			if _, statErr := os.Stat(current); statErr == nil {
				rootStackFirstRelease = false
				existing, err := os.ReadFile(current)
				if err != nil {
					return err
				}
				retainedStack = existing
				if err := rejectImplicitInfrastructureMajorChange(existing, payload); err != nil {
					return err
				}
			} else if os.IsNotExist(statErr) {
				rootStackFirstRelease = true
			} else {
				return statErr
			}
			if err := ensureInfrastructureVolumes(plan.Stack.App, payload, retainedStack); err != nil {
				return err
			}
			if err := ensureInfrastructureSecrets(plan.Stack.App, payload); err != nil {
				return err
			}
			if err := ensureNativePostgres(plan.Stack.App, payload); err != nil {
				return err
			}
			// Housekeeping, so its failure is recorded and not fatal: a host
			// whose task-history setting cannot be read today still deploys,
			// and the sweep after promotion simply reclaims less until it can.
			if err := ensureSwarmTaskHistoryLimit(); err != nil {
				rootLog("app=%s swarm: task history limit not enforced: %v", plan.Stack.App, err)
			}
			rotated, err := retainRollbackTarget(current, previous, payload)
			if err != nil {
				return err
			}
			if rotated {
				rootLog("app=%s rollback target: previous.yml now holds the release that was serving", plan.Stack.App)
			} else {
				rootLog("app=%s rollback target: stack unchanged, previous.yml left as it was", plan.Stack.App)
			}
			// Journaled first, and the file is not written if this fails: it is
			// what lets recovery tell this operation's current.yml from an
			// unknown one if the helper dies anywhere after the write.
			if err := coord.JournalCurrentManifest(phase, rootRecoveryDigest(payload)); err != nil {
				return err
			}
			if err := writeRootFile(current, payload, 0o600); err != nil {
				return err
			}
		} else {
			if _, err := os.Stat(previous); err != nil {
				return errors.New("no retained previous stack is available")
			}
			// An explicit rollback (also used after a failed origin proof)
			// touches the same volumes as emergency rollback. Reuse its live
			// image decision before deployment so older application code cannot
			// silently downgrade Redis or RabbitMQ over newer data.
			var cleanup func()
			var allowed bool
			deployFile, cleanup, allowed = emergencyRollbackManifest(root, plan.Stack.App, previous)
			defer cleanup()
			if !allowed {
				return errors.New("rollback refused: cannot protect live stateful images; inspect the helper journal")
			}
		}
		// The address of the managed database is resolved here, on the host, and
		// written into the stack that is about to be applied. The CLI cannot know
		// it: Docker allocates the gateway at install time and it differs between
		// hosts. A stack with no managed database is deployed from the signed file
		// itself, byte for byte, exactly as before.
		stackFile, err := stackFileWithManagedDatabaseHost(root, deployFile)
		if err != nil {
			return err
		}
		firstReleaseApply := plan.Action == "stack-apply" && rootStackFirstRelease
		if firstReleaseApply {
			if err := coord.JournalFirstReleaseConvergence(phase, coord.FirstReleaseConvergencePending); err != nil {
				return fmt.Errorf("journal first-release convergence before stack deploy: %w", err)
			}
		}
		// The promotion mode is decided HERE, before `docker stack deploy`, from
		// what is on the host now and the signed stack: whether this is a first
		// release, and whether the edge already holds a valid certificate for
		// every hostname the stack publishes. The same mode sizes this wait and,
		// through the response, the client's origin proof and availability wait.
		// A rollback re-applies a release that was already serving and keeps the
		// legacy waits, as does everything that cannot prove the cheaper mode.
		promotionMode := config.PromotionModeLegacy
		if plan.Action == "stack-apply" {
			promotionMode = selectRootPromotionMode(rootStackFirstRelease, payload, rootEdgeCertificateReader, time.Now())
			rootStackPromotionMode = promotionMode
			rootLog("app=%s promotion mode: %s", plan.Stack.App, promotionMode)
		}
		command := exec.Command("/usr/bin/docker", "stack", "deploy", "--detach", "--prune", "-c", stackFile, plan.Stack.App)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		// Captured HERE, before the call, and not inside the wait. Swarm stamps
		// UpdateStatus.StartedAt while this command is still running : to the
		// millisecond of the deploy : so a timestamp taken after it returns
		// would sit after StartedAt, the freshness test in rootUpdateGaveUp
		// would be permanently false, and the terminal-rollback fast fail would
		// be dead code.
		deployedAt := time.Now()
		output, err := rootStackDeployOutput(command)
		if err != nil {
			rootLog("app=%s docker stack deploy failed: %s", plan.Stack.App, strings.TrimSpace(string(output)))
			// Only stack-apply replaced current.yml before deploying. A failed
			// rollback must retain the serving release, not claim its target won.
			// previous.yml may be older when an identical apply skipped rotation.
			if plan.Action == "stack-apply" && retainedStack != nil {
				// The restore is best effort by necessity : there is no better
				// state to fall back to if it fails : but a failure here means
				// current.yml now describes a stack that was never applied, and
				// the operator must be able to learn that from the host.
				if restoreErr := writeRootFile(current, retainedStack, 0o600); restoreErr != nil {
					rootLog("app=%s current.yml could not be restored after the failed deploy, on-disk state no longer matches what runs: %v", plan.Stack.App, restoreErr)
				} else {
					rootLog("app=%s current.yml restored to the previous release", plan.Stack.App)
				}
			}
			return fmt.Errorf("docker stack deploy failed: %s", strings.TrimSpace(string(output)))
		}
		rootLog("app=%s action=%s docker stack deploy accepted", plan.Stack.App, plan.Action)
		waits := rootStackWaits(plan, promotionMode)
		// stackFile is the right argument for both actions. On a stack-rollback
		// it is derived from previous.yml, so the wait then proves the tasks
		// carry the PREVIOUS release's images : which is exactly what a rollback
		// has to converge to. `shuttle rollback` shared the blind wait and then
		// swapped current.yml and previous.yml on the strength of it, so it
		// could exit 0 while the release the operator was fleeing kept serving,
		// with the two retained files now inverted. Proving convergence before
		// that swap is what closes it.
		convergenceWait := rootPromotionConvergenceWait(waits, plan.Action == "stack-apply" && rootStackFirstRelease)
		if err := rootStackWait(plan.Stack.App, stackFile, deployedAt, convergenceWait); err != nil {
			var convergenceJournalErr, restoreErr error
			if firstReleaseApply {
				convergenceJournalErr = coord.JournalFirstReleaseConvergence(phase, coord.FirstReleaseConvergenceFailed)
			}
			rootLog("app=%s stack did not converge within %s: %v", plan.Stack.App, convergenceWait, err)
			if plan.Action == "stack-apply" && retainedStack != nil {
				if restoreErr = writeRootFile(current, retainedStack, 0o600); restoreErr != nil {
					rootLog("app=%s current.yml could not be restored before the emergency rollback: %v", plan.Stack.App, restoreErr)
				}
				// A failed current.yml restore must not suppress the emergency
				// deploy. Use captured serving bytes in an independent temporary
				// file; previous.yml may be older after an identical apply.
				manifest, prepareErr := rootStackRollbackTemp(root, ".shuttle-rollback-*.yml")
				rollbackFile := previous
				if prepareErr == nil {
					temporary := manifest.Name()
					defer os.Remove(temporary)
					_, writeErr := manifest.Write(retainedStack)
					prepareErr = errors.Join(writeErr, manifest.Close())
					if prepareErr == nil {
						rollbackFile = temporary
					}
				}
				if prepareErr != nil {
					// An unwritable directory must not prevent deploying an
					// existing exact copy. Older rollback history is not a substitute.
					previousBody, readErr := os.ReadFile(previous)
					if readErr != nil || !bytes.Equal(previousBody, retainedStack) {
						return errors.Join(err, convergenceJournalErr, restoreErr, fmt.Errorf("prepare emergency rollback manifest (no matching previous.yml): %w", prepareErr), readErr)
					}
					rootLog("app=%s temporary rollback manifest unavailable; using byte-identical previous.yml: %v", plan.Stack.App, prepareErr)
				}
				if injected, injectErr := stackFileWithManagedDatabaseHost(root, rollbackFile); injectErr == nil {
					rollbackFile = injected
				}
				// The serving manifest can predate a Redis or RabbitMQ update:
				// applying it as is would downgrade their data (DEV-DEPL-46).
				// Only the temporary Docker input is adjusted. A failed restore
				// of current.yml remains reported for subsequent recovery.
				rollbackFile, releaseRollbackFile, rollbackAllowed := emergencyRollbackManifest(root, plan.Stack.App, rollbackFile)
				defer releaseRollbackFile()
				if !rollbackAllowed {
					return errors.Join(err, convergenceJournalErr, restoreErr)
				}
				rollback := exec.Command("/usr/bin/docker", "stack", "deploy", "--detach", "--prune", "-c", rollbackFile, plan.Stack.App)
				rollback.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
				rolledBackAt := time.Now()
				// The operation is already failing with the convergence error,
				// which is the one the operator must see. The rollback's own
				// outcome cannot change that verdict, but it decides what the
				// host is serving now, so it goes to the journal.
				if rollbackOutput, rollbackErr := rootStackDeployOutput(rollback); rollbackErr != nil {
					rootLog("app=%s emergency rollback to the previous release failed: %s", plan.Stack.App, strings.TrimSpace(string(rollbackOutput)))
				} else {
					// Deliberately NOT the full convergence budget. Giving the
					// recovery the same wait doubles the operation against the
					// client's SSH deadline and turns a clean "did not converge"
					// verdict into an undiagnosable client-side timeout. But
					// leaving it unobserved leaves the one question an operator
					// has at 2am : is the host serving the old release, or
					// nothing? : unanswered, so it gets a short bounded look and
					// the answer goes to the journal either way.
					if verifyErr := rootStackWait(plan.Stack.App, rollbackFile, rolledBackAt, rootEmergencyRollbackWait); verifyErr != nil {
						rootLog("app=%s emergency rollback submitted, but the previous release did NOT come back within %s: %v", plan.Stack.App, rootEmergencyRollbackWait, verifyErr)
					} else {
						rootLog("app=%s emergency rollback complete: the previous release is serving", plan.Stack.App)
					}
				}
			}
			return errors.Join(err, convergenceJournalErr, restoreErr)
		}
		if firstReleaseApply {
			if err := coord.JournalFirstReleaseConvergence(phase, coord.FirstReleaseConvergenceSucceeded); err != nil {
				return fmt.Errorf("journal successful first-release convergence: %w", err)
			}
		}
		rootLog("app=%s stack converged", plan.Stack.App)
		deployedPayload, err := os.ReadFile(deployFile)
		if err != nil {
			return err
		}
		if err := applyRootCaddyRoute(plan.Stack.App, deployedPayload, waits.CaddyReload); err != nil {
			return err
		}
		if plan.Action == "stack-rollback" {
			identical, err := rotateRetainedStacksAfterRollback(current, previous)
			if err != nil {
				return err
			}
			if identical {
				rootLog("app=%s rollback applied, but current.yml and previous.yml were identical: the release that was serving was redeployed", plan.Stack.App)
			} else {
				rootLog("app=%s rollback applied, retained stacks swapped", plan.Stack.App)
			}
		}
		// A rollback has swapped the retained files by this point. current.yml
		// now describes the observed healthy release; stackFile may be the old
		// previous.yml path, which has just been replaced by the undone release.
		if err := confirmRootHashvaultRelease(plan.Stack.App, current, hashvaultPromotionConfirmBudget); err != nil && !errors.Is(err, errHashvaultNoRelease) {
			rootLog("app=%s hashvault confirmation pending: %s", plan.Stack.App, err)
			fmt.Fprintln(os.Stderr, "warning: hashvault release confirmation is pending; unseal the vault, then run shuttle secrets sync")
		}
		if plan.Action == "stack-apply" {
			collect := collectRootRegistryGarbage
			if rootActionRunsConcurrently(plan) {
				collect = func() error { return collectRootRegistryGarbageAlone(plan.Stack.App, plan.OperationID) }
			}
			// The coordinator fences stack-apply when OperationApp is absent. The
			// signed client always sets it, so the concurrent path must acquire its
			// own sole-operation window around each registry deletion pass.
			return sweepAfterRootPromotion(plan.Stack.App, rootRetainedStacksShared, func() error {
				return maintainRootRegistry(plan.Stack.App, current, previous, plan.Stack.RegistryCacheBudgetBytes, collect, rootAppStateRoot, rootActionRunsConcurrently(plan), plan.OperationID)
			}, func() error {
				return errors.Join(pruneRootImageStore(current, previous), pruneRootInfrastructureImages(current, previous, plan.OperationID, rootActionRunsConcurrently(plan)))
			})
		}
		return nil
	})
	if plan.Stack != nil && plan.Stack.Remove {
		if known, ok := err.(*coord.KnownOutcomeError); ok {
			fmt.Fprintln(os.Stderr, rootKnownOutcomeMarker+cleanRootKnownOutcomeReason(known.Error()))
		}
	}
	return err

}

func runningRootRegistryImage() (string, error) {
	image, err := runFixedValue(10*time.Second, "/usr/bin/docker", "container", "inspect", "--format", "{{.Config.Image}}", rootRegistryContainer)
	if err != nil {
		return "", fmt.Errorf("read the running loopback registry image: %w", err)
	}
	image = strings.TrimSpace(image)
	if err := validateOfficialRegistryImage(image); err != nil {
		return "", fmt.Errorf("running loopback registry image is unsafe: %w", err)
	}
	return image, nil
}

func validateOfficialRegistryImage(image string) error {
	match := officialInfrastructureImage.FindStringSubmatch(strings.TrimSpace(image))
	if match == nil || match[1] != "registry" {
		return errors.New("registry image must be an official registry reference pinned by sha256 digest")
	}
	return nil
}

func registryImageVersion(taggedImage string) ([]int, error) {
	match := officialInfrastructureImage.FindStringSubmatch(strings.TrimSpace(taggedImage))
	if match == nil || match[1] != "registry" {
		return nil, errors.New("registry image must be an official registry reference pinned by sha256 digest")
	}
	version := strings.SplitN(match[2], "-", 2)[0]
	parts := strings.Split(version, ".")
	parsed := make([]int, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("registry tag %q has no comparable version", match[2])
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("registry tag %q has no comparable version", match[2])
		}
		parsed[i] = value
	}
	return parsed, nil
}

func rootRegistryImageUpdateAllowed(running, planned string) error {
	current, err := registryImageVersion(running)
	if err != nil {
		return fmt.Errorf("running registry image is invalid: %w", err)
	}
	want, err := registryImageVersion(planned)
	if err != nil {
		return err
	}
	if current[0] != want[0] {
		return fmt.Errorf("registry major change %d -> %d requires an explicit migration", current[0], want[0])
	}
	for i := 0; len(want) > 1 && i < max(len(current), len(want)); i++ {
		before, after := 0, 0
		if i < len(current) {
			before = current[i]
		}
		if i < len(want) {
			after = want[i]
		}
		if after < before {
			return fmt.Errorf("planned registry version %s is older than running version %s", strings.TrimPrefix(strings.SplitN(planned, "@", 2)[0], "registry:"), strings.TrimPrefix(strings.SplitN(running, "@", 2)[0], "registry:"))
		}
		if after > before {
			break
		}
	}
	return nil
}

func rootRegistryConvergenceCommands(running, planned, user, owner string) ([][]string, error) {
	if err := validateOfficialRegistryImage(planned); err != nil {
		return nil, err
	}
	if err := validateOfficialRegistryImage(running); err != nil {
		return nil, fmt.Errorf("running registry image is unsafe: %w", err)
	}
	if strings.TrimSpace(owner) != "system" {
		return nil, errors.New("refusing to replace a loopback registry not owned by Shuttle")
	}
	if err := rootRegistryImageUpdateAllowed(running, planned); err != nil {
		return nil, err
	}
	// With a major-only tag such as registry:3, the order of two digests cannot be established. The resolved digest is the newest image for that major at resolution time over TLS from the fixed Hub hosts; an older image served under that tag is a supply-chain compromise that version comparison would not prevent. Keep the exact identity recorded for rollback.
	if running == planned && strings.TrimSpace(user) == rootRegistryUser {
		return nil, nil
	}
	return [][]string{
		{"pull", "--quiet", planned},
		{"stop", rootRegistryContainer},
		{"rm", rootRegistryContainer},
		rootRegistryChownArgs(),
		rootRegistryCreateArgs(),
	}, nil
}

func validateRootRegistryVolume(mounts []recoveryRegistryMount) error {
	for _, mount := range mounts {
		if mount.Destination != "/var/lib/registry" {
			continue
		}
		if mount.Type == "volume" && mount.Name == rootRegistryVolume {
			return nil
		}
		mountName := mount.Name
		if mount.Type != "volume" {
			mountName = mount.Source
		}
		found := mount.Type + ":" + mountName
		return fmt.Errorf("refusing to replace loopback registry: /var/lib/registry is mounted from %s, expected volume:%s", found, rootRegistryVolume)
	}
	return fmt.Errorf("refusing to replace loopback registry: /var/lib/registry mount was not found, expected volume:%s", rootRegistryVolume)
}

// Registry replacement must exclude both other replacements and active pushes.
// Pushes hold an operation reservation, not the shared-resource lock. Read the
// identity under that lock, then hold sole-operation admission across stop/rm/run
// so a new push cannot start in the gap. If another app is active, keep the
// observed image for this deploy's collector and defer the replacement.
func convergeRootRegistryImage(ctx context.Context, operationID, planned string) error {
	return rootRetainedStacksShared(func() error {
		inspection, err := rootRegistryDockerValue(10*time.Second, "/usr/bin/docker", "container", "inspect", rootRegistryContainer, "--format", "{{json .}}")
		if err != nil {
			return fmt.Errorf("inspect running loopback registry before image convergence: %w", err)
		}
		var current recoveryRegistryInspect
		if err := json.Unmarshal([]byte(strings.TrimSpace(inspection)), &current); err != nil {
			return fmt.Errorf("decode running loopback registry before image convergence: %w", err)
		}
		if err := validateRootRegistryVolume(current.Mounts); err != nil {
			return err
		}
		rootRegistryImage = planned
		commands, err := rootRegistryConvergenceCommands(current.Config.Image, planned, current.Config.User, current.Config.Labels[shuttleOwnerLabel])
		if err != nil || len(commands) == 0 {
			return err
		}
		// Persist the signed target and the volume before the container ceases
		// to be available as evidence. Never stop it if the journal write fails.
		if current.HostConfig.RestartPolicy.Name != "always" {
			return errors.New("registry restart policy is unsafe")
		}
		if err := validateLoopbackRegistryBindings(current.HostConfig.PortBindings); err != nil {
			return err
		}
		volume, err := rootRegistryDockerValue(10*time.Second, "/usr/bin/docker", "volume", "inspect", rootRegistryVolume, "--format", "{{json .}}")
		if err != nil {
			return fmt.Errorf("inspect registry volume before replacement: %w", err)
		}
		volumeProof, err := rootRegistryVolumeProof(volume)
		if err != nil {
			return err
		}
		if err := rootRegistryJournal(ctx, coord.RegistryReplacement{Image: planned, VolumeSHA256: volumeProof}); err != nil {
			return err
		}
		err = rootRegistrySoleOperation(operationID, func() error {
			for _, args := range commands {
				if err := rootRegistryDockerCommand("/usr/bin/docker", args...); err != nil {
					return fmt.Errorf("converge loopback registry image: %w", err)
				}
			}
			return nil
		})
		if errors.Is(err, coord.ErrOtherOperationsActive) {
			rootRegistryImage = current.Config.Image
			rootRegistryLog("registry: image convergence deferred; requested=%s running=%s: %v", planned, rootRegistryImage, err)
			return nil
		}
		return err
	})
}

// sweepAfterRootPromotion runs the registry and image store sweeps that follow
// a promotion, and decides what their failure means for the operation.
//
// When this runs the promotion is finished: the stack converged on the signed
// digests and the route is loaded. Every failure below therefore falls on one
// side of a single question: does the host still hold a state somebody has
// observed?
//
//   - Yes, for nearly all of them. A manifest DELETE that gets "connection
//     reset by peer" (web, 2026-10-08), a tag listing that times out, an
//     image the daemon refuses to remove, a volume that cannot be measured, the
//     shared lock held past its wait: each one leaves what it found in place,
//     and the next sweep recomputes its plan from the retained stacks and
//     deletes the same leftovers. That is the deferral the alone-only collector
//     already practises. The phase completes with a warning
//     (coord.PhaseWarning) and the next deploy is not blocked.
//   - No, when the collector stopped the loopback registry and could not prove
//     it started again (rootRegistryLeftDownError). Every later pull on the
//     host would fail, so that outcome still ends recovery_required, where the
//     registry-gc and deploy reconcilers restart the pinned registry.
//
// Swarm convergence is not on this list because it is proven before the sweep
// starts: a stack that did not converge never reaches this function and keeps
// failing its phase as before.
func sweepAfterRootPromotion(app string, shared func(func() error) error, registry, imageStore func() error) error {
	var deferred []error
	ran := false
	err := shared(func() error {
		ran = true
		if err := registry(); err != nil {
			rootLog("app=%s registry maintenance failed: %v", app, err)
			var down *rootRegistryLeftDownError
			if errors.As(err, &down) {
				return &rootCleanupError{err: err}
			}
			deferred = append(deferred, fmt.Errorf("registry: %w", err))
		}
		if err := imageStore(); err != nil {
			rootLog("app=%s image store maintenance failed: %v", app, err)
			deferred = append(deferred, fmt.Errorf("image store: %w", err))
		}
		return nil
	})
	if err != nil && ran {
		return err
	}
	if err != nil {
		// The shared lock was never taken, so nothing was swept or stopped.
		deferred = append(deferred, err)
	}
	if len(deferred) == 0 {
		return nil
	}
	return deferRootSweep(app, fmt.Errorf("promotion succeeded; cleanup deferred to the next sweep: %w", errors.Join(deferred...)))
}

// deferRootSweep turns a sweep failure into the warning outcome: logged on the
// host, printed as one shuttle-root warning line for the client, and returned
// as a coord.PhaseWarning so the phase completes instead of failing.
func deferRootSweep(app string, warning error) error {
	rootLog("app=%s %v", app, warning)
	fmt.Fprintf(os.Stderr, "%s%s\n", rootHelperWarningPrefix, strings.ReplaceAll(warning.Error(), "\n", "; "))
	return coord.Warn(warning)
}

// rootRegistryLeftDownError reports that the collector stopped the loopback
// registry and could not bring it back. It is the one sweep failure that does
// not leave the host as it was found.
type rootRegistryLeftDownError struct{ err error }

func (e *rootRegistryLeftDownError) Error() string {
	return fmt.Sprintf("loopback registry may be left stopped: %v", e.err)
}

func (e *rootRegistryLeftDownError) Unwrap() error { return e.err }

// reclaimRootStack sweeps the images of the releases an application has moved
// past, on request and before a deploy, so the free-disk guard that follows
// measures a host that has already been cleaned.
//
// Until this existed the sweep ran only after a successful promotion, which put
// the cure behind the door it was meant to keep open: a host refused at 80 %
// occupancy could never promote again, so it could never sweep again, and the
// leftovers of its own past releases kept it refused. The reclaim runs on the
// same lock, under the same identity checks and from the same retained stacks
// as a promotion : it just does not promote anything.
func reclaimRootStack(plan rootplan.Plan) error {
	return withCoordinatedRootOperation(plan, false, func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		rootLog("app=%s action=stack-reclaim begin", plan.Stack.App)
		if err := ensureSwarmTaskHistoryLimit(); err != nil {
			rootLog("app=%s swarm: task history limit not enforced: %v", plan.Stack.App, err)
		}
		root := filepath.Join(rootAppStateRoot, plan.Stack.App)
		return reclaimImageStoreBeforeDeploy(plan.Stack.App, rootRetainedStacksShared, func() error {
			current, previous := filepath.Join(root, "current.yml"), filepath.Join(root, "previous.yml")
			return errors.Join(
				pruneRootImageStore(current, previous),
				pruneRootInfrastructureImages(current, previous, plan.OperationID, rootActionRunsConcurrently(plan)),
				pruneRootHostImages(current, previous, plan.OperationID, rootActionRunsConcurrently(plan)),
			)
		})
	})
}

// reclaimImageStoreBeforeDeploy decides what a failed pre-deploy sweep means
// for the deploy operation it runs under.
//
// The sweep is housekeeping that happens to come first. An image the daemon
// refuses to remove, a listing that times out or the shared lock held past its
// wait all leave the image store as it was found (the sweep never forces a
// removal and never stops anything), and the next sweep recomputes the same
// plan. Failing the phase instead made the deploy operation recovery_required,
// and every later deploy of the application was refused until the journal was
// edited by hand, over leftovers that were already there. The phase therefore
// completes with a warning. Identity and the other checks before the sweep are
// not covered: they fail the phase as before.
func reclaimImageStoreBeforeDeploy(app string, shared func(func() error) error, imageStore func() error) error {
	err := shared(imageStore)
	if err == nil {
		return nil
	}
	return deferRootSweep(app, fmt.Errorf("image store reclaim deferred to the next sweep: %w", err))
}

// swarmTaskHistoryLimit is how many finished tasks Swarm keeps per service slot.
//
// The default is five, and each of those task records pins the image its task
// ran, so a sweep that respects the daemon's refusal to remove a held image :
// as it must : reclaims nothing until five releases have gone by. Two keeps the
// task that just ended, which is what `docker service ps` needs to show why a
// rollout failed, and lets the image store hold the releases that can still be
// rolled back to instead of the ones that merely happened.
const swarmTaskHistoryLimit = 2

// rootStoppedContainerInspectFormat is read by parseRootContainers, which
// splits on tab characters; the separators are written as \t escapes so they
// cannot be lost to an editor turning them into spaces.
const rootStoppedContainerInspectFormat = "{{.Id}}\t{{.State.Status}}\t{{.Image}}\t{{index .Config.Labels \"com.docker.swarm.task.id\"}}"

// rootImageStoreInspectBudget bounds the whole stopped-container inspect pass of
// one sweep (it runs under the shared-resource lock).
const rootImageStoreInspectBudget = 60 * time.Second

func rootDiskSpaceRefusal() error {
	return fmt.Errorf("deployment refused: less than %d percent disk space remains", rootMinFreeDiskPercent)
}

var (
	swarmTaskHistoryValue     = runFixedValue
	swarmTaskHistoryCommand   = runFixed
	rootRetainedStacksShared  = withRootSharedResources
	rootImageStoreKeepDigests = func(current, previous string) (map[string]bool, error) {
		return rootRegistryKeepDigests(rootAppStateRoot, current, previous)
	}
	rootImageStoreRetainedStacksExist = func(current, previous string) (bool, error) {
		return rootRetainedStackFilesExist(rootAppStateRoot, current, previous)
	}
	rootImageStoreNow           = time.Now
	rootImageStoreDockerValue   = runFixedValue
	rootImageStoreDockerCommand = runFixed
	rootInfraSoleOperation      = func(operationID string, fn func() error) error {
		return coord.NewDefault().WithSoleOperation(context.Background(), operationID, fn)
	}
	rootInfrastructureKeep = readRootInfrastructureKeep
)

// swarmTaskHistoryNeedsUpdate decides from what the daemon reports whether the
// cluster spec has to be rewritten. Rewriting it bumps the spec version on
// every call, so an already-correct value is left alone; a value that cannot be
// read is treated as wrong, because the cost of one redundant update is nothing
// and the cost of a limit silently left at five is the sweep doing nothing.
func swarmTaskHistoryNeedsUpdate(reported string) bool {
	current, err := strconv.Atoi(strings.TrimSpace(reported))
	return err != nil || current != swarmTaskHistoryLimit
}

func ensureSwarmTaskHistoryLimit() error {
	reported, err := swarmTaskHistoryValue(15*time.Second, "/usr/bin/docker", "info", "--format", "{{.Swarm.Cluster.Spec.Orchestration.TaskHistoryRetentionLimit}}")
	if err != nil {
		return fmt.Errorf("inspect swarm task history: %w", err)
	}
	if !swarmTaskHistoryNeedsUpdate(reported) {
		return nil
	}
	if err := swarmTaskHistoryCommand("/usr/bin/docker", "swarm", "update", "--task-history-limit", strconv.Itoa(swarmTaskHistoryLimit)); err != nil {
		return err
	}
	rootLog("swarm: task history limit set to %d (was %q)", swarmTaskHistoryLimit, strings.TrimSpace(reported))
	return nil
}

// retainRollbackTarget rotates the stack that is serving into previous.yml,
// before the promotion about to happen overwrites current.yml.
//
// It refuses to rotate a stack that has not changed, and that refusal is the
// whole function. The stack carries digests, never tags : resolveRemoteRegistryDigests
// pins every image before it is signed : so a rebuild that produces the same
// digests produces a byte-identical stack. Rotating for such a promotion
// replaces the only rollback target with a copy of the release already serving,
// and `shuttle rollback` then redeploys the very release it was asked to undo.
// That is not theoretical: it is what /var/lib/shuttle/apps/demo-app looked
// like, current.yml and previous.yml sharing one checksum.
//
// The consequence reaches further than rollback. rootRegistryKeepDigests reads
// both files, so two identical stacks halve the set of digests the registry
// maintenance protects, and the previous release's manifests are collected on
// the next promotion.
//
// It reports whether it rotated, so the caller can say so in the journal: a
// skipped rotation is a decision the operator may need to see, not a silence.
func retainRollbackTarget(currentPath, previousPath string, payload []byte) (bool, error) {
	body, err := os.ReadFile(currentPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if bytes.Equal(body, payload) {
		return false, nil
	}
	if err := writeRootFile(previousPath, body, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

type registryCatalog struct {
	Repositories []string `json:"repositories"`
}

type registryTags struct {
	Tags []string `json:"tags"`
}

const (
	rootRegistryVolume    = "shuttle-registry"
	rootRegistryContainer = "shuttle-registry"
	// The unprivileged identity the registry and its collector share. `setup`
	// installs it; a host provisioned before that policy still runs the
	// registry as root, so every manifest it wrote is root-owned and the
	// collector, which never runs as root, fails each sweep on unlinkat with
	// "permission denied". Converging here as well means one deploy repairs
	// such a host, with no operator step.
	rootRegistryUser  = "10001:10001"
	rootRegistryOwner = "dev.shuttle.owner=system"
	// The tag BuildKit rewrites on every `--cache-to type=registry` export.
	rootRegistryCacheTag = "buildcache"
)

// registryTagIndex is what the loopback registry says it holds: repository ->
// tag -> manifest digest. Reading it into a plain value is what makes the
// maintenance decision testable without a registry, a daemon or root.
type registryTagIndex map[string]map[string]string

// registryMaintenance is the decision taken before anything is deleted.
type registryMaintenance struct {
	// DeleteManifests holds "repository@sha256:..." references whose tags no
	// longer belong to a retained release.
	DeleteManifests []string
	// CollectGarbage is always true, and that is the fix. The previous code
	// only ran the collector when a *tagged* manifest had been deleted, and it
	// ran it without --delete-untagged. Both halves leaked: every deploy
	// rewrites the :buildcache tag, so the manifest it used to point at becomes
	// untagged, invisible to a tag walk, unreferenced by any GC mark, and its
	// blobs stay on disk forever. A registry cache export in mode=max is 1 to
	// 2 GB per PHP application, so the volume grew by that much per release
	// until ensureRemoteDiskBudget refused every further deploy.
	CollectGarbage bool
}

// planRootRegistryMaintenance decides which tagged manifests this host no longer
// needs. keep holds the image digests referenced by the retained stacks.
//
// The invariant this function exists to protect: the manifest the :buildcache
// tag currently points at is never deleted. Losing it would restart every build
// from a cold cache, which is the exact cost the registry cache was added to
// avoid. Its blobs survive the collector for free, because --delete-untagged
// only removes manifests no tag references and this one is tagged.
func planRootRegistryMaintenance(keep map[string]bool, index registryTagIndex) registryMaintenance {
	retained := map[string]bool{}
	for digest := range keep {
		retained[digest] = true
	}
	for _, tags := range index {
		if digest, ok := tags[rootRegistryCacheTag]; ok {
			retained[digest] = true
		}
	}
	references := []string{}
	for repository, tags := range index {
		seen := map[string]bool{}
		for _, digest := range tags {
			if retained[digest] || seen[digest] {
				continue
			}
			seen[digest] = true
			references = append(references, repository+"@"+digest)
		}
	}
	sort.Strings(references)
	return registryMaintenance{DeleteManifests: references, CollectGarbage: true}
}

// planRegistryCacheEviction applies retention.registry_cache. It is the second
// stage, consulted only once the collector has already reclaimed everything that
// was unreferenced, so the size it judges is real resident data.
//
// The build cache is the only thing it may drop. The release manifests still on
// disk are the current and previous stacks, which `shuttle rollback` needs; a
// cap that ate those would trade a full disk for an unrecoverable deploy. The
// next build then runs cold once and re-exports a fresh cache, which is the
// intended, bounded cost of the cap.
func planRegistryCacheEviction(sizeBytes, budgetBytes int64, index registryTagIndex) []string {
	if budgetBytes <= 0 || sizeBytes <= budgetBytes {
		return nil
	}
	references := []string{}
	for repository, tags := range index {
		if digest, ok := tags[rootRegistryCacheTag]; ok {
			references = append(references, repository+"@"+digest)
		}
	}
	sort.Strings(references)
	return references
}

// rootRegistryGarbageCollectArgs is the collector invocation. --delete-untagged
// is what actually reclaims the orphaned cache manifests: without it the
// collector marks every manifest as live, whether or not a tag still points at
// it, and only ever removes blobs nothing references at all.
func rootRegistryGarbageCollectArgs() []string {
	return []string{"run", "--rm", "--name", "shuttle-registry-gc", "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "-v", rootRegistryVolume + ":/var/lib/registry", rootRegistryImage, "garbage-collect", "--delete-untagged", "/etc/distribution/config.yml"}
}

// rootRegistryChownArgs re-owns the volume for the unprivileged registry. It is
// the one operation that still needs root, so it runs in a container that holds
// nothing but CHOWN and DAC_OVERRIDE, on no network, and is gone before the
// collector starts.
func rootRegistryChownArgs() []string {
	return []string{"run", "--rm", "--network", "none", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges=true", "--entrypoint", "/bin/sh", "-v", rootRegistryVolume + ":/var/lib/registry", rootRegistryImage, "-ec", "chown -R " + rootRegistryUser + " /var/lib/registry"}
}

// rootRegistryCreateArgs mirrors the container `setup` installs. Both paths must
// keep producing the same container: a registry recreated here with different
// flags would drift from the audited one.
func rootRegistryCreateArgs() []string {
	return []string{"run", "-d", "--user", rootRegistryUser, "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--restart=always", "--name", rootRegistryContainer, "--label", rootRegistryOwner, "--log-opt", "max-size=10m", "--log-opt", "max-file=3", "--health-cmd", "/bin/registry --version >/dev/null", "--health-interval", "5s", "--health-timeout", "2s", "--health-retries", "10", "-e", "REGISTRY_STORAGE_DELETE_ENABLED=true", "-p", "127.0.0.1:5000:5000", "-v", rootRegistryVolume + ":/var/lib/registry", rootRegistryImage}
}

// rootRegistryNeedsMigration reads `docker container inspect`. Only a container
// Shuttle owns is ever replaced, and an unreadable or foreign one is left
// exactly as it is: a sweep is housekeeping and must never remove a registry
// this host did not install.
func rootRegistryNeedsMigration(user, owner string) bool {
	return strings.TrimSpace(user) != rootRegistryUser && strings.TrimSpace(owner) == "system"
}

// migrateRootRegistryToNonRoot runs between the stop and the collector, while
// the registry is already down. It returns whether the container was replaced,
// so the caller knows to recreate it instead of starting one that no longer
// exists.
func migrateRootRegistryToNonRoot() (bool, error) {
	report, err := runFixedValue(5*time.Second, "/usr/bin/docker", "container", "inspect", rootRegistryContainer, "--format", "{{.Config.User}}\t{{index .Config.Labels \"dev.shuttle.owner\"}}")
	if err != nil {
		return false, nil
	}
	// Only the line ending is trimmed. A registry that runs as root prints an
	// empty first field, and TrimSpace would eat the leading tab with it,
	// collapsing the row to one field and silently skipping the very host this
	// migration exists for.
	fields := strings.SplitN(strings.Trim(report, "\r\n"), "\t", 2)
	if len(fields) != 2 || !rootRegistryNeedsMigration(fields[0], fields[1]) {
		return false, nil
	}
	rootLog("registry: migrating the loopback registry from root to %s so the collector can reclaim its own manifests", rootRegistryUser)
	if err := runFixed("/usr/bin/docker", "rm", rootRegistryContainer); err != nil {
		return false, err
	}
	if err := runFixed("/usr/bin/docker", rootRegistryChownArgs()...); err != nil {
		return true, err
	}
	return true, nil
}

// A redirected privileged DELETE can reach another path or host and still be
// counted as a successful manifest deletion. Root registry clients therefore
// return redirects to the caller instead of following them.
func rootLoopbackRegistryClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// maintainRootRegistry deletes the application's superseded manifests and evicts
// build caches over budget, then reclaims their blobs through collect. collect
// is the plain collector for a fenced operation and the alone-only collector for
// a concurrent one; the caller holds the shared-resource lock.
func maintainRootRegistry(app, currentPath, previousPath string, cacheBudgetBytes int64, collect func() error, stateRoot string, concurrent bool, operationID string) error {
	keep, err := rootRegistryKeepRead(stateRoot, currentPath, previousPath)
	if err != nil {
		rootRegistryLog("app=%s registry: retained stacks could not be read, deferring sweep: %v", app, err)
		return nil
	}
	if len(keep) == 0 {
		rootRegistryLog("registry: not swept, no retained digest could be read from any stack under %s", stateRoot)
		return nil
	}
	owned, shared, err := rootRegistryOwnedRepositories(app, currentPath, previousPath, stateRoot)
	if err != nil {
		rootRegistryLog("app=%s registry: repository ownership could not be read, deferring sweep: %v", app, err)
		return nil
	}
	sharedLogged := map[string]bool{}
	logShared := func(repositories []string) {
		for _, repository := range repositories {
			if !sharedLogged[repository] {
				rootRegistryLog("app=%s registry: shared repository %s not swept", app, repository)
				sharedLogged[repository] = true
			}
		}
	}
	logShared(shared)
	client := rootLoopbackRegistryClient(5 * time.Second)
	index, err := readRootRegistryIndex(client, owned)
	if err != nil {
		return err
	}
	plan := planRootRegistryMaintenance(keep, index)
	rootRegistryLog("app=%s registry: %d digests retained across all applications, %d superseded manifests to delete", app, len(keep), len(plan.DeleteManifests))
	abortSweep := false
	if len(plan.DeleteManifests) > 0 {
		deferred, err := rootRegistryDeletePass(app, operationID, concurrent, func() error {
			fresh, err := rootRegistryKeepRead(stateRoot, currentPath, previousPath)
			if err != nil {
				rootRegistryLog("app=%s registry: retained stacks could not be re-read, deferring remaining deletions: %v", app, err)
				abortSweep = true
				return nil
			}
			if len(fresh) == 0 {
				rootRegistryLog("registry: not swept, no retained digest could be read from any stack under %s", stateRoot)
				abortSweep = true
				return nil
			}
			freshPlan := planRootRegistryMaintenance(fresh, index)
			candidates := intersectRootRegistryCandidates(plan.DeleteManifests, freshPlan.DeleteManifests)
			freshOwned, freshShared, err := rootRegistryOwnedRepositories(app, currentPath, previousPath, stateRoot)
			if err != nil {
				rootRegistryLog("app=%s registry: repository ownership could not be re-read, deferring remaining deletions: %v", app, err)
				abortSweep = true
				return nil
			}
			logShared(freshShared)
			candidates = filterRootRegistryCandidates(candidates, freshOwned)
			return deleteRootRegistryManifests(client, candidates)
		})
		if err != nil {
			return err
		}
		if deferred {
			return nil
		}
	}
	if abortSweep {
		return nil
	}
	if plan.CollectGarbage {
		if err := collect(); err != nil {
			return fmt.Errorf("collect registry garbage: %w", err)
		}
	}
	if cacheBudgetBytes <= 0 {
		return nil
	}
	size, err := rootRegistryVolumeMeasure()
	if err != nil {
		return fmt.Errorf("measure registry volume for cache cap: %w", err)
	}
	eviction := planRegistryCacheEviction(size, cacheBudgetBytes, index)
	eviction = filterRootRegistryCandidates(eviction, owned)
	rootRegistryLog("app=%s registry: %d MiB resident against a %d MiB cap, %d build caches to evict", app, size>>20, cacheBudgetBytes>>20, len(eviction))
	if len(eviction) == 0 {
		return nil
	}
	deferred, err := rootRegistryDeletePass(app, operationID, concurrent, func() error {
		fresh, err := rootRegistryKeepRead(stateRoot, currentPath, previousPath)
		if err != nil {
			rootRegistryLog("app=%s registry: retained stacks could not be re-read, deferring cache eviction: %v", app, err)
			abortSweep = true
			return nil
		}
		if len(fresh) == 0 {
			rootRegistryLog("registry: not swept, no retained digest could be read from any stack under %s", stateRoot)
			abortSweep = true
			return nil
		}
		freshOwned, freshShared, err := rootRegistryOwnedRepositories(app, currentPath, previousPath, stateRoot)
		if err != nil {
			rootRegistryLog("app=%s registry: repository ownership could not be re-read, deferring cache eviction: %v", app, err)
			abortSweep = true
			return nil
		}
		logShared(freshShared)
		// Eviction plans from the cache budget, not from the keep set, but a
		// digest a retained stack still references must never go: if a
		// buildcache tag and a release ever share a digest, deleting it would
		// break pulls and rollbacks of that release.
		candidates := make([]string, 0, len(eviction))
		for _, reference := range filterRootRegistryCandidates(eviction, freshOwned) {
			if _, digest, ok := strings.Cut(reference, "@"); ok && fresh[digest] {
				continue
			}
			candidates = append(candidates, reference)
		}
		return deleteRootRegistryManifests(client, candidates)
	})
	if err != nil {
		return err
	}
	if deferred || abortSweep {
		// A deferred pass deleted nothing; an aborted one could not verify the
		// keep set or ownership. Neither may stop the registry for a collection.
		return nil
	}
	// The cache manifests are already deleted when this collector runs. A
	// collector failure is still returned because cleanup outcome is part of the
	// operation result, even though the promoted stack remains serving.
	if err := collect(); err != nil {
		return fmt.Errorf("collect evicted registry cache: %w", err)
	}
	return nil
}

// rootImageStoreEntry is one row of this node's image store: the repository the
// image was pulled from, the digest that names it there, and the local id the
// daemon deletes by.
type rootImageStoreEntry struct {
	Repository string
	Digest     string
	ID         string
}

type rootContainerEntry struct {
	ID, State, ImageID, TaskID string
}

func planRootStoppedTaskContainers(superseded map[string]bool, containers []rootContainerEntry) []string {
	ids := []string{}
	seen := map[string]bool{}
	for _, container := range containers {
		if container.State != "exited" && container.State != "dead" {
			continue
		}
		if container.TaskID == "" || !superseded[container.ImageID] || container.ID == "" || seen[container.ID] {
			continue
		}
		seen[container.ID] = true
		ids = append(ids, container.ID)
	}
	sort.Strings(ids)
	return ids
}

// planRootImageStorePrune returns the local image ids this node no longer needs,
// in a stable order.
//
// Deleting the registry manifest never reclaimed the layers: the node keeps its
// own copy of every image it has pulled, Swarm never drops one because the last
// task using it went away, and nothing else in Shuttle touched that store. Each
// promotion whose digests changed therefore left a full set of images behind for
// good, until ensureRemoteDiskBudget and the helper's own statfs check refused
// every further deploy : a host that is blocked rather than cleaned.
//
// Scope is the point of this function. Only images pulled from the loopback
// registry are eligible: those are the ones Shuttle published and is answerable
// for. A database, the shared edge, an unrelated application, an image loaded by
// hand : anything the helper did not put here : is never a candidate, whatever
// the disk says. An image whose digest the store does not report is skipped too:
// it cannot be matched against the retained stacks, and an image that cannot be
// proven unused is kept.
//
// keep is the set that already protects the registry manifests, built from every
// application's retained stacks, so a local image survives exactly as long as the
// release `shuttle rollback` can return to.
func planRootImageStorePrune(keep map[string]bool, entries []rootImageStoreEntry) []string {
	// An empty keep set does not mean nothing is retained. It means the caller
	// could not say what is retained, and every path that produces one is a
	// failure to read: a stack that does not parse, a write interrupted halfway,
	// a state directory written by an older generation. rootStackRegistryDigests
	// answers a malformed stack with no digests and no error, so the emptiness
	// arrives in silence. Sweeping on it would delete every release image the
	// loopback registry ever published, the serving one included : and the
	// daemon's refusal to remove an image a container still holds is an accident
	// of timing, not a guarantee, least of all for the rollback target once
	// Swarm's task history has rotated. Not knowing is a reason to stop; it is
	// never a licence to delete.
	if len(keep) == 0 {
		return nil
	}
	// The store is listed one row per repository digest, so a single local image
	// can appear several times: pulled again under a new digest, or shared
	// between two repositories. The daemon deletes by id, and an id carries all
	// of them at once : so an id that any row proves is still needed is
	// protected before a single deletion is planned, whatever the other rows
	// say. Deciding row by row would let a superseded digest take a retained
	// release's layers with it.
	protected := map[string]bool{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Repository, rootRegistryImagePrefix) || keep[entry.Digest] || entry.Digest == "" {
			protected[entry.ID] = true
		}
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Repository, rootRegistryImagePrefix) {
			continue
		}
		if !strings.HasPrefix(entry.Digest, "sha256:") {
			continue
		}
		if entry.ID == "" || protected[entry.ID] || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		ids = append(ids, entry.ID)
	}
	sort.Strings(ids)
	return ids
}

// parseRootImageStore reads the tab-separated listing produced by `docker image
// ls`. A row the daemon reports without a digest keeps an empty one, so
// planRootImageStorePrune can skip it rather than guess.
func parseRootImageStore(output string) []rootImageStoreEntry {
	entries := []rootImageStoreEntry{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 3 {
			continue
		}
		entry := rootImageStoreEntry{Repository: fields[0], Digest: fields[1], ID: fields[2]}
		if entry.Repository == "" || entry.ID == "" {
			continue
		}
		if entry.Digest == "<none>" {
			entry.Digest = ""
		}
		entries = append(entries, entry)
	}
	return entries
}

// parseRootInfraImageStore is the strict twin of parseRootImageStore for the
// infrastructure pass: a non-empty row that is not exactly repository, digest
// and id is an error, never a skipped row, because an incomplete image to
// digest map can hide that an image is still retained.
func parseRootInfraImageStore(output string) ([]rootImageStoreEntry, error) {
	entries := []rootImageStoreEntry{}
	for number, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 3 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
			return nil, fmt.Errorf("image listing row %d is malformed: %q", number+1, line)
		}
		entry := rootImageStoreEntry{Repository: fields[0], Digest: fields[1], ID: fields[2]}
		if entry.Digest == "<none>" {
			entry.Digest = ""
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseRootContainers(output string) []rootContainerEntry {
	containers := []rootContainerEntry{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
			continue
		}
		taskID := fields[3]
		if taskID == "<no value>" {
			taskID = ""
		}
		containers = append(containers, rootContainerEntry{ID: fields[0], State: fields[1], ImageID: fields[2], TaskID: taskID})
	}
	return containers
}

type rootCleanupError struct{ err error }

func (e *rootCleanupError) Error() string {
	return fmt.Sprintf("promotion succeeded; cleanup failed: %v", e.err)
}

func (e *rootCleanupError) Unwrap() error { return e.err }

// pruneRootImageStore reclaims the layers of the releases this host has moved
// past. It runs after maintainRootRegistry so it reads the same retained stacks
// the registry maintenance just honoured. Each deploy already sweeps before
// deploy (stack-reclaim) and after promotion; releases arrive only through
// deploys, so deleting stopped task containers lets these sweeps converge
// without a timer or disk-pressure trigger.
//
// Swarm task history and orphaned exited containers can outlive the task and
// pin old images indefinitely. Only exited/dead containers carrying a Swarm
// task id and a still-superseded image id are removed, without --force. The
// fresh keep-set reads close races with another application's promotion and
// rollback. Cleanup failures are deferred by the caller, never a promotion
// failure.
func pruneRootImageStore(currentPath, previousPath string) error {
	keep, err := rootImageStoreKeepDigests(currentPath, previousPath)
	if err != nil {
		rootLog("image store: not swept, retained stacks could not be read: %v", err)
		return err
	}
	if len(keep) == 0 {
		// Before the first release on a host no stack is retained at all, so
		// there is nothing a sweep could free: on the 2026-10-28 VM e2e the
		// pre-deploy sweep of a fresh host's first deploy printed "image store
		// reclaim deferred to the next sweep: no retained release digest could
		// be read" on a healthy run. That is not a failure. Retained files
		// that exist but yield no digest still are, and still stop the sweep.
		retained, existErr := rootImageStoreRetainedStacksExist(currentPath, previousPath)
		if existErr == nil && !retained {
			rootLog("image store: nothing to sweep yet, no release is retained on this host")
			return nil
		}
		rootLog("image store: not swept, no retained digest could be read from any stack under %s", rootAppStateRoot)
		return errors.New("no retained release digest could be read")
	}
	listing, err := rootImageStoreDockerValue(30*time.Second, "/usr/bin/docker", "image", "ls", "--all", "--digests", "--no-trunc", "--format", "{{.Repository}}\t{{.Digest}}\t{{.ID}}")
	if err != nil {
		rootLog("image store: not swept, listing failed: %v", err)
		return err
	}
	entries := parseRootImageStore(listing)
	initialCandidates := planRootImageStorePrune(keep, entries)
	candidates := append([]string(nil), initialCandidates...)
	removedContainers, removed, held := 0, 0, 0
	var failures []error
	abortRemovals := false
	defer func() {
		rootLog("image store: %d digests retained, %d superseded images found, %d stopped task containers removed, %d removed, %d still held by a container", len(keep), len(initialCandidates), removedContainers, removed, held)
	}()
	// The daemon filters the listing to stopped Swarm task containers, so the
	// per-container inspect only ever runs on eligible candidates, and the whole
	// inspect pass is bounded: it holds the shared-resource lock, and a degraded
	// daemon answering each inspect slowly must not run the operation into its
	// watchdog. Containers left uninspected are simply kept until the next sweep.
	containerListing, containerListErr := rootImageStoreDockerValue(30*time.Second, "/usr/bin/docker", "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", "status=exited", "--filter", "status=dead", "--filter", "label=com.docker.swarm.task.id")
	if containerListErr != nil {
		rootLog("image store: stopped task containers not listed: %v", containerListErr)
	} else if strings.TrimSpace(containerListing) != "" && len(initialCandidates) != 0 {
		var inspected []rootContainerEntry
		inspectDeadline := rootImageStoreNow().Add(rootImageStoreInspectBudget)
		for _, id := range strings.Fields(containerListing) {
			if !rootImageStoreNow().Before(inspectDeadline) {
				rootLog("image store: stopped task container inspection stopped after %s; the rest is kept for the next sweep", rootImageStoreInspectBudget)
				break
			}
			// Each inspect gets at most what is left of the pass budget, so the
			// pass never holds the shared lock past rootImageStoreInspectBudget.
			timeout := 10 * time.Second
			if remaining := inspectDeadline.Sub(rootImageStoreNow()); remaining < timeout {
				timeout = remaining
			}
			output, inspectErr := rootImageStoreDockerValue(timeout, "/usr/bin/docker", "container", "inspect", "--format", rootStoppedContainerInspectFormat, id)
			if inspectErr != nil {
				rootLog("image store: container %s disappeared before inspect: %v", id, inspectErr)
				continue
			}
			inspected = append(inspected, parseRootContainers(output)...)
		}
		planned := planRootStoppedTaskContainers(candidateIDSet(initialCandidates), inspected)
		if len(planned) != 0 {
			freshKeep, keepErr := rootImageStoreKeepDigests(currentPath, previousPath)
			if keepErr != nil || len(freshKeep) == 0 {
				if keepErr == nil {
					keepErr = errors.New("no retained release digest could be read")
				}
				rootLog("image store: stopped task container removal aborted, retained stacks could not be re-read: %v", keepErr)
				failures = append(failures, keepErr)
				candidates = nil
				abortRemovals = true
			} else {
				candidates = intersectRootImageCandidates(initialCandidates, planRootImageStorePrune(freshKeep, entries))
				containerIDs := planRootStoppedTaskContainers(candidateIDSet(candidates), inspected)
				for _, id := range containerIDs {
					if err := rootImageStoreDockerCommand("/usr/bin/docker", "container", "rm", id); err != nil {
						rootLog("image store: kept stopped task container %s: %v", id, err)
						failures = append(failures, fmt.Errorf("remove stopped task container %s: %w", id, err))
						continue
					}
					removedContainers++
					rootLog("image store: removed stopped task container %s", id)
				}
			}
		}
	}
	if len(initialCandidates) != 0 && !abortRemovals {
		freshKeep, keepErr := rootImageStoreKeepDigests(currentPath, previousPath)
		if keepErr != nil || len(freshKeep) == 0 {
			if keepErr == nil {
				keepErr = errors.New("no retained release digest could be read")
			}
			rootLog("image store: image removal aborted, retained stacks could not be re-read: %v", keepErr)
			failures = append(failures, keepErr)
			candidates = nil
		} else {
			candidates = intersectRootImageCandidates(initialCandidates, planRootImageStorePrune(freshKeep, entries))
		}
	}
	for _, id := range candidates {
		// Deliberately not --force. A container
		// still holding the image makes the daemon refuse, and that refusal is
		// the second check: during a rolling update a task of the outgoing
		// release is alive while the new stack is already on disk, and Swarm's
		// task history keeps it referenced for a while afterwards. Skipping such
		// an image costs one release of disk until that history rotates away;
		// forcing it would pull layers out from under a running task. Nor may a
		// housekeeping sweep fail a release that is already promoted and
		// serving. The caller reports the cleanup failure separately from the
		// successful promotion.
		if err := rootImageStoreDockerCommand("/usr/bin/docker", "image", "rm", id); err != nil {
			references, inspectErr := rootImageStoreDockerValue(10*time.Second, "/usr/bin/docker", "ps", "--all", "--quiet", "--filter", "ancestor="+id)
			if inspectErr == nil && strings.TrimSpace(references) != "" {
				held++
				rootLog("image store: retained %s because a container still references it", id)
				continue
			}
			failures = append(failures, fmt.Errorf("remove image %s: %w", id, errors.Join(err, inspectErr)))
			rootLog("image store: kept %s: %v", id, err)
			continue
		}
		removed++
		rootLog("image store: removed %s", id)
	}
	return errors.Join(failures...)
}

type rootInfraContainerEntry struct {
	ID, State, ImageID, TaskID, Service, Namespace string
	ServiceID, Slot                                string
	Created                                        time.Time
}

// planRootInfrastructureContainers selects stopped Swarm tasks from only
// Shuttle's app Redis/RabbitMQ services and the shared Caddy service.
func planRootInfrastructureContainers(inScope func(service, namespace string) bool, keepIDs map[string]bool, containers []rootInfraContainerEntry) []string {
	var ids []string
	seen := map[string]bool{}
	for _, container := range containers {
		if (container.State != "exited" && container.State != "dead") || container.TaskID == "" || container.ID == "" || keepIDs[container.ImageID] || !inScope(container.Service, container.Namespace) || seen[container.ID] {
			continue
		}
		seen[container.ID] = true
		ids = append(ids, container.ID)
	}
	sort.Strings(ids)
	return ids
}

func planRootInfrastructureImages(repositories map[string]bool, keepDigests, keepIDs, heldIDs map[string]bool, entries []rootImageStoreEntry) []string {
	protected := map[string]bool{}
	for _, entry := range entries {
		if entry.ID == "" || !repositories[rootInfraRepository(entry.Repository)] || entry.Digest == "" || keepDigests[entry.Digest] || keepIDs[entry.ID] || heldIDs[entry.ID] {
			protected[entry.ID] = true
		}
	}
	var ids []string
	seen := map[string]bool{}
	for _, entry := range entries {
		if !repositories[rootInfraRepository(entry.Repository)] || !rootRegistryDigestName.MatchString(entry.Digest) || entry.ID == "" || protected[entry.ID] || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		ids = append(ids, entry.ID)
	}
	sort.Strings(ids)
	return ids
}

func rootInfraRepository(repository string) string {
	if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
		repository = repository[:colon]
	}
	if repository == "redis" || repository == "docker.io/library/redis" {
		return "redis"
	}
	if repository == "rabbitmq" || repository == "docker.io/library/rabbitmq" {
		return "rabbitmq"
	}
	if repository == "caddy" || repository == "docker.io/library/caddy" {
		return "caddy"
	}
	return ""
}

// rootInfraContainerInspectFormat must be an interpreted string: a raw string
// would hand Docker a literal backslash-t, which its template engine prints
// as is, so no inspected row would split into its fields and the pass would never
// remove anything.
const rootInfraContainerInspectFormat = "{{.Id}}\t{{.State.Status}}\t{{.Image}}\t{{index .Config.Labels \"com.docker.swarm.task.id\"}}\t{{index .Config.Labels \"com.docker.swarm.service.name\"}}\t{{index .Config.Labels \"com.docker.stack.namespace\"}}\t{{index .Config.Labels \"com.docker.swarm.task.name\"}}\t{{index .Config.Labels \"com.docker.swarm.node.id\"}}\t{{index .Config.Labels \"com.docker.swarm.task.slot\"}}\t{{index .Config.Labels \"com.docker.swarm.service.id\"}}\t{{.Created}}"

type rootInfraKeepSet struct {
	digests       map[string]bool
	appNamespaces map[string]bool
}

// rootInfrastructureKeep reads retained R2(b)+(c) state. Missing retained
// files are expected during first setup; malformed files or daemon output
// defer removals. The file contents come from root-owned retained state, never
// the CLI. Callers decide whether an empty digest set is acceptable.
func readRootInfrastructureKeep(currentPath, previousPath, stateRoot, caddyStackPath string) (rootInfraKeepSet, error) {
	keep := rootInfraKeepSet{digests: map[string]bool{}, appNamespaces: map[string]bool{}}
	collect := func(path string) error {
		body, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var document map[string]any
		if err := yaml.Unmarshal(body, &document); err != nil {
			return fmt.Errorf("parse retained stack %s: %w", path, err)
		}
		services, ok := document["services"].(map[string]any)
		if !ok {
			return fmt.Errorf("parse retained stack %s: services is missing or invalid", path)
		}
		for _, raw := range services {
			service, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("parse retained stack %s: invalid service", path)
			}
			// Every retained service names its image. A missing or non-string
			// image is malformed state, not an absent reference: skipping it
			// would shrink the keep set while other digests keep it non-empty.
			image, ok := service["image"].(string)
			if !ok || strings.TrimSpace(image) == "" {
				return fmt.Errorf("parse retained stack %s: a service has no image", path)
			}
			if err := addRootInfraReference(keep.digests, image, true); err != nil {
				return fmt.Errorf("parse retained stack %s: %w", path, err)
			}
		}
		return nil
	}
	for _, path := range []string{currentPath, previousPath} {
		if err := collect(path); err != nil {
			return rootInfraKeepSet{}, err
		}
	}
	entries, err := os.ReadDir(stateRoot)
	if err != nil && !os.IsNotExist(err) {
		return rootInfraKeepSet{}, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !rootAppName.MatchString(entry.Name()) {
			continue
		}
		keep.appNamespaces[entry.Name()] = true
		for _, name := range []string{"current.yml", "previous.yml"} {
			if err := collect(filepath.Join(stateRoot, entry.Name(), name)); err != nil {
				return rootInfraKeepSet{}, err
			}
		}
	}
	caddyBody, err := os.ReadFile(caddyStackPath)
	if err != nil && !os.IsNotExist(err) {
		return rootInfraKeepSet{}, err
	}
	if err == nil {
		var document map[string]any
		if err := yaml.Unmarshal(caddyBody, &document); err != nil {
			return rootInfraKeepSet{}, fmt.Errorf("parse Caddy stack: %w", err)
		}
		services, ok := document["services"].(map[string]any)
		if !ok {
			return rootInfraKeepSet{}, errors.New("parse Caddy stack: services is missing or invalid")
		}
		for _, raw := range services {
			service, ok := raw.(map[string]any)
			if !ok {
				return rootInfraKeepSet{}, errors.New("parse Caddy stack: invalid service")
			}
			image, ok := service["image"].(string)
			if !ok || strings.TrimSpace(image) == "" {
				return rootInfraKeepSet{}, errors.New("parse Caddy stack: a service has no image")
			}
			if err := addRootInfraReference(keep.digests, image, true); err != nil {
				return rootInfraKeepSet{}, fmt.Errorf("parse Caddy stack: %w", err)
			}
		}
	}
	return keep, nil
}

func addRootInfraReference(keep map[string]bool, reference string, allDigests bool) error {
	repository, digest, hasDigest := strings.Cut(reference, "@")
	repo := rootInfraRepository(repository)
	if !hasDigest {
		if repo != "" {
			return fmt.Errorf("infrastructure image %q has no digest", reference)
		}
		return nil
	}
	if !rootRegistryDigestName.MatchString(digest) {
		return fmt.Errorf("image %q has an invalid digest", reference)
	}
	if allDigests || repo == "caddy" || repo == "" {
		keep[digest] = true
	}
	return nil
}

func rootInfraServiceImages() (map[string]bool, error) {
	refs, err := rootSwarmServiceImageRefs()
	if err != nil {
		return nil, err
	}
	return rootInfraServiceImageDigests(refs)
}

func rootInfraServiceImageDigests(refs []string) (map[string]bool, error) {
	kept := map[string]bool{}
	for _, image := range refs {
		repository, digest, hasDigest := strings.Cut(image, "@")
		if !hasDigest {
			if rootInfraRepository(repository) != "" || strings.TrimSpace(repository) == "" {
				return nil, fmt.Errorf("Swarm service infrastructure image %q has no digest", image)
			}
			continue
		}
		if !rootRegistryDigestName.MatchString(digest) {
			return nil, fmt.Errorf("Swarm service image %q has invalid digest", image)
		}
		kept[digest] = true
	}
	return kept, nil
}

type rootSwarmServiceImageRefPair struct {
	current  string
	previous string
}

// rootSwarmServiceImageRefPairs reads both service specs because a rollout can
// leave an image in PreviousSpec after the current task has moved on. Keeping
// the references separate lets the host sweep protect previous images without
// making their repositories eligible for cleanup.
func rootSwarmServiceImageRefPairs() ([]rootSwarmServiceImageRefPair, error) {
	// `docker service ls` has no --no-trunc flag: on the DEV-DEPL-55 VM run of
	// 2026-10-28 (Docker 29.9.2) "--quiet --no-trunc" failed with "unknown
	// flag: --no-trunc", so the keep set never built and both this sweep and
	// the app image-store sweep deferred on every deploy. Faked docker in unit
	// tests cannot see that; use the form the rest of the helper already runs.
	listing, err := rootImageStoreDockerValue(20*time.Second, "/usr/bin/docker", "service", "ls", "--format", "{{.ID}}")
	if err != nil {
		return nil, fmt.Errorf("list Swarm services: %w", err)
	}
	deadline := rootImageStoreNow().Add(rootImageStoreInspectBudget)
	refs := []rootSwarmServiceImageRefPair{}
	for _, id := range strings.Fields(listing) {
		if !rootImageStoreNow().Before(deadline) {
			return nil, errors.New("Swarm service inspection deadline exceeded")
		}
		timeout := 10 * time.Second
		if left := deadline.Sub(rootImageStoreNow()); left < timeout {
			timeout = left
		}
		payload, err := rootImageStoreDockerValue(timeout, "/usr/bin/docker", "service", "inspect", id)
		if err != nil {
			return nil, fmt.Errorf("inspect Swarm service %s: %w", id, err)
		}
		var docs []struct {
			Spec struct {
				TaskTemplate struct {
					ContainerSpec struct {
						Image string `json:"Image"`
					} `json:"ContainerSpec"`
				} `json:"TaskTemplate"`
			} `json:"Spec"`
			PreviousSpec *struct {
				TaskTemplate struct {
					ContainerSpec struct {
						Image string `json:"Image"`
					} `json:"ContainerSpec"`
				} `json:"TaskTemplate"`
			} `json:"PreviousSpec"`
		}
		if err := json.Unmarshal([]byte(payload), &docs); err != nil || len(docs) == 0 {
			return nil, fmt.Errorf("parse Swarm service %s inspect: %w", id, errors.Join(err, errors.New("empty service inspect")))
		}
		// A service always has a Spec image; a PreviousSpec, when present,
		// always has one too. Only a null PreviousSpec (never updated) is absent.
		current := docs[0].Spec.TaskTemplate.ContainerSpec.Image
		if strings.TrimSpace(current) == "" {
			return nil, fmt.Errorf("Swarm service %s inspect has no Spec image", id)
		}
		pair := rootSwarmServiceImageRefPair{}
		if current != "<no value>" {
			pair.current = current
		}
		if docs[0].PreviousSpec != nil {
			previous := docs[0].PreviousSpec.TaskTemplate.ContainerSpec.Image
			if strings.TrimSpace(previous) == "" {
				return nil, fmt.Errorf("Swarm service %s inspect has a PreviousSpec without an image", id)
			}
			if previous != "<no value>" {
				pair.previous = previous
			}
		}
		for _, image := range []string{pair.current, pair.previous} {
			if image == "" || image == "<no value>" {
				continue
			}
			if strings.ContainsAny(image, " \t\r\n") {
				return nil, fmt.Errorf("Swarm service %s inspect has a malformed image reference %q", id, image)
			}
		}
		refs = append(refs, pair)
	}
	return refs, nil
}

// rootSwarmServiceImageRefs retains the existing all-spec interface for
// callers that only need the complete image keep set.
func rootSwarmServiceImageRefs() ([]string, error) {
	pairs, err := rootSwarmServiceImageRefPairs()
	if err != nil {
		return nil, err
	}
	refs := make([]string, 0, len(pairs)*2)
	for _, pair := range pairs {
		if pair.current != "" {
			refs = append(refs, pair.current)
		}
		if pair.previous != "" {
			refs = append(refs, pair.previous)
		}
	}
	return refs, nil
}

func rootInfraKeepSetRead(currentPath, previousPath string) (rootInfraKeepSet, error) {
	keep, _, _, err := rootInfraKeepSetReadWithRefs(currentPath, previousPath)
	if err != nil {
		return rootInfraKeepSet{}, err
	}
	if len(keep.digests) == 0 {
		return rootInfraKeepSet{}, errors.New("no retained infrastructure image digest could be read")
	}
	return keep, nil
}

// rootInfraKeepSetReadWithRefs shares one bounded Swarm listing between the
// infrastructure keep set and the host pass, which needs current and previous
// references separately for repository eligibility and image protection.
// An empty result is valid to the host pass when the host has no retained
// infrastructure or release, while rootInfraKeepSetRead keeps its existing
// fail-closed contract for the infrastructure image sweep.
func rootInfraKeepSetReadWithRefs(currentPath, previousPath string) (rootInfraKeepSet, []string, []string, error) {
	keep, err := rootInfrastructureKeep(currentPath, previousPath, rootAppStateRoot, "/etc/shuttle/caddy-stack.yml")
	if err != nil {
		return rootInfraKeepSet{}, nil, nil, err
	}
	if keep.digests == nil {
		return rootInfraKeepSet{}, nil, nil, errors.New("retained infrastructure digest set is unavailable")
	}
	pairs, err := rootSwarmServiceImageRefPairs()
	if err != nil {
		return rootInfraKeepSet{}, nil, nil, err
	}
	currentRefs := make([]string, 0, len(pairs))
	previousRefs := make([]string, 0, len(pairs))
	allRefs := make([]string, 0, len(pairs)*2)
	for _, pair := range pairs {
		if pair.current != "" {
			currentRefs = append(currentRefs, pair.current)
			allRefs = append(allRefs, pair.current)
		}
		if pair.previous != "" {
			previousRefs = append(previousRefs, pair.previous)
			allRefs = append(allRefs, pair.previous)
		}
	}
	services, err := rootInfraServiceImageDigests(allRefs)
	if err != nil {
		return rootInfraKeepSet{}, nil, nil, err
	}
	for digest := range services {
		keep.digests[digest] = true
	}
	return keep, currentRefs, previousRefs, nil
}

func rootInfraListContainers() ([]rootInfraContainerEntry, error) {
	listing, err := rootImageStoreDockerValue(20*time.Second, "/usr/bin/docker", "container", "ls", "--all", "--no-trunc", "--quiet")
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	deadline := rootImageStoreNow().Add(rootImageStoreInspectBudget)
	var inspected []rootInfraContainerEntry
	for _, id := range strings.Fields(listing) {
		if !rootImageStoreNow().Before(deadline) {
			return nil, errors.New("container inspection deadline exceeded")
		}
		timeout := 10 * time.Second
		if left := deadline.Sub(rootImageStoreNow()); left < timeout {
			timeout = left
		}
		output, err := rootImageStoreDockerValue(timeout, "/usr/bin/docker", "container", "inspect", "--format", rootInfraContainerInspectFormat, id)
		if err != nil {
			return nil, fmt.Errorf("inspect container %s: %w", id, err)
		}
		// Strip line endings only: empty or `<no value>` Swarm labels must keep
		// their tab-delimited positions, or the row will appear malformed and
		// defer the sweep.
		for _, row := range strings.Split(strings.TrimRight(output, "\r\n"), "\n") {
			fields := strings.Split(strings.TrimRight(row, "\r"), "\t")
			if (len(fields) != 6 && len(fields) != 11) || fields[0] != id || fields[1] == "" || fields[2] == "" {
				return nil, fmt.Errorf("parse container %s inspect: expected id, state, image and labels", id)
			}
			for index := 3; index < len(fields); index++ {
				if fields[index] == "<no value>" {
					fields[index] = ""
				}
			}
			entry := rootInfraContainerEntry{ID: fields[0], State: fields[1], ImageID: fields[2], TaskID: fields[3], Service: fields[4], Namespace: fields[5]}
			if len(fields) == 11 {
				entry.Slot = rootHostTaskSlot(fields[4], fields[6], fields[3], fields[7], fields[8])
				entry.ServiceID = fields[9]
				entry.Created, _ = parseRootHostImageCreatedAt(fields[10])
			}
			inspected = append(inspected, entry)
		}
	}
	return inspected, nil
}

// pruneRootInfrastructureImages reclaims old Docker Hub images used by
// Shuttle's app Redis/RabbitMQ tasks and the shared Caddy edge. Dockerd keeps
// images after Swarm task containers stop, so old service versions accumulate
// until the host's disk guard refuses another deploy. The task container and
// image passes are separate because a stopped task must be removed before its
// image can be considered, while every live task and every retained or Swarm
// rollback reference must keep its image. A failed read cannot prove that a
// release is unused, so it defers cleanup. The image pass also needs the host
// operation fence: a concurrent deploy may have pulled an image before its
// stack file and service spec are visible to this reader.
func pruneRootInfrastructureImages(currentPath, previousPath, operationID string, concurrent bool) error {
	kept, removedContainers, removed, stillHeld := 0, 0, 0, 0
	defer func() {
		rootLog("infra images: %d kept, %d stopped infrastructure task containers removed, %d images removed, %d still held by a container", kept, removedContainers, removed, stillHeld)
	}()
	keep, err := rootInfraKeepSetRead(currentPath, previousPath)
	if err != nil {
		rootLog("infra images: sweep deferred, keep set could not be read: %v", err)
		return err
	}
	listing, err := rootImageStoreDockerValue(30*time.Second, "/usr/bin/docker", "image", "ls", "--all", "--digests", "--no-trunc", "--format", "{{.Repository}}\t{{.Digest}}\t{{.ID}}")
	if err != nil {
		rootLog("infra images: sweep deferred, image listing failed: %v", err)
		return err
	}
	entries, err := parseRootInfraImageStore(listing)
	if err != nil {
		rootLog("infra images: sweep deferred, image listing is malformed: %v", err)
		return err
	}
	repositories := map[string]bool{"redis": true, "rabbitmq": true, "caddy": true}
	inspected, err := rootInfraListContainers()
	if err != nil {
		rootLog("infra images: sweep deferred, containers could not be inspected: %v", err)
		return err
	}
	keptIDs := map[string]bool{}
	for _, c := range inspected {
		if c.State != "exited" && c.State != "dead" {
			keptIDs[c.ImageID] = true
		}
	}
	for _, entry := range entries {
		if keep.digests[entry.Digest] {
			keptIDs[entry.ID] = true
		}
	}
	appNamespaces := keep.appNamespaces
	inScope := func(service, namespace string) bool {
		return namespace == "shuttle-edge" && service == "shuttle-edge_caddy" || appNamespaces[namespace] && (service == namespace+"_redis" || service == namespace+"_rabbitmq")
	}
	firstContainers := planRootInfrastructureContainers(inScope, keptIDs, inspected)
	fresh, err := rootInfraKeepSetRead(currentPath, previousPath)
	if err != nil {
		rootLog("infra images: container pass deferred, keep set could not be re-read: %v", err)
		return err
	}
	// Re-read all daemon states immediately before removal, then intersect with
	// the original plan. A disappearance or state change can only cancel removal.
	currentInspected, err := rootInfraListContainers()
	if err != nil {
		rootLog("infra images: container pass deferred, containers could not be re-read: %v", err)
		return err
	}
	freshKeptIDs := map[string]bool{}
	for _, c := range currentInspected {
		if c.State != "exited" && c.State != "dead" {
			freshKeptIDs[c.ImageID] = true
		}
	}
	for _, entry := range entries {
		if fresh.digests[entry.Digest] {
			freshKeptIDs[entry.ID] = true
		}
	}
	containerIDs := intersectRootImageCandidates(firstContainers, planRootInfrastructureContainers(inScope, freshKeptIDs, currentInspected))
	for _, id := range containerIDs {
		if removeErr := rootImageStoreDockerCommand("/usr/bin/docker", "container", "rm", id); removeErr != nil {
			rootLog("infra images: kept stopped task container %s: %v", id, removeErr)
		} else {
			removedContainers++
		}
	}
	imagePass := func() error {
		fresh, err := rootInfraKeepSetRead(currentPath, previousPath)
		if err != nil {
			return err
		}
		held := map[string]bool{}
		freshContainers, err := rootInfraListContainers()
		if err != nil {
			return err
		}
		for _, c := range freshContainers {
			held[c.ImageID] = true
		}
		initialKeepIDs := map[string]bool{}
		for _, c := range inspected {
			if c.State != "exited" && c.State != "dead" {
				initialKeepIDs[c.ImageID] = true
			}
		}
		for _, entry := range entries {
			if keep.digests[entry.Digest] {
				initialKeepIDs[entry.ID] = true
			}
		}
		firstUnheld := planRootInfrastructureImages(repositories, keep.digests, initialKeepIDs, nil, entries)
		freshUnheld := planRootInfrastructureImages(repositories, fresh.digests, initialKeepIDs, nil, entries)
		stillHeld = 0
		for _, id := range intersectRootImageCandidates(firstUnheld, freshUnheld) {
			if held[id] {
				stillHeld++
			}
		}
		candidates := planRootInfrastructureImages(repositories, fresh.digests, initialKeepIDs, held, entries)
		candidates = intersectRootImageCandidates(planRootInfrastructureImages(repositories, keep.digests, keptIDs, held, entries), candidates)
		for _, id := range candidates {
			if err := rootImageStoreDockerCommand("/usr/bin/docker", "image", "rm", id); err != nil {
				rootLog("infra images: kept %s: %v", id, err)
				continue
			}
			removed++
		}
		infraIDs := map[string]bool{}
		for _, entry := range entries {
			if repositories[rootInfraRepository(entry.Repository)] && entry.ID != "" {
				infraIDs[entry.ID] = true
			}
		}
		kept = len(infraIDs) - removed
		return nil
	}
	if concurrent {
		entered := false
		err = rootInfraSoleOperation(operationID, func() error { entered = true; return imagePass() })
		if err != nil {
			if !entered {
				rootLog("infra images: image pass deferred while another operation is active: %v", err)
				return nil
			}
			rootLog("infra images: image pass deferred: %v", err)
			return err
		}
	} else {
		err = imagePass()
	}
	if err != nil {
		rootLog("infra images: image pass deferred: %v", err)
		return err
	}
	return nil
}

func candidateIDSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

func intersectRootImageCandidates(first, fresh []string) []string {
	allowed := candidateIDSet(fresh)
	intersection := make([]string, 0, len(first))
	for _, id := range first {
		if allowed[id] {
			intersection = append(intersection, id)
		}
	}
	return intersection
}

var (
	rootRegistryRepositoryName = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	rootRegistryTagName        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	rootRegistryDigestName     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func readRootRegistryIndex(client *http.Client, owned []string) (registryTagIndex, error) {
	var catalog registryCatalog
	if err := rootRegistryJSON(client, strings.TrimRight(rootRegistryBaseURL, "/")+"/v2/_catalog?n=1000", &catalog); err != nil {
		return nil, fmt.Errorf("list loopback registry: %w", err)
	}
	ownedSet := make(map[string]bool, len(owned))
	for _, repository := range owned {
		if rootRegistryRepositoryName.MatchString(repository) {
			ownedSet[repository] = true
		}
	}
	index := registryTagIndex{}
	for _, repository := range catalog.Repositories {
		if !rootRegistryRepositoryName.MatchString(repository) {
			rootRegistryLog("registry: skipped invalid catalog repository %q", repository)
			continue
		}
		if !ownedSet[repository] {
			continue
		}
		var tags registryTags
		if err := rootRegistryJSON(client, strings.TrimRight(rootRegistryBaseURL, "/")+"/v2/"+url.PathEscape(repository)+"/tags/list?n=1000", &tags); err != nil {
			return nil, err
		}
		resolved := map[string]string{}
		for _, tag := range tags.Tags {
			if !rootRegistryTagName.MatchString(tag) {
				rootRegistryLog("registry: skipped invalid tag %q in repository %s", tag, repository)
				continue
			}
			digest, err := rootRegistryDigest(client, repository, tag)
			if err != nil {
				return nil, err
			}
			resolved[tag] = digest
		}
		index[repository] = resolved
	}
	return index, nil
}

func deleteRootRegistryManifests(client *http.Client, references []string) error {
	for _, reference := range references {
		repository, digest, _ := strings.Cut(reference, "@")
		if !rootRegistryRepositoryName.MatchString(repository) || !rootRegistryDigestName.MatchString(digest) {
			return fmt.Errorf("invalid owned registry manifest reference %q", reference)
		}
		request, _ := http.NewRequest(http.MethodDelete, strings.TrimRight(rootRegistryBaseURL, "/")+"/v2/"+url.PathEscape(repository)+"/manifests/"+url.PathEscape(digest), nil)
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusNotFound {
			return fmt.Errorf("registry refused owned manifest deletion for %s: HTTP %d", repository, response.StatusCode)
		}
	}
	return nil
}

// errRegistryPullInFlight reports a sweep that refused to start because a task
// on this node was still pulling. It is a deferral, never a failure: the sweep
// runs again on the next promotion and on demand through stack-reclaim.
var errRegistryPullInFlight = errors.New("registry sweep deferred: a task on this node is still pulling an image")

// rootRegistryQuiesceWait is how long the sweep waits for the node to stop
// pulling before deferring. Short on purpose: this is belt and braces on top of
// a convergence wait that has already proven this deploy's own pulls are
// finished, so anything still pulling here belongs to something else and is not
// this operation's to wait for.
const rootRegistryQuiesceWait = 2 * time.Second

// collectRootRegistryGarbage stops the registry for the duration of the sweep,
// because distribution's collector is not safe against concurrent writes: a push
// landing mid-sweep can have its freshly uploaded blobs judged unreferenced.
//
// Stopping the registry also resets every pull in flight against it. That is
// what turned a still-downloading blob into "read: connection reset by peer",
// the task into Rejected and the promotion into a silent Swarm rollback. The
// convergence wait removes the deterministic trigger : this deploy's pulls are
// provably finished before this runs : but three windows survive it and none can
// be closed by a wait: Swarm's ten-second update monitor can still roll a
// service back afterwards, restart_policy: on-failure can restart a task
// afterwards, and Swarm's reconciliation of any OTHER stack on this host is not
// serialised by the root-operation lock at all. Hence the guard below.
func collectRootRegistryGarbage() error {
	if err := awaitRootRegistryQuiet(); err != nil {
		return err
	}
	if err := runFixed("/usr/bin/docker", "stop", rootRegistryContainer); err != nil {
		// A stop that errors may still have stopped it.
		return &rootRegistryLeftDownError{err: err}
	}
	// A failed migration leaves the registry removed, so the recreate below is
	// what brings the host back rather than a start that has nothing to start.
	migrated, migrateErr := migrateRootRegistryToNonRoot()
	if migrateErr != nil {
		rootLog("registry: could not be migrated to %s: %v", rootRegistryUser, migrateErr)
	}
	gc := exec.Command("/usr/bin/docker", rootRegistryGarbageCollectArgs()...)
	gc.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, gcErr := gc.CombinedOutput()
	startErr := restartRootRegistry(func() error {
		if migrated {
			return runFixed("/usr/bin/docker", rootRegistryCreateArgs()...)
		}
		return runFixed("/usr/bin/docker", "start", rootRegistryContainer)
	}, inspectRootRegistryHealth, probeRootRegistryV2, time.Sleep)
	if startErr != nil {
		// Whatever the collector did, a registry left stopped is the worse
		// outcome: every later pull on this host fails. It is reported on its
		// own line and joined to the collector's error rather than hidden
		// behind it.
		rootLog("registry: could not be restarted after garbage collection: %v", startErr)
	}
	if gcErr != nil && startErr == nil {
		return fmt.Errorf("registry garbage collection failed: %s", strings.TrimSpace(string(output)))
	}
	if gcErr != nil {
		return &rootRegistryLeftDownError{err: errors.Join(fmt.Errorf("registry garbage collection failed: %s", strings.TrimSpace(string(output))), startErr)}
	}
	if startErr != nil {
		return &rootRegistryLeftDownError{err: startErr}
	}
	rootLog("registry: garbage collected and restarted")
	return nil
}

const rootRegistryReadyWait = 30 * time.Second

type rootRegistryHealthInspect func(time.Duration) (string, error)
type rootRegistryV2Probe func(time.Duration) error

func restartRootRegistry(start func() error, inspect rootRegistryHealthInspect, probe rootRegistryV2Probe, pause func(time.Duration)) error {
	return restartRootRegistryWithTimeout(rootRegistryReadyWait, start, inspect, probe, pause)
}

func restartRootRegistryWithTimeout(timeout time.Duration, start func() error, inspect rootRegistryHealthInspect, probe rootRegistryV2Probe, pause func(time.Duration)) error {
	if err := start(); err != nil {
		return &rootRegistryLeftDownError{err: err}
	}
	if err := waitRootRegistryReady(timeout, inspect, probe, pause); err != nil {
		return &rootRegistryLeftDownError{err: err}
	}
	return nil
}

func waitRootRegistryReady(timeout time.Duration, inspect rootRegistryHealthInspect, probe rootRegistryV2Probe, pause func(time.Duration)) error {
	// On 2026-10-28, both Ubuntu 24.04 and Debian 13 returned from docker start
	// before the registry was ready, so the next strict doctor failed briefly.
	// Require Docker health and the loopback Distribution endpoint before success.
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("registry did not become healthy and answer /v2/ within %s", timeout)
		}
		health, inspectErr := inspect(min(remaining, 5*time.Second))
		if inspectErr == nil && strings.TrimSpace(health) == "healthy" {
			remaining = time.Until(deadline)
			if remaining > 0 {
				if probeErr := probe(min(remaining, 2*time.Second)); probeErr == nil {
					return nil
				}
			}
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("registry did not become healthy and answer /v2/ within %s", timeout)
		}
		pause(min(remaining, time.Second))
	}
}

func inspectRootRegistryHealth(timeout time.Duration) (string, error) {
	return runFixedValue(timeout, "/usr/bin/docker", "container", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", rootRegistryContainer)
}

func probeRootRegistryV2(timeout time.Duration) error {
	client := rootLoopbackRegistryClient(timeout)
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(rootRegistryBaseURL, "/")+"/v2/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("registry /v2/ returned HTTP %d", response.StatusCode)
	}
	return nil
}

// awaitRootRegistryQuiet refuses to tear the registry down while this node is
// still pulling.
//
// It blocks on the Preparing state alone : the state in which swarmkit's
// Prepare runs pullImage : and never on Pending, Assigned, Ready or Starting. A
// task that can never be scheduled sits in Pending forever, so blocking on that
// set would pin the host permanently "busy": the sweep would never run again
// and the registry volume would grow until the 20 % free-disk guard refused
// every deploy, which is the exact failure this sweep exists to prevent.
//
// A `docker node ps` that cannot be run is a deferral, not a go-ahead. Stopping
// the registry without knowing whether this node is still Preparing is the
// original incident (connection reset under an in-flight pull). A deferred
// sweep retries on the next promotion; a disk that grows by one more release is
// cheaper than killing a pull that is still running.
func awaitRootRegistryQuiet() error {
	deadline := time.Now().Add(rootRegistryQuiesceWait)
	for {
		body, err := runFixedValue(time.Second, "/usr/bin/docker", "node", "ps", "--filter", "desired-state=running", "--no-trunc", "--format", rootNodeTaskStateFormat)
		if rootRegistryQuietEnough(body, err) {
			return nil
		}
		if err != nil {
			rootLog("registry: node task states could not be read, deferring the sweep: %v", err)
			return errRegistryPullInFlight
		}
		if !time.Now().Before(deadline) {
			return errRegistryPullInFlight
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// rootRegistryVolumeBytes measures the registry on the only side that can see
// it. The volume is a plain directory owned by root on this host, so the helper
// walks it directly instead of running yet another container just to run `du`.
func rootRegistryVolumeBytes() (int64, error) {
	inspect := exec.Command("/usr/bin/docker", "volume", "inspect", "--format", "{{.Mountpoint}}", rootRegistryVolume)
	inspect.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := inspect.Output()
	if err != nil {
		return 0, fmt.Errorf("inspect registry volume: %w", err)
	}
	mountpoint := strings.TrimSpace(string(output))
	if !filepath.IsAbs(mountpoint) {
		return 0, errors.New("registry volume has no absolute mountpoint")
	}
	return directoryBytes(mountpoint)
}

func directoryBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Only regular files occupy registry storage; symlinks are counted at
		// their target if that target is itself inside the volume.
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// rootRegistryKeepDigests collects every registry digest that any application
// on this host still references : the app being deployed, through the paths it
// passes, and every other app through the stacks the helper stored for it.
//
// Scanning the other apps is not caution, it is correctness. Repository names
// are flat (`<app>-<service>`), so `demo-app` with a service `agents-api` and
// `demo-app-agents` with a service `api` both produce `demo-app-agents-api`.
// No prefix test can separate them, because the name genuinely belongs to both.
// Deciding what to delete from the deployed app's stacks alone therefore let a
// promotion of one application erase the release manifests of another, and take
// its rollback with them.
//
// A digest kept because a neighbour still uses it costs one manifest of disk
// until that neighbour moves on. A digest deleted because a neighbour was not
// consulted costs that neighbour its ability to roll back.
func rootRegistryKeepDigests(stateRoot, currentPath, previousPath string) (map[string]bool, error) {
	keep := map[string]bool{}
	collect := func(path string) error {
		body, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, digest := range rootStackRegistryDigests(body) {
			keep[digest] = true
		}
		return nil
	}
	for _, path := range []string{currentPath, previousPath} {
		if err := collect(path); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(stateRoot)
	if os.IsNotExist(err) {
		return keep, nil
	}
	if err != nil {
		return nil, err
	}
	// Sorted by ReadDir, and every entry is read: the result cannot depend on
	// directory order, which invariant 2 requires of anything feeding a
	// generated artifact or a deletion decision.
	for _, entry := range entries {
		if !entry.IsDir() || !rootAppName.MatchString(entry.Name()) {
			continue
		}
		for _, name := range []string{"current.yml", "previous.yml"} {
			if err := collect(filepath.Join(stateRoot, entry.Name(), name)); err != nil {
				return nil, err
			}
		}
	}
	return keep, nil
}

// rootRetainedStackFilesExist reports whether any retained stack file exists:
// the deploying app's current or previous file, or any app's under stateRoot.
// Any error other than "does not exist" is returned, so a sweep stays closed.
func rootRetainedStackFilesExist(stateRoot, currentPath, previousPath string) (bool, error) {
	exists := func(path string) (bool, error) {
		_, err := os.Lstat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for _, path := range []string{currentPath, previousPath} {
		if found, err := exists(path); err != nil || found {
			return found, err
		}
	}
	entries, err := os.ReadDir(stateRoot)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !rootAppName.MatchString(entry.Name()) {
			continue
		}
		for _, name := range []string{"current.yml", "previous.yml"} {
			if found, err := exists(filepath.Join(stateRoot, entry.Name(), name)); err != nil || found {
				return found, err
			}
		}
	}
	return false, nil
}

// rootRegistryOwnedRepositories reads the signed stacks the helper retained.
// Repository ownership is exact: an application may sweep only repository
// names in its own current.yml or previous.yml, and any name also retained by
// another application is shared and cannot be swept by either one. A name
// absent from both retained files may leak registry data, but guessing from an
// app-name prefix can delete a neighbour's freshly pushed release before its
// current.yml is written, so those repositories are deliberately not swept.
func rootRegistryOwnedRepositories(app, currentPath, previousPath, stateRoot string) (owned []string, shared []string, err error) {
	appRepositories, err := rootRegistryRepositoriesInFiles(currentPath, previousPath)
	if err != nil {
		return nil, nil, err
	}
	ownedSet := map[string]bool{}
	for _, repository := range appRepositories {
		ownedSet[repository] = true
	}
	sharedSet := map[string]bool{}
	entries, err := os.ReadDir(stateRoot)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == app || !rootAppName.MatchString(entry.Name()) {
			continue
		}
		other, err := rootRegistryRepositoriesInFiles(filepath.Join(stateRoot, entry.Name(), "current.yml"), filepath.Join(stateRoot, entry.Name(), "previous.yml"))
		if err != nil {
			return nil, nil, fmt.Errorf("read retained stacks for %s: %w", entry.Name(), err)
		}
		for _, repository := range other {
			if ownedSet[repository] {
				sharedSet[repository] = true
			}
		}
	}
	for repository := range ownedSet {
		if sharedSet[repository] {
			shared = append(shared, repository)
		} else {
			owned = append(owned, repository)
		}
	}
	sort.Strings(owned)
	sort.Strings(shared)
	return owned, shared, nil
}

func rootRegistryRepositoriesInFiles(paths ...string) ([]string, error) {
	set := map[string]bool{}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var document map[string]any
		if err := yaml.Unmarshal(body, &document); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		services, ok := document["services"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("parse %s: services map is missing", path)
		}
		for _, raw := range services {
			service, _ := raw.(map[string]any)
			image := strings.TrimSpace(fmt.Sprint(service["image"]))
			if !strings.HasPrefix(image, rootRegistryImagePrefix) {
				continue
			}
			remainder := strings.TrimPrefix(image, rootRegistryImagePrefix)
			repository, digest, ok := strings.Cut(remainder, "@")
			if !ok || !rootRegistryDigestName.MatchString(digest) {
				continue
			}
			if !rootRegistryRepositoryName.MatchString(repository) {
				rootRegistryLog("registry: skipped invalid retained repository %q", repository)
				continue
			}
			set[repository] = true
		}
	}
	result := make([]string, 0, len(set))
	for repository := range set {
		result = append(result, repository)
	}
	sort.Strings(result)
	return result, nil
}

func rootRegistryDeletePass(app, operationID string, concurrent bool, fn func() error) (bool, error) {
	if !concurrent {
		return false, fn()
	}
	ran := false
	err := rootRegistrySoleOperation(operationID, func() error {
		ran = true
		return fn()
	})
	if err != nil && !ran {
		rootRegistryLog("app=%s registry: delete pass deferred while another operation is active: %v", app, err)
		return true, nil
	}
	return false, err
}

func intersectRootRegistryCandidates(first, fresh []string) []string {
	set := make(map[string]bool, len(fresh))
	for _, reference := range fresh {
		set[reference] = true
	}
	result := make([]string, 0, len(first))
	for _, reference := range first {
		if set[reference] {
			result = append(result, reference)
		}
	}
	return result
}

func filterRootRegistryCandidates(references, owned []string) []string {
	set := make(map[string]bool, len(owned))
	for _, repository := range owned {
		set[repository] = true
	}
	result := make([]string, 0, len(references))
	for _, reference := range references {
		repository, _, _ := strings.Cut(reference, "@")
		if set[repository] {
			result = append(result, reference)
		}
	}
	return result
}

// rootStackRegistryDigests returns the digests of every image a stack pulls from
// the loopback registry, whichever application published them.
func rootStackRegistryDigests(body []byte) []string {
	var document map[string]any
	if yaml.Unmarshal(body, &document) != nil {
		return nil
	}
	services, _ := document["services"].(map[string]any)
	values := []string{}
	for _, raw := range services {
		service, _ := raw.(map[string]any)
		image := strings.TrimSpace(fmt.Sprint(service["image"]))
		if !strings.HasPrefix(image, rootRegistryImagePrefix) {
			continue
		}
		if _, digest, ok := strings.Cut(image, "@"); ok {
			values = append(values, digest)
		}
	}
	return values
}

func rootRegistryJSON(client *http.Client, endpoint string, target any) error {
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("registry returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	return decoder.Decode(target)
}

func rootRegistryDigest(client *http.Client, repository, tag string) (string, error) {
	if !rootRegistryRepositoryName.MatchString(repository) || !rootRegistryTagName.MatchString(tag) {
		return "", errors.New("invalid registry repository or tag")
	}
	request, _ := http.NewRequest(http.MethodHead, strings.TrimRight(rootRegistryBaseURL, "/")+"/v2/"+url.PathEscape(repository)+"/manifests/"+url.PathEscape(tag), nil)
	request.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	digest := strings.TrimSpace(response.Header.Get("Docker-Content-Digest"))
	if response.StatusCode/100 != 2 || !rootRegistryDigestName.MatchString(digest) {
		return "", errors.New("registry manifest has no canonical digest")
	}
	return digest, nil
}

// rootRouteDomain is hoisted out of the request path: compiling a regexp on
// every signed operation is work done once per process instead.
var rootRouteDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

// The injected runner keeps the destructive ordering testable without Docker.
//
// The caller asks Docker for `{{json ...StopGracePeriod}}`, which prints the
// duration as integer nanoseconds and an unset value as `null`. The plain
// template prints Go duration text ("10s"): the 30-10-2026 e2e on Docker 29.9.2
// showed every `docker stack deploy` service carries 10s, so the strict
// nanosecond parser refused every Swarm destroy and left the host blocked.
func parseStopGracePeriods(body []byte) (time.Duration, error) {
	text := strings.TrimSuffix(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	lines := strings.Split(text, "\n")
	maximum := time.Duration(0)
	for _, line := range lines {
		token := strings.TrimSpace(line)
		if token == "" || token == "null" || token == "<nil>" || token == "0" {
			if maximum < 10*time.Second {
				maximum = 10 * time.Second
			}
			continue
		}
		for _, digit := range token {
			if digit < '0' || digit > '9' {
				return 0, fmt.Errorf("invalid Docker stop grace period %q", token)
			}
		}
		nanoseconds, err := strconv.ParseInt(token, 10, 64)
		if err != nil || nanoseconds < 0 {
			return 0, fmt.Errorf("invalid Docker stop grace period %q", token)
		}
		grace := time.Duration(nanoseconds)
		if grace == 0 {
			grace = 10 * time.Second
		}
		if grace > maximum {
			maximum = grace
		}
	}
	return maximum, nil
}

func destroyDrainBound(maxGrace time.Duration) time.Duration {
	if maxGrace >= destroyDrainCeiling-30*time.Second {
		return destroyDrainCeiling
	}
	bound := maxGrace + 30*time.Second
	if bound < 30*time.Second {
		return 30 * time.Second
	}
	return bound
}

func destroyDeadlineRunner(parent context.Context, deadline func() time.Time, execute func(context.Context, ...string) ([]byte, error)) func(...string) ([]byte, error) {
	return destroyDeadlineRunnerWithParent(func() context.Context { return parent }, deadline, execute)
}

func destroyDeadlineRunnerWithParent(parent func() context.Context, deadline func() time.Time, execute func(context.Context, ...string) ([]byte, error)) func(...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		ctx, cancel := destroyDeadlineContext(parent(), deadline())
		defer cancel()
		return execute(ctx, args...)
	}
}

func destroyDeadlineContext(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	if deadline.IsZero() {
		return context.WithCancel(parent)
	}
	return context.WithDeadline(parent, deadline)
}

// The 30-10-2026 demo-prod incident showed that Swarm can leave an exited
// task container attached to a volume for seconds after service removal. The
// drain therefore proves both running and all-container absence before volume
// removal, and includes each service's configured stop grace period.
func drainRootStackBeforeRemoval(app string, run func(...string) ([]byte, error), now func() time.Time, sleep func(time.Duration)) (time.Time, error) {
	return drainRootStackBeforeRemovalWithBudget(app, run, now, sleep, 0, nil)
}

func drainRootStackBeforeRemovalWithBudget(app string, run func(...string) ([]byte, error), now func() time.Time, sleep func(time.Duration), priorBound time.Duration, persistDeadline func(time.Duration, time.Time) error) (time.Time, error) {
	return drainRootStackBeforeRemovalWithStartedAt(app, run, now, sleep, now(), priorBound, persistDeadline)
}

func drainRootStackBeforeRemovalWithStartedAt(app string, run func(...string) ([]byte, error), now func() time.Time, sleep func(time.Duration), startedAt time.Time, priorBound time.Duration, persistDeadline func(time.Duration, time.Time) error) (time.Time, error) {
	discoveryDeadline := startedAt.Add(rootHelperOperationMargin)
	if persistDeadline != nil {
		discoveryBound := min(max(priorBound, 30*time.Second), destroyDrainCeiling)
		if err := persistDeadline(discoveryBound, discoveryDeadline); err != nil {
			return time.Time{}, fmt.Errorf("persist destroy discovery deadline: %w", err)
		}
	}
	filter := "label=com.docker.stack.namespace=" + app
	body, err := run("service", "ls", "--filter", filter, "--format", "{{.ID}}")
	if err != nil {
		return time.Time{}, fmt.Errorf("inspect owned services before removal: %w", err)
	}
	ids := strings.Fields(string(body))
	maxGrace := time.Duration(0)
	if len(ids) > 0 {
		graceBody, err := run(append([]string{"service", "inspect", "--format", "{{json .Spec.TaskTemplate.ContainerSpec.StopGracePeriod}}"}, ids...)...)
		if err != nil {
			return time.Time{}, fmt.Errorf("inspect owned service stop grace periods: %w", err)
		}
		maxGrace, err = parseStopGracePeriods(graceBody)
		if err != nil {
			return time.Time{}, err
		}
	}
	bound := destroyDrainBound(maxGrace)
	if priorBound > bound {
		bound = min(max(priorBound, 30*time.Second), destroyDrainCeiling)
	}
	deadline := now().Add(bound)
	if persistDeadline != nil {
		if err := persistDeadline(bound, deadline); err != nil {
			return time.Time{}, fmt.Errorf("persist destroy drain deadline: %w", err)
		}
	}
	if len(ids) > 0 {
		args := append([]string{"service", "rm"}, ids...)
		if output, err := run(args...); err != nil {
			if !dockerObjectAbsentAny("service", ids, string(output), err.Error()) {
				return time.Time{}, fmt.Errorf("stop owned services before network removal: %w: %s", err, strings.TrimSpace(string(output)))
			}
		}
	}
	for {
		body, err := run("ps", "-q", "--filter", filter)
		if err != nil {
			return time.Time{}, fmt.Errorf("inspect owned containers before network removal: %w", err)
		}
		if strings.TrimSpace(string(body)) != "" {
			if !now().Before(deadline) {
				return time.Time{}, fmt.Errorf("application %s still has running containers; refusing to remove its networks", app)
			}
			sleep(500 * time.Millisecond)
			continue
		}
		break
	}
	for {
		body, err := run("ps", "-a", "-q", "--no-trunc", "--filter", filter)
		if err != nil {
			return time.Time{}, fmt.Errorf("inspect all owned containers before volume removal: %w", err)
		}
		containers := strings.Fields(string(body))
		if len(containers) == 0 {
			return deadline, nil
		}
		if !now().Before(deadline) {
			return time.Time{}, fmt.Errorf("application %s still has containers after %s; refusing to remove its volumes", app, bound)
		}
		for _, id := range containers {
			inspected, inspectErr := run("container", "inspect", "--format", "{{.State.Status}}\t{{index .Config.Labels \"com.docker.swarm.task.id\"}}", id)
			if inspectErr != nil {
				if dockerObjectAbsent("container", id, string(inspected), inspectErr.Error()) {
					continue
				}
				return time.Time{}, fmt.Errorf("inspect owned container %s before volume removal: %w: %s", id, inspectErr, strings.TrimSpace(string(inspected)))
			}
			status, taskLabel, hasLabelSeparator := strings.Cut(strings.TrimSpace(string(inspected)), "\t")
			status = strings.TrimSpace(status)
			if !hasLabelSeparator || strings.TrimSpace(taskLabel) == "" || (status != "exited" && status != "dead") {
				continue
			}
			output, removeErr := run("container", "rm", id)
			if removeErr != nil && !dockerObjectAbsent("container", id, string(output), removeErr.Error()) {
				return time.Time{}, fmt.Errorf("remove stopped task container %s before volume removal: %w: %s", id, removeErr, strings.TrimSpace(string(output)))
			}
		}
		if !now().Before(deadline) {
			body, err := run("ps", "-a", "-q", "--no-trunc", "--filter", filter)
			if err != nil {
				return time.Time{}, fmt.Errorf("inspect all owned containers before volume removal: %w", err)
			}
			if len(strings.Fields(string(body))) == 0 {
				return deadline, nil
			}
			return time.Time{}, fmt.Errorf("application %s still has containers after %s; refusing to remove its volumes", app, bound)
		}
		sleep(500 * time.Millisecond)
	}
}

func removeOwnedVolumes(app string, run func(...string) ([]byte, error), deadline time.Time, now func() time.Time, sleep func(time.Duration)) error {
	filter := "label=com.docker.stack.namespace=" + app
	if !now().Before(deadline) {
		return fmt.Errorf("list owned volumes: %s", context.DeadlineExceeded)
	}
	body, err := run("volume", "ls", "--filter", filter, "--format", "{{.Name}}")
	if err != nil {
		return fmt.Errorf("list owned volumes: %s", volumeCommandError(body, err))
	}
	seen := map[string]bool{}
	for _, name := range strings.Fields(string(body)) {
		seen[name] = true
		if err := removeOwnedVolume(app, name, "owned volume", run, deadline, now, sleep); err != nil {
			return err
		}
	}
	for _, name := range []string{app + "_redis_data", app + "_rabbitmq_data"} {
		if seen[name] {
			continue
		}
		if err := removeOwnedVolume(app, name, "owned infrastructure volume", run, deadline, now, sleep); err != nil {
			return err
		}
	}
	return nil
}

func removePreparedDestroyVolumes(app string, journal *destroyCleanupJournal, run func(...string) ([]byte, error), deadline time.Time, now func() time.Time, sleep func(time.Duration), persist func() error) error {
	if journal == nil || !journal.Progress.VolumesPrepared {
		return errors.New("destroy volume snapshot is not prepared")
	}
	// The 30-10-2026 demo-prod incident showed that rediscovery can authorize
	// deletion of a matching volume created after this destroy's durable snapshot.
	// Feed the shared removal loop only the durable pending snapshot, never a new
	// Docker listing. Its rm adapter persists each completion before continuing.
	preparedNames := slices.Clone(journal.PendingVolumes)
	if len(preparedNames) == 0 {
		return nil
	}
	preparedSet := make(map[string]bool, len(preparedNames))
	for _, name := range preparedNames {
		if preparedSet[name] {
			return errors.New("destroy cleanup journal contains a duplicate pending volume")
		}
		preparedSet[name] = true
	}
	filter := "label=com.docker.stack.namespace=" + app
	journaledRun := func(args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "volume" && args[1] == "ls" {
			if len(args) != 6 || args[2] != "--filter" || args[3] != filter || args[4] != "--format" || args[5] != "{{.Name}}" {
				return nil, errors.New("unexpected volume discovery during prepared destroy cleanup")
			}
			return []byte(strings.Join(preparedNames, "\n")), nil
		}
		if len(args) >= 2 && args[0] == "volume" && args[1] == "inspect" {
			if len(args) != 5 || args[2] != "--format" || args[3] != "{{json .Labels}}" {
				return nil, errors.New("unexpected volume inspection during prepared destroy cleanup")
			}
			if !preparedSet[args[4]] {
				return []byte("Error: No such volume"), errors.New("no such volume")
			}
			return run(args...)
		}
		if len(args) == 3 && args[0] == "volume" && args[1] == "rm" {
			name := args[2]
			if !slices.Contains(journal.PendingVolumes, name) {
				return nil, fmt.Errorf("refusing to remove unjournaled volume %s", name)
			}
			output, err := run(args...)
			if err == nil || dockerObjectAbsent("volume", name, string(output), err.Error()) {
				journal.PendingVolumes = removeDestroyPendingItem(journal.PendingVolumes, name)
				if persistErr := persist(); persistErr != nil {
					return output, fmt.Errorf("journal removed application volume %s: %w", name, persistErr)
				}
			}
			return output, err
		}
		return run(args...)
	}
	if err := removeOwnedVolumes(app, journaledRun, deadline, now, sleep); err != nil {
		return err
	}
	// The shared loop succeeds without calling rm for two kinds of journaled
	// names: a volume Docker already deleted before an interruption kept the
	// journal from recording it (an absence response on inspect), and a volume whose
	// labels now name another owner, which is kept on purpose. Both are settled
	// outcomes. Left in the pending list, they made the caller mark volumes
	// removed while destroyCleanupSettled refused the journal forever, so no
	// later recovery could finish the destroy.
	if len(journal.PendingVolumes) > 0 {
		rootLog("destroy: settling journaled volumes absent or kept for ownership: %s", strings.Join(journal.PendingVolumes, ", "))
		journal.PendingVolumes = nil
		if err := persist(); err != nil {
			return fmt.Errorf("journal settled application volumes: %w", err)
		}
	}
	return nil
}

type ownedVolumeTarget struct {
	name        string
	description string
}

func discoverOwnedVolumes(app string, run func(...string) ([]byte, error), deadline time.Time, now func() time.Time) ([]ownedVolumeTarget, error) {
	filter := "label=com.docker.stack.namespace=" + app
	runBeforeDeadline := func(args ...string) ([]byte, error) {
		if !now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		return run(args...)
	}
	body, err := runBeforeDeadline("volume", "ls", "--filter", filter, "--format", "{{.Name}}")
	if err != nil {
		return nil, fmt.Errorf("list owned volumes: %s", volumeCommandError(body, err))
	}
	seen := map[string]bool{}
	targets := make([]ownedVolumeTarget, 0)
	add := func(name, description string) error {
		if seen[name] {
			return nil
		}
		seen[name] = true
		labelsBody, inspectErr := runBeforeDeadline("volume", "inspect", "--format", "{{json .Labels}}", name)
		if inspectErr != nil {
			if dockerObjectAbsent("volume", name, string(labelsBody), inspectErr.Error()) {
				return nil
			}
			return fmt.Errorf("inspect %s %s ownership: %s", description, name, volumeCommandError(labelsBody, inspectErr))
		}
		labels, err := parseRootVolumeLabels(labelsBody)
		if err != nil {
			return fmt.Errorf("inspect %s %s ownership labels: %w", description, name, err)
		}
		owned, reason := rootVolumeOwnedByApp(labels, app)
		if !owned {
			rootLog("destroy: keeping %s %s: %s", description, name, reason)
			return nil
		}
		targets = append(targets, ownedVolumeTarget{name: name, description: description})
		return nil
	}
	for _, name := range strings.Fields(string(body)) {
		if err := add(name, "owned volume"); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{app + "_redis_data", app + "_rabbitmq_data"} {
		if err := add(name, "owned infrastructure volume"); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func removeOwnedVolume(app, name, description string, run func(...string) ([]byte, error), deadline time.Time, now func() time.Time, sleep func(time.Duration)) error {
	runBeforeDeadline := func(args ...string) ([]byte, error) {
		if !now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		return run(args...)
	}
	labelsBody, inspectErr := runBeforeDeadline("volume", "inspect", "--format", "{{json .Labels}}", name)
	if inspectErr != nil {
		if dockerObjectAbsent("volume", name, string(labelsBody), inspectErr.Error()) {
			return nil
		}
		return fmt.Errorf("inspect %s %s ownership: %s", description, name, volumeCommandError(labelsBody, inspectErr))
	}
	labels, err := parseRootVolumeLabels(labelsBody)
	if err != nil {
		return fmt.Errorf("inspect %s %s ownership labels: %w", description, name, err)
	}
	owned, reason := rootVolumeOwnedByApp(labels, app)
	if !owned {
		rootLog("destroy: keeping %s %s: %s", description, name, reason)
		return nil
	}
	var lastOutput []byte
	var lastErr error
	for {
		if !now().Before(deadline) {
			return fmt.Errorf("remove %s %s: %s", description, name, volumeCommandError(lastOutput, lastErr))
		}
		output, removeErr := runBeforeDeadline("volume", "rm", name)
		if removeErr == nil || dockerObjectAbsent("volume", name, string(output), removeErr.Error()) {
			return nil
		}
		if !strings.Contains(strings.ToLower(string(output)), "volume is in use") {
			return fmt.Errorf("remove %s %s: %s", description, name, volumeCommandError(output, removeErr))
		}
		lastOutput, lastErr = output, removeErr
		sleep(500 * time.Millisecond)
	}
}

func rootVolumeOwnedByApp(labels map[string]string, app string) (bool, string) {
	stack, hasStack := labels["com.docker.stack.namespace"]
	owner, hasOwner := labels[shuttleOwnerLabel]
	if hasStack && stack != app {
		return false, fmt.Sprintf("conflicting stack namespace label %q", stack)
	}
	if hasOwner && owner != app {
		return false, fmt.Sprintf("conflicting Shuttle owner label %q", owner)
	}
	if hasStack || hasOwner {
		return true, ""
	}
	return false, "volume has no positive Shuttle ownership label"
}

func volumeCommandError(output []byte, err error) string {
	message := strings.TrimSpace(string(output))
	if message == "" && err != nil {
		message = err.Error()
	}
	return message
}

func parseRootVolumeLabels(body []byte) (map[string]string, error) {
	var labels map[string]string
	if err := json.Unmarshal(body, &labels); err != nil {
		return nil, err
	}
	return labels, nil
}

const (
	// v1 predated signed drop consent. Its readers reject unknown schemas, so
	// v2 prevents an older helper from replanning cleanup under its old rules.
	rootDestroyCleanupSchema   = "shuttle.destroy-cleanup/v2"
	rootDestroyCleanupMaxBytes = 128 << 10
)

// Keep cleanup records below a subdirectory so the coordinator's flat .json
// operation-record scan never mistakes one for a reservation.
var rootDestroyCleanupRoot = filepath.Join(coord.DefaultRoot, "destroy-cleanup")

var rootDestroyWriteJournal = writeDestroyCleanupJournalAt

type destroyOperationContextKey struct{}

type destroyCleanupProgress struct {
	ServicesRemoved             bool `json:"services_removed,omitempty"`
	ContainersGone              bool `json:"containers_gone,omitempty"`
	StackRemoved                bool `json:"stack_removed,omitempty"`
	NetworksGone                bool `json:"networks_gone,omitempty"`
	SecretsPrepared             bool `json:"secrets_prepared,omitempty"`
	SecretsRemoved              bool `json:"secrets_removed,omitempty"`
	VolumesRemoved              bool `json:"volumes_removed,omitempty"`
	VolumesPrepared             bool `json:"volumes_prepared,omitempty"`
	RouteRemoved                bool `json:"route_removed,omitempty"`
	RouteDirectorySynced        bool `json:"route_directory_synced,omitempty"`
	PostgresDropsPrepared       bool `json:"postgres_drops_prepared,omitempty"`
	PostgresDropsComplete       bool `json:"postgres_drops_complete,omitempty"`
	PostgresDropIntentsPrepared bool `json:"postgres_drop_intents_prepared,omitempty"`
	LedgerUpdated               bool `json:"ledger_updated,omitempty"`
	StateRemoved                bool `json:"state_removed,omitempty"`
	CredentialsPrepared         bool `json:"credentials_prepared,omitempty"`
	CredentialsRemoved          bool `json:"credentials_removed,omitempty"`
	CaddyReloaded               bool `json:"caddy_reloaded,omitempty"`
}

type destroyCleanupJournal struct {
	BackupGeneration        int               `json:"backup_generation,omitempty"`
	PostgresRemovalFailure  string            `json:"postgres_removal_failure,omitempty"`
	PostgresBackupsComplete bool              `json:"postgres_backups_complete,omitempty"`
	PostgresBackupFailure   string            `json:"postgres_backup_failure,omitempty"`
	BackupPaths             map[string]string `json:"backup_paths,omitempty"`
	// Only the verified signed remove plan initializes this consent. Recovery
	// uses the durable value; old journals without it keep PostgreSQL objects.
	DropDatabases            bool                   `json:"drop_databases,omitempty"`
	Schema                   string                 `json:"schema"`
	OperationID              string                 `json:"operation_id"`
	App                      string                 `json:"app"`
	DrainBoundNanos          int64                  `json:"drain_bound_ns"`
	DrainDeadline            string                 `json:"drain_deadline,omitempty"`
	Removal                  postgresRemoval        `json:"postgres_removal"`
	PostgresDropIntent       *postgresDropIntent    `json:"postgres_drop_intent,omitempty"`
	PendingDatabases         []string               `json:"pending_databases,omitempty"`
	PendingRoles             []string               `json:"pending_roles,omitempty"`
	PendingSecrets           []string               `json:"pending_secrets,omitempty"`
	PendingVolumes           []string               `json:"pending_volumes,omitempty"`
	PendingCredentialSecrets []string               `json:"pending_credential_secrets,omitempty"`
	PendingCredentialFiles   []string               `json:"pending_credential_files,omitempty"`
	PendingRoutes            []string               `json:"pending_routes,omitempty"`
	Progress                 destroyCleanupProgress `json:"progress"`
}

type postgresDropIntent struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	OID  string `json:"oid"`
}

func destroyCleanupJournalPath(root, operationID string) (string, error) {
	if root == "" || operationID == "" {
		return "", errors.New("destroy cleanup journal identity is invalid")
	}
	digest := strings.TrimPrefix(rootRecoveryDigest([]byte(operationID)), "sha256:")
	return filepath.Join(root, "destroy-cleanup-"+digest+".json"), nil
}

func validateDestroyCleanupJournal(journal destroyCleanupJournal, operationID, app string) error {
	if (journal.Schema != rootDestroyCleanupSchema && journal.Schema != "shuttle.destroy-cleanup/v1") || journal.OperationID != operationID || journal.App != app ||
		journal.DrainBoundNanos < int64(30*time.Second) || journal.DrainBoundNanos > int64(destroyDrainCeiling) {
		return errors.New("destroy cleanup journal does not match the operation")
	}
	for name, path := range journal.BackupPaths {
		legacy := filepath.Join(destroyBackupRoot, app, operationID+"-"+name+".dump")
		generation := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), operationID+"-"), "-"+name+".dump")
		n, parseErr := strconv.Atoi(generation)
		generated := parseErr == nil && n > 0 && n <= journal.BackupGeneration && path == filepath.Join(destroyBackupRoot, app, fmt.Sprintf("%s-%d-%s.dump", operationID, n, name))
		if validManagedDatabaseName(name) != nil || (path != legacy && !generated) {
			return errors.New("destroy cleanup journal contains an invalid backup path")
		}
	}
	for _, name := range append(append([]string(nil), journal.Removal.Databases...), journal.Removal.Roles...) {
		if err := validManagedDatabaseName(name); err != nil {
			return errors.New("destroy cleanup journal contains an invalid PostgreSQL name")
		}
	}
	for _, object := range journal.Removal.Kept {
		if (object.Kind != "database" && object.Kind != "role") || validManagedDatabaseName(object.Name) != nil {
			return errors.New("destroy cleanup journal contains an invalid kept PostgreSQL object")
		}
	}
	for _, name := range append(append([]string(nil), journal.PendingDatabases...), journal.PendingRoles...) {
		if err := validManagedDatabaseName(name); err != nil {
			return errors.New("destroy cleanup journal contains an invalid pending PostgreSQL name")
		}
	}
	if intent := journal.PostgresDropIntent; intent != nil {
		if !journal.Progress.PostgresDropIntentsPrepared {
			return errors.New("destroy cleanup journal contains a PostgreSQL drop intent without identity tracking")
		}
		pending := journal.PendingDatabases
		if intent.Kind == "role" {
			pending = journal.PendingRoles
		} else if intent.Kind != "database" {
			return errors.New("destroy cleanup journal contains an invalid PostgreSQL drop intent")
		}
		oid, oidErr := strconv.ParseUint(intent.OID, 10, 32)
		if validManagedDatabaseName(intent.Name) != nil || oidErr != nil || oid == 0 || strconv.FormatUint(oid, 10) != intent.OID || !slices.Contains(pending, intent.Name) {
			return errors.New("destroy cleanup journal contains an invalid PostgreSQL drop intent")
		}
	}
	for _, name := range append(append(append([]string(nil), journal.PendingSecrets...), journal.PendingCredentialSecrets...), journal.PendingVolumes...) {
		if !destroyPendingDockerName.MatchString(name) {
			return errors.New("destroy cleanup journal contains an invalid pending Docker object name")
		}
	}
	for _, name := range journal.PendingCredentialFiles {
		if filepath.Base(name) != name || name == "." || name == ".." || strings.IndexByte(name, 0) >= 0 {
			return errors.New("destroy cleanup journal contains an invalid credential filename")
		}
	}
	for _, name := range journal.PendingRoutes {
		if name != "50-"+app+".caddy" {
			return errors.New("destroy cleanup journal contains an invalid Caddy route")
		}
	}
	if journal.DrainDeadline != "" {
		if _, err := time.Parse(time.RFC3339Nano, journal.DrainDeadline); err != nil {
			return errors.New("destroy cleanup journal has an invalid drain deadline")
		}
	}
	return nil
}

var destroyPendingDockerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

func readDestroyCleanupJournalAt(root, operationID, app string) (*destroyCleanupJournal, []byte, error) {
	path, err := destroyCleanupJournalPath(root, operationID)
	if err != nil {
		return nil, nil, err
	}
	body, err := readAnchoredBoundedFile(root, path, rootDestroyCleanupMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var journal destroyCleanupJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, nil, err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("destroy cleanup journal contains trailing JSON")
	}
	if err := validateDestroyCleanupJournal(journal, operationID, app); err != nil {
		return nil, nil, err
	}
	return &journal, body, nil
}

func writeDestroyCleanupJournalAt(root string, journal destroyCleanupJournal) error {
	if err := validateDestroyCleanupJournal(journal, journal.OperationID, journal.App); err != nil {
		return err
	}
	// Accept retained v1 evidence, but never write consent under its old schema
	// again, including when recovery persists progress on a v1 journal.
	journal.Schema = rootDestroyCleanupSchema
	path, err := destroyCleanupJournalPath(root, journal.OperationID)
	if err != nil {
		return err
	}
	if err := refuseSymlinkAncestors(filepath.Dir(root)); err != nil {
		return fmt.Errorf("check destroy cleanup journal parent: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create destroy cleanup journal directory: %w", err)
	}
	if err := refuseSymlinkAncestors(root); err != nil {
		return fmt.Errorf("check destroy cleanup journal path: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("destroy cleanup journal directory is not a private directory")
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if len(body)+1 > rootDestroyCleanupMaxBytes {
		return errors.New("destroy cleanup journal exceeds the size limit")
	}
	return writeRootFile(path, append(body, '\n'), 0o600)
}

func removeDestroyCleanupJournalAt(root, operationID string) error {
	path, err := destroyCleanupJournalPath(root, operationID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncRootFileDirectory(root)
}

// Preview deliberately bypasses the mutating coordinator and journal writer.
// Its only host commands are discovery and PostgreSQL size/existence queries.
var rootDestroyPreview = func(operation rootplan.StackOperation, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), rootHelperOperationMargin)
	defer cancel()
	removal, err := planPostgresRemovalWithContext(ctx, rootAppStateRoot, operation.App)
	if err != nil {
		return err
	}
	run := func(args ...string) ([]byte, error) {
		return runRootSubprocessOutput(ctx, "/usr/bin/docker", args...)
	}
	return previewDestroyResources(ctx, rootAppStateRoot, rootSecretRoot, operation.App, operation.DropDatabases, removal, out, run, preRunDatabaseSize)
}

func previewDestroyResources(ctx context.Context, stateRoot, secretRoot, app string, drop bool, removal postgresRemoval, out io.Writer, run func(...string) ([]byte, error), size func(context.Context, string) (int64, error)) error {
	removal = postgresRemovalWithConsent(removal, drop)
	if err := reportDestroyPostgres(ctx, removal, out, size); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "would remove stack %s\nwould remove route /opt/shuttle/caddy/conf.d/50-%s.caddy\n", app, app); err != nil {
		return err
	}
	volumes, err := discoverOwnedVolumes(app, run, time.Now().Add(rootHelperOperationMargin), time.Now)
	if err != nil {
		return err
	}
	for _, volume := range volumes {
		if _, err := fmt.Fprintf(out, "would remove volume %s\n", volume.name); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(filepath.Join(stateRoot, app))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		action := "would remove"
		if !drop && entry.Name() == "postgres.json" {
			action = "kept"
		}
		if _, err := fmt.Fprintf(out, "%s state %s\n", action, filepath.Join(stateRoot, app, entry.Name())); err != nil {
			return err
		}
	}
	body, err := run("secret", "ls", "--filter", "label="+shuttleOwnerLabel+"="+app, "--format", "{{.Name}}")
	if err != nil {
		return fmt.Errorf("list owned secrets: %w", err)
	}
	secrets := append(strings.Fields(string(body)), app+"_redis_password_v1", app+"_rabbitmq_password_v1", app+"_postgres_password_v1")
	secrets = append(secrets, removal.Secrets...)
	selection := postgresCredentialsToKeep(app, removal, nil, postgresLedger{})
	secrets = append(secrets, selection.DockerSecrets...)
	slices.Sort(secrets)
	for _, name := range slices.Compact(secrets) {
		// Inspect only identity, never a secret's payload.
		body, err := run("secret", "inspect", "--format", "{{.Spec.Name}}", name)
		if err != nil {
			if dockerObjectAbsent("secret", name, string(body), err.Error()) {
				continue
			}
			return fmt.Errorf("inspect secret %s: %w", name, err)
		}
		action := "would remove"
		if slices.Contains(selection.DockerSecrets, name) {
			action = "kept"
		}
		if _, err := fmt.Fprintf(out, "%s secret %s\n", action, name); err != nil {
			return err
		}
	}
	entries, err = os.ReadDir(filepath.Join(secretRoot, app))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		action := "would remove"
		if slices.Contains(selection.Files, entry.Name()) {
			action = "kept"
		}
		if _, err := fmt.Fprintf(out, "%s credential file %s\n", action, filepath.Join(secretRoot, app, entry.Name())); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(out, "dry-run: no resources or state changed; roles and credentials may be kept if database removal fails")
	return err
}

func removeRootStack(app, operationID string, out io.Writer) error {
	return removeRootStackWithConsent(app, operationID, nil, out)
}

type destroyHostRuntime struct {
	stateRoot, secretRoot, caddyRoot string
	docker                           func(context.Context, ...string) ([]byte, error)
	oid                              func(context.Context, string, string) (string, bool, error)
	drop                             func(context.Context, string, ...string) error
	reload                           func(time.Time) error
}

var rootDestroyHost = func() destroyHostRuntime {
	return destroyHostRuntime{
		stateRoot: rootAppStateRoot, secretRoot: rootSecretRoot, caddyRoot: "/opt/shuttle/caddy/conf.d",
		docker: func(ctx context.Context, args ...string) ([]byte, error) {
			command := exec.CommandContext(ctx, "/usr/bin/docker", args...)
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			return command.CombinedOutput()
		},
		oid: postgresObjectOIDContext, drop: runDestroyFixed,
		reload: func(deadline time.Time) error {
			return withRootSharedResources(func() error { return reloadSharedCaddyUntil(deadline) })
		},
	}
}

func removeRootStackWithConsent(app, operationID string, consent *bool, out io.Writer) error {
	return removeRootStackWithRuntime(rootDestroyHost(), app, operationID, consent, out)
}

func removeRootStackAt(stateRoot, app, operationID string, consent *bool, out io.Writer, runDocker func(context.Context, ...string) ([]byte, error)) error {
	runtime := rootDestroyHost()
	runtime.stateRoot, runtime.docker = stateRoot, runDocker
	return removeRootStackWithRuntime(runtime, app, operationID, consent, out)
}

func removeRootStackWithRuntime(runtime destroyHostRuntime, app, operationID string, consent *bool, out io.Writer) error {
	stateRoot, runDocker := runtime.stateRoot, runtime.docker
	if !rootAppName.MatchString(app) || operationID == "" {
		return errors.New("destroy cleanup journal identity is invalid")
	}
	journal, _, err := readDestroyCleanupJournalAt(rootDestroyCleanupRoot, operationID, app)
	if err != nil {
		return fmt.Errorf("read destroy cleanup journal: %w", err)
	}
	if journal == nil && consent == nil {
		return errors.New("destroy recovery requires its original cleanup journal")
	}
	if journal != nil && len(journal.BackupPaths) > 0 && !journal.PostgresBackupsComplete && journal.PostgresBackupFailure == "" {
		// The dump can fail while the filesystem also refuses its failure
		// record. A durable start without completion must mean keep on recovery.
		journal.PostgresBackupFailure = "previous final dump was not confirmed complete"
	}
	if journal != nil && consent != nil && journal.DropDatabases != *consent {
		return errors.New("destroy database consent differs from the original signed operation; recover that operation first")
	}
	operationStarted := time.Now()
	rootWatchdogState.Lock()
	phaseDeadline := rootWatchdogState.deadline
	rootWatchdogState.Unlock()
	if phaseDeadline.IsZero() {
		phaseDeadline = operationStarted.Add(rootOperationBudget)
	}
	savedDrainBound := 30 * time.Second
	if journal != nil {
		savedDrainBound = time.Duration(journal.DrainBoundNanos)
	}
	activeParent, cancelActiveParent := context.WithDeadline(context.Background(), operationStarted.Add(rootHelperOperationMargin))
	defer func() { cancelActiveParent() }()
	var commandDeadline time.Time
	drainRun := destroyDeadlineRunnerWithParent(func() context.Context { return activeParent }, func() time.Time { return commandDeadline }, runDocker)
	if journal == nil {
		journal = &destroyCleanupJournal{
			Schema: rootDestroyCleanupSchema, OperationID: operationID, App: app, DropDatabases: *consent,
			DrainBoundNanos: int64(savedDrainBound),
			DrainDeadline:   operationStarted.Add(rootHelperOperationMargin).UTC().Format(time.RFC3339Nano),
			PendingRoutes:   []string{"50-" + app + ".caddy"},
		}
		removal, planErr := planPostgresRemovalWithContext(activeParent, stateRoot, app)
		if planErr != nil {
			return coord.KnownOutcome(fmt.Errorf("destroy refused before mutation: %w", planErr))
		}
		removal = postgresRemovalWithConsent(removal, journal.DropDatabases)
		journal.Removal = removal
		journal.PendingDatabases, journal.PendingRoles = append([]string(nil), removal.Databases...), append([]string(nil), removal.Roles...)
		journal.Progress.PostgresDropsPrepared = true
		if len(removal.Databases) > 0 {
			existing := make([]string, 0, len(removal.Databases))
			for _, name := range removal.Databases {
				exists, err := preRunDatabaseExists(activeParent, name)
				if err != nil {
					return coord.KnownOutcome(fmt.Errorf("destroy refused before mutation: %w", err))
				}
				if exists {
					existing = append(existing, name)
				}
			}
			if err := checkPreRunBackupCapacity(activeParent, filepath.Dir(destroyBackupRoot), app, existing, preRunDumpDeadline); err != nil {
				return coord.KnownOutcome(fmt.Errorf("destroy refused before mutation: %w", err))
			}
		}
		if err := rootDestroyWriteJournal(rootDestroyCleanupRoot, *journal); err != nil {
			return fmt.Errorf("journal destroy discovery deadline before commands: %w", err)
		}
	}
	commandDeadline = operationStarted.Add(rootHelperOperationMargin)
	persist := func() error { return rootDestroyWriteJournal(rootDestroyCleanupRoot, *journal) }
	mark := func(update func(*destroyCleanupProgress)) error {
		update(&journal.Progress)
		return persist()
	}
	// The 30-10-2026 demo-prod incident showed an interrupted cleanup could
	// repeat PostgreSQL drops from its original snapshot. Persist discovery's
	// deadline before planning or service inspection, then journal each object's
	// completion before moving to another removal step. Discovery uses the
	// helper-operation margin; the drain receives its own grace-based deadline.
	journal.DrainDeadline = commandDeadline.UTC().Format(time.RFC3339Nano)
	if err := persist(); err != nil {
		return fmt.Errorf("persist destroy discovery deadline: %w", err)
	}
	if !journal.DropDatabases || journal.PostgresBackupFailure != "" || journal.PostgresRemovalFailure != "" {
		if err := pruneCompletedDestroyPostgresOwnership(stateRoot, app, journal); err != nil {
			return err
		}
		previouslyKept := len(journal.Removal.Kept)
		journal.Removal = postgresRemovalWithConsent(destroyPendingPostgresRemoval(journal), false)
		if journal.PostgresBackupFailure != "" || journal.PostgresRemovalFailure != "" {
			for i := previouslyKept; i < len(journal.Removal.Kept); i++ {
				journal.Removal.Kept[i].Reason = "previous PostgreSQL cleanup failed; retained for a new destroy"
			}
		}
		journal.PendingDatabases, journal.PendingRoles = nil, nil
		journal.PostgresDropIntent = nil
		// A legacy journal may have prepared credential deletion before the
		// upgrade. Recompute it now that its databases and roles are kept.
		journal.PendingCredentialSecrets, journal.PendingCredentialFiles = nil, nil
		journal.Progress.CredentialsPrepared = false
		journal.Progress.CredentialsRemoved = false
		if err := persist(); err != nil {
			return err
		}
	}
	if err := prepareDestroyPostgresDropTracking(journal, persist); err != nil {
		return fmt.Errorf("prepare PostgreSQL drop identity tracking: %w", err)
	}
	if !journal.Progress.PostgresDropsPrepared {
		if journal.Progress.PostgresDropsComplete {
			journal.PendingDatabases = nil
			journal.PendingRoles = nil
			journal.Progress.PostgresDropsPrepared = true
		} else if !journal.Progress.RouteRemoved {
			// Older cleanup records predate per-object progress. A record that has
			// not reached route removal cannot have started PostgreSQL drops, so its
			// ownership ledger can be planned again. Once route removal was
			// recorded, an old partial outcome is ambiguous; replaying it could
			// drop a newly created same-name database.
			ctx, cancel := destroyDeadlineContext(activeParent, commandDeadline)
			removal, planErr := planPostgresRemovalWithContext(ctx, stateRoot, app)
			cancel()
			if planErr != nil {
				return fmt.Errorf("plan PostgreSQL removal: %w", planErr)
			}
			removal = postgresRemovalWithConsent(removal, journal.DropDatabases)
			journal.Removal = removal
			journal.PendingDatabases = append([]string(nil), removal.Databases...)
			journal.PendingRoles = append([]string(nil), removal.Roles...)
			journal.Progress.PostgresDropsPrepared = true
		} else if len(journal.Removal.Databases)+len(journal.Removal.Roles) == 0 {
			journal.Progress.PostgresDropsPrepared = true
		} else {
			return errors.New("destroy cleanup journal lacks per-object PostgreSQL progress; refusing to repeat an uncertain drop")
		}
		if err := persist(); err != nil {
			return fmt.Errorf("journal pending PostgreSQL objects: %w", err)
		}
	}
	removal := journal.Removal
	if err := reportDestroyPostgres(activeParent, destroyPendingPostgresRemoval(journal), out, preRunDatabaseSize); err != nil {
		return err
	}
	if len(journal.PendingRoutes) == 0 && !journal.Progress.RouteDirectorySynced {
		journal.PendingRoutes = []string{"50-" + app + ".caddy"}
		if err := persist(); err != nil {
			return fmt.Errorf("journal pending Caddy route: %w", err)
		}
	}
	var drainDeadline time.Time
	if !journal.Progress.ServicesRemoved || !journal.Progress.ContainersGone {
		discoveryDeadlinePersisted := false
		drainDeadline, err = drainRootStackBeforeRemovalWithStartedAt(
			app, drainRun, time.Now, time.Sleep, operationStarted, savedDrainBound,
			func(bound time.Duration, deadline time.Time) error {
				if !discoveryDeadlinePersisted {
					discoveryDeadlinePersisted = true
					journal.DrainBoundNanos = int64(bound)
					journal.DrainDeadline = deadline.UTC().Format(time.RFC3339Nano)
					commandDeadline = deadline
					return persist()
				}
				journal.DrainBoundNanos = int64(bound)
				journal.DrainDeadline = deadline.UTC().Format(time.RFC3339Nano)
				commandDeadline = deadline
				cancelActiveParent()
				// The deferred closure cancels whichever context is current; the
				// named cancel keeps go vet's lostcancel check satisfied.
				rearmedParent, rearmCancel := context.WithTimeout(context.Background(), destroyDrainCeiling+30*time.Second)
				activeParent, cancelActiveParent = rearmedParent, rearmCancel
				return persist()
			},
		)
		if err != nil {
			return err
		}
		if err := mark(func(progress *destroyCleanupProgress) {
			progress.ServicesRemoved = true
			progress.ContainersGone = true
		}); err != nil {
			return fmt.Errorf("journal drained application containers: %w", err)
		}
	} else {
		bound := min(max(time.Duration(journal.DrainBoundNanos), 30*time.Second), destroyDrainCeiling)
		drainDeadline = operationStarted.Add(bound)
		journal.DrainBoundNanos = int64(bound)
		journal.DrainDeadline = drainDeadline.UTC().Format(time.RFC3339Nano)
		commandDeadline = drainDeadline
		cancelActiveParent()
		// The deferred closure cancels whichever context is current; the
		// named cancel keeps go vet's lostcancel check satisfied.
		rearmedParent, rearmCancel := context.WithTimeout(context.Background(), destroyDrainCeiling+30*time.Second)
		activeParent, cancelActiveParent = rearmedParent, rearmCancel
		if err := persist(); err != nil {
			return fmt.Errorf("persist resumed destroy deadline: %w", err)
		}
	}
	if !journal.Progress.StackRemoved {
		if output, err := drainRun("stack", "rm", app); err != nil && !strings.Contains(string(output), "Nothing found") {
			return fmt.Errorf("remove stack: %s", volumeCommandError(output, err))
		}
		if err := mark(func(progress *destroyCleanupProgress) { progress.StackRemoved = true }); err != nil {
			return fmt.Errorf("journal removed application stack: %w", err)
		}
	}
	if !journal.Progress.NetworksGone {
		for {
			body, err := drainRun("service", "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", "{{.ID}}")
			if err != nil {
				return fmt.Errorf("inspect stack removal: %s", volumeCommandError(body, err))
			}
			networkBody, networkErr := drainRun("network", "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", "{{.ID}}")
			if networkErr != nil {
				return fmt.Errorf("inspect owned network removal: %s", volumeCommandError(networkBody, networkErr))
			}
			if strings.TrimSpace(string(body)) == "" && strings.TrimSpace(string(networkBody)) == "" {
				break
			}
			if !time.Now().Before(drainDeadline) {
				return errors.New("stack service/network removal did not converge within the destroy deadline")
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err := mark(func(progress *destroyCleanupProgress) { progress.NetworksGone = true }); err != nil {
			return fmt.Errorf("journal removed application networks: %w", err)
		}
	}
	// The drain has stopped application writers. Only now take the final
	// snapshot; a pre-drain snapshot silently omitted writes during shutdown.
	if journal.DropDatabases && journal.PostgresBackupFailure == "" && len(journal.PendingDatabases) > 0 {
		// Each generation consumes additional disk, including recovery after a
		// successful earlier dump. Recheck after drain before creating any file.
		backupLimit := phaseDeadline.Add(-rootHelperOperationMargin)
		backupCtx, cancelBackup := context.WithDeadline(context.Background(), backupLimit)
		existing := make([]string, 0, len(journal.PendingDatabases))
		var backupErr error
		for _, name := range journal.PendingDatabases {
			var exists bool
			exists, backupErr = preRunDatabaseExists(backupCtx, name)
			if backupErr != nil {
				break
			}
			if exists {
				existing = append(existing, name)
			}
		}
		if backupErr == nil {
			backupErr = checkPreRunBackupCapacity(backupCtx, filepath.Dir(destroyBackupRoot), app, existing, time.Until(backupLimit))
		}
		var dumpBudget time.Duration
		if backupErr == nil {
			dumpBudget, backupErr = destroyDumpBudget(backupCtx, existing, time.Until(backupLimit))
		}
		if backupErr == nil {
			journal.BackupPaths = planDestroyBackupPaths(journal)
			journal.BackupGeneration++
			journal.PostgresBackupsComplete = false
			if err := persist(); err != nil {
				cancelBackup()
				return err
			}
			dumpCtx, cancelDump := context.WithTimeout(backupCtx, dumpBudget)
			backupErr = backupDestroyDatabasesAt(dumpCtx, app, journal.PendingDatabases, journal.BackupPaths, out)
			cancelDump()
		}
		cancelBackup()
		// Discovery, drain, dumps and cleanup share the phase watchdog. Keep
		// two minutes for settlement and leave thirty seconds for its final
		// journal/writer close, instead of adding five minutes after the dump.
		cancelActiveParent()
		drainDeadline = phaseDeadline.Add(-30 * time.Second)
		commandDeadline = drainDeadline
		rearmed, rearmCancel := context.WithDeadline(context.Background(), drainDeadline)
		activeParent, cancelActiveParent = rearmed, rearmCancel
		if backupErr == nil {
			journal.PostgresBackupsComplete = true
			if err := persist(); err != nil {
				return err
			}
		}
		if backupErr != nil {
			// Persist the keep decision before continuing: recovery must never
			// turn a failed final dump back into permission to drop the database.
			journal.PostgresBackupFailure = cleanRootRefusalReason(backupErr.Error())
			if err := pruneCompletedDestroyPostgresOwnership(stateRoot, app, journal); err != nil {
				return err
			}
			previouslyKept := len(journal.Removal.Kept)
			journal.Removal = postgresRemovalWithConsent(destroyPendingPostgresRemoval(journal), false)
			for i := previouslyKept; i < len(journal.Removal.Kept); i++ {
				journal.Removal.Kept[i].Reason = "final dump failed; retained for a new destroy"
			}
			journal.PendingDatabases, journal.PendingRoles = nil, nil
			journal.PostgresDropIntent = nil
			journal.PendingCredentialSecrets, journal.PendingCredentialFiles = nil, nil
			journal.Progress.CredentialsPrepared, journal.Progress.CredentialsRemoved = false, false
			if err := persist(); err != nil {
				return err
			}
			removal = journal.Removal
			if err := reportDestroyPostgres(activeParent, removal, out, preRunDatabaseSize); err != nil {
				return err
			}
		}
	}
	if !journal.Progress.SecretsRemoved {
		if !journal.Progress.SecretsPrepared {
			owned := []string{app + "_redis_password_v1", app + "_rabbitmq_password_v1"}
			owned = append(owned, removal.Secrets...)
			// Application secrets carry a version in their name, so removal cannot
			// enumerate them: it asks Docker which secrets this application owns.
			labelledBody, err := drainRun("secret", "ls", "--filter", "label="+shuttleOwnerLabel+"="+app, "--format", "{{.Name}}")
			if err != nil {
				return fmt.Errorf("list owned secrets: %s", volumeCommandError(labelledBody, err))
			}
			owned = append(owned, strings.Fields(string(labelledBody))...)
			owned = filterPostgresSecretsFromOwned(owned, app, removal)
			slices.Sort(owned)
			journal.PendingSecrets = slices.Compact(owned)
			if err := mark(func(progress *destroyCleanupProgress) { progress.SecretsPrepared = true }); err != nil {
				return fmt.Errorf("journal pending application secrets: %w", err)
			}
		}
		for _, name := range append([]string(nil), journal.PendingSecrets...) {
			output, inspectErr := drainRun("secret", "inspect", name)
			if inspectErr != nil && !dockerObjectAbsent("secret", name, string(output), inspectErr.Error()) {
				return fmt.Errorf("inspect owned secret %s: %s", name, volumeCommandError(output, inspectErr))
			}
			if inspectErr == nil {
				output, err := drainRun("secret", "rm", name)
				if err != nil && !dockerObjectAbsent("secret", name, string(output), err.Error()) {
					return fmt.Errorf("remove owned secret %s: %s", name, volumeCommandError(output, err))
				}
			}
			journal.PendingSecrets = removeDestroyPendingItem(journal.PendingSecrets, name)
			if err := persist(); err != nil {
				return fmt.Errorf("journal removed application secret %s: %w", name, err)
			}
		}
		if err := mark(func(progress *destroyCleanupProgress) { progress.SecretsRemoved = true }); err != nil {
			return fmt.Errorf("journal removed application secrets: %w", err)
		}
	}
	if !journal.Progress.VolumesRemoved {
		if !journal.Progress.VolumesPrepared {
			targets, err := discoverOwnedVolumes(app, drainRun, drainDeadline, time.Now)
			if err != nil {
				return err
			}
			journal.PendingVolumes = make([]string, 0, len(targets))
			for _, target := range targets {
				journal.PendingVolumes = append(journal.PendingVolumes, target.name)
			}
			if err := mark(func(progress *destroyCleanupProgress) { progress.VolumesPrepared = true }); err != nil {
				return fmt.Errorf("journal pending application volumes: %w", err)
			}
		}
		if err := removePreparedDestroyVolumes(app, journal, drainRun, drainDeadline, time.Now, time.Sleep, persist); err != nil {
			return err
		}
		if err := mark(func(progress *destroyCleanupProgress) { progress.VolumesRemoved = true }); err != nil {
			return fmt.Errorf("journal removed application volumes: %w", err)
		}
	}
	routePath := filepath.Join(runtime.caddyRoot, "50-"+app+".caddy")
	if len(journal.PendingRoutes) > 0 && journal.Progress.CaddyReloaded {
		journal.Progress.CaddyReloaded = false
		if err := persist(); err != nil {
			return fmt.Errorf("journal pending Caddy reload after route cleanup: %w", err)
		}
	}
	if journal.Progress.RouteDirectorySynced && len(journal.PendingRoutes) == 0 {
		if _, err := os.Lstat(routePath); err == nil {
			journal.PendingRoutes = []string{"50-" + app + ".caddy"}
			journal.Progress.RouteRemoved = false
			journal.Progress.RouteDirectorySynced = false
			journal.Progress.CaddyReloaded = false
			if err := persist(); err != nil {
				return fmt.Errorf("journal recreated application Caddy route: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect application Caddy route before cleanup: %w", err)
		}
	}
	if !journal.Progress.RouteDirectorySynced || len(journal.PendingRoutes) > 0 {
		if len(journal.PendingRoutes) == 0 {
			journal.PendingRoutes = []string{"50-" + app + ".caddy"}
			if err := persist(); err != nil {
				return fmt.Errorf("journal pending Caddy route: %w", err)
			}
		}
		for _, name := range append([]string(nil), journal.PendingRoutes...) {
			if name != "50-"+app+".caddy" {
				return errors.New("destroy cleanup journal contains an invalid Caddy route")
			}
			routePath := filepath.Join(runtime.caddyRoot, name)
			if err := completeDestroyRouteRemoval(journal, name, routePath, persist); err != nil {
				return fmt.Errorf("sync Caddy route directory after removal: %w", err)
			}
		}
	}
	if !journal.Progress.PostgresDropsComplete || !journal.Progress.LedgerUpdated || !journal.Progress.StateRemoved || !journal.Progress.CredentialsRemoved {
		work := destroyPendingPostgresRemoval(journal)
		var progressErr error
		lines, postgresErr := applyPostgresRemovalSteps(app, work, postgresRemovalSteps{
			drop: func(kind, name string) error {
				if progressErr != nil {
					return progressErr
				}
				binary := "/usr/bin/dropdb"
				if kind == "role" {
					binary = "/usr/bin/dropuser"
				}
				var dropped bool
				err := applyDestroyPostgresDrop(
					journal,
					kind,
					name,
					func(kind, name string) (string, bool, error) {
						ctx, cancel := destroyDeadlineContext(activeParent, commandDeadline)
						defer cancel()
						return runtime.oid(ctx, kind, name)
					},
					func() error {
						ctx, cancel := destroyDeadlineContext(activeParent, commandDeadline)
						defer cancel()
						if err := runtime.drop(ctx, "/usr/sbin/runuser", "-u", "postgres", "--", binary, "--if-exists", name); err != nil {
							return err
						}
						dropped = true
						return nil
					},
					persist,
					func(line string) {
						fmt.Fprintln(out, line)
						rootLog("%s", line)
					},
				)
				if errors.Is(err, errDestroyJournalProgress) || (err != nil && journal.PostgresDropIntent != nil) {
					// An uncertain command must retain its OID intent. Do not let
					// remainder settlement erase it or attempt another object.
					progressErr = err
				}
				if err != nil {
					return err
				}
				if dropped {
					rootLog("destroy: PostgreSQL %s %s dropped", kind, name)
				}
				return nil
			},
			settleWithheld: func(withheld []string) error {
				if progressErr != nil {
					return progressErr
				}
				return settleWithheldDestroyPostgresRoles(journal, withheld, persist)
			},
			writeOrClearLedger: func(remainder postgresLedger) error {
				if progressErr != nil {
					return progressErr
				}
				if journal.DropDatabases && journal.PostgresBackupFailure == "" && journal.PostgresRemovalFailure == "" {
					if err := writeOrClearPostgresLedger(stateRoot, app, remainder); err != nil {
						return err
					}
				}
				if len(remainder.Databases)+len(remainder.Roles) > 0 {
					// A refused drop leaves owned data, not unfinished host cleanup.
					// Keep its ledger and credentials, then permit the normal retry
					// advertised to the operator once the rest of destroy is settled.
					journal.PostgresRemovalFailure = "PostgreSQL objects could not be removed"
					kept := postgresRemovalWithConsent(postgresRemoval{Databases: remainder.Databases, Roles: remainder.Roles}, false)
					for i := range kept.Kept {
						kept.Kept[i].Reason = "could not be removed; retained for a new destroy"
					}
					journal.Removal.Kept = append(journal.Removal.Kept, kept.Kept...)
					journal.Removal.Databases, journal.Removal.Roles = nil, nil
					journal.PendingDatabases, journal.PendingRoles = nil, nil
					journal.PostgresDropIntent = nil
				}
				journal.Progress.PostgresDropsComplete = destroyPostgresDropsComplete(journal, remainder) || journal.PostgresRemovalFailure != ""
				journal.Progress.LedgerUpdated = true
				if err := persist(); err != nil {
					return fmt.Errorf("journal PostgreSQL drop result and ledger: %w", err)
				}
				return nil
			},
			removeState: func(hasRemainder bool) error {
				if !journal.DropDatabases || journal.PostgresBackupFailure != "" || journal.PostgresRemovalFailure != "" {
					// Keeping data must also keep its ownership proof for a later
					// explicitly authorized destroy, without leaving recovery pending.
					// Without a ledger there is no PostgreSQL remainder. Keeping an
					// empty app directory made image sweeps retain its namespace.
					_, ledgerErr := os.Lstat(postgresLedgerPath(stateRoot, app))
					if ledgerErr != nil && !os.IsNotExist(ledgerErr) {
						return ledgerErr
					}
					if err := removePostgresAppState(stateRoot, app, ledgerErr == nil); err != nil {
						return err
					}
					return mark(func(progress *destroyCleanupProgress) { progress.StateRemoved = true })
				}
				if hasRemainder {
					if err := removePostgresAppState(stateRoot, app, true); err != nil {
						return err
					}
					return mark(func(progress *destroyCleanupProgress) { progress.StateRemoved = true })
				}
				if journal.Progress.StateRemoved {
					return nil
				}
				if err := removePostgresAppState(stateRoot, app, false); err != nil {
					return err
				}
				return mark(func(progress *destroyCleanupProgress) { progress.StateRemoved = true })
			},
			removeCredentials: func(removal postgresRemoval, withheld []string) error {
				if len(journal.PendingDatabases)+len(journal.PendingRoles) > 0 {
					return nil
				}
				if journal.Progress.CredentialsRemoved {
					return nil
				}
				if err := removePostgresAppCredentialsAt(stateRoot, runtime.secretRoot, app, journal.Removal, withheld, drainRun, journal, persist); err != nil {
					return err
				}
				return mark(func(progress *destroyCleanupProgress) { progress.CredentialsRemoved = true })
			},
		})
		for _, line := range lines {
			fmt.Fprintln(out, line)
			rootLog("%s", line)
		}
		if postgresErr != nil {
			return postgresErr
		}
		if len(journal.PendingDatabases)+len(journal.PendingRoles) != 0 {
			return errors.New("PostgreSQL removal remains pending; preserving the destroy cleanup journal")
		}
	}
	if !journal.Progress.CaddyReloaded {
		if err := runtime.reload(drainDeadline); err != nil {
			return err
		}
		if err := mark(func(progress *destroyCleanupProgress) { progress.CaddyReloaded = true }); err != nil {
			return fmt.Errorf("journal reloaded shared Caddy: %w", err)
		}
	}
	if err := removeCompletedDestroyCleanupJournalAt(rootDestroyCleanupRoot, operationID, journal); err != nil {
		return fmt.Errorf("remove completed destroy cleanup journal: %w", err)
	}
	if journal.PostgresRemovalFailure != "" {
		return coord.KnownOutcome(fmt.Errorf("destroy completed with PostgreSQL objects kept: %s; run shuttle destroy --drop-databases --yes again using the same app config", journal.PostgresRemovalFailure))
	}
	if journal.PostgresBackupFailure != "" {
		return coord.KnownOutcome(fmt.Errorf("destroy completed with PostgreSQL databases and roles kept: %s; run shuttle destroy --drop-databases --yes again using the same app config", journal.PostgresBackupFailure))
	}
	return nil
}

func removeDestroyRouteAndSync(routePath string) error {
	if err := os.Remove(routePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	directory := filepath.Dir(routePath)
	if err := syncRootFileDirectory(directory); err != nil {
		if os.IsNotExist(err) {
			if _, statErr := os.Stat(directory); os.IsNotExist(statErr) {
				return nil
			}
		}
		return err
	}
	return nil
}

func completeDestroyRouteRemoval(journal *destroyCleanupJournal, name, routePath string, persist func() error) error {
	if name != "50-"+journal.App+".caddy" || !slices.Contains(journal.PendingRoutes, name) {
		return errors.New("Caddy route is not pending in the destroy journal")
	}
	if err := removeDestroyRouteAndSync(routePath); err != nil {
		return err
	}
	journal.PendingRoutes = removeDestroyPendingItem(journal.PendingRoutes, name)
	journal.Progress.RouteRemoved = true
	journal.Progress.RouteDirectorySynced = true
	return persist()
}

func removeDestroyPendingItem(items []string, item string) []string {
	for i, candidate := range items {
		if candidate == item {
			return slices.Delete(items, i, i+1)
		}
	}
	return items
}

// The 30-10-2026 demo-prod incident showed that a best-effort PostgreSQL
// drop can leave durable work behind. The journal is removable only when every
// pending object and every cleanup phase has been settled.
func destroyCleanupSettled(journal *destroyCleanupJournal) bool {
	if journal == nil || journal.PostgresDropIntent != nil ||
		len(journal.PendingDatabases)+len(journal.PendingRoles)+len(journal.PendingSecrets)+len(journal.PendingVolumes)+
			len(journal.PendingCredentialSecrets)+len(journal.PendingCredentialFiles)+len(journal.PendingRoutes) != 0 {
		return false
	}
	p := journal.Progress
	return p.ServicesRemoved && p.ContainersGone && p.StackRemoved && p.NetworksGone &&
		p.SecretsPrepared && p.SecretsRemoved && p.VolumesPrepared && p.VolumesRemoved &&
		p.RouteRemoved && p.RouteDirectorySynced && p.PostgresDropsPrepared && p.PostgresDropIntentsPrepared &&
		p.PostgresDropsComplete && p.LedgerUpdated && p.StateRemoved &&
		p.CredentialsPrepared && p.CredentialsRemoved && p.CaddyReloaded
}

func prepareDestroyPostgresDropTracking(journal *destroyCleanupJournal, persist func() error) error {
	if journal == nil {
		return errors.New("destroy cleanup journal is missing")
	}
	if journal.Progress.PostgresDropIntentsPrepared {
		return nil
	}
	// The 30-10-2026 demo-prod incident showed that older journals cannot
	// distinguish a completed drop from a same-name replacement. Refuse that
	// ambiguous state instead of inventing an OID after the destructive command.
	if journal.Progress.PostgresDropsPrepared && journal.Progress.RouteRemoved &&
		len(journal.PendingDatabases)+len(journal.PendingRoles) != 0 {
		return errors.New("destroy cleanup journal lacks PostgreSQL drop identities for pending objects")
	}
	journal.Progress.PostgresDropIntentsPrepared = true
	if err := persist(); err != nil {
		return fmt.Errorf("%w: prepare PostgreSQL drop identity tracking: %v", errDestroyJournalProgress, err)
	}
	return nil
}

func destroyPostgresDropsComplete(journal *destroyCleanupJournal, remainder postgresLedger) bool {
	return journal != nil && journal.PostgresDropIntent == nil &&
		len(journal.PendingDatabases)+len(journal.PendingRoles) == 0 &&
		len(remainder.Databases)+len(remainder.Roles) == 0
}

func removeCompletedDestroyCleanupJournalAt(root, operationID string, journal *destroyCleanupJournal) error {
	if !destroyCleanupSettled(journal) {
		return errors.New("destroy cleanup journal still has pending work")
	}
	return removeDestroyCleanupJournalAt(root, operationID)
}

// A failed dump after a partial destroy used to discard the original removal
// snapshot while keeping its entire ledger. A later same-name database was then
// falsely owned. Prune only confirmed completions before converting the journal
// to kept objects, so any write failure leaves the durable completion proof for
// recovery. Pending, explicitly kept and unrelated ledger entries stay owned.
func pruneCompletedDestroyPostgresOwnership(stateRoot, app string, journal *destroyCleanupJournal) error {
	if !journal.DropDatabases || !journal.Progress.PostgresDropsPrepared || !journal.Progress.PostgresDropIntentsPrepared {
		return nil
	}
	ledger, err := readPostgresLedger(stateRoot, app)
	if err != nil {
		return fmt.Errorf("read PostgreSQL ledger before pruning completed destroy objects: %w", err)
	}
	completed := false
	for _, objects := range []struct {
		kind             string
		planned, pending []string
		owned            *[]string
	}{
		{"database", journal.Removal.Databases, journal.PendingDatabases, &ledger.Databases},
		{"role", journal.Removal.Roles, journal.PendingRoles, &ledger.Roles},
	} {
		for _, name := range objects.planned {
			if slices.Contains(objects.pending, name) || slices.ContainsFunc(journal.Removal.Kept, func(object keptPostgresObject) bool { return object.Kind == objects.kind && object.Name == name }) {
				continue
			}
			completed = true
			*objects.owned = removeDestroyPendingItem(*objects.owned, name)
		}
	}
	if !completed {
		return nil
	}
	// Repeat the write even if a previous rename already removed the names:
	// its directory sync may have failed while the journal still holds proof.
	if err := writeOrClearPostgresLedger(stateRoot, app, ledger); err != nil {
		return fmt.Errorf("prune completed PostgreSQL destroy ownership: %w", err)
	}
	if len(ledger.Databases)+len(ledger.Roles) == 0 {
		if err := syncRootFileDirectory(filepath.Join(stateRoot, app)); err != nil {
			return fmt.Errorf("sync pruned PostgreSQL destroy ledger: %w", err)
		}
	}
	return nil
}

func destroyPendingPostgresRemoval(journal *destroyCleanupJournal) postgresRemoval {
	work := journal.Removal
	if journal.Progress.PostgresDropsComplete {
		work.Databases = nil
		work.Roles = nil
		return work
	}
	work.Databases = append([]string(nil), journal.PendingDatabases...)
	work.Roles = append([]string(nil), journal.PendingRoles...)
	return work
}

func recordCompletedDestroyPostgresDrop(journal *destroyCleanupJournal, kind, name string, persist func() error) error {
	var pending *[]string
	switch kind {
	case "database":
		pending = &journal.PendingDatabases
	case "role":
		pending = &journal.PendingRoles
	default:
		return fmt.Errorf("unknown PostgreSQL destroy object kind %q", kind)
	}
	found := false
	for _, candidate := range *pending {
		if candidate == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("PostgreSQL %s %s is not pending in the destroy journal", kind, name)
	}
	if intent := journal.PostgresDropIntent; intent != nil && (intent.Kind != kind || intent.Name != name) {
		return errors.New("PostgreSQL drop completion does not match the journaled in-flight intent")
	}
	*pending = removeDestroyPendingItem(*pending, name)
	journal.PostgresDropIntent = nil
	if err := persist(); err != nil {
		return fmt.Errorf("%w: journal dropped PostgreSQL %s %s: %v", errDestroyJournalProgress, kind, name, err)
	}
	return nil
}

var errDestroyJournalProgress = errors.New("destroy journal progress could not be persisted")

func applyDestroyPostgresDrop(journal *destroyCleanupJournal, kind, name string, inspectOID func(string, string) (string, bool, error), drop func() error, persist func() error, report func(string)) error {
	if !journal.DropDatabases || journal.PostgresBackupFailure != "" || journal.PostgresRemovalFailure != "" || (len(journal.BackupPaths) > 0 && !journal.PostgresBackupsComplete) {
		return errors.New("PostgreSQL drop requires explicit signed --drop-databases consent and successful dumps")
	}
	pending := &journal.PendingDatabases
	if kind == "role" {
		pending = &journal.PendingRoles
	} else if kind != "database" {
		return fmt.Errorf("unknown PostgreSQL destroy object kind %q", kind)
	}
	if !slices.Contains(*pending, name) {
		return fmt.Errorf("PostgreSQL %s %s is not pending in the destroy journal", kind, name)
	}
	intent := journal.PostgresDropIntent
	if intent != nil && (intent.Kind != kind || intent.Name != name) {
		return errors.New("PostgreSQL drop does not match the journaled in-flight intent")
	}
	oid, exists, err := inspectOID(kind, name)
	if err != nil {
		return err
	}
	if !exists {
		return recordCompletedDestroyPostgresDrop(journal, kind, name, persist)
	}
	if intent != nil && intent.OID != oid {
		return recordRecreatedDestroyPostgresObject(journal, kind, name, oid, persist, report)
	}
	if intent == nil {
		journal.PostgresDropIntent = &postgresDropIntent{Kind: kind, Name: name, OID: oid}
		if err := persist(); err != nil {
			return fmt.Errorf("%w: journal PostgreSQL %s %s OID before drop: %v", errDestroyJournalProgress, kind, name, err)
		}
		// The 30-10-2026 demo-prod incident exposed the crash gap between an
		// external drop and its completion record. Recheck after the intent is
		// durable so a replacement observed before the command is kept.
		oid, exists, err = inspectOID(kind, name)
		if err != nil {
			return err
		}
		if !exists {
			return recordCompletedDestroyPostgresDrop(journal, kind, name, persist)
		}
		if journal.PostgresDropIntent.OID != oid {
			return recordRecreatedDestroyPostgresObject(journal, kind, name, oid, persist, report)
		}
	}
	if err := drop(); err != nil {
		// Exit 1 can mean the connection closed after DROP committed. Only a
		// fresh OID read proves refusal: absence is completion, the same OID
		// permits later databases, and a replacement or failed read retains
		// the original intent so recovery cannot drop a new same-name object.
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			afterOID, exists, inspectErr := inspectOID(kind, name)
			if inspectErr != nil {
				return errors.Join(err, inspectErr)
			}
			if !exists {
				return recordCompletedDestroyPostgresDrop(journal, kind, name, persist)
			}
			if afterOID != journal.PostgresDropIntent.OID {
				return err
			}
			journal.PostgresDropIntent = nil
			if persistErr := persist(); persistErr != nil {
				return fmt.Errorf("%w: journal refused PostgreSQL %s %s: %v", errDestroyJournalProgress, kind, name, persistErr)
			}
		}
		return err
	}
	return recordCompletedDestroyPostgresDrop(journal, kind, name, persist)
}

// settleWithheldDestroyPostgresRoles turns a role kept on purpose into a
// settled outcome. A role whose drop fails while a kept database still depends
// on it is preserved by design, but it stayed in PendingRoles with its drop
// intent, so every recovery answered "PostgreSQL removal remains pending" and
// the destroy could only finish after someone dropped a resource Shuttle had
// deliberately kept. Recording it in Removal.Kept also keeps its credentials on
// every later pass, since credential selection reads Removal.Kept.
func settleWithheldDestroyPostgresRoles(journal *destroyCleanupJournal, withheld []string, persist func() error) error {
	if journal == nil || len(withheld) == 0 {
		return nil
	}
	for _, role := range withheld {
		if !slices.Contains(journal.PendingRoles, role) {
			return fmt.Errorf("withheld PostgreSQL role %s is not pending in the destroy journal", role)
		}
		kept := false
		for _, object := range journal.Removal.Kept {
			if object.Kind == "role" && object.Name == role {
				kept = true
				break
			}
		}
		if !kept {
			journal.Removal.Kept = append(journal.Removal.Kept, keptPostgresObject{Kind: "role", Name: role, Reason: "drop failed while a kept database still depends on it"})
		}
		journal.PendingRoles = removeDestroyPendingItem(journal.PendingRoles, role)
		if intent := journal.PostgresDropIntent; intent != nil && intent.Kind == "role" && intent.Name == role {
			journal.PostgresDropIntent = nil
		}
	}
	sort.Slice(journal.Removal.Kept, func(i, j int) bool {
		if journal.Removal.Kept[i].Kind == journal.Removal.Kept[j].Kind {
			return journal.Removal.Kept[i].Name < journal.Removal.Kept[j].Name
		}
		return journal.Removal.Kept[i].Kind < journal.Removal.Kept[j].Kind
	})
	if err := persist(); err != nil {
		return fmt.Errorf("%w: journal withheld PostgreSQL roles: %v", errDestroyJournalProgress, err)
	}
	return nil
}

func recordRecreatedDestroyPostgresObject(journal *destroyCleanupJournal, kind, name, currentOID string, persist func() error, report func(string)) error {
	intent := journal.PostgresDropIntent
	if intent == nil || intent.Kind != kind || intent.Name != name || intent.OID == currentOID {
		return errors.New("recreated PostgreSQL object does not match the journaled OID change")
	}
	previousOID := intent.OID
	reason := fmt.Sprintf("recreated after an interrupted destroy; OID changed from %s to %s", previousOID, currentOID)
	kept := false
	for _, object := range journal.Removal.Kept {
		if object.Kind == kind && object.Name == name {
			kept = true
			break
		}
	}
	if !kept {
		journal.Removal.Kept = append(journal.Removal.Kept, keptPostgresObject{Kind: kind, Name: name, Reason: reason})
		sort.Slice(journal.Removal.Kept, func(i, j int) bool {
			if journal.Removal.Kept[i].Kind == journal.Removal.Kept[j].Kind {
				return journal.Removal.Kept[i].Name < journal.Removal.Kept[j].Name
			}
			return journal.Removal.Kept[i].Kind < journal.Removal.Kept[j].Kind
		})
	}
	pending := &journal.PendingDatabases
	if kind == "role" {
		pending = &journal.PendingRoles
	}
	*pending = removeDestroyPendingItem(*pending, name)
	journal.PostgresDropIntent = nil
	if err := persist(); err != nil {
		return fmt.Errorf("%w: journal recreated PostgreSQL %s %s: %v", errDestroyJournalProgress, kind, name, err)
	}
	if report != nil {
		report(fmt.Sprintf("kept PostgreSQL %s %s: %s", kind, name, reason))
	}
	return nil
}

func runDestroyFixed(ctx context.Context, name string, args ...string) error {
	output, err := runRootSubprocess(ctx, name, args...)
	if ctx.Err() != nil {
		return fmt.Errorf("%s timed out: %w", filepath.Base(name), ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", filepath.Base(name), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func removePostgresAppState(stateRoot, app string, hasRemainder bool) error {
	appRoot := filepath.Join(stateRoot, app)
	if !hasRemainder {
		return os.RemoveAll(appRoot)
	}
	entries, err := os.ReadDir(appRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "postgres.json" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(appRoot, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func removePostgresAppCredentials(app string, removal postgresRemoval, withheld []string, run func(...string) ([]byte, error), journal *destroyCleanupJournal, persist func() error) error {
	return removePostgresAppCredentialsAt(rootAppStateRoot, rootSecretRoot, app, removal, withheld, run, journal, persist)
}

func removePostgresAppCredentialsAt(stateRoot, secretsRoot, app string, removal postgresRemoval, withheld []string, run func(...string) ([]byte, error), journal *destroyCleanupJournal, persist func() error) error {
	remainder, err := readPostgresLedger(stateRoot, app)
	if err != nil {
		return err
	}
	selection := postgresCredentialsToKeep(app, removal, withheld, remainder)
	keepSecrets := make(map[string]bool, len(selection.DockerSecrets))
	for _, name := range selection.DockerSecrets {
		keepSecrets[name] = true
	}
	roles := map[string]bool{strings.ReplaceAll(app, "-", "_"): true}
	for _, role := range removal.Roles {
		roles[role] = true
	}
	for _, object := range removal.Kept {
		if object.Kind == "role" {
			roles[object.Name] = true
		}
	}
	for _, role := range withheld {
		roles[role] = true
	}
	secretNames := []string{app + "_postgres_password_v1"}
	secretNames = append(secretNames, removal.Secrets...)
	for role := range roles {
		if role != strings.ReplaceAll(app, "-", "_") {
			secretNames = append(secretNames, managedRoleSecretName(app, role))
		}
	}
	slices.Sort(secretNames)
	secretNames = slices.Compact(secretNames)
	secretNamesToRemove := make([]string, 0, len(secretNames))
	for _, name := range secretNames {
		if !keepSecrets[name] {
			secretNamesToRemove = append(secretNamesToRemove, name)
		}
	}
	secretRoot := filepath.Join(secretsRoot, app)
	entries, err := os.ReadDir(secretRoot)
	if os.IsNotExist(err) {
		entries = nil
	} else if err != nil {
		return err
	}
	keepFiles := make(map[string]bool, len(selection.Files))
	for _, name := range selection.Files {
		keepFiles[name] = true
	}
	if !journal.Progress.CredentialsPrepared {
		journal.PendingCredentialSecrets = secretNamesToRemove
		journal.PendingCredentialFiles = nil
		for _, entry := range entries {
			if !keepFiles[entry.Name()] {
				journal.PendingCredentialFiles = append(journal.PendingCredentialFiles, entry.Name())
			}
		}
		slices.Sort(journal.PendingCredentialFiles)
		journal.Progress.CredentialsPrepared = true
		if err := persist(); err != nil {
			return fmt.Errorf("journal pending PostgreSQL credentials: %w", err)
		}
	}
	for _, name := range append([]string(nil), journal.PendingCredentialSecrets...) {
		output, err := run("secret", "inspect", name)
		if err != nil {
			if dockerObjectAbsent("secret", name, string(output), err.Error()) {
				journal.PendingCredentialSecrets = removeDestroyPendingItem(journal.PendingCredentialSecrets, name)
				if err := persist(); err != nil {
					return fmt.Errorf("journal missing PostgreSQL credential secret %s: %w", name, err)
				}
				continue
			}
			return fmt.Errorf("inspect PostgreSQL credential secret %s: %s", name, volumeCommandError(output, err))
		}
		output, err = run("secret", "rm", name)
		if err != nil && !dockerObjectAbsent("secret", name, string(output), err.Error()) {
			return fmt.Errorf("remove PostgreSQL credential secret %s: %s", name, volumeCommandError(output, err))
		}
		journal.PendingCredentialSecrets = removeDestroyPendingItem(journal.PendingCredentialSecrets, name)
		if err := persist(); err != nil {
			return fmt.Errorf("journal removed PostgreSQL credential secret %s: %w", name, err)
		}
	}
	for _, name := range append([]string(nil), journal.PendingCredentialFiles...) {
		if filepath.Base(name) != name || name == "." || name == ".." {
			return errors.New("destroy cleanup journal contains an invalid credential filename")
		}
		if err := os.RemoveAll(filepath.Join(secretRoot, name)); err != nil {
			return err
		}
		journal.PendingCredentialFiles = removeDestroyPendingItem(journal.PendingCredentialFiles, name)
		if err := persist(); err != nil {
			return fmt.Errorf("journal removed PostgreSQL credential file %s: %w", name, err)
		}
	}
	if len(keepFiles) == 0 {
		if err := os.Remove(secretRoot); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTEMPTY) {
			return err
		}
	}
	return nil
}

type infrastructureVolume struct {
	name string
	uid  int
	gid  int
}

func infrastructureVolumes(app string, payload []byte, retainedStacks ...[]byte) ([]infrastructureVolume, error) {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, err
	}
	services, _ := document["services"].(map[string]any)
	var retainedServices map[string]any
	if len(retainedStacks) > 0 && len(retainedStacks[0]) > 0 {
		var retained map[string]any
		if err := yaml.Unmarshal(retainedStacks[0], &retained); err != nil {
			return nil, err
		}
		retainedServices, _ = retained["services"].(map[string]any)
	}
	volumes := []infrastructureVolume{}
	for _, candidate := range infrastructureRuntimes {
		raw, enabled := services[candidate.service]
		if !enabled {
			continue
		}
		service, ok := raw.(map[string]any)
		image := ""
		if ok {
			image = strings.TrimSpace(fmt.Sprint(service["image"]))
		}
		if !ok {
			return nil, fmt.Errorf("%s infrastructure image does not match the pinned runtime", candidate.service)
		}
		if image != candidate.image && !retainedInfrastructureImage(retainedServices, candidate.service, image) {
			if err := verifyInfrastructurePatchUpdate(candidate, retainedInfrastructureImageOf(retainedServices, candidate.service), image); err != nil {
				return nil, fmt.Errorf("%s infrastructure image does not match the pinned runtime: %w", candidate.service, err)
			}
		}
		// The ownership given to the volume below is only correct for the
		// account the container actually assumes, so the helper refuses a
		// payload that declares another one rather than chowning a directory
		// its service cannot open.
		if strings.TrimSpace(fmt.Sprint(service["user"])) != candidate.user() {
			return nil, fmt.Errorf("%s infrastructure service does not run as the account that owns its data", candidate.service)
		}
		expectedName := app + "_" + candidate.service + "_data"
		matched := false
		serviceVolumes, ok := service["volumes"].([]any)
		if !ok {
			return nil, fmt.Errorf("%s infrastructure volume definition is invalid", candidate.service)
		}
		for _, rawVolume := range serviceVolumes {
			source, target, valid := rootVolumeSourceTarget(rawVolume)
			if valid && source == expectedName && target == candidate.target {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("%s infrastructure volume does not match the owned data path", candidate.service)
		}
		volumes = append(volumes, infrastructureVolume{name: expectedName, uid: candidate.uid, gid: candidate.gid})
	}
	return volumes, nil
}

func retainedInfrastructureImage(services map[string]any, name, image string) bool {
	return image != "" && retainedInfrastructureImageOf(services, name) == image
}

func retainedInfrastructureImageOf(services map[string]any, name string) string {
	service, ok := services[name].(map[string]any)
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(service["image"]))
}

// officialInfrastructureImage is an official Docker Hub image named by an
// immutable digest. Without a registry or a namespace the name resolves to
// docker.io/library/<service>, where only the image maintainers publish, and
// the digest pins the exact content: the tag between the two is decoration.
var officialInfrastructureImage = regexp.MustCompile(`^(redis|rabbitmq|caddy|registry):([0-9][A-Za-z0-9._-]*)@sha256:[0-9a-f]{64}$`)

// infrastructureImageVersion pulls an image before reading the version proved
// by its configuration or server binary. Recovery uses the same reader without
// pulling, so an absent retained image still requires administrator action.
var infrastructureImageVersion = func(image, versionEnv string) (string, error) {
	if _, err := runFixedOutput(5*time.Minute, "/usr/bin/docker", "pull", "--quiet", image); err != nil {
		return "", err
	}
	return readInfrastructureImageVersion(context.Background(), rootDockerRead, image, versionEnv)
}

func readInfrastructureImageVersion(ctx context.Context, read infrastructureDockerRead, image, versionEnv string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	raw, err := read(ctx, "image", "inspect", "--format", "{{json .Config.Env}}", image)
	if err != nil {
		return "", fmt.Errorf("read the environment of %s (image must already be present on the host): %w", image, err)
	}
	var env []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &env); err != nil {
		return "", fmt.Errorf("read the environment of %s: %w", image, err)
	}
	return infrastructureVersionFromEnvironment(ctx, read, image, versionEnv, env)
}

func infrastructureVersionFromEnvironment(ctx context.Context, read infrastructureDockerRead, image, versionEnv string, env []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for _, entry := range env {
		if value, found := strings.CutPrefix(entry, versionEnv+"="); found {
			return value, nil
		}
	}
	// Redis 8 removed REDIS_VERSION from Config.Env. Probe only the fixed
	// server binary, bypassing the entrypoint and mounting no host data; a
	// tag cannot prove the version that will open the retained data volume.
	for _, runtime := range infrastructureRuntimes {
		if runtime.versionEnv != versionEnv || runtime.versionBinary == "" {
			continue
		}
		body, err := read(ctx, "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--user", runtime.user(), "--entrypoint", runtime.versionBinary, image, "--version")
		if err != nil {
			return "", fmt.Errorf("read the server version of %s: %w", image, err)
		}
		match := redisServerVersion.FindStringSubmatch(strings.TrimSpace(body))
		if match != nil {
			if _, ok := parseInfrastructureVersion(match[1]); ok {
				return match[1], nil
			}
		}
		return "", fmt.Errorf("%s returned an invalid server version", image)
	}
	return "", fmt.Errorf("%s does not declare %s", image, versionEnv)
}

var redisServerVersion = regexp.MustCompile(`^Redis server v=([0-9]+\.[0-9]+\.[0-9]+)(?: sha=[0-9a-f]+:[0-9]+ malloc=[A-Za-z0-9._-]+ bits=(?:32|64) build=[0-9a-f]+)?$`)

// verifyInfrastructurePatchUpdate accepts a newly resolved digest only when
// the image's own version confirms that the retained data remains compatible.
// Tags choose the retained major; image metadata catches a misleading tag and
// refuses a downgrade before the helper changes a stateful service.
func verifyInfrastructurePatchUpdate(runtime infrastructureRuntime, retained, image string) error {
	needsVersionCheck, err := infrastructureImageNeedsVersionCheck(runtime, retained, image)
	if err != nil {
		return err
	}
	if !needsVersionCheck {
		return nil
	}
	before, err := infrastructureImageVersion(retained, runtime.versionEnv)
	if err != nil {
		return fmt.Errorf("retained image version: %w", err)
	}
	after, err := infrastructureImageVersion(image, runtime.versionEnv)
	if err != nil {
		return fmt.Errorf("candidate image version: %w", err)
	}
	from, ok := parseInfrastructureVersion(before)
	if !ok {
		return fmt.Errorf("retained version %q is not a release version", before)
	}
	to, ok := parseInfrastructureVersion(after)
	if !ok {
		return fmt.Errorf("candidate version %q is not a release version", after)
	}
	if to[0] != from[0] {
		return fmt.Errorf("major change %s -> %s requires an explicit data migration", before, after)
	}
	if slices.Compare(to, from) < 0 {
		return fmt.Errorf("%s is older than the retained %s", after, before)
	}
	return nil
}

// infrastructureImageNeedsVersionCheck is the shared read-only decision used
// before a stack phase opens and again while preparing its infrastructure
// volumes. It accepts a signed official digest on a fresh host, and checks tag
// majors against the retained service before any pull.
func infrastructureImageNeedsVersionCheck(runtime infrastructureRuntime, retained, image string) (bool, error) {
	if retained == image {
		return false, nil
	}
	match := officialInfrastructureImage.FindStringSubmatch(image)
	if match == nil || match[1] != runtime.service {
		return false, fmt.Errorf("%s is not an official %s image pinned by digest", image, runtime.service)
	}
	if retained == "" {
		return false, nil
	}
	retainedMatch := officialInfrastructureImage.FindStringSubmatch(retained)
	if retainedMatch == nil || retainedMatch[1] != runtime.service {
		return false, fmt.Errorf("retained image %q is not an official %s image pinned by digest", retained, runtime.service)
	}
	oldMajor, newMajor := leadingMajor(retainedMatch[2]), leadingMajor(match[2])
	if oldMajor != "" && newMajor != "" {
		oldNumber, _ := strconv.Atoi(oldMajor)
		newNumber, _ := strconv.Atoi(newMajor)
		if newNumber < oldNumber {
			return false, fmt.Errorf("%s tag major %d is older than running major %d", runtime.service, newNumber, oldNumber)
		}
	}
	return true, nil
}

func validateInfrastructureImagesBeforeMutation(payload, retainedStack []byte) error {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return err
	}
	services, _ := document["services"].(map[string]any)
	var retainedServices map[string]any
	if len(retainedStack) > 0 {
		var retained map[string]any
		if err := yaml.Unmarshal(retainedStack, &retained); err != nil {
			return err
		}
		retainedServices, _ = retained["services"].(map[string]any)
	}
	for _, runtime := range infrastructureRuntimes {
		raw, enabled := services[runtime.service]
		if !enabled {
			continue
		}
		service, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s infrastructure image does not match the pinned runtime", runtime.service)
		}
		image := strings.TrimSpace(fmt.Sprint(service["image"]))
		retainedImage := retainedInfrastructureImageOf(retainedServices, runtime.service)
		_, err := infrastructureImageNeedsVersionCheck(runtime, retainedImage, image)
		if err != nil {
			return fmt.Errorf("%s infrastructure image does not match the pinned runtime: %w", runtime.service, err)
		}
	}
	return nil
}

// parseInfrastructureVersion reads MAJOR.MINOR[.PATCH]; anything else (a
// release candidate, a build suffix) is not a version this rule reasons about.
func parseInfrastructureVersion(value string) ([]int, bool) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, false
	}
	version := make([]int, 3)
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || strconv.Itoa(number) != part {
			return nil, false
		}
		version[index] = number
	}
	return version, true
}

func ensureInfrastructureVolumes(app string, payload []byte, retainedStacks ...[]byte) error {
	volumes, err := infrastructureVolumes(app, payload, retainedStacks...)
	if err != nil {
		return err
	}
	if len(volumes) == 0 {
		return nil
	}
	rootBody, err := exec.Command("/usr/bin/docker", "info", "--format", "{{.DockerRootDir}}").Output()
	if err != nil || strings.TrimSpace(string(rootBody)) == "" {
		return errors.New("inspect Docker root directory")
	}
	volumeRoot := filepath.Join(filepath.Clean(strings.TrimSpace(string(rootBody))), "volumes")
	for _, volume := range volumes {
		inspect := exec.Command("/usr/bin/docker", "volume", "inspect", volume.name)
		inspect.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		if inspect.Run() != nil {
			create := exec.Command("/usr/bin/docker", "volume", "create", "--label", "dev.shuttle.owner="+app, "--label", "com.docker.stack.namespace="+app, volume.name)
			create.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			if output, createErr := create.CombinedOutput(); createErr != nil {
				return fmt.Errorf("create owned infrastructure volume: %s", strings.TrimSpace(string(output)))
			}
		}
		mountBody, inspectErr := exec.Command("/usr/bin/docker", "volume", "inspect", "--format", "{{.Mountpoint}}", volume.name).Output()
		mountpoint := filepath.Clean(strings.TrimSpace(string(mountBody)))
		expectedMountpoint := filepath.Join(volumeRoot, volume.name, "_data")
		if inspectErr != nil || mountpoint != expectedMountpoint {
			return errors.New("infrastructure volume mountpoint is outside Docker's volume root")
		}
		info, statErr := os.Lstat(mountpoint)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("infrastructure volume mountpoint is not a real directory")
		}
		if err := os.Chown(mountpoint, volume.uid, volume.gid); err != nil {
			return fmt.Errorf("set infrastructure volume ownership: %w", err)
		}
		if err := os.Chmod(mountpoint, 0o700); err != nil {
			return fmt.Errorf("set infrastructure volume permissions: %w", err)
		}
	}
	return nil
}

func ensureInfrastructureSecrets(app string, payload []byte) error {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return err
	}
	services, _ := document["services"].(map[string]any)
	for _, service := range []string{"redis", "rabbitmq"} {
		if _, enabled := services[service]; !enabled {
			continue
		}
		secretName := infrastructureSecretName(app, service)
		if result := exec.Command("/usr/bin/docker", "secret", "inspect", secretName).Run(); result == nil {
			continue
		}
		dir := filepath.Join(rootSecretRoot, app)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		path := filepath.Join(dir, service+".password")
		secret, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			random := make([]byte, 32)
			if _, err := rand.Read(random); err != nil {
				return err
			}
			secret = []byte(base64.RawURLEncoding.EncodeToString(random))
			if err := writeRootFile(path, append(secret, '\n'), 0o600); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		command := exec.Command("/usr/bin/docker", "secret", "create", "--label", shuttleOwnerLabel+"="+app, secretName, "-")
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		command.Stdin = bytes.NewReader(bytes.TrimSpace(secret))
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("create infrastructure secret: %s", strings.TrimSpace(string(output)))
		}
	}
	return nil
}

const (
	// rootConvergenceCallCap bounds one docker read inside the convergence
	// wait. A wedged docker CLI must not be able to spend the budget the other
	// services still need: a wait that expires holding one hung call reports a
	// timeout with nothing to say about which service or why, which is the
	// failure mode this rewrite exists to remove.
	rootConvergenceCallCap = 2 * time.Second
	// rootConvergenceProbeInterval throttles the UpdateStatus probe. It is a
	// diagnosis and an early abort, never a pass condition, so it does not need
	// to keep up with the poll.
	rootConvergenceProbeInterval = time.Second
	// rootConvergenceDiagnosticBudget is a bounded pass run AFTER the
	// convergence budget expired, only to fill in the update state of the
	// services that did not converge. It sits outside the budget on purpose:
	// rootOperationBudget is ten minutes, so two seconds spent making the error
	// name the cause is free, and the alternative is a timeout that says
	// nothing.
	rootConvergenceDiagnosticBudget = 2 * time.Second
	// rootEmergencyRollbackWait bounds the look the failure path takes at its
	// own recovery. It is a fixed short cap rather than a share of the promotion
	// budget because the convergence budget has, by definition, already been
	// spent when this runs, and the client's SSH deadline is still counting.
	rootEmergencyRollbackWait = 20 * time.Second
)

// waitRootStack blocks until every service the applied stack declares is
// running the image that stack declares for it, or until the budget carried by
// the signed plan runs out.
//
// WHY IT IS NOT A REPLICA COUNT. Every Shuttle service is generated with
// update_config order: start-first, so during a rolling update Swarm keeps the
// OLD task running and healthy until the new one is ready. `docker service ls`
// therefore reports "1/1" for a service whose update has not begun, and the
// previous implementation : running == desired, nothing else : returned
// "converged" in milliseconds on every deploy. It reported a successful
// promotion for a stack whose primary service Swarm had rolled back to the
// previous release, and it let the registry garbage collector stop the registry
// while Swarm was still pulling from it, which is what caused that rollback.
// "1/1" means nothing yet. What the running tasks are running is the answer.
//
// The predicate, per service declared in the APPLIED STACK FILE and re-evaluated
// from scratch on every poll, lives in evaluateRootServiceConvergence next to
// the traps it avoids. The file is the right source rather than the live service
// spec because swarmkit restores PreviousSpec into Spec when it completes a
// rollback: a check against the live spec agrees with the tasks on the OLD image
// and passes on exactly the failure it was built to catch.
//
// Iteration is over the stack file and never over the live roster, which is what
// makes an added service, a removed service and `--prune` all behave: a service
// the prune is deleting can still be listed for a moment, and waiting for it to
// reach an image the stack no longer declares never terminates.
func waitRootStack(app, stackFile string, deployedAt time.Time, timeout time.Duration) error {
	payload, err := os.ReadFile(stackFile)
	if err != nil {
		return fmt.Errorf("stack %s cannot be verified: the applied stack file could not be read: %w", app, err)
	}
	wanted, err := rootStackServices(app, payload)
	if err != nil {
		return fmt.Errorf("stack %s cannot be verified: %w", app, err)
	}
	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(timeout))
	defer cancel()

	verdicts := make(map[string]rootServiceVerdict, len(wanted))
	updates := make(map[string]rootServiceUpdate, len(wanted))
	reported := make(map[string]string, len(wanted))
	fallbackLogged := make(map[string]bool, len(wanted))
	var lastProbe time.Time

	for ctx.Err() == nil {
		roster, rosterErr := rootServiceRosterNow(ctx, app)
		converged := true
		for _, want := range wanted {
			verdict := rootServiceVerdict{}
			readErr := rosterErr
			// A roster that cannot be read, and an absent service while a prune
			// is running, are both not-converged-yet and are retried. Treating
			// either as fatal would fail promotions on a transient.
			if readErr == nil {
				tasks, tasksErr := rootServiceTasksNow(ctx, want.Service)
				if tasksErr != nil {
					readErr = tasksErr
				} else {
					entry, listed := roster[want.Service]
					verdict = evaluateRootServiceConvergence(want, entry, listed, tasks)
				}
			}
			if readErr != nil {
				// A read that failed : most often because the deadline cut it
				// short on the last round : says nothing about the release. The
				// last verdict that did say something is carried into the
				// reason, or the expiry message would name the interrupted
				// observation instead of the state it was observing.
				verdict = rootServiceVerdict{Reason: readErr.Error()}
				if last := verdicts[want.Service]; !last.Converged && strings.TrimSpace(last.Reason) != "" {
					verdict.Reason = last.Reason + " (last observed; then " + readErr.Error() + ")"
					verdict.Failed = last.Failed
				}
			}
			// Never memoised. Swarm's update monitor (deploy.update_monitor_seconds,
			// five seconds unless the project says otherwise) runs with
			// failure_action: rollback, so a service can converge and then
			// regress inside the wait; remembering the first "yes" would hide
			// the regression and hand back a success.
			verdicts[want.Service] = verdict
			converged = converged && verdict.Converged
			if verdict.TagFallback && !fallbackLogged[want.Service] {
				fallbackLogged[want.Service] = true
				rootLog("app=%s service=%s release identity fell back to the tag: docker reported the running image without its digest", app, want.Service)
			}
			summary := "running the applied release"
			if !verdict.Converged {
				summary = verdict.Reason
			}
			// Logged on change only. At two polls a second, logging every round
			// would bury the journal under one repeated line.
			if reported[want.Service] != summary {
				reported[want.Service] = summary
				rootLog("app=%s service=%s %s", app, want.Service, summary)
			}
		}
		if converged {
			if !deployedAt.IsZero() {
				for _, want := range wanted {
					update, ok := rootServiceUpdateNow(ctx, want.Service)
					if !ok || !rootUpdateUndoesRelease(update, deployedAt) {
						continue
					}
					updates[want.Service] = update
					verdicts[want.Service] = rootServiceVerdict{Reason: "swarm is rolling this deploy back (" + strings.TrimSpace(update.State) + ")"}
					converged = false
					if rootUpdateGaveUp(update, deployedAt) {
						return rootStackConvergenceError("stack "+app+" promotion was rolled back by swarm", wanted, verdicts, updates)
					}
				}
			}
			if converged {
				rootLog("app=%s stack converged: %d service(s) on the applied release in %s", app, len(wanted), time.Since(start).Round(time.Millisecond))
				return nil
			}
		}
		if time.Since(lastProbe) >= rootConvergenceProbeInterval {
			lastProbe = time.Now()
			gaveUp := false
			for _, want := range wanted {
				if verdicts[want.Service].Converged {
					continue
				}
				update, ok := rootServiceUpdateNow(ctx, want.Service)
				if !ok {
					continue
				}
				updates[want.Service] = update
				gaveUp = gaveUp || rootUpdateGaveUp(update, deployedAt)
			}
			// The one signal that is terminal: Swarm has restored the previous
			// spec and no further waiting can change it. Aborting here gets the
			// stack-wide emergency rollback started sooner. Note this is NOT a
			// fast fail on a Rejected task: restart_policy is on-failure with
			// max_attempts 3, so a single rejection : including the registry
			// reset that caused this bug : is routinely recovered, and failing
			// on it would roll back healthy releases over a hiccup.
			if gaveUp {
				return rootStackConvergenceError("stack "+app+" promotion was rolled back by swarm", wanted, verdicts, updates)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(rootStackPollInterval(time.Since(start))):
		}
	}
	diagnoseRootStackConvergence(wanted, verdicts, updates)
	return rootStackConvergenceError(fmt.Sprintf("stack %s did not converge within %s", app, timeout), wanted, verdicts, updates)
}

// rootDockerRead runs one read-only docker command under the convergence
// deadline, capped at rootConvergenceCallCap or whatever is left of the budget,
// whichever is shorter.
//
// exec.CommandContext kills with SIGKILL on expiry. That is safe here and only
// here: all three commands this wait runs are reads, so a killed CLI leaves no
// server-side state behind.
func rootDockerRead(ctx context.Context, args ...string) (string, error) {
	limit := rootConvergenceCallCap
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < limit {
			limit = remaining
		}
	}
	if limit <= 0 {
		return "", errors.New("no time left in the convergence budget")
	}
	callCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	command := exec.CommandContext(callCtx, "/usr/bin/docker", args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	body, err := command.Output()
	if err == nil {
		return string(body), nil
	}
	// A call the deadline killed is not a docker failure. Reporting it as one
	// would put "signal: killed" in front of the operator instead of the reason
	// the wait ran out of time.
	if callCtx.Err() != nil {
		return "", fmt.Errorf("%s did not answer within %s", rootDockerCallName(args), limit.Round(time.Millisecond))
	}
	reason := strings.TrimSpace(stderr.String())
	if reason == "" {
		reason = err.Error()
	}
	return "", errors.New(reason)
}

func rootDockerCallName(args []string) string {
	if len(args) >= 2 {
		return "docker " + args[0] + " " + args[1]
	}
	return "docker"
}

// rootServiceRosterNow is the live service list of one stack namespace. Swarm's
// own running/desired accounting is read from here because it is the only
// source that is correct for a global service too, where the desired count is
// the node count and the helper cannot derive it.
func rootServiceRosterNow(ctx context.Context, app string) (map[string]rootServiceRoster, error) {
	body, err := rootDockerRead(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", rootServiceRosterFormat)
	if err != nil {
		return nil, err
	}
	return parseRootServiceRoster(body), nil
}

// rootServiceTasksNow lists every task of one service.
//
// --no-trunc is mandatory, not cosmetic. Without it the task formatter strips
// the digest off any NamedTagged reference : redis:7.4.5-alpine@sha256:… is
// printed as redis:7.4.5-alpine : so no stack using production.redis or
// production.rabbitmq could ever match, and it truncates .Error to thirty
// characters, which is exactly the field carrying the message that names the
// cause.
//
// There is deliberately no --filter desired-state=running. Once the
// orchestrator demotes a Rejected task to DesiredState=Shutdown it leaves that
// view, taking the only explanation of the failure with it. The filtering is
// done in Go over the full list instead, so one command serves both the
// decision and the diagnosis.
func rootServiceTasksNow(ctx context.Context, service string) ([]rootServiceTask, error) {
	body, err := rootDockerRead(ctx, "service", "ps", "--no-trunc", "--no-resolve", "--format", rootServiceTaskFormat, service)
	if err != nil {
		return nil, err
	}
	return parseRootServiceTasks(body), nil
}

func rootServiceUpdateNow(ctx context.Context, service string) (rootServiceUpdate, bool) {
	body, err := rootDockerRead(ctx, "service", "inspect", "--format", rootServiceUpdateFormat, service)
	if err != nil {
		return rootServiceUpdate{}, false
	}
	return parseRootServiceUpdate(body)
}

// diagnoseRootStackConvergence fills in the update state of the services that
// did not converge, on its own short context outside the exhausted budget, so
// the expiry message can name what Swarm thinks it was doing.
func diagnoseRootStackConvergence(wanted []rootStackService, verdicts map[string]rootServiceVerdict, updates map[string]rootServiceUpdate) {
	ctx, cancel := context.WithTimeout(context.Background(), rootConvergenceDiagnosticBudget)
	defer cancel()
	for _, want := range wanted {
		if verdicts[want.Service].Converged {
			continue
		}
		if update, ok := rootServiceUpdateNow(ctx, want.Service); ok {
			updates[want.Service] = update
		}
	}
}

// rootStackWaits turns the promotion budget carried by the signed plan into the
// privileged waits this helper is allowed to perform. The budget is transported
// rather than read from a configuration file because the helper runs as root
// and must derive everything from content the operator's key signed; rootplan
// range-checks the value, and DeployWaits clamps it again, so the worst a
// tampered-but-signed plan can do is bounded and always far below the
// root-operation lock budget.
//
// mode is the promotion mode the helper chose for this stack-apply before it
// deployed (config.SwarmWaits): legacy for a rollback and for anything that
// cannot prove the capped mode safe, so a rollback keeps its timing.
func rootStackWaits(plan rootplan.Plan, mode config.PromotionMode) config.DeployWaitBudget {
	seconds := 0
	if plan.Stack != nil {
		seconds = plan.Stack.PromotionSLOSeconds
	}
	if seconds == 0 {
		// A plan minted before the budget was transported: fall back to the
		// budget Shuttle ships for every non-PHP preset.
		seconds = config.DefaultDeploySLOSeconds("")
	}
	return config.SwarmWaits(seconds, mode)
}

// The 2026-10-28 Ubuntu 24.04 and Debian 13 acceptance run showed a cold first
// RabbitMQ task still Starting when the 16.5 s share expired. First releases
// pull cold images and do not evaluate the total SLO, so give only their stack
// convergence the 120 s floor. Existing releases keep the planned wait exactly.
func rootPromotionConvergenceWait(waits config.DeployWaitBudget, firstRelease bool) time.Duration {
	if firstRelease && waits.StackConvergence < config.FirstReleaseStackConvergenceFloor {
		return config.FirstReleaseStackConvergenceFloor
	}
	return waits.StackConvergence
}

// caddyRouteFragment derives the Caddy fragment from the signed stack alone.
// Kept pure and separate from the write and the reload so the routing decision
// : which service, which domain, which port : is testable without a filesystem
// or a running edge.
//
// It returns an empty fragment when the stack publishes nothing, which is how an
// internal application is expressed: no domain label, no route, no reload.
func caddyRouteFragment(app string, payload []byte) (string, error) {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return "", err
	}
	service, labels, err := serviceWithLabel(document, "dev.shuttle.domain")
	if err != nil {
		return "", err
	}
	if service == "" {
		return "", nil
	}
	// The fragment proxies to the Swarm DNS name `<stack>_<service>`, so the
	// service name is part of the routing decision and gets the same treatment
	// as the domain and the port: validated here, inside the signed operation,
	// because the root helper trusts nothing the CLI claims to have checked.
	if !rootServiceName.MatchString(service) {
		return "", errors.New("route service name is invalid")
	}
	domain := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.domain"]))
	port := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.port"]))
	if !rootRouteDomain.MatchString(domain) {
		return "", errors.New("route domain is invalid")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("route port is invalid")
	}
	// An origin behind a CDN or a tunnel is reached over plain HTTP: the edge in
	// front already terminated TLS, and the tunnel has no inbound path for an
	// ACME challenge to arrive on. Emitting a bare site address makes Caddy
	// redirect that leg to HTTPS and start requesting certificates it can never
	// obtain, which breaks the very hop it was asked to serve. The scheme is
	// therefore part of the routing decision, and travels signed like the rest.
	scheme := ""
	// "<nil>" is what fmt.Sprint yields for an absent label and stays a case of
	// its own; the two real modes are named by the constants the validator and
	// the origin proof use, so the three readers of this value cannot drift
	// apart. The helper still re-validates what it parses: a constant is a
	// compile-time value, not trust extended to the CLI.
	switch mode := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.tls"])); mode {
	case "", "<nil>", config.TLSModeACME:
	case config.TLSModeOff:
		scheme = httpOrigin.Scheme + "://"
	default:
		return "", fmt.Errorf("route tls mode %q is invalid", mode)
	}
	// A trusted-client restriction is the access control an operator put in
	// front of that origin. Dropping it silently on the way into the shared
	// edge would publish, wide open, something that was not before.
	guard, err := caddyClientGuard(labels)
	if err != nil {
		return "", err
	}
	// The gate is rendered or the fragment is refused: a malformed hash must
	// never produce a site that is half protected. Before this was written
	// here, a "protected" pre-production was public in silence.
	gate, err := caddyBasicAuth(labels)
	if err != nil {
		return "", err
	}
	domainGate, err := caddyDomainBasicAuth(labels)
	if err != nil {
		return "", err
	}
	primaryGate := gate
	if !domainGate {
		primaryGate = ""
	}
	routes, err := caddyPathRoutes(app, labels)
	if err != nil {
		return "", err
	}
	// The published service is the fall-through, always last: a path that
	// matched nothing has to reach something, and putting it first would
	// shadow every route behind it.
	headers, err := caddyDeclaredHeaders(labels)
	if err != nil {
		return "", err
	}
	// After the baseline import, so a declared header overrides the shared one
	// by name rather than sitting beside it as a duplicate.
	trusted, err := caddyTrustedProxies(labels, "    ")
	if err != nil {
		return "", err
	}
	fragment := fmt.Sprintf("%s%s {\n  import shuttle_security\n%s%s%s%s  reverse_proxy %s_%s:%d%s\n}\n", scheme, domain, primaryGate, headers, guard, routes, app, service, portNumber, trusted)
	// The extra hostnames come after the domain, each as a site of the same
	// shape. The scheme, the client guard and the trusted proxies are
	// properties of the application : the edge in front of it fronts every
	// hostname : so they apply to each site alike; headers and path routes
	// are the host's own.
	hosts, err := caddyHostRoutes(app, domain, scheme, guard, trusted, gate, labels)
	if err != nil {
		return "", err
	}
	return fragment + hosts, nil
}

// rootPathRoute is one decoded path handler, as carried by the signed stack.
type rootPathRoute struct {
	Path    string `json:"path"`
	Service string `json:"service"`
	Port    int    `json:"port"`
}

// rootHostRoute is one decoded extra hostname, as carried by the signed stack.
// HealthPath is deliberately absent: the helper writes routes, it does not
// probe them, and a field it does not read is a field it cannot misuse.
type rootHostRoute struct {
	Host       string            `json:"host"`
	Service    string            `json:"service"`
	Port       int               `json:"port"`
	PathRoutes []rootPathRoute   `json:"path_routes"`
	Headers    map[string]string `json:"headers"`
	// BasicAuth imports the domain's gate; a host declares no users of its own.
	BasicAuth bool `json:"basic_auth"`
}

// rootBasicAuthUser and rootBasicAuthHash mirror the CLI's own checks on the
// same values, applied again here because the helper trusts nothing the CLI
// claims to have validated.
var rootBasicAuthUser = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
var rootBasicAuthHash = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)

// caddyBasicAuth renders the basic_auth block declared on the published
// service, or nothing when the stack declares no gate. One invalid entry
// refuses the whole block: a site protected for some users and open for a
// typo is worse than a deploy that stops.
func caddyBasicAuth(labels map[string]any) (string, error) {
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.basic_auth"]))
	if raw == "" || raw == "<nil>" {
		return "", nil
	}
	var users []struct {
		Username string `json:"username"`
		Hash     string `json:"hash"`
	}
	if err := json.Unmarshal([]byte(raw), &users); err != nil {
		return "", errors.New("route basic auth list is not valid JSON")
	}
	if len(users) == 0 || len(users) > 8 {
		return "", errors.New("route basic auth list must name between 1 and 8 users")
	}
	public, err := caddyBasicAuthPublicPaths(labels)
	if err != nil {
		return "", err
	}
	seen := map[string]bool{}
	var b strings.Builder
	if len(public) > 0 {
		// The matcher travels inside the gate, so every site that imports
		// the gate (the domain and any gated host route) defines it too.
		fmt.Fprintf(&b, "  @shuttle_gated not path %s\n", strings.Join(public, " "))
		b.WriteString("  basic_auth @shuttle_gated {\n")
	} else {
		b.WriteString("  basic_auth {\n")
	}
	for _, user := range users {
		if !rootBasicAuthUser.MatchString(user.Username) {
			return "", fmt.Errorf("route basic auth username %q is invalid", user.Username)
		}
		if seen[user.Username] {
			return "", fmt.Errorf("route basic auth username %q is declared twice", user.Username)
		}
		seen[user.Username] = true
		if !rootBasicAuthHash.MatchString(user.Hash) {
			return "", fmt.Errorf("route basic auth hash for %q is not a bcrypt hash", user.Username)
		}
		fmt.Fprintf(&b, "    %s %s\n", user.Username, user.Hash)
	}
	b.WriteString("  }\n")
	return b.String(), nil
}

// caddyBasicAuthPublicPaths decodes the paths served without the gate. They
// are checked again here, with the same narrow matcher as path routes: the
// list is written into a Caddyfile the root-owned edge loads, and "/" or "/*"
// would quietly turn a protected site into a public one.
func caddyBasicAuthPublicPaths(labels map[string]any) ([]string, error) {
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.basic_auth_public_paths"]))
	if raw == "" || raw == "<nil>" {
		return nil, nil
	}
	var paths []string
	if err := json.Unmarshal([]byte(raw), &paths); err != nil {
		return nil, errors.New("route basic auth public paths are not valid JSON")
	}
	if len(paths) == 0 || len(paths) > 16 {
		return nil, errors.New("route basic auth public paths must name between 1 and 16 paths")
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if !rootCaddyPath.MatchString(path) || strings.Contains(path, "..") || path == "/" || path == "/*" {
			return nil, fmt.Errorf("route basic auth public path %q is invalid", path)
		}
		if seen[path] {
			return nil, fmt.Errorf("route basic auth public path %q is declared twice", path)
		}
		seen[path] = true
	}
	return paths, nil
}

// caddyDomainBasicAuth controls whether the primary site imports the shared
// gate. The absent label retains the historical behavior for older stacks and
// helpers; an explicit false is what expresses a public primary domain with a
// separately gated host route.
func caddyDomainBasicAuth(labels map[string]any) (bool, error) {
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.domain_basic_auth"]))
	if raw == "" || raw == "<nil>" {
		return true, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false, errors.New("route domain basic auth flag is invalid")
	}
	return enabled, nil
}

// caddyHostRoutes renders one site block per extra hostname declared on the
// published service. Every field is re-validated here, inside the signed
// operation, because a hostname is written into a Caddyfile the root-owned
// edge loads and will request a certificate for: the helper trusts the stack
// it was handed, not the CLI that claims to have checked it.
//
// gate is the domain's rendered basic_auth block, empty when there is none; a
// host that asks for it when the stack declares none is refused rather than
// published open.
func caddyHostRoutes(app, domain, scheme, guard, trusted, gate string, labels map[string]any) (string, error) {
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.host_routes"]))
	if raw == "" || raw == "<nil>" {
		return "", nil
	}
	var hosts []rootHostRoute
	if err := json.Unmarshal([]byte(raw), &hosts); err != nil {
		return "", errors.New("route host list is not valid JSON")
	}
	if len(hosts) == 0 || len(hosts) > 16 {
		return "", errors.New("route host list must name between 1 and 16 hosts")
	}
	seen := map[string]bool{}
	var builder strings.Builder
	for _, host := range hosts {
		if !rootRouteDomain.MatchString(host.Host) {
			return "", fmt.Errorf("route host %q is invalid", host.Host)
		}
		if host.Host == domain {
			return "", fmt.Errorf("route host %q is already the route domain", host.Host)
		}
		if seen[host.Host] {
			return "", fmt.Errorf("route host %q is declared twice", host.Host)
		}
		seen[host.Host] = true
		if !rootServiceName.MatchString(host.Service) {
			return "", fmt.Errorf("route host service %q is invalid", host.Service)
		}
		if host.Port < 1 || host.Port > 65535 {
			return "", fmt.Errorf("route host port %d is invalid", host.Port)
		}
		if len(host.PathRoutes) > 16 {
			return "", fmt.Errorf("route host %q names more than 16 paths", host.Host)
		}
		routes, err := renderCaddyPathRoutes(app, host.PathRoutes, trusted)
		if err != nil {
			return "", err
		}
		headers, err := renderCaddyHeaders(host.Headers)
		if err != nil {
			return "", err
		}
		hostGate := ""
		if host.BasicAuth {
			if gate == "" {
				return "", fmt.Errorf("route host %q asks for a basic auth gate the stack does not declare", host.Host)
			}
			hostGate = gate
		}
		fmt.Fprintf(&builder, "%s%s {\n  import shuttle_security\n%s%s%s%s  reverse_proxy %s_%s:%d%s\n}\n", scheme, host.Host, hostGate, headers, guard, routes, app, host.Service, host.Port, trusted)
	}
	return builder.String(), nil
}

// rootCaddyPath is the matcher the helper accepts. It is narrower than what
// Caddy would parse, because the value is written into a configuration file the
// root-owned edge loads: a brace or a newline there does not fail, it opens a
// block nobody wrote.
var rootCaddyPath = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*\*?$`)

// caddyPathRoutes renders the per-path handlers declared on the published
// service. Every field is re-validated here, inside the signed operation,
// because the helper trusts the stack and not the CLI that built it.
func caddyPathRoutes(app string, labels map[string]any) (string, error) {
	// Every leg to the application gets the same trust decision: a header the
	// published service believes and a path route does not would make the two
	// disagree about the scheme of the same request.
	trusted, err := caddyTrustedProxies(labels, "    ")
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.path_routes"]))
	if raw == "" || raw == "<nil>" {
		return "", nil
	}
	var routes []rootPathRoute
	if err := json.Unmarshal([]byte(raw), &routes); err != nil {
		return "", errors.New("route path list is not valid JSON")
	}
	if len(routes) == 0 || len(routes) > 16 {
		return "", errors.New("route path list must name between 1 and 16 paths")
	}
	return renderCaddyPathRoutes(app, routes, trusted)
}

// renderCaddyPathRoutes writes the handle blocks for an already decoded path
// list, validating each entry. Shared by the domain and by every host route,
// so the two cannot drift apart in what they accept.
func renderCaddyPathRoutes(app string, routes []rootPathRoute, trusted string) (string, error) {
	seen := map[string]bool{}
	var builder strings.Builder
	for _, route := range routes {
		if !rootCaddyPath.MatchString(route.Path) {
			return "", fmt.Errorf("route path %q is invalid", route.Path)
		}
		if seen[route.Path] {
			return "", fmt.Errorf("route path %q is declared twice", route.Path)
		}
		seen[route.Path] = true
		if !rootServiceName.MatchString(route.Service) {
			return "", fmt.Errorf("route path service %q is invalid", route.Service)
		}
		if route.Port < 1 || route.Port > 65535 {
			return "", fmt.Errorf("route path port %d is invalid", route.Port)
		}
		fmt.Fprintf(&builder, "  handle %s {\n    reverse_proxy %s_%s:%d%s\n  }\n", route.Path, app, route.Service, route.Port, trusted)
	}
	return builder.String(), nil
}

// caddyDeclaredHeaders renders the per-application response headers.
//
// Re-validated here rather than trusted: the CLI checked the same values, but
// this is the side that writes them into a Caddyfile the root-owned edge loads,
// where a brace or a newline opens a block the operator never wrote.
func caddyDeclaredHeaders(labels map[string]any) (string, error) {
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.headers"]))
	if raw == "" || raw == "<nil>" {
		return "", nil
	}
	var declared map[string]string
	if err := json.Unmarshal([]byte(raw), &declared); err != nil {
		return "", errors.New("route headers are not a JSON object")
	}
	return renderCaddyHeaders(declared)
}

// renderCaddyHeaders writes the header block for an already decoded map,
// validating each entry. Shared by the domain and by every host route.
func renderCaddyHeaders(declared map[string]string) (string, error) {
	if len(declared) == 0 {
		return "", nil
	}
	if len(declared) > 16 {
		return "", errors.New("route declares too many headers")
	}
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	// Sorted: the fragment must be byte-identical between deploys, or the edge
	// is reloaded for nothing and a real change cannot be spotted in a diff.
	slices.Sort(names)
	var b strings.Builder
	b.WriteString("  header {\n")
	for _, name := range names {
		if !caddyRouteHeaderName.MatchString(name) {
			return "", fmt.Errorf("route header name %q is not a header name", name)
		}
		value := declared[name]
		if len(value) > 1024 {
			return "", fmt.Errorf("route header %s is too long", name)
		}
		for _, r := range value {
			if r < 0x20 || r > 0x7e || r == '"' || r == '{' || r == '}' {
				return "", fmt.Errorf("route header %s carries a character that would change the edge configuration", name)
			}
		}
		fmt.Fprintf(&b, "    %s \"%s\"\n", name, value)
	}
	b.WriteString("  }\n")
	return b.String(), nil
}

// caddyRouteHeaderName mirrors the CLI's own check on the same value.
var caddyRouteHeaderName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// caddyTrustedProxies renders the reverse_proxy block that makes Caddy believe
// the X-Forwarded-* headers of the peer in front of it.
//
// Caddy overwrites X-Forwarded-Proto with the scheme of the leg it served, and
// behind a CDN or a tunnel that leg is plain HTTP. The application therefore
// learns "http" for a request the client made over HTTPS, and every absolute
// URL it builds comes out wrong: a redirect from https to http makes any HTTP
// client drop the Authorization header, so an API answered "missing or expired
// token" on a token that was neither. Password-reset links and OAuth callbacks
// have the same defect, silently.
//
// The peers whose headers may be believed are exactly the peers allowed to
// reach the site at all, so the allow-list is the trust list : there is no
// second thing to configure, and no way for the two to disagree.
func caddyTrustedProxies(labels map[string]any, indent string) (string, error) {
	entries, err := caddyAllowedCIDRs(labels)
	if err != nil || len(entries) == 0 {
		return "", err
	}
	// indent is the column of the reverse_proxy this block hangs off, so a
	// directive nested inside a handle stays readable in the generated file.
	return " {\n" + indent + "  trusted_proxies " + strings.Join(entries, " ") + "\n" + indent + "}", nil
}

// caddyAllowedCIDRs parses and sorts the declared client allow-list.
func caddyAllowedCIDRs(labels map[string]any) ([]string, error) {
	raw := strings.TrimSpace(fmt.Sprint(labels["dev.shuttle.allow_cidrs"]))
	if raw == "" || raw == "<nil>" {
		return nil, nil
	}
	entries := strings.Split(raw, ",")
	if len(entries) > 32 {
		return nil, errors.New("route client allow-list is too long")
	}
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return nil, fmt.Errorf("route client allow-list entry %q is not a CIDR", entry)
		}
		entries[i] = entry
	}
	// Sorted so the same allow-list always renders the same fragment: a route
	// that changes byte for byte between deploys reloads the shared edge for
	// nothing, and makes a real change impossible to spot in a diff.
	slices.Sort(entries)
	return slices.Compact(entries), nil
}

// caddyClientGuard renders the optional `remote_ip` restriction. Every entry is
// parsed as a CIDR here, inside the signed operation: the value is written into
// a Caddyfile the root-owned edge loads, so a malformed entry must be refused
// rather than emitted and left for Caddy to interpret.
func caddyClientGuard(labels map[string]any) (string, error) {
	entries, err := caddyAllowedCIDRs(labels)
	if err != nil || len(entries) == 0 {
		return "", err
	}
	// A guard, not a route. The previous form opened `handle @trusted { }` and a
	// `handle { respond 403 }` beside it, which made the allow-list one branch of
	// the site's routing rather than a condition on it: `handle` blocks are
	// mutually exclusive, so a trusted client matched the empty block and every
	// path route written below it became unreachable. Each one silently fell
	// through to the published service, so /api, /graphql and /auth were answered
	// by the front end : a 404 page where the API was supposed to be, on a
	// deployment that reported every service healthy.
	//
	// Refusing the untrusted client outright leaves the routing that follows
	// exactly as it would be without an allow-list.
	return fmt.Sprintf("  @untrusted not remote_ip %s\n  respond @untrusted 403\n", strings.Join(entries, " ")), nil
}

// runDeclaredOperation executes one maintenance command inside a running task
// of a deployed service.
//
// The command is not in the request. The request carries a name; the command is
// read from the labels of the service Docker is actually running, which is the
// stack the operator signed and the helper applied. An unprivileged caller can
// therefore pick among approved operations and cannot compose a new one, which
// is the whole reason this is not simply a remote shell.
//
// It is executed with exec.Command and an argv, never through a shell, so an
// argument cannot become a second command.
func runDeclaredOperationForPlan(plan rootplan.Plan, output io.Writer) error {
	var target declaredOperation
	var container string
	if err := withPreRunWatchdog(func() error {
		var err error
		target, container, err = preflightDeclaredOperation(plan, output)
		return err
	}); err != nil {
		return emitPreflightRefusal(err)
	}
	phaseStarted := false
	err := withCoordinatedRootPhaseStarted(plan, func() { phaseStarted = true }, func(phase context.Context) error {
		if err := coord.JournalRunTarget(phase, target.Service, container); err != nil {
			return err
		}
		return declaredOperationExec(container, target.Command, output)
	})
	// This also reports a durable successful run replay refused by the
	// coordinator, before declaredOperationExec can repeat its side effects.
	if err != nil && !phaseStarted {
		return emitPreflightRefusal(err)
	}
	if known, ok := err.(*coord.KnownOutcomeError); ok && known != nil {
		fmt.Fprintln(os.Stderr, rootKnownOutcomeMarker+cleanRootKnownOutcomeReason(known.Error()))
	}
	return err
}

func resolveDeclaredOperation(app, operation string) (declaredOperation, error) {
	if !rootAppName.MatchString(app) || !rootOperationName.MatchString(operation) {
		return declaredOperation{}, errors.New("invalid run request")
	}
	declared, err := declaredOperationsLookup(app)
	if err != nil {
		return declaredOperation{}, err
	}
	target, ok := declared[operation]
	if !ok {
		return declaredOperation{}, fmt.Errorf("operation %s is not declared by the deployed stack", operation)
	}
	if !rootServiceName.MatchString(target.Service) || len(target.Command) == 0 {
		return declaredOperation{}, errors.New("declared operation is malformed")
	}
	for _, argument := range target.Command {
		if argument == "" || strings.ContainsAny(argument, "\r\n\x00") {
			return declaredOperation{}, errors.New("declared operation carries an unusable argument")
		}
	}
	return target, nil
}

type declaredOperation struct {
	Service      string   `json:"service"`
	Command      []string `json:"command"`
	BackupBefore bool     `json:"backup_before,omitempty"`
}

var (
	rootOperationCoordinator        = coord.NewDefault
	rootCoordinatedIdentityVerifier = verifyRootOperationIdentity
	rootCoordinatedMutationGuard    = refuseRootHelperMutationDuringMigration
	declaredOperationsServices      = func(app string) ([]string, error) {
		command := exec.Command("/usr/bin/docker", "service", "ls",
			"--filter", "label=com.docker.stack.namespace="+app,
			"--format", "{{.Name}}")
		listed, err := command.Output()
		if err != nil {
			return nil, fmt.Errorf("list services for %s: %w", app, err)
		}
		return strings.Fields(string(listed)), nil
	}
	declaredOperationsLabel = func(service string) (string, error) {
		inspect := exec.Command("/usr/bin/docker", "service", "inspect", service,
			"--format", "{{index .Spec.Labels \"dev.shuttle.operations\"}}")
		encoded, err := inspect.Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(encoded)), nil
	}
	declaredOperationsLookup        = declaredOperations
	declaredOperationContainer      = runningTaskContainer
	declaredOperationInspectExecIDs = inspectDeclaredOperationExecIDs
	declaredOperationRunExec        = runDeclaredOperationExec
	declaredOperationExec           = func(container string, command []string, output io.Writer) error {
		return classifyDeclaredOperationExec(container, command, output, declaredOperationInspectExecIDs, declaredOperationRunExec)
	}
)

func inspectDeclaredOperationExecIDs(container string) ([]string, bool, error) {
	arguments := []string{"container", "inspect", "--format", "{{json .ExecIDs}}", container}
	command := exec.Command("/usr/bin/docker", arguments...)
	body, err := command.CombinedOutput()
	if err != nil {
		if dockerObjectNotFound(string(body)) {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("inspect container exec IDs: %w", err)
	}
	encoded := strings.TrimSpace(string(body))
	if encoded == "null" {
		// Docker encodes an empty ExecIDs slice as null after a successful inspect.
		return []string{}, true, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(encoded), &ids); err != nil || ids == nil {
		return nil, true, errors.New("container exec ID inspection was not an unambiguous JSON array")
	}
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id {
			return nil, true, errors.New("container exec ID inspection contained an invalid ID")
		}
	}
	return ids, true, nil
}

func runDeclaredOperationExec(container string, command []string, output io.Writer) error {
	arguments := append([]string{"exec", container}, command...)
	process := exec.Command("/usr/bin/docker", arguments...)
	process.Stdout = output
	process.Stderr = output
	return process.Run()
}

func classifyDeclaredOperationExec(container string, command []string, output io.Writer, inspect func(string) ([]string, bool, error), run func(string, []string, io.Writer) error) error {
	before, beforeExists, beforeErr := inspect(container)
	execErr := run(container, command, output)
	if execErr == nil || !knownDockerExecExit(execErr) {
		return execErr
	}
	after, exists, afterErr := inspect(container)
	if afterErr != nil {
		return execErr
	}
	if !exists {
		return coord.KnownOutcome(execErr)
	}
	if beforeErr != nil || !beforeExists {
		return execErr
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, id := range before {
		beforeSet[id] = struct{}{}
	}
	for _, id := range after {
		if _, existed := beforeSet[id]; !existed {
			return execErr
		}
	}
	return coord.KnownOutcome(execErr)
}

func knownDockerExecExit(err error) bool {
	exit, ok := err.(*exec.ExitError)
	if !ok || exit == nil {
		return false
	}
	code := exit.ExitCode()
	return code >= 1 && code <= 124 || code == 126 || code == 127 || code >= 128 && code <= 254
}

// declaredOperations reads the operations label off the deployed services of an
// app. It reads Docker rather than any file on disk: what is running is what was
// signed, and a stale file could otherwise authorise a command the current
// release never declared.
func declaredOperations(app string) (map[string]declaredOperation, error) {
	services, err := declaredOperationsServices(app)
	if err != nil {
		return nil, err
	}
	sort.Strings(services)
	var matchedServices []string
	var encodedOperations string
	for _, service := range services {
		body, err := declaredOperationsLabel(service)
		if err != nil {
			return nil, fmt.Errorf("inspect service %s for declared operations: %w", service, err)
		}
		if body == "" || body == "<no value>" {
			continue
		}
		matchedServices = append(matchedServices, service)
		encodedOperations = body
	}
	if len(matchedServices) > 1 {
		return nil, fmt.Errorf("more than one service of %s declares operations (%s); only the published service may", app, strings.Join(matchedServices, ", "))
	}
	if len(matchedServices) == 1 {
		operations := map[string]declaredOperation{}
		if err := json.Unmarshal([]byte(encodedOperations), &operations); err != nil {
			return nil, fmt.Errorf("declared operations of %s are not readable: %w", matchedServices[0], err)
		}
		return operations, nil
	}
	return nil, fmt.Errorf("no deployed service of %s declares any operation", app)
}

// runningTaskContainer resolves one running container of a Swarm service. A
// service with no running task is reported as such rather than silently doing
// nothing, because an operation that quietly did not run is worse than one that
// failed.
func runningTaskContainer(service string) (string, error) {
	command := exec.Command("/usr/bin/docker", "ps", "--quiet", "--no-trunc",
		"--filter", "label=com.docker.swarm.service.name="+service)
	listed, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("find a running task of %s: %w", service, err)
	}
	fields := strings.Fields(string(listed))
	if len(fields) == 0 {
		return "", fmt.Errorf("service %s has no running task", service)
	}
	return fields[0], nil
}

// applyRootCaddyRoute writes the application's edge fragment and reloads the
// shared Caddy, under the shared-resource lock so that the collision scan, the
// write and the reload see no other application's fragment change halfway.
func applyRootCaddyRoute(app string, payload []byte, reloadTimeout time.Duration) error {
	return withRootSharedResources(func() error {
		return applyRootCaddyRouteShared(app, payload, reloadTimeout)
	})
}

func applyRootCaddyRouteShared(app string, payload []byte, reloadTimeout time.Duration) error {
	fragment, err := caddyRouteFragment(app, payload)
	if err != nil {
		return err
	}
	if fragment == "" {
		return nil
	}
	own := filepath.Join("/opt/shuttle/caddy/conf.d", "50-"+app+".caddy")
	// Retire the previous generation's fragment for THIS app before writing
	// ours. The blue/green runner wrote <app>.caddy; the Swarm helper writes
	// 50-<app>.caddy. Both are imported by the shared Caddyfile glob, so the
	// two declare the same hostnames and Caddy refuses the whole config with
	// "ambiguous site definition". Same app, same hostnames, superseded file:
	// removing it is not a guess.
	if err := os.Remove(filepath.Join("/opt/shuttle/caddy/conf.d", app+".caddy")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("retire the superseded Caddy fragment of %s: %w", app, err)
	}
	// Anything else that claims our hostnames is NOT ours to delete, but it
	// must not be discovered by Caddy's parser either.
	//
	// Measured on a real cutover (03-09-2026): the stack converged, every
	// service reported healthy, and the deploy then died on "adapting config
	// using caddyfile: ambiguous site definition: domebao.com" -- a message
	// that names the hostname but not the file holding it. Because the reload
	// is the last step of promotion, the release was applied and running while
	// the edge kept serving nothing: 502 on every public domain for as long as
	// it took a human to find two stale files by hand. Failing here, naming
	// them, turns a 40-minute outage into a one-line fix.
	if err := detectForeignCaddySiteCollision("/opt/shuttle/caddy/conf.d", own, fragment); err != nil {
		return err
	}
	if err := writeRootFile(own, []byte(fragment), 0o644); err != nil {
		return err
	}
	return reloadSharedCaddy(reloadTimeout)
}

// detectForeignCaddySiteCollision fails when another fragment in the same
// directory already declares one of the addresses this app is about to claim.
func detectForeignCaddySiteCollision(dir, own, fragment string) error {
	claimed := map[string]bool{}
	for _, address := range caddyFragmentSiteAddresses(fragment) {
		claimed[address] = true
	}
	if len(claimed) == 0 {
		return nil
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*.caddy"))
	if err != nil {
		return fmt.Errorf("scan %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry == own {
			continue
		}
		content, err := os.ReadFile(entry)
		if err != nil {
			// Unreadable is not colliding, and refusing a deploy over a file
			// we cannot even read would be worse than the collision.
			continue
		}
		for _, address := range caddyFragmentSiteAddresses(string(content)) {
			if claimed[address] {
				return fmt.Errorf(
					"%s already declares the site %s, which this deployment also claims; Caddy would refuse the whole configuration with \"ambiguous site definition\". Remove the stale fragment on the host and redeploy: rm %s",
					entry, address, entry)
			}
		}
	}
	return nil
}

// defaultCaddyReloadTimeout bounds a shared-edge reload that is not part of a
// budgeted promotion (stack removal). A privileged operation that blocks
// forever holds the root-operation lock, which freezes every later Shuttle
// command on the host until the VPS is rebooted out of band, so no step here is
// allowed to wait indefinitely.
var defaultCaddyReloadTimeout = config.SwarmWaits(config.DefaultDeploySLOSeconds(""), config.PromotionModeLegacy).CaddyReload

// reloadSharedCaddy applies the route fragments in /opt/shuttle/caddy/conf.d
// to the running edge.
//
// It reloads Caddy in place instead of replacing the Swarm task. The edge
// publishes 80/443 in host mode with a single replica, so restarting the task
// takes the public endpoint down for the duration, and `docker service update
// --force` waits for a convergence that a host-port conflict can prevent
// forever. An in-place reload keeps existing connections, needs no new port
// binding, and returns in well under a second.
func reloadSharedCaddy(budget time.Duration) error {
	return reloadSharedCaddyUntil(time.Now().Add(budget))
}

func reloadSharedCaddyUntil(deadline time.Time) error {
	// One deadline for the whole reload, not one per command. The two Docker
	// calls run in sequence, so a per-command timeout would let the phase cost
	// twice what the promotion budget allocated to it. Destroy passes its
	// journaled cleanup deadline so a separate Caddy timeout cannot outlive the
	// removal contract.
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return errors.New("shared Caddy reload timed out at the destroy deadline")
	}
	container, err := runFixedOutput(remaining, "/usr/bin/docker", "ps", "-q",
		"--filter", "label=com.docker.swarm.service.name=shuttle-edge_caddy")
	if err != nil {
		return fmt.Errorf("inspect shared Caddy: %w", err)
	}
	id, _, _ := strings.Cut(strings.TrimSpace(container), "\n")
	if id == "" {
		return errors.New("the shared Caddy container is not running; the edge cannot be reloaded")
	}
	remaining = time.Until(deadline)
	if remaining <= 0 {
		return errors.New("shared Caddy reload timed out at the destroy deadline")
	}
	if _, err := runFixedOutput(remaining, "/usr/bin/docker", "exec", id,
		"caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("reload shared Caddy: %w", err)
	}
	return nil
}

// runFixedOutput runs a fixed command under a hard deadline and returns its
// standard output. The deadline is what keeps a hung Docker call from holding
// the root-operation lock forever.
func runFixedOutput(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s timed out after %s", filepath.Base(name), timeout)
	}
	if err != nil {
		return "", fmt.Errorf("%s failed: %s", filepath.Base(name), strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

// rootOperationBudget is the longest a single privileged operation may hold the
// root-operation lock. It is generous: the slowest legitimate operation is a
// first stack promotion pulling images over a cold network.
//
// The budget exists because the failure it prevents is unrecoverable from the
// operator's side. A privileged call that blocks forever keeps the lock, so
// every later Shuttle command fails with "another root operation is active",
// and `deploy` cannot clear it: its only sudo capability is this helper, and
// systemd refuses it a reboot. The host then needs the provider console. Dying
// on the budget releases the flock with the process and leaves the host usable.
// rootOperationLockWait is how long an operation waits for the host's lock
// before giving up.
//
// The lock was host-wide for every promotion, because a promotion reloads the
// shared edge and garbage-collects the shared registry. Since 14-09-2026 an
// application's promotion holds its own executor lock instead, and only the
// edge reload and the registry and image-store sweeps take the shared-resource
// lock (withRootSharedResources). But refusing instantly
// made that exclusivity everyone's problem as soon as a host served more than
// one application : a deploy of B failed outright because A happened to be
// mid-promotion, and a scheduled pipeline turned a queueing question into a red
// build.
//
// Waiting answers it where it belongs. The window is the operation budget: an
// operation that could still start and finish is worth waiting for, and past
// that the watchdog would have aborted the holder anyway, so a longer wait
// could only outlive the thing it waits on.
const rootOperationLockWait = rootOperationBudget

// rootOperationLockPoll is the interval between attempts. flock has no timed
// variant, so the wait is a poll; the interval is short enough to be invisible
// next to a promotion and long enough not to spin.
const rootOperationLockPoll = 250 * time.Millisecond

// operationsRootStatus is the helper-side status collector. It runs on the
// VPS, so the journal is never mistaken for a workstation-local state store.
func operationsRootStatus(ctx context.Context) ([]byte, error) {
	records, err := rootOperationCoordinator().List(ctx)
	if err != nil {
		return nil, err
	}
	if records == nil {
		records = []coord.Record{}
	}
	for i := range records {
		records[i] = operationResponseRecord(records[i])
	}
	body, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

var rootWatchdogState struct {
	sync.Mutex
	recover  func()
	deadline time.Time
}

func setRootWatchdogRecovery(recover func()) {
	rootWatchdogState.Lock()
	rootWatchdogState.recover = recover
	rootWatchdogState.Unlock()
}

func rootOperationWatchdogFired() {
	rootWatchdogState.Lock()
	recover := rootWatchdogState.recover
	rootWatchdogState.Unlock()
	if recover != nil {
		recover()
	}
}

func reserveRootOperation(plan rootplan.Plan) error {
	if err := verifyRootOperationIdentity(plan); err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse signed operation expiry: %w", err)
	}
	coordinator := rootOperationCoordinator()
	_, err = coordinator.Reserve(context.Background(), coord.Request{
		ID: plan.OperationID, Kind: plan.OperationKind, App: plan.OperationApp,
		Principal: plan.OperatorKeyFingerprint, OwnerKeyFingerprint: plan.OperatorKeyFingerprint,
		Host: plan.RequiredHostFingerprint, Lease: 35 * time.Minute,
		PlanExpiresAt: expires, HostIdentity: plan.RequiredHostFingerprint,
		Validate: func() error {
			if err := refuseRootHelperMutationDuringMigration(plan.Action); err != nil {
				return err
			}
			return verifyRootOperationIdentity(plan)
		},
	})
	if err != nil {
		return fmt.Errorf("reserve coordinated operation: %w", err)
	}
	// Helper replacement is executed entirely by the signed root process.
	// Its migration proof binds and drains that exact executor separately.
	if plan.OperationKind == "helper-update" {
		return nil
	}
	return initializeRootOperationWriters(context.Background(), coordinator, plan)
}

// withCoordinatedRootOperation bridges the signed root plan to the durable
// journal. The short flock still serializes journal transitions, while the
// durable active record blocks incompatible work during the long Docker phase.
// A failed or interrupted terminal phase remains recovery_required until an
// operator observes the host and explicitly applies the resulting plan.
func withCoordinatedRootOperation(plan rootplan.Plan, terminal bool, run func() error) error {
	return withCoordinatedRootOperationStarted(plan, terminal, nil, run)
}

func withCoordinatedRootOperationStarted(plan rootplan.Plan, terminal bool, phaseStarted func(), run func() error) error {
	return withCoordinatedRootPhaseStarted(plan, phaseStarted, func(context.Context) error { return run() })
}

// withCoordinatedRootPhase is withCoordinatedRootOperation for a callback that
// needs the phase context, to journal through coord.JournalCurrentManifest.
func withCoordinatedRootPhase(plan rootplan.Plan, run func(context.Context) error) error {
	return withCoordinatedRootPhaseStarted(plan, nil, run)
}

func withCoordinatedRootPhaseStarted(plan rootplan.Plan, phaseStarted func(), run func(context.Context) error) error {
	if plan.OperationID == "" {
		return errors.New("root helper requires the durable operation coordination capability")
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse signed operation expiry: %w", err)
	}
	coordinator := rootOperationCoordinator()
	scanRefused := false
	request := coord.PhaseRequest{
		ID: plan.OperationID, Kind: plan.OperationKind, App: plan.OperationApp,
		Principal: plan.OperatorKeyFingerprint, OwnerKeyFingerprint: plan.OperatorKeyFingerprint,
		Host: plan.RequiredHostFingerprint, Name: plan.Action, PlanExpiresAt: expires,
		HostIdentity: plan.RequiredHostFingerprint,
		Validate: func(record coord.Record) error {
			if err := rootCoordinatedIdentityVerifier(plan); err != nil {
				return err
			}
			if plan.Action == "helper-update" && plan.OperationKind == "helper-update" {
				if err := rootHelperUpdatePreflight(plan, record); err != nil {
					scanRefused = true
					return err
				}
			}
			return nil
		},
		Concurrent: rootActionRunsConcurrently(plan),
	}
	setRootWatchdogRecovery(func() {
		_ = coordinator.MarkWatchdogRecoveryForPhase(request, "root helper watchdog aborted the operation", "observe actual service state", "verify retained current and previous releases", "verify registry health and data witnesses")
	})
	defer setRootWatchdogRecovery(nil)
	// ExecutePhase owns the coordinator flock, or for a concurrent action the
	// application's executor flock, for the entire callback. The watchdog is
	// inside that callback so its lock-free evidence write happens before
	// os.Exit(75), while no second flock can deadlock the helper.
	err = coordinator.ExecutePhase(context.Background(), request, func(phase context.Context, _ coord.Record) error {
		if phaseStarted != nil {
			phaseStarted()
		}
		if err := rootCoordinatedMutationGuard(plan.Action); err != nil {
			return err
		}
		return withRootOperationWatchdog(func() error { return run(phase) })
	})
	if _, known := err.(*coord.KnownOutcomeError); known && plan.Action == "helper-update" && plan.OperationKind == "helper-update" {
		// The candidate policy refused before replacement and its admission was
		// cleared. Settle this known phase even if the client has disconnected.
		request.Validate = func(coord.Record) error { return rootCoordinatedIdentityVerifier(plan) }
		return errors.Join(err, coordinator.Control(context.Background(), request, "refuse", "helper-update candidate refused before replacement"))
	}
	if scanRefused {
		// A refused scan precedes staging and candidate execution. Close the
		// phase-less reservation even if the client disconnects; otherwise its
		// lease would expire into recovery_required with an unchanged helper.
		request.Validate = func(coord.Record) error { return rootCoordinatedIdentityVerifier(plan) }
		return errors.Join(err, coordinator.Control(context.Background(), request, "refuse", "helper-update scan refused before mutation"))
	}
	return err
}

// rootActionRunsConcurrently names the signed actions whose callback may overlap
// another application's.
//
// Each of them writes only its own application's stack, secrets and tasks. What
// they share with other applications (the edge configuration and its reload,
// the registry catalogue, the image store) is taken under
// withRootSharedResources inside the callback, and the registry collector
// additionally waits until its operation is alone on the host. A global kind,
// helper-update and the writer inventory keep the host journal flock across
// their callback, as before.
func rootActionRunsConcurrently(plan rootplan.Plan) bool {
	if plan.OperationApp == "" || coord.IsGlobal(plan.OperationKind) {
		return false
	}
	switch plan.Action {
	case "stack-apply", "stack-rollback", "stack-reclaim", "secrets-apply", "secrets-host", "secrets-hashvault", "hashvault-sync", "run":
		return true
	default:
		return false
	}
}

// rootSharedResourceLockPath serialises the host resources every application
// shares. Two promotions may overlap, but not their edge reloads: each writes
// its fragment into one conf.d and reloads one Caddy, so a fragment refused by
// Caddy would fail the other application's reload too, and two sweeps of the
// registry and image store would plan deletions from each other's half-done
// state.
const rootSharedResourceLockPath = "/run/shuttle-shared.lock"

// withRootSharedResources runs fn under the shared-resource lock, waiting as
// long as an operation may run. A global operation takes it while holding the
// host journal flock, and the registry collector takes the journal flock while
// holding it. The journal keeps a global operation and an application operation
// from being live together, and the collector's journal wait is short and
// turns into a deferral, so the two orders cannot hold each other forever.
func withRootSharedResources(fn func() error) error {
	lock, err := os.OpenFile(rootSharedResourceLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open shared-resource lock: %w", err)
	}
	defer lock.Close()
	if err := acquireRootOperationLock(lock, rootOperationLockWait); err != nil {
		return fmt.Errorf("edge and registry are held by another operation: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// collectRootRegistryGarbageAlone runs the registry collector only while
// operationID is the sole operation on the host.
//
// Garbage collection stops the registry and deletes every blob no manifest
// references yet, which is exactly what another application's push in flight
// looks like. When promotions were serialised by a host-wide reservation the
// collector could not meet a push; now it can, so it waits for a moment when
// nothing else is reserved. A deferral is not an error: the superseded manifests
// are already deleted, and the next promotion that runs alone reclaims their
// blobs.
func collectRootRegistryGarbageAlone(app, operationID string) error {
	err := coord.NewDefault().WithSoleOperation(context.Background(), operationID, collectRootRegistryGarbage)
	if errors.Is(err, coord.ErrOtherOperationsActive) {
		rootLog("app=%s registry: garbage collection deferred: %v", app, err)
		return nil
	}
	return err
}

func withRootOperationWatchdog(run func() error) error {
	rootWatchdogState.Lock()
	rootWatchdogState.deadline = time.Now().Add(rootOperationBudget)
	rootWatchdogState.Unlock()
	defer func() {
		rootWatchdogState.Lock()
		rootWatchdogState.deadline = time.Time{}
		rootWatchdogState.Unlock()
	}()
	watchdog := time.AfterFunc(rootOperationBudget, func() {
		rootOperationWatchdogFired()
		fmt.Fprintf(os.Stderr, "root operation exceeded %s and was aborted so the host stays operable\n", rootOperationBudget)
		os.Exit(75)
	})
	defer watchdog.Stop()
	return run()
}

func withRootOperationLock(run func() error) error {
	lock, err := os.OpenFile("/run/shuttle-root.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open root-operation lock: %w", err)
	}
	defer lock.Close()
	if err := acquireRootOperationLock(lock, rootOperationLockWait); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := refuseRootHelperMutationDuringMigration("baseline"); err != nil {
		return err
	}

	watchdog := time.AfterFunc(rootOperationBudget, func() {
		rootOperationWatchdogFired()
		fmt.Fprintf(os.Stderr, "root operation exceeded %s and was aborted so the host stays operable\n", rootOperationBudget)
		os.Exit(75)
	})
	defer watchdog.Stop()
	return run()
}

// acquireRootOperationLock takes the exclusive lock, waiting up to budget for
// whoever holds it. The error names the wait, because "another root operation
// is active" after ten minutes of queueing describes the same symptom as after
// none and leaves the operator guessing which one they hit.
func acquireRootOperationLock(lock *os.File, budget time.Duration) error {
	started := time.Now()
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("take root-operation lock: %w", err)
		}
		if waited := time.Since(started); waited >= budget {
			return fmt.Errorf("another root operation is still active after waiting %s", waited.Round(time.Second))
		}
		time.Sleep(rootOperationLockPoll)
	}
}

func verifyRootOperationIdentity(plan rootplan.Plan) error {
	if err := verifyHostFingerprint(plan.RequiredHostFingerprint); err != nil {
		return err
	}
	return verifyOperatorKey(plan.OperatorUser, plan.OperatorKeyFingerprint)
}

func verifyHostFingerprint(expected string) error {
	body, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return fmt.Errorf("read host identity: %w", err)
	}
	key, _, _, _, err := gossh.ParseAuthorizedKey(body)
	if err != nil || gossh.FingerprintSHA256(key) != expected {
		return errors.New("host identity does not match signed root operation")
	}
	return nil
}

func verifyOperatorKey(operator, expected string) error {
	body, err := os.ReadFile(filepath.Join("/home", operator, ".ssh", "authorized_keys"))
	if err != nil {
		return fmt.Errorf("read operator authorization: %w", err)
	}
	remaining := bytes.TrimSpace(body)
	for len(remaining) > 0 {
		key, _, _, rest, parseErr := gossh.ParseAuthorizedKey(remaining)
		if parseErr != nil {
			return errors.New("operator authorized_keys contains invalid data")
		}
		if gossh.FingerprintSHA256(key) == expected {
			return nil
		}
		remaining = bytes.TrimSpace(rest)
	}
	return errors.New("signed operator key is not authorized")
}

// syncRootFileDirectory is the seam writeRootFile uses to make a rename durable.
// It points at syncRootRecoveryDir so one helper opens and syncs a directory;
// a test replaces it to observe the call and to inject a failure.
var syncRootFileDirectory = syncRootRecoveryDir

// writeRootFile replaces path with body through a synced temporary file and a
// rename. Syncing the file alone is not enough: the rename is a change to the
// parent directory, and until that directory reaches the disk a power cut can
// bring the old entry back. current.yml is journaled first (stack-apply calls
// coord.JournalCurrentManifest before writing it), so the journal is ahead of
// the file; Swarm is still on the old release at that point, because docker
// stack deploy runs afterwards. Without the directory sync the file could revert
// to the old content after a power cut while the journal names the new digest,
// and recovery would read two stories. The directory is therefore synced after
// the rename, and a failure is returned wrapped in errRootFileNotDurable: the
// file is already replaced, so a caller holding a multi-file invariant (the
// rollback swap) can tell this apart from a write that changed nothing.
// stack-apply simply aborts on it, before docker stack deploy: previous.yml then
// holds the serving release and current.yml either that same release or the
// journaled new manifest, which is the state a crash at that point leaves and
// recovery already handles.
func writeRootFile(path string, body []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink at %s", path)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".shuttle-root-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if err := syncRootFileDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%s was replaced but its directory could not be synced: %w: %w", path, errRootFileNotDurable, err)
	}
	return nil
}

// errRootFileNotDurable marks a writeRootFile failure that happened after the
// rename: the new content is in place, only its durability is unproven.
var errRootFileNotDurable = errors.New("root file replaced but not durable")

// swapRetainedStacks exchanges current.yml and previous.yml after a rollback and
// reports whether they were identical. The swap is two renames, so a failure of
// the first one that left the file replaced (errRootFileNotDurable) must not
// skip the second: returning there would leave both slots holding the rollback
// target and the undone release would be lost. Any other first-write error
// changed nothing and returns at once, as before. Both outcomes are joined.
func swapRetainedStacks(current, previous string) (bool, error) {
	currentBody, currentErr := os.ReadFile(current)
	previousBody, previousErr := os.ReadFile(previous)
	if currentErr != nil || previousErr != nil {
		return false, errors.New("cannot rotate retained stacks after rollback")
	}
	identical := bytes.Equal(currentBody, previousBody)
	firstErr := writeRootFile(current, previousBody, 0o600)
	if firstErr != nil && !errors.Is(firstErr, errRootFileNotDurable) {
		return identical, firstErr
	}
	return identical, errors.Join(firstErr, writeRootFile(previous, currentBody, 0o600))
}

func rotateRetainedStacksAfterRollback(current, previous string) (bool, error) {
	var identical bool
	err := rootRetainedStacksShared(func() error {
		var err error
		identical, err = swapRetainedStacks(current, previous)
		return err
	})
	return identical, err
}

// runFixedValue reads one value from a command's stdout. It exists beside
// runFixedOutput because the two answer different questions: combined output is
// what an operator needs to read a failure, but a value that is going to be
// parsed must not have a warning the daemon printed on stderr glued to it : a
// parse that fails on "WARNING: ...\n5" would rewrite a cluster setting on
// every promotion to correct a value that was right all along.
func runFixedValue(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s timed out after %s", filepath.Base(name), timeout)
	}
	if err != nil {
		reason := strings.TrimSpace(stderr.String())
		if reason == "" {
			// A command that never ran : missing binary, refused exec : has
			// no stderr; the error itself is then the only account of it.
			reason = err.Error()
		}
		return "", fmt.Errorf("%s failed: %s", filepath.Base(name), reason)
	}
	return string(output), nil
}

func runFixed(name string, args ...string) error {
	command := exec.Command(name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %s", filepath.Base(name), strings.TrimSpace(string(output)))
	}
	return nil
}

func containsWord(value, word string) bool {
	for _, candidate := range strings.Fields(value) {
		if candidate == word {
			return true
		}
	}
	return false
}

func hasSSHDDirective(body []byte, expected string) bool {
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == expected {
			return true
		}
	}
	return false
}

// verifyEffectiveAllowUsers compares the accounts sshd actually allows against
// the ones the installed baseline names.
//
// The comparison is a set, in both directions. Missing an account is the
// lockout this whole check exists to prevent; an extra one is a host allowing
// somebody the signed baseline never approved, which is the same question asked
// from the other side.
func verifyEffectiveAllowUsers(effective []byte, allowUsers string) error {
	want := strings.Fields(strings.ToLower(allowUsers))
	var got []string
	for _, line := range strings.Split(string(effective), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(strings.ToLower(line)), "allowusers "); ok {
			got = append(got, strings.Fields(rest)...)
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(slices.Compact(want), slices.Compact(got)) {
		return fmt.Errorf("effective sshd configuration does not match the signed baseline: it allows %v, the baseline names %v; confirm that %s reads %q before setting AllowUsers itself",
			got, want, rootSSHDMainPath, rootSSHDIncludeLine)
	}
	return nil
}
