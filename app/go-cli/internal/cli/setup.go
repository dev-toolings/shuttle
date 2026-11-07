package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
)

type setupOptions struct {
	config          configFlags
	target          string
	expectedHostKey string
	publicKeyPath   string
	helperBinary    string
	operatorUser    string
	operatorKeyPath string
	operator        *setupOperatorAccess
	// retainUsers are the --retain-user flags as typed; retained is the merged,
	// validated, sorted list of existing accounts the signed baseline keeps
	// able to log in without changing anything else about them.
	retainUsers []string
	retained    []string
	dryRun      bool
	yes         bool
	// adopt opts a host that is already in service into convergence. It is the
	// only thing that relaxes the first-contact user or the foreign-resource
	// refusal; without it every check below behaves exactly as it did before
	// the flag existed.
	adopt bool
	// allowReboot lets an adoption complete a reboot the host's own packages
	// already require. It exists because the alternative — rebooting a host
	// that is serving traffic because a convergence run happened to reach that
	// point — is a decision about someone else's production window, and
	// Shuttle does not get to make it silently. A fresh setup still reboots
	// unconditionally: nothing is running on it yet.
	allowReboot bool
	// cutoverEdge lets an adoption take 80 and 443 from whatever answers on
	// them today and hand them to the shared Shuttle edge. It is opt-in for
	// the same reason --allow-reboot is: the ports are held by a container
	// that is serving requests right now, Docker cannot bind a host-mode port
	// twice, and so the switch is an outage — short, but an outage. An
	// operator asks for it; a convergence run never decides it.
	cutoverEdge bool
	// unmanaged lets an adoption take a host that no Shuttle generation ever
	// installed. The survey refuses such a host by default, because "adopt"
	// has always meant "converge what Shuttle already set up" and the marker
	// it looks for is how it tells a Shuttle host from an unrelated machine.
	// A host in service that Shuttle never touched is a different decision —
	// its containers, its accounts and its firewall are somebody else's — so
	// it is asked for by name, and the plan says what claiming it changes.
	unmanaged bool
	// lockOutFirstContactUser removes the login this adoption arrived on,
	// while retaining deploy and a separately declared administrator.
	//
	// Preserving that account is the default because it is the one the
	// operator is holding the session open with, and on a host adopted from a
	// previous generation it is usually also the account that generation's
	// deployments still run through: signing an AllowUsers list without it
	// ends the run by cutting the branch it is sitting on. Strict hardening is
	// where this is going, so it has a flag rather than a comment — but it has
	// to be asked for, once the operator knows nothing else depends on that
	// login. A different administrator must be configured before removing it.
	lockOutFirstContactUser bool
}

// setupMode says whether the convergence stages are generated for a fresh VPS
// or for a host that is already serving traffic.
//
// It exists so the difference is one explicit value threaded through the
// generators instead of a second copy of each script. setupModeFresh must
// produce byte-identical programs to the ones that shipped before adoption
// could apply anything; TestSetupStagesAreUnchangedWithoutAdoption asserts it.
type setupMode int

const (
	setupModeFresh setupMode = iota
	setupModeAdoption
)

func (m setupMode) adopting() bool { return m == setupModeAdoption }

// setupRunner executes a generated root program on the host.
//
// A fresh setup connects as root and runs the program as the remote shell's
// command, exactly as it always has. An adoption usually connects as an
// operator account, so the same program travels on standard input to
// `sudo -n sh -s`: the script is never concatenated with a command line, and
// sudo is proven non-interactive before this type is ever constructed.
type setupRunner struct {
	client *shuttlessh.Client
	sudo   bool
}

func (r setupRunner) run(program string) shuttlessh.Result {
	if !r.sudo {
		return r.client.Run(program)
	}
	// sudo resets the environment, so a stage run through it loses
	// SSH_CONNECTION -- the only place the operator's address is available.
	// The base stage reads it to exempt that address from fail2ban, and under
	// `set -u` an unset variable aborted the whole stage: adoption from a sudo
	// account could not get past 10-base. Forward the value explicitly.
	return r.client.RunWithStdin(`sudo -n env SSH_CONNECTION="${SSH_CONNECTION:-}" sh -s`, []byte(program))
}

// applySigned hands one signed root operation to the helper over this runner's
// channel. The envelope travels on standard input, exactly as it does for a
// fresh setup; only the way the helper is reached differs.
func (r setupRunner) applySigned(envelope []byte) shuttlessh.Result {
	return r.client.RunWithStdin(rootHelperApplyCommand(r.sudo), envelope)
}

// rootHelperApplyCommand is the remote command line a signed operation is fed
// to. It is a function of one bit — whether this channel has to become root
// first — and it is separate so the two spellings can be asserted without a
// host: which channel a rollback travels on is the difference between an
// automatic recovery and a message saying one was attempted.
func rootHelperApplyCommand(sudo bool) string {
	if sudo {
		return "sudo -n /usr/local/libexec/shuttle-root apply"
	}
	return "/usr/local/libexec/shuttle-root apply"
}

type setupIdentity struct {
	// user is the login used at first contact. It is "root" for every run
	// except an adoption, which may connect as a sudo-capable operator because
	// a host in service usually has root SSH closed already.
	user                   string
	host                   string
	port                   int
	operatorKey            string
	operatorKeyFingerprint string
}

type setupOperatorAccess struct {
	user        string
	publicKey   string
	fingerprint string
}

func newSetupCommand() *cobra.Command {
	var options setupOptions
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Configure and harden one fresh Shuttle VPS",
		Args:  cobra.NoArgs,
		// A refused setup is an operational error, not a usage mistake: the
		// full flag help after "this host was already set up" buried the
		// copyable --adopt command (VM e2e, 2026-10-28).
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetup(cmd, options)
		},
	}
	addConfigFlags(cmd, &options.config)
	cmd.Flags().StringVar(&options.target, "target", "", "literal first-contact target root@IP[:port]")
	cmd.Flags().StringVar(&options.expectedHostKey, "expected-host-key", "", "out-of-band ED25519 host fingerprint (SHA256:...)")
	cmd.Flags().StringVar(&options.publicKeyPath, "public-key", "", "public key already installed for root and to install for deploy")
	cmd.Flags().StringVar(&options.helperBinary, "helper-binary", "", "Linux shuttle binary to install as the root helper")
	cmd.Flags().StringVar(&options.operatorUser, "operator-user", "", "root-equivalent administrator account (required unless adoption retains an administrator)")
	cmd.Flags().StringVar(&options.operatorKeyPath, "operator-public-key", "", "distinct public key to authorize for the emergency operator")
	cmd.Flags().StringArrayVar(&options.retainUsers, "retain-user", nil, "existing account that keeps SSH access after hardening, left otherwise untouched; repeatable, merged with setup.retained_users")
	cmd.Flags().BoolVar(&options.dryRun, "dry-run", false, "perform the verified read-only preflight and print the convergence plan")
	cmd.Flags().BoolVar(&options.yes, "yes", false, "confirm the remote setup")
	cmd.Flags().BoolVar(&options.adopt, "adopt", false, "converge a host already in service: allow a sudo user at first contact and survey the existing deployment instead of refusing it")
	cmd.Flags().BoolVar(&options.allowReboot, "allow-reboot", false, "with --adopt, allow this run to complete a reboot the host's packages already require")
	cmd.Flags().BoolVar(&options.cutoverEdge, "cutover-edge", false, "with --adopt, stop the container that holds 80/443 and hand those ports to the shared Shuttle edge; the incumbent is restarted if the edge does not become healthy")
	cmd.Flags().BoolVar(&options.unmanaged, "unmanaged", false, "with --adopt, take a host in service that no Shuttle generation ever set up; the survey otherwise refuses it as an unrelated machine")
	cmd.Flags().BoolVar(&options.lockOutFirstContactUser, "lock-out-first-contact-user", false, "with --adopt, the first-contact account loses SSH access; requires a different --operator-user and --operator-public-key")
	return cmd
}

func runSetup(cmd *cobra.Command, options setupOptions) error {
	started := time.Now()
	cfg, err := loadWithFlags(options.config)
	if err != nil {
		return err
	}
	if cfg.UsesCompose() {
		return errors.New("shuttle setup does not apply to deploy.strategy: compose: that strategy deploys to a host nobody may change, as an account that already exists; switch to deploy.strategy: swarm to set a host up")
	}
	identity, err := validateSetupIdentity(cfg, options)
	if err != nil {
		return err
	}
	operator, err := resolveSetupOperatorAccess(cfg, options, identity.operatorKeyFingerprint)
	if err != nil {
		return err
	}
	options.operator = operator
	if operator != nil {
		cfg.Setup.OperatorUser = operator.user
	}
	retained, err := resolveSetupRetainedUsers(cfg, options, operator)
	if err != nil {
		return err
	}
	options.retained = retained
	// Written back so cfg.AllowedSSHUsers() — what the host identity records
	// and what every later audit expects — includes accounts retained by flag.
	cfg.Setup.RetainedUsers = retained
	// --allow-reboot is refused rather than ignored outside adoption: a fresh
	// setup already completes the package reboot it caused, so a flag that
	// looks like it grants something would be granting nothing.
	if options.allowReboot && !options.adopt {
		return errors.New("--allow-reboot only applies to --adopt; a fresh setup always completes the reboot its own package installation requires")
	}
	// The same reasoning as --allow-reboot: outside adoption both of these
	// would grant nothing, and a flag that grants nothing is worse than a flag
	// that does not exist. A fresh VPS has no incumbent on 80/443 to cut over
	// from, and no first-contact account to preserve — it is reached as root,
	// and closing root is what the baseline has always done.
	if options.cutoverEdge && !options.adopt {
		return errors.New("--cutover-edge only applies to --adopt; a fresh setup deploys the shared edge because nothing else on that host is listening on 80/443")
	}
	if options.lockOutFirstContactUser && !options.adopt {
		return errors.New("--lock-out-first-contact-user only applies to --adopt; a fresh setup requires a separate administrator")
	}
	if options.unmanaged && !options.adopt {
		return errors.New("--unmanaged only applies to --adopt; a fresh setup already expects a host nothing has set up, and refuses one that is in service")
	}
	if err := requireSetupAdministrator(identity, options); err != nil {
		return err
	}
	if err := refuseRetainedFirstContactLockOut(identity, options); err != nil {
		return err
	}
	if options.adopt {
		if !options.dryRun && options.yes {
			adoptClient, err := shuttlessh.NewClientExactWithFingerprint(identity.host, identity.user, identity.port, options.expectedHostKey)
			if err != nil {
				return err
			}
			retained, err := retainedInfrastructureImagesForSetup(cfg, adoptClient, identity.user != "root")
			if err != nil {
				return err
			}
			if err := resolveConfiguredInfrastructure(context.Background(), cfg, true, retained); err != nil {
				return err
			}
		}
		return runSetupAdoption(cmd.OutOrStdout(), cfg, identity, options, started)
	}
	client, err := shuttlessh.NewClientExactWithFingerprint(identity.host, identity.user, identity.port, options.expectedHostKey)
	if err != nil {
		return err
	}
	if err := setupReadOnlyPreflight(client, cfg, identity, options); err != nil {
		return err
	}
	if err := preflightSetupOperator(setupRunner{client: client}, operator); err != nil {
		return err
	}
	if err := preflightSetupRetainedUsers(setupRunner{client: client}, options.retained); err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), setupPlanWithOperator(identity, resolvedSetupDatabaseVersion(cfg), operator))
	fmt.Fprint(cmd.OutOrStdout(), setupRetainedUsersSummary(identity, options.retained))
	if options.dryRun {
		fmt.Fprintln(cmd.OutOrStdout(), "Preflight verified; no remote state was changed.")
		return nil
	}
	if !options.yes {
		return errors.New("remote setup requires explicit --yes confirmation (use --dry-run first)")
	}

	retainedImages, err := retainedInfrastructureImagesForSetup(cfg, client, identity.user != "root")
	if err != nil {
		return err
	}
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, true, retainedImages); err != nil {
		return err
	}
	if err := infrastructureSecurityCheck(cfg, true); err != nil {
		return err
	}

	helperPath, err := resolveLinuxHelper(options.helperBinary)
	if err != nil {
		return err
	}
	privateKeyPath, publicTrustPath, err := ensureRootOperationKeyPair()
	if err != nil {
		return err
	}
	publicTrust, err := os.ReadFile(publicTrustPath)
	if err != nil {
		return err
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		return err
	}

	runner := setupRunner{client: client}
	if err := installSetupHost(runner, cmd.OutOrStdout(), cfg, identity, operator, publicTrust, helper); err != nil {
		return err
	}
	if err := convergeDirectSSHService(runner, cmd.OutOrStdout()); err != nil {
		return err
	}
	if err := setupSharedCaddy(client, cfg); err != nil {
		return err
	}
	if err := completePendingSetupReboot(runner, cmd.OutOrStdout(), cfg.App, identity.operatorKeyFingerprint, options.expectedHostKey); err != nil {
		return err
	}
	if result := client.Run(setupInfrastructureProofCommand()); result.Code != 0 {
		return fmt.Errorf("refusing to disable root: infrastructure proof failed: %s", strings.TrimSpace(result.Stderr))
	}

	deployClient, err := shuttlessh.NewClientExactWithFingerprint(identity.host, "deploy", identity.port, options.expectedHostKey)
	if err != nil {
		return fmt.Errorf("refusing to disable root: deploy SSH proof failed: %w", err)
	}
	proof := deployClient.Run(deployLeastPrivilegeProofSource)
	if proof.Code != 0 {
		return fmt.Errorf("refusing to disable root: deploy least-privilege proof failed: %s", proof.Stderr)
	}
	if operator != nil {
		if err := proveSetupOperator(identity, options.expectedHostKey, operator); err != nil {
			return fmt.Errorf("refusing to disable root: %w", err)
		}
	}

	privateKey, err := rootplan.ReadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	envelopes, err := prepareBaselineEnvelopes(identity, options.expectedHostKey, privateKey, time.Now(), setupExtraSSHUsers(operator, options.retained))
	if err != nil {
		return err
	}
	if err := saveTrustedHostIdentity(trustedHostIdentity{Version: 2, Host: identity.host, Port: identity.port, HostKeyFingerprint: options.expectedHostKey, OperatorKeyFingerprint: identity.operatorKeyFingerprint, AllowedSSHUsers: cfg.AllowedSSHUsers()}); err != nil {
		return fmt.Errorf("persist verified VPS identity before SSH hardening: %w", err)
	}
	recoveryClient := deployClient
	rollback := func(cause error) error {
		rollbackResult := runAfterSSHDReload(func() shuttlessh.Result {
			return recoveryClient.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelopes.rollback)
		})
		if rollbackResult.Code != 0 {
			return fmt.Errorf("%w; CRITICAL: automatic SSH root rollback failed: %s", cause, strings.TrimSpace(rollbackResult.Stderr))
		}
		return fmt.Errorf("%w; the previous SSH root configuration was restored automatically", cause)
	}

	result := client.RunWithStdin("/usr/local/libexec/shuttle-root apply", envelopes.baseline)
	if result.Code != 0 {
		return rollback(fmt.Errorf("signed SSH hardening failed: %s", strings.TrimSpace(result.Stderr)))
	}

	deployClient, err = dialAfterSSHDReload(identity, options, "deploy")
	if err != nil {
		return rollback(fmt.Errorf("post-hardening deploy SSH proof failed: %w", err))
	}
	recoveryClient = deployClient
	if result = runAfterSSHDReload(func() shuttlessh.Result {
		return deployClient.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelopes.audit)
	}); result.Code != 0 {
		return rollback(fmt.Errorf("post-hardening signed audit failed: %s", strings.TrimSpace(result.Stderr)))
	}
	if operator != nil {
		if err := proveSetupOperator(identity, options.expectedHostKey, operator); err != nil {
			return rollback(fmt.Errorf("post-hardening %w", err))
		}
	}
	if result = deployClient.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelopes.commit); result.Code != 0 {
		return rollback(fmt.Errorf("commit signed SSH hardening failed: %s", strings.TrimSpace(result.Stderr)))
	}
	fmt.Fprint(cmd.OutOrStdout(), setupAccessSummary(identity, []string{operator.user}))
	fmt.Fprint(cmd.OutOrStdout(), setupRetainedUsersSummary(identity, options.retained))
	return finishSetup(cmd.OutOrStdout(), cfg.Setup.SLOSeconds, time.Since(started))
}

// installSetupHost keeps the fresh order in one tested place. stages[1:] skips
// the safety stage on purpose, so losing the first call would silently replace
// a helper that still owns a pending destroy journal (DEV-DEPL-102).
func installSetupHost(runner setupRunner, out io.Writer, cfg *config.Config, identity setupIdentity, operator *setupOperatorAccess, publicTrust, helper []byte) error {
	client := runner.client
	// Refuse before uploads or host convergence can change an installed host.
	stages := setupStages(cfg, identity.port, setupModeFresh)
	if err := runSetupStages(runner, out, stages[:1]); err != nil {
		return err
	}
	if result := client.UploadContent(identity.operatorKey+"\n", "/tmp/shuttle-operator.pub", 0o600); result.Code != 0 {
		return fmt.Errorf("upload deploy key: %s", result.Stderr)
	}
	if operator != nil {
		if result := client.UploadContent(operator.publicKey+"\n", "/tmp/shuttle-emergency-operator.pub", 0o600); result.Code != 0 {
			return fmt.Errorf("upload emergency operator key: %s", result.Stderr)
		}
	}
	if result := client.UploadContent(string(publicTrust), "/tmp/shuttle-root-trust.pem", 0o600); result.Code != 0 {
		return fmt.Errorf("upload root-operation trust key: %s", result.Stderr)
	}
	if result := client.UploadContent(string(helper), "/tmp/shuttle-root", 0o700); result.Code != 0 {
		return fmt.Errorf("upload root helper: %s", result.Stderr)
	}

	return runSetupStages(runner, out, stages[1:])
}

// convergeDirectSSHService removes Debian's socket-activation race before the
// signed hardening transaction starts. sshd re-execs itself on SIGHUP; when
// ssh.socket still owns the listening port, the replacement daemon cannot bind
// and both the hardening reload and its rollback lose their transport.
//
// Switching to ssh.service has its own trap, seen on two fresh Ubuntu 24.04
// hosts out of two on 2026-10-27: the base stage's package upgrade (needrestart
// or the openssh postinst) leaves an `sshd -D` listener running inside
// ssh.service's cgroup that is not the unit's MainPID. Ubuntu ships the unit
// with KillMode=process, so stopping or restarting it never kills that process,
// and `systemctl restart ssh.service` died with "Bind to port 22 on 0.0.0.0
// failed: Address already in use" while the journal said "Found left-over
// process in control group". Setup failed on a host that was otherwise sound.
// The manual repair that kept the operator's session alive was to SIGTERM that
// one listener and start the unit: sessions are its children and survive.
//
// The script now does exactly that, and nothing broader. It reaps a process
// listening on TCP 22 only if it is not the unit's MainPID and is provably an
// sshd listener orphaned to init (see the orphan rule below). Anything else on
// port 22 (a web server, an sshd of another parent, a session) stops setup with
// its PID and arguments in the message and is never killed, because guessing
// wrong would cut the only transport to the host. It never uses `systemctl
// kill`, `--kill-whom=all` or `pkill sshd`, which would take the sessions down
// with the listener. After the restart it requires every listener on port 22 to
// be the new MainPID (PID 1 included: a socket still held by systemd is not a
// converged host), so a leftover cannot pass as one. When no orphan exists the
// commands and their order are unchanged; the additions are read-only checks.
//
// The conversion also runs when ssh.service is not active, not only when
// ssh.socket is enabled. The first version keyed on the socket alone, so a
// setup that failed after `disable --now ssh.socket` (the bind failure above,
// a refused foreign listener, a crash) left a host with no socket and a dead
// service, and the rerun skipped the block and failed on the final is-active
// check: that host could never repair itself. Disabling an already disabled
// socket is harmless, and a host already on a healthy direct ssh.service (socket
// not enabled, service active) is still not touched.
//
// A reaped orphan is reported on the setup output even when setup succeeds. The
// script says so on stderr, which was only shown when it failed, so the one run
// that actually killed a process on the host (VM 242, PID 11025, 2026-10-27)
// left no trace of it on the operator's screen. Only the "stopping orphan sshd
// listener" lines are forwarded: the rest of stderr on success is systemctl's
// own chatter ("Removed ...", "Created symlink ...").
// runAfterSSHDReload runs one command right after the SSH baseline reloaded
// sshd, retrying only while the TCP connect is refused. On the 2026-10-28 VM
// e2e (Debian 13, DEV-DEPL-64) sshd took a SIGHUP restart in the very second
// setup sent the post-hardening audit: "post-hardening signed audit failed:
// dial tcp 192.168.1.244:22: connect: connection refused; CRITICAL: automatic
// SSH root rollback failed" on a host that was correctly hardened. A refused
// connect proves nothing ran, so the signed envelope was never consumed and a
// retry is safe; any other failure (authentication, host key, a refusal from
// the helper) is returned at once. The wait is bounded by the same budget as
// adoption's post-reload login proof.
//
// Only a typed pre-session refusal is retried (Result.ConnectRefused): stderr
// text could come from a remote command that did run. No new attempt starts
// once the budget is spent, and the pause never runs past it; an attempt that
// does start keeps its own client timeouts, so a running signed operation is
// never cut short.
func runAfterSSHDReload(run func() shuttlessh.Result) shuttlessh.Result {
	return runAfterSSHDReloadWithin(adoptionLoginProofBudget, adoptionLoginProofPoll, run)
}

func runAfterSSHDReloadWithin(budget, poll time.Duration, run func() shuttlessh.Result) shuttlessh.Result {
	deadline := time.Now().Add(budget)
	for {
		result := run()
		if result.Code == 0 || !result.ConnectRefused {
			return result
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return result
		}
		time.Sleep(min(poll, remaining))
		if time.Until(deadline) <= 0 {
			return result
		}
	}
}

func convergeDirectSSHService(runner setupRunner, out io.Writer) error {
	result := runner.run(setupDirectSSHServiceCommand())
	if result.Code != 0 {
		return fmt.Errorf("converge direct SSH service before hardening: %s", strings.TrimSpace(result.Stderr))
	}
	reportReapedSSHListeners(out, result.Stderr)
	return nil
}

// reportReapedSSHListeners copies the script's "stopping orphan sshd listener"
// lines from a successful run to the setup output.
func reportReapedSSHListeners(out io.Writer, stderr string) {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "stopping orphan sshd listener ") {
			fmt.Fprintf(out, "  -> %s\n", line)
		}
	}
}

// setupDirectSSHServiceCommand is the POSIX sh program convergeDirectSSHService
// runs as root. It is a function so tests can parse it and run it against stub
// commands; every external command is invoked by name for that reason, and the
// one path root used to read a process, proc=/proc on the first line, is the
// single line a test swaps for a fixture directory.
//
// Orphan rule: the exact predicate applied to a non-MainPID listener on TCP 22
// before it receives SIGTERM. All four must hold, read from /proc/PID:
//
//   - the parent PID (stat) is 1: a listener that a login session or another
//     daemon still owns is not an orphan (the unit's own MainPID is excluded
//     before this);
//   - comm is exactly "sshd" (the kernel name, which sshd's process-title
//     rewrite does not change), so a daemon that merely renames its title is
//     not matched;
//   - the cgroup file holds the line 0::/system.slice/ssh.service (cgroup v2,
//     Ubuntu 24.04), so the process is the one stranded in this unit's control
//     group. A legitimate sshd run by another unit, a container or by hand, or
//     a host on another cgroup layout, is refused with the usual message;
//   - the command line is an sshd listener: "sshd: ... [listener] ..." (the
//     title OpenSSH sets once it listens) or "/usr/sbin/sshd -D" / "sshd -D"
//     (before the title is rewritten). "sshd: user@pts/0", "sshd-session" and
//     the like never match.
//
// Why /proc and not ps: the first version read these with
// `ps -o ppid= -o comm= -o cgroup= -o args=`, whose columns are padded and
// width-limited (the cgroup is truncated), so a real orphan would have been
// refused and the incident left unfixed. /proc has no such limit. stat is
// parsed after its LAST ") " because comm may itself contain spaces and
// parentheses; the fields after it are state, ppid, ... and the start time
// (field 22 overall). cmdline arrives NUL separated and is turned into spaces.
//
// PID 1 is never a candidate. While ssh.socket is still active, ss lists
// systemd on the same line as the real owner (users:(("sshd",pid=X,..),
// ("systemd",pid=1,..))); that is the socket fd, gone once the socket is
// stopped. The reap loop skips it silently, but the post-restart verification
// does not: a PID 1 still holding port 22 after the restart fails the run.
//
// A listed PID whose /proc entry cannot be read is refused when ss still lists
// it (we cannot prove what it is) and skipped when it has already left ss (it
// exited between the two commands).
//
// Just before SIGTERM the process is read again and must be identical: same
// start time, ppid, comm and cgroup. A different start time means the PID was
// reused by another process, which is refused, not killed. The command line is
// compared only up to "[listener]" because OpenSSH appends a live "N of
// 10-100 startups" counter that a connecting scanner changes between the two
// reads; comparing it would refuse a perfectly good orphan. One race remains,
// accepted: between that last read and `kill` the PID could still be reused.
// POSIX sh has no pidfd to close it, and the window is a few milliseconds.
func setupDirectSSHServiceCommand() string {
	return `set -eu
proc=/proc
ssh_listener_pids() {
  ss -Hltnp 'sport = :22' | tr ',' '\n' | sed -n 's/^pid=\([0-9][0-9]*\)$/\1/p' | sort -u
}
listeners_match_unit() {
  unit_main=$(systemctl show -p MainPID --value ssh.service)
  [ -n "$unit_main" ] && [ "$unit_main" != 0 ] || return 1
  found=$(ssh_listener_pids)
  [ -n "$found" ] || return 1
  for found_pid in $found; do
    [ "$found_pid" = "$unit_main" ] || return 1
  done
}
read_proc() {
  rp_dir="$proc/$1"
  rp_stat=$(cat "$rp_dir/stat" 2>/dev/null) || return 1
  rp_comm=$(cat "$rp_dir/comm" 2>/dev/null) || return 1
  rp_cgroup=$(cat "$rp_dir/cgroup" 2>/dev/null) || return 1
  rp_args=$(cat "$rp_dir/cmdline" 2>/dev/null | tr '\000' ' ' | sed 's/ *$//; s/\[listener\].*/[listener]/')
  rp_rest=${rp_stat##*) }
  set -- $rp_rest
  [ "$#" -ge 20 ] || return 1
  rp_state=$1
  rp_ppid=$2
  shift 19
  rp_start=$1
  rp_identity="$rp_start|$rp_ppid|$rp_comm|$rp_cgroup|$rp_args"
}
still_running() {
  kill -0 "$1" 2>/dev/null || return 1
  read_proc "$1" || return 1
  [ "$rp_state" != Z ]
}
reap_orphan_sshd_listeners() {
  # systemd keeps a stale MainPID on a unit it already reports inactive: on
  # fresh Ubuntu 24.04 VMs (2026-10-28) the sshd that needrestart started kept
  # TCP 22 after ssh.socket stopped, its unit went inactive with MainPID still
  # naming it, and this exclusion spared it, so the restart could not bind and
  # systemd then removed /run/sshd: the host lost SSH. Spare MainPID only
  # while the unit is really active.
  unit_main=$(systemctl show -p MainPID --value ssh.service)
  if ! systemctl is-active --quiet ssh.service; then unit_main=none; fi
  for pid in $(ssh_listener_pids); do
    if [ "$pid" = 1 ] || [ "$pid" = "$unit_main" ]; then
      continue
    fi
    if ! read_proc "$pid"; then
      if ssh_listener_pids | grep -qx "$pid"; then
        echo "refusing to touch PID $pid listening on TCP 22: $proc/$pid cannot be read, free port 22 manually" >&2
        exit 1
      fi
      continue
    fi
    first=$rp_identity
    ppid=$rp_ppid
    comm=$rp_comm
    cgroup=$(printf '%s\n' "$rp_cgroup" | tr '\n' ' ')
    args=$rp_args
    orphan=0
    if [ "$ppid" = 1 ] && [ "$comm" = sshd ] && printf '%s\n' "$rp_cgroup" | grep -qx '0::/system.slice/ssh.service'; then
      case "$args" in
        "sshd: "*"[listener]"*|"/usr/sbin/sshd -D"*|"sshd -D"*) orphan=1 ;;
      esac
    fi
    if [ "$orphan" != 1 ]; then
      echo "refusing to touch PID $pid listening on TCP 22 (ppid=$ppid comm=$comm cgroup=$cgroup args=$args): it is not an orphan sshd listener of ssh.service, free port 22 manually" >&2
      exit 1
    fi
    if ! read_proc "$pid" || [ "$rp_identity" != "$first" ]; then
      echo "refusing to kill PID $pid: it changed between the ownership check and the kill (start time, parent, name or cgroup differ: the PID may have been reused)" >&2
      exit 1
    fi
    echo "stopping orphan sshd listener PID $pid (left in ssh.service's cgroup, not its MainPID)" >&2
    kill -TERM "$pid"
    waited=0
    while still_running "$pid"; do
      if [ "$waited" -ge 5 ]; then
        echo "orphan sshd listener PID $pid is still running 5 seconds after SIGTERM" >&2
        exit 1
      fi
      sleep 1
      waited=$((waited + 1))
    done
  done
}
# cloud-init's ssh module regenerates host keys and restarts ssh on first
# boot. Converting the socket while it runs left Ubuntu 24.04 with no sshd at
# all on the 2026-10-28 VM e2e ("Found left-over process ... in control
# group", "Bind to port 22 ... Address already in use", "Missing privilege
# separation directory: /run/sshd"): wait for it to finish first.
if command -v cloud-init >/dev/null 2>&1; then timeout 900 cloud-init status --wait >/dev/null 2>&1 || true; fi
# A conversion that cannot bring ssh.service up must never leave the host
# without a listener: give port 22 back to ssh.socket before failing.
restore_socket() {
  echo "$1" >&2
  systemctl stop ssh.service 2>/dev/null || true
  # A stranded listener would keep TCP 22 and refuse every login without
  # /run/sshd; free the port, recreate the directory, then give it back.
  # In a subshell: the reaper exits on a listener it refuses to touch, and
  # that must not skip giving the port back.
  ( reap_orphan_sshd_listeners ) || true
  install -d -m 0755 /run/sshd
  if systemctl enable --now ssh.socket >/dev/null 2>&1 && ssh_listener_pids | grep -qx 1; then
    echo "ssh.socket now listens on TCP 22 again" >&2
  else
    echo "ssh.socket could not take TCP 22 back; restart the host from its provider console" >&2
  fi
  exit 1
}
if systemctl is-enabled --quiet ssh.socket 2>/dev/null || ! systemctl is-active --quiet ssh.service; then
  command -v ss >/dev/null || { echo "ss is required to see who listens on TCP 22" >&2; exit 1; }
  systemctl disable --now ssh.socket
  # Stop the service explicitly so its state is known (stopped) before the
  # reap, whatever stopping the socket did to it.
  systemctl stop ssh.service
  reap_orphan_sshd_listeners
  install -d -m 0755 /run/sshd
  systemctl enable ssh.service
  systemctl restart ssh.service || restore_socket "ssh.service failed to start"
  attempt=0
  until listeners_match_unit; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 5 ]; then
      restore_socket "after restarting ssh.service, TCP 22 listeners ($(ssh_listener_pids | tr '\n' ' ')) are not exactly its MainPID ($(systemctl show -p MainPID --value ssh.service))"
    fi
    sleep 1
  done
fi
systemctl is-active --quiet ssh.service
sshd -t
`
}

// finishSetup is the terminal decision of a converged host: report the budget,
// then succeed. Like finishSwarmDeploy it has no failing branch by design.
//
// The old code returned an error whose own text read "host remains converged",
// which says exactly what was wrong with it: the VPS was configured, hardened,
// SSH-locked down and proven, and `shuttle setup` still exited non-zero. A buyer
// on a slow provider mirror saw their first contact with the product fail on a
// stopwatch and had no way to tell that outcome apart from a real convergence
// failure. Every genuine failure — a stage that errors, a negative
// infrastructure proof, a deploy user that is not least-privileged, a failed SSH
// hardening — is still an error raised by the checks above, each of which rolls
// back before returning.
func finishSetup(out io.Writer, sloSeconds int, total time.Duration) error {
	fmt.Fprintf(out, "Setup converged safely in %s.\n", total.Round(time.Second))
	reportSetupSLO(measureSetupSLO(sloSeconds, total))
	return nil
}

// setupSLOOutcome is the finished setup compared to its configured budget.
type setupSLOOutcome struct {
	Measured time.Duration
	Budget   time.Duration
	Missed   bool
}

// measureSetupSLO compares a converged host against setup.slo_seconds and
// returns a measurement only — never an error.
//
// The budget now comes from the configuration instead of a hard-coded ten
// minutes. setup.slo_seconds was written into every generated config.json and
// validated on load while setup.go ignored it entirely, so the only setting the
// file offered about setup regulated nothing at all.
func measureSetupSLO(sloSeconds int, total time.Duration) setupSLOOutcome {
	budget := time.Duration(sloSeconds) * time.Second
	if budget <= 0 {
		budget = time.Duration(config.DefaultSetupSLOSeconds) * time.Second
	}
	return setupSLOOutcome{Measured: total, Budget: budget, Missed: total > budget}
}

func reportSetupSLO(outcome setupSLOOutcome) {
	if !outcome.Missed {
		output.OK("Setup SLO met: %s <= %s", formatDeployDuration(outcome.Measured), formatDeployDuration(outcome.Budget))
		return
	}
	output.Attn("Setup SLO missed: %s > %s (the host is converged and hardened; raise %s if this is normal for your provider)",
		formatDeployDuration(outcome.Measured), formatDeployDuration(outcome.Budget), "setup.slo_seconds")
}

type baselineEnvelopes struct {
	baseline []byte
	audit    []byte
	rollback []byte
	commit   []byte
}

// prepareBaselineEnvelopes seals the four envelopes of the SSH hardening
// transaction.
//
// extraSSHUsers are accounts kept able to log in beyond deploy. The wire format
// still supports the historical baseline without extra users; setup now gates
// that low-level capability with a required surviving administrator.
func prepareBaselineEnvelopes(identity setupIdentity, hostFingerprint string, privateKey ed25519.PrivateKey, now time.Time, extraSSHUsers []string) (baselineEnvelopes, error) {
	constructors := []func(string, string, time.Time, time.Duration) (rootplan.Plan, error){
		func(operatorKeyFingerprint, host string, at time.Time, validity time.Duration) (rootplan.Plan, error) {
			return rootplan.NewBaselineWithSSHUsers(operatorKeyFingerprint, host, extraSSHUsers, at, validity)
		},
		rootplan.NewAudit,
		rootplan.NewBaselineRollback,
		rootplan.NewBaselineCommit,
	}
	encoded := make([][]byte, 0, len(constructors))
	for _, construct := range constructors {
		plan, err := construct(identity.operatorKeyFingerprint, hostFingerprint, now, 5*time.Minute)
		if err == nil {
			plan, err = rootplan.Sign(plan, privateKey)
		}
		if err != nil {
			return baselineEnvelopes{}, err
		}
		envelope, err := encodeRootHelperEnvelope(plan, nil)
		if err != nil {
			return baselineEnvelopes{}, err
		}
		encoded = append(encoded, envelope)
	}
	return baselineEnvelopes{baseline: encoded[0], audit: encoded[1], rollback: encoded[2], commit: encoded[3]}, nil
}

func validateSetupIdentity(resolved *config.Config, options setupOptions) (setupIdentity, error) {
	target, err := parseSSHTarget(options.target)
	if err != nil {
		return setupIdentity{}, err
	}
	// Without --adopt this is unchanged: first contact is root, full stop.
	// With it, a host in service is reached through an operator account,
	// because closing root SSH is precisely what a previously converged host
	// did. What is relaxed is who logs in; the host still has to match the
	// out-of-band fingerprint checked below and by the SSH client itself.
	if !options.adopt {
		if target.User != "root" {
			return setupIdentity{}, errors.New("setup first contact must use --target root@IP[:port]")
		}
	} else if !adoptionUserPattern.MatchString(target.User) {
		return setupIdentity{}, errors.New("--adopt first contact must name its login explicitly, as --target user@IP[:port]")
	}
	var configuredHost string
	var configuredPort int
	for _, group := range resolved.Servers {
		configuredHost, configuredPort = group.Hosts[0], group.Port
	}
	if target.Host != configuredHost || target.Port != configuredPort {
		return setupIdentity{}, fmt.Errorf("--target must match the literal VPS endpoint in config.json (%s:%d)", configuredHost, configuredPort)
	}
	if options.expectedHostKey == "" {
		return setupIdentity{}, errors.New("--expected-host-key is required and must come from the provider console")
	}
	if strings.TrimSpace(options.publicKeyPath) == "" {
		return setupIdentity{}, errors.New("--public-key is required")
	}
	body, err := os.ReadFile(options.publicKeyPath)
	if err != nil {
		return setupIdentity{}, fmt.Errorf("read --public-key: %w", err)
	}
	key, _, _, rest, err := gossh.ParseAuthorizedKey(bytes.TrimSpace(body))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return setupIdentity{}, errors.New("--public-key must contain exactly one OpenSSH public key")
	}
	return setupIdentity{user: target.User, host: target.Host, port: target.Port, operatorKey: strings.TrimSpace(string(body)), operatorKeyFingerprint: gossh.FingerprintSHA256(key)}, nil
}

func resolveSetupOperatorAccess(cfg *config.Config, options setupOptions, deployKeyFingerprint string) (*setupOperatorAccess, error) {
	user := strings.TrimSpace(cfg.Setup.OperatorUser)
	keyPath := strings.TrimSpace(cfg.Setup.OperatorPublicKey)
	keyFromFlag := false
	if value := strings.TrimSpace(options.operatorUser); value != "" {
		user = value
	}
	if value := strings.TrimSpace(options.operatorKeyPath); value != "" {
		keyPath, keyFromFlag = value, true
	}
	if (user == "") != (keyPath == "") {
		return nil, errors.New("--operator-user and --operator-public-key must be declared together, either as flags or under setup")
	}
	if user == "" {
		return nil, nil
	}
	if !adoptionUserPattern.MatchString(user) || user == "root" || user == "deploy" {
		return nil, errors.New("operator user must be a lowercase Unix account other than root or deploy")
	}
	resolvedPath, err := resolveSetupOperatorKeyPath(options.config, keyPath, keyFromFlag)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("read operator public key: %w", err)
	}
	key, _, _, rest, err := gossh.ParseAuthorizedKey(bytes.TrimSpace(body))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("operator public key must contain exactly one OpenSSH public key")
	}
	fingerprint := gossh.FingerprintSHA256(key)
	if fingerprint == deployKeyFingerprint {
		return nil, errors.New("operator public key must be distinct from deploy's public key")
	}
	return &setupOperatorAccess{user: user, publicKey: strings.TrimSpace(string(body)), fingerprint: fingerprint}, nil
}

func resolveSetupOperatorKeyPath(flags configFlags, value string, fromFlag bool) (string, error) {
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, strings.TrimPrefix(value, "~/")), nil
	}
	if filepath.IsAbs(value) || fromFlag {
		return filepath.Abs(value)
	}
	configPath := flags.path
	if configPath == "" {
		found, err := config.FindDefault()
		if err != nil {
			return "", err
		}
		configPath = found
	}
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(absConfig), value), nil
}

const setupOperatorProofSource = `set -eu
test "$(id -u)" -ne 0
test "$(sudo -n id -u)" = 0
sudo -n /usr/bin/docker info --format '{{.ServerVersion}}' >/dev/null
`

func proveSetupOperator(identity setupIdentity, hostFingerprint string, operator *setupOperatorAccess) error {
	client, err := shuttlessh.NewClientExactWithFingerprint(identity.host, operator.user, identity.port, hostFingerprint)
	if err != nil {
		return fmt.Errorf("operator SSH proof failed: %w", err)
	}
	proof := client.Run(setupOperatorProofSource)
	if proof.Code != 0 {
		return fmt.Errorf("operator root-equivalent sudo proof failed: %s", strings.TrimSpace(proof.Stderr))
	}
	return nil
}

const setupReadOnlyPreflightSource = `set -eu
. /etc/os-release
printf 'os=%s version=%s\n' "$ID" "$VERSION_ID"
case "$ID:$VERSION_ID" in ubuntu:24.04|debian:13) ;; *) exit 42;; esac
test "$(id -u)" = 0
ssh-keygen -lf /root/.ssh/authorized_keys -E sha256 | awk '{print $2}' | grep -Fx "$1" >/dev/null
if [ ! -f /etc/shuttle/setup-state ] && [ ! -f /etc/shuttle/setup.d/10-base ]; then
  if command -v docker >/dev/null 2>&1 && { [ -n "$(docker ps -aq 2>/dev/null)" ] || [ -n "$(docker service ls -q 2>/dev/null)" ]; }; then exit 43; fi
  if command -v psql >/dev/null 2>&1 && [ -n "$(runuser -u postgres -- psql -Atqc "select datname from pg_database where datistemplate=false and datname <> 'postgres'" 2>/dev/null)" ]; then exit 43; fi
fi
`

func setupReadOnlyPreflight(client *shuttlessh.Client, cfg *config.Config, identity setupIdentity, options setupOptions) error {
	result := client.RunWithStdin("sh -s -- "+shell.Escape(identity.operatorKeyFingerprint), []byte(setupReadOnlyPreflightSource))
	return interpretSetupPreflightForHost(result, cfg, identity, options)
}

// A saved setup identity explains an authentication failure only when the
// pinned host key still matches. Setup deliberately closes root SSH, so the
// durable recovery path is the trusted operator through --adopt, not a
// retry or a change to the root SSH policy.
func interpretSetupPreflightForHost(result shuttlessh.Result, cfg *config.Config, identity setupIdentity, options setupOptions) error {
	preflightErr := interpretSetupPreflight(result)
	if preflightErr == nil || !isSSHAuthenticationFailure(result) {
		return preflightErr
	}
	trusted, err := loadTrustedHostIdentity(identity.host, identity.port)
	if err != nil || options.expectedHostKey != trusted.HostKeyFingerprint {
		return preflightErr
	}
	operator := setupAdoptionOperatorUser(cfg, options, trusted)
	if operator == "" || options.publicKeyPath == "" {
		return preflightErr
	}
	command := setupAdoptionCommand(identity, operator, trusted, options)
	return fmt.Errorf("this host was already set up by Shuttle, which intentionally closes root SSH access. Use the configured operator account instead:\n  %s", command)
}

func isSSHAuthenticationFailure(result shuttlessh.Result) bool {
	message := strings.ToLower(result.Stderr)
	return result.Code == 255 && strings.Contains(message, "unable to authenticate") && strings.Contains(message, "attempted methods")
}

func setupAdoptionOperatorUser(cfg *config.Config, options setupOptions, trusted trustedHostIdentity) string {
	if options.operator != nil {
		return options.operator.user
	}
	if user := strings.TrimSpace(options.operatorUser); user != "" {
		return user
	}
	if user := strings.TrimSpace(cfg.Setup.OperatorUser); user != "" {
		return user
	}
	retained := make(map[string]bool, len(options.retained)+len(cfg.Setup.RetainedUsers))
	for _, user := range append(append([]string(nil), options.retained...), cfg.Setup.RetainedUsers...) {
		retained[user] = true
	}
	var candidates []string
	for _, user := range trusted.AllowedSSHUsers {
		if user == "" || user == "root" || user == "deploy" || retained[user] {
			continue
		}
		candidates = append(candidates, user)
	}
	candidates = sortedUnique(candidates)
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
}

func setupAdoptionCommand(identity setupIdentity, operator string, trusted trustedHostIdentity, options setupOptions) string {
	host := identity.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if identity.port != 22 {
		host += ":" + strconv.Itoa(identity.port)
	}
	arguments := []string{"shuttle", "setup", "--adopt"}
	configPath := options.config.path
	if configPath == "" {
		configPath, _ = config.FindDefault()
	}
	if configPath != "" {
		arguments = append(arguments, "--config", shell.Escape(configPath))
	}
	if options.config.env != "" {
		arguments = append(arguments, "--env", shell.Escape(options.config.env))
	}
	arguments = append(arguments,
		"--target", shell.Escape(operator+"@"+host),
		"--expected-host-key", shell.Escape(trusted.HostKeyFingerprint),
		"--public-key", shell.Escape(options.publicKeyPath),
	)
	if options.helperBinary != "" {
		arguments = append(arguments, "--helper-binary", shell.Escape(options.helperBinary))
	}
	if options.operator != nil {
		if strings.TrimSpace(options.operatorUser) != "" {
			arguments = append(arguments, "--operator-user", shell.Escape(operator))
		}
		if options.operatorKeyPath != "" {
			arguments = append(arguments, "--operator-public-key", shell.Escape(options.operatorKeyPath))
		}
	}
	for _, user := range options.retainUsers {
		arguments = append(arguments, "--retain-user", shell.Escape(user))
	}
	if options.dryRun {
		arguments = append(arguments, "--dry-run")
	}
	if options.yes {
		arguments = append(arguments, "--yes")
	}
	return strings.Join(arguments, " ")
}

// interpretSetupPreflight maps the preflight's typed exit codes to the verdicts
// `setup` has always returned. It is split out so those verdicts can be
// asserted as text: --adopt must not move any of them.
func interpretSetupPreflight(result shuttlessh.Result) error {
	if result.Code == 42 {
		return fmt.Errorf("unsupported VPS OS: %s", strings.TrimSpace(result.Stdout))
	}
	if result.Code == 43 {
		return errors.New("VPS contains foreign Docker or PostgreSQL resources; refusing setup")
	}
	if result.Code != 0 {
		return fmt.Errorf("verified setup preflight failed (root key, OS, or inventory): %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

// setupPostgresPlanLabel names, in the plan an operator reads before confirming,
// the PostgreSQL the run will end up with. A declared version is named; an
// undeclared one cannot be, because the answer is on the host — so the plan
// states the rule instead of inventing a number.
func setupPostgresPlanLabel(version int) string {
	if version == 0 {
		return fmt.Sprintf("PostgreSQL (the supported cluster already on the host, otherwise %d)", config.DefaultDatabaseVersion)
	}
	return fmt.Sprintf("PostgreSQL %d", version)
}

func setupPlan(identity setupIdentity, databaseVersion int) string {
	return setupPlanWithOperator(identity, databaseVersion, nil)
}

func setupPlanWithOperator(identity setupIdentity, databaseVersion int, operator *setupOperatorAccess) string {
	if operator == nil {
		return "Setup cannot proceed without an administrator: supply --operator-user ops --operator-public-key ~/.ssh/ops_ed25519.pub. No Linux password is generated.\n"
	}
	return fmt.Sprintf(`Verified Shuttle setup plan for root@%s:%d
  1. install security baseline, Docker CE/Buildx, %s
  2. initialize one-node Swarm and a loopback persistent registry
  3. create deploy with the attested key and no sudo/docker membership
  4. create %s with its distinct key (%s) and explicit NOPASSWD root access
  5. install the Ed25519-verified typed root helper
  6. complete one required package reboot and verify the attested host returns
  7. prove every retained SSH path, then disable root/password/keyboard-interactive SSH
  8. retain checkpoints for safe idempotent resume
`, identity.host, identity.port, setupPostgresPlanLabel(databaseVersion), operator.user, operator.fingerprint) + setupAccessSummary(identity, []string{operator.user})
}

func completePendingSetupReboot(runner setupRunner, out io.Writer, app, owner, host string) error {
	// A read-only probe avoids a reservation when no reboot is needed. The
	// scheduling program checks the pending flag again under the common flock.
	probe := runner.run(`set -eu; cat /proc/sys/kernel/random/boot_id; if [ -e /var/run/reboot-required ]; then exit 75; fi`)
	if probe.Code == 0 && strings.TrimSpace(probe.Stdout) != "" {
		return nil
	}
	if probe.Code != 75 {
		return fmt.Errorf("inspect setup reboot requirement: %s", probe.Stderr)
	}
	report, err := completeCoordinatedSetupReboot(runner, app, owner, host)
	fmt.Fprintf(out, "  -> package reboot %s operation=%s\n", report.State, report.OperationID)
	return err
}

func rebootCompleted(before string, result shuttlessh.Result) bool {
	after := strings.TrimSpace(result.Stdout)
	return result.Code == 0 && after != "" && after != strings.TrimSpace(before)
}

func resolveLinuxHelper(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	current, err := os.Executable()
	if err == nil && runtime.GOOS == "linux" {
		return current, nil
	}
	return "", errors.New("setup apply from a non-Linux workstation requires --helper-binary pointing to a Linux Shuttle release binary")
}

func ensureRootOperationKeyPair() (string, string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(configDir, "shuttle", "v2")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	privatePath := filepath.Join(dir, "root-operations.pem")
	publicPath := filepath.Join(dir, "root-operations.pub.pem")
	if _, err := os.Stat(privatePath); os.IsNotExist(err) {
		if err := rootplan.GenerateKeyPair(privatePath, publicPath); err != nil {
			return "", "", err
		}
	}
	return privatePath, publicPath, nil
}

// setupStage is one checkpointed convergence step and the program that
// converges it.
type setupStage struct {
	name    string
	command string
}

// setupStages is the ordered list of stages both `setup` and `setup --adopt`
// execute, in the same order, guarded by the same /etc/shuttle/setup.d
// checkpoints — which is what makes either of them resumable.
//
// Shared-edge cutover and signed SSH hardening run afterwards. The operator
// stage is deliberately not checkpoint-skipped: resuming can add a missing key
// or finish publishing sudo access before the SSH proof is attempted again.
func setupStages(cfg *config.Config, sshPort int, mode setupMode) []setupStage {
	stages := []setupStage{
		{"helper-safety", setupHelperReplacementGuard},
		{"base", setupBaseCommandWithPolicies(mode, cfg.Setup.SwapMode, cfg.Setup.AppArmorMode)},
		{"docker", setupDockerCommand(mode, cfg.ResolvedInfrastructure["registry"])},
		{"postgres", setupPostgresCommandWithBackupRetention(resolvedSetupDatabaseVersion(cfg), cfg.App, cfg.Retention.Backups)},
		{"runtime", setupRuntimeCommand(sshPort, cfg.AllowedPublicTCPPorts(), mode)},
	}
	if cfg.Setup.OperatorUser != "" {
		stages = append(stages, setupStage{"operator", setupOperatorCommand(cfg.Setup.OperatorUser)})
	}
	return stages
}

func runSetupStages(runner setupRunner, out io.Writer, stages []setupStage) error {
	for _, stage := range stages {
		fmt.Fprintf(out, "  -> %s\n", stage.name)
		result := runner.run(stage.command)
		if result.Code != 0 {
			return fmt.Errorf("setup stage %s failed safely: %s", stage.name, strings.TrimSpace(result.Stderr))
		}
	}
	return nil
}

func checkpoint(stage, body string) string {
	return fmt.Sprintf("set -eu\ninstall -d -m 0700 /etc/shuttle/setup.d\nif [ ! -f /etc/shuttle/setup.d/%s ]; then\n%s\ntouch /etc/shuttle/setup.d/%s\nfi\n", stage, body, stage)
}

// setupBaseCommand installs the security baseline.
//
// On a fresh VPS it also runs `apt-get dist-upgrade -y`, which is the right
// thing to do to a machine nobody depends on yet: it is empty, and starting it
// on held-back kernel and security updates would ship a host that is out of
// date on day one.
//
// On a host in service that same command is an unrequested change to software
// the operator did not ask Shuttle to touch — it can pull a new kernel, restart
// services underneath running workloads and leave a reboot pending — so
// adoption installs exactly the packages the baseline needs and upgrades
// nothing else. Unattended-upgrades is still enabled, so security updates
// continue to arrive on the host's own schedule rather than on Shuttle's.
func setupBaseCommand(mode setupMode) string {
	return setupBaseCommandWithPolicies(mode, "managed", "managed")
}

func setupBaseCommandWithSwap(mode setupMode, swapMode string) string {
	return setupBaseCommandWithPolicies(mode, swapMode, "managed")
}

func setupBaseCommandWithPolicies(mode setupMode, swapMode, appArmorMode string) string {
	upgrade := "apt-get dist-upgrade -y\n"
	if mode.adopting() {
		upgrade = ""
	}
	swap := `if ! swapon --show=NAME --noheadings | grep -q .; then
  fallocate -l 2G /swapfile
  chmod 0600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -Fqx '/swapfile none swap sw 0 0' /etc/fstab || printf '%s\n' '/swapfile none swap sw 0 0' >>/etc/fstab
fi
`
	if swapMode == "host" {
		swap = "# Swap is owned by the host kernel (for example for an unprivileged LXC).\n"
	}
	services := "systemctl enable --now apparmor fail2ban unattended-upgrades systemd-timesyncd\n"
	if appArmorMode == "host" {
		services = "# AppArmor profile loading is owned by the host kernel.\nsystemctl enable --now fail2ban unattended-upgrades systemd-timesyncd\n"
	}
	// jq is what 20-docker edits /etc/docker/daemon.json with on an adopted
	// host (see setupDockerCommand). A fresh VPS has no daemon.json to edit,
	// and its package list must not move.
	packages := ""
	if mode.adopting() {
		packages = " jq"
	}
	// A fresh cloud VM may still be running cloud-init, or the apt-daily
	// timers, when setup starts: on the 2026-10-28 VM e2e setup failed with
	// "E: Could not get lock /var/lib/dpkg/lock-frontend". Setup waits for
	// cloud-init to finish, and every apt call waits for the dpkg lock
	// instead of failing on it.
	body := `export DEBIAN_FRONTEND=noninteractive
if command -v cloud-init >/dev/null 2>&1; then timeout 900 cloud-init status --wait >/dev/null 2>&1 || true; fi
printf 'DPkg::Lock::Timeout "600";\n' > /etc/apt/apt.conf.d/50shuttle-dpkg-lock
apt-get update -y
` + upgrade + `apt-get install -y ca-certificates curl gnupg sudo ufw fail2ban apparmor apparmor-utils unattended-upgrades openssh-server systemd-timesyncd` + packages + `
install -d -m 0755 /etc/apt/keyrings
printf '%s\n' 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' >/etc/apt/apt.conf.d/20auto-upgrades
` + services + `# Exempt the operator's own address from fail2ban.
#
# This stage installs fail2ban, and the SSH hardening that follows closes the
# first-contact account: on a host adopted as root, the signed baseline is
# "AllowUsers deploy" and root can no longer open a session. An operator who
# then retries root@ out of habit -- or whose tooling does -- spends five
# failed publickey auths and gets the SOURCE ADDRESS banned. fail2ban bans an
# IP, not an account, so the ban also severs the deploy@ access this very run
# just created, and the host becomes reachable only through the provider's
# out-of-band console.
#
# Measured on a real adoption (03-09-2026): five root@ attempts after the
# baseline applied, jail sshd reported "Currently banned: 1" with the
# operator's address, and every subsequent deploy@ connection was refused --
# on a host whose sshd was listening and whose UFW allowed 22/tcp. The
# deployment stalled there until someone opened a browser console.
#
# The operator is trusted by construction: they hold the key that signs every
# root operation on this host. Exempting the address they are converging from
# removes a trap Shuttle sets for itself. Addresses accumulate across runs, so
# adopting from a second workstation does not evict the first.
operator_ip="${SSH_CONNECTION:-}"
operator_ip="${operator_ip%% *}"
if [ -n "$operator_ip" ]; then
  install -d -m 0755 /etc/fail2ban/jail.d
  operator_jail=/etc/fail2ban/jail.d/10-shuttle-operator.conf
  ignored=""
  [ -f "$operator_jail" ] && ignored=$(sed -n 's/^ignoreip[[:space:]]*=[[:space:]]*//p' "$operator_jail" | head -1)
  [ -n "$ignored" ] || ignored="127.0.0.1/8 ::1"
  case " $ignored " in
    *" $operator_ip "*) ;;
    *) ignored="$ignored $operator_ip" ;;
  esac
  printf '%s\n' '# Written by shuttle setup: the operator address must never be banned.' '[DEFAULT]' "ignoreip = $ignored" >"$operator_jail"
  systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
fi
` + swap
	policy := `
# This drop-in is outside the 10-base checkpoint so a completed setup and
# adopted hosts converge to the policy doctor verifies on every invocation.
. /etc/os-release
case "$ID:$VERSION_ID" in
  ubuntu:24.04)
    unattended_policy='#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\nUnattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-security"; "${distro_id}ESMApps:${distro_codename}-apps-security"; "${distro_id}ESM:${distro_codename}-infra-security"; };\nUnattended-Upgrade::Automatic-Reboot "false";'
    ;;
  debian:13)
    unattended_policy='#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\nUnattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"; };\nUnattended-Upgrade::Automatic-Reboot "false";'
    ;;
  *) echo "unsupported unattended-upgrades policy for $ID $VERSION_ID" >&2; exit 1 ;;
esac
unattended_file=/etc/apt/apt.conf.d/52shuttle-unattended-upgrades
unattended_tmp=$(mktemp /etc/apt/apt.conf.d/.52shuttle-unattended-upgrades.XXXXXX)
printf '%b\n' "$unattended_policy" >"$unattended_tmp"
chmod 0644 "$unattended_tmp"
if ! cmp -s "$unattended_tmp" "$unattended_file"; then
  mv -f "$unattended_tmp" "$unattended_file"
else
  rm -f "$unattended_tmp"
fi
`
	return checkpoint("10-base", body) + policy
}

// Existing owned registry data is migrated before recreating the container.
// The root ownership helper is short-lived and gone before any audit runs.
const setupRegistryNonRootSource = `docker volume inspect shuttle-registry >/dev/null 2>&1 || docker volume create --label dev.shuttle.owner=system shuttle-registry >/dev/null
if docker container inspect shuttle-registry >/dev/null 2>&1; then
  registry_user=$(docker container inspect shuttle-registry --format '{{.Config.User}}')
  existing_image=$(docker container inspect shuttle-registry --format '{{.Config.Image}}')
  registry_mount=$(docker container inspect shuttle-registry --format '{{range .Mounts}}{{if eq .Destination "/var/lib/registry"}}{{.Type}}:{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}')
  if [ "$registry_mount" != volume:shuttle-registry ]; then
    echo "refusing to replace loopback registry: /var/lib/registry is mounted from ${registry_mount:-no mount}, expected volume:shuttle-registry" >&2
    exit 1
  fi
  if [ "$existing_image" != '__SHUTTLE_REGISTRY_IMAGE__' ]; then
    test "$(docker container inspect shuttle-registry --format '{{index .Config.Labels "dev.shuttle.owner"}}')" = system
    existing_tag=${existing_image#registry:}
    existing_tag=${existing_tag%%@*}
    desired_image='__SHUTTLE_REGISTRY_IMAGE__'
    desired_tag=${desired_image#registry:}
    desired_tag=${desired_tag%%@*}
    existing_major=$(printf '%s\n' "$existing_tag" | sed 's/[^0-9].*//')
    desired_major=$(printf '%s\n' "$desired_tag" | sed 's/[^0-9].*//')
    if [ "$existing_major" != "$desired_major" ]; then
      echo "registry major change $existing_major -> $desired_major requires an explicit migration" >&2
      exit 1
    fi
    # With a major-only tag such as registry:3, the order of two digests cannot be established. The resolved digest is the newest image for that major at resolution time over TLS from the fixed Hub hosts; an older image served under that tag is a supply-chain compromise that version comparison would not prevent. Keep the exact identity recorded for rollback.
    existing_version=$(printf '%s\n' "$existing_tag" | sed 's/[^0-9.].*//')
    desired_version=$(printf '%s\n' "$desired_tag" | sed 's/[^0-9.].*//')
    if [ "$desired_version" != "$desired_major" ] && [ "$(printf '%s\n%s\n' "$existing_version" "$desired_version" | sort -V | head -n 1)" = "$desired_version" ] && [ "$existing_version" != "$desired_version" ]; then
      echo "planned registry version $desired_version is older than running version $existing_version" >&2
      exit 1
    fi
    if [ "$existing_image" != "$desired_image" ]; then
      docker pull --quiet "$desired_image"
    fi
  fi
  if [ "$registry_user" != 10001:10001 ] || [ "$existing_image" != '__SHUTTLE_REGISTRY_IMAGE__' ]; then
    test "$(docker container inspect shuttle-registry --format '{{index .Config.Labels "dev.shuttle.owner"}}')" = system
    docker stop shuttle-registry >/dev/null
    docker rm shuttle-registry >/dev/null
  fi
fi
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges=true --entrypoint /bin/sh -v shuttle-registry:/var/lib/registry __SHUTTLE_REGISTRY_IMAGE__ -ec 'chown -R 10001:10001 /var/lib/registry'
`

const setupRegistryCreateSource = `docker container inspect shuttle-registry >/dev/null 2>&1 || docker run -d --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges=true --restart=always --name shuttle-registry --label dev.shuttle.owner=system --log-opt max-size=10m --log-opt max-file=3 --health-cmd '/bin/registry --version >/dev/null' --health-interval 5s --health-timeout 2s --health-retries 10 -e REGISTRY_STORAGE_DELETE_ENABLED=true -p 127.0.0.1:5000:5000 -v shuttle-registry:/var/lib/registry __SHUTTLE_REGISTRY_IMAGE__
`

// setupDockerGatewayMTUSource aligns docker_gwbridge with a network whose MTU
// is below 1500, before `swarm init` would create that bridge at Docker's
// default of 1500.
//
// On Google Cloud (1460), VXLAN-backed clouds (1450) and some VMs nested in
// Kubernetes (1400), the default-route interface cannot carry a 1500-byte
// frame. A Swarm task leaves the host through docker_gwbridge, so its TCP
// stack advertises an MSS sized for 1500, and every full-size segment is then
// dropped on the wire. DNS and handshakes still succeed, which is what makes
// the failure hard to read: Caddy's ACME order hangs, an application's calls
// to an external API time out, and nothing in the logs says why. FrankenDeploy
// hit the same defect on docker0 (yoanbernabeu/frankendeploy#112); under Swarm
// the bridge in the path is docker_gwbridge, and host-mode ports (the shared
// edge's 80/443) go through it too.
//
// The bridge can only be shaped before it exists: Docker documents creating
// it by hand, with these options, ahead of `swarm init`. A bridge that already
// exists belongs to a running Swarm, and recreating it means leaving the
// Swarm, so this stage leaves it alone and `doctor` reports the mismatch
// (docker.gateway_mtu). At 1500 or above, or when the MTU cannot be read,
// nothing is created and the stage behaves exactly as before.
const setupDockerGatewayMTUSource = `mtu_if=$(ip -o -4 route show default | awk '{print $5; exit}')
host_mtu=0
if [ -n "$mtu_if" ] && [ -r "/sys/class/net/$mtu_if/mtu" ]; then
  host_mtu=$(cat "/sys/class/net/$mtu_if/mtu")
fi
case "$host_mtu" in ''|*[!0-9]*) host_mtu=0 ;; esac
if [ "$host_mtu" -ge 1280 ] && [ "$host_mtu" -lt 1500 ] && ! docker network inspect docker_gwbridge >/dev/null 2>&1; then
  docker network create --driver bridge \
    --opt com.docker.network.bridge.name=docker_gwbridge \
    --opt com.docker.network.bridge.enable_icc=false \
    --opt com.docker.network.bridge.enable_ip_masquerade=true \
    --opt com.docker.network.driver.mtu="$host_mtu" \
    docker_gwbridge >/dev/null
fi
`

// setupDockerCommand is 20-docker. On a fresh VPS it is exactly the program
// it always was. On an adopted host two things differ, both because the host
// already runs a Docker somebody else configured:
//
//   - `live-restore` must be off before `docker swarm init`, which refuses it
//     outright ("--live-restore daemon configuration is incompatible with swarm
//     mode"). The setting is reloadable: the value in daemon.json is flipped
//     with jq so every other key survives (log rotation lives there), dockerd
//     is sent SIGHUP through `systemctl reload`, and not one container is
//     restarted by this run. What changes is later: with live-restore off, a
//     dockerd restart or a reboot stops and restarts every container on the
//     host per its restart policy. The plan says so before --yes.
//   - `swarm init` names its `--advertise-addr`. A cloud instance with a
//     private-network NIC can carry two global IPv4 addresses, and without the
//     flag `swarm init` stops on "could not choose an IP address to advertise".
//     The address is the one on the interface the default route leaves by,
//     derived the same way the firewall script derives "outside".
//
// Refusals rather than repairs: a daemon.json that is not JSON is somebody's
// hand-written file, and rewriting it would be guessing at what they meant.
func setupDockerCommand(mode setupMode, images ...string) string {
	swarmInit := `docker info --format '{{.Swarm.LocalNodeState}}' | grep -qx active || docker swarm init
`
	if mode.adopting() {
		swarmInit = `daemon_json=/etc/docker/daemon.json
if [ -f "$daemon_json" ]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to edit $daemon_json and is not installed; 10-base installs it on an adopted host, re-run setup" >&2
    exit 1
  fi
  if ! jq -e . "$daemon_json" >/dev/null 2>&1; then
    echo "$daemon_json is not valid JSON; it was written by hand, so fix it by hand before adoption turns live-restore off" >&2
    exit 1
  fi
  if [ "$(jq -r '.["live-restore"] // false' "$daemon_json")" = true ]; then
    cp -p "$daemon_json" "$daemon_json.shuttle-previous"
    jq '.["live-restore"] = false' "$daemon_json" >"$daemon_json.shuttle-next"
    jq -e . "$daemon_json.shuttle-next" >/dev/null
    mv -f "$daemon_json.shuttle-next" "$daemon_json"
    systemctl reload docker
  fi
fi
if [ "$(docker info --format '{{.LiveRestoreEnabled}}')" != false ]; then
  echo "dockerd still reports live-restore enabled, and Swarm cannot be initialised while it is; check $daemon_json and the systemd unit's ExecStart" >&2
  exit 1
fi
advertise_if=$(ip -o -4 route show default | awk '{print $5; exit}')
advertise=$(ip -o -4 addr show dev "$advertise_if" scope global | awk '{print $4; exit}' | cut -d/ -f1)
if [ -z "$advertise" ]; then
  echo 'cannot determine the address to advertise the Swarm node on: no global IPv4 on the default-route interface' >&2
  exit 1
fi
docker info --format '{{.Swarm.LocalNodeState}}' | grep -qx active || docker swarm init --advertise-addr "$advertise"
test "$(docker info --format '{{.LiveRestoreEnabled}}')" = false
`
	}
	body := `if ! command -v docker >/dev/null 2>&1; then
  . /etc/os-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  arch=$(dpkg --print-architecture)
  . /etc/os-release
  echo "deb [arch=$arch signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID ${VERSION_CODENAME} stable" >/etc/apt/sources.list.d/docker.list
  apt-get update -y
  # stack deploy ignores security_opt. Configure the daemon before its first
  # package start, so Swarm tasks inherit no-new-privileges without a second rollout.
  # Existing configuration belongs to the operator; doctor reports any gap.
  if [ ! -e /etc/docker/daemon.json ]; then
    install -m 0755 -d /etc/docker
    printf '%s\n' '{"no-new-privileges":true}' >/etc/docker/daemon.json
  fi
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
` + setupDockerGatewayMTUSource + swarmInit + `if docker network inspect caddy_network >/dev/null 2>&1; then
  edge_driver=$(docker network inspect caddy_network --format '{{.Driver}}')
  if [ "$edge_driver" != overlay ]; then
    echo "caddy_network already exists as a '$edge_driver' network; Swarm services cannot attach to it, so the shared edge and every application would fail to converge." >&2
    echo "Docker cannot change a network's driver or rename it. Move whatever uses it to another network, remove caddy_network, then run setup again. Attached containers:" >&2
    docker network inspect caddy_network --format '{{range .Containers}}{{.Name}} {{end}}' >&2
    exit 1
  fi
else
  docker network create --driver overlay --attachable caddy_network
fi
docker volume inspect shuttle-registry >/dev/null 2>&1 || docker volume create --label dev.shuttle.owner=system shuttle-registry >/dev/null
` + setupRegistryNonRootSource + `
` + setupRegistryCreateSource + `
attempt=0
ready=0
while [ "$attempt" -lt 24 ]; do
  if [ "$(docker container inspect shuttle-registry --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null)" = healthy ] && curl -fsS --max-time 2 http://127.0.0.1:5000/v2/ >/dev/null; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$ready" != 1 ]; then
  docker container logs --tail 50 shuttle-registry >&2
  exit 1
fi
`
	registryImage := "__SHUTTLE_REGISTRY_IMAGE__"
	if len(images) > 0 && images[0] != "" {
		registryImage = images[0]
	}
	body = strings.ReplaceAll(body, "__SHUTTLE_REGISTRY_IMAGE__", registryImage)
	body = strings.ReplaceAll(body, "__SHUTTLE_REGISTRY_IMAGE__", registryImage)
	return checkpoint("20-docker", body) + checkpoint("21-registry-nonroot", strings.ReplaceAll(setupRegistryNonRootSource+setupRegistryCreateSource, "__SHUTTLE_REGISTRY_IMAGE__", registryImage))
}

// setupInfrastructureProofCommand is the gate a fresh setup must pass before
// root SSH is disabled. It proves the finished article: the shared edge is
// answering on 80/443, no reboot is pending, and no unit has failed. Nothing
// below is ever relaxed — an adopted host is proven by
// setupAdoptionProofCommand instead, which asserts a different set because a
// different set is what stages 10-base through 40-runtime are responsible for.
func setupInfrastructureProofCommand() string {
	return `set -eu
attempt=0
ready=0
while [ "$attempt" -lt 30 ]; do
  caddy_id=$(docker ps -q --filter label=com.docker.swarm.service.name=shuttle-edge_caddy | head -n 1)
  if test "$(docker container inspect shuttle-registry --format '{{.State.Running}}' 2>/dev/null)" = true \
    && test "$(docker container inspect shuttle-registry --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null)" = healthy \
    && curl -fsS --max-time 3 http://127.0.0.1:5000/v2/ >/dev/null 2>&1 \
    && docker service ls --filter name=shuttle-edge_caddy --format '{{.Name}} {{.Replicas}}' | grep -qx 'shuttle-edge_caddy 1/1' \
    && test -n "$caddy_id" \
    && systemctl is-active --quiet docker postgresql fail2ban ssh; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$ready" != 1 ]; then
  docker container inspect shuttle-registry --format 'registry={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{end}}' >&2 2>/dev/null || :
  docker service ls --filter name=shuttle-edge_caddy --format 'caddy={{.Replicas}}' >&2 2>/dev/null || :
  systemctl is-active docker postgresql fail2ban ssh >&2 2>/dev/null || :
  exit 1
fi
test "$(docker container inspect shuttle-registry --format '{{.HostConfig.RestartPolicy.Name}}')" = always
docker container inspect shuttle-registry --format '{{json .HostConfig.PortBindings}}' | grep -Fq '127.0.0.1'
docker exec "$caddy_id" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
fail2ban-client status sshd >/dev/null
ufw status | grep -qx 'Status: active'
iptables -C DOCKER-USER -j ufw-user-forward
iptables -C DOCKER-USER -j RETURN
iptables -S DOCKER-USER | grep -Fq -- '-j ufw-docker-logging-deny'
test ! -e /var/run/reboot-required
! systemctl --failed --no-legend --plain | grep -q .
! resolvectl status | grep -Eq '(\+LLMNR|\+mDNS|LLMNR/|mDNS/)'
`
}

// setupAdoptionProofCommand is the gate an adoption must pass at the end of
// 40-runtime. It proves what this run is accountable for and refuses to
// pretend about the rest.
//
// It cannot be the proof above. That one requires `shuttle-edge_caddy 1/1`,
// which an adopted host does not have because 50-caddy-direct is deliberately
// not run: the incumbent listener still holds 80/443 and taking those ports is
// a scheduled cutover, not a side effect of convergence. It also requires no
// pending reboot and no failed unit, neither of which this run promises: the
// reboot is the operator's window (--allow-reboot), and a unit that was
// already failing before Shuttle arrived is the host's pre-existing state, not
// something adoption caused or fixed.
//
// What it does prove is every artifact stages 10-base to 40-runtime create, and
// it proves the firewall against the same port list that generated it, so a
// declared public port that the rules missed fails the run instead of being
// discovered when the service stops answering.
func setupAdoptionProofCommand(sshPort int, publicTCPPorts []int) string {
	var b strings.Builder
	b.WriteString(`set -eu
attempt=0
ready=0
while [ "$attempt" -lt 30 ]; do
  if test "$(docker container inspect shuttle-registry --format '{{.State.Running}}' 2>/dev/null)" = true \
    && test "$(docker container inspect shuttle-registry --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null)" = healthy \
    && curl -fsS --max-time 3 http://127.0.0.1:5000/v2/ >/dev/null 2>&1 \
    && docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -qx active \
    && systemctl is-active --quiet docker postgresql fail2ban ssh; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$ready" != 1 ]; then
  docker container inspect shuttle-registry --format 'registry={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{end}}' >&2 2>/dev/null || :
  docker info --format 'swarm={{.Swarm.LocalNodeState}}' >&2 2>/dev/null || :
  systemctl is-active docker postgresql fail2ban ssh >&2 2>/dev/null || :
  exit 1
fi
test "$(docker container inspect shuttle-registry --format '{{.HostConfig.RestartPolicy.Name}}')" = always
docker container inspect shuttle-registry --format '{{json .HostConfig.PortBindings}}' | grep -Fq '127.0.0.1'
test -x /usr/local/libexec/shuttle-root
test -f /etc/shuttle/trusted-root-operations.pem
test -f /etc/shuttle/setup-state
id deploy >/dev/null
! id -nG deploy | tr ' ' '\n' | grep -Eqx '(sudo|docker)'
fail2ban-client status sshd >/dev/null
ufw status | grep -qx 'Status: active'
`)
	fmt.Fprintf(&b, "ufw status | grep -q '^%d/tcp'\n", sshPort)
	for _, port := range publicTCPPorts {
		fmt.Fprintf(&b, "ufw status | grep -q '^%d/tcp'\n", port)
	}
	b.WriteString(`iptables -C DOCKER-USER -j ufw-user-forward
iptables -C DOCKER-USER -j RETURN
iptables -S DOCKER-USER | grep -Fq -- '-j ufw-docker-logging-deny'
! resolvectl status | grep -Eq '(\+LLMNR|\+mDNS|LLMNR/|mDNS/)'
`)
	return b.String()
}

// supportedDatabaseVersionsShellList renders the supported majors as the
// word list the generated script iterates over. Interpolated from the config
// package rather than written out, so a residual /etc/postgresql/13 is never a
// candidate and a major added there is probed here without a second edit.
func supportedDatabaseVersionsShellList() string {
	parts := make([]string, 0, len(config.SupportedDatabaseVersions))
	for _, version := range config.SupportedDatabaseVersions {
		parts = append(parts, strconv.Itoa(version))
	}
	return strings.Join(parts, " ")
}

// resolvedSetupDatabaseVersion is the PostgreSQL major `setup` works on when
// the configuration declares one. Zero means it declared none, and the decision
// moves to the host — see setupPostgresCommand.
//
// Declaring database.version is not only a choice of major: it is what turns the
// application into a managed database, and the root helper then owns the role
// named after the application, password included (ensurePostgresRole issues
// ALTER ROLE ... PASSWORD on a role that already exists). On an adopted host
// carrying a hand-managed production database of the same name, that would
// reset a live credential. So an operator must be able to leave the block out
// entirely and still have setup use the cluster the host already has.
func resolvedSetupDatabaseVersion(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.Database.Version
}

// setupPostgresCommand generates the 30-postgres checkpoint for one PostgreSQL
// major.
//
// version is the major the configuration declared, or 0 when it declared none.
// The two cases differ only in how the generated script learns the number:
//
//	declared  the number is written into the script; the explicit choice wins,
//	          and a host that does not have that cluster gets it installed.
//	0         the script resolves it on the host — exactly one supported cluster
//	          under /etc/postgresql is adopted as it stands, none installs
//	          DefaultDatabaseVersion, and several is a question only the
//	          operator can answer, so it is refused rather than guessed.
//
// Resolution happens in the shell rather than in Go because /etc/postgresql is
// on the target, and `setup` has no read-only survey of it at this point.
//
// The install guard is the configuration file this step is about to edit, not
// `command -v psql`. A host carrying only postgresql-client — a routine thing,
// it arrives with plenty of packages — answers that probe, so the server
// install was skipped and the first sed died on a file that was never going to
// exist. Guarding on the artifact makes the check and the work agree by
// construction, and it is also what makes adoption free: a cluster that is
// already there is used, never reinstalled.
//
// gpg --dearmor refuses to overwrite, so --yes is what lets a checkpoint
// that failed after writing the keyring be retried at all.
// PostgreSQL dumps can contain application data and password hashes. Publish
// only a complete, verified archive and keep partial files private on failure.
const postgresBackupScript = `#!/bin/bash
set -euo pipefail
umask 077
dir=/var/backups/shuttle-postgres
retention_dir=/etc/shuttle/postgres-backup.d
exec 9>"$dir/.backup.lock"
flock -n 9
stamp=$(date -u +%Y%m%dT%H%M%SZ)
tmp=$(mktemp "$dir/.backup-$stamp.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
runuser -u postgres -- pg_dumpall | gzip -9 >"$tmp"
gzip -t "$tmp"
# The random suffix prevents a second backup in the same second from replacing
# an already valid archive. Both names live on the same filesystem.
mv -- "$tmp" "$dir/$stamp-${tmp##*.}.sql.gz"
# The timer is shared by every app on this host, so honor the most generous
# declared count. Old hosts and configs without a valid file keep the historic
# seven-archive default; malformed files are reported and ignored.
shopt -s nullglob
max_keep=0
for retention_file in "$retention_dir"/*.conf; do
  if [[ ! -f "$retention_file" ]]; then
    printf 'ignoring malformed PostgreSQL backup retention config: %s\n' "$retention_file" >&2
    continue
  fi
  mapfile -t retention_lines < "$retention_file"
  if (( ${#retention_lines[@]} != 1 )) || [[ ! ${retention_lines[0]} =~ ^keep=([1-7])$ ]]; then
    printf 'ignoring malformed PostgreSQL backup retention config: %s\n' "$retention_file" >&2
    continue
  fi
  value=${BASH_REMATCH[1]}
  if (( value > max_keep )); then
    max_keep=$value
  fi
done
keep=$max_keep
if (( keep == 0 )); then
  keep=7
fi
find "$dir" -maxdepth 1 -type f -name '*.sql.gz' -printf '%T@ %p\n' | sort -rn | sed -n "$((keep + 1)),\$p" | cut -d' ' -f2- | xargs -r rm --
`

// This is the immediately previous shipped policy. It is safe to replace
// because it differs only by lacking per-app retention; local edits are not.
const previousPostgresBackupScript = `#!/bin/bash
set -euo pipefail
umask 077
dir=/var/backups/shuttle-postgres
exec 9>"$dir/.backup.lock"
flock -n 9
stamp=$(date -u +%Y%m%dT%H%M%SZ)
tmp=$(mktemp "$dir/.backup-$stamp.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
runuser -u postgres -- pg_dumpall | gzip -9 >"$tmp"
gzip -t "$tmp"
# The random suffix prevents a second backup in the same second from replacing
# an already valid archive. Both names live on the same filesystem.
mv -- "$tmp" "$dir/$stamp-${tmp##*.}.sql.gz"
find "$dir" -maxdepth 1 -type f -name '*.sql.gz' -printf '%T@ %p\n' | sort -rn | sed -n '8,$p' | cut -d' ' -f2- | xargs -r rm --
`

// Match only known shipped policies. Local backup customizations are
// deliberately not overwritten by a checkpointed setup resume.
const legacyPostgresBackupScript = `#!/bin/sh
set -eu
dir=/var/backups/shuttle-postgres
stamp=$(date -u +%Y%m%dT%H%M%SZ)
tmp="$dir/.backup-$stamp.sql.gz"
runuser -u postgres -- pg_dumpall | gzip -9 >"$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$dir/$stamp.sql.gz"
find "$dir" -maxdepth 1 -type f -name '*.sql.gz' -printf '%T@ %p\n' | sort -rn | sed -n '8,$p' | cut -d' ' -f2- | xargs -r rm --
`

func postgresBackupRetentionConfig(app string, backups int) string {
	if backups == 0 {
		backups = 7
	}
	path := "/etc/shuttle/postgres-backup.d/" + app + ".conf"
	return fmt.Sprintf(`install -d -o root -g root -m 0700 /etc/shuttle/postgres-backup.d
retention_file=%s
install -o root -g root -m 0600 /dev/null "$retention_file"
printf 'keep=%d\n' >"$retention_file"
chown root:root "$retention_file"
chmod 0600 "$retention_file"
`, shell.Escape(path), backups)
}

func setupPostgresBackupMigration(app string, backups int) string {
	return `(
set -eu
umask 077
policy=/usr/local/sbin/shuttle-postgres-backup
if [ ! -f "$policy" ] || [ -L "$policy" ]; then
  echo 'managed PostgreSQL backup script is missing or symlinked; refusing automatic migration' >&2
  exit 1
fi
work=$(mktemp -d /usr/local/sbin/.shuttle-postgres-backup.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
cat >"$work/current" <<'SHUTTLE_BACKUP_CURRENT'
` + postgresBackupScript + `SHUTTLE_BACKUP_CURRENT
cat >"$work/previous" <<'SHUTTLE_BACKUP_PREVIOUS'
` + previousPostgresBackupScript + `SHUTTLE_BACKUP_PREVIOUS
cat >"$work/legacy" <<'SHUTTLE_BACKUP_LEGACY'
` + legacyPostgresBackupScript + `SHUTTLE_BACKUP_LEGACY
if cmp -s "$policy" "$work/current"; then
  :
elif cmp -s "$policy" "$work/previous"; then
  chmod 0700 "$work/current"
  mv -f -- "$work/current" "$policy"
elif cmp -s "$policy" "$work/legacy"; then
  chmod 0700 "$work/current"
  mv -f -- "$work/current" "$policy"
else
  echo 'managed PostgreSQL backup script differs from the known policy; refusing automatic migration' >&2
  exit 1
fi
` + postgresBackupRetentionConfig(app, backups) + `
)
`
}

func setupPostgresCommand(version int) string {
	return setupPostgresCommandWithBackupRetention(version, "demo", 7)
}

func setupPostgresCommandWithBackupRetention(version int, app string, backups int) string {
	// major is what the generated script substitutes wherever the version
	// appears. A declared version is written out literally, so a configuration
	// on 16 still produces the text it has always produced; a resolved one
	// travels as the shell variable the preamble below sets.
	major, preamble := strconv.Itoa(version), ""
	if version == 0 {
		major = "$version"
		preamble = fmt.Sprintf(`version=
found=
matched=0
for candidate in %s; do
  if [ -f "/etc/postgresql/$candidate/main/postgresql.conf" ]; then
    matched=$((matched + 1))
    version="$candidate"
    found="${found:+$found }$candidate"
  fi
done
if [ "$matched" -gt 1 ]; then
  echo "several supported PostgreSQL clusters are present ($found); declare database.version in config.json to name the one Shuttle must use" >&2
  exit 1
fi
if [ "$matched" -eq 0 ]; then
  version=%d
fi
`, supportedDatabaseVersionsShellList(), config.DefaultDatabaseVersion)
	}
	// The head is the only version-dependent part, and it carries no percent
	// sign, so it can be formatted; the tail below is kept verbatim because it
	// is full of printf formats that would have to be escaped for no reason.
	//
	// The port check exists because the `ss -lnt | grep 127.0.0.1:5432`
	// assertions further down prove that *something* answers on 5432, not that
	// the cluster this step just configured is the thing answering. On a host
	// with two clusters the target can sit on 5433, and every one of those
	// assertions would pass against the wrong database.
	//
	// It reads the configured port out of the postgresql.conf this step already
	// opened, rather than calling pg_lsclusters: that would be a new dependency
	// on postgresql-common, and it reports the port a cluster is *running* on,
	// which is the state this step is about to change by restarting. Debian's
	// packaging writes an explicit `port = ...` into every cluster's
	// postgresql.conf — 5432 for the first, 5433 for the next — so the answer is
	// already in the file. The last assignment is the one PostgreSQL honours,
	// hence `tail -n 1`; the leading `^[[:space:]]*port` will not match a
	// commented-out `#port` line. The pipeline's exit status is sed's, which
	// succeeds on empty input, so a conf with no port line leaves $port empty
	// and fails closed with "unknown" rather than aborting under `set -e`.
	// It runs before the first sed: a cluster Shuttle is going to refuse must
	// not be edited on the way to refusing it.
	head := fmt.Sprintf(`conf=/etc/postgresql/%[1]s/main/postgresql.conf
hba=/etc/postgresql/%[1]s/main/pg_hba.conf
if [ ! -f "$conf" ]; then
  . /etc/os-release
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor --yes -o /etc/apt/keyrings/postgresql.gpg
  echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" >/etc/apt/sources.list.d/pgdg.list
  apt-get update -y
  apt-get install -y postgresql-%[1]s postgresql-client-%[1]s
fi
if [ ! -f "$conf" ]; then
  echo "PostgreSQL %[1]s is not installed at /etc/postgresql/%[1]s/main after the install step; Shuttle requires the packaged postgresql-%[1]s server" >&2
  echo "clusters present: $(ls -1 /etc/postgresql 2>/dev/null | tr '\n' ' ')" >&2
  exit 1
fi
port=$(grep -E "^[[:space:]]*port[[:space:]]*=" "$conf" | tail -n 1 | sed -E "s/^[^=]*=[[:space:]]*([0-9]+).*/\1/")
if [ "$port" != 5432 ]; then
  echo "PostgreSQL %[1]s at /etc/postgresql/%[1]s/main is configured on port ${port:-unknown}, not 5432; Shuttle addresses the managed cluster on 5432" >&2
  exit 1
fi
`, major)
	body := preamble + head + `gateway=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Gateway}}')
subnet=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Subnet}}')
test -n "$gateway" && test -n "$subnet"
sed -i "s/^#\?password_encryption.*/password_encryption = 'scram-sha-256'/" "$conf"
sed -i "s/^#\?listen_addresses.*/listen_addresses = '127.0.0.1,$gateway'/" "$conf"
printf '%s\n' 'local all postgres peer' 'host all all 127.0.0.1/32 scram-sha-256' "host all all $subnet scram-sha-256" >"$hba"
systemctl enable --now postgresql
systemctl restart postgresql
ss -lnt | grep -F '127.0.0.1:5432' >/dev/null
ss -lnt | grep -F "$gateway:5432" >/dev/null
install -d -o root -g root -m 0700 /var/backups/shuttle-postgres
cat >/usr/local/sbin/shuttle-postgres-backup <<'SHUTTLE_BACKUP'
` + postgresBackupScript + `SHUTTLE_BACKUP
chmod 0700 /usr/local/sbin/shuttle-postgres-backup
` + postgresBackupRetentionConfig(app, backups) + `
printf '%s\n' '[Unit]' 'Description=Shuttle local PostgreSQL backup' '[Service]' 'Type=oneshot' 'ExecStart=/usr/local/sbin/shuttle-postgres-backup' >/etc/systemd/system/shuttle-postgres-backup.service
printf '%s\n' '[Unit]' 'Description=Daily Shuttle PostgreSQL backup' '[Timer]' 'OnCalendar=daily' 'Persistent=true' 'RandomizedDelaySec=10m' '[Install]' 'WantedBy=timers.target' >/etc/systemd/system/shuttle-postgres-backup.timer
systemctl daemon-reload
systemctl enable --now shuttle-postgres-backup.timer
/usr/local/sbin/shuttle-postgres-backup
`
	// The backup policy and its retention run on every setup, not behind a
	// checkpoint: hosts already marked 31-postgres-backup would otherwise never
	// receive a new script nor a changed postgres_backups value. Both steps are
	// idempotent (an identical script is left alone, the retention file is
	// rewritten with the same content).
	return checkpoint("30-postgres", body) + setupPostgresBackupMigration(app, backups) +
		checkpoint("32-postgres-boot-order", preamble+setupPostgresBootOrderBody(major))
}

// setupPostgresBootOrderBody orders the managed cluster after Docker.
//
// 30-postgres binds listen_addresses to the docker_gwbridge gateway, an address
// that only exists once dockerd has recreated the bridge. Debian's unit graph
// has no such edge, so on every reboot PostgreSQL came up first, silently
// dropped the address it could not bind and answered on loopback only: the
// application containers dialled the gateway and got "connection refused"
// until an operator restarted the cluster by hand (seen twice on one host on
// 2026-09-06). A drop-in on the cluster unit is the whole fix; it is its own
// checkpoint so hosts set up before it existed converge on the next setup run
// without re-running 30-postgres, and it resolves the major the same way that
// step does because 30's marker may already be present.
func setupPostgresBootOrderBody(major string) string {
	return fmt.Sprintf(`dropin=/etc/systemd/system/postgresql@%[1]s-main.service.d
install -d -m 0755 "$dropin"
printf '%%s\n' '# Written by shuttle setup (32-postgres-boot-order); do not edit.' '# listen_addresses includes the docker_gwbridge gateway: without this edge' '# PostgreSQL starts before Docker creates the bridge, binds loopback only,' '# and the managed database is unreachable from containers until a restart.' '[Unit]' 'After=docker.service' 'Wants=docker.service' >"$dropin/10-shuttle-after-docker.conf"
systemctl daemon-reload
`, major)
}

// setupRuntimeCommand creates the deploy user, installs the signed root helper
// and applies the host firewall policy.
//
// publicTCPPorts comes from config.AllowedPublicTCPPorts(), which always
// contains 80 and 443 and may contain more: a host in service can legitimately
// publish something else — an analytics container on 3000 is the case that
// forced this — and `ufw --force reset` below removes every rule the host had,
// so anything not generated from that list stops answering. The same list
// generates the UFW rules and the DOCKER-USER policy, so the packets the
// firewall accepts and the packets Docker forwards cannot drift apart.
func setupRuntimeCommand(sshPort int, publicTCPPorts []int, mode setupMode) string {
	var body strings.Builder
	fmt.Fprintf(&body, `id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy
# useradd leaves the home at the distribution default (0750 on Ubuntu), which
# the readiness check for this very account then fails on. The mode is set here
# so a freshly set up host does not audit dirty on its own doing.
install -d -o deploy -g deploy -m 0700 /home/deploy
install -d -o deploy -g deploy -m 0700 /home/deploy/.ssh
install -o deploy -g deploy -m 0600 /tmp/shuttle-operator.pub /home/deploy/.ssh/authorized_keys
gpasswd -d deploy sudo >/dev/null 2>&1 || true
gpasswd -d deploy docker >/dev/null 2>&1 || true
install -d -m 0755 /usr/local/libexec /etc/shuttle
install -o root -g root -m 0755 /tmp/shuttle-root /usr/local/libexec/shuttle-root
install -o root -g root -m 0444 /tmp/shuttle-root-trust.pem /etc/shuttle/trusted-root-operations.pem
install -d -m 0755 /etc/systemd/resolved.conf.d
printf '%%s\n' '[Resolve]' 'LLMNR=no' 'MulticastDNS=no' >/etc/systemd/resolved.conf.d/60-shuttle.conf
systemctl restart systemd-resolved
printf '%%s\n' '[sshd]' 'enabled = true' 'port = %d' >/etc/fail2ban/jail.d/shuttle-sshd.local
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow %d/tcp
`, sshPort, sshPort)
	for _, port := range publicTCPPorts {
		fmt.Fprintf(&body, "ufw allow %d/tcp\n", port)
	}
	body.WriteString("ufw allow 443/udp\n")
	// The managed PostgreSQL listens on the Docker gateway so containers can
	// reach it — that is the whole point of binding it there. But the gateway
	// is an address of the host, so a container connecting to it is INPUT
	// traffic, and the default-deny policy installed just above dropped it.
	// The database Shuttle provisions was therefore unreachable by the
	// application it exists to serve, on every host, and silently: the service
	// is up, the port is listening, and the connection simply times out.
	//
	// Opened only from the gateway's own subnet, and only on 5432: this is not
	// a hole in the firewall, it is the one path the design already assumed.
	body.WriteString(`gateway=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Gateway}}')
subnet=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Subnet}}')
if [ -n "$gateway" ] && [ -n "$subnet" ]; then
  ufw allow from "$subnet" to "$gateway" port 5432 proto tcp
else
  echo 'cannot determine the Docker gateway; the managed database would be unreachable from every container' >&2
  exit 1
fi
`)
	if mode.adopting() {
		body.WriteString(adoptionFirewallReachabilityGuard(sshPort))
	}
	body.WriteString("cat >/usr/local/libexec/shuttle-docker-user-firewall <<'SHUTTLE_DOCKER_FIREWALL'\n")
	firewallStart := body.Len()
	body.WriteString(`#!/bin/sh
set -eu
iptables=/usr/sbin/iptables
# UFW starts before networking and Docker at boot. There is no forwarding
# policy to apply until Docker creates this chain; the ordered systemd service
# applies it after Docker starts. A live chain still requires a valid route.
"$iptables" -S DOCKER-USER >/dev/null 2>&1 || exit 0
# The interface the default route leaves by is what "outside" means on this
# host. Derived rather than assumed: eth0 is a convention, not a guarantee.
external=$(ip -o -4 route show default | awk '{print $5; exit}')
if [ -z "$external" ]; then
  echo 'cannot determine the external interface; refusing to install a policy that would filter east-west traffic' >&2
  exit 1
fi
if ! "$iptables" -S ufw-user-forward >/dev/null 2>&1; then
  echo 'UFW user-forward chain is unavailable' >&2
  exit 1
fi
if "$iptables" -S ufw-docker-logging-deny >/dev/null 2>&1; then
  "$iptables" -F ufw-docker-logging-deny
else
  "$iptables" -N ufw-docker-logging-deny
fi
"$iptables" -F DOCKER-USER
"$iptables" -A DOCKER-USER -j ufw-user-forward
"$iptables" -A DOCKER-USER -p udp --sport 53 --dport 1024:65535 -j RETURN
# The edge publishes 80/443, and Docker DNATs those connections to the Caddy
# container, whose address lives inside the private ranges denied below. Without
# these three rules the deny list silently blackholes the shared edge, so a
# freshly set-up VPS answers SSH and nothing else: the site is unreachable and
# ACME can never complete its HTTP-01 or TLS-ALPN-01 challenge. Allow exactly the
# published edge ports, before the private-range denies, and nothing more.
`)
	for _, port := range publicTCPPorts {
		fmt.Fprintf(&body, "\"$iptables\" -A DOCKER-USER -p tcp --dport %d --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN\n", port)
	}
	body.WriteString(`"$iptables" -A DOCKER-USER -p udp --dport 443 -j RETURN
# DOCKER-USER governs what may enter from outside. The rules below match on
# destination alone, and DOCKER-USER is traversed by every forwarded packet —
# including the ones that never came from outside. With br_netfilter, traffic
# between two containers of the same bridge crosses FORWARD too, and it does so
# before Docker's own per-bridge ACCEPT rules. So a deny list written for
# ingress silently cut east-west traffic: an application could not reach its own
# database, a front end could not reach its API, and a container could not reach
# a service on the LAN. Nothing looked wrong — container healthchecks probe
# 127.0.0.1 inside their own namespace and never cross this chain — so the host
# reported healthy while returning 502 to every real request.
#
# Anything that did not arrive on the external interface is therefore not
# ingress, and this chain has no business filtering it.
"$iptables" -A DOCKER-USER ! -i "$external" -j RETURN
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 10.0.0.0/8 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 172.16.0.0/12 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -d 192.168.0.0/16 -p udp --dport 0:32767 -j ufw-docker-logging-deny
"$iptables" -A DOCKER-USER -j RETURN
"$iptables" -A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix '[UFW DOCKER BLOCK] '
"$iptables" -A ufw-docker-logging-deny -j DROP
`)
	firewallScript := body.String()[firewallStart:]
	body.WriteString(`SHUTTLE_DOCKER_FIREWALL
chmod 0755 /usr/local/libexec/shuttle-docker-user-firewall
cat >/etc/ufw/after.init <<'SHUTTLE_UFW_AFTER_INIT'
#!/bin/sh
set -eu
case "${1:-}" in
  start) /usr/local/libexec/shuttle-docker-user-firewall ;;
  stop|status|flush-all) ;;
  *) echo "Usage: after.init {start|stop|flush-all|status}" >&2; exit 1 ;;
esac
SHUTTLE_UFW_AFTER_INIT
chmod 0755 /etc/ufw/after.init
cat >/etc/systemd/system/shuttle-docker-user-firewall.service <<'SHUTTLE_DOCKER_FIREWALL_UNIT'
[Unit]
Description=Apply Shuttle UFW policy to Docker forwarding
After=ufw.service docker.service
Requires=docker.service
Wants=ufw.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/shuttle-docker-user-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SHUTTLE_DOCKER_FIREWALL_UNIT
systemctl daemon-reload
ufw --force enable
systemctl enable --now shuttle-docker-user-firewall.service
systemctl restart fail2ban
printf 'version=2\n' >/etc/shuttle/setup-state
`)
	// The helper and the key it trusts are installed on every run, outside the
	// checkpoint that guards the rest of this stage.
	//
	// The checkpoint exists so a converged host does not reinstall Docker or
	// re-run apt. Freezing the helper with them meant a host that had been set
	// up once could never receive a fix to it: `shuttle update` updates the
	// operator's own binary, and `setup` skipped the only step that ships the
	// remote one. A defect in the code that runs as root on every operator's
	// VPS had no route to those operators at all.
	//
	// The dedicated first stage retains destroy evidence with its installed
	// reader before uploads or any checkpointed host mutation can run.
	return checkpoint("40-runtime", body.String()) + checkpoint("41-firewall-boot", setupFirewallBootMigration(firewallScript)) + `install -d -m 0755 /usr/local/libexec /etc/shuttle
install -o root -g root -m 0755 /tmp/shuttle-root /usr/local/libexec/shuttle-root
install -o root -g root -m 0444 /tmp/shuttle-root-trust.pem /etc/shuttle/trusted-root-operations.pem
`
}

// Setup does not execute the signed update protocol or compare versions. An
// older --helper-binary must never inherit pending cleanup under older rules.
// Keep this temporary-file contract aligned with helperDestroyTemporaryPattern.
const setupHelperReplacementGuard = `set -eu
helper=/usr/local/libexec/shuttle-root
cleanup=/var/lib/shuttle/operations/destroy-cleanup
refuse_helper_replacement() {
  echo 'helper replacement refused while destroy cleanup evidence remains; recover with the installed helper first: docs/operations-recovery.md' >&2
  exit 1
}
if [ -e "$helper" ] || [ -L "$helper" ]; then
  if [ -e "$cleanup" ] || [ -L "$cleanup" ]; then
    [ -d "$cleanup" ] && [ ! -L "$cleanup" ] && [ -r "$cleanup" ] && [ -x "$cleanup" ] && [ "$(stat -c '%u:%a' "$cleanup")" = '0:700' ] || refuse_helper_replacement
    for entry in "$cleanup"/* "$cleanup"/.[!.]* "$cleanup"/..?*; do
      [ -e "$entry" ] || [ -L "$entry" ] || continue
      name=${entry##*/}
      case "$name" in
        .shuttle-root-*)
          suffix=${name#.shuttle-root-}
          case "$suffix" in ''|*[!0-9]*) refuse_helper_replacement ;; esac
          [ -f "$entry" ] && [ ! -L "$entry" ] && [ "$(stat -c '%u:%a' "$entry")" = '0:600' ] || refuse_helper_replacement
          ;;
        *) refuse_helper_replacement ;;
      esac
    done
  fi
fi
`

// Upgrade only the exact managed policy. A changed port list or a locally
// edited script needs review rather than an implicit firewall replacement.
// This writes no live rules: normal UFW startup applies the corrected script.
func setupFirewallBootMigration(current string) string {
	guard := `"$iptables" -S DOCKER-USER >/dev/null 2>&1 || exit 0
`
	bootGuard := `# UFW starts before networking and Docker at boot. There is no forwarding
# policy to apply until Docker creates this chain; the ordered systemd service
# applies it after Docker starts. A live chain still requires a valid route.
` + guard
	legacy := strings.Replace(current, bootGuard, "", 1)
	legacy = strings.Replace(legacy, `if ! "$iptables" -S ufw-user-forward`, guard+`if ! "$iptables" -S ufw-user-forward`, 1)
	return `(
set -eu
policy=/usr/local/libexec/shuttle-docker-user-firewall
if [ ! -f "$policy" ] || [ -L "$policy" ]; then
  echo 'managed Docker firewall script is missing or symlinked; refusing automatic migration' >&2
  exit 1
fi
work=$(mktemp -d /usr/local/libexec/.shuttle-firewall.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cat >"$work/current" <<'SHUTTLE_FIREWALL_CURRENT'
` + current + `SHUTTLE_FIREWALL_CURRENT
cat >"$work/legacy" <<'SHUTTLE_FIREWALL_LEGACY'
` + legacy + `SHUTTLE_FIREWALL_LEGACY
if cmp -s "$policy" "$work/current"; then
  exit 0
fi
if ! cmp -s "$policy" "$work/legacy"; then
  echo 'managed Docker firewall script differs from the known policy; refusing automatic migration' >&2
  exit 1
fi
chmod 0755 "$work/current"
mv -f "$work/current" "$policy"
)
`
}

func requireSetupAdministrator(identity setupIdentity, options setupOptions) error {
	if options.lockOutFirstContactUser && options.operator != nil && options.operator.user == identity.user {
		return errors.New("--lock-out-first-contact-user requires a different replacement operator account")
	}
	if options.operator != nil || (options.adopt && !options.lockOutFirstContactUser && identity.user != "root" && identity.user != "deploy") {
		return nil
	}
	return errors.New("setup requires an SSH administrator before closing root access; supply --operator-user ops --operator-public-key ~/.ssh/ops_ed25519.pub (with a key distinct from deploy), or adopt through a retained non-root administrator")
}

func setupAccessSummary(identity setupIdentity, administrators []string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Access: deploy is restricted automation: ssh -p %d deploy@%s\n", identity.port, identity.host)
	for _, user := range administrators {
		fmt.Fprintf(&out, "Administrator %s: ssh -p %d %s@%s ; then sudo -i (no password required).\n", user, identity.port, user, identity.host)
	}
	out.WriteString("No Linux password is generated. SSH uses your private keys; keep administrator keys available through ssh-agent or SSH configuration. Root SSH and SSH password authentication are disabled after setup.\n")
	return out.String()
}

func setupOperatorPreflightCommand(user string) string {
	return "set -eu\nuser=" + shell.Escape(user) + `
if id "$user" >/dev/null 2>&1; then
  test "$(id -u "$user")" -ge 1000
  test "$(id -u "$user")" -lt 65534
  test "$(getent passwd "$user" | cut -d: -f6)" = "/home/$user"
  case "$(getent passwd "$user" | cut -d: -f7)" in /bin/bash|/bin/sh|/bin/dash|/bin/zsh|/usr/bin/bash|/usr/bin/zsh) ;; *) exit 1;; esac
else
  # Do not turn a leftover home and its unknown keys into an administrator.
  test ! -e "/home/$user"
fi
for path in "/home/$user" "/home/$user/.ssh"; do
  test ! -L "$path"
  if test -e "$path"; then test -d "$path"; fi
done
keys="/home/$user/.ssh/authorized_keys"
test ! -L "$keys"
if test -e "$keys"; then test -f "$keys"; test "$(stat -c %h "$keys")" = 1; fi
rule="/etc/sudoers.d/91-shuttle-operator-$user"
test ! -L "$rule"
if test -e "$rule"; then
  test -f "$rule"
  test "$(stat -c %h "$rule")" = 1
  test "$(cat "$rule")" = "$user ALL=(ALL:ALL) NOPASSWD: ALL"
fi
`
}

func preflightSetupOperator(runner setupRunner, operator *setupOperatorAccess) error {
	if operator == nil {
		return nil
	}
	if result := runner.run(setupOperatorPreflightCommand(operator.user)); result.Code != 0 {
		return fmt.Errorf("operator %s is incompatible with setup; account, SSH paths or managed sudo policy failed read-only preflight: %s", operator.user, strings.TrimSpace(result.Stderr))
	}
	return nil
}

func setupOperatorCommand(user string) string {
	quotedUser := shell.Escape(user)
	sudoers := shell.Escape(user + " ALL=(ALL:ALL) NOPASSWD: ALL\n")
	return setupOperatorPreflightCommand(user) + fmt.Sprintf(`
user=%s
if ! id "$user" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$user"
  passwd -l "$user" >/dev/null
fi
test "$(id -u "$user")" -ne 0
home=$(getent passwd "$user" | cut -d: -f6)
test "$home" = "/home/$user"
group=$(id -gn "$user")
install -d -o "$user" -g "$group" -m 0700 "$home"
install -d -o "$user" -g "$group" -m 0700 "$home/.ssh"
keys="$home/.ssh/authorized_keys"
if [ ! -e "$keys" ]; then
  install -o "$user" -g "$group" -m 0600 /dev/null "$keys"
fi
key=$(cat /tmp/shuttle-emergency-operator.pub)
if ! grep -Fqx -- "$key" "$keys"; then
  printf '\n%%s\n' "$key" >>"$keys"
fi
chown "$user:$group" "$keys"
chmod 0600 "$keys"
# Publish a validated rule before removing any pre-existing sudo membership.
# A separate file per account keeps another administrator's rule intact.
rule="/etc/sudoers.d/91-shuttle-operator-$user"
work=$(mktemp /etc/sudoers.d/.shuttle-operator.XXXXXX)
trap 'rm -f "$work"' EXIT HUP INT TERM
printf %%s %s >"$work"
chmod 0440 "$work"
visudo -cf "$work" >/dev/null
mv -f "$work" "$rule"
for privileged_group in sudo docker; do
  if id -nG "$user" | tr ' ' '\n' | grep -Fx "$privileged_group" >/dev/null; then
    gpasswd -d "$user" "$privileged_group" >/dev/null
  fi
done
`, quotedUser, sudoers)
}

// adoptionFirewallReachabilityGuard is the only part of this lot that can cut
// the branch it is sitting on.
//
// `ufw --force reset` above removed every rule the host had, and `ufw --force
// enable` below installs a default-deny policy. On a fresh VPS the SSH port is
// known by construction: the configuration declares it, --target matched it,
// and nothing else was ever listening. On a host in service it is not: sshd may
// answer on a port this configuration does not name — a second port kept for
// another operator, or a socket-activated listener whose port lives in
// ssh.socket rather than in sshd_config — and enabling a default-deny firewall
// without it is how an adoption locks everyone, including itself, out of a
// machine that is serving traffic.
//
// So: add a rule for every port sshd actually listens on, before enabling, and
// refuse to go any further unless the rule for the port this run arrived on is
// already among the added rules. `ufw show added` is read rather than `ufw
// status` because the firewall is still inactive at this point, and an
// inactive firewall reports no rules at all.
func adoptionFirewallReachabilityGuard(sshPort int) string {
	return fmt.Sprintf(`ssh_ports=$(
  {
    printf '%%s\n' %d
    sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'
    systemctl show ssh.socket -p ListenStream --value 2>/dev/null | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p'
    ss -H -ltnp 2>/dev/null | awk '/"sshd"/ { fields = split($4, parts, ":"); print parts[fields] }'
  } | grep -E '^[0-9]+$' | sort -un
)
for ssh_port in $ssh_ports; do
  ufw allow "$ssh_port"/tcp
done
if ! ufw show added | grep -Fqx "ufw allow %d/tcp"; then
  echo "refusing to enable the firewall: no rule was added for SSH port %d, and enabling a default-deny policy without it would close this session" >&2
  exit 1
fi
`, sshPort, sshPort, sshPort)
}

func setupSharedCaddy(client *shuttlessh.Client, cfg *config.Config) error {
	// A fresh setup runs the stage as the root shell's command, which is what
	// setupRunner with sudo unset does: this call is the one it always made.
	return deploySharedCaddy(setupRunner{client: client}, cfg, caddyCheckpointReconcile(cfg.Caddy.Email)+setupCaddyCommand())
}

// deploySharedCaddy uploads the edge's generated assets and runs one
// 50-caddy-direct program. The caller selects its checkpoint behavior because
// only a normal fresh setup or cutover may reconcile the mounted config first.
func deploySharedCaddy(runner setupRunner, cfg *config.Config, command string) error {
	return deploySharedCaddyWithVolumePreparation(runner, cfg, command, caddyVolumePreparation(cfg.Caddy))
}

func deploySharedCaddyWithVolumePreparation(runner setupRunner, cfg *config.Config, command, volumePreparation string) error {
	files := []struct {
		path string
		body string
		mode os.FileMode
	}{
		{"/tmp/shuttle-Caddyfile", caddyfileContent(cfg.Caddy.Email), 0o600},
		{"/tmp/shuttle-caddy-stack.yml", setupCaddyStack(caddyImage(cfg.Caddy), cfg.Caddy), 0o600},
		{"/tmp/shuttle-edge-entrypoint", caddyEntrypointScript(cfg.Caddy), 0o600},
		{"/tmp/shuttle-caddy-volumes.sh", volumePreparation, 0o600},
	}
	for _, file := range files {
		if result := runner.client.UploadContent(file.body, file.path, file.mode); result.Code != 0 {
			return fmt.Errorf("upload shared Caddy asset: %s", result.Stderr)
		}
	}
	if result := runner.run(command); result.Code != 0 {
		return fmt.Errorf("shared Caddy setup failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

// caddyDataVolume resolves the volume mounted at /data, where the ACME account
// and every issued certificate live. Reusing an existing one is how an edge
// adopts a deployment that already holds valid certificates instead of
// re-issuing every hostname during a cutover.
func caddyDataVolume(cfg config.Caddy) (name string, external bool) {
	if existing := cfg.DataVolume; existing != "" {
		return existing, true
	}
	return "shuttle_caddy_data", false
}

// caddyEntrypoint returns the container entrypoint and command.
//
// With no secret to export, Caddy is executed directly: no shell in the process
// tree, nothing between PID 1 and the server. When secrets must reach the
// environment — a DNS-01 challenge reads its credential as {env.NAME} — a small
// generated script is mounted as a config object and exec's Caddy, so the
// wrapper leaves no process behind and the credential never touches disk
// unencrypted.
func caddyEntrypoint(cfg config.Caddy) (entrypoint, command string) {
	if len(cfg.SecretEnv) == 0 {
		return `["/usr/bin/caddy"]`, `["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]`
	}
	return `["/bin/sh", "/etc/caddy/shuttle-edge-entrypoint"]`, ""
}

// caddyEntrypointScript exports each mapped secret from its file, then replaces
// itself with Caddy.
func caddyEntrypointScript(cfg config.Caddy) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Generated by shuttle setup. Exports Swarm secrets that a Caddyfile\n")
	b.WriteString("# reads as {env.NAME}, then execs Caddy so no shell stays as PID 1.\n")
	b.WriteString("set -eu\n")
	for _, name := range sortedKeys(cfg.SecretEnv) {
		secret := cfg.SecretEnv[name]
		// Fail loudly: a missing secret file used to expand to an empty
		// placeholder, which turns into certificates that never renew and an
		// error that only surfaces weeks later.
		fmt.Fprintf(&b, "[ -r /run/secrets/%s ] || { echo 'missing secret: %s' >&2; exit 1; }\n", secret, secret)
		fmt.Fprintf(&b, "%s=\"$(cat /run/secrets/%s)\"\n", name, secret)
		fmt.Fprintf(&b, "export %s\n", name)
	}
	b.WriteString("exec /usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile\n")
	return b.String()
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Only Shuttle-owned volumes are re-owned. Adopted certificate stores must
// already permit the service identity; setup never changes shared ownership.
func caddyVolumePreparation(cfg config.Caddy) string {
	return caddyVolumePreparationScript(cfg, false)
}

// Adoption snapshots volume-root ownership before re-owning files for the new
// edge. On production-host (30-10-2026), rollback returned to a root edge with
// cap_drop ALL; leaving its 0600 certificates owned by 10001 made HTTPS fail.
func caddyVolumePreparationWithOwnerSnapshot(cfg config.Caddy) string {
	return caddyVolumePreparationScript(cfg, true)
}

func caddyVolumePreparationScript(cfg config.Caddy, snapshotOwners bool) string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	data, external := caddyDataVolume(cfg)
	managed := []string{"shuttle-edge_shuttle_caddy_config"}
	if !external {
		data = "shuttle-edge_" + data
		managed = append(managed, data)
	}
	var b strings.Builder
	b.WriteString("set -eu\n")
	if snapshotOwners {
		for _, volume := range managed {
			fmt.Fprintf(&b, "docker volume inspect %s >/dev/null 2>&1 || docker volume create --label dev.shuttle.owner=system %s >/dev/null\n", quote(volume), quote(volume))
		}
		b.WriteString("[ -n \"${SHUTTLE_CADDY_OWNER_FILE:-}\" ] || { echo 'missing Caddy volume owner record path' >&2; exit 1; }\n")
		// Every path's owner is recorded, not only the volume root: the chown
		// below is recursive, and a root-owned 0600 certificate under a
		// 10001-owned root must come back as root (review of DEV-DEPL-81,
		// round 3). A manifest line that is not "<uid>:<gid> /volume..." (a
		// path with a newline, say) aborts before anything is re-owned.
		for index, volume := range managed {
			manifest := fmt.Sprintf("\"$SHUTTLE_CADDY_OWNER_FILE.%d\"", index)
			fmt.Fprintf(&b, "docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add DAC_READ_SEARCH --security-opt no-new-privileges=true --entrypoint /bin/sh -v %s %s -ec 'find /volume -xdev -exec stat -c \"%%u:%%g %%n\" {} +' > %s\n", quote(volume+":/volume:nocopy"), quote(caddyImage(cfg)), manifest)
			fmt.Fprintf(&b, "awk '$1 !~ /^[0-9]+:[0-9]+$/ || (substr($0, length($1) + 2) != \"/volume\" && index(substr($0, length($1) + 2), \"/volume/\") != 1) { bad = 1 } END { exit bad }' %s || { echo 'invalid Caddy volume owner manifest' >&2; exit 1; }\n", manifest)
			fmt.Fprintf(&b, "grep -q '^[0-9]*:[0-9]* /volume$' %s || { echo 'Caddy volume owner manifest has no root entry' >&2; exit 1; }\n", manifest)
			fmt.Fprintf(&b, "printf '%%s %%s\\n' %s %s >> \"$SHUTTLE_CADDY_OWNER_FILE\"\n", quote(volume), manifest)
		}
		for _, volume := range managed {
			fmt.Fprintf(&b, "docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges=true --entrypoint /bin/sh -v %s %s -ec 'chown -R 10001:10001 /volume'\n", quote(volume+":/volume:nocopy"), quote(caddyImage(cfg)))
		}
	} else {
		for _, volume := range managed {
			fmt.Fprintf(&b, "docker volume inspect %s >/dev/null 2>&1 || docker volume create --label dev.shuttle.owner=system %s >/dev/null\n", quote(volume), quote(volume))
			fmt.Fprintf(&b, "docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges=true --entrypoint /bin/sh -v %s %s -ec 'chown -R 10001:10001 /volume'\n", quote(volume+":/volume:nocopy"), quote(caddyImage(cfg)))
		}
	}
	fmt.Fprintf(&b, "docker volume inspect %s >/dev/null\n", quote(data))
	fmt.Fprintf(&b, "docker run --rm --network none --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges=true --entrypoint /bin/sh -v %s %s -ec 'test -r /data && test -w /data && test -x /data'\n", quote(data+":/data:nocopy"), quote(caddyImage(cfg)))
	return b.String()
}

func setupCaddyStack(image string, cfg config.Caddy) string {
	dataVolume, externalData := caddyDataVolume(cfg)
	entrypoint, command := caddyEntrypoint(cfg)

	var b strings.Builder
	b.WriteString("services:\n  caddy:\n")
	fmt.Fprintf(&b, "    image: %s\n    user: \"10001:10001\"\n", image)
	fmt.Fprintf(&b, "    entrypoint: %s\n", entrypoint)
	if command != "" {
		fmt.Fprintf(&b, "    command: %s\n", command)
	}
	b.WriteString(`    ports:
      - {target: 80, published: 80, protocol: tcp, mode: host}
      - {target: 443, published: 443, protocol: tcp, mode: host}
      - {target: 443, published: 443, protocol: udp, mode: host}
    configs:
      - {source: shuttle_caddyfile, target: /etc/caddy/Caddyfile, mode: 0444}
`)
	if len(cfg.SecretEnv) > 0 {
		b.WriteString("      - {source: shuttle_edge_entrypoint_v1, target: /etc/caddy/shuttle-edge-entrypoint, mode: 0555}\n")
	}
	b.WriteString("    volumes:\n")
	b.WriteString("      - /opt/shuttle/caddy/conf.d:/etc/caddy/conf.d:ro\n")
	fmt.Fprintf(&b, "      - {type: volume, source: %s, target: /data, volume: {nocopy: true}}\n", dataVolume)
	b.WriteString("      - {type: volume, source: shuttle_caddy_config, target: /config, volume: {nocopy: true}}\n")
	for _, mount := range cfg.Mounts {
		suffix := ""
		if mount.IsReadOnly() {
			suffix = ":ro"
		}
		fmt.Fprintf(&b, "      - %s:%s%s\n", mount.Source, mount.Target, suffix)
	}
	if len(cfg.Env) > 0 {
		b.WriteString("    environment:\n")
		for _, name := range sortedKeys(cfg.Env) {
			fmt.Fprintf(&b, "      %s: %q\n", name, cfg.Env[name])
		}
	}
	if len(cfg.SecretEnv) > 0 {
		b.WriteString("    secrets:\n")
		for _, name := range sortedKeys(cfg.SecretEnv) {
			fmt.Fprintf(&b, "      - {source: %s, target: %s, uid: \"10001\", gid: \"10001\", mode: 0400}\n", cfg.SecretEnv[name], cfg.SecretEnv[name])
		}
	}
	b.WriteString(`    networks: [caddy_network]
    read_only: true
    tmpfs: [/tmp]
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    logging:
      driver: json-file
      options: {max-size: 10m, max-file: "3"}
    healthcheck:
      test: [CMD, caddy, validate, --config, /etc/caddy/Caddyfile, --adapter, caddyfile]
      interval: 5s
      timeout: 2s
      retries: 10
    deploy:
      replicas: 1
      # Host-mode ports cannot be bound by two tasks at once; see
      # TestSharedCaddyNeverUpdatesStartFirstOnHostPorts.
      update_config: {order: stop-first, failure_action: rollback}
      resources:
        limits: {cpus: "0.50", memory: 256M}
configs:
  shuttle_caddyfile:
    file: /tmp/shuttle-Caddyfile
`)
	fmt.Fprintf(&b, "    name: %s\n", caddyfileConfigName(cfg.Email))
	if len(cfg.SecretEnv) > 0 {
		b.WriteString("  shuttle_edge_entrypoint_v1:\n    file: /tmp/shuttle-edge-entrypoint\n")
	}
	if len(cfg.SecretEnv) > 0 {
		b.WriteString("secrets:\n")
		for _, name := range sortedKeys(cfg.SecretEnv) {
			fmt.Fprintf(&b, "  %s: {external: true}\n", cfg.SecretEnv[name])
		}
	}
	b.WriteString("volumes:\n")
	if externalData {
		// Declared external on purpose: Shuttle adopts a volume it did not
		// create, and must never be the reason its certificates are recreated.
		fmt.Fprintf(&b, "  %s: {external: true}\n", dataVolume)
	} else {
		fmt.Fprintf(&b, "  %s: {}\n", dataVolume)
	}
	b.WriteString("  shuttle_caddy_config: {}\nnetworks:\n  caddy_network: {external: true}\n")
	return b.String()
}

// caddyEdgeStagingSource writes the edge's root-owned inputs. It touches no
// listener, so it is identical on a fresh host and on an adopted one.
const caddyEdgeStagingSource = `cp /tmp/shuttle-caddy-stack.yml /etc/shuttle/caddy-stack.yml
sh /tmp/shuttle-caddy-volumes.sh
install -d -m 0755 /opt/shuttle/caddy/conf.d
printf '%s\n' '# Shuttle application routes are written by the signed root helper.' >/opt/shuttle/caddy/conf.d/00-empty.caddy
install -o root -g root -m 0444 /tmp/shuttle-Caddyfile /etc/shuttle/Caddyfile
`

// caddyEdgeDeployAndWaitSource deploys the stack and leaves `ready` at 1 only
// when the edge is both replicated 1/1 and able to validate its own
// configuration. It is shared verbatim by the fresh stage and the cutover so
// the two can never disagree about what "the edge came up" means — and so the
// cutover's restore branch triggers on exactly the condition the fresh stage
// fails on.
const caddyEdgeDeployAndWaitSource = `docker stack deploy --detach --prune -c /etc/shuttle/caddy-stack.yml shuttle-edge
attempt=0
ready=0
while [ "$attempt" -lt 24 ]; do
  container=$(docker ps -q --filter label=com.docker.swarm.service.name=shuttle-edge_caddy | head -n 1)
  if [ -n "$container" ] && [ "$(docker service ls --filter name=shuttle-edge_caddy --format '{{.Replicas}}')" = "1/1" ] && docker exec "$container" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 5
done
`

func setupCaddyCommand() string {
	return checkpoint("50-caddy-direct", caddyEdgeStagingSource+caddyEdgeDeployAndWaitSource+`if [ "$ready" != 1 ]; then
  docker service ps --no-trunc shuttle-edge_caddy >&2
  exit 1
fi
`)
}

// setupCaddyDomainPrecheckCommand proves a current HTTPS site answers before
// adoption writes identity or applies a host stage. It returns the successful
// domains so later probes keep the same coverage baseline.
func setupCaddyDomainPrecheckCommand(probeHosts []string) string {
	var b strings.Builder
	b.WriteString(`set -eu
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to prove the edge still serves HTTPS; no host changes were made" >&2
  exit 1
fi
before_hosts=''
`)
	for _, host := range sortedUnique(probeHosts) {
		fmt.Fprintf(&b, `probe_host=%s
if curl -sS -o /dev/null --max-time 10 --resolve "$probe_host:443:127.0.0.1" "https://$probe_host/"; then
  before_hosts="${before_hosts}${before_hosts:+ }$probe_host"
  printf 'serving-host=%%s\n' "$probe_host"
fi
`, shell.Escape(host))
	}
	b.WriteString(`if [ -z "$before_hosts" ]; then
  echo "refusing edge re-convergence: no previously serving HTTPS domain could be verified; no host changes were made" >&2
  exit 1
fi
`)
	return b.String()
}

// setupCaddyReconvergeCommand replaces an already-serving edge only after the
// adoption survey found drift. A detached stack deploy can briefly leave the
// old task running, so UpdateStatus plus the service spec and task identity
// prove the replacement. The saved prior spec also lets rollback wait for the
// restored task and verify that its listeners and every site from the early
// adoption precheck recover.
func setupCaddyReconvergeCommand(image string, probeHosts []string) string {
	var b strings.Builder
	b.WriteString(`set -eu
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to prove the edge still serves HTTPS; no edge update was attempted" >&2
  exit 1
fi
old_service_version=$(docker service inspect shuttle-edge_caddy --format '{{.Version.Index}}')
old_service_spec=$(docker service inspect shuttle-edge_caddy --format '{{json .Spec}}')
old_container_spec=$(docker service inspect shuttle-edge_caddy --format '{{json .Spec.TaskTemplate.ContainerSpec}}')
old_container_identity=$(docker service inspect shuttle-edge_caddy --format '{{.Spec.TaskTemplate.ContainerSpec.User}}|{{.Spec.TaskTemplate.ContainerSpec.Image}}')
`)
	fmt.Fprintf(&b, "expected_container_hardening=%s\n", shell.Escape("10001:10001|"+image+`|true|["ALL"]|["CAP_NET_BIND_SERVICE"]`))
	b.WriteString("before_hosts=")
	b.WriteString(shell.Escape(strings.Join(sortedUnique(probeHosts), " ")))
	b.WriteString(`
if [ -z "$before_hosts" ]; then
  echo "refusing edge re-convergence: no previously serving HTTPS domain was provided; no edge update was attempted" >&2
  exit 1
fi
verify_before_hosts() {
  for probe_host in $before_hosts; do
    if ! curl -sS -o /dev/null --max-time 10 --resolve "$probe_host:443:127.0.0.1" "https://$probe_host/"; then
      echo "refusing edge re-convergence: previously serving HTTPS domain $probe_host stopped answering; no edge update was attempted" >&2
      return 1
    fi
  done
}
if ! verify_before_hosts; then exit 1; fi
`)
	// DEV-DEPL-81 review: ownership recovery is armed before the first chown.
	// The staging below re-owns the incumbent's volumes, so any later exit
	// that does not end with a converged edge (a failed precheck, a deploy
	// that left the spec unchanged, a rollback) gives the volumes back to
	// their recorded owners from the EXIT trap. production-host's root edge runs
	// with cap_drop ALL and cannot read 10001-owned certificates otherwise.
	fmt.Fprintf(&b, "owner_restore_image=%s\n", shell.Escape(image))
	b.WriteString(`owner_dir=$(mktemp -d /tmp/shuttle-caddy-owners.XXXXXX)
umask 077
owner_file="$owner_dir/owners"
: > "$owner_file"
export SHUTTLE_CADDY_OWNER_FILE="$owner_file"
ownership_restored=0
edge_converged=0
restore_caddy_volume_owners() {
  while IFS=' ' read -r volume manifest; do
    [ -n "$volume" ] || continue
    [ -s "$manifest" ] || return 1
    root_owner=$(sed -n 's|^\([0-9]*:[0-9]*\) /volume$|\1|p' "$manifest")
    case "$root_owner" in ''|*[!0-9:]*|:*|*:|*:*:*) return 1 ;; esac
    # Files the failed edge created get the volume root's owner first, then
    # every recorded path gets exactly the owner it had before this run.
    # Whole lines are read so a name ending in a space stays that name, and a
    # recorded path that no longer exists is skipped instead of aborting the
    # loop before later certificates (review of DEV-DEPL-81, round 4).
    docker run --rm -i --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add DAC_READ_SEARCH --security-opt no-new-privileges=true --entrypoint /bin/sh -v "$volume:/volume:nocopy" "$owner_restore_image" -ec 'chown -R "$1" /volume; while IFS= read -r line; do owner=${line%% *}; path=${line#* }; if [ -e "$path" ] || [ -L "$path" ]; then chown -h "$owner" "$path"; fi; done' restore "$root_owner" < "$manifest" || return 1
  done < "$owner_file"
}
finish_caddy_owner_record() {
  if [ "$edge_converged" -ne 1 ] && [ "$ownership_restored" -ne 1 ] && [ -s "$owner_file" ]; then
    if restore_caddy_volume_owners; then
      ownership_restored=1
    else
      echo "CRITICAL: Caddy volume ownership could not be restored; the previous edge may not read its certificates" >&2
    fi
  fi
  rm -rf "$owner_dir"
}
trap finish_caddy_owner_record EXIT
`)
	b.WriteString(caddyEdgeStagingSource)
	fmt.Fprintf(&b, `image=%s
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker pull "$image"
fi
`, shell.Escape(image))
	b.WriteString(`if ! verify_before_hosts; then exit 1; fi
`)
	b.WriteString(`failed_step=''
swarm_rollback_started=0
if docker stack deploy --detach --prune -c /etc/shuttle/caddy-stack.yml shuttle-edge; then
  :
else
  deploy_exit=$?
  if current_service_spec=$(docker service inspect shuttle-edge_caddy --format '{{json .Spec}}' 2>/dev/null); then
    if [ "$current_service_spec" = "$old_service_spec" ]; then
      echo "shared edge stack deploy failed with exit $deploy_exit; the service spec is unchanged, so rollback was not needed" >&2
      exit "$deploy_exit"
    fi
    failed_step="docker stack deploy failed with exit $deploy_exit after changing the service spec"
  else
    failed_step="docker stack deploy failed with exit $deploy_exit and the resulting service spec could not be inspected"
  fi
fi
attempt=0
update_state=''
while [ -z "$failed_step" ] && [ "$attempt" -lt 120 ]; do
  if update_state=$(docker service inspect shuttle-edge_caddy --format '{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}' 2>/dev/null); then
    :
  else
    update_state=inspect_failed
  fi
  case "$update_state" in
    completed) break ;;
    rollback_started|rollback_completed|rollback_paused|paused)
      case "$update_state" in
        rollback_started|rollback_completed|rollback_paused) swarm_rollback_started=1 ;;
      esac
      failed_step="Swarm update entered $update_state"
      break
      ;;
  esac
  attempt=$((attempt + 1))
  sleep 1
done
if [ -z "$failed_step" ] && [ "$update_state" != completed ]; then
  failed_step='Swarm update did not complete within 120 seconds'
fi
expected_spec=`)
	fmt.Fprintf(&b, "%s\n", shell.Escape("10001:10001|"+image+`|true|["ALL"]|["CAP_NET_BIND_SERVICE"]`))
	b.WriteString(`if [ -z "$failed_step" ]; then
  if actual_spec=$(docker service inspect shuttle-edge_caddy --format '{{.Spec.TaskTemplate.ContainerSpec.User}}|{{.Spec.TaskTemplate.ContainerSpec.Image}}|{{.Spec.TaskTemplate.ContainerSpec.ReadOnly}}|{{json .Spec.TaskTemplate.ContainerSpec.CapabilityDrop}}|{{json .Spec.TaskTemplate.ContainerSpec.CapabilityAdd}}' 2>/dev/null | sed 's/"NET_BIND_SERVICE"/"CAP_NET_BIND_SERVICE"/g') && [ "$actual_spec" = "$expected_spec" ]; then
    :
  else
    failed_step='service spec did not match the rendered hardening properties and image'
  fi
fi
if [ -z "$failed_step" ]; then
  running_containers=$(docker ps -q --filter label=com.docker.swarm.service.name=shuttle-edge_caddy 2>/dev/null || :)
  ready_container=''
  for container in $running_containers; do
    if actual_hardening=$(docker inspect --format '{{.Config.User}}|{{.Config.Image}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}' "$container" 2>/dev/null | sed 's/"NET_BIND_SERVICE"/"CAP_NET_BIND_SERVICE"/g') && [ "$actual_hardening" = "$expected_container_hardening" ] && docker exec "$container" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
      ready_container=$container
      break
    fi
  done
  if [ -z "$ready_container" ]; then
    failed_step='no running task with the rendered image and user 10001:10001 validated its Caddyfile'
  fi
fi
if [ -z "$failed_step" ] && [ -n "$before_hosts" ]; then
  deadline=$(($(date +%s) + 60))
  all_hosts_answered=0
  while [ "$all_hosts_answered" -ne 1 ]; do
    pass=1
    for probe_host in $before_hosts; do
      now=$(date +%s)
      remaining=$((deadline - now))
      if [ "$remaining" -le 0 ]; then
        pass=0
        break
      fi
      curl_timeout=10
      if [ "$remaining" -lt "$curl_timeout" ]; then curl_timeout=$remaining; fi
      if ! curl -sS -o /dev/null --max-time "$curl_timeout" --resolve "$probe_host:443:127.0.0.1" "https://$probe_host/"; then
        pass=0
      fi
    done
    now=$(date +%s)
    remaining=$((deadline - now))
    if [ "$remaining" -le 0 ]; then
      pass=0
    else
      curl_timeout=10
      if [ "$remaining" -lt "$curl_timeout" ]; then curl_timeout=$remaining; fi
      if ! curl -sS -o /dev/null --max-time "$curl_timeout" http://127.0.0.1/; then
        pass=0
      fi
    fi
    if [ "$pass" -eq 1 ]; then
      all_hosts_answered=1
      break
    fi
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
      failed_step='HTTP 80 or a site that answered HTTPS before the update stopped answering'
      break
    fi
    sleep 1
  done
fi
if [ -n "$failed_step" ]; then
  # The previous edge (on production-host: root with cap_drop ALL) cannot start
  # while its files belong to 10001, so owners come back before any rollback
  # is awaited, and the explicit rollback is detached: without --detach,
  # docker service rollback blocks until a task that cannot start converges
  # (reviews of DEV-DEPL-81, rounds 1 and 2).
  if restore_caddy_volume_owners; then ownership_restored=1; fi
  if [ "$swarm_rollback_started" -ne 1 ]; then
    rollback_request_version=$(docker service inspect shuttle-edge_caddy --format '{{.Version.Index}}' 2>/dev/null || :)
    if [ -z "$rollback_request_version" ] || ! docker service rollback --detach shuttle-edge_caddy >/dev/null 2>&1; then
      echo "CRITICAL: the shared edge rollback failed; inspect docker service ps shuttle-edge_caddy" >&2
      exit 1
    fi
  fi
  # 150 s, not 60: the e2e of 30-10-2026 (VM 246, Docker 29.9.2) saw the
  # rollback task start exactly 60 s after its creation in 2 of 6 automatic
  # rollbacks (dockerd: "error reallocating node", allocator retry), so a
  # recovered edge was reported CRITICAL about 10 s before it came back.
  recovery_deadline=$(($(date +%s) + 150))
  recovery_step='Swarm did not complete the rollback'
  restored_task=''
  recovery_ready=0
  recovery_https_curl() {
    probe_host=$1
    probe_url=$2
    now=$(date +%s)
    remaining=$((recovery_deadline - now))
    if [ "$remaining" -le 0 ]; then return 1; fi
    curl_timeout=10
    if [ "$remaining" -lt "$curl_timeout" ]; then curl_timeout=$remaining; fi
    curl -sS -o /dev/null --max-time "$curl_timeout" --resolve "$probe_host:443:127.0.0.1" "$probe_url"
  }
  while [ "$recovery_ready" -ne 1 ]; do
    now=$(date +%s)
    if [ "$now" -ge "$recovery_deadline" ]; then break; fi
    recovery_status=$(docker service inspect shuttle-edge_caddy --format '{{.UpdateStatus.State}}' 2>/dev/null || :)
    recovery_version=$(docker service inspect shuttle-edge_caddy --format '{{.Version.Index}}' 2>/dev/null || :)
    recovery_spec=$(docker service inspect shuttle-edge_caddy --format '{{json .Spec.TaskTemplate.ContainerSpec}}' 2>/dev/null || :)
    if [ "$recovery_spec" != "$old_container_spec" ]; then
      recovery_step='service spec did not return to the previous edge'
    elif [ "$swarm_rollback_started" -eq 1 ] && { [ "$recovery_status" != rollback_completed ] || [ "$recovery_version" -le "$old_service_version" ]; }; then
      recovery_step="Swarm rollback is still $recovery_status"
    elif [ "$swarm_rollback_started" -eq 0 ] && { [ "$recovery_version" -le "$rollback_request_version" ] || { [ "$recovery_status" != completed ] && [ "$recovery_status" != rollback_completed ]; }; }; then
      recovery_step="requested rollback is still $recovery_status"
    else
      if [ "$ownership_restored" -ne 1 ]; then
        if restore_caddy_volume_owners; then
          ownership_restored=1
        else
          recovery_step='Caddy volume ownership could not be restored'
        fi
      fi
      if [ "$ownership_restored" -eq 1 ]; then
        replicas=$(docker service ls --filter name=shuttle-edge_caddy --format '{{.Replicas}}' 2>/dev/null || :)
        running_containers=$(docker ps -q --filter label=com.docker.swarm.service.name=shuttle-edge_caddy 2>/dev/null || :)
        running_count=0
        restored_task=''
        if [ "$replicas" = 1/1 ]; then
          for container in $running_containers; do
            task_identity=$(docker inspect --format '{{index .Config.Labels "com.docker.swarm.task.id"}}|{{.Config.User}}|{{.Config.Image}}' "$container" 2>/dev/null || :)
            task_id=${task_identity%%|*}
            actual_identity=${task_identity#*|}
            if [ -n "$task_id" ] && [ "$actual_identity" = "$old_container_identity" ] && docker exec "$container" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
              running_count=$((running_count + 1))
              restored_task=$task_id
            fi
          done
        fi
        if [ "$running_count" -ne 1 ]; then
          recovery_step='the restored service has no single running task matching its previous spec'
          restored_task=''
        else
          recovery_step='the restored edge is not answering on HTTP 80 and its previously answering HTTPS domains on 443'
          probe_ok=1
          if ! curl -sS -o /dev/null --max-time 10 http://127.0.0.1/; then probe_ok=0; fi
          if [ "$probe_ok" -eq 1 ]; then
            for probe_host in $before_hosts; do
              if ! recovery_https_curl "$probe_host" "https://$probe_host/"; then probe_ok=0; break; fi
            done
          fi
          if [ "$probe_ok" -eq 1 ]; then recovery_ready=1; fi
        fi
      fi
    fi
    if [ "$recovery_ready" -ne 1 ]; then sleep 1; fi
  done
  if [ "$recovery_ready" -ne 1 ]; then
    echo "CRITICAL: the shared edge rollback recovery failed ($recovery_step); inspect docker service ps shuttle-edge_caddy" >&2
    exit 1
  fi
  echo "the shared edge did not converge ($failed_step); rollback restored task $restored_task and recovered HTTP 80 and previously answering HTTPS domains on 443" >&2
  exit 1
fi
edge_converged=1
install -d -m 0700 /etc/shuttle/setup.d
touch /etc/shuttle/setup.d/50-caddy-direct`)
	return b.String()
}

// setupCaddyCutoverCommand is 50-caddy-direct for a host whose 80/443 are
// already answering.
//
// Docker cannot bind a host-mode port twice, so the shared edge cannot come up
// beside the incumbent: one of them holds the ports and the other fails to
// start. The cutover is therefore an outage, and everything here exists to keep
// it bounded and reversible.
//
//   - The image is pulled before anything is stopped. Pulling afterwards would
//     stretch the outage over a download whose length nobody knows.
//   - Only `incumbent` is stopped, and only after `docker container inspect`
//     confirms it is the container the plan named. A listener this run did not
//     identify is never touched — the caller refuses the cutover instead.
//   - `docker stop` rather than `docker rm`: the container, its volumes and its
//     configuration survive, so restoring it is one verb.
//   - If the edge does not reach 1/1 with a valid configuration inside the
//     budget, the half-deployed stack is removed, its task is waited out — a
//     task still shutting down still owns the port — and the incumbent is
//     started again. A failed cutover must hand the ports back, not leave the
//     host with nothing listening on 80 and 443.
//
// An empty incumbent means the survey found no container holding those ports:
// there is nothing to stop and nothing to restore, so those branches are not
// generated at all rather than being generated and skipped.
func setupCaddyCutoverCommand(incumbent string, image string) string {
	var b strings.Builder
	b.WriteString(caddyEdgeStagingSource)
	fmt.Fprintf(&b, `image=%s
docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
`, shell.Escape(image))
	if incumbent != "" {
		// The restart policy is read before the stop and set to `no` after it.
		// Stopped is not gone: under `restart: always` the next dockerd
		// restart or reboot would start the incumbent again and race the edge
		// for 80/443, on a host whose live-restore 20-docker has just turned
		// off. The surveyed policy is put back on the restore branch, so a
		// failed cutover leaves the container exactly as it found it.
		fmt.Fprintf(&b, `incumbent=%s
docker container inspect "$incumbent" >/dev/null
incumbent_restart=$(docker container inspect "$incumbent" --format '{{.HostConfig.RestartPolicy.Name}}')
[ -n "$incumbent_restart" ] || incumbent_restart=no
docker stop --time 20 "$incumbent" >/dev/null
docker update --restart no "$incumbent" >/dev/null
`, shell.Escape(incumbent))
	}
	b.WriteString(caddyEdgeDeployAndWaitSource)
	b.WriteString(`if [ "$ready" != 1 ]; then
  docker service ps --no-trunc shuttle-edge_caddy >&2 || :
`)
	if incumbent != "" {
		b.WriteString(`  echo "the shared edge did not become healthy inside its budget; restoring the incumbent on 80/443" >&2
  docker stack rm shuttle-edge >/dev/null 2>&1 || :
  waited=0
  while [ "$waited" -lt 30 ]; do
    if [ -z "$(docker ps -aq --filter label=com.docker.swarm.service.name=shuttle-edge_caddy)" ]; then
      break
    fi
    waited=$((waited + 1))
    sleep 2
  done
  docker update --restart "$incumbent_restart" "$incumbent" >/dev/null 2>&1 || :
  if docker start "$incumbent" >/dev/null 2>&1 && [ "$(docker container inspect "$incumbent" --format '{{.State.Running}}' 2>/dev/null)" = true ]; then
    echo "restored $incumbent: it holds 80/443 again, exactly as it did before this run" >&2
  else
    echo "CRITICAL: $incumbent could not be restarted, so nothing is listening on 80/443; start it by hand" >&2
  fi
`)
	}
	b.WriteString(`  exit 1
fi
`)
	return checkpoint("50-caddy-direct", b.String())
}
