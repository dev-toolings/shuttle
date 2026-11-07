package cli

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

func newHelperCommand() *cobra.Command {
	root := &cobra.Command{Use: "helper", Short: "Inspect and update the signed root helper"}
	root.AddCommand(newHelperStatusCommand(), newHelperUpdateCommand())
	return root
}

func newHelperStatusCommand() *cobra.Command {
	var flags configFlags
	command := &cobra.Command{
		Use:   "status",
		Short: "Show the installed root helper capabilities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			report, err := queryRootHelperCapabilities(cfg)
			if err != nil {
				if status, ok := helperMigrationStatusFromCapabilityError(err); ok {
					fmt.Fprintf(cmd.OutOrStdout(), "migration=%s id=%s phase=%s\n", status.Schema, status.ID, status.Phase)
					return nil
				}
				if rootHelperLacksCapabilities(err) {
					return fmt.Errorf("installed root helper predates capability negotiation; %s: %w", rootHelperBootstrapHint, err)
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "protocol=%d version=%s features=%s\n", report.Protocol, report.Version, strings.Join(report.Features, ","))
			return nil
		},
	}
	addConfigFlags(command, &flags)
	return command
}

func newHelperUpdateCommand() *cobra.Command {
	var flags configFlags
	var binaryPath string
	var yes bool
	var dryRun bool
	var allowDowngrade bool
	command := &cobra.Command{
		Use:   "update",
		Short: "Atomically install a signed root helper update",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// A failed signed update must leave recovery guidance visible without Cobra usage noise.
			cmd.SilenceUsage = true
			// main prints the returned error once; cobra printing it too showed every
			// recovery line twice.
			cmd.SilenceErrors = true
			cfg, err := loadWithFlags(flags)
			if err != nil {
				return err
			}
			resolved, err := resolveLinuxHelper(binaryPath)
			if err != nil {
				return err
			}
			payload, err := os.ReadFile(resolved)
			if err != nil {
				return fmt.Errorf("read helper binary: %w", err)
			}
			if len(payload) == 0 || len(payload) > rootplan.MaxHelperPayload {
				return fmt.Errorf("helper binary size must be between 1 byte and %d MiB", rootplan.MaxHelperPayload>>20)
			}
			digest := rootplan.PayloadDigest(payload)
			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "Would install %s (%d bytes, %s) through the signed root helper.\n", resolved, len(payload), digest)
				if allowDowngrade {
					fmt.Fprintln(cmd.OutOrStdout(), "Rollback consent will be signed; the installed helper refuses it while a destroy journal is pending.")
				}
				return nil
			}
			if !yes {
				return errors.New("helper update requires explicit --yes confirmation (use --dry-run first)")
			}
			if err := updateSignedRootHelper(cfg, payload, allowDowngrade); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Root helper updated atomically to %s.\n", digest)
			return nil
		},
	}
	addConfigFlags(command, &flags)
	command.Flags().StringVar(&binaryPath, "binary", "", "Linux Shuttle binary to install (default: current executable)")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "show the signed replacement without mutating")
	command.Flags().BoolVar(&yes, "yes", false, "confirm the helper replacement")
	command.Flags().BoolVar(&allowDowngrade, "allow-downgrade", false, "allow an older helper release only when no destroy journal is pending")
	return command
}

func queryRootHelperCapabilities(cfg *config.Config) (rootHelperCapabilities, error) {
	group, host, err := singleVPS(cfg)
	if err != nil {
		return rootHelperCapabilities{}, err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return rootHelperCapabilities{}, err
	}
	return queryRootHelperCapabilitiesWithClient(group, host, client)
}

func queryRootHelperCapabilitiesWithClient(group config.ServerGroup, host string, client *shuttlessh.Client) (rootHelperCapabilities, error) {
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return rootHelperCapabilities{}, err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return rootHelperCapabilities{}, err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return rootHelperCapabilities{}, err
	}
	return queryRootHelperCapabilitiesOn(client, identity, privateKey)
}

func queryRootHelperCapabilitiesOn(client *shuttlessh.Client, identity trustedHostIdentity, privateKey ed25519.PrivateKey) (rootHelperCapabilities, error) {
	plan, err := rootplan.NewCapabilitiesAudit(identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return rootHelperCapabilities{}, err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return rootHelperCapabilities{}, err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		return rootHelperCapabilities{}, fmt.Errorf("installed root helper cannot report capabilities: %s", strings.TrimSpace(result.Stderr))
	}
	body := result.Stdout
	if marker := strings.LastIndex(body, "\noperation=audit "); marker >= 0 {
		body = body[:marker]
	}
	return decodeRootHelperCapabilities(strings.TrimSpace(body))
}

// ensureRequiredRootHelperCapabilities refuses a promotion the installed helper
// cannot carry out, before the first build.
//
// It queries unconditionally. requiredRootHelperCapabilities never returns an
// empty list, so the early return this function used to take ("no feature is
// declared, therefore any helper will do") is gone, and with it the failure it
// let through: a helper predating the convergence wait accepted the stack,
// returned before Swarm had pulled anything, and then stopped the loopback
// registry for its garbage sweep while the pulls were still in flight. Every
// task was Rejected on "connection refused", Swarm rolled the release back, and
// the only thing that named the incident was a release-identity mismatch
// pointing at Swarm. One signed audit round-trip buys the error that names the
// helper instead.
// rootHelperBootstrapHint says how to install a helper that is too old to
// replace itself. "with root access" alone sends the operator at a door shuttle
// itself closed: setup writes PermitRootLogin no, so the binary cannot be
// scp'd as root. It travels through the deployment account, which is reachable,
// and the provider console installs it. Measured on a v0.0.4 helper: without
// this route the host was undeployable until someone found the console.
const rootHelperBootstrapHint = "bootstrap this release once with root access: `shuttle setup` sets PermitRootLogin no, so copy the Linux shuttle binary to the deployment account (`scp <binary> <deploy-user>@<host>:shuttle-root.new`), then, as root on the provider console, run `install -m 0755 -o root -g root ~<deploy-user>/shuttle-root.new /usr/local/libexec/shuttle-root`"

func ensureRequiredRootHelperCapabilities(cfg *config.Config, group config.ServerGroup, host string, client *shuttlessh.Client) error {
	required := requiredRootHelperCapabilities(cfg)
	return ensureRootHelperCapabilitiesWithClient(group, host, client, required)
}

func ensureRootHelperCapabilitiesWithClient(group config.ServerGroup, host string, client *shuttlessh.Client, required []string) error {
	report, err := queryRootHelperCapabilitiesWithClient(group, host, client)
	if err != nil {
		if rootHelperLacksCapabilities(err) {
			if slices.Contains(required, capabilityDestroyLedgerOnly) {
				return fmt.Errorf("managed PostgreSQL safety requires capability %s; run `shuttle helper update --dry-run`, then `shuttle helper update --yes`: %w", capabilityDestroyLedgerOnly, err)
			}
			return fmt.Errorf("deployment requires root helper capabilities %s, but the installed helper predates capability negotiation and cannot self-update; %s, then run `shuttle helper status`: %w", strings.Join(required, ","), rootHelperBootstrapHint, err)
		}
		return fmt.Errorf("cannot negotiate required root helper capabilities %s: %w", strings.Join(required, ","), err)
	}
	return rootHelperCapabilityRefusal(report, required)
}

func updateSignedRootHelper(cfg *config.Config, payload []byte, allowDowngrade bool) error {
	return updateSignedRootHelperWithFinalizer(cfg, payload, allowDowngrade, signedHelperMigrationFinalizer)
}

func updateSignedRootHelperWithFinalizer(cfg *config.Config, payload []byte, allowDowngrade bool, finalize helperMigrationFinalizer) error {
	group, host, err := singleVPS(cfg)
	if err != nil {
		return err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return err
	}
	client.SetOperationTimeout(5 * time.Minute)
	report, err := queryRootHelperCapabilitiesWithClient(group, host, client)
	legacy := false
	pending := false
	pendingID := ""
	if err != nil {
		if helperMigrationCapabilitiesWithheld(err) {
			pending = true
			if status, ok := helperMigrationStatusFromCapabilityError(err); ok {
				pendingID = status.ID
			}
		} else if !rootHelperLacksCapabilities(err) {
			return fmt.Errorf("cannot verify whether the installed helper supports self-update: %w", err)
		}
		if !pending {
			legacy = true
		}
	} else if err := requireRootHelperCapabilities(report, []string{capabilitySignedHelperUpdate}); err != nil {
		return fmt.Errorf("installed helper cannot self-update; %s: %w", rootHelperBootstrapHint, err)
	} else if !containsRootHelperCapability(report.Features, "helper-migration") {
		// A helper that can understand the capability audit and the historical
		// signed update still cannot receive the new finalize action safely.
		// Treat it as legacy and finalize only after its candidate has created
		// the durable intent.
		legacy = true
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return err
	}
	candidateDigest := rootplan.PayloadDigest(payload)
	var reservedID string
	if !pending {
		plan, err := rootplan.NewHelperUpdate(candidateDigest, int64(len(payload)), identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 5*time.Minute)
		if err == nil {
			plan.Helper.AllowDowngrade = allowDowngrade
		}
		// A modern helper already requires a durable operation ID on
		// helper-update. Signing without one is refused at apply, and the
		// candidate --help probe then sees the caller's own active journal
		// as a foreign lease. Reserve helper-update first and bind that ID
		// into the signed plan. The legacy first hop stays operation-free:
		// an old helper never understood operation-reserve.
		if err == nil && !legacy {
			reservedID, err = reserveRemoteOperation(client, identity, privateKey, helperMigrationOwnReservationKind, "")
			if err != nil {
				return fmt.Errorf("reserve helper-update operation: %w", err)
			}
			plan, err = bindOperationPlan(plan, reservedID, helperMigrationOwnReservationKind, "")
		}
		if err == nil {
			plan, err = rootplan.Sign(plan, privateKey)
		}
		if err != nil {
			return err
		}
		envelope, err := encodeRootHelperEnvelope(plan, payload)
		if err != nil {
			return err
		}
		result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
		if result.Code != 0 {
			applyErr := fmt.Errorf("signed root helper update failed: %s", strings.TrimSpace(result.Stderr))
			if reservedID != "" {
				return helperUpdateApplyFailure(client, identity, privateKey, reservedID, applyErr)
			}
			return applyErr
		}
	}
	// The candidate probe writes the durable intent under the parent's flock.
	// Skipping finalization after a modern replacement leaves capability
	// advertisement withheld on the new helper. The parent-wired
	// signedHelperMigrationFinalizer stays the only completion channel;
	// a completed intent is idempotent and a missing hook still fails closed.
	if finalize == nil {
		finalize = unavailableHelperMigrationFinalizer
	}
	if err := finalize(client, identity, helperMigrationFinalizeRequest{CandidateSHA256: candidateDigest, Host: identity.HostKeyFingerprint, IntentID: pendingID}); err != nil {
		return fmt.Errorf("helper migration finalization failed (replacement is not confirmed); see docs/operations-recovery.md#interrupted-helper-probe: %w", err)
	}
	updated, err := queryRootHelperCapabilitiesWithClient(group, host, client)
	if err != nil {
		return fmt.Errorf("root helper was replaced but its capabilities cannot be verified: %w", err)
	}
	want := currentRootHelperCapabilities().Features
	sort.Strings(want)
	if err := requireRootHelperCapabilities(updated, want); err != nil {
		return fmt.Errorf("root helper was replaced but verification failed: %w", err)
	}
	return nil
}

// A failed modern apply leaves its reserved helper-update record durable; query
// it once so the operator sees recovery guidance instead of only SSH stderr.
func helperUpdateApplyFailure(client *shuttlessh.Client, identity trustedHostIdentity, key ed25519.PrivateKey, id string, applyErr error) error {
	records, err := readRemoteOperationStatus(client, identity, key)
	if err != nil {
		return fmt.Errorf("%w; %w", applyErr, hedgedRecoveryHint(id, "helper-update"))
	}
	for _, record := range records {
		if record.ID == id && record.RecoveryRequired {
			return fmt.Errorf("%w; %w", applyErr, recoveryHint(id, record.Kind))
		}
		// A lost reply or preflight refusal can leave the reservation before
		// its first phase. Request refusal, never abort: the helper rechecks
		// that no phase started under its lock before releasing the lease.
		if record.ID == id && record.Kind == "helper-update" && record.State == "active" && len(record.Phases) == 0 {
			operation := &remoteOperation{id: id, kind: "helper-update", client: client, identity: identity, key: key}
			if err := remoteOperationControl(operation, "operation-refuse", "helper-update failed before mutation"); err != nil {
				return errors.Join(applyErr, err, hedgedRecoveryHint(id, "helper-update"))
			}
		}
	}
	return applyErr
}

func rootHelperLacksCapabilities(err error) bool {
	if err == nil {
		return false
	}
	reason := err.Error()
	return rootHelperLacksOperation(reason) ||
		strings.Contains(reason, "unsupported audit operation") ||
		strings.Contains(reason, "decode root-operation plan")
}

func containsRootHelperCapability(features []string, want string) bool {
	for _, feature := range features {
		if feature == want {
			return true
		}
	}
	return false
}
