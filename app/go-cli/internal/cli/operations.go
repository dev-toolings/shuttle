package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

// newOperationsCommand exposes the VPS journal through the same pinned SSH and
// signed helper channel used by the other privileged operations.
func newOperationsCommand() *cobra.Command {
	var flags configFlags
	root := &cobra.Command{Use: "operations", Short: "Inspect and explicitly recover coordinated maintenance operations"}
	root.PersistentFlags().StringVar(&flags.path, "config", "", "path to config.json (legacy shuttle.yml is accepted)")
	root.PersistentFlags().StringVarP(&flags.env, "env", "e", "", "environment overlay")
	root.AddCommand(newOperationsStatusCommand(&flags), newOperationsRecoverCommand(&flags), newOperationsWritersCommand(&flags), newRebootCommand())
	return root
}

func newOperationsStatusCommand(provided ...*configFlags) *cobra.Command {
	flags, owned := operationFlags(provided...)
	var asJSON bool
	cmd := &cobra.Command{Use: "status", Short: "Show active and recovered operation journal records", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadWithFlags(*flags)
		if err != nil {
			return err
		}
		body, err := runRemoteOperations(cfg, "status", "", "")
		if err != nil {
			return err
		}
		var records []coord.Record
		if err := decodeSingleJSON(body, &records); err != nil {
			return fmt.Errorf("decode remote operations status: %w", err)
		}
		if asJSON {
			return writeOperationJSON(cmd.OutOrStdout(), records)
		}
		for _, record := range records {
			target := record.App
			if target == "" {
				target = "VPS"
			}
			state := record.State
			if record.RecoveryRequired {
				state = coord.RecoveryRequired
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %-15s %-16s target=%s age=%s\n", record.ID, record.Kind, state, target, operationAge(record.UpdatedAt))
		}
		return nil
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print machine-readable journal records")
	if owned {
		addConfigFlags(cmd, flags)
	}
	return cmd
}

func newOperationsRecoverCommand(provided ...*configFlags) *cobra.Command {
	flags, owned := operationFlags(provided...)
	var asJSON, dryRun, yes bool
	var planDigest string
	cmd := &cobra.Command{Use: "recover <operation-id>", SilenceUsage: true, Short: "Observe and explicitly recover one interrupted operation", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !dryRun && !yes {
			return errors.New("operation recovery requires --yes after reviewing --dry-run")
		}
		cfg, err := loadWithFlags(*flags)
		if err != nil {
			return err
		}
		if dryRun {
			body, err := runRemoteOperations(cfg, "recovery-plan", args[0], "")
			if err != nil {
				return err
			}
			var plan coord.RecoveryPlan
			if err := decodeSingleJSON(body, &plan); err != nil {
				return fmt.Errorf("decode remote recovery plan: %w", err)
			}
			if asJSON {
				return writeOperationJSON(cmd.OutOrStdout(), plan)
			}
			return writeRecoveryPlan(cmd.OutOrStdout(), plan)
		}
		if planDigest == "" {
			return errors.New("recovery apply requires --plan-digest from a fresh observed dry run")
		}
		body, err := runRemoteOperations(cfg, "recovery-apply", args[0], planDigest)
		return presentRemoteRecoveryApply(cmd.OutOrStdout(), asJSON, args[0], planDigest, body, err)
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print machine-readable recovery output")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "observe and print planned safe actions without applying them")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the exact observed recovery plan")
	cmd.Flags().StringVar(&planDigest, "plan-digest", "", "digest printed by the reviewed recovery plan")
	if owned {
		addConfigFlags(cmd, flags)
	}
	return cmd
}

func operationFlags(provided ...*configFlags) (*configFlags, bool) {
	if len(provided) > 0 && provided[0] != nil {
		return provided[0], false
	}
	return &configFlags{}, true
}

func runRemoteOperations(cfg *config.Config, action, id, digest string) ([]byte, error) {
	if cfg == nil || cfg.UsesCompose() {
		return nil, errors.New("coordinated operations require deploy.strategy: swarm and a configured root helper")
	}
	group, host, err := singleVPS(cfg)
	if err != nil {
		return nil, err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return nil, err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return nil, err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return nil, err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return nil, err
	}
	return runRemoteOperationsOn(client, identity, privateKey, action, id, digest)
}

// runRemoteOperationsOn sends one signed operations request over an already
// open connection, so a deploy can recover its own blocker without a second
// SSH session.
func runRemoteOperationsOn(client *shuttlessh.Client, identity trustedHostIdentity, privateKey ed25519.PrivateKey, action, id, digest string) ([]byte, error) {
	client.SetOperationTimeout(10 * time.Minute)
	if action == "recovery-plan" || action == "recovery-apply" {
		// Recovery can reach an older helper without ever passing destroy's
		// capability gate. Read the record first: legacy pending drops carry
		// neither signed consent nor a dump, and must never be replayed there.
		body, err := runRemoteOperationsOn(client, identity, privateKey, "status", "", "")
		if err != nil {
			return nil, err
		}
		var records []coord.Record
		if err := decodeSingleJSON(body, &records); err != nil {
			return nil, fmt.Errorf("decode recovery operation record: %w", err)
		}
		found := false
		for _, record := range records {
			if record.ID != id {
				continue
			}
			found = true
			if record.Kind == "destroy" {
				report, err := queryRootHelperCapabilitiesOn(client, identity, privateKey)
				if err == nil {
					err = requireRootHelperCapabilities(report, []string{capabilityDestroySafeOptions})
				}
				if err != nil {
					return nil, fmt.Errorf("destroy recovery requires %s; run shuttle helper update --dry-run, then shuttle helper update --yes: %w", capabilityDestroySafeOptions, err)
				}
			}
			break
		}
		if !found {
			return nil, fmt.Errorf("recovery operation %s was not found in helper status", id)
		}
	}
	envelope, err := remoteOperationsEnvelope(identity, privateKey, action, id, digest)
	if err != nil {
		return nil, err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	return remoteOperationsResult(action, result)
}

// remoteOperationsEnvelope is shared by the regular command and bounded
// recovery probes; the latter must not mutate the shared SSH timeout.
func remoteOperationsEnvelope(identity trustedHostIdentity, privateKey ed25519.PrivateKey, action, id, digest string) ([]byte, error) {
	var plan rootplan.Plan
	var err error
	now := time.Now().UTC()
	switch action {
	case "status":
		plan, err = rootplan.NewOperationsStatus(identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 2*time.Minute)
	case "recovery-plan":
		plan, err = rootplan.NewRecoveryPlan(id, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 2*time.Minute)
	case "recovery-apply":
		plan, err = rootplan.NewRecoveryApply(id, digest, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, 2*time.Minute)
	default:
		return nil, fmt.Errorf("unsupported remote operations action %q", action)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return nil, err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	return envelope, err
}

const (
	recoveryPlanSchemaName  = "shuttle.recovery-plan/v1"
	recoveryApplySchemaName = "shuttle.recovery-apply/v1"
)

// remoteRecoveryApplyResult is the untagged decode of shuttle.recovery-apply/v1.
// The linux helper owns the producer type; this copy is the CLI transport
// contract so a workstation can still print a partial apply.
type remoteRecoveryApplyResult struct {
	Schema            string                    `json:"schema"`
	ID                string                    `json:"id"`
	State             string                    `json:"state"`
	Observed          coord.RecoveryObservation `json:"observed"`
	Actions           []string                  `json:"actions"`
	PlanDigest        string                    `json:"plan_digest"`
	CompletedSteps    []string                  `json:"completed_steps"`
	Details           []string                  `json:"details,omitempty"`
	Error             string                    `json:"error,omitempty"`
	RemainingRecovery []string                  `json:"remaining_recovery"`
}

func (r remoteRecoveryApplyResult) asPlan() coord.RecoveryPlan {
	return coord.RecoveryPlan{Schema: r.Schema, ID: r.ID, State: r.State, Observed: r.Observed, Actions: r.Actions, PlanDigest: r.PlanDigest}
}

// remoteOperationsResult keeps recovery-apply stdout on a nonzero helper
// exit. The apply report is the operator's only view of completed_steps
// after a partial apply; discarding it made every failed recovery look
// like it did nothing. Other actions still fail closed on stderr.
func remoteOperationsResult(action string, result shuttlessh.Result) ([]byte, error) {
	body := []byte(result.Stdout)
	var remoteErr error
	if result.Code != 0 {
		remoteErr = fmt.Errorf("remote %s failed: %s", action, strings.TrimSpace(result.Stderr))
		if action != "recovery-apply" || len(bytes.TrimSpace(body)) == 0 {
			return nil, remoteErr
		}
	}
	if err := validateRemoteJSON(result.Stdout); err != nil {
		if remoteErr != nil {
			return nil, remoteErr
		}
		return nil, fmt.Errorf("remote %s returned an invalid JSON document: %w", action, err)
	}
	return body, remoteErr
}

func presentRemoteRecoveryApply(out io.Writer, asJSON bool, id, digest string, body []byte, remoteErr error) error {
	if len(bytes.TrimSpace(body)) == 0 {
		if remoteErr != nil {
			return remoteErr
		}
		return errors.New("remote recovery-apply returned an empty document")
	}
	report, err := decodeRemoteRecoveryApply(body, id, digest)
	if err != nil {
		if remoteErr != nil {
			return remoteErr
		}
		return fmt.Errorf("decode remote recovery result: %w", err)
	}
	if asJSON {
		if report.Schema == recoveryPlanSchemaName {
			err = writeOperationJSON(out, report.asPlan())
		} else {
			err = writeOperationJSON(out, report)
		}
	} else {
		err = writeRecoveryApplyResult(out, report)
	}
	if err != nil {
		return err
	}
	if remoteErr != nil {
		return remoteErr
	}
	if report.Error != "" {
		return errors.New(report.Error)
	}
	if len(report.RemainingRecovery) > 0 {
		return errors.New("recovery apply left incomplete recovery steps")
	}
	return nil
}

func decodeRemoteRecoveryApply(body []byte, wantID, wantDigest string) (remoteRecoveryApplyResult, error) {
	var raw map[string]json.RawMessage
	if err := decodeSingleJSON(body, &raw); err != nil {
		return remoteRecoveryApplyResult{}, err
	}
	schema, err := jsonStringField(raw, "schema")
	if err != nil || schema == "" {
		return remoteRecoveryApplyResult{}, errors.New("recovery result is missing a schema")
	}
	switch schema {
	case recoveryApplySchemaName:
		return decodeRecoveryApplyEnvelope(body, raw, wantID, wantDigest)
	case recoveryPlanSchemaName:
		var plan coord.RecoveryPlan
		if err := decodeSingleJSON(body, &plan); err != nil {
			return remoteRecoveryApplyResult{}, err
		}
		if err := matchRecoveryIdentity(plan.ID, plan.PlanDigest, wantID, wantDigest); err != nil {
			return remoteRecoveryApplyResult{}, err
		}
		return remoteRecoveryApplyResult{Schema: plan.Schema, ID: plan.ID, State: plan.State, Observed: plan.Observed, Actions: plan.Actions, PlanDigest: plan.PlanDigest}, nil
	default:
		return remoteRecoveryApplyResult{}, fmt.Errorf("unsupported recovery result schema %q", schema)
	}
}

func decodeRecoveryApplyEnvelope(body []byte, raw map[string]json.RawMessage, wantID, wantDigest string) (remoteRecoveryApplyResult, error) {
	for _, key := range []string{"schema", "id", "state", "observed", "actions", "plan_digest", "completed_steps", "remaining_recovery"} {
		if _, ok := raw[key]; !ok {
			return remoteRecoveryApplyResult{}, fmt.Errorf("recovery apply JSON is missing %s", key)
		}
	}
	if err := requireJSONArray(raw, "actions"); err != nil {
		return remoteRecoveryApplyResult{}, err
	}
	if observed := bytes.TrimSpace(raw["observed"]); len(observed) == 0 || observed[0] != '{' {
		return remoteRecoveryApplyResult{}, errors.New("recovery apply observed field must be an object")
	}
	if err := requireJSONArray(raw, "completed_steps"); err != nil {
		return remoteRecoveryApplyResult{}, err
	}
	if err := requireJSONArray(raw, "remaining_recovery"); err != nil {
		return remoteRecoveryApplyResult{}, err
	}
	var report remoteRecoveryApplyResult
	if err := decodeSingleJSON(body, &report); err != nil {
		return remoteRecoveryApplyResult{}, err
	}
	if strings.TrimSpace(report.State) == "" {
		return remoteRecoveryApplyResult{}, errors.New("recovery apply state is missing")
	}
	if report.Schema != recoveryApplySchemaName {
		return remoteRecoveryApplyResult{}, fmt.Errorf("unsupported recovery result schema %q", report.Schema)
	}
	if err := matchRecoveryIdentity(report.ID, report.PlanDigest, wantID, wantDigest); err != nil {
		return remoteRecoveryApplyResult{}, err
	}
	if report.CompletedSteps == nil {
		report.CompletedSteps = []string{}
	}
	if report.RemainingRecovery == nil {
		report.RemainingRecovery = []string{}
	}
	return report, nil
}

func matchRecoveryIdentity(gotID, gotDigest, wantID, wantDigest string) error {
	if gotID != wantID {
		return fmt.Errorf("recovery result id %q does not match requested operation %q", gotID, wantID)
	}
	if gotDigest != wantDigest {
		return fmt.Errorf("recovery result plan-digest %q does not match --plan-digest", gotDigest)
	}
	return nil
}

func jsonStringField(raw map[string]json.RawMessage, key string) (string, error) {
	value, ok := raw[key]
	if !ok {
		return "", fmt.Errorf("missing %s", key)
	}
	var text string
	if err := json.Unmarshal(value, &text); err != nil {
		return "", fmt.Errorf("recovery result field %s is not a string", key)
	}
	return text, nil
}

func requireJSONArray(raw map[string]json.RawMessage, key string) error {
	value, ok := raw[key]
	if !ok {
		return fmt.Errorf("recovery apply JSON is missing %s", key)
	}
	trimmed := bytes.TrimSpace(value)
	// The helper marshals empty slices as null in existing apply reports.
	if bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return fmt.Errorf("recovery apply JSON field %s must be an array", key)
	}
	return nil
}

func writeRecoveryApplyResult(out io.Writer, report remoteRecoveryApplyResult) error {
	if err := writeRecoveryPlan(out, report.asPlan()); err != nil {
		return err
	}
	if report.Schema != recoveryApplySchemaName && report.Error == "" && len(report.CompletedSteps) == 0 && len(report.RemainingRecovery) == 0 {
		return nil
	}
	if len(report.CompletedSteps) == 0 {
		fmt.Fprintln(out, "  completed: none")
	}
	for _, detail := range report.Details {
		fmt.Fprintln(out, detail)
	}
	for _, step := range report.CompletedSteps {
		fmt.Fprintf(out, "  completed: %s\n", step)
	}
	if len(report.RemainingRecovery) == 0 {
		fmt.Fprintln(out, "  remaining: none")
	}
	for _, step := range report.RemainingRecovery {
		fmt.Fprintf(out, "  remaining: %s\n", step)
	}
	if report.Error != "" {
		fmt.Fprintf(out, "  error: %s\n", report.Error)
	}
	return nil
}

func validateRemoteJSON(body string) error {
	decoder := json.NewDecoder(strings.NewReader(body))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("helper stdout contains a trailer or multiple documents")
	}
	return nil
}

func decodeSingleJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}

// localRecoveryObserver is deliberately incapable of claiming remote state.
// Recovery observations belong to the root helper on the VPS, after pinned SSH
// and signature validation. In particular, Docker presence on a workstation
// cannot prove that a VPS executor stopped.
func localRecoveryObserver(context.Context, coord.Record) (coord.RecoveryObservation, error) {
	return coord.RecoveryObservation{Safe: false, ServiceState: "remote VPS observation required", RegistryState: "remote VPS observation required", DataState: "remote VPS observation required", Unresolved: []string{"observation was not collected by the VPS helper"}}, nil
}

func writeOperationJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeRecoveryPlan(out io.Writer, plan coord.RecoveryPlan) error {
	fmt.Fprintf(out, "Recovery plan for %s (%s)\n", plan.ID, plan.State)
	fmt.Fprintf(out, "  observed service=%s registry=%s data=%s\n", plan.Observed.ServiceState, plan.Observed.RegistryState, plan.Observed.DataState)
	fmt.Fprintf(out, "  plan-digest=%s\n", plan.PlanDigest)
	for _, action := range plan.Actions {
		fmt.Fprintf(out, "  -> %s\n", action)
	}
	for _, detail := range plan.Observed.Details {
		fmt.Fprintf(out, "  inventory: %s\n", detail)
	}
	return nil
}

func operationAge(value string) string { return strings.TrimSpace(ageSince(value)) }

func ageSince(value string) string {
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || at.After(time.Now()) {
		return "unknown"
	}
	return time.Since(at).Round(time.Second).String()
}

// operationReservationWait is how long a command queues behind a conflicting
// operation on the same host before giving up. It matches the helper's
// rootOperationBudget: past that, the operation it waits on has been aborted by
// its watchdog anyway.
const operationReservationWait = 10 * time.Minute

// operationReservationPoll spaces the retries. Each retry is one signed SSH
// round trip, so it is kept well above the helper's own lock poll.
const operationReservationPoll = 5 * time.Second

// Unknown reservation replies are retried only a small, bounded number of
// times. The reservation ID makes those sends idempotent at the coordinator.
var operationReservationUnknownAttempts = 3
var operationReservationUnknownPause = operationReservationPoll

type reservationOutcomeUnknownError struct{ ID, Stderr string }

func (e *reservationOutcomeUnknownError) Error() string {
	return fmt.Sprintf("reserve coordinated operation %s: the host did not confirm the reservation: %s", e.ID, e.Stderr)
}

// reserveRemoteOperation reserves an operation, waiting while another one that
// conflicts with it is still running.
//
// The helper refuses a conflicting reservation at once ("waited 0s"). That was
// the whole failure when a deploy of one application met the deploy of another
// on the same host: nothing was wrong, the second simply arrived 49 seconds
// too early. A conflict with a live operation is now waited out; one that
// requires recovery is returned at once, because only an operator can clear it.
//
// One exception to "only an operator can clear it": a deploy blocked by an
// earlier deploy of the same application whose recovery has nothing left to
// do. See autoRecoverNoopDeploy.
//
// Reserve returns an existing active record only when its operator key,
// principal, host, kind and application match. Reusing this ID therefore makes
// retries adopt this invocation's reservation without adopting another user's.
func reserveRemoteOperation(client *shuttlessh.Client, identity trustedHostIdentity, privateKey ed25519.PrivateKey, kind, app string) (string, error) {
	id, err := coord.NewID()
	if err != nil {
		return "", err
	}
	started := time.Now()
	announced := false
	attempted := map[string]bool{}
	unknownAttempts := 0
	var lastUnknownErr *reservationOutcomeUnknownError
	for {
		err := reserveRemoteOperationOnce(client, identity, privateKey, id, kind, app)
		if err == nil {
			return id, nil
		}
		var unknownErr *reservationOutcomeUnknownError
		if errors.As(err, &unknownErr) {
			unknownAttempts++
			lastUnknownErr = unknownErr
			unknownFailure := func() error {
				return fmt.Errorf("%w; %w", lastUnknownErr, hedgedRecoveryHint(id, kind))
			}
			if unknownAttempts >= operationReservationUnknownAttempts || time.Since(started) >= operationReservationWait {
				return "", unknownFailure()
			}
			pause := operationReservationUnknownPause
			if pause >= operationReservationWait-time.Since(started) {
				return "", unknownFailure()
			}
			time.Sleep(pause)
			if time.Since(started) >= operationReservationWait {
				return "", unknownFailure()
			}
			continue
		}
		if blocker, ok := noopDeployRecoveryCandidate(err, kind, app); ok && !attempted[blocker] {
			attempted[blocker] = true
			if recoverErr := autoRecoverNoopDeploy(client, identity, privateKey, blocker); recoverErr != nil {
				return "", fmt.Errorf("%w; automatic recovery declined: %v; run `shuttle operations recover %s%s --dry-run`", err, recoverErr, blocker, recoveryInvocation)
			}
			continue
		}
		if !operationReservationRetryable(err) {
			if strings.Contains(err.Error(), "operation "+id+" already exists in state recovery_required") {
				return "", fmt.Errorf("%w; %w", err, recoveryHint(id, kind))
			}
			if match := recoveryRequiredBlocker.FindStringSubmatch(err.Error()); match != nil {
				err = fmt.Errorf("%w; %w", err, recoveryHint(match[1], match[2]))
				return "", err
			}
			// Once a reply was lost, the first request may have persisted, and
			// no later refusal (an older helper repeating writers-initialize, an
			// identity error on the replay) proves otherwise. Keep the ID.
			if unknownAttempts > 0 {
				return "", fmt.Errorf("%w; %w", err, hedgedRecoveryHint(id, kind))
			}
			return "", err
		}
		if time.Since(started) >= operationReservationWait {
			return "", fmt.Errorf("%w (still conflicting after waiting %s)", err, time.Since(started).Round(time.Second))
		}
		if !announced {
			fmt.Fprintf(os.Stderr, "[shuttle] %s: another operation holds this host, waiting up to %s\n", kind, operationReservationWait)
			announced = true
		}
		time.Sleep(operationReservationPoll)
	}
}

// operationReservationRetryable recognises the two refusals a wait can clear:
// a live conflicting operation, and a journal lock that stayed busy.
func operationReservationRetryable(err error) bool {
	message := err.Error()
	return strings.Contains(message, " is active for ") || strings.Contains(message, "operation lock busy after waiting")
}

// recoveryRequiredBlocker parses the helper's BusyError for an unrecovered
// operation (operations.BusyError). It reaches the client as SSH stderr.
var recoveryRequiredBlocker = regexp.MustCompile(`operation ([0-9a-f-]+) requires recovery for ([a-z][a-z0-9-]*) \(target ([^,]+),`)

// noopDeployRecoveryCandidate names the blocking operation a deploy may try to
// recover on its own: a deploy blocked by an unrecovered deploy of the same
// application. Another application, a helper update or a VPS-wide operation
// stays the operator's to observe.
func noopDeployRecoveryCandidate(err error, kind, app string) (string, bool) {
	if kind != "deploy" || app == "" || err == nil {
		return "", false
	}
	match := recoveryRequiredBlocker.FindStringSubmatch(err.Error())
	if match == nil || match[2] != "deploy" || match[3] != app {
		return "", false
	}
	return match[1], true
}

// noopRecoveryPlan accepts a plan that only closes the journal: the helper
// observed every proof it needs and derived no action from it. Its Actions
// then fall back to the record's generic checklist, so Observed.Actions, not
// Actions, is what says nothing will be changed.
func noopRecoveryPlan(plan coord.RecoveryPlan, id string) error {
	switch {
	case plan.ID != id:
		return fmt.Errorf("recovery plan is for %s", plan.ID)
	case plan.State != coord.RecoveryRequired:
		return fmt.Errorf("operation state is %q", plan.State)
	case plan.PlanDigest == "":
		return errors.New("recovery plan has no digest")
	case !plan.Observed.Safe:
		return errors.New(strings.Join(append([]string{"observation is not safe"}, plan.Observed.MissingProof...), "; "))
	case len(plan.Observed.Unresolved) > 0 || len(plan.Observed.MissingProof) > 0:
		return errors.New("observation has unresolved evidence")
	case len(plan.Observed.Actions) > 0:
		return fmt.Errorf("recovery would act on the host: %s", strings.Join(plan.Observed.Actions, "; "))
	}
	return nil
}

// autoRecoverNoopDeploy clears an aborted deploy whose recovery is pure
// bookkeeping, then lets the new deploy reserve the host.
//
// Every failed deploy aborts into recovery_required, including one that died
// in the local image build before promoting anything. On demo-console that left
// the next `shuttle deploy` refused with "requires recovery for deploy" a dozen
// times (journal of 198.51.100.31, 2026-10-06 to 2026-10-10), and each time
// the operator ran the same dry run, read "tasks match retained current
// digests", and applied it with nothing to do. This plays that exact gesture:
// the helper observes, the plan must derive no action, and the apply is bound
// to the observed digest, which the helper re-observes under its flock before
// closing the record. Any action, missing proof or other blocker still stops
// the deploy and names the manual command.
func autoRecoverNoopDeploy(client *shuttlessh.Client, identity trustedHostIdentity, privateKey ed25519.PrivateKey, id string) error {
	body, err := runRemoteOperationsOn(client, identity, privateKey, "recovery-plan", id, "")
	if err != nil {
		return err
	}
	var plan coord.RecoveryPlan
	if err := decodeSingleJSON(body, &plan); err != nil {
		return fmt.Errorf("decode remote recovery plan: %w", err)
	}
	if err := noopRecoveryPlan(plan, id); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[shuttle] deploy: previous deploy %s aborted with nothing to repair (%s); recovering it (plan-digest=%s)\n", id, plan.Observed.ServiceState, plan.PlanDigest)
	body, err = runRemoteOperationsOn(client, identity, privateKey, "recovery-apply", id, plan.PlanDigest)
	return presentRemoteRecoveryApply(io.Discard, false, id, plan.PlanDigest, body, err)
}

func reserveRemoteOperationOnce(client *shuttlessh.Client, identity trustedHostIdentity, privateKey ed25519.PrivateKey, id, kind, app string) error {
	plan, err := rootplan.NewOperationReserve(id, kind, app, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 5*time.Minute)
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		stderr := strings.TrimSpace(result.Stderr)
		if result.OutcomeUnknown {
			return &reservationOutcomeUnknownError{ID: id, Stderr: stderr}
		}
		return fmt.Errorf("reserve coordinated operation failed: %s", stderr)
	}
	return nil
}

func bindOperationPlan(plan rootplan.Plan, id, kind, app string) (rootplan.Plan, error) {
	if id == "" {
		return plan, errors.New("missing durable operation id")
	}
	return rootplan.WithOperationID(plan, id, kind, app)
}
