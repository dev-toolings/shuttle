package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/spf13/cobra"
)

// rootStackFirstRelease is set by applyRootStack (Linux) when no current.yml
// existed before a stack-apply. It lives in this shared file because the
// protocol code here reads it on every platform: declared only in the Linux
// file, it broke the darwin release build of v0.0.57.
var rootStackFirstRelease bool

// rootStackPromotionMode is the promotion mode applyRootStack chose for a
// stack-apply, before it ran `docker stack deploy`. It is reported to the client
// in the response and lives here for the same reason as rootStackFirstRelease.
var rootStackPromotionMode config.PromotionMode

const rootRefusalControlPrefix = "refused before any mutation: "
const rootKnownOutcomeControlPrefix = "run command failed: "

// cleanRootRefusalReason makes helper diagnostics safe for both the signed
// control result and stderr marker. The marker prefix is longer, so it sets the
// shared 512-byte ceiling before either protocol value is built.
func cleanRootRefusalReason(reason string) string {
	return cleanRootMarkerReason(reason, rootPreflightRefusalMarker)
}

func cleanRootKnownOutcomeReason(reason string) string {
	return cleanRootMarkerReason(reason, rootKnownOutcomeMarker)
}

func cleanRootMarkerReason(reason, marker string) string {
	reason = strings.ToValidUTF8(reason, "?")
	var cleaned strings.Builder
	space := false
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			r = ' '
		}
		if r == ' ' {
			if space || cleaned.Len() == 0 {
				continue
			}
			space = true
		} else {
			space = false
		}
		cleaned.WriteRune(r)
	}
	value := strings.TrimSpace(cleaned.String())
	maxBytes := 511 - len(marker)
	if len(value) <= maxBytes {
		return value
	}
	var bounded strings.Builder
	for _, r := range value {
		if bounded.Len()+len(string(r)) > maxBytes {
			break
		}
		bounded.WriteRune(r)
	}
	return strings.TrimSpace(bounded.String())
}

func refusedBeforeMutationReason(stderr string) (string, bool) {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if reason, ok := strings.CutPrefix(line, rootPreflightRefusalMarker); ok {
			return cleanRootRefusalReason(reason), true
		}
	}
	return "", false
}

func knownRunOutcomeReason(stderr string) (string, bool) {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if reason, ok := strings.CutPrefix(line, rootKnownOutcomeMarker); ok {
			return cleanRootKnownOutcomeReason(reason), true
		}
	}
	return "", false
}

func dockerObjectNotFound(message string) bool {
	return dockerObjectAbsent("container", "", message) || strings.Contains(strings.ToLower(message), "no such object")
}

const (
	rootHelperTrustedKey = "/etc/shuttle/trusted-root-operations.pem"
	maxRootPayload       = 4 << 20
	// The pre-flight and coordinated phase have independent watchdogs. This
	// derived deadline keeps the SSH socket alive until either one can finish.
	rootOperationBudget     = 10 * time.Minute
	preRunDumpDeadline      = rootOperationBudget / 2
	preRunPreflightBudget   = preRunDumpDeadline + rootHelperOperationMargin
	rootRunTransportTimeout = preRunPreflightBudget + rootOperationBudget + rootHelperOperationMargin
	// A signed helper binary is larger than a stack or secret payload. The
	// envelope reader accepts this upper bound, then applies the narrower
	// per-action limit after decoding the signed plan.
	maxRootEnvelope = 48 << 20
	// rootHelperWarningPrefix marks a stderr line of a helper run that exits
	// zero: housekeeping that failed after the requested change succeeded.
	// The client prints those lines as warnings and nothing else from stderr.
	rootHelperWarningPrefix    = "shuttle-root warning: "
	rootHelperReclaimedPrefix  = "shuttle-root reclaimed: "
	rootPreflightRefusalMarker = "shuttle-root: refused before any mutation: "
	rootKnownOutcomeMarker     = "shuttle-root: command finished, outcome known: "
)

func reportRootHelperReclaims(stderr string) int {
	count := 0
	for _, line := range strings.Split(stderr, "\n") {
		if reclaimed, ok := strings.CutPrefix(strings.TrimSpace(line), rootHelperReclaimedPrefix); ok {
			reclaimed = strings.TrimSpace(reclaimed)
			if reclaimed == "" {
				continue
			}
			output.Detail("Image store: removed %s", reclaimed)
			count++
		}
	}
	return count
}

// reportRootHelperWarnings prints the warnings a successful helper run left
// on stderr. Without it a deferred registry sweep would be visible only in the
// host journal, and a disk that keeps filling would surprise the operator.
// It reports whether any warning was printed, so a caller does not follow one
// with a line claiming the work was done.
func reportRootHelperWarnings(stderr string) bool {
	warned := false
	for _, line := range strings.Split(stderr, "\n") {
		if warning, ok := strings.CutPrefix(strings.TrimSpace(line), rootHelperWarningPrefix); ok && warning != "" {
			output.Attn("%s", warning)
			warned = true
		}
	}
	return warned
}

// rootServiceName bounds the service name that reaches a Caddy fragment, a
// `docker service ps` argument or a Swarm service name. It mirrors the Compose
// charset accepted by the CLI, restated here because the root helper trusts
// nothing the CLI claims to have already checked.
//
// It lives in the untagged half of the helper because the convergence decision
// re-checks the same names and is compiled and tested on every platform.
var rootServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
var rootContainerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// rootAppName and rootOperationName restate the CLI's charsets. The helper
// re-checks every value it is handed, including ones the CLI has already
// validated: it is a trust boundary, not a second opinion.
var (
	rootAppName       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	rootOperationName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

type rootHelperEnvelope struct {
	Plan    json.RawMessage `json:"plan"`
	Payload string          `json:"payload,omitempty"`
}

// NewRootHelperCommand is selected only when the executable is installed as
// shuttle-root. The helper has one stdin-only entrypoint and no shell/path
// flags, so sudo cannot be used to broaden the signed operation.
func NewRootHelperCommand() *cobra.Command {
	root := &cobra.Command{Use: "shuttle-root", Short: "Apply signed Shuttle root operations", SilenceUsage: true, SilenceErrors: true}
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(&cobra.Command{Use: "apply [monitor-run app]", Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		if len(args) == 2 && args[0] == "monitor-run" && rootAppName.MatchString(args[1]) {
			return nil
		}
		return errors.New("apply accepts a signed envelope or the root-only monitor-run app form")
	}, RunE: func(cmd *cobra.Command, args []string) error {
		if !rootHelperSupported() {
			return errors.New("shuttle-root is supported only on Linux")
		}
		if !runningAsRoot() {
			return errors.New("shuttle-root must run as uid 0")
		}
		if len(args) == 2 {
			return runDirectRootMonitoring(args[1], cmd.OutOrStdout())
		}
		plan, payload, err := decodeRootHelperEnvelope(cmd.InOrStdin())
		if err != nil {
			return err
		}
		trusted, err := rootplan.ReadTrustedKey(rootHelperTrustedKey)
		if err != nil {
			return fmt.Errorf("load root-operation trust anchor: %w", err)
		}
		if err := rootplan.Verify(plan, trusted, time.Now()); err != nil {
			// %q, not %s: this is the one line written about a plan that has not
			// been verified, and Decode does not constrain the action field. A
			// quoted value cannot carry a newline into the journal and forge the
			// lines that follow it.
			rootLog("action=%q refused: %v", plan.Action, err)
			return err
		}
		if plan.Action != "run" {
			if err := refuseRootHelperMutationDuringMigration(plan.Action); err != nil {
				return err
			}
		}
		if coordinationRequired(plan.Action) && plan.OperationID == "" && !isDestroyDryRun(plan) {
			return errors.New("root helper requires the durable operation coordination capability")
		}
		jsonProtocol := false
		var protocolOutput []byte
		rootLog("action=%s digest=%s begin", plan.Action, plan.Digest)
		switch plan.Action {
		case "operation-writer-register", "operation-writers-close", "operation-writers-commit":
			if len(payload) != 0 {
				return errors.New("writer transition does not accept a payload")
			}
			jsonProtocol = true
			protocolOutput, err = controlRootOperationWriters(cmd.Context(), plan)

		case "helper-migration-finalize", "helper-migration-reconcile":
			if len(payload) != 0 {
				return errors.New("helper migration does not accept a payload")
			}
			err = applySignedHelperMigration(cmd.Context(), plan)

		case "operation-renew", "operation-finish", "operation-abort", "operation-refuse":
			if len(payload) != 0 {
				return errors.New("operation control does not accept a payload")
			}
			jsonProtocol = true
			protocolOutput, err = controlRootOperation(cmd.Context(), plan)
		case "operation-reserve":
			if len(payload) != 0 {
				return errors.New("operation reservation does not accept a payload")
			}
			err = reserveRootOperation(plan)
		case "operations-status":
			if len(payload) != 0 {
				return errors.New("operations status does not accept a payload")
			}
			if err := verifyRootOperationIdentity(plan); err != nil {
				return err
			}
			jsonProtocol = true
			protocolOutput, err = operationsRootStatus(cmd.Context())
		case "recovery-plan":
			if len(payload) != 0 || plan.Recovery == nil {
				return errors.New("recovery plan request is incomplete")
			}
			if err := verifyRootOperationIdentity(plan); err != nil {
				return err
			}
			if err := refuseGenericRebootRecovery(cmd.Context(), plan.Recovery.OperationID); err != nil {
				return err
			}
			jsonProtocol = true
			protocolOutput, err = recoveryRootPlan(cmd.Context(), plan.Recovery.OperationID)
		case "recovery-apply":
			if len(payload) != 0 || plan.Recovery == nil {
				return errors.New("recovery apply request is incomplete")
			}
			if err := verifyRootOperationIdentity(plan); err != nil {
				return err
			}
			if err := refuseGenericRebootRecovery(cmd.Context(), plan.Recovery.OperationID); err != nil {
				return err
			}
			jsonProtocol = true
			protocolOutput, err = recoveryRootApply(cmd.Context(), plan.Recovery.OperationID, plan.Recovery.PlanDigest, plan)
		case "baseline":
			if len(payload) != 0 {
				return errors.New("baseline does not accept a payload")
			}
			err = applyRootBaseline(plan)
		case "baseline-rollback":
			if len(payload) != 0 {
				return errors.New("baseline rollback does not accept a payload")
			}
			err = rollbackRootBaseline(plan)
		case "baseline-commit":
			if len(payload) != 0 {
				return errors.New("baseline commit does not accept a payload")
			}
			err = commitRootBaseline(plan)
		case "audit":
			if len(payload) != 0 {
				return errors.New("audit does not accept a payload")
			}
			var evidence string
			evidence, err = auditRootOperation(plan)
			if err == nil {
				if plan.Audit != nil && plan.Audit.Mode == "infra-images" {
					jsonProtocol = true
					protocolOutput = []byte(evidence)
				} else {
					fmt.Fprint(cmd.OutOrStdout(), evidence)
				}
			}
		case "run":
			if len(payload) != 0 {
				return errors.New("run does not accept a payload")
			}
			if plan.Run == nil {
				return errors.New("run operation is incomplete")
			}
			err = runDeclaredOperationForPlan(plan, cmd.OutOrStdout())
		case "secrets-apply":
			if plan.Secrets == nil {
				return errors.New("secrets operation is incomplete")
			}
			if rootplan.PayloadDigest(payload) != plan.Secrets.PayloadSHA256 {
				return errors.New("secrets payload does not match the signed digest")
			}
			err = applyRootSecrets(plan, payload)
		case "secrets-host":
			if len(payload) != 0 {
				return errors.New("host secrets does not accept a payload")
			}
			if plan.HostSecrets == nil {
				return errors.New("host secrets operation is incomplete")
			}
			err = applyRootHostSecrets(plan, cmd.OutOrStdout())
		case "secrets-hashvault":
			if plan.Hashvault == nil || rootplan.PayloadDigest(payload) != plan.Hashvault.PayloadSHA256 {
				return errors.New("hashvault payload does not match its signed request")
			}
			err = applyRootHashvault(plan, payload, cmd.OutOrStdout())
		case "hashvault-sync":
			if len(payload) != 0 {
				return errors.New("hashvault sync accepts no payload")
			}
			err = syncRootHashvault(plan, cmd.OutOrStdout())
		case "helper-update":
			if plan.Helper == nil {
				return errors.New("helper update operation is incomplete")
			}
			if int64(len(payload)) != plan.Helper.Size || rootplan.PayloadDigest(payload) != plan.Helper.PayloadSHA256 {
				return errors.New("helper payload does not match the signed digest and size")
			}
			err = applyRootHelperUpdate(plan, payload)
		case "stack-apply", "stack-rollback":
			if plan.Stack == nil {
				return errors.New("stack operation is incomplete")
			}
			if plan.Action == "stack-apply" && !plan.Stack.Remove && rootplan.PayloadDigest(payload) != plan.Stack.PayloadSHA256 {
				return errors.New("stack payload does not match the signed digest")
			}
			if plan.Stack.Remove && len(payload) != 0 {
				return errors.New("stack removal does not accept a payload")
			}
			if plan.Action == "stack-rollback" && len(payload) != 0 {
				return errors.New("stack rollback does not accept a payload")
			}
			rootStackFirstRelease = false
			rootStackPromotionMode = ""
			err = applyRootStack(plan, payload)
			// Printed on every successful stack-apply, not only for a first
			// release: the client spends the rest of the promotion budget in the
			// mode chosen here (DEV-DEPL-83). A stack removal chose none, and a
			// missing mode reads as legacy on the other side too.
			if err == nil && plan.Action == "stack-apply" {
				jsonProtocol = true
				mode := rootStackPromotionMode
				if mode == "" {
					mode = config.PromotionModeLegacy
				}
				protocolOutput, err = json.Marshal(stackPromoteResponse{FirstRelease: rootStackFirstRelease, Mode: string(mode)})
				if err == nil {
					protocolOutput = append(protocolOutput, '\n')
				}
			}
		case "stack-reclaim":
			if plan.Stack == nil {
				return errors.New("stack operation is incomplete")
			}
			if len(payload) != 0 {
				return errors.New("stack reclaim does not accept a payload")
			}
			err = reclaimRootStack(plan)
		case "monitor-install":
			if plan.Monitoring == nil || rootplan.PayloadDigest(payload) != plan.Monitoring.PayloadSHA256 {
				return errors.New("monitoring payload does not match the signed digest")
			}
			err = installRootMonitoring(plan, payload)
		case "monitor-remove":
			if len(payload) != 0 {
				return errors.New("monitor-remove does not accept a payload")
			}
			err = removeRootMonitoring(plan)
		case "monitor-run":
			if len(payload) != 0 {
				return errors.New("monitor-run does not accept a payload")
			}
			err = runSignedRootMonitoring(plan, cmd.OutOrStdout())
		case "monitor-status":
			if len(payload) != 0 {
				return errors.New("monitor-status does not accept a payload")
			}
			err = runSignedRootMonitoringStatus(plan, cmd.OutOrStdout())
		case "monitor-maintenance":
			if len(payload) != 0 {
				return errors.New("monitor-maintenance does not accept a payload")
			}
			err = setRootMonitoringMaintenance(plan)
		case "backup-status":
			if plan.BackupStatus == nil || rootplan.PayloadDigest(payload) != plan.BackupStatus.PayloadSHA256 {
				return errors.New("backup status payload does not match the signed digest")
			}
			err = publishRootBackupStatus(plan, payload)
		default:
			return errors.New("unsupported signed root operation")
		}
		return emitRootHelperResult(cmd.OutOrStdout(), plan.Action, plan.Digest, jsonProtocol, protocolOutput, err)
	}})
	return root
}

// emitRootHelperResult is the helper's stdout contract. recoveryRootApply
// returns shuttle.recovery-apply/v1 together with an error on a partial
// apply; dropping that body on the error path hid completed_steps and
// remaining_recovery from the operator while still exiting nonzero.
func emitRootHelperResult(out io.Writer, action, digest string, jsonProtocol bool, protocolOutput []byte, err error) error {
	if err != nil {
		rootLog("action=%s digest=%s failed: %v", action, digest, err)
		if jsonProtocol {
			if writeErr := writeRootHelperProtocolOutput(out, protocolOutput); writeErr != nil {
				return fmt.Errorf("%w (also failed to write protocol output: %v)", err, writeErr)
			}
		}
		return err
	}
	rootLog("action=%s digest=%s ok", action, digest)
	if writeErr := writeRootHelperProtocolOutput(out, protocolOutput); writeErr != nil {
		return writeErr
	}
	if jsonProtocol || action == "monitor-run" || action == "monitor-status" || action == "backup-status" {
		return nil
	}
	fmt.Fprintf(out, "operation=%s digest=%s\n", action, digest)
	return nil
}

func writeRootHelperProtocolOutput(out io.Writer, protocolOutput []byte) error {
	if len(protocolOutput) == 0 {
		return nil
	}
	_, err := out.Write(protocolOutput)
	return err
}

func coordinationRequired(action string) bool {
	switch action {
	case "stack-apply", "stack-rollback", "stack-reclaim", "secrets-apply", "secrets-host", "secrets-hashvault", "hashvault-sync", "helper-update", "run":
		return true
	default:
		return false
	}
}

func encodeRootHelperEnvelope(plan rootplan.Plan, payload []byte) ([]byte, error) {
	planJSON, err := rootplan.Marshal(plan)
	if err != nil {
		return nil, err
	}
	envelope := rootHelperEnvelope{Plan: bytes.TrimSpace(planJSON)}
	if len(payload) > 0 {
		if len(payload) > rootPayloadLimit(plan) {
			return nil, errors.New("root-operation payload exceeds the limit for its action")
		}
		envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	}
	return json.Marshal(envelope)
}

func decodeRootHelperEnvelope(input io.Reader) (rootplan.Plan, []byte, error) {
	body, err := io.ReadAll(io.LimitReader(input, maxRootEnvelope+1))
	if err != nil || len(body) > maxRootEnvelope {
		return rootplan.Plan{}, nil, errors.New("root-operation envelope exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var envelope rootHelperEnvelope
	if err := decoder.Decode(&envelope); err != nil || len(envelope.Plan) == 0 {
		return rootplan.Plan{}, nil, errors.New("decode root-operation envelope")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return rootplan.Plan{}, nil, errors.New("root-operation envelope must contain one JSON document")
	}
	plan, err := rootplan.Decode(bytes.NewReader(envelope.Plan))
	if err != nil {
		return rootplan.Plan{}, nil, err
	}
	var payload []byte
	if envelope.Payload != "" {
		payload, err = base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil || len(payload) > rootPayloadLimit(plan) {
			return rootplan.Plan{}, nil, errors.New("decode root-operation payload")
		}
	}
	return plan, payload, nil
}

func rootPayloadLimit(plan rootplan.Plan) int {
	if plan.Action == "helper-update" {
		return rootplan.MaxHelperPayload
	}
	return maxRootPayload
}
