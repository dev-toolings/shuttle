package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

const recoveryProbeTimeout = 15 * time.Second

// Cobra runs one command per process. Capture its explicit config selection
// before RunE so errors wrapped there already contain a copyable recovery hint.
var recoveryInvocation string

var recoveryInvocationBareValue = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

func recordRecoveryInvocation(cmd *cobra.Command) {
	configPath, env := "", ""
	if flag := cmd.Flag("config"); flag != nil && flag.Changed {
		configPath = flag.Value.String()
	}
	if flag := cmd.Flag("env"); flag != nil && flag.Changed {
		env = flag.Value.String()
	}
	recoveryInvocation = recoveryInvocationSuffix(configPath, env)
}

func recoveryInvocationSuffix(configPath, env string) string {
	if configPath == "" && env == "" {
		return ""
	}
	var suffix strings.Builder
	if configPath != "" {
		suffix.WriteString(" --config ")
		suffix.WriteString(recoveryInvocationValue(configPath))
	}
	if env != "" {
		suffix.WriteString(" -e ")
		suffix.WriteString(recoveryInvocationValue(env))
	}
	return suffix.String()
}

func recoveryInvocationValue(value string) string {
	if recoveryInvocationBareValue.MatchString(value) {
		return value
	}
	return shell.Escape(value)
}

type operationRequiresRecoveryError struct {
	ID, Kind   string
	Invocation string
	Confirmed  bool
}

func (e *operationRequiresRecoveryError) Error() string {
	if !e.Confirmed {
		return fmt.Sprintf("operation %s may require recovery: check `shuttle operations status%s`, then `shuttle operations recover %s%s --dry-run`", e.ID, e.Invocation, e.ID, e.Invocation)
	}
	switch e.Kind {
	case "deploy", "rollback", "backup", "registry-gc", "secrets-sync", "run", "destroy":
		return fmt.Sprintf("operation %s requires recovery: run `shuttle operations recover %s%s --dry-run`, then `shuttle operations recover %s%s --yes --plan-digest <digest>` with the digest it prints", e.ID, e.ID, e.Invocation, e.ID, e.Invocation)
	case "helper-update":
		return fmt.Sprintf("operation %s requires recovery: run `shuttle operations recover %s%s --dry-run` and follow what it reports", e.ID, e.ID, e.Invocation)
	case "reboot":
		return fmt.Sprintf("operation %s requires recovery: `shuttle operations recover` cannot repair a reboot; run `shuttle operations reboot --resume %s%s --yes` (see `shuttle operations status%s`)", e.ID, e.ID, e.Invocation, e.Invocation)
	default:
		return fmt.Sprintf("operation %s requires recovery: `shuttle operations recover` cannot repair a %s; see `shuttle operations status%s` and docs/operations-recovery.md", e.ID, e.Kind, e.Invocation)
	}
}

// The operator-visible recovery hints follow the helper's recovery dispatch.
// A failed promotion was otherwise followed by generic lease-control noise.
func recoveryKindSupported(kind string) (bool, string) {
	switch kind {
	case "deploy", "rollback", "backup", "registry-gc", "helper-update", "secrets-sync", "run", "destroy":
		return true, ""
	case "reboot":
		return false, "reboot recovery is not owned by this reconciler; use operations reboot --resume"
	case "restore":
		return false, "kind " + kind + " requires its own reconciler"
	default:
		return false, "kind " + kind + " is not owned by this reconciler"
	}
}

func recoveryHint(id, kind string) error {
	return &operationRequiresRecoveryError{ID: id, Kind: kind, Invocation: recoveryInvocation, Confirmed: true}
}

func hedgedRecoveryHint(id, kind string) error {
	return &operationRequiresRecoveryError{ID: id, Kind: kind, Invocation: recoveryInvocation}
}

func classifyControlError(err error, client *shuttlessh.Client, identity trustedHostIdentity, key ed25519.PrivateKey, id, kind string) error {
	var controlErr *operationControlError
	if !errors.As(err, &controlErr) {
		return err
	}
	legacy := false
	for _, line := range strings.Split(controlErr.Stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "operation requires recovery" {
			return recoveryHint(id, kind)
		}
		if strings.HasSuffix(line, "operation is not active for this phase") {
			legacy = true
		}
	}
	if !legacy {
		return err
	}
	records, probeErr := readRemoteOperationStatus(client, identity, key)
	if probeErr != nil {
		return hedgedRecoveryHint(id, kind)
	}
	for _, record := range records {
		if record.ID == id {
			if record.RecoveryRequired {
				return recoveryHint(id, kind)
			}
			return err
		}
	}
	return err
}

func readRemoteOperationStatus(client *shuttlessh.Client, identity trustedHostIdentity, key ed25519.PrivateKey) ([]coord.Record, error) {
	envelope, err := remoteOperationsEnvelope(identity, key, "status", "", "")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), recoveryProbeTimeout)
	defer cancel()
	result := client.RunWithStdinContext(ctx, "sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	body, err := remoteOperationsResult("status", result)
	if err != nil {
		return nil, err
	}
	var records []coord.Record
	if err := decodeSingleJSON(body, &records); err != nil {
		return nil, err
	}
	return records, nil
}
