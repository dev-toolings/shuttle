package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/readiness"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func runSignedStackAudit(cfg *config.Config, mode, service string, lines int) (string, error) {
	group, host, err := singleVPS(cfg)
	if err != nil {
		return "", err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return "", err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return "", err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return "", err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return "", err
	}
	plan, err := rootplan.NewStackAudit(mode, cfg.App, service, lines, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return "", err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return "", err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		return "", fmt.Errorf("signed %s audit failed: %s", mode, result.Stderr)
	}
	return result.Stdout, nil
}

func runSignedReadinessAudit(cfg *config.Config) (readiness.Report, error) {
	if !cfg.IsInternal() && cfg.Readiness.HealthcheckPath == "" {
		return readiness.Report{}, errors.New(`readiness.healthcheck_path is required for a public app: add it to config.json, for example {"readiness": {"healthcheck_path": "/health"}}`)
	}
	group, host, err := singleVPS(cfg)
	if err != nil {
		return readiness.Report{}, err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return readiness.Report{}, err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return readiness.Report{}, err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return readiness.Report{}, err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return readiness.Report{}, err
	}
	allowedSSHUsers := cfg.AllowedSSHUsers()
	if len(identity.AllowedSSHUsers) > 0 {
		allowedSSHUsers = append([]string(nil), identity.AllowedSSHUsers...)
	}
	domain, healthPath := domainString(cfg.Domain), cfg.Readiness.HealthcheckPath
	if cfg.IsInternal() {
		domain, healthPath = "", ""
	}
	plan, err := rootplan.NewReadinessAuditWithAccess(cfg.App, domain, healthPath, "", group.Port, cfg.Production.Redis, cfg.AllowedPublicTCPPorts(), allowedSSHUsers, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return readiness.Report{}, err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return readiness.Report{}, err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		if err := internalReadinessHelperCompatibilityError(domain, result.Stderr); err != nil {
			return readiness.Report{}, err
		}
		return readiness.Report{}, fmt.Errorf("signed readiness audit failed: %s", strings.TrimSpace(result.Stderr))
	}
	body := result.Stdout
	if marker := strings.LastIndex(body, "\noperation=audit "); marker >= 0 {
		body = body[:marker]
	}
	var report readiness.Report
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		return readiness.Report{}, fmt.Errorf("decode signed readiness report: %w", err)
	}
	report.Target = "deploy@" + host
	return report, nil
}

func internalReadinessHelperCompatibilityError(domain, stderr string) error {
	// The helper prints its refusal with a trailing newline (Fprintln), and
	// SSH keeps it: compare the trimmed text, still exactly.
	if domain == "" && strings.TrimSpace(stderr) == "invalid readiness audit" {
		return errors.New("the host helper is too old for an internal app readiness audit; run `shuttle helper update`")
	}
	return nil
}

// runSignedOperation asks the privileged helper to execute one operation the
// deployed stack declares. The name travels; the command does not.
//
// The validity window bounds when the operation may start, not how long it may
// run. Fifteen minutes is the protocol ceiling and leaves room for backup
// pre-flight and coordinator lock waits before the helper starts the phase.
const rootRunPlanValidity = 15 * time.Minute

func newSignedRunPlan(app, operation string, options rootplan.RunOptions, identity trustedHostIdentity, now time.Time) (rootplan.Plan, error) {
	return rootplan.NewRun(app, operation, options, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, now, rootRunPlanValidity)
}

var setRootRunTransportTimeout = func(client *shuttlessh.Client, timeout time.Duration) {
	client.SetOperationTimeout(timeout)
}

func configureRootRunTransportTimeout(client *shuttlessh.Client) {
	setRootRunTransportTimeout(client, rootRunTransportTimeout)
}

func runSignedOperation(cfg *config.Config, operation string, options rootplan.RunOptions) (body string, operationErr error) {
	group, host, err := singleVPS(cfg)
	if err != nil {
		return "", err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return "", err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return "", err
	}
	if err := ensureRootHelperCapabilitiesWithClient(group, host, client, runRootHelperCapabilities(cfg, options)); err != nil {
		return "", err
	}
	// The default two-minute deadline is a TCP socket deadline. When it fires,
	// the client aborts the lease while the helper can keep running as root. The
	// derived timeout covers both watchdogs and their usual margins.
	configureRootRunTransportTimeout(client)
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return "", err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return "", err
	}
	lease, err := beginRemoteOperation(client, identity, privateKey, "run", cfg.App)
	if err != nil {
		return "", err
	}
	defer lease.finish(&operationErr)
	plan, err := newSignedRunPlan(cfg.App, operation, options, identity, time.Now())
	if err == nil {
		plan, err = bindOperationPlan(plan, lease.id, lease.kind, cfg.App)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return "", err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return "", err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		if reason, ok := knownRunOutcomeReason(result.Stderr); ok {
			lease.knownOutcome = true
			lease.knownOutcomeReason = reason
			return result.Stdout, fmt.Errorf("operation %s failed: %s", operation, reason)
		}
		if reason, ok := refusedBeforeMutationReason(result.Stderr); ok {
			lease.refusedBeforeMutation = true
			lease.refusalReason = reason
		}
		return result.Stdout, fmt.Errorf("operation %s failed: %s", operation, strings.TrimSpace(result.Stderr))
	}
	return result.Stdout, nil
}
