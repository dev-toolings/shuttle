package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
)

const (
	rootHelperProtocolVersion         = 1
	capabilityCoordinatedOperations   = "coordinated-operations-v1"
	capabilitySignedHelperUpdate      = "signed-helper-update"
	capabilityCaddyDomainBasicAuth    = "caddy-domain-basic-auth"
	capabilityCaddyHostRouteBasicAuth = "caddy-host-route-basic-auth"
	// capabilityCaddyBasicAuthPublicPaths names the helper that renders
	// caddy.basic_auth.public_paths. An older helper ignores the label and
	// gates everything, which is safe but leaves the prompt loop in place,
	// so a config that declares the list requires it.
	capabilityCaddyBasicAuthPublicPaths = "caddy-basic-auth-public-paths"
	capabilityReadonlyDockerDebug       = "readonly-docker-debug"
	capabilityMonitoringRuntime         = "monitoring-runtime"
	capabilityBackupLifecycle           = "backup-lifecycle"
	// An older helper decodes this label with encoding/json, silently ignores
	// backup_before, then runs the migration without a dump. This is required
	// for opted-in operations, not a capability to negotiate around.
	capabilityPreRunBackup = "pre-run-backup"
	// capabilityStackConvergenceWait names the helper that waits for the
	// release to be RUNNING before it returns, instead of returning on a
	// replica count. It is required by every deploy, unconditionally, because
	// a helper without it does not merely report optimistically: it hands
	// control back while Swarm is still pulling, and the registry sweep that
	// follows stops the loopback registry under those pulls. The tasks are
	// Rejected on "connection refused", Swarm rolls the services back, and the
	// promotion is lost. That is not a degraded feature to negotiate around,
	// it is a helper that destroys the release it was given.
	capabilityStackConvergenceWait = "stack-convergence-wait"
	// An older helper can drop an unrecorded database during destroy. Managed
	// provisioning also needs this contract to refuse adopting such objects.
	capabilityDestroyLedgerOnly = "destroy-ledger-only"
	// An older helper leaves interrupted destroys globally recovery-required
	// without a reconciler, so destroy must not reserve an operation until the
	// helper can finish that removal through operations recover.
	capabilityDestroyRecovery    = "destroy-recovery"
	capabilityDestroySafeOptions = "destroy-safe-options"
	// capabilitySecretsHost names the helper that can read the declared secrets
	// from a file on the VPS and publish them itself. A helper without it
	// refuses the action outright, which is the answer that matters: the
	// alternative to refusing is a deploy whose stack mounts secret objects
	// nobody created, and a service that waits for them until the promotion
	// budget runs out without ever saying why.
	capabilitySecretsHost      = "secrets-host"
	capabilitySecretsHashvault = "secrets-hashvault"
	// An older helper rejects the retained infra-images audit after deploy has
	// reserved an operation, leaving recovery_required before any stack change.
	capabilityInfraImagesAudit = "infra-images-audit"
	// An older coordinator rejects operation-refuse, so failed deploys and runs
	// fall back to operation-abort and leave recovery_required without a mutation.
	// This covers journal-proven pre-promotion deploy failures, runs refused
	// before mutation or ended with a known outcome, and stack-apply pre-flight.
	capabilityOperationRefusal = "operation-refusal"
)

var rootHelperCapabilityName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// Every rootplan request must either belong to the coordinated-operations-v1
// baseline or name a capability callers negotiate before sending it. A change
// in the meaning of an existing action (as deploy refusal did) also needs a
// new capability, which this table cannot detect.
var rootPlanRequestCapabilities = map[string]string{
	"action:audit":                      "",
	"action:backup-status":              "",
	"action:baseline":                   "",
	"action:baseline-commit":            "",
	"action:baseline-rollback":          "",
	"action:hashvault-sync":             capabilitySecretsHashvault,
	"action:helper-migration-finalize":  "",
	"action:helper-migration-reconcile": "",
	"action:helper-update":              "",
	"action:monitor-install":            "",
	"action:monitor-maintenance":        "",
	"action:monitor-remove":             "",
	"action:monitor-run":                "",
	"action:monitor-status":             "",
	"action:operation-abort":            "",
	"action:operation-finish":           "",
	"action:operation-refuse":           capabilityOperationRefusal,
	"action:operation-renew":            "",
	"action:operation-reserve":          "",
	"action:operation-writer-register":  "",
	"action:operation-writers-close":    "",
	"action:operation-writers-commit":   "",
	"action:operations-status":          "",
	"action:recovery-apply":             "",
	"action:recovery-plan":              "",
	"action:run":                        "",
	"action:secrets-apply":              "",
	"action:secrets-hashvault":          capabilitySecretsHashvault,
	"action:secrets-host":               "",
	"action:stack-apply":                "",
	"action:stack-reclaim":              "",
	"action:stack-rollback":             "",
	"audit:baseline":                    "",
	"audit:capabilities":                "",
	"audit:debug-inspect":               "",
	"audit:debug-logs":                  "",
	"audit:debug-network":               "",
	"audit:debug-ps":                    "",
	"audit:debug-services":              "",
	"audit:debug-tasks":                 "",
	"audit:infra-images":                capabilityInfraImagesAudit,
	"audit:logs":                        "",
	"audit:readiness":                   "",
	"audit:status":                      "",
}

type rootHelperCapabilities struct {
	Protocol int      `json:"protocol"`
	Version  string   `json:"version"`
	Features []string `json:"features"`
}

func currentRootHelperCapabilities() rootHelperCapabilities {
	features := []string{
		"helper-migration",
		capabilityCoordinatedOperations,
		capabilityCaddyBasicAuthPublicPaths,
		capabilityCaddyDomainBasicAuth,
		capabilityCaddyHostRouteBasicAuth,
		capabilityReadonlyDockerDebug,
		capabilityMonitoringRuntime,
		capabilityPreRunBackup,
		capabilityBackupLifecycle,
		capabilitySecretsHost,
		capabilitySecretsHashvault,
		capabilitySignedHelperUpdate,
		capabilityStackConvergenceWait,
		capabilityDestroyLedgerOnly,
		capabilityDestroyRecovery,
		capabilityDestroySafeOptions,
		capabilityInfraImagesAudit,
		capabilityOperationRefusal,
	}
	sort.Strings(features)
	return rootHelperCapabilities{Protocol: rootHelperProtocolVersion, Version: version.Version, Features: features}
}

func encodeRootHelperCapabilities() (string, error) {
	if err := rootHelperMigrationCapabilitiesReady(); err != nil {
		return "", err
	}
	body, err := json.Marshal(currentRootHelperCapabilities())
	if err != nil {
		return "", err
	}
	return string(body) + "\n", nil
}

func decodeRootHelperCapabilities(body string) (rootHelperCapabilities, error) {
	var report rootHelperCapabilities
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		return report, errors.New("decode root helper capabilities")
	}
	if report.Protocol < 1 || report.Version == "" || len(report.Features) == 0 || !sort.StringsAreSorted(report.Features) {
		return report, errors.New("root helper returned an invalid capability report")
	}
	for i, feature := range report.Features {
		if !rootHelperCapabilityName.MatchString(feature) || (i > 0 && report.Features[i-1] == feature) {
			return report, errors.New("root helper returned an invalid capability report")
		}
	}
	return report, nil
}

// requiredRootHelperCapabilities lists what the installed helper must be able
// to do before this configuration may be promoted.
//
// The list is never empty. Every other entry is opt-in, negotiated from what
// the configuration declares, but capabilityStackConvergenceWait is
// unconditional, because it is not a feature of the deploy, it is the
// precondition for the deploy meaning anything. An older helper answers
// "applied" in milliseconds and then garbage-collects the registry out from
// under Swarm's pulls; the release is rolled back and the operator is left
// reading a release-identity mismatch that names Swarm rather than the helper
// that caused it. Refusing here costs one signed audit round-trip and happens
// before the first build.
func requiredRootHelperCapabilities(cfg *config.Config) []string {
	required := []string{capabilityCoordinatedOperations, capabilityStackConvergenceWait}
	if cfg.UsesHostSecrets() {
		required = append(required, capabilitySecretsHost)
	}
	if cfg.UsesHashvaultSecrets() {
		required = append(required, capabilitySecretsHashvault)
	}
	if cfg.Database.Managed() {
		required = append(required, capabilityDestroyLedgerOnly)
	}
	if cfg.Monitoring != nil && cfg.Monitoring.Enabled {
		required = append(required, capabilityMonitoringRuntime)
	}
	if cfg.Caddy.DomainBasicAuth != nil {
		required = append(required, capabilityCaddyDomainBasicAuth)
	}
	if len(cfg.Caddy.BasicAuth.PublicPaths) > 0 {
		required = append(required, capabilityCaddyBasicAuthPublicPaths)
	}
	for _, operation := range cfg.Operations {
		if operation.BackupBefore {
			required = append(required, capabilityPreRunBackup)
			break
		}
	}
	for _, route := range cfg.Caddy.HostRoutes {
		if route.BasicAuth {
			required = append(required, capabilityCaddyHostRouteBasicAuth)
			break
		}
	}
	sort.Strings(required)
	return required
}

func deployRootHelperCapabilities(cfg *config.Config) []string {
	return sortedUniqueCapabilities(append(requiredRootHelperCapabilities(cfg), capabilityInfraImagesAudit, capabilityOperationRefusal))
}

// A pre-run backup of a managed database must reach a helper that drops only
// ledger-recorded objects; the negotiation keeps that gate.
func runRootHelperCapabilities(cfg *config.Config, options rootplan.RunOptions) []string {
	required := []string{capabilityCoordinatedOperations, capabilityOperationRefusal}
	if options.RequireBackup {
		required = append(required, capabilityPreRunBackup)
		if cfg != nil && cfg.Database.Managed() {
			required = append(required, capabilityDestroyLedgerOnly)
		}
	}
	return sortedUniqueCapabilities(required)
}

func sortedUniqueCapabilities(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := unique[value]; exists {
			continue
		}
		unique[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func missingRootHelperCapabilities(report rootHelperCapabilities, required []string) []string {
	available := make(map[string]bool, len(report.Features))
	for _, feature := range report.Features {
		available[feature] = true
	}
	missing := []string{}
	for _, feature := range required {
		if !available[feature] {
			missing = append(missing, feature)
		}
	}
	return missing
}

func requireRootHelperCapabilities(report rootHelperCapabilities, required []string) error {
	if missing := missingRootHelperCapabilities(report, required); len(missing) > 0 {
		return fmt.Errorf("root helper is missing required capabilities: %v", missing)
	}
	return nil
}

func rootHelperCapabilityRefusal(report rootHelperCapabilities, required []string) error {
	missing := missingRootHelperCapabilities(report, required)
	if len(missing) == 0 {
		return nil
	}
	if slices.Contains(missing, capabilityDestroyLedgerOnly) {
		return fmt.Errorf("root helper is missing required capabilities: %v; managed PostgreSQL safety requires a helper with %s: run `shuttle helper update --dry-run`, then `shuttle helper update --yes`", missing, capabilityDestroyLedgerOnly)
	}
	return fmt.Errorf("root helper is missing required capabilities: %v; the installed helper reports version %s: run `shuttle helper update --dry-run`, then `shuttle helper update --yes`", missing, report.Version)
}
