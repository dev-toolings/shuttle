package cli

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestDeployRootHelperCapabilitiesRequireInfraImagesAuditAndOperationRefusal(t *testing.T) {
	cfg := &config.Config{}
	want := []string{
		capabilityCoordinatedOperations,
		capabilityInfraImagesAudit,
		capabilityOperationRefusal,
		capabilityStackConvergenceWait,
	}
	got := deployRootHelperCapabilities(cfg)
	if len(got) != len(want) || !sort.StringsAreSorted(got) {
		t.Fatalf("deploy capabilities must be sorted and complete: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("deploy capabilities = %v, want %v", got, want)
		}
	}
	if base := requiredRootHelperCapabilities(cfg); len(base) != 2 || base[0] != capabilityCoordinatedOperations || base[1] != capabilityStackConvergenceWait {
		t.Fatalf("the shared base capability set changed: %v", base)
	}
}

func TestRunRootHelperCapabilitiesRequireOperationRefusal(t *testing.T) {
	want := []string{capabilityCoordinatedOperations, capabilityOperationRefusal}
	got := runRootHelperCapabilities(&config.Config{}, rootplan.RunOptions{})
	if len(got) != len(want) || !sort.StringsAreSorted(got) {
		t.Fatalf("run capabilities must be sorted and complete: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("run capabilities = %v, want %v", got, want)
		}
	}
	withBackup := runRootHelperCapabilities(&config.Config{}, rootplan.RunOptions{RequireBackup: true})
	wantWithBackup := []string{capabilityCoordinatedOperations, capabilityOperationRefusal, capabilityPreRunBackup}
	if len(withBackup) != len(wantWithBackup) || !sort.StringsAreSorted(withBackup) {
		t.Fatalf("backup run capabilities must be sorted and complete: %v", withBackup)
	}
	for i := range wantWithBackup {
		if withBackup[i] != wantWithBackup[i] {
			t.Fatalf("backup run capabilities = %v, want %v", withBackup, wantWithBackup)
		}
	}
}

func TestCurrentRootHelperPublishesDestroyRecovery(t *testing.T) {
	if !containsCapability(currentRootHelperCapabilities().Features, capabilityDestroyRecovery) {
		t.Fatal("current root helper does not publish destroy-recovery")
	}
}

func TestHelperCapabilityRefusalNamesHelperUpdateForV0047(t *testing.T) {
	report := rootHelperCapabilities{
		Protocol: rootHelperProtocolVersion,
		Version:  "v0.0.47",
		Features: []string{
			"backup-lifecycle",
			"caddy-basic-auth-public-paths",
			"caddy-domain-basic-auth",
			"caddy-host-route-basic-auth",
			"coordinated-operations-v1",
			"helper-migration",
			"monitoring-runtime",
			"readonly-docker-debug",
			"secrets-hashvault",
			"secrets-host",
			"signed-helper-update",
			"stack-convergence-wait",
		},
	}
	err := rootHelperCapabilityRefusal(report, deployRootHelperCapabilities(&config.Config{}))
	want := "root helper is missing required capabilities: [infra-images-audit operation-refusal]; the installed helper reports version v0.0.47: run `shuttle helper update --dry-run`, then `shuttle helper update --yes`"
	if err == nil || err.Error() != want {
		t.Fatalf("refusal = %v, want %q", err, want)
	}
	if err := rootHelperCapabilityRefusal(currentRootHelperCapabilities(), deployRootHelperCapabilities(&config.Config{})); err != nil {
		t.Fatalf("the current helper must satisfy deploy capabilities: %v", err)
	}
}

func TestEveryRootPlanRequestHasABaselineOrPublishedCapability(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "../rootplan/rootplan.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var validate *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "validate" {
			validate = function
			break
		}
	}
	if validate == nil {
		t.Fatal("rootplan.validate was not found")
	}

	requests := make(map[string]bool)
	switches := make(map[string]bool)
	ast.Inspect(validate.Body, func(node ast.Node) bool {
		switchStatement, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		kind := ""
		switch tag := switchStatement.Tag.(type) {
		case *ast.SelectorExpr:
			if base, ok := tag.X.(*ast.Ident); ok && base.Name == "plan" && tag.Sel.Name == "Action" {
				kind = "action"
			}
			if mode, ok := tag.X.(*ast.SelectorExpr); ok && tag.Sel.Name == "Mode" {
				if audit, ok := mode.X.(*ast.Ident); ok && audit.Name == "plan" && mode.Sel.Name == "Audit" {
					kind = "audit"
				}
			}
		}
		if kind == "" {
			return true
		}
		switches[kind] = true
		for _, statement := range switchStatement.Body.List {
			clause, ok := statement.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expression := range clause.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Errorf("%s case must be a string literal", kind)
					continue
				}
				value, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr != nil {
					t.Errorf("cannot read %s case %s: %v", kind, literal.Value, unquoteErr)
					continue
				}
				requests[kind+":"+value] = true
			}
		}
		return true
	})
	if !switches["action"] || !switches["audit"] {
		t.Fatalf("validate switches found = %v, want action and audit mode", switches)
	}

	for request := range requests {
		if _, ok := rootPlanRequestCapabilities[request]; !ok {
			t.Errorf("rootplan request %q has no capability declaration", request)
		}
	}
	for request, capability := range rootPlanRequestCapabilities {
		if !requests[request] {
			t.Errorf("capability declaration %q matches no rootplan request", request)
		}
		if capability != "" && !containsCapability(currentRootHelperCapabilities().Features, capability) {
			t.Errorf("capability %q for %q is not published by the current helper", capability, request)
		}
	}

	baseline := []string{
		"action:audit", "action:backup-status", "action:baseline", "action:baseline-rollback", "action:baseline-commit",
		"action:helper-migration-finalize", "action:helper-migration-reconcile", "action:helper-update",
		"action:monitor-install", "action:monitor-remove", "action:monitor-run", "action:monitor-status", "action:monitor-maintenance",
		"action:operation-renew", "action:operation-finish", "action:operation-abort", "action:operation-reserve", "action:operations-status",
		"action:operation-writer-register", "action:operation-writers-close", "action:operation-writers-commit",
		"action:recovery-plan", "action:recovery-apply", "action:run", "action:secrets-apply", "action:secrets-host",
		"action:stack-apply", "action:stack-rollback", "action:stack-reclaim",
		"audit:baseline", "audit:capabilities", "audit:status", "audit:logs", "audit:debug-ps", "audit:debug-services",
		"audit:debug-network", "audit:debug-tasks", "audit:debug-inspect", "audit:debug-logs", "audit:readiness",
	}
	var actualBaseline []string
	for request, capability := range rootPlanRequestCapabilities {
		if capability == "" {
			actualBaseline = append(actualBaseline, request)
		}
	}
	sort.Strings(baseline)
	sort.Strings(actualBaseline)
	if len(actualBaseline) != len(baseline) {
		t.Fatalf("baseline request count = %d, want %d: %v", len(actualBaseline), len(baseline), actualBaseline)
	}
	for i := range baseline {
		if actualBaseline[i] != baseline[i] {
			t.Fatalf("baseline requests = %v, want %v", actualBaseline, baseline)
		}
	}
}

func TestRequiredRootHelperCapabilitiesFollowAccessPolicy(t *testing.T) {
	disabled := false
	cfg := &config.Config{}
	if required := requiredRootHelperCapabilities(cfg); len(required) != 2 || required[0] != capabilityCoordinatedOperations || required[1] != capabilityStackConvergenceWait {
		t.Fatalf("the bare configuration must still require the convergence wait: %v", required)
	}

	cfg.Caddy.DomainBasicAuth = &disabled
	if required := requiredRootHelperCapabilities(cfg); len(required) != 3 || required[0] != capabilityCaddyDomainBasicAuth || required[1] != capabilityCoordinatedOperations || required[2] != capabilityStackConvergenceWait {
		t.Fatalf("domain opt-out must require its helper capability: %v", required)
	}

	cfg.Caddy.HostRoutes = []config.CaddyHostRoute{{Host: "bo.example.com", BasicAuth: true}}
	required := requiredRootHelperCapabilities(cfg)
	if len(required) != 4 || required[0] != capabilityCaddyDomainBasicAuth || required[1] != capabilityCaddyHostRouteBasicAuth || required[2] != capabilityCoordinatedOperations || required[3] != capabilityStackConvergenceWait {
		t.Fatalf("per-host auth must require both features: %v", required)
	}
	if !sort.StringsAreSorted(required) {
		t.Fatalf("required capabilities must be sorted for a stable message: %v", required)
	}
}

// TestBareDeploymentRequiresTheConvergenceWait pins the regression that cost a
// production release: with no Caddy feature declared, the required list used to
// be empty, ensureRequiredRootHelperCapabilities returned before asking the
// host anything, and a helper predating the convergence wait was free to accept
// the stack, return early and stop the registry under Swarm's pulls. A helper
// that reports every OTHER capability must still be refused.
func TestBareDeploymentRequiresTheConvergenceWait(t *testing.T) {
	required := requiredRootHelperCapabilities(&config.Config{})
	stale := rootHelperCapabilities{
		Protocol: rootHelperProtocolVersion,
		Version:  "v0.0.3",
		Features: []string{capabilityCaddyDomainBasicAuth, capabilityCaddyHostRouteBasicAuth, capabilityReadonlyDockerDebug, capabilitySignedHelperUpdate},
	}
	if err := requireRootHelperCapabilities(stale, required); err == nil {
		t.Fatal("a helper without the convergence wait must not be allowed to promote")
	}
	if err := requireRootHelperCapabilities(currentRootHelperCapabilities(), required); err != nil {
		t.Fatalf("the current helper must satisfy a bare deployment: %v", err)
	}
}

func TestDestroyLedgerOnlyCapabilityGuardsDestroyAndManagedOperations(t *testing.T) {
	if !containsCapability(currentRootHelperCapabilities().Features, capabilityDestroyLedgerOnly) {
		t.Fatal("the current helper must advertise destroy-ledger-only")
	}
	if err := requireRootHelperCapabilities(currentRootHelperCapabilities(), []string{capabilityDestroyLedgerOnly}); err != nil {
		t.Fatalf("the current helper must satisfy destroy capability checks: %v", err)
	}
	legacy := rootHelperCapabilities{Protocol: rootHelperProtocolVersion, Version: "old", Features: []string{capabilityCoordinatedOperations}}
	if err := destroyCapabilityDecision(legacy, "example"); err == nil {
		t.Fatal("destroy must refuse a helper without destroy-ledger-only")
	}
	if err := destroyCapabilityDecision(currentRootHelperCapabilities(), "example"); err != nil {
		t.Fatalf("destroy must accept a helper with the capability: %v", err)
	}
	managed := &config.Config{Database: config.DatabaseConfig{Version: 16}}
	if !containsCapability(requiredRootHelperCapabilities(managed), capabilityDestroyLedgerOnly) {
		t.Fatal("managed deploy, rollback and Hashvault sync must require destroy-ledger-only")
	}
	unmanaged := requiredRootHelperCapabilities(&config.Config{})
	if containsCapability(unmanaged, capabilityDestroyLedgerOnly) {
		t.Fatal("an unmanaged app must not gain the managed PostgreSQL requirement")
	}
}

func TestDestroyLedgerOnlyRequiredForBackupFlowsWithManagedDatabase(t *testing.T) {
	managed := &config.Config{Database: config.DatabaseConfig{Version: 16}}
	unmanaged := &config.Config{}
	backup := rootplan.RunOptions{RequireBackup: true}
	preRunReport := rootHelperCapabilities{Version: "v0.0.60", Features: []string{capabilityCoordinatedOperations, capabilityOperationRefusal, capabilityPreRunBackup}}
	if err := rootHelperCapabilityRefusal(preRunReport, runRootHelperCapabilities(managed, backup)); err == nil || !strings.Contains(err.Error(), capabilityDestroyLedgerOnly) {
		t.Fatalf("pre-run backup must require destroy-ledger-only for a managed database: %v", err)
	}
	if err := rootHelperCapabilityRefusal(preRunReport, runRootHelperCapabilities(unmanaged, backup)); err != nil {
		t.Fatalf("pre-run backup must not require destroy-ledger-only for an unmanaged app: %v", err)
	}
	if slices.Contains(runRootHelperCapabilities(managed, rootplan.RunOptions{}), capabilityDestroyLedgerOnly) {
		t.Fatal("a run without pre-run backup keeps its previous requirements")
	}

	lifecycleReport := rootHelperCapabilities{Features: []string{capabilityBackupLifecycle}}
	if publish, err := interpretManagedBackupLifecycleCapability(true, false, nil, lifecycleReport); err == nil || publish || !strings.Contains(err.Error(), capabilityDestroyLedgerOnly) {
		t.Fatalf("backup lifecycle must require destroy-ledger-only for a managed database: publish=%t err=%v", publish, err)
	}
	if publish, err := interpretManagedBackupLifecycleCapability(false, false, nil, lifecycleReport); err != nil || !publish {
		t.Fatalf("backup lifecycle must not require destroy-ledger-only for an unmanaged app: publish=%t err=%v", publish, err)
	}
}

func TestPreRunBackupCapabilityIsOptInAndAvailable(t *testing.T) {
	base := requiredRootHelperCapabilities(&config.Config{})
	want := []string{capabilityCoordinatedOperations, capabilityStackConvergenceWait}
	if len(base) != len(want) || base[0] != want[0] || base[1] != want[1] {
		t.Fatalf("default required capabilities changed: %v", base)
	}
	cfg := &config.Config{Operations: map[string]config.Operation{"migrate": {Service: "api", Command: []string{"php", "migrate"}, BackupBefore: true}}}
	required := requiredRootHelperCapabilities(cfg)
	if !sort.StringsAreSorted(required) || !containsCapability(required, capabilityPreRunBackup) {
		t.Fatalf("backup operation did not require sorted capability: %v", required)
	}
	if !containsCapability(currentRootHelperCapabilities().Features, capabilityPreRunBackup) {
		t.Fatal("current helper does not advertise pre-run backup")
	}
}

func containsCapability(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRootHelperCapabilityReportIsStrictAndComplete(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the root helper reports capabilities only where it runs: on the Linux host")
	}
	body, err := encodeRootHelperCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	report, err := decodeRootHelperCapabilities(strings.TrimSpace(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{capabilityCaddyDomainBasicAuth, capabilityCaddyHostRouteBasicAuth, capabilityReadonlyDockerDebug, capabilitySignedHelperUpdate, capabilityStackConvergenceWait, capabilityDestroyLedgerOnly} {
		if err := requireRootHelperCapabilities(report, []string{required}); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{
		`{"protocol":0,"version":"dev","features":["signed-helper-update"]}`,
		`{"protocol":1,"version":"dev","features":["z","a"]}`,
		`{"protocol":1,"version":"dev","features":["bad feature"]}`,
		`{"protocol":1,"version":"dev","features":["a","a"]}`,
	} {
		if _, err := decodeRootHelperCapabilities(invalid); err == nil {
			t.Fatalf("invalid capability report accepted: %s", invalid)
		}
	}
}

func TestLegacyRootHelperCapabilityErrorsAreRecognized(t *testing.T) {
	for _, reason := range []string{
		"installed root helper cannot report capabilities: unsupported audit operation",
		"installed root helper cannot report capabilities: decode root-operation plan",
		"installed root helper cannot report capabilities: unsupported root-operation contract",
	} {
		if !rootHelperLacksCapabilities(errors.New(reason)) {
			t.Fatalf("legacy helper error was not recognized: %s", reason)
		}
	}
	if rootHelperLacksCapabilities(errors.New("ssh connection refused")) {
		t.Fatal("a transport failure must not be described as an old helper")
	}
}
