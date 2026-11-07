package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

func TestRecoveryInvocationSuffix(t *testing.T) {
	for _, tc := range []struct {
		name, configPath, env, want string
	}{
		{"empty", "", "", ""},
		{"config-and-env", "@docker/preprod/shuttle.yml", "preprod", " --config @docker/preprod/shuttle.yml -e preprod"},
		{"config-only", "config.json", "", " --config config.json"},
		{"env-only", "", "prod", " -e prod"},
		{"space", "config with spaces.json", "", " --config 'config with spaces.json'"},
		{"single-quote", "config'quoted.json", "", " --config 'config'\"'\"'quoted.json'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := recoveryInvocationSuffix(tc.configPath, tc.env); got != tc.want {
				t.Fatalf("suffix = %q, want %q", got, tc.want)
			}
		})
	}

	for _, value := range []string{"config with spaces.json", "config'quoted.json"} {
		t.Run("shell-round-trip/"+value, func(t *testing.T) {
			command := "sh -c 'printf %s \"$1\"' sh " + recoveryInvocationValue(value)
			output, err := exec.Command("sh", "-c", command).Output()
			if err != nil {
				t.Fatalf("run escaped value through sh: %v", err)
			}
			if string(output) != value {
				t.Fatalf("shell round-trip = %q, want %q", output, value)
			}
		})
	}
}

func TestRecoveryHintsRepeatInvocation(t *testing.T) {
	previous := recoveryInvocation
	recoveryInvocation = " --config 'preprod config.yml' -e prod"
	t.Cleanup(func() { recoveryInvocation = previous })

	const id = "12345678-1234-1234-1234-123456789abc"
	const invocation = " --config 'preprod config.yml' -e prod"
	for _, tc := range []struct{ kind, want string }{
		{"deploy", "operation " + id + " requires recovery: run `shuttle operations recover " + id + invocation + " --dry-run`, then `shuttle operations recover " + id + invocation + " --yes --plan-digest <digest>` with the digest it prints"},
		{"helper-update", "operation " + id + " requires recovery: run `shuttle operations recover " + id + invocation + " --dry-run` and follow what it reports"},
		{"reboot", "operation " + id + " requires recovery: `shuttle operations recover` cannot repair a reboot; run `shuttle operations reboot --resume " + id + invocation + " --yes` (see `shuttle operations status" + invocation + "`)"},
		{"destroy", "operation " + id + " requires recovery: run `shuttle operations recover " + id + invocation + " --dry-run`, then `shuttle operations recover " + id + invocation + " --yes --plan-digest <digest>` with the digest it prints"},
	} {
		if got := recoveryHint(id, tc.kind).Error(); got != tc.want {
			t.Errorf("%s hint = %q, want %q", tc.kind, got, tc.want)
		}
	}
	wantHedged := "operation " + id + " may require recovery: check `shuttle operations status" + invocation + "`, then `shuttle operations recover " + id + invocation + " --dry-run`"
	if got := hedgedRecoveryHint(id, "deploy").Error(); got != wantHedged {
		t.Fatalf("hedged hint = %q, want %q", got, wantHedged)
	}
}

func TestRecordRecoveryInvocationReadsOnlyChangedFlags(t *testing.T) {
	previous := recoveryInvocation
	t.Cleanup(func() { recoveryInvocation = previous })
	t.Setenv("SHUTTLE_SITE_URL", "")

	configPath := filepath.Join(t.TempDir(), "missing.json")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"config-and-env", []string{"operations", "status", "--config", configPath, "-e", "preprod"}, recoveryInvocationSuffix(configPath, "preprod")},
		{"env-only", []string{"operations", "status", "--env", "preprod"}, " -e preprod"},
		{"none", []string{"operations", "status"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			recoveryInvocation = " stale value"
			root := NewRootCommand()
			root.SilenceErrors = true
			root.SilenceUsage = true
			root.SetArgs(tc.args)
			if err := root.Execute(); err == nil {
				t.Fatal("status with a missing config unexpectedly succeeded")
			}
			if recoveryInvocation != tc.want {
				t.Fatalf("recorded invocation = %q, want %q", recoveryInvocation, tc.want)
			}
		})
	}
}

func TestNoSubcommandReplacesRootPersistentPreRun(t *testing.T) {
	root := NewRootCommand()
	if root.PersistentPreRun == nil || root.PersistentPreRunE != nil {
		t.Fatal("root must own the persistent pre-run hook")
	}
	var walk func(*cobra.Command)
	walk = func(parent *cobra.Command) {
		for _, command := range parent.Commands() {
			if command.PersistentPreRun != nil || command.PersistentPreRunE != nil {
				t.Errorf("%s replaces the root persistent pre-run hook", command.CommandPath())
			}
			walk(command)
		}
	}
	walk(root)
}

func TestReservationAutoRecoveryDeclineRepeatsInvocation(t *testing.T) {
	previous := recoveryInvocation
	recoveryInvocation = " --config 'preprod config.yml' -e preprod"
	t.Cleanup(func() { recoveryInvocation = previous })

	const blockerID = "12345678-1234-1234-1234-123456789abc"
	requests := 0
	fixture, pin := administratorSSHFixture(t, func(_, _ string, _ []byte) shuttlessh.Result {
		requests++
		if requests == 1 {
			return shuttlessh.Result{Code: 1, Stderr: "operation " + blockerID + " requires recovery for deploy (target demo, age 1s); waited 0s"}
		}
		return shuttlessh.Result{Code: 1, Stderr: "recovery plan unavailable"}
	})
	client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, fixture.user, fixture.port, pin)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := trustedHostIdentity{HostKeyFingerprint: pin, OperatorKeyFingerprint: fixture.operatorKeyFingerprint}
	_, err = reserveRemoteOperation(client, identity, key, "deploy", "demo")
	want := "run `shuttle operations recover " + blockerID + recoveryInvocation + " --dry-run`"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("reservation error = %v, want recovery command %q", err, want)
	}
	if requests != 2 {
		t.Fatalf("SSH requests = %d, want reservation plus refused auto-recovery", requests)
	}
}

func TestOperationRecoveryHintTexts(t *testing.T) {
	// Commands executed by other tests in this package record their --config
	// in the package state; these texts describe an invocation without flags.
	previous := recoveryInvocation
	recoveryInvocation = ""
	t.Cleanup(func() { recoveryInvocation = previous })
	const id = "12345678-1234-1234-1234-123456789abc"
	for _, tc := range []struct{ kind, want string }{
		{"deploy", "operation " + id + " requires recovery: run `shuttle operations recover " + id + " --dry-run`, then `shuttle operations recover " + id + " --yes --plan-digest <digest>` with the digest it prints"},
		{"helper-update", "operation " + id + " requires recovery: run `shuttle operations recover " + id + " --dry-run` and follow what it reports"},
		{"reboot", "operation " + id + " requires recovery: `shuttle operations recover` cannot repair a reboot; run `shuttle operations reboot --resume " + id + " --yes` (see `shuttle operations status`)"},
		{"destroy", "operation " + id + " requires recovery: run `shuttle operations recover " + id + " --dry-run`, then `shuttle operations recover " + id + " --yes --plan-digest <digest>` with the digest it prints"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			if got := recoveryHint(id, tc.kind).Error(); got != tc.want {
				t.Fatalf("hint = %q, want %q", got, tc.want)
			}
		})
	}
	if got := hedgedRecoveryHint(id, "deploy").Error(); got != "operation "+id+" may require recovery: check `shuttle operations status`, then `shuttle operations recover "+id+" --dry-run`" {
		t.Fatalf("hedged hint = %q", got)
	}
}

func TestRecoveryKindSupportedPortableContract(t *testing.T) {
	wants := map[string]struct {
		supported bool
		reason    string
	}{
		"deploy": {true, ""}, "rollback": {true, ""}, "backup": {true, ""}, "registry-gc": {true, ""},
		"helper-update": {true, ""}, "secrets-sync": {true, ""}, "run": {true, ""},
		"reboot":  {false, "reboot recovery is not owned by this reconciler; use operations reboot --resume"},
		"destroy": {true, ""},
		"restore": {false, "kind restore requires its own reconciler"},
		"unknown": {false, "kind unknown is not owned by this reconciler"},
	}
	for kind, want := range wants {
		got, reason := recoveryKindSupported(kind)
		if got != want.supported || reason != want.reason {
			t.Errorf("recoveryKindSupported(%q) = (%v, %q), want (%v, %q)", kind, got, reason, want.supported, want.reason)
		}
	}
}

func TestEveryReservedOperationKindHasARecoveryPath(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate CLI package for reservation recovery guard")
	}
	entries, err := os.ReadDir(filepath.Dir(testFile))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(testFile), name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			function, ok := call.Fun.(*ast.Ident)
			if !ok || function.Name != "beginRemoteOperation" {
				return true
			}
			if len(call.Args) < 4 {
				t.Errorf("%s: beginRemoteOperation call has no fourth kind argument", name)
				return true
			}
			literal, ok := call.Args[3].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Errorf("%s: beginRemoteOperation kind must be a string literal", name)
				return true
			}
			kind, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Errorf("%s: invalid operation kind %s: %v", name, literal.Value, err)
				return true
			}
			kinds[kind] = true
			return true
		})
	}
	if len(kinds) == 0 {
		t.Fatal("no reserved operation kinds were found")
	}
	for kind := range kinds {
		if kind == "reboot" {
			continue
		}
		if supported, reason := recoveryKindSupported(kind); !supported {
			t.Errorf("reserved operation kind %q has no recovery path: %s", kind, reason)
		}
	}
}

func operationStatusFixture(t *testing.T, row []coord.Record, fail bool) (*shuttlessh.Client, trustedHostIdentity, ed25519.PrivateKey, *int) {
	t.Helper()
	var statusCalls int
	fixture, pin := administratorSSHFixture(t, func(_, command string, input []byte) shuttlessh.Result {
		if command != "sudo -n /usr/local/libexec/shuttle-root apply" {
			return shuttlessh.Result{Code: 1, Stderr: "unexpected command"}
		}
		plan, _, err := decodeRootHelperEnvelope(strings.NewReader(string(input)))
		if err != nil || plan.Action != "operations-status" {
			return shuttlessh.Result{Code: 1, Stderr: "unexpected signed status request"}
		}
		statusCalls++
		if fail {
			return shuttlessh.Result{Code: 255, Stderr: "transport failed"}
		}
		body, _ := json.Marshal(row)
		return shuttlessh.Result{Stdout: string(body)}
	})
	client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, fixture.user, fixture.port, pin)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := trustedHostIdentity{HostKeyFingerprint: pin, OperatorKeyFingerprint: fixture.operatorKeyFingerprint}
	return client, identity, key, &statusCalls
}

func TestClassifyLegacyControlErrorBySignedStatus(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	original := &operationControlError{ID: id, Action: "operation-renew", Stderr: "warning: old helper\n" + id + " operation is not active for this phase"}
	for _, tc := range []struct {
		name  string
		rows  []coord.Record
		fail  bool
		want  string
		calls int
	}{
		{"recovery", []coord.Record{{ID: id, Kind: "deploy", RecoveryRequired: true}}, false, recoveryHint(id, "deploy").Error(), 1},
		{"completed", []coord.Record{{ID: id, Kind: "deploy", State: "completed"}}, false, original.Error(), 1},
		{"missing", []coord.Record{{ID: "other"}}, false, original.Error(), 1},
		{"read-failed", nil, true, hedgedRecoveryHint(id, "deploy").Error(), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, identity, key, calls := operationStatusFixture(t, tc.rows, tc.fail)
			got := classifyControlError(original, client, identity, key, id, "deploy")
			if got.Error() != tc.want || *calls != tc.calls {
				t.Fatalf("classification = %v, status calls=%d", got, *calls)
			}
		})
	}
	client, identity, key, calls := operationStatusFixture(t, nil, false)
	sentinel := &operationControlError{ID: id, Action: "operation-renew", Stderr: "notice\noperation requires recovery\nmore"}
	got := classifyControlError(sentinel, client, identity, key, id, "deploy")
	if got.Error() != recoveryHint(id, "deploy").Error() || *calls != 0 {
		t.Fatalf("sentinel classification = %v, calls=%d", got, *calls)
	}
}

func TestHelperUpdateApplyFailureReadsReservationState(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	applyErr := errors.New("signed root helper update failed: apply failed")
	for _, tc := range []struct {
		name string
		rows []coord.Record
		fail bool
		want string
	}{
		{"recovery", []coord.Record{{ID: id, Kind: "helper-update", RecoveryRequired: true}}, false, recoveryHint(id, "helper-update").Error()},
		{"read-failed", nil, true, hedgedRecoveryHint(id, "helper-update").Error()},
		{"completed", []coord.Record{{ID: id, Kind: "helper-update", State: "completed"}}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, identity, key, _ := operationStatusFixture(t, tc.rows, tc.fail)
			got := helperUpdateApplyFailure(client, identity, key, id, applyErr)
			if !strings.Contains(got.Error(), applyErr.Error()) {
				t.Fatalf("original apply error lost: %v", got)
			}
			if tc.want == "" {
				if got != applyErr {
					t.Fatalf("completed reservation added a hint: %v", got)
				}
			} else if !strings.Contains(got.Error(), tc.want) {
				t.Fatalf("result %q lacks hint %q", got, tc.want)
			}
		})
	}
}

func TestRecoveryHintTypeIsDiscoverableThroughWrapping(t *testing.T) {
	var hint *operationRequiresRecoveryError
	if err := errors.As(errors.Join(errors.New("original"), recoveryHint("id", "deploy")), &hint); !err || !hint.Confirmed {
		t.Fatalf("wrapped hint not discoverable: %#v", hint)
	}
}

func TestHelperUpdateFailureRefusesOnlyUnstartedReservation(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	for _, tc := range []struct {
		name      string
		phases    []coord.Phase
		refuseErr error
		wantCalls int
	}{
		{name: "before phase", wantCalls: 1},
		{name: "refusal failed", refuseErr: errors.New("refusal transport failed"), wantCalls: 1},
		{name: "phase already started", phases: []coord.Phase{{Name: "helper-update"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, identity, key, _ := operationStatusFixture(t, []coord.Record{{ID: id, Kind: "helper-update", State: "active", Phases: tc.phases}}, false)
			old := remoteOperationControl
			t.Cleanup(func() { remoteOperationControl = old })
			calls := 0
			remoteOperationControl = func(o *remoteOperation, action, result string) error {
				calls++
				if o.id != id || o.kind != "helper-update" || action != "operation-refuse" {
					t.Fatalf("unexpected refusal: %+v %s", o, action)
				}
				return tc.refuseErr
			}
			applyErr := errors.New("scan refused")
			got := helperUpdateApplyFailure(client, identity, key, id, applyErr)
			if calls != tc.wantCalls || !errors.Is(got, applyErr) {
				t.Fatalf("calls=%d error=%v", calls, got)
			}
			if tc.refuseErr != nil && !strings.Contains(got.Error(), tc.refuseErr.Error()) {
				t.Fatalf("lost refusal failure: %v", got)
			}
		})
	}
}
