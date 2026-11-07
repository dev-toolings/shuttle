//go:build linux

package cli

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestDestroyStackReportsHelperOutputBeforeFailure(t *testing.T) {
	var out bytes.Buffer
	result := shuttlessh.Result{Stdout: "kept PostgreSQL database demo_app: legacy\n", Stderr: "Caddy reload failed", Code: 1}
	err := reportDestroyResult(&out, result, nil)
	if out.String() != result.Stdout {
		t.Fatalf("helper stdout must be forwarded before checking its status: %q", out.String())
	}
	if err == nil || !strings.Contains(err.Error(), "Caddy reload failed") {
		t.Fatalf("nonzero helper status must still return its error: %v", err)
	}
}

func TestDestroyStackReportsHelperOutputOnSuccess(t *testing.T) {
	var out bytes.Buffer
	result := shuttlessh.Result{Stdout: "kept PostgreSQL role demo_app: legacy\n"}
	if err := reportDestroyResult(&out, result, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != result.Stdout {
		t.Fatalf("successful helper output was not forwarded: %q", out.String())
	}
}

func TestDestroyStackRequiresDestroyRecoveryCapability(t *testing.T) {
	current := currentRootHelperCapabilities()
	withoutRecovery := current
	withoutRecovery.Features = nil
	for _, feature := range current.Features {
		if feature != capabilityDestroyRecovery {
			withoutRecovery.Features = append(withoutRecovery.Features, feature)
		}
	}
	want := "the root helper on prod.example cannot recover an interrupted destroy; run shuttle helper update --dry-run, then shuttle helper update --yes"
	if err := destroyCapabilityDecision(withoutRecovery, "prod.example"); err == nil || err.Error() != want {
		t.Fatalf("missing destroy recovery refusal = %v, want %q", err, want)
	}
	if err := destroyCapabilityDecision(current, "prod.example"); err != nil {
		t.Fatalf("current helper must support destroy recovery: %v", err)
	}
}

func TestRemoveRootStackPostgresStepsRunInDurableOrder(t *testing.T) {
	var order []string
	steps := postgresRemovalSteps{
		drop: func(kind, name string) error {
			order = append(order, "drop:"+kind+":"+name)
			return nil
		},
		writeOrClearLedger: func(ledger postgresLedger) error {
			if ledger.Version != postgresLedgerVersion || len(ledger.Roles)+len(ledger.Databases) != 0 {
				t.Fatalf("successful drops must clear the retry ledger: %#v", ledger)
			}
			order = append(order, "ledger")
			return nil
		},
		removeState: func(hasRemainder bool) error {
			if hasRemainder {
				t.Fatal("successful drops must not leave a retry ledger")
			}
			order = append(order, "state")
			return nil
		},
		removeCredentials: func(postgresRemoval, []string) error {
			order = append(order, "credentials")
			return nil
		},
	}
	_, err := applyPostgresRemovalSteps("demo", postgresRemoval{Databases: []string{"db"}, Roles: []string{"role"}}, steps)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"drop:database:db", "drop:role:role", "ledger", "state", "credentials"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("PostgreSQL destroy steps ran out of order: got %v, want %v", order, want)
	}
}

func TestRemoveRootStackPostgresLedgerFailureStopsBeforeStateAndCredentials(t *testing.T) {
	ledgerErr := errors.New("ledger disk failure")
	var order []string
	steps := postgresRemovalSteps{
		drop: func(kind, name string) error {
			order = append(order, "drop:"+kind+":"+name)
			return nil
		},
		writeOrClearLedger: func(postgresLedger) error {
			order = append(order, "ledger")
			return ledgerErr
		},
		removeState: func(bool) error {
			order = append(order, "state")
			return nil
		},
		removeCredentials: func(postgresRemoval, []string) error {
			order = append(order, "credentials")
			return nil
		},
	}
	_, err := applyPostgresRemovalSteps("demo", postgresRemoval{Databases: []string{"db"}}, steps)
	if !errors.Is(err, ledgerErr) {
		t.Fatalf("ledger write failure must be returned: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"drop:database:db", "ledger"}) {
		t.Fatalf("state and credentials must remain untouched after ledger failure: %v", order)
	}
}
