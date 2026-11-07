//go:build linux

package cli

import (
	"bytes"
	"context"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestDestroyNeverDropsWithoutExplicitSignedConsent(t *testing.T) {
	journal := &destroyCleanupJournal{PendingDatabases: []string{"demo"}, Progress: destroyCleanupProgress{PostgresDropIntentsPrepared: true}}
	dropped := false
	err := applyDestroyPostgresDrop(journal, "database", "demo", func(string, string) (string, bool, error) {
		return "42", true, nil
	}, func() error { dropped = true; return nil }, func() error { return nil }, func(string) {})
	if dropped || err == nil {
		t.Fatalf("missing consent must refuse every drop: dropped=%v error=%v", dropped, err)
	}
}

func TestDestroyKeepsOwnedObjectsAndCredentialsByDefault(t *testing.T) {
	root := t.TempDir()
	ledger := postgresLedger{Version: 1, Databases: []string{"demo"}, Roles: []string{"demo"}}
	if err := writePostgresLedger(root, "demo", ledger); err != nil {
		t.Fatal(err)
	}
	removal, err := planPostgresRemovalWithProbes(root, "demo", false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	removal = postgresRemovalWithConsent(removal, false)
	_, _, _ = applyPostgresRemoval("demo", removal, func(string, string) error { t.Fatal("default destroy attempted a drop"); return nil })
	if len(removal.Kept) != 2 {
		t.Fatalf("owned resources not reported as kept: %+v", removal)
	}
	selection := postgresCredentialsToKeep("demo", removal, nil, postgresLedger{})
	if !slices.Contains(selection.DockerSecrets, "demo_postgres_password_v1") {
		t.Fatalf("credentials lost: %+v", selection)
	}
	if err := removePostgresAppState(root, "demo", true); err != nil {
		t.Fatal(err)
	}
	got, err := readPostgresLedger(root, "demo")
	if err != nil || !reflect.DeepEqual(got, ledger) {
		t.Fatalf("ownership proof lost: %+v %v", got, err)
	}
}

func TestDestroyDryRunInventoriesResourcesWithoutMutations(t *testing.T) {
	root := t.TempDir()
	stateRoot, secretRoot := filepath.Join(root, "apps"), filepath.Join(root, "secrets")
	if err := writePostgresLedger(stateRoot, "demo", postgresLedger{Version: 1, Databases: []string{"demo"}, Roles: []string{"demo"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(postgresLedgerPath(stateRoot, "demo"))
	removal := postgresRemoval{Databases: []string{"demo"}, Roles: []string{"demo"}, Kept: []keptPostgresObject{{Kind: "database", Name: "external", Reason: "not recorded"}}}
	run := func(args ...string) ([]byte, error) {
		switch {
		case args[0] == "volume" && args[1] == "ls":
			return []byte("demo_data"), nil
		case args[0] == "volume" && args[1] == "inspect":
			return []byte(`{"com.docker.stack.namespace":"demo"}`), nil
		case args[0] == "secret" && args[1] == "ls":
			return []byte("demo_api_key_v1 demo_postgres_password_v1"), nil
		case args[0] == "secret" && args[1] == "inspect":
			return []byte(args[len(args)-1]), nil
		default:
			t.Fatalf("dry-run attempted a mutation: %v", args)
			return nil, nil
		}
	}
	for _, drop := range []bool{false, true} {
		var out bytes.Buffer
		err := previewDestroyResources(context.Background(), stateRoot, secretRoot, "demo", drop, removal, &out, run, func(context.Context, string) (int64, error) { return 1024, nil })
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range []string{"stack demo", "volume demo_data", "state " + postgresLedgerPath(stateRoot, "demo"), "PostgreSQL database demo (size=1024 bytes)", "PostgreSQL role demo", "secret demo_api_key_v1", "kept PostgreSQL database external"} {
			if !strings.Contains(out.String(), part) {
				t.Fatalf("preview missing %q: %s", part, out.String())
			}
		}
		action := "kept"
		if drop {
			action = "would drop"
		}
		if !strings.Contains(out.String(), action+" PostgreSQL database demo") {
			t.Fatal(out.String())
		}
	}
	after, _ := os.ReadFile(postgresLedgerPath(stateRoot, "demo"))
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run changed ledger")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Fatalf("dry-run created host state: %v", entries)
	}
}

func TestDestroyDryRunBypassesMutationCoordinator(t *testing.T) {
	oldIdentity, oldPhase, oldPreview := rootCoordinatedIdentityVerifier, rootStackPhase, rootDestroyPreview
	t.Cleanup(func() {
		rootCoordinatedIdentityVerifier, rootStackPhase, rootDestroyPreview = oldIdentity, oldPhase, oldPreview
	})
	verified, previewed := false, false
	rootCoordinatedIdentityVerifier = func(rootplan.Plan) error { verified = true; return nil }
	rootStackPhase = func(rootplan.Plan, func(context.Context) error) error {
		t.Fatal("preview entered mutation coordinator")
		return nil
	}
	rootDestroyPreview = func(op rootplan.StackOperation, _ io.Writer) error {
		previewed = true
		if !verified || !op.DropDatabases {
			t.Fatal("preview lost verified signed intent")
		}
		return nil
	}
	plan := rootplan.Plan{Action: "stack-apply", Stack: &rootplan.StackOperation{App: "demo", Remove: true, DryRun: true, DropDatabases: true}}
	if err := applyRootStack(plan, nil); err != nil {
		t.Fatal(err)
	}
	if !previewed {
		t.Fatal("preview not invoked")
	}
}
