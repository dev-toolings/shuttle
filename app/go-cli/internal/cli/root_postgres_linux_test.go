//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"gopkg.in/yaml.v3"
)

type removalProbeCalls struct {
	installed int
	database  int
	role      int
}

func stubRemovalPostgresProbes(t *testing.T, installed bool, database func(string) (bool, error), role func(string) (bool, error)) *removalProbeCalls {
	t.Helper()
	oldInstalled, oldDatabase, oldRole := removalPostgresInstalled, removalDatabaseExists, removalRoleExists
	calls := &removalProbeCalls{}
	removalPostgresInstalled = func() bool {
		calls.installed++
		return installed
	}
	removalDatabaseExists = func(name string) (bool, error) {
		calls.database++
		if database != nil {
			return database(name)
		}
		return false, nil
	}
	removalRoleExists = func(name string) (bool, error) {
		calls.role++
		if role != nil {
			return role(name)
		}
		return false, nil
	}
	t.Cleanup(func() {
		removalPostgresInstalled, removalDatabaseExists, removalRoleExists = oldInstalled, oldDatabase, oldRole
	})
	return calls
}

func writeLedger(t *testing.T, root, app string, ledger postgresLedger) {
	t.Helper()
	if err := writePostgresLedger(root, app, ledger); err != nil {
		t.Fatal(err)
	}
}

func TestPlanPostgresRemovalEmptyLedgerAndPostgresAbsentDoesNothing(t *testing.T) {
	calls := stubRemovalPostgresProbes(t, false, nil, nil)
	removal, err := planPostgresRemoval(t.TempDir(), "demo-app")
	if err != nil {
		t.Fatal(err)
	}
	if len(removal.Databases)+len(removal.Roles)+len(removal.Secrets)+len(removal.Kept) != 0 {
		t.Fatalf("an empty ledger must authorize no drops or keeps, got %#v", removal)
	}
	if calls.installed != 1 || calls.database != 0 || calls.role != 0 {
		t.Fatalf("database and role probes must not run without PostgreSQL: %#v", calls)
	}
}

func TestPlanPostgresRemovalKeepsExistingUnrecordedDerivedObjects(t *testing.T) {
	calls := stubRemovalPostgresProbes(t, true,
		func(name string) (bool, error) { return name == "demo_app", nil },
		func(name string) (bool, error) { return name == "demo_app", nil },
	)
	removal, err := planPostgresRemoval(t.TempDir(), "demo-app")
	if err != nil {
		t.Fatal(err)
	}
	if len(removal.Databases) != 0 || len(removal.Roles) != 0 || len(removal.Kept) != 2 {
		t.Fatalf("unrecorded derived objects must only be kept, got %#v", removal)
	}
	for _, object := range removal.Kept {
		if object.Reason != "not recorded as created by Shuttle for demo-app; drop it by hand if that is intended" {
			t.Fatalf("unexpected keep reason: %#v", object)
		}
	}
	if removal.Kept[0].Kind != "database" || removal.Kept[1].Kind != "role" || calls.database != 1 || calls.role != 1 {
		t.Fatalf("kept objects and probes must be ordered, got %#v and %#v", removal.Kept, calls)
	}
}

func TestPlanPostgresRemovalKeepsDerivedObjectsWhenExistenceChecksFail(t *testing.T) {
	probeErr := errors.New("connection refused")
	stubRemovalPostgresProbes(t, true,
		func(string) (bool, error) { return false, probeErr },
		func(string) (bool, error) { return false, probeErr },
	)
	removal, err := planPostgresRemoval(t.TempDir(), "demo-app")
	if err != nil {
		t.Fatal(err)
	}
	if len(removal.Databases) != 0 || len(removal.Roles) != 0 || len(removal.Kept) != 2 {
		t.Fatalf("a failed existence check must never authorize a drop: %#v", removal)
	}
	for _, object := range removal.Kept {
		if object.Reason != "existence check failed: connection refused" {
			t.Fatalf("unexpected probe failure reason: %#v", object)
		}
	}
}

func TestPlanPostgresRemovalProbeFalseKeepsAndReportsNothing(t *testing.T) {
	stubRemovalPostgresProbes(t, true, nil, nil)
	removal, err := planPostgresRemoval(t.TempDir(), "demo-app")
	if err != nil {
		t.Fatal(err)
	}
	_, _, lines := applyPostgresRemoval("demo-app", removal, func(string, string) error {
		t.Fatal("an unrecorded derived object must not be dropped")
		return nil
	})
	if len(removal.Kept) != 0 || len(lines) != 0 {
		t.Fatalf("false probes must produce no kept objects or output lines: %#v, %#v", removal, lines)
	}
}

// Removal drops what this application created, in an order PostgreSQL accepts,
// and one secret per additional role.
func TestPlanPostgresRemovalDropsWhatTheApplicationCreated(t *testing.T) {
	calls := stubRemovalPostgresProbes(t, true, nil, nil)
	root := t.TempDir()
	writeLedger(t, root, "demo", postgresLedger{Roles: []string{"demo", "reporting"}, Databases: []string{"demo", "reporting"}})

	removal, err := planPostgresRemoval(root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removal.Databases, ",") != "demo,reporting" {
		t.Fatalf("declared databases must be dropped, got %#v", removal.Databases)
	}
	if strings.Join(removal.Roles, ",") != "demo,reporting" {
		t.Fatalf("declared roles must be dropped, got %#v", removal.Roles)
	}
	if strings.Join(removal.Secrets, ",") != "demo_db_reporting_password_v1" {
		t.Fatalf("only the additional role has a derived secret, got %#v", removal.Secrets)
	}
	if calls.database != 0 || calls.role != 0 {
		t.Fatalf("recorded derived names must not be probed: %#v", calls)
	}
}

// The property that matters: a database another application created is never
// dropped, even when its name is the one this application would derive.
func TestPlanPostgresRemovalNeverDropsAnotherApplicationsDatabase(t *testing.T) {
	calls := stubRemovalPostgresProbes(t, true, nil, nil)
	root := t.TempDir()
	writeLedger(t, root, "billing", postgresLedger{Roles: []string{"shared", "demo"}, Databases: []string{"shared", "demo"}})
	writeLedger(t, root, "demo", postgresLedger{Roles: []string{"demo_only"}, Databases: []string{"demo_only"}})

	removal, err := planPostgresRemoval(root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, removal.Databases...), removal.Roles...) {
		if name == "shared" || name == "demo" {
			t.Fatalf("removal touched an object owned by another application: %#v", removal)
		}
	}
	for _, object := range removal.Kept {
		if object.Name == "shared" || object.Name == "demo" {
			t.Fatalf("an object claimed by another app must not be kept or dropped: %#v", removal)
		}
	}
	if strings.Join(removal.Databases, ",") != "demo_only" || strings.Join(removal.Roles, ",") != "demo_only" {
		t.Fatalf("removal must still drop this application's own objects, got %#v", removal)
	}
	if calls.database != 0 || calls.role != 0 {
		t.Fatalf("objects claimed by another ledger must not be probed: %#v", calls)
	}
}

// Two applications claiming one object is refused rather than resolved: there
// is no correct way to pick, and the wrong pick runs dropdb on live data.
func TestPostgresLedgerOwnersRefusesAContestedObject(t *testing.T) {
	root := t.TempDir()
	writeLedger(t, root, "alpha", postgresLedger{Databases: []string{"shared"}})
	writeLedger(t, root, "beta", postgresLedger{Databases: []string{"shared"}})

	if _, _, err := postgresLedgerOwners(root); err == nil || !strings.Contains(err.Error(), "claimed by both alpha and beta") {
		t.Fatalf("expected a deterministic refusal, got %v", err)
	}
}

// A ledger that cannot be read stops the removal instead of falling back to
// dropping whatever carries the derived name.
func TestPlanPostgresRemovalStopsOnAnUnreadableLedger(t *testing.T) {
	stubRemovalPostgresProbes(t, false, nil, nil)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(postgresLedgerPath(root, "demo"), []byte("{\"version\":1,\"roles\":[\"DROP\"]}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := planPostgresRemoval(root, "demo"); err == nil {
		t.Fatal("a ledger naming an invalid identifier must stop the removal")
	}
}

func TestPlanPostgresRemovalSortsEveryListAndRetriesFromLedgerOnly(t *testing.T) {
	stubRemovalPostgresProbes(t, true, nil, nil)
	root := t.TempDir()
	writeLedger(t, root, "demo", postgresLedger{
		Roles:     []string{"zeta", "demo", "alpha"},
		Databases: []string{"zeta", "demo", "alpha"},
	})
	removal, err := planPostgresRemoval(root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removal.Databases, ",") != "alpha,demo,zeta" || strings.Join(removal.Roles, ",") != "alpha,demo,zeta" || strings.Join(removal.Secrets, ",") != "demo_db_alpha_password_v1,demo_db_zeta_password_v1" {
		t.Fatalf("all removal lists must be sorted: %#v", removal)
	}
	retryRoot := t.TempDir()
	retryLedger := postgresLedger{Version: postgresLedgerVersion, Roles: []string{"retry_role"}, Databases: []string{"retry_db"}}
	if err := writePostgresLedger(retryRoot, "retry-app", retryLedger); err != nil {
		t.Fatal(err)
	}
	stubRemovalPostgresProbes(t, true, nil, nil)
	retry, err := planPostgresRemoval(retryRoot, "retry-app")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(retry.Databases, ",") != "retry_db" || strings.Join(retry.Roles, ",") != "retry_role" {
		t.Fatalf("a second destroy with only the retry ledger must plan exactly its entries, got %#v", retry)
	}
}

func TestApplyPostgresRemovalRecordsFailuresAndSortsLines(t *testing.T) {
	removal := postgresRemoval{
		Databases: []string{"zeta_db", "alpha_db"},
		Roles:     []string{"zeta_role", "alpha_role"},
	}
	var dropped []string
	remainder, withheld, lines := applyPostgresRemoval("demo", removal, func(kind, name string) error {
		if kind == "database" && name == "alpha_db" {
			return errors.New("in use")
		}
		dropped = append(dropped, kind+":"+name)
		return nil
	})
	if strings.Join(dropped, ",") != "database:zeta_db" {
		t.Fatalf("databases must be attempted before roles: %#v", dropped)
	}
	if remainder.Version != postgresLedgerVersion || strings.Join(remainder.Databases, ",") != "alpha_db" || len(remainder.Roles) != 2 || len(withheld) != 0 {
		t.Fatalf("only the failed database belongs in the retry ledger: %#v, %#v", remainder, withheld)
	}
	if len(lines) != 3 || lines[0] != "kept PostgreSQL database alpha_db: in use" {
		t.Fatalf("failed drop must be reported as retryable: %#v", lines)
	}
}

func TestDestroyPostgresDropIntentReconcilesInterruptedDrop(t *testing.T) {
	for _, kind := range []string{"database", "role"} {
		t.Run(kind, func(t *testing.T) {
			const name = "demo_object"
			journal := &destroyCleanupJournal{
				DropDatabases: true,
				Removal:       postgresRemoval{},
			}
			pending := &journal.PendingDatabases
			if kind == "role" {
				pending = &journal.PendingRoles
			}
			*pending = []string{name}
			if kind == "database" {
				journal.Removal.Databases = []string{name}
			} else {
				journal.Removal.Roles = []string{name}
			}
			var persistedIntent destroyCleanupJournal
			persistCalls := 0
			persist := func() error {
				persistCalls++
				if persistCalls == 1 {
					persistedIntent = *journal
					persistedIntent.PendingDatabases = append([]string(nil), journal.PendingDatabases...)
					persistedIntent.PendingRoles = append([]string(nil), journal.PendingRoles...)
					intentCopy := *journal.PostgresDropIntent
					persistedIntent.PostgresDropIntent = &intentCopy
					return nil
				}
				return errors.New("simulated journal write failure after drop success")
			}
			drops := 0
			inspect := func(gotKind, gotName string) (string, bool, error) {
				if gotKind != kind || gotName != name {
					t.Fatalf("inspected %s %s, want %s %s", gotKind, gotName, kind, name)
				}
				return "741", true, nil
			}
			err := applyDestroyPostgresDrop(journal, kind, name, inspect, func() error {
				drops++
				return nil
			}, persist, nil)
			if !errors.Is(err, errDestroyJournalProgress) || drops != 1 || persistedIntent.PostgresDropIntent == nil {
				t.Fatalf("interrupted drop err=%v drops=%d persisted=%+v", err, drops, persistedIntent.PostgresDropIntent)
			}
			if persistedIntent.PostgresDropIntent.Kind != kind || persistedIntent.PostgresDropIntent.Name != name || persistedIntent.PostgresDropIntent.OID != "741" {
				t.Fatalf("in-flight identity = %+v", persistedIntent.PostgresDropIntent)
			}

			// The durable intent is the state recovery reads after the process exits.
			recovered := persistedIntent
			var recoveredReports []string
			err = applyDestroyPostgresDrop(&recovered, kind, name, func(string, string) (string, bool, error) {
				return "", false, nil
			}, func() error {
				drops++
				return nil
			}, func() error { return nil }, func(line string) { recoveredReports = append(recoveredReports, line) })
			if err != nil || drops != 1 || len(recovered.PendingDatabases)+len(recovered.PendingRoles) != 0 || recovered.PostgresDropIntent != nil || len(recoveredReports) != 0 {
				t.Fatalf("recovery repeated a completed drop: err=%v drops=%d journal=%+v reports=%v", err, drops, recovered, recoveredReports)
			}
		})
	}
}

func TestDestroyPostgresDropIntentKeepsRecreatedObject(t *testing.T) {
	for _, kind := range []string{"database", "role"} {
		t.Run(kind, func(t *testing.T) {
			const name = "demo_object"
			journal := &destroyCleanupJournal{DropDatabases: true, PostgresDropIntent: &postgresDropIntent{Kind: kind, Name: name, OID: "741"}}
			pending := &journal.PendingDatabases
			if kind == "role" {
				pending = &journal.PendingRoles
			}
			*pending = []string{name}
			dropCalls := 0
			var reports []string
			err := applyDestroyPostgresDrop(journal, kind, name, func(string, string) (string, bool, error) {
				return "742", true, nil
			}, func() error {
				dropCalls++
				return nil
			}, func() error { return nil }, func(line string) { reports = append(reports, line) })
			if err != nil || dropCalls != 0 || len(*pending) != 0 || journal.PostgresDropIntent != nil || len(journal.Removal.Kept) != 1 {
				t.Fatalf("recreated object was not kept: err=%v drops=%d journal=%+v", err, dropCalls, journal)
			}
			if len(reports) != 1 || !strings.Contains(reports[0], "recreated after an interrupted destroy") {
				t.Fatalf("recreated object report = %v", reports)
			}
			if kind == "role" {
				selection := postgresCredentialsToKeep("demo", journal.Removal, nil, postgresLedger{})
				if !slices.Contains(selection.DockerSecrets, managedRoleSecretName("demo", name)) {
					t.Fatalf("recreated role credentials were not kept: %+v", selection)
				}
			}
		})
	}
}

func TestRootPostgresCommandKillsBlockedDescendants(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "descendant-survived")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", `(sleep 0.4; printf survived > "$1") & wait`, "sh", marker)
	started := time.Now()
	_, err := runRootProcessGroup(command, 100*time.Millisecond)
	if err == nil || ctx.Err() == nil {
		t.Fatalf("blocked command returned err=%v context=%v", err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked command exceeded its cancellation bound: %s", elapsed)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("blocked descendant survived process-group cancellation: stat err=%v", err)
	}
}

func TestApplyPostgresRemovalWithholdsAnyRoleWhileADatabaseIsKept(t *testing.T) {
	removal := postgresRemoval{
		Databases: []string{"owned_db"},
		Roles:     []string{"unrelated_role"},
		Kept:      []keptPostgresObject{{Kind: "database", Name: "legacy_db", Reason: "kept"}},
	}
	remainder, withheld, lines := applyPostgresRemoval("demo", removal, func(kind, name string) error {
		if kind == "role" {
			return errors.New("still owns another database")
		}
		return nil
	})
	if len(remainder.Roles) != 0 || strings.Join(withheld, ",") != "unrelated_role" {
		t.Fatalf("a recorded role blocked by any kept database must leave the retry ledger: %#v, %#v", remainder, withheld)
	}
	if len(lines) != 2 || !strings.Contains(strings.Join(lines, "\n"), "kept PostgreSQL role unrelated_role: database(s) legacy_db were kept; drop it by hand after those databases") {
		t.Fatalf("withheld role and kept database must both be reported: %#v", lines)
	}
}

func TestApplyPostgresRemovalCredentialSelection(t *testing.T) {
	removal := postgresRemoval{
		Roles: []string{"analytics", "retry_role"},
		Kept: []keptPostgresObject{
			{Kind: "role", Name: "analytics", Reason: "probe failed"},
			{Kind: "role", Name: "demo_app", Reason: "legacy"},
		},
	}
	selection := postgresCredentialsToKeep("demo-app", removal, []string{"retry_role"}, postgresLedger{})
	if strings.Join(selection.DockerSecrets, ",") != "demo-app_db_analytics_password_v1,demo-app_db_retry_role_password_v1,demo-app_postgres_password_v1" {
		t.Fatalf("kept roles must keep only their corresponding Docker secrets: %#v", selection)
	}
	if strings.Join(selection.Files, ",") != "db-analytics.password,db-retry_role.password,postgres.password" {
		t.Fatalf("kept roles must keep only their corresponding password files: %#v", selection)
	}
	selection = postgresCredentialsToKeep("demo-app", postgresRemoval{Roles: []string{"analytics"}}, nil, postgresLedger{})
	if len(selection.DockerSecrets) != 0 || len(selection.Files) != 0 {
		t.Fatalf("successful drops and retryable roles without withholding keep no credentials: %#v", selection)
	}
}

func TestCredentialsToKeepPreservesRetryableFailedDeclaredAndDerivedRoles(t *testing.T) {
	removal := postgresRemoval{Roles: []string{"analytics", "demo_app", "retry_role", "dropped_role"}}
	remainder := postgresLedger{Roles: []string{"demo_app", "retry_role"}}
	selection := postgresCredentialsToKeep("demo-app", removal, nil, remainder)
	if strings.Join(selection.DockerSecrets, ",") != "demo-app_db_retry_role_password_v1,demo-app_postgres_password_v1" {
		t.Fatalf("retryable roles must keep their Docker secrets, while dropped roles lose them: %#v", selection)
	}
	if strings.Join(selection.Files, ",") != "db-retry_role.password,postgres.password" {
		t.Fatalf("retryable roles must keep their password files, while dropped roles lose them: %#v", selection)
	}
}

func TestOwnershipPreflightRefusesUnrecordedDerivedRoleOrDatabase(t *testing.T) {
	stateRoot := t.TempDir()
	payload := []byte("services:\n  api:\n    deploy:\n      labels:\n        dev.shuttle.postgres: \"true\"\n")
	for _, test := range []struct {
		name       string
		roleExists bool
		dbExists   bool
		want       string
	}{
		{name: "derived role", roleExists: true, want: "PostgreSQL role demo_app already exists"},
		{name: "derived database", dbExists: true, want: "PostgreSQL database demo_app already exists"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := stubRemovalPostgresProbes(t, true,
				func(string) (bool, error) { return test.dbExists, nil },
				func(string) (bool, error) { return test.roleExists, nil },
			)
			err := preflightManagedPostgresOwnershipAt(stateRoot, "demo-app", payload)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ownership preflight must refuse the unrecorded derived object, got %v", err)
			}
			if calls.role != 1 || calls.database != 1 {
				t.Fatalf("preflight must use both read-only existence probes: %#v", calls)
			}
			entries, readErr := os.ReadDir(stateRoot)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("ownership preflight must not write state: entries=%v err=%v", entries, readErr)
			}
		})
	}
}

func TestOwnershipPreflightIsDispatchedForStackApply(t *testing.T) {
	oldStackPreflight := rootStackApplyPreflight
	oldPreflight := rootPostgresOwnershipPreflight
	var order []string
	rootStackApplyPreflight = func(rootplan.Plan, []byte) error {
		order = append(order, "stack preflight")
		return nil
	}
	rootPostgresOwnershipPreflight = func(app string, _ []byte) error {
		if app != "demo-app" {
			t.Fatalf("ownership preflight received wrong app: %s", app)
		}
		order = append(order, "ownership preflight")
		return nil
	}
	t.Cleanup(func() {
		rootStackApplyPreflight = oldStackPreflight
		rootPostgresOwnershipPreflight = oldPreflight
	})
	plan := rootplan.Plan{Action: "stack-apply", Stack: &rootplan.StackOperation{App: "demo-app"}}
	if err := preflightRootStackApply(plan, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "stack preflight,ownership preflight" {
		t.Fatalf("stack-apply must finish ownership checks before deployment mutation, got %v", order)
	}
}

func TestApplyPostgresRemovalFiltersOwnerLabelledRoleSecrets(t *testing.T) {
	removal := postgresRemoval{Roles: []string{"reporting", "audit"}}
	owned := []string{"demo_db_reporting_password_v1", "demo_db_audit_password_v1", "demo_postgres_password_v1", "demo_app_other_secret"}
	filtered := filterPostgresSecretsFromOwned(owned, "demo", removal)
	if strings.Join(filtered, ",") != "demo_app_other_secret" {
		t.Fatalf("PostgreSQL credentials must wait for the outcome-aware cleanup: %#v", filtered)
	}
}

func TestPostgresAdoptionDecisionRefusesUnrecordedExistingDerivedObjects(t *testing.T) {
	passwordDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(passwordDir, "postgres.password"), []byte("existing-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		roleExists bool
		dbExists   bool
		ledger     postgresLedger
		kind       string
	}{
		{name: "role with old password file", roleExists: true, kind: "role"},
		{name: "database", dbExists: true, kind: "database"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := postgresProvisionDecision(test.ledger, test.roleExists, test.dbExists, nil)
			var refusal *postgresProvisionRefusal
			if !errors.As(err, &refusal) || refusal.kind != test.kind {
				t.Fatalf("existing unrecorded %s must be refused, got %v", test.kind, err)
			}
		})
	}
	if err := postgresProvisionDecision(postgresLedger{Roles: []string{"derived"}, Databases: []string{"derived"}}, true, true, nil); err != nil {
		t.Fatalf("recorded objects must be accepted: %v", err)
	}
	if err := postgresProvisionDecision(postgresLedger{}, false, false, nil); err != nil {
		t.Fatalf("missing objects may be created: %v", err)
	}
	probeErr := errors.New("existence check failed")
	if err := postgresProvisionDecision(postgresLedger{}, false, false, probeErr); !errors.Is(err, probeErr) {
		t.Fatalf("probe error must abort before writes: %v", err)
	}
}

func TestPostgresAdoptionRefusalMessageNamesTheManualLedgerEntry(t *testing.T) {
	for _, kind := range []string{"role", "database"} {
		got := postgresProvisionRefusalMessage("demo-app", "demo_app", kind)
		want := "PostgreSQL " + kind + " demo_app already exists and is not recorded as created by Shuttle for demo-app; refusing to change it. If Shuttle created it before ownership tracking, add it to /var/lib/shuttle/apps/demo-app/postgres.json as documented in docs/configuration.md; otherwise rename the app"
		if got != want {
			t.Fatalf("managed deploy refusal must explain exact manual ledger recovery, got %q", got)
		}
	}
}

func TestPostgresLedgerCanBeClearedWhenMissing(t *testing.T) {
	if err := writeOrClearPostgresLedger(t.TempDir(), "demo", postgresLedger{Version: postgresLedgerVersion}); err != nil {
		t.Fatalf("clearing a missing ledger must be idempotent: %v", err)
	}
}

func TestPostgresLedgerRoundTrips(t *testing.T) {
	root := t.TempDir()
	empty, err := readPostgresLedger(root, "demo")
	if err != nil || len(empty.Roles) != 0 || len(empty.Databases) != 0 {
		t.Fatalf("a missing ledger reads as empty, got %#v, %v", empty, err)
	}
	writeLedger(t, root, "demo", postgresLedger{Roles: []string{"a"}, Databases: []string{"b"}})
	back, err := readPostgresLedger(root, "demo")
	if err != nil || !back.hasRole("a") || !back.hasDatabase("b") || back.Version != postgresLedgerVersion {
		t.Fatalf("ledger round-trip failed: %#v, %v", back, err)
	}
}

const managedStackFixture = `
services:
  web:
    image: registry/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    environment:
      APP_ENV: production
    deploy:
      labels:
        dev.shuttle.postgres: "true"
  worker:
    image: registry/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    deploy: {}
`

func stackServices(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	services, _ := document["services"].(map[string]any)
	return services
}

// The address lands on the service the stack itself designates, and on no other.
func TestInjectManagedDatabaseHostSkipsAServiceWithoutADatabasePassword(t *testing.T) {
	injected, changed, err := injectManagedDatabaseHost([]byte(managedStackFixture), "172.18.0.1")
	if err != nil || !changed {
		t.Fatalf("injectManagedDatabaseHost() = %v, %v", changed, err)
	}
	services := stackServices(t, injected)
	web, _ := services["web"].(map[string]any)
	environment, _ := web["environment"].(map[string]any)
	if environment[managedDatabaseHostVariable] != "172.18.0.1" {
		t.Fatalf("the labelled service must receive the address: %#v", environment)
	}
	if environment["APP_ENV"] != "production" {
		t.Fatalf("the service's own environment must survive: %#v", environment)
	}
	worker, _ := services["worker"].(map[string]any)
	if _, present := worker["environment"]; present {
		t.Fatalf("a service holding no database password receives nothing: %#v", worker)
	}
}

// §4: a stack with no managed database is deployed byte for byte as signed.
func TestInjectManagedDatabaseHostLeavesAnUnmanagedStackAlone(t *testing.T) {
	payload := []byte(strings.Replace(managedStackFixture, "dev.shuttle.postgres: \"true\"", "dev.shuttle.domain: demo.example.com", 1))
	injected, changed, err := injectManagedDatabaseHost(payload, "172.18.0.1")
	if err != nil || changed {
		t.Fatalf("an unmanaged stack must not be rewritten: %v, %v", changed, err)
	}
	if string(injected) != string(payload) {
		t.Fatalf("the stack must be returned unchanged:\n%s", injected)
	}
	declared, err := stackDeclaresManagedDatabase(payload)
	if err != nil || declared {
		t.Fatalf("stackDeclaresManagedDatabase() = %v, %v", declared, err)
	}
}

// A list environment keeps working, and Shuttle's answer replaces whatever the
// compose file guessed: the application cannot know this address.
func TestInjectManagedDatabaseHostReplacesADeclaredValue(t *testing.T) {
	payload := []byte(strings.Replace(managedStackFixture, "    environment:\n      APP_ENV: production\n", "    environment:\n      - APP_ENV=production\n      - POSTGRES_HOST=localhost\n", 1))
	injected, changed, err := injectManagedDatabaseHost(payload, "172.18.0.1")
	if err != nil || !changed {
		t.Fatalf("injectManagedDatabaseHost() = %v, %v", changed, err)
	}
	web, _ := stackServices(t, injected)["web"].(map[string]any)
	entries, _ := web["environment"].([]any)
	found := 0
	for _, entry := range entries {
		if entry == "POSTGRES_HOST=172.18.0.1" {
			found++
		}
		if entry == "POSTGRES_HOST=localhost" {
			t.Fatalf("the guessed address must be replaced: %#v", entries)
		}
	}
	if found != 1 {
		t.Fatalf("the address must appear exactly once: %#v", entries)
	}
}

// An empty or unusable address is refused, because an empty variable produces an
// application that starts, dials nothing and fails later.
func TestInjectManagedDatabaseHostRefusesAnUnusableAddress(t *testing.T) {
	for _, gateway := range []string{"", "   ", "not-an-ip", "172.18.0.1 ", "$(id)"} {
		if _, _, err := injectManagedDatabaseHost([]byte(managedStackFixture), gateway); err == nil {
			t.Fatalf("gateway %q must be refused", gateway)
		}
	}
}

// The injected stack is deployed, so it is validated: a stack that passes the
// signed checks must still pass them after the address is written into it.
func TestInjectedManagedDatabaseStackStillPassesRootValidation(t *testing.T) {
	payload := []byte(`
services:
  web:
    image: registry/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck: {test: ["CMD", "true"]}
    deploy:
      labels:
        dev.shuttle.postgres: "true"
      resources:
        limits: {cpus: "1", memory: 512M}
`)
	if err := validateRootStack(payload); err != nil {
		t.Fatalf("fixture must be valid before injection: %v", err)
	}
	injected, changed, err := injectManagedDatabaseHost(payload, "172.18.0.1")
	if err != nil || !changed {
		t.Fatalf("injectManagedDatabaseHost() = %v, %v", changed, err)
	}
	if err := validateRootStack(injected); err != nil {
		t.Fatalf("the stack that is actually deployed must validate: %v", err)
	}
	// A previous.yml retained before a policy was added still has to reach the
	// emergency rollback with its database address.
	legacy := append(append([]byte{}, payload...), []byte("volumes:\n  data: {driver_opts: {type: nfs}}\n")...)
	legacyInjected, changed, err := injectManagedDatabaseHost(legacy, "172.18.0.1")
	if err != nil || !changed {
		t.Fatalf("injectManagedDatabaseHost() = %v, %v", changed, err)
	}
	if err := validateRetainedRootStack(legacyInjected); err != nil {
		t.Fatalf("a retained stack must stay deployable: %v", err)
	}
}

// The signed payload on disk stays what was signed; only the derived file
// carries the address, and only when there is a managed database.
func TestStackFileWithManagedDatabaseHostKeepsTheSignedFile(t *testing.T) {
	dir := t.TempDir()
	signed := filepath.Join(dir, "current.yml")
	payload := []byte(strings.Replace(managedStackFixture, "dev.shuttle.postgres: \"true\"", "dev.shuttle.domain: demo.example.com", 1))
	if err := os.WriteFile(signed, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := stackFileWithManagedDatabaseHost(dir, signed)
	if err != nil {
		t.Fatal(err)
	}
	if file != signed {
		t.Fatalf("a stack without a managed database is deployed from the signed file, got %q", file)
	}
	if _, err := os.Stat(filepath.Join(dir, "effective.yml")); !os.IsNotExist(err) {
		t.Fatalf("no derived file may be written for an unmanaged stack: %v", err)
	}
}
