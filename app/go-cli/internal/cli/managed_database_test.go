package cli

import (
	"strconv"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func managedDatabaseConfig() *config.Config {
	cfg := &config.Config{App: "demo"}
	cfg.Domain = "demo.example.com"
	cfg.Database.Version = 16
	return cfg
}

func managedDatabaseStack(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	cf := parseComposeString(t, `
services:
  web:
    build: .
    healthcheck: {test: ["CMD", "true"]}
  worker:
    build: .
    healthcheck: {test: ["CMD", "true"]}
`)
	digest := "registry/app@sha256:" + strings.Repeat("a", 64)
	generated, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{"web": digest, "worker": digest}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	assertRootGlobalSectionsAccept(t, generated)
	secured, err := secureStack(generated, cfg, "8000")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(secured), &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func serviceLabels(t *testing.T, root map[string]any, service string) map[string]any {
	t.Helper()
	deploy, _ := generatedService(t, root, service)["deploy"].(map[string]any)
	labels, _ := deploy["labels"].(map[string]any)
	return labels
}

// Declared roles and databases have to reach the host. They travel on the
// service that already carries dev.shuttle.postgres, in the order they were
// written, because that is the payload the operator signs.
func TestSecureStackCarriesDeclaredRolesAndDatabases(t *testing.T) {
	cfg := managedDatabaseConfig()
	cfg.Database.Roles = []config.DatabaseRole{{Name: "demo"}, {Name: "reporting"}}
	cfg.Database.Databases = []config.DatabaseDatabase{
		{Name: "demo", Owner: "demo"},
		{Name: "reporting", Owner: "reporting", Schemas: []string{"marts", "staging"}},
	}
	root := managedDatabaseStack(t, cfg)

	labels := serviceLabels(t, root, "web")
	raw, present := labels[managedDatabaseLabel]
	if !present {
		t.Fatalf("the declared databases must travel with the stack: %#v", labels)
	}
	plan, err := parseManagedDatabasePlan(raw.(string))
	if err != nil {
		t.Fatalf("the emitted label must pass the helper's own validation: %v", err)
	}
	if len(plan.Roles) != 2 || plan.Roles[0].Name != "demo" || plan.Roles[1].Name != "reporting" {
		t.Fatalf("roles travel in the declared order, got %#v", plan.Roles)
	}
	if len(plan.Databases) != 2 || plan.Databases[1].Name != "reporting" || plan.Databases[1].Owner != "reporting" {
		t.Fatalf("databases travel as declared, got %#v", plan.Databases)
	}
	if len(plan.Databases[1].Schemas) != 2 || plan.Databases[1].Schemas[0] != "marts" {
		t.Fatalf("schemas travel as declared, got %#v", plan.Databases[1].Schemas)
	}

	// One secret per additional role, derived and versioned, mounted next to the
	// POSTGRES_PASSWORD the application's own role already gets.
	secrets, _ := root["secrets"].(map[string]any)
	if _, present := secrets["demo_db_reporting_password_v1"]; !present {
		t.Fatalf("the additional role needs an external secret: %#v", secrets)
	}
	if _, present := secrets["demo_db_demo_password_v1"]; present {
		t.Fatalf("the application's own role must not get a second password: %#v", secrets)
	}
	mounted := map[string]string{}
	for _, entry := range generatedService(t, root, "web")["secrets"].([]any) {
		reference := entry.(map[string]any)
		mounted[reference["source"].(string)] = reference["target"].(string)
	}
	if mounted["demo_postgres_password_v1"] != "POSTGRES_PASSWORD" {
		t.Fatalf("the managed database password must stay mounted: %#v", mounted)
	}
	if mounted["demo_db_reporting_password_v1"] != "POSTGRES_PASSWORD_REPORTING" {
		t.Fatalf("the additional role password is missing from the service: %#v", mounted)
	}
	if labels := serviceLabels(t, root, "worker"); labels[managedDatabaseLabel] != nil {
		t.Fatalf("a service that is not the published one carries no database label: %#v", labels)
	}
}

// §4: a configuration that declares no roles and no databases produces exactly
// the stack it produced before the declared list meant anything.
func TestSecureStackManagedDatabaseDefaultsAreUnchanged(t *testing.T) {
	cfg := managedDatabaseConfig()
	root := managedDatabaseStack(t, cfg)

	labels := serviceLabels(t, root, "web")
	if labels[managedPostgresLabel] != "true" {
		t.Fatalf("the managed database label must stay: %#v", labels)
	}
	if _, present := labels[managedDatabaseLabel]; present {
		t.Fatalf("nothing declared, nothing emitted: %#v", labels)
	}
	secrets, _ := root["secrets"].(map[string]any)
	if len(secrets) != 1 {
		t.Fatalf("only the managed database secret belongs here: %#v", secrets)
	}
	if _, present := secrets["demo_postgres_password_v1"]; !present {
		t.Fatalf("the managed database secret is missing: %#v", secrets)
	}
	references := generatedService(t, root, "web")["secrets"].([]any)
	if len(references) != 1 {
		t.Fatalf("the published service keeps exactly one secret: %#v", references)
	}
}

// Every supported major produces the same managed stack. The label and the
// mounted POSTGRES_PASSWORD are what tell the root helper there is a database
// to provision at all, so a major that produced neither would validate at the
// desk and silently deploy an application with no database.
func TestSecureStackMarksEverySupportedMajorAsManaged(t *testing.T) {
	for _, version := range config.SupportedDatabaseVersions {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			cfg := managedDatabaseConfig()
			cfg.Database.Version = version
			root := managedDatabaseStack(t, cfg)

			if labels := serviceLabels(t, root, "web"); labels[managedPostgresLabel] != "true" {
				t.Fatalf("database.version %d must carry the managed database label: %#v", version, labels)
			}
			secrets, _ := root["secrets"].(map[string]any)
			if _, present := secrets["demo_postgres_password_v1"]; !present {
				t.Fatalf("database.version %d must declare the managed database secret: %#v", version, secrets)
			}
			mounted := map[string]string{}
			for _, entry := range generatedService(t, root, "web")["secrets"].([]any) {
				reference := entry.(map[string]any)
				mounted[reference["source"].(string)] = reference["target"].(string)
			}
			if mounted["demo_postgres_password_v1"] != "POSTGRES_PASSWORD" {
				t.Fatalf("database.version %d must mount POSTGRES_PASSWORD: %#v", version, mounted)
			}
		})
	}
}

// A configuration with no managed database at all keeps producing a stack with
// no database label, no secret and no environment.
func TestSecureStackWithoutManagedDatabaseIsUntouched(t *testing.T) {
	cfg := &config.Config{App: "demo"}
	cfg.Domain = "demo.example.com"
	root := managedDatabaseStack(t, cfg)

	labels := serviceLabels(t, root, "web")
	if _, present := labels[managedPostgresLabel]; present {
		t.Fatalf("no managed database was configured: %#v", labels)
	}
	if _, present := root["secrets"]; present {
		t.Fatalf("no managed database means no secrets section: %#v", root["secrets"])
	}
}

func TestSecureStackRefusesARoleWhoseSecretNameDoesNotFit(t *testing.T) {
	cfg := managedDatabaseConfig()
	cfg.App = strings.Repeat("a", 50)
	cfg.Database.Roles = []config.DatabaseRole{{Name: strings.Repeat("b", 20)}}
	cf := parseComposeString(t, "services:\n  web:\n    build: .\n    healthcheck: {test: [\"CMD\", \"true\"]}\n")
	generated, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{"web": "registry/app@sha256:" + strings.Repeat("a", 64)}, secretManifest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secureStack(generated, cfg, "8000"); err == nil || !strings.Contains(err.Error(), "above the 64 Docker allows") {
		t.Fatalf("expected a refusal naming the Docker limit, got %v", err)
	}
}

// The helper re-validates everything the CLI validated, and refuses rather than
// repairs: these values end up inside CREATE ROLE and createdb.
func TestParseManagedDatabasePlanRefusesWhatItWouldHaveToClean(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"not json", `{`, "not valid JSON"},
		{"two documents", `{"roles":[{"name":"app"}]} {"roles":[{"name":"app"}]}`, "exactly one JSON document"},
		{"unknown field", `{"roles":[{"name":"app","superuser":true}]}`, "not valid JSON"},
		{"no roles", `{"databases":[{"name":"app","owner":"app"}]}`, "between 1 and 16 roles"},
		{"padded name", `{"roles":[{"name":" app "}]}`, "not a lowercase PostgreSQL identifier"},
		{"quoted name", `{"roles":[{"name":"app\"; DROP DATABASE demo; --"}]}`, "not a lowercase PostgreSQL identifier"},
		{"uppercase", `{"roles":[{"name":"App"}]}`, "not a lowercase PostgreSQL identifier"},
		{"reserved prefix", `{"roles":[{"name":"pg_toast_x"}]}`, "pg_ prefix"},
		{"reserved name", `{"roles":[{"name":"app"}],"databases":[{"name":"template1","owner":"app"}]}`, "reserved PostgreSQL name"},
		{"duplicate role", `{"roles":[{"name":"app"},{"name":"app"}]}`, "declared twice"},
		{"undeclared owner", `{"roles":[{"name":"app"}],"databases":[{"name":"reporting","owner":"other"}]}`, "not a declared role"},
		{"duplicate schema", `{"roles":[{"name":"app"}],"databases":[{"name":"reporting","owner":"app","schemas":["s","s"]}]}`, "declares schema \"s\" twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseManagedDatabasePlan(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseManagedDatabasePlan(%s) error = %v, want %q", tc.raw, err, tc.want)
			}
		})
	}
}

func TestParseManagedDatabasePlanAcceptsNothing(t *testing.T) {
	for _, raw := range []string{"", "   ", "<nil>"} {
		plan, err := parseManagedDatabasePlan(raw)
		if err != nil || !plan.empty() {
			t.Fatalf("parseManagedDatabasePlan(%q) = %#v, %v; want an empty plan", raw, plan, err)
		}
	}
}

// A declared list on a stack with no managed database would provision nothing
// and report nothing, which is the failure this change exists to remove.
func TestManagedDatabaseLabelWithoutTheManagedDatabaseIsRefused(t *testing.T) {
	var document map[string]any
	if err := yaml.Unmarshal([]byte(`
services:
  web:
    deploy:
      labels:
        dev.shuttle.databases: '{"roles":[{"name":"app"}]}'
`), &document); err != nil {
		t.Fatal(err)
	}
	if _, err := managedDatabaseLabelFromStack(document); err == nil || !strings.Contains(err.Error(), "without a managed database") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}
