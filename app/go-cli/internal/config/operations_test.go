package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func operationsFixture(operations map[string]Operation) *Config {
	cfg := primaryServiceFixture()
	cfg.Operations = operations
	return cfg
}

func TestOperationBackupBeforeRequiresManagedDatabase(t *testing.T) {
	cfg := operationsFixture(map[string]Operation{"migrate": {Service: "api", Command: []string{"php", "migrate"}, BackupBefore: true}})
	cfg.Database.Version = DefaultDatabaseVersion
	if err := validateOperations(cfg); err != nil {
		t.Fatalf("backup_before with managed PostgreSQL must validate: %v", err)
	}
	cfg.Database = DatabaseConfig{}
	if err := validateOperations(cfg); err == nil || !strings.Contains(err.Error(), "operations.migrate.backup_before requires a managed PostgreSQL database (database block)") {
		t.Fatalf("backup_before without managed PostgreSQL must name the operation: %v", err)
	}
}

func TestOperationBackupBeforeRequiresBooleanThroughLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"operations":{"migrate":{"service":"api","command":["php","migrate"],"backup_before":"yes"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, ""); err == nil {
		t.Fatal("non-boolean backup_before must be rejected by the normal load path")
	}
}

func TestOperationsAcceptTheCommandsThisDeploymentNeeds(t *testing.T) {
	cfg := operationsFixture(map[string]Operation{
		"migrate": {Service: "api", Command: []string{"php", "bin/console", "doctrine:migrations:migrate", "--no-interaction"}},
		"reindex": {Service: "api", Command: []string{"php", "bin/console", "app:search:reindex-listings"}},
	})
	if err := validateOperations(cfg); err != nil {
		t.Fatalf("declared operations must validate, got %v", err)
	}
}

func TestOperationsRejectUnusableDeclarations(t *testing.T) {
	cases := map[string]map[string]Operation{
		"uppercase name":       {"Reindex": {Service: "api", Command: []string{"php"}}},
		"name with a slash":    {"a/b": {Service: "api", Command: []string{"php"}}},
		"empty command":        {"reindex": {Service: "api", Command: nil}},
		"empty argument":       {"reindex": {Service: "api", Command: []string{"php", ""}}},
		"newline in argument":  {"reindex": {Service: "api", Command: []string{"php", "a\nb"}}},
		"invalid service name": {"reindex": {Service: "Api Core", Command: []string{"php"}}},
	}
	for name, operations := range cases {
		if err := validateOperations(operationsFixture(operations)); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// A shell metacharacter is not dangerous here — the command is an argv passed to
// docker exec, never to a shell — so it must not be rejected either. Refusing it
// would only teach an operator to work around the validation.
func TestOperationsAllowArgumentsThatWouldMatterToAShell(t *testing.T) {
	cfg := operationsFixture(map[string]Operation{
		"report": {Service: "api", Command: []string{"php", "bin/console", "app:report", "--filter=a;b|c"}},
	})
	if err := validateOperations(cfg); err != nil {
		t.Fatalf("an argv argument is not a shell string, got %v", err)
	}
}

func TestOperationErrorsNameTheOffendingOperation(t *testing.T) {
	err := validateOperations(operationsFixture(map[string]Operation{
		"reindex": {Service: "api", Command: nil},
	}))
	if err == nil || !strings.Contains(err.Error(), "operations.reindex.command") {
		t.Fatalf("the error must name the operation, got %v", err)
	}
}
