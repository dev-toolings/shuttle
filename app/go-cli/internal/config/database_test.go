package config

import (
	"strings"
	"testing"
)

func TestValidateDatabaseConfigAcceptsRolesDatabasesAndSchemas(t *testing.T) {
	spec := DatabaseConfig{
		Version:   16,
		Roles:     []DatabaseRole{{Name: "app"}, {Name: "reporting"}},
		Databases: []DatabaseDatabase{{Name: "app", Owner: "app", Schemas: []string{"private", "analytics"}}},
	}
	if err := validateDatabaseConfig("demo", spec); err != nil {
		t.Fatalf("valid database config rejected: %v", err)
	}
}

func TestValidateDatabaseConfigRejectsUnsafeOrUnresolvedNames(t *testing.T) {
	cases := []struct {
		name string
		app  string
		spec DatabaseConfig
		want string
	}{
		{"uppercase role", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "App"}}}, "lowercase PostgreSQL identifier"},
		{"duplicate role", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "app"}, {Name: "app"}}}, "duplicate role"},
		{"unknown owner", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "app"}}, Databases: []DatabaseDatabase{{Name: "reporting", Owner: "missing"}}}, "not declared"},
		{"duplicate schema", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "app"}}, Databases: []DatabaseDatabase{{Name: "app", Owner: "app", Schemas: []string{"private", "private"}}}}, "duplicate schema"},
		// A name that has to be trimmed before it is safe is refused, not
		// trimmed: the value checked here is the value written into CREATE ROLE.
		{"padded role", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: " app "}}}, "lowercase PostgreSQL identifier"},
		{"quote in role", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "app'; DROP DATABASE demo; --"}}}, "lowercase PostgreSQL identifier"},
		{"reserved prefix", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "pg_admin"}}}, "pg_ prefix"},
		{"reserved database", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "app"}}, Databases: []DatabaseDatabase{{Name: "postgres", Owner: "app"}}}, "reserved PostgreSQL name"},
		// The trap this change exists to remove: a declared list that validates
		// and provisions nothing, because nothing marks the managed database.
		{"roles without a managed database", "demo", DatabaseConfig{Roles: []DatabaseRole{{Name: "app"}}}, "require a managed database.version (16, 17, 18)"},
		{"databases without roles", "demo", DatabaseConfig{Version: 16, Databases: []DatabaseDatabase{{Name: "reporting", Owner: "app"}}}, "requires at least one role"},
		{"foreign owner for the application database", "demo", DatabaseConfig{Version: 16, Roles: []DatabaseRole{{Name: "demo"}, {Name: "other"}}, Databases: []DatabaseDatabase{{Name: "demo", Owner: "other"}}}, "owned by its own role"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateDatabaseConfig(tc.app, tc.spec); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateDatabaseConfig() error = %v, want %q", err, tc.want)
			}
		})
	}
}

// The configuration `shuttle init --with-db postgres` writes declares exactly
// the role and database the helper already derives from the application name.
// It has to keep validating, and its owner has to keep being accepted.
func TestValidateDatabaseConfigAcceptsTheGeneratedSingleDatabaseShape(t *testing.T) {
	spec := DatabaseConfig{
		Version:   16,
		Backup:    DatabaseBackup{Mode: "local", Retention: 7},
		Roles:     []DatabaseRole{{Name: "shuttle_smoke"}},
		Databases: []DatabaseDatabase{{Name: "shuttle_smoke", Owner: "shuttle_smoke"}},
	}
	if err := validateDatabaseConfig("shuttle-smoke", spec); err != nil {
		t.Fatalf("the generated single-database configuration was rejected: %v", err)
	}
}

// A configuration that declares neither roles nor databases must be validated
// by exactly the rules it was validated by before they meant anything.
func TestValidateDatabaseConfigLeavesTheUndeclaredDefaultAlone(t *testing.T) {
	if err := validateDatabaseConfig("demo", DatabaseConfig{}); err != nil {
		t.Fatalf("empty database config rejected: %v", err)
	}
	if err := validateDatabaseConfig("demo", DatabaseConfig{Version: 16, Backup: DatabaseBackup{Mode: "local", Retention: 7}}); err != nil {
		t.Fatalf("managed database without declared objects rejected: %v", err)
	}
	if err := validateDatabaseConfig("demo", DatabaseConfig{Version: 15}); err == nil {
		t.Fatal("database.version 15 must still be refused")
	}
}
