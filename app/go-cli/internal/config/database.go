package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SupportedDatabaseVersions are the PostgreSQL major versions Shuttle installs
// or adopts. Both are current PGDG majors, and a host already in service is as
// likely to be carrying one as the other — refusing the one it has would mean
// installing a second cluster next to a production database, which is the
// outcome this list exists to avoid.
//
// Order matters: it is the order the versions are probed in on the host and the
// order they are named in every refusal, so the same configuration produces the
// same text on every run.
var SupportedDatabaseVersions = []int{16, 17, 18}

// DefaultDatabaseVersion selects the latest stable PostgreSQL major for a new
// configuration. Existing declared majors remain supported for adoption and
// restores; changing the default never upgrades an existing data directory.
const DefaultDatabaseVersion = 18

// Managed reports whether this configuration asks Shuttle to own a PostgreSQL
// role, database and password for the application. It is the single test the
// rest of the codebase asks — a bare `Version == 16` was the same question
// written in a way that could only ever have one answer.
func (c DatabaseConfig) Managed() bool {
	for _, supported := range SupportedDatabaseVersions {
		if c.Version == supported {
			return true
		}
	}
	return false
}

// supportedDatabaseVersionList renders the supported majors for an error
// message. Built from the list rather than written out, so a version added
// above cannot be missing from the sentence that refuses everything else.
func supportedDatabaseVersionList() string {
	parts := make([]string, 0, len(SupportedDatabaseVersions))
	for _, version := range SupportedDatabaseVersions {
		parts = append(parts, strconv.Itoa(version))
	}
	return strings.Join(parts, ", ")
}

// DatabaseConfig declares non-secret PostgreSQL roles, databases, and schemas.
// Passwords are generated once on the target and stored in its root-only
// database secret directory; they are never accepted in config.json.
type DatabaseConfig struct {
	Version   int                `yaml:"version,omitempty" json:"version,omitempty"`
	Backup    DatabaseBackup     `yaml:"backup,omitempty" json:"backup,omitempty"`
	Roles     []DatabaseRole     `yaml:"roles,omitempty" json:"roles,omitempty"`
	Databases []DatabaseDatabase `yaml:"databases,omitempty" json:"databases,omitempty"`
}

type DatabaseBackup struct {
	Mode      string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Retention int    `yaml:"retention,omitempty" json:"retention,omitempty"`
}

type DatabaseRole struct {
	Name string `yaml:"name" json:"name"`
}

type DatabaseDatabase struct {
	Name    string   `yaml:"name" json:"name"`
	Owner   string   `yaml:"owner" json:"owner"`
	Schemas []string `yaml:"schemas,omitempty" json:"schemas,omitempty"`
}

var postgresIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// maxDatabaseObjects bounds each declared list. The list travels inside the
// signed stack and every entry becomes a privileged CREATE on the host, so it
// is bounded at the desk as well as on arrival.
const maxDatabaseObjects = 16

// reservedPostgresNames are names PostgreSQL owns. They are refused rather than
// silently skipped: a declared object that is never created is the trap this
// validation exists to remove.
var reservedPostgresNames = map[string]bool{
	"postgres":           true,
	"template0":          true,
	"template1":          true,
	"information_schema": true,
	"public":             true,
}

// validatePostgresName checks the exact string that will be emitted. Nothing is
// trimmed: a name that would have to be cleaned before it could be written into
// CREATE ROLE is not a name the operator meant to write.
func validatePostgresName(field, name string) error {
	if !postgresIdentifier.MatchString(name) {
		return fmt.Errorf("%s must be a lowercase PostgreSQL identifier, got %q", field, name)
	}
	if strings.HasPrefix(name, "pg_") {
		return fmt.Errorf("%s must not use the pg_ prefix PostgreSQL reserves, got %q", field, name)
	}
	if reservedPostgresNames[name] {
		return fmt.Errorf("%s must not be the reserved PostgreSQL name %q", field, name)
	}
	return nil
}

// DerivedDatabaseIdentifier is the role and database Shuttle provisions for an
// application from its name alone. It is exported so the same derivation is
// used when refusing a declared role that would collide with it.
func DerivedDatabaseIdentifier(app string) string {
	return strings.ReplaceAll(app, "-", "_")
}

func validateDatabaseConfig(app string, cfg DatabaseConfig) error {
	if cfg.Version != 0 && !cfg.Managed() {
		return fmt.Errorf("database.version must be one of %s", supportedDatabaseVersionList())
	}
	if cfg.Backup.Mode != "" && cfg.Backup.Mode != "local" {
		return fmt.Errorf("database.backup.mode must be local")
	}
	if cfg.Backup.Retention != 0 && cfg.Backup.Retention != 7 {
		return fmt.Errorf("database.backup.retention must be 7")
	}
	if len(cfg.Roles) == 0 && len(cfg.Databases) == 0 {
		return nil
	}
	// Declared roles and databases are provisioned by the root helper, which
	// only acts on the stack that carries dev.shuttle.postgres. Without the
	// managed database they would validate here and create nothing there.
	if !cfg.Managed() {
		return errors.New("database.roles and database.databases require a managed database.version (" + supportedDatabaseVersionList() + ")")
	}
	if len(cfg.Roles) == 0 {
		return errors.New("database.databases requires at least one role in database.roles")
	}
	if len(cfg.Roles) > maxDatabaseObjects || len(cfg.Databases) > maxDatabaseObjects {
		return fmt.Errorf("database.roles and database.databases are limited to %d entries each", maxDatabaseObjects)
	}
	derived := DerivedDatabaseIdentifier(app)
	roles := make(map[string]struct{}, len(cfg.Roles))
	for index, role := range cfg.Roles {
		if err := validatePostgresName(fmt.Sprintf("database.roles[%d].name", index), role.Name); err != nil {
			return err
		}
		if _, exists := roles[role.Name]; exists {
			return fmt.Errorf("database.roles contains duplicate role %q", role.Name)
		}
		roles[role.Name] = struct{}{}
	}

	databases := make(map[string]struct{}, len(cfg.Databases))
	for index, database := range cfg.Databases {
		if err := validatePostgresName(fmt.Sprintf("database.databases[%d].name", index), database.Name); err != nil {
			return err
		}
		if _, exists := databases[database.Name]; exists {
			return fmt.Errorf("database.databases contains duplicate database %q", database.Name)
		}
		databases[database.Name] = struct{}{}
		if err := validatePostgresName(fmt.Sprintf("database.databases[%d].owner", index), database.Owner); err != nil {
			return err
		}
		if _, exists := roles[database.Owner]; !exists {
			return fmt.Errorf("database.databases[%q].owner %q is not declared in database.roles", database.Name, database.Owner)
		}
		// The application's own database is created once, owned by the role
		// derived from the application name. Nothing reassigns it afterwards, so
		// a declaration naming another owner would describe a state the host
		// never reaches.
		if database.Name == derived && database.Owner != derived {
			return fmt.Errorf("database.databases[%q].owner must be %q: the database Shuttle provisions for this application is owned by its own role", database.Name, derived)
		}
		if len(database.Schemas) > maxDatabaseObjects {
			return fmt.Errorf("database.databases[%q].schemas is limited to %d entries", database.Name, maxDatabaseObjects)
		}
		schemas := make(map[string]struct{}, len(database.Schemas))
		for schemaIndex, schema := range database.Schemas {
			if err := validatePostgresName(fmt.Sprintf("database.databases[%q].schemas[%d]", database.Name, schemaIndex), schema); err != nil {
				return err
			}
			if _, exists := schemas[schema]; exists {
				return fmt.Errorf("database.databases[%q].schemas contains duplicate schema %q", database.Name, schema)
			}
			schemas[schema] = struct{}{}
		}
	}
	return nil
}
