package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// serviceWithLabel finds the single service carrying a Shuttle deploy label.
//
// The root helper never reads config.json: it only ever sees the signed stack
// payload. Rather than teach the signed protocol a service name — one more
// field to validate, and one more way for the two sides to disagree — the
// helper reads the labels the stack already carries. The stack is what was
// signed, so the name it declares is the name that was approved.
//
// More than one match is an error, not a coin flip: Go randomises map
// iteration, so picking "the first" would route traffic to a different service
// on different runs.
func serviceWithLabel(document map[string]any, label string) (string, map[string]any, error) {
	services, _ := document["services"].(map[string]any)
	var foundName string
	var foundLabels map[string]any
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		deploy, _ := service["deploy"].(map[string]any)
		labels, _ := deploy["labels"].(map[string]any)
		if _, present := labels[label]; !present {
			continue
		}
		if foundName != "" {
			return "", nil, fmt.Errorf("stack declares label %s on more than one service (%s, %s)", label, foundName, name)
		}
		foundName, foundLabels = name, labels
	}
	if foundName == "" {
		return "", nil, nil
	}
	return foundName, foundLabels, nil
}

// managedDatabaseLabel carries the roles and databases an application declared,
// on the same service that carries dev.shuttle.postgres.
//
// It travels as a label because the root helper has no access to config.json:
// the signed stack is the only thing it trusts, so the list of objects it is
// asked to create has to be part of what was signed. It is re-validated on
// arrival by parseManagedDatabasePlan, which is the only reader.
const managedDatabaseLabel = "dev.shuttle.databases"

// managedPostgresLabel marks the service that gets the managed database.
const managedPostgresLabel = "dev.shuttle.postgres"

// managedDatabaseHostVariable is the single environment variable the helper
// injects into that service. The address is the Docker gateway allocated on the
// host, so it cannot be known when config.json is written; the URL built from
// it belongs to the application, not to Shuttle.
const managedDatabaseHostVariable = "POSTGRES_HOST"

// managedDatabasePasswordTarget is the mount name of the managed database
// password. A per-role password is this name plus the role, so the prefix is
// what identifies a service that talks to the managed database.
const managedDatabasePasswordTarget = "POSTGRES_PASSWORD"

type managedDatabasePlan struct {
	Roles     []managedDatabaseRole `json:"roles,omitempty"`
	Databases []managedDatabase     `json:"databases,omitempty"`
}

type managedDatabaseRole struct {
	Name string `json:"name"`
}

type managedDatabase struct {
	Name    string   `json:"name"`
	Owner   string   `json:"owner"`
	Schemas []string `json:"schemas,omitempty"`
}

func (p managedDatabasePlan) empty() bool { return len(p.Roles) == 0 && len(p.Databases) == 0 }

// managedDatabaseIdentifier is the only spelling accepted for a name that ends
// up inside CREATE ROLE, createdb or CREATE SCHEMA. A value that would need
// quoting, trimming or escaping is refused, never cleaned: the string that is
// checked here is the string that is emitted.
var managedDatabaseIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// maxManagedDatabaseObjects bounds each declared list. A stack asking for more
// than this is not a configuration mistake worth guessing at.
const maxManagedDatabaseObjects = 16

// reservedManagedDatabaseNames are names PostgreSQL owns. Creating them fails
// on the host and dropping them would take the cluster with it, so they are
// refused at both ends instead.
var reservedManagedDatabaseNames = map[string]bool{
	"postgres":           true,
	"template0":          true,
	"template1":          true,
	"information_schema": true,
	"public":             true,
}

func validManagedDatabaseName(name string) error {
	if !managedDatabaseIdentifier.MatchString(name) {
		return fmt.Errorf("%q is not a lowercase PostgreSQL identifier", name)
	}
	if strings.HasPrefix(name, "pg_") {
		return fmt.Errorf("%q uses the pg_ prefix PostgreSQL reserves", name)
	}
	if reservedManagedDatabaseNames[name] {
		return fmt.Errorf("%q is a reserved PostgreSQL name", name)
	}
	return nil
}

// maxDockerSecretName is the longest name Docker accepts for a secret.
const maxDockerSecretName = 64

// managedRoleSecretName is the Docker Secret holding one role's password. It is
// derived from the application and the role, never supplied: the operator names
// the role, Shuttle names the credential.
func managedRoleSecretName(app, role string) string {
	return app + "_db_" + role + "_password_v1"
}

// checkedManagedRoleSecretName refuses a name Docker would not accept, at the
// point where the name is emitted into the stack. A stack referencing an
// external secret that can never be created deploys a service that never starts.
func checkedManagedRoleSecretName(app, role string) (string, error) {
	name := managedRoleSecretName(app, role)
	if len(name) > maxDockerSecretName {
		return "", fmt.Errorf("database role %q makes the derived secret name %q %d characters long, above the %d Docker allows", role, name, len(name), maxDockerSecretName)
	}
	return name, nil
}

// managedRoleSecretTarget is where that password is mounted inside the
// container, next to the /run/secrets/POSTGRES_PASSWORD the single-database
// path already provides.
func managedRoleSecretTarget(role string) string {
	return config.ManagedRoleSecretTarget(role)
}

// managedRoleSecretFile is the root-only file on the host that keeps the
// generated password across deploys.
func managedRoleSecretFile(role string) string { return "db-" + role + ".password" }

// managedDatabasePlanFromConfig carries the declared list from config.json to
// the label, unchanged. The order is the operator's, not a map's.
func managedDatabasePlanFromConfig(database config.DatabaseConfig) managedDatabasePlan {
	plan := managedDatabasePlan{}
	for _, role := range database.Roles {
		plan.Roles = append(plan.Roles, managedDatabaseRole{Name: role.Name})
	}
	for _, entry := range database.Databases {
		plan.Databases = append(plan.Databases, managedDatabase{Name: entry.Name, Owner: entry.Owner, Schemas: append([]string(nil), entry.Schemas...)})
	}
	return plan
}

// parseManagedDatabasePlan re-validates, inside the signed operation, the list
// the CLI already validated. The helper is a trust boundary, not a second
// opinion: everything below is checked again, and anything ambiguous — a
// duplicate, an owner that is not declared, a name that would need quoting — is
// refused rather than repaired.
func parseManagedDatabasePlan(raw string) (managedDatabasePlan, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "<nil>" {
		return managedDatabasePlan{}, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var plan managedDatabasePlan
	if err := decoder.Decode(&plan); err != nil {
		return managedDatabasePlan{}, errors.New("managed database list is not valid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return managedDatabasePlan{}, errors.New("managed database list must contain exactly one JSON document")
	}
	if len(plan.Roles) == 0 || len(plan.Roles) > maxManagedDatabaseObjects {
		return managedDatabasePlan{}, fmt.Errorf("managed database list must declare between 1 and %d roles", maxManagedDatabaseObjects)
	}
	if len(plan.Databases) > maxManagedDatabaseObjects {
		return managedDatabasePlan{}, fmt.Errorf("managed database list must declare at most %d databases", maxManagedDatabaseObjects)
	}
	roles := map[string]bool{}
	for _, role := range plan.Roles {
		if err := validManagedDatabaseName(role.Name); err != nil {
			return managedDatabasePlan{}, fmt.Errorf("managed database role %w", err)
		}
		if roles[role.Name] {
			return managedDatabasePlan{}, fmt.Errorf("managed database role %q is declared twice", role.Name)
		}
		roles[role.Name] = true
	}
	databases := map[string]bool{}
	for _, database := range plan.Databases {
		if err := validManagedDatabaseName(database.Name); err != nil {
			return managedDatabasePlan{}, fmt.Errorf("managed database %w", err)
		}
		if databases[database.Name] {
			return managedDatabasePlan{}, fmt.Errorf("managed database %q is declared twice", database.Name)
		}
		databases[database.Name] = true
		if err := validManagedDatabaseName(database.Owner); err != nil {
			return managedDatabasePlan{}, fmt.Errorf("managed database owner %w", err)
		}
		if !roles[database.Owner] {
			return managedDatabasePlan{}, fmt.Errorf("managed database %q names owner %q, which is not a declared role", database.Name, database.Owner)
		}
		if len(database.Schemas) > maxManagedDatabaseObjects {
			return managedDatabasePlan{}, fmt.Errorf("managed database %q must declare at most %d schemas", database.Name, maxManagedDatabaseObjects)
		}
		schemas := map[string]bool{}
		for _, schema := range database.Schemas {
			if err := validManagedDatabaseName(schema); err != nil {
				return managedDatabasePlan{}, fmt.Errorf("managed database schema %w", err)
			}
			if schemas[schema] {
				return managedDatabasePlan{}, fmt.Errorf("managed database %q declares schema %q twice", database.Name, schema)
			}
			schemas[schema] = true
		}
	}
	return plan, nil
}

// encodeManagedDatabasePlan renders the label. The order is the order the
// operator wrote, and it round-trips through parseManagedDatabasePlan, so the
// same configuration always produces the same signed stack.
func encodeManagedDatabasePlan(plan managedDatabasePlan) (string, error) {
	body, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	encoded := string(body)
	if _, err := parseManagedDatabasePlan(encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

// managedDatabaseLabelFromStack reads the declared list off the service that
// carries dev.shuttle.postgres, which is the service the stack itself points
// at — not a service name the caller claims.
func managedDatabaseLabelFromStack(document map[string]any) (managedDatabasePlan, error) {
	managedService, managedLabels, err := serviceWithLabel(document, managedPostgresLabel)
	if err != nil {
		return managedDatabasePlan{}, err
	}
	declaredService, declaredLabels, err := serviceWithLabel(document, managedDatabaseLabel)
	if err != nil {
		return managedDatabasePlan{}, err
	}
	if declaredService == "" {
		return managedDatabasePlan{}, nil
	}
	// A declared list anywhere but on the service that gets the managed database
	// would be read by nobody and provision nothing: exactly the silence this
	// change exists to end.
	if managedService == "" || strings.TrimSpace(fmt.Sprint(managedLabels[managedPostgresLabel])) != "true" || declaredService != managedService {
		return managedDatabasePlan{}, errors.New("managed database list is declared without a managed database on the same service")
	}
	return parseManagedDatabasePlan(fmt.Sprint(declaredLabels[managedDatabaseLabel]))
}

// postgresLedger records the PostgreSQL objects one application actually
// created on this host.
//
// It exists so removal can drop what this application made and nothing else. A
// database another application uses is not this application's to delete, and
// "the name derived from the app" was never a proof of ownership.
type postgresLedger struct {
	Version   int      `json:"version"`
	Roles     []string `json:"roles,omitempty"`
	Databases []string `json:"databases,omitempty"`
}

const postgresLedgerVersion = 1

func (l postgresLedger) hasRole(name string) bool {
	for _, role := range l.Roles {
		if role == name {
			return true
		}
	}
	return false
}

func (l postgresLedger) hasDatabase(name string) bool {
	for _, database := range l.Databases {
		if database == name {
			return true
		}
	}
	return false
}

func decodePostgresLedger(body []byte) (postgresLedger, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var ledger postgresLedger
	if err := decoder.Decode(&ledger); err != nil {
		return postgresLedger{}, errors.New("postgres ownership ledger is not valid JSON")
	}
	if ledger.Version != postgresLedgerVersion {
		return postgresLedger{}, fmt.Errorf("unsupported postgres ownership ledger version %d", ledger.Version)
	}
	for _, name := range append(append([]string{}, ledger.Roles...), ledger.Databases...) {
		if err := validManagedDatabaseName(name); err != nil {
			return postgresLedger{}, fmt.Errorf("postgres ownership ledger names %w", err)
		}
	}
	return ledger, nil
}

func encodePostgresLedger(ledger postgresLedger) ([]byte, error) {
	ledger.Version = postgresLedgerVersion
	body, err := json.Marshal(ledger)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}
