//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// shuttleOwnerLabel marks the Docker objects one application owns, so removal
// can find the ones whose names it cannot enumerate.
const shuttleOwnerLabel = "dev.shuttle.owner"

// rootSecretRoot holds the generated credentials of every application on this
// host, one directory per application, readable by root alone.
const rootSecretRoot = "/var/lib/shuttle/secrets"

// rootPostgresIdentifier is the helper's own spelling rule for the identifier
// derived from the application name. Declared roles and databases go through
// managedDatabaseIdentifier instead, which also accepts a leading underscore.
var rootPostgresIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// postgresLedgerPath is where one application records the PostgreSQL objects it
// created. It lives beside the signed stacks, under the same root-only tree.
func postgresLedgerPath(stateRoot, app string) string {
	return filepath.Join(stateRoot, app, "postgres.json")
}

func readPostgresLedger(stateRoot, app string) (postgresLedger, error) {
	body, err := os.ReadFile(postgresLedgerPath(stateRoot, app))
	if os.IsNotExist(err) {
		return postgresLedger{Version: postgresLedgerVersion}, nil
	}
	if err != nil {
		return postgresLedger{}, err
	}
	return decodePostgresLedger(body)
}

func writePostgresLedger(stateRoot, app string, ledger postgresLedger) error {
	if err := os.MkdirAll(filepath.Join(stateRoot, app), 0o700); err != nil {
		return err
	}
	body, err := encodePostgresLedger(ledger)
	if err != nil {
		return err
	}
	return writeRootFile(postgresLedgerPath(stateRoot, app), body, 0o600)
}

// postgresLedgerOwners reports which application created each PostgreSQL object
// on this host.
//
// It is the answer to the one question the previous code never asked before
// running dropdb: whose database is this? Two applications claiming the same
// object is refused rather than resolved, because there is no correct way to
// pick, and the wrong pick deletes production data.
func postgresLedgerOwners(stateRoot string) (map[string]string, map[string]string, error) {
	roles := map[string]string{}
	databases := map[string]string{}
	entries, err := os.ReadDir(stateRoot)
	if os.IsNotExist(err) {
		return roles, databases, nil
	}
	if err != nil {
		return nil, nil, err
	}
	// os.ReadDir sorts by filename, so a conflict is always reported with the
	// same pair of names in the same order.
	for _, entry := range entries {
		if !entry.IsDir() || !rootAppName.MatchString(entry.Name()) {
			continue
		}
		app := entry.Name()
		ledger, err := readPostgresLedger(stateRoot, app)
		if err != nil {
			return nil, nil, fmt.Errorf("read the postgres ownership ledger of %s: %w", app, err)
		}
		for _, role := range ledger.Roles {
			if owner, claimed := roles[role]; claimed && owner != app {
				return nil, nil, fmt.Errorf("PostgreSQL role %q is claimed by both %s and %s", role, owner, app)
			}
			roles[role] = app
		}
		for _, database := range ledger.Databases {
			if owner, claimed := databases[database]; claimed && owner != app {
				return nil, nil, fmt.Errorf("PostgreSQL database %q is claimed by both %s and %s", database, owner, app)
			}
			databases[database] = app
		}
	}
	return roles, databases, nil
}

// ensurePostgresPassword returns the credential kept for this application under
// its root-only secret directory, generating it on first use. The file name is
// derived by the caller; it is never taken from the stack.
func ensurePostgresPassword(app, file string) (string, error) {
	dir := filepath.Join(rootSecretRoot, app)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, file)
	secret, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		secret = []byte(base64.RawURLEncoding.EncodeToString(random))
		if err := writeRootFile(path, append(secret, '\n'), 0o600); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(secret)), nil
}

func postgresRoleExists(identifier string) (bool, error) {
	body, err := exec.Command("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-Atqc", "SELECT 1 FROM pg_roles WHERE rolname='"+identifier+"'").Output()
	if err != nil {
		return false, errors.New("inspect PostgreSQL role")
	}
	return strings.TrimSpace(string(body)) == "1", nil
}

func postgresDatabaseExists(identifier string) (bool, error) {
	body, err := exec.Command("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-Atqc", "SELECT 1 FROM pg_database WHERE datname='"+identifier+"'").Output()
	if err != nil {
		return false, errors.New("inspect PostgreSQL database")
	}
	return strings.TrimSpace(string(body)) == "1", nil
}

// These probes are shared by managed provisioning and removal. Keeping the
// existence checks injectable lets both decisions be tested without invoking
// runuser or psql.
var (
	removalPostgresInstalled = func() bool {
		_, err := os.Stat("/usr/bin/pg_lsclusters")
		return err == nil
	}
	removalDatabaseExists = postgresDatabaseExists
	removalRoleExists     = postgresRoleExists
)

// runPostgresPasswordStatement executes a statement that carries a credential.
// Its output is deliberately dropped: psql echoes the failing statement, and a
// password in an error message is a password in the deploy log.
func runPostgresPasswordStatement(action, identifier, statement string) error {
	command := exec.Command("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-v", "ON_ERROR_STOP=1", "-c", statement)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if _, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s PostgreSQL role %s failed", action, identifier)
	}
	return nil
}

// ensurePostgresRole creates the role or resets its password to the one Shuttle
// holds. Replayed on every deploy, so both branches have to be safe to repeat.
func ensurePostgresRole(identifier, password string, exists bool) error {
	if !exists {
		return runPostgresPasswordStatement("create", identifier, "CREATE ROLE "+identifier+" LOGIN PASSWORD '"+password+"'")
	}
	return runPostgresPasswordStatement("alter", identifier, "ALTER ROLE "+identifier+" PASSWORD '"+password+"'")
}

// ensurePostgresDockerSecret publishes a generated credential as a Docker
// Secret. The name is derived by the caller and versioned, so an existing
// secret already holds the value this deploy would write.
func ensurePostgresDockerSecret(name, password, label string) error {
	if exec.Command("/usr/bin/docker", "secret", "inspect", name).Run() == nil {
		return nil
	}
	arguments := []string{"secret", "create"}
	if label != "" {
		arguments = append(arguments, "--label", label)
	}
	command := exec.Command("/usr/bin/docker", append(arguments, name, "-")...)
	command.Stdin = bytes.NewReader([]byte(password))
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("create PostgreSQL Docker Secret: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// ensureNativePostgres provisions the managed database for the service the
// signed stack marks with dev.shuttle.postgres.
//
// The identifier derived from the application name is created when missing and
// changed only when this application's ledger records it. Existing unrecorded
// objects are never adopted, because the old derived name also matched objects
// created outside Shuttle. Additional declared roles and databases follow the
// same ownership rule and are recorded before creation.
func ensureNativePostgres(app string, payload []byte) error {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return err
	}
	// Read off the stack, and refused when a declared list has no managed
	// database to be created in: a declaration that provisions nothing and says
	// nothing is the trap this change exists to close.
	declared, err := managedDatabaseLabelFromStack(document)
	if err != nil {
		return err
	}
	name, labels, err := serviceWithLabel(document, managedPostgresLabel)
	if err != nil {
		return err
	}
	if name == "" || fmt.Sprint(labels[managedPostgresLabel]) != "true" {
		return nil
	}
	identifier := strings.ReplaceAll(app, "-", "_")
	if !rootPostgresIdentifier.MatchString(identifier) {
		return errors.New("derived PostgreSQL identifier is invalid")
	}
	roleOwners, databaseOwners, err := postgresLedgerOwners(rootAppStateRoot)
	if err != nil {
		return err
	}
	ledger, err := readPostgresLedger(rootAppStateRoot, app)
	if err != nil {
		return err
	}
	record := func(updated postgresLedger) error {
		ledger = updated
		return writePostgresLedger(rootAppStateRoot, app, ledger)
	}

	// Check both derived objects before writing the password, changing PostgreSQL,
	// or recording ownership. A role password file cannot prove that Shuttle
	// created the role: an earlier deploy could have written it after taking over
	// an unrelated role with the same derived name.
	if owner, claimed := roleOwners[identifier]; claimed && owner != app {
		return fmt.Errorf("PostgreSQL role %q belongs to application %s", identifier, owner)
	}
	if owner, claimed := databaseOwners[identifier]; claimed && owner != app {
		return fmt.Errorf("PostgreSQL database %q belongs to application %s", identifier, owner)
	}
	provisionLedger := postgresProvisionLedger(ledger, identifier)
	decideProvision := func(roleExists, databaseExists bool, probeErr error) error {
		return postgresProvisionDecisionError(app, identifier, provisionLedger, roleExists, databaseExists, probeErr)
	}
	roleExists, err := removalRoleExists(identifier)
	if err != nil {
		return decideProvision(false, false, err)
	}
	databaseExists, err := removalDatabaseExists(identifier)
	if err != nil {
		return decideProvision(roleExists, false, err)
	}
	if err := decideProvision(roleExists, databaseExists, nil); err != nil {
		return err
	}
	password, err := ensurePostgresPassword(app, "postgres.password")
	if err != nil {
		return err
	}
	if !roleExists && !ledger.hasRole(identifier) {
		if err := record(postgresLedger{Roles: append(ledger.Roles, identifier), Databases: ledger.Databases}); err != nil {
			return err
		}
	}
	if err := ensurePostgresRole(identifier, password, roleExists); err != nil {
		return err
	}
	if !databaseExists {
		if !ledger.hasDatabase(identifier) {
			if err := record(postgresLedger{Roles: ledger.Roles, Databases: append(ledger.Databases, identifier)}); err != nil {
				return err
			}
		}
		if err := runFixed("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/createdb", "--owner", identifier, identifier); err != nil {
			return err
		}
	}
	if err := ensurePostgresDockerSecret(app+"_postgres_password_v1", password, ""); err != nil {
		return err
	}

	for _, role := range declared.Roles {
		if role.Name == identifier {
			continue
		}
		if owner, claimed := roleOwners[role.Name]; claimed && owner != app {
			return fmt.Errorf("PostgreSQL role %q belongs to application %s", role.Name, owner)
		}
		exists, err := postgresRoleExists(role.Name)
		if err != nil {
			return err
		}
		if exists && !ledger.hasRole(role.Name) {
			return fmt.Errorf("PostgreSQL role %q already exists and was not created by Shuttle for %s", role.Name, app)
		}
		if !ledger.hasRole(role.Name) {
			// Recorded before it is created: a ledger that claims an object which
			// does not exist yet costs one no-op drop, while an object that
			// exists and is claimed by nobody can never be cleaned up.
			if err := record(postgresLedger{Roles: append(ledger.Roles, role.Name), Databases: ledger.Databases}); err != nil {
				return err
			}
		}
		rolePassword, err := ensurePostgresPassword(app, managedRoleSecretFile(role.Name))
		if err != nil {
			return err
		}
		if err := ensurePostgresRole(role.Name, rolePassword, exists); err != nil {
			return err
		}
		if err := ensurePostgresDockerSecret(managedRoleSecretName(app, role.Name), rolePassword, shuttleOwnerLabel+"="+app); err != nil {
			return err
		}
	}

	for _, database := range declared.Databases {
		if database.Name != identifier {
			if owner, claimed := databaseOwners[database.Name]; claimed && owner != app {
				return fmt.Errorf("PostgreSQL database %q belongs to application %s", database.Name, owner)
			}
			exists, err := postgresDatabaseExists(database.Name)
			if err != nil {
				return err
			}
			if exists && !ledger.hasDatabase(database.Name) {
				return fmt.Errorf("PostgreSQL database %q already exists and was not created by Shuttle for %s", database.Name, app)
			}
			if !ledger.hasDatabase(database.Name) {
				if err := record(postgresLedger{Roles: ledger.Roles, Databases: append(ledger.Databases, database.Name)}); err != nil {
					return err
				}
			}
			if !exists {
				if err := runFixed("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/createdb", "--owner", database.Owner, database.Name); err != nil {
					return err
				}
			}
		}
		for _, schema := range database.Schemas {
			if err := runFixed("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-v", "ON_ERROR_STOP=1", "-d", database.Name, "-c", "CREATE SCHEMA IF NOT EXISTS "+schema+" AUTHORIZATION "+database.Owner); err != nil {
				return err
			}
		}
	}
	return nil
}

// preflightManagedPostgresOwnership checks whether the stack's derived
// PostgreSQL objects may be provisioned. It only reads ownership state and
// uses the same injectable existence probes as provisioning.
func preflightManagedPostgresOwnership(app string, payload []byte) error {
	return preflightManagedPostgresOwnershipAt(rootAppStateRoot, app, payload)
}

func preflightManagedPostgresOwnershipAt(stateRoot, app string, payload []byte) error {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return err
	}
	if _, err := managedDatabaseLabelFromStack(document); err != nil {
		return err
	}
	name, labels, err := serviceWithLabel(document, managedPostgresLabel)
	if err != nil {
		return err
	}
	if name == "" || fmt.Sprint(labels[managedPostgresLabel]) != "true" {
		return nil
	}
	identifier := strings.ReplaceAll(app, "-", "_")
	if !rootPostgresIdentifier.MatchString(identifier) {
		return errors.New("derived PostgreSQL identifier is invalid")
	}
	roleOwners, databaseOwners, err := postgresLedgerOwners(stateRoot)
	if err != nil {
		return err
	}
	if owner, claimed := roleOwners[identifier]; claimed && owner != app {
		return fmt.Errorf("PostgreSQL role %q belongs to application %s", identifier, owner)
	}
	if owner, claimed := databaseOwners[identifier]; claimed && owner != app {
		return fmt.Errorf("PostgreSQL database %q belongs to application %s", identifier, owner)
	}
	ledger, err := readPostgresLedger(stateRoot, app)
	if err != nil {
		return err
	}
	provisionLedger := postgresProvisionLedger(ledger, identifier)
	roleExists, err := removalRoleExists(identifier)
	if err != nil {
		return postgresProvisionDecisionError(app, identifier, provisionLedger, false, false, err)
	}
	databaseExists, err := removalDatabaseExists(identifier)
	if err != nil {
		return postgresProvisionDecisionError(app, identifier, provisionLedger, roleExists, false, err)
	}
	return postgresProvisionDecisionError(app, identifier, provisionLedger, roleExists, databaseExists, nil)
}

func postgresProvisionLedger(ledger postgresLedger, identifier string) postgresLedger {
	provisionLedger := postgresLedger{}
	if ledger.hasRole(identifier) {
		provisionLedger.Roles = []string{identifier}
	}
	if ledger.hasDatabase(identifier) {
		provisionLedger.Databases = []string{identifier}
	}
	return provisionLedger
}

func postgresOwnershipPreflight(ledger postgresLedger, roleExists, databaseExists bool, probeErr error) error {
	return postgresProvisionDecision(ledger, roleExists, databaseExists, probeErr)
}

func postgresProvisionDecisionError(app, identifier string, ledger postgresLedger, roleExists, databaseExists bool, probeErr error) error {
	err := postgresOwnershipPreflight(ledger, roleExists, databaseExists, probeErr)
	var refusal *postgresProvisionRefusal
	if errors.As(err, &refusal) {
		return errors.New(postgresProvisionRefusalMessage(app, identifier, refusal.kind))
	}
	return err
}

// keptPostgresObject is an existing derived object that the ledger does not
// authorize Shuttle to remove.
type keptPostgresObject struct {
	Kind   string
	Name   string
	Reason string
}

// postgresRemoval is what removing an application is allowed to drop.
type postgresRemoval struct {
	Databases []string
	Roles     []string
	Secrets   []string
	Kept      []keptPostgresObject
}

// planPostgresRemoval decides what to drop for an application being removed.
//
// The ledger is the only proof that permits a drop. An unrecorded derived name
// is probed and reported when present, because legacy Shuttle ownership cannot
// be distinguished from an unrelated production database or role.
func planPostgresRemoval(stateRoot, app string) (postgresRemoval, error) {
	return planPostgresRemovalWithProbes(stateRoot, app, removalPostgresInstalled(), removalRoleExists, removalDatabaseExists)
}

func planPostgresRemovalWithContext(ctx context.Context, stateRoot, app string) (postgresRemoval, error) {
	roleExists := func(identifier string) (bool, error) {
		return postgresObjectExistsContext(ctx, "SELECT 1 FROM pg_roles WHERE rolname='"+identifier+"'", "inspect PostgreSQL role")
	}
	databaseExists := func(identifier string) (bool, error) {
		return postgresObjectExistsContext(ctx, "SELECT 1 FROM pg_database WHERE datname='"+identifier+"'", "inspect PostgreSQL database")
	}
	return planPostgresRemovalWithProbes(stateRoot, app, removalPostgresInstalled(), roleExists, databaseExists)
}

func postgresObjectExistsContext(ctx context.Context, query, description string) (bool, error) {
	body, err := runRootSubprocessOutput(ctx, "/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-Atqc", query)
	if ctx.Err() != nil {
		return false, fmt.Errorf("%s timed out: %w", description, ctx.Err())
	}
	if err != nil {
		return false, errors.New(description)
	}
	return strings.TrimSpace(string(body)) == "1", nil
}

const rootSubprocessWaitDelay = 2 * time.Second

func runRootSubprocess(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return runRootProcessGroup(command, rootSubprocessWaitDelay)
}

func runRootSubprocessOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return runRootProcessGroupOutput(command, rootSubprocessWaitDelay)
}

// The 30-10-2026 demo-prod incident showed that killing runuser alone can
// leave dropdb or psql children alive with inherited output pipes. Keep each
// command in its own process group and bound the pipe-drain wait after cancel.
func runRootProcessGroup(command *exec.Cmd, waitDelay time.Duration) ([]byte, error) {
	prepareRootProcessGroup(command, waitDelay)
	return command.CombinedOutput()
}

func runRootProcessGroupOutput(command *exec.Cmd, waitDelay time.Duration) ([]byte, error) {
	prepareRootProcessGroup(command, waitDelay)
	body, err := command.Output()
	// Docker reports missing objects on stderr. Dropping that diagnostic made
	// destroy --dry-run fail for optional volumes and secrets never created.
	// Keep successful stdout clean for parsers, and preserve the exit status.
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(exit.Stderr) > 0 {
		return body, fmt.Errorf("%w: %s", err, bytes.TrimSpace(exit.Stderr))
	}
	return body, err
}

func prepareRootProcessGroup(command *exec.Cmd, waitDelay time.Duration) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = waitDelay
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func postgresObjectOIDContext(ctx context.Context, kind, name string) (string, bool, error) {
	if err := validManagedDatabaseName(name); err != nil {
		return "", false, err
	}
	var query string
	switch kind {
	case "database":
		query = "SELECT oid::text FROM pg_database WHERE datname='" + name + "'"
	case "role":
		query = "SELECT oid::text FROM pg_roles WHERE rolname='" + name + "'"
	default:
		return "", false, fmt.Errorf("unknown PostgreSQL object kind %q", kind)
	}
	body, err := runRootSubprocessOutput(ctx, "/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-Atqc", query)
	if ctx.Err() != nil {
		return "", false, fmt.Errorf("inspect PostgreSQL %s OID timed out: %w", kind, ctx.Err())
	}
	if err != nil {
		return "", false, fmt.Errorf("inspect PostgreSQL %s OID: %w", kind, err)
	}
	oid := strings.TrimSpace(string(body))
	if oid == "" {
		return "", false, nil
	}
	parsed, err := strconv.ParseUint(oid, 10, 32)
	if err != nil || parsed == 0 {
		return "", false, fmt.Errorf("inspect PostgreSQL %s OID returned an invalid identity", kind)
	}
	return strconv.FormatUint(parsed, 10), true, nil
}

func planPostgresRemovalWithProbes(stateRoot, app string, postgresInstalled bool, roleExists, databaseExists func(string) (bool, error)) (postgresRemoval, error) {
	identifier := strings.ReplaceAll(app, "-", "_")
	if !rootPostgresIdentifier.MatchString(identifier) {
		return postgresRemoval{}, errors.New("derived PostgreSQL identifier is invalid")
	}
	ledger, err := readPostgresLedger(stateRoot, app)
	if err != nil {
		return postgresRemoval{}, err
	}
	roleOwners, databaseOwners, err := postgresLedgerOwners(stateRoot)
	if err != nil {
		return postgresRemoval{}, err
	}
	removal := postgresRemoval{}
	seenDatabases := map[string]bool{}
	for _, database := range ledger.Databases {
		if seenDatabases[database] {
			continue
		}
		seenDatabases[database] = true
		if owner, claimed := databaseOwners[database]; claimed && owner != app {
			continue
		}
		removal.Databases = append(removal.Databases, database)
	}
	seenRoles := map[string]bool{}
	for _, role := range ledger.Roles {
		if seenRoles[role] {
			continue
		}
		seenRoles[role] = true
		if owner, claimed := roleOwners[role]; claimed && owner != app {
			continue
		}
		removal.Roles = append(removal.Roles, role)
		if role != identifier {
			removal.Secrets = append(removal.Secrets, managedRoleSecretName(app, role))
		}
	}
	// A derived name is never treated as ownership evidence. Probe it only when
	// neither this app nor another app's ledger already settles ownership.
	if postgresInstalled {
		if !ledger.hasDatabase(identifier) {
			if _, claimed := databaseOwners[identifier]; !claimed {
				exists, probeErr := databaseExists(identifier)
				if exists || probeErr != nil {
					removal.Kept = append(removal.Kept, keptPostgresObject{Kind: "database", Name: identifier, Reason: postgresRemovalProbeReason(app, probeErr)})
				}
			}
		}
		if !ledger.hasRole(identifier) {
			if _, claimed := roleOwners[identifier]; !claimed {
				exists, probeErr := roleExists(identifier)
				if exists || probeErr != nil {
					removal.Kept = append(removal.Kept, keptPostgresObject{Kind: "role", Name: identifier, Reason: postgresRemovalProbeReason(app, probeErr)})
				}
			}
		}
	}
	sort.Strings(removal.Databases)
	sort.Strings(removal.Roles)
	sort.Strings(removal.Secrets)
	sort.Slice(removal.Kept, func(i, j int) bool {
		if removal.Kept[i].Kind != removal.Kept[j].Kind {
			return removal.Kept[i].Kind < removal.Kept[j].Kind
		}
		return removal.Kept[i].Name < removal.Kept[j].Name
	})
	return removal, nil
}

func postgresRemovalProbeReason(app string, probeErr error) string {
	if probeErr != nil {
		return "existence check failed: " + probeErr.Error()
	}
	return "not recorded as created by Shuttle for " + app + "; drop it by hand if that is intended"
}

type postgresProvisionRefusal struct{ kind string }

func (e *postgresProvisionRefusal) Error() string {
	return "unrecorded existing PostgreSQL " + e.kind
}

// postgresProvisionDecision receives a ledger narrowed to the derived role and
// database. This keeps the decision independent of host commands and context.
func postgresProvisionDecision(ledger postgresLedger, roleExists, databaseExists bool, probeErr error) error {
	if probeErr != nil {
		return probeErr
	}
	if roleExists && len(ledger.Roles) == 0 {
		return &postgresProvisionRefusal{kind: "role"}
	}
	if databaseExists && len(ledger.Databases) == 0 {
		return &postgresProvisionRefusal{kind: "database"}
	}
	return nil
}

func postgresProvisionRefusalMessage(app, identifier, kind string) string {
	return fmt.Sprintf("PostgreSQL %s %s already exists and is not recorded as created by Shuttle for %s; refusing to change it. If Shuttle created it before ownership tracking, add it to /var/lib/shuttle/apps/%s/postgres.json as documented in docs/configuration.md; otherwise rename the app", kind, identifier, app, app)
}

// applyPostgresRemoval applies only the already planned drops and keeps failed
// drops in a ledger so a later destroy can retry them.
func applyPostgresRemoval(app string, removal postgresRemoval, drop func(kind, name string) error) (remainder postgresLedger, withheld []string, lines []string) {
	remainder.Version = postgresLedgerVersion
	keptDatabases := []string{}
	for _, object := range removal.Kept {
		if object.Kind == "database" {
			keptDatabases = append(keptDatabases, object.Name)
		}
	}
	sort.Strings(keptDatabases)
	for _, database := range removal.Databases {
		if err := drop("database", database); err != nil {
			remainder.Databases = append(remainder.Databases, database)
			lines = append(lines, fmt.Sprintf("kept PostgreSQL database %s: %v", database, err))
		}
	}
	for _, role := range removal.Roles {
		// DROP ROLE checks ownership, not every login dependency. A kept
		// database may still connect with this role even when it owns nothing.
		if len(keptDatabases) > 0 {
			withheld = append(withheld, role)
			lines = append(lines, fmt.Sprintf("kept PostgreSQL role %s: database(s) %s were kept; drop it by hand after those databases", role, strings.Join(keptDatabases, ", ")))
			continue
		}
		if len(remainder.Databases) > 0 {
			remainder.Roles = append(remainder.Roles, role)
			lines = append(lines, fmt.Sprintf("kept PostgreSQL role %s: database removal remains pending", role))
			continue
		}
		if err := drop("role", role); err != nil {
			remainder.Roles = append(remainder.Roles, role)
			lines = append(lines, fmt.Sprintf("kept PostgreSQL role %s: %v", role, err))
		}
	}
	for _, object := range removal.Kept {
		lines = append(lines, fmt.Sprintf("kept PostgreSQL %s %s: %s", object.Kind, object.Name, object.Reason))
	}
	sort.Strings(remainder.Databases)
	sort.Strings(remainder.Roles)
	sort.Strings(withheld)
	sort.Strings(lines)
	return remainder, withheld, lines
}

type postgresCredentialSelection struct {
	DockerSecrets []string
	Files         []string
}

// postgresCredentialsToKeep selects credentials by PostgreSQL ownership
// outcome, not by the stack file or by a possibly stale password file.
func postgresCredentialsToKeep(app string, removal postgresRemoval, withheld []string, remainder postgresLedger) postgresCredentialSelection {
	identifier := strings.ReplaceAll(app, "-", "_")
	knownRoles := map[string]bool{identifier: true}
	keptRoles := map[string]bool{}
	for _, role := range removal.Roles {
		knownRoles[role] = true
	}
	for _, object := range removal.Kept {
		if object.Kind == "role" {
			knownRoles[object.Name] = true
			keptRoles[object.Name] = true
		}
	}
	for _, role := range withheld {
		knownRoles[role] = true
		keptRoles[role] = true
	}
	for _, role := range remainder.Roles {
		knownRoles[role] = true
		keptRoles[role] = true
	}
	selection := postgresCredentialSelection{}
	for role := range knownRoles {
		if !keptRoles[role] {
			continue
		}
		if role == identifier {
			selection.DockerSecrets = append(selection.DockerSecrets, app+"_postgres_password_v1")
			selection.Files = append(selection.Files, "postgres.password")
		} else {
			selection.DockerSecrets = append(selection.DockerSecrets, managedRoleSecretName(app, role))
			selection.Files = append(selection.Files, managedRoleSecretFile(role))
		}
	}
	sort.Strings(selection.DockerSecrets)
	sort.Strings(selection.Files)
	return selection
}

// filterPostgresSecretsFromOwned keeps credentials out of the early generic
// secret cleanup. The final PostgreSQL step decides their fate after each drop.
func filterPostgresSecretsFromOwned(owned []string, app string, removal postgresRemoval) []string {
	protected := map[string]bool{app + "_postgres_password_v1": true}
	for _, role := range removal.Roles {
		protected[managedRoleSecretName(app, role)] = true
	}
	for _, object := range removal.Kept {
		if object.Kind == "role" && object.Name != strings.ReplaceAll(app, "-", "_") {
			protected[managedRoleSecretName(app, object.Name)] = true
		}
	}
	filtered := make([]string, 0, len(owned))
	for _, name := range owned {
		if !protected[name] {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

type postgresRemovalSteps struct {
	drop               func(kind, name string) error
	writeOrClearLedger func(postgresLedger) error
	removeState        func(hasRemainder bool) error
	removeCredentials  func(postgresRemoval, []string) error
	// settleWithheld records roles kept on purpose (their drop failed while a
	// kept database still needs them) before the ledger step judges completion.
	// Optional: callers without a destroy journal leave it nil.
	settleWithheld func([]string) error
}

func applyPostgresRemovalSteps(app string, removal postgresRemoval, steps postgresRemovalSteps) ([]string, error) {
	remainder, withheld, lines := applyPostgresRemoval(app, removal, steps.drop)
	if steps.settleWithheld != nil && len(withheld) > 0 {
		if err := steps.settleWithheld(withheld); err != nil {
			return lines, err
		}
	}
	hasRemainder := len(remainder.Databases) > 0 || len(remainder.Roles) > 0
	if err := steps.writeOrClearLedger(remainder); err != nil {
		return lines, err
	}
	if err := steps.removeState(hasRemainder); err != nil {
		return lines, err
	}
	if err := steps.removeCredentials(removal, withheld); err != nil {
		return lines, err
	}
	return lines, nil
}

func writeOrClearPostgresLedger(stateRoot, app string, remainder postgresLedger) error {
	if len(remainder.Databases) > 0 || len(remainder.Roles) > 0 {
		return writePostgresLedger(stateRoot, app, remainder)
	}
	if err := os.Remove(postgresLedgerPath(stateRoot, app)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// dockerGatewayAddress is the address the managed PostgreSQL listens on for
// containers: the gateway of docker_gwbridge, which setup binds listen_addresses
// and pg_hba to. Docker allocates it at install time, so only the host can
// answer this question.
func dockerGatewayAddress() (string, error) {
	command := exec.Command("/usr/bin/docker", "network", "inspect", "docker_gwbridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	body, err := command.Output()
	address := strings.TrimSpace(string(body))
	if err != nil || net.ParseIP(address) == nil {
		// Fail closed. An empty value would deploy an application that starts,
		// dials nothing and fails later, which is the silent mode this exists to
		// remove.
		return "", errors.New("cannot determine the docker_gwbridge gateway address; the managed database would be unreachable from the application")
	}
	return address, nil
}

// injectManagedDatabaseHost puts the database address in the environment of the
// service the signed stack marks with dev.shuttle.postgres, and of no other.
//
// It runs in the helper because the CLI cannot know this address, and it runs
// on the service the stack itself designates rather than on a name supplied
// alongside it. A stack with no managed database is returned untouched.
// servicesMountingDatabasePassword returns the services holding a credential for
// the managed database, by the name it is mounted under.
func servicesMountingDatabasePassword(services map[string]any) map[string]bool {
	holders := map[string]bool{}
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		list, _ := service["secrets"].([]any)
		for _, entry := range list {
			reference, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			target := strings.TrimSpace(fmt.Sprint(reference["target"]))
			if target == managedDatabasePasswordTarget || strings.HasPrefix(target, managedDatabasePasswordTarget+"_") {
				holders[name] = true
				break
			}
		}
	}
	return holders
}

func injectManagedDatabaseHost(payload []byte, gateway string) ([]byte, bool, error) {
	if net.ParseIP(strings.TrimSpace(gateway)) == nil || strings.TrimSpace(gateway) != gateway {
		return nil, false, errors.New("managed database address is not a bare IP address")
	}
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, false, err
	}
	name, labels, err := serviceWithLabel(document, managedPostgresLabel)
	if err != nil {
		return nil, false, err
	}
	if name == "" || fmt.Sprint(labels[managedPostgresLabel]) != "true" {
		return payload, false, nil
	}
	services, _ := document["services"].(map[string]any)
	if _, ok := services[name].(map[string]any); !ok {
		return nil, false, fmt.Errorf("service %s is invalid", name)
	}
	// Every service holding a database password, not the labelled one alone.
	//
	// The address went to the published service only, so a service that had
	// been given a password had no way to learn where to use it and fell back
	// to whatever hostname its image was built with, for example a Compose
	// service name that does not exist here:
	//
	//     psycopg.OperationalError: failed to resolve host 'agents-postgres'
	//
	// Derived from the payload rather than carried in the plan: a service that
	// mounts POSTGRES_PASSWORD, or one role's password, is by construction a
	// service that connects to the managed database.
	targets := servicesMountingDatabasePassword(services)
	targets[name] = true
	// Sorted, so the derived file is the same on every run.
	names := make([]string, 0, len(targets))
	for target := range targets {
		names = append(names, target)
	}
	sort.Strings(names)
	for _, target := range names {
		service, ok := services[target].(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("service %s is invalid", target)
		}
		service["environment"] = setStackEnvironment(service["environment"], managedDatabaseHostVariable, gateway)
	}
	encoded, err := yaml.Marshal(document)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

// stackDeclaresManagedDatabase reports whether the signed stack asks for the
// managed database at all. Nothing is resolved, written or injected for a stack
// that does not: it is deployed from the signed file itself.
func stackDeclaresManagedDatabase(payload []byte) (bool, error) {
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return false, err
	}
	name, labels, err := serviceWithLabel(document, managedPostgresLabel)
	if err != nil {
		return false, err
	}
	return name != "" && fmt.Sprint(labels[managedPostgresLabel]) == "true", nil
}

// stackFileWithManagedDatabaseHost returns the file `docker stack deploy` reads.
//
// For a stack without a managed database it is the signed file, unchanged. For
// one with a managed database it is a derived file carrying POSTGRES_HOST, kept
// beside the signed stacks and re-validated before it is deployed: the signed
// payload on disk stays exactly what was signed.
func stackFileWithManagedDatabaseHost(stateDir, signedFile string) (string, error) {
	body, err := os.ReadFile(signedFile)
	if err != nil {
		return "", err
	}
	declared, err := stackDeclaresManagedDatabase(body)
	if err != nil {
		return "", err
	}
	if !declared {
		return signedFile, nil
	}
	gateway, err := dockerGatewayAddress()
	if err != nil {
		return "", err
	}
	injected, changed, err := injectManagedDatabaseHost(body, gateway)
	if err != nil {
		return "", err
	}
	if !changed {
		return signedFile, nil
	}
	// Re-validated because it is what gets deployed. Validating the payload and
	// applying a different one is the gap every other check here exists to close.
	if err := validateRetainedRootStack(injected); err != nil {
		return "", fmt.Errorf("stack carrying the managed database address is not deployable: %w", err)
	}
	path := filepath.Join(stateDir, "effective.yml")
	if err := writeRootFile(path, injected, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// setStackEnvironment sets one variable in either Compose environment form,
// replacing whatever the stack declared: the address of the managed database is
// Shuttle's answer, not the application's guess.
func setStackEnvironment(existing any, key, value string) any {
	switch typed := existing.(type) {
	case map[string]any:
		typed[key] = value
		return typed
	case []any:
		result := make([]any, 0, len(typed)+1)
		for _, entry := range typed {
			text, ok := entry.(string)
			if ok && (text == key || strings.HasPrefix(text, key+"=")) {
				continue
			}
			result = append(result, entry)
		}
		return append(result, key+"="+value)
	default:
		return map[string]any{key: value}
	}
}

// Consent changes only the removal decision, never ownership. In the production
// incident, an ordinary app retirement also retired a database used elsewhere.
func postgresRemovalWithConsent(removal postgresRemoval, drop bool) postgresRemoval {
	if drop {
		return removal
	}
	for _, name := range removal.Databases {
		removal.Kept = append(removal.Kept, keptPostgresObject{Kind: "database", Name: name, Reason: "--drop-databases was not requested"})
	}
	for _, name := range removal.Roles {
		removal.Kept = append(removal.Kept, keptPostgresObject{Kind: "role", Name: name, Reason: "--drop-databases was not requested"})
	}
	removal.Databases, removal.Roles = nil, nil
	return removal
}

func reportDestroyPostgres(ctx context.Context, removal postgresRemoval, out io.Writer, size func(context.Context, string) (int64, error)) error {
	report := func(action, kind, name, reason string) error {
		measurement := "size=n/a"
		if kind == "database" {
			measurement = "size=unknown"
			if bytes, err := size(ctx, name); err == nil && bytes >= 0 {
				measurement = fmt.Sprintf("size=%d bytes", bytes)
			}
		}
		_, err := fmt.Fprintf(out, "%s PostgreSQL %s %s (%s): %s\n", action, kind, name, measurement, reason)
		return err
	}
	for _, name := range removal.Databases {
		if err := report("would drop", "database", name, "ledger-owned; dump required first"); err != nil {
			return err
		}
	}
	for _, name := range removal.Roles {
		if err := report("would drop", "role", name, "ledger-owned"); err != nil {
			return err
		}
	}
	for _, object := range removal.Kept {
		if err := report("kept", object.Kind, object.Name, object.Reason); err != nil {
			return err
		}
	}
	return nil
}

var destroyBackupRoot = "/var/backups/shuttle-postgres/pre-destroy"

// The fixed five-minute timeout repeatedly failed large final dumps after the
// app was already gone. Estimate the complete generation at 1 MiB/s plus thirty
// seconds for each archive's startup and verification. If it cannot fit before
// cleanup's watchdog reserve, keep the data instead of entering recovery again.
func destroyDumpBudget(ctx context.Context, databases []string, available time.Duration) (time.Duration, error) {
	budget := time.Second
	for _, name := range databases {
		size, err := preRunDatabaseSize(ctx, name)
		if err != nil {
			return 0, fmt.Errorf("read size for destroy dump budget of %s: %w", name, err)
		}
		if size < 0 {
			return 0, fmt.Errorf("invalid size for destroy dump budget of %s", name)
		}
		seconds := size / (1 << 20)
		if size%(1<<20) != 0 {
			seconds++
		}
		// Compare before duration conversion so a large size cannot overflow.
		if seconds > int64(rootOperationBudget/time.Second) {
			return 0, fmt.Errorf("destroy dump budget for %s cannot fit within %s before the phase watchdog; database kept", name, available)
		}
		budget += time.Duration(seconds)*time.Second + 30*time.Second
		if budget > available {
			return 0, fmt.Errorf("destroy dump budget for %s needs %s, only %s remains before the phase watchdog; database kept", name, budget, available)
		}
	}
	if budget > available {
		return 0, errors.New("destroy dump budget exhausted before the phase watchdog; databases kept")
	}
	return budget, nil
}

// Every archive is written through a root-owned descriptor by pg_dump running
// as postgres. No archive is overwritten or pruned: these may be the last copies
// of deliberately deleted data, unlike routine rolling pre-run backups.
func backupDestroyDatabasesAt(ctx context.Context, app string, databases []string, paths map[string]string, out io.Writer) error {
	if !rootAppName.MatchString(app) {
		return errors.New("invalid destroy backup application")
	}
	dir := filepath.Join(destroyBackupRoot, app)
	if err := refuseSymlinkAncestors(filepath.Dir(destroyBackupRoot)); err != nil {
		return err
	}
	if err := ensurePrivateBaselineDirectory(destroyBackupRoot, true); err != nil {
		return err
	}
	if err := ensurePrivateBaselineDirectory(dir, true); err != nil {
		return err
	}
	for _, name := range databases {
		if err := validManagedDatabaseName(name); err != nil {
			return err
		}
		exists, err := preRunDatabaseExists(ctx, name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := fmt.Fprintf(out, "backup skip db=%s: recorded but absent\n", name); err != nil {
				return err
			}
			continue
		}
		final := paths[name]
		if filepath.Dir(final) != dir || filepath.Base(final) == "." || !strings.HasSuffix(final, "-"+name+".dump") {
			return errors.New("invalid destroy archive path")
		}
		// Each pass uses a new generation. Refuse an occupied path rather than
		// reusing a snapshot taken before writes after an interrupted drop.
		if _, err := os.Lstat(final); err == nil {
			return fmt.Errorf("destroy archive %s already exists", final)
		} else if !os.IsNotExist(err) {
			return err
		}
		archive, err := os.CreateTemp(dir, ".destroy-*")
		if err != nil {
			return err
		}
		path := archive.Name()
		var stderr tailBuffer
		dump := preRunCommand(ctx, true, "pg_dump", "-Fc", "--no-password", "-d", name)
		dump.Stdout, dump.Stderr = archive, &stderr
		dumpErr := dump.Run()
		if dumpErr == nil {
			dumpErr = archive.Sync()
		}
		info, statErr := archive.Stat()
		closeErr := archive.Close()
		if err := errors.Join(dumpErr, statErr, closeErr); err != nil {
			_ = os.Remove(path)
			return fmt.Errorf("pg_dump failed for %s: %w: %s", name, err, cleanRootRefusalReason(stderr.String()))
		}
		if info.Size() == 0 {
			_ = os.Remove(path)
			return fmt.Errorf("pg_dump produced an empty archive for %s", name)
		}
		if err := verifyPreRunArchive(ctx, path, name, preRunDumpDeadline); err != nil {
			_ = os.Remove(path)
			return err
		}
		// Publish only a complete, synced, verified archive. A killed pg_dump
		// leaves a visibly temporary file, never an apparent final backup.
		if err := os.Rename(path, final); err != nil {
			_ = os.Remove(path)
			return err
		}
		if err := syncDirectory(dir); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "backup PostgreSQL database %s -> %s (%d bytes, verified)\n", name, final, info.Size()); err != nil {
			return err
		}
	}
	return nil
}

func destroyDatabaseBackupPaths(app, operationID string, databases []string) map[string]string {
	paths := make(map[string]string, len(databases))
	for _, name := range databases {
		paths[name] = filepath.Join(destroyBackupRoot, app, operationID+"-"+name+".dump")
	}
	return paths
}

// A durable drop intent may precede the actual drop. Recovery must capture
// writes made since that intent, even when the OID is unchanged. A fresh
// generation preserves the earlier snapshot; the drop still checks its OID.
func planDestroyBackupPaths(journal *destroyCleanupJournal) map[string]string {
	return destroyDatabaseBackupPaths(journal.App, fmt.Sprintf("%s-%d", journal.OperationID, journal.BackupGeneration+1), journal.PendingDatabases)
}
