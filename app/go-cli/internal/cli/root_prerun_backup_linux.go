//go:build linux

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"gopkg.in/yaml.v3"
)

const preRunBackupRetention = 5 // Keep five successful pre-run backup generations per application.

var (
	preRunBackupRoot    = "/var/backups/shuttle-postgres/pre-run"
	preRunDailyLockPath = "/var/backups/shuttle-postgres/.backup.lock"
	preRunNow           = time.Now
	preRunDumpTimeout   = func() time.Duration { return preRunDumpDeadline }
	preRunExecutable    = func(name string) string {
		switch name {
		case "psql":
			return "/usr/bin/psql"
		case "pg_dump":
			return "/usr/bin/pg_dump"
		case "pg_restore":
			return "/usr/bin/pg_restore"
		default:
			return ""
		}
	}
	preRunPostgresIdentity = func() (uid, gid int, home string, err error) {
		account, err := user.Lookup("postgres")
		if err != nil {
			return 0, 0, "", err
		}
		uid, err = strconv.Atoi(account.Uid)
		if err != nil {
			return 0, 0, "", err
		}
		gid, err = strconv.Atoi(account.Gid)
		return uid, gid, account.HomeDir, err
	}
	preRunCredentialEnabled  = func() bool { return true }
	preRunCommandPrefix      = func(string) []string { return nil }
	preRunCommandEnvironment = func() []string { return nil }
	preRunCommand            = defaultPreRunCommand
	preRunFilesystem         = func(dir string) (uint64, uint64, error) {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(dir, &stat); err != nil {
			return 0, 0, err
		}
		return stat.Bavail * uint64(stat.Bsize), stat.Blocks * uint64(stat.Bsize), nil
	}
	preRunDatabaseSize   = defaultPreRunDatabaseSize
	preRunDatabaseExists = defaultPreRunDatabaseExists
	preRunLedger         = func(app string) (postgresLedger, error) {
		return readPostgresLedger(rootAppStateRoot, app)
	}
	preRunOwners = func() (map[string]string, map[string]string, error) {
		return postgresLedgerOwners(rootAppStateRoot)
	}
	preRunStackDatabases = func(app string) ([]string, error) {
		path := filepath.Join(rootAppStateRoot, app, "current.yml")
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read deployed stack %s: %w", path, err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(body, &document); err != nil {
			return nil, fmt.Errorf("decode deployed stack %s: %w", path, err)
		}
		declared, err := managedDatabaseLabelFromStack(document)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(declared.Databases))
		for _, database := range declared.Databases {
			names = append(names, database.Name)
		}
		return names, nil
	}
	preRunReservation    = defaultPreRunReservation
	preRunVerifyIdentity = verifyRootOperationIdentity
	preRunMutationGuard  = refuseRootHelperMutationDuringMigration
)

var preRunArchiveName = regexp.MustCompile(`^([0-9]{8}T[0-9]{6}Z)-([a-z][a-z0-9-]{0,62})-([a-z_][a-z0-9_]{0,62})\.dump$`)

type rootPreflightRefusal struct{ reason string }

func (r *rootPreflightRefusal) Error() string { return r.reason }

func refuseBeforeMutation(err error) error {
	if err == nil {
		return nil
	}
	var refusal *rootPreflightRefusal
	if errors.As(err, &refusal) {
		return refusal
	}
	return &rootPreflightRefusal{reason: err.Error()}
}

func emitPreflightRefusal(err error) error {
	refusal := refuseBeforeMutation(err)
	reason := cleanRootRefusalReason(refusal.Error())
	fmt.Fprintln(os.Stderr, rootPreflightRefusalMarker+reason)
	return &rootPreflightRefusal{reason: reason}
}

func withPreRunWatchdog(run func() error) error {
	watchdog := time.AfterFunc(preRunPreflightBudget, func() {
		fmt.Fprintf(os.Stderr, "root operation pre-flight exceeded %s and was aborted so the host stays operable\n", preRunPreflightBudget)
		os.Exit(75)
	})
	defer watchdog.Stop()
	return run()
}

func preflightDeclaredOperation(plan rootplan.Plan, output io.Writer) (declaredOperation, string, error) {
	if plan.Run == nil {
		return declaredOperation{}, "", errors.New("run operation is incomplete")
	}
	if err := preRunMutationGuard(plan.Action); err != nil {
		return declaredOperation{}, "", err
	}
	if err := preRunVerifyIdentity(plan); err != nil {
		return declaredOperation{}, "", err
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil || time.Until(expires) < preRunPreflightBudget+time.Minute {
		return declaredOperation{}, "", errors.New("run plan expires before the pre-flight budget and lock wait can complete")
	}
	if err := preRunReservation(context.Background(), plan); err != nil {
		return declaredOperation{}, "", err
	}
	target, err := resolveDeclaredOperation(plan.Run.App, plan.Run.Operation)
	if err != nil {
		return declaredOperation{}, "", err
	}
	if plan.Run.SkipBackup && !target.BackupBefore {
		return declaredOperation{}, "", fmt.Errorf("skip_backup was requested but operation %s does not declare backup_before in the deployed stack", plan.Run.Operation)
	}
	if target.BackupBefore && !plan.Run.RequireBackup {
		return declaredOperation{}, "", fmt.Errorf("deployed operation %s declares backup_before but the plan does not require it; update the CLI or redeploy", plan.Run.Operation)
	}
	if plan.Run.RequireBackup && !target.BackupBefore {
		return declaredOperation{}, "", fmt.Errorf("config.json declares backup_before for %s but the deployed stack does not; run shuttle deploy first", plan.Run.Operation)
	}
	container, err := declaredOperationContainer(plan.Run.App + "_" + target.Service)
	if err != nil {
		return declaredOperation{}, "", err
	}
	if target.BackupBefore && plan.Run.SkipBackup {
		fmt.Fprintf(output, "backup  skipped by --skip-backup (operation %s)\n", plan.Run.Operation)
	} else if target.BackupBefore {
		if err := preRunBackup(plan.Run.App, plan.Run.Operation, output); err != nil {
			return declaredOperation{}, "", err
		}
		container, err = declaredOperationContainer(plan.Run.App + "_" + target.Service)
		if err != nil {
			return declaredOperation{}, "", fmt.Errorf("resolve running task after pre-run backup: %w", err)
		}
	}
	return target, container, nil
}

func defaultPreRunReservation(ctx context.Context, plan rootplan.Plan) error {
	record, err := coord.NewDefault().RequireLive(ctx, plan.OperationID)
	if err != nil {
		return err
	}
	if record.Kind != plan.OperationKind || record.App != plan.OperationApp || record.Principal != plan.OperatorKeyFingerprint || record.OwnerKeyFingerprint != plan.OperatorKeyFingerprint || record.Host != plan.RequiredHostFingerprint || record.State != "active" || record.RecoveryRequired {
		return errors.New("run plan does not match a live active reservation")
	}
	return nil
}

func defaultPreRunCommand(ctx context.Context, asPostgres bool, name string, args ...string) *exec.Cmd {
	path := preRunExecutable(name)
	if path == "" {
		return exec.CommandContext(ctx, "", args...)
	}
	commandArgs := append(append([]string(nil), preRunCommandPrefix(name)...), args...)
	command := exec.CommandContext(ctx, path, commandArgs...)
	// Pdeathsig follows the creating OS thread, as in the existing SSH writer.
	// The process-group kill on context deadline is the actual descendant fence.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 5 * time.Second
	if asPostgres {
		uid, gid, home, err := preRunPostgresIdentity()
		if err != nil {
			command.Path = ""
			command.Args = []string{"postgres identity lookup failed: " + err.Error()}
			return command
		}
		command.Dir = home
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + home}
		if preRunCredentialEnabled() {
			command.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		}
	}
	command.Env = append(command.Env, preRunCommandEnvironment()...)
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return command
}

func defaultPreRunDatabaseExists(ctx context.Context, name string) (bool, error) {
	if err := validPreRunDatabaseName(name); err != nil {
		return false, err
	}
	command := preRunCommand(ctx, true, "psql", "-X", "-Atqc", "SELECT 1 FROM pg_database WHERE datname='"+name+"'")
	body, err := command.Output()
	if err != nil {
		return false, fmt.Errorf("probe PostgreSQL database %s: %w", name, err)
	}
	return strings.TrimSpace(string(body)) == "1", nil
}

func defaultPreRunDatabaseSize(ctx context.Context, name string) (int64, error) {
	if err := validPreRunDatabaseName(name); err != nil {
		return 0, err
	}
	command := preRunCommand(ctx, true, "psql", "-X", "-Atqc", "SELECT pg_database_size('"+name+"')")
	body, err := command.Output()
	if err != nil {
		return 0, fmt.Errorf("read size of PostgreSQL database %s: %w", name, err)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("read size of PostgreSQL database %s: invalid byte count", name)
	}
	return size, nil
}

func validPreRunDatabaseName(name string) error {
	if rootPostgresIdentifier.MatchString(name) {
		return nil
	}
	return validManagedDatabaseName(name)
}

type preRunDatabaseCandidate struct {
	name     string
	recorded bool
}

func preRunDatabaseCandidates(app string) ([]preRunDatabaseCandidate, error) {
	derived := strings.ReplaceAll(app, "-", "_")
	if !rootPostgresIdentifier.MatchString(derived) {
		return nil, errors.New("derived PostgreSQL identifier is invalid")
	}
	ledger, err := preRunLedger(app)
	if err != nil {
		return nil, fmt.Errorf("read PostgreSQL ownership ledger of %s: %w", app, err)
	}
	_, owners, err := preRunOwners()
	if err != nil {
		return nil, fmt.Errorf("read PostgreSQL ownership: %w", err)
	}
	stackNames, err := preRunStackDatabases(app)
	if err != nil {
		return nil, fmt.Errorf("read managed databases from the deployed stack: %w", err)
	}
	set := map[string]bool{derived: false}
	for _, name := range ledger.Databases {
		if err := validManagedDatabaseName(name); err != nil {
			return nil, fmt.Errorf("invalid database in PostgreSQL ownership ledger: %w", err)
		}
		set[name] = true
	}
	for _, name := range stackNames {
		if err := validManagedDatabaseName(name); err != nil {
			return nil, fmt.Errorf("invalid database in deployed stack label: %w", err)
		}
		set[name] = true
	}
	names := make([]string, 0, len(set))
	for name := range set {
		if owner, claimed := owners[name]; claimed && owner != app {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	candidates := make([]preRunDatabaseCandidate, 0, len(names))
	for _, name := range names {
		candidates = append(candidates, preRunDatabaseCandidate{name: name, recorded: set[name]})
	}
	return candidates, nil
}

func preRunBackup(app, operation string, output io.Writer) (result error) {
	if !rootAppName.MatchString(app) || !rootOperationName.MatchString(operation) {
		return errors.New("invalid pre-run backup identity")
	}
	if err := os.MkdirAll(preRunBackupRoot, 0o700); err != nil {
		return fmt.Errorf("create pre-run backup root: %w", err)
	}
	if err := os.Chmod(preRunBackupRoot, 0o700); err != nil {
		return fmt.Errorf("secure pre-run backup root: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(preRunBackupRoot, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open pre-run backup lock: %w", err)
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return fmt.Errorf("secure pre-run backup lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errors.New("another pre-run backup is in progress on this host; retry when it ends")
		}
		return fmt.Errorf("take pre-run backup lock: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := requireDailyBackupIdle(); err != nil {
		return err
	}
	dir := filepath.Join(preRunBackupRoot, app)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create pre-run backup directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure pre-run backup directory: %w", err)
	}
	if err := sweepPreRunTemps(dir); err != nil {
		return fmt.Errorf("remove stale pre-run backup files: %w", err)
	}
	dumpDeadline := preRunDumpTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), dumpDeadline)
	defer cancel()
	candidates, err := preRunDatabaseCandidates(app)
	if err != nil {
		return err
	}
	existing := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		exists, err := preRunDatabaseExists(ctx, candidate.name)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("pre-run backup deadline %s exceeded while probing %s: %w", dumpDeadline, candidate.name, ctx.Err())
			}
			return fmt.Errorf("probe PostgreSQL database %s: %w", candidate.name, err)
		}
		if !exists {
			if candidate.recorded {
				fmt.Fprintf(output, "backup  skip db=%s: recorded but absent\n", candidate.name)
			}
			continue
		}
		existing = append(existing, candidate.name)
	}
	if len(existing) == 0 {
		return fmt.Errorf("operation %s declares backup_before but no PostgreSQL database of %s exists on this host", operation, app)
	}
	if err := checkPreRunBackupCapacity(ctx, dir, app, existing, dumpDeadline); err != nil {
		return err
	}
	// Runs are concurrent across applications. PostgreSQL and each following
	// migration share this filesystem, so every dump preserves ten percent free.
	stamp := preRunNow().UTC().Format("20060102T150405Z")
	var temporaries, published []string
	complete := false
	defer func() {
		if complete {
			return
		}
		for _, path := range temporaries {
			_ = os.Remove(path)
		}
		for _, path := range published {
			_ = os.Remove(path)
		}
	}()
	for _, name := range existing {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("pre-run backup deadline %s exceeded while backing up %s: %w", dumpDeadline, name, err)
		}
		archive, err := os.CreateTemp(dir, ".pre-run-*")
		if err != nil {
			return fmt.Errorf("create pre-run archive for %s: %w", name, err)
		}
		temporary := archive.Name()
		temporaries = append(temporaries, temporary)
		if err := archive.Chmod(0o600); err != nil {
			archive.Close()
			return fmt.Errorf("secure pre-run archive for %s: %w", name, err)
		}
		var stderr tailBuffer
		dump := preRunCommand(ctx, true, "pg_dump", "-Fc", "--no-password", "-d", name)
		dump.Stdout = archive
		dump.Stderr = &stderr
		dumpErr := dump.Run()
		if dumpErr != nil {
			archive.Close()
			if ctx.Err() != nil {
				return fmt.Errorf("pre-run backup deadline %s exceeded while dumping %s: %w", dumpDeadline, name, ctx.Err())
			}
			return fmt.Errorf("pg_dump failed for %s: %s", name, cleanRootRefusalReason(stderr.String()))
		}
		if err := archive.Sync(); err != nil {
			archive.Close()
			return fmt.Errorf("sync pre-run archive for %s: %w", name, err)
		}
		info, statErr := archive.Stat()
		closeErr := archive.Close()
		if statErr != nil {
			return fmt.Errorf("inspect pre-run archive for %s: %w", name, statErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close pre-run archive for %s: %w", name, closeErr)
		}
		if info.Size() == 0 {
			return fmt.Errorf("pg_dump produced an empty archive for %s", name)
		}
		if err := verifyPreRunArchive(ctx, temporary, name, dumpDeadline); err != nil {
			return err
		}
		final := filepath.Join(dir, stamp+"-"+operation+"-"+name+".dump")
		if err := os.Link(temporary, final); err != nil {
			return fmt.Errorf("publish verified pre-run archive for %s: %w", name, err)
		}
		published = append(published, final)
		if err := os.Remove(temporary); err != nil {
			return fmt.Errorf("remove temporary pre-run archive for %s: %w", name, err)
		}
		temporaries = temporaries[:len(temporaries)-1]
		fmt.Fprintf(output, "backup  app=%s db=%s -> %s (%s, verified)\n", app, name, final, humanBytes(uint64(info.Size())))
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync pre-run backup directory: %w", err)
	}
	complete = true
	if err := retainPreRunArchives(dir, stamp); err != nil {
		fmt.Fprintf(os.Stderr, "%swarning: pre-run backup retention cleanup failed: %s\n", rootHelperWarningPrefix, cleanRootRefusalReason(err.Error()))
	}
	return nil
}

func requireDailyBackupIdle() error {
	if err := os.MkdirAll(filepath.Dir(preRunDailyLockPath), 0o700); err != nil {
		return fmt.Errorf("open daily PostgreSQL backup lock directory: %w", err)
	}
	lock, err := os.OpenFile(preRunDailyLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open daily PostgreSQL backup lock: %w", err)
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return fmt.Errorf("secure daily PostgreSQL backup lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errors.New("the daily PostgreSQL backup is running; retry when it ends")
		}
		return fmt.Errorf("take daily PostgreSQL backup lock: %w", err)
	}
	return syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
}

func sweepPreRunTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".pre-run-") || entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func verifyPreRunArchive(ctx context.Context, path, database string, deadline time.Duration) error {
	archive, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open pre-run archive for verification (%s): %w", database, err)
	}
	defer archive.Close()
	var stderr tailBuffer
	restore := preRunCommand(ctx, true, "pg_restore", "--list")
	restore.Stdin = archive
	restore.Stdout = io.Discard
	restore.Stderr = &stderr
	if err := restore.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("pre-run backup deadline %s exceeded while verifying %s: %w", deadline, database, ctx.Err())
		}
		return fmt.Errorf("pg_restore could not verify archive for %s: %s", database, cleanRootRefusalReason(stderr.String()))
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func retainPreRunArchives(dir, currentStamp string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	stamps := map[string]bool{}
	var matching []string
	for _, entry := range entries {
		match := preRunArchiveName.FindStringSubmatch(entry.Name())
		if match == nil || !entry.Type().IsRegular() {
			continue
		}
		stamps[match[1]] = true
		matching = append(matching, entry.Name())
	}
	ordered := make([]string, 0, len(stamps))
	for stamp := range stamps {
		ordered = append(ordered, stamp)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ordered)))
	keep := map[string]bool{currentStamp: true}
	for i := 0; i < len(ordered) && i < preRunBackupRetention; i++ {
		keep[ordered[i]] = true
	}
	var errs []error
	for _, name := range matching {
		stamp := preRunArchiveName.FindStringSubmatch(name)[1]
		if keep[stamp] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func humanBytes(value uint64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	amount := float64(value)
	unit := "B"
	for _, next := range units {
		amount /= 1024
		unit = next
		if amount < 1024 {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", amount, unit)
}

type tailBuffer struct{ data []byte }

func (b *tailBuffer) Write(value []byte) (int, error) {
	b.data = append(b.data, value...)
	if len(b.data) > 512 {
		b.data = append([]byte(nil), b.data[len(b.data)-512:]...)
	}
	return len(value), nil
}

func (b *tailBuffer) String() string { return string(bytes.TrimSpace(b.data)) }

// Both pre-run and destroy refuse before mutation when complete database dumps
// would consume the ten-percent filesystem reserve.
func checkPreRunBackupCapacity(ctx context.Context, dir, app string, existing []string, dumpDeadline time.Duration) error {
	var need uint64
	for _, name := range existing {
		size, err := preRunDatabaseSize(ctx, name)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("pre-run backup deadline %s exceeded while reading size of %s: %w", dumpDeadline, name, ctx.Err())
			}
			return fmt.Errorf("read size of PostgreSQL database %s: %w", name, err)
		}
		if size < 0 || uint64(size) > ^uint64(0)-need {
			return fmt.Errorf("invalid or overflowing size for PostgreSQL database %s", name)
		}
		need += uint64(size)
	}
	available, total, err := preRunFilesystem(dir)
	if err != nil {
		return fmt.Errorf("measure space for pre-run backup: %w", err)
	}
	reserve := total / 10
	if available < need || available-need < reserve {
		return fmt.Errorf("not enough space for the pre-run backup of %s: databases %s, %s available in %s, 10%% of the %s filesystem (%s) must stay free", app, humanBytes(need), humanBytes(available), dir, humanBytes(total), humanBytes(reserve))
	}
	return nil
}
