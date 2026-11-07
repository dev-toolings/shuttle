//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const (
	helperMigrationIntentPath        = "/var/lib/shuttle/helper-migration/intent.json"
	helperMigrationHistoryPath       = "/var/lib/shuttle/helper-migration/history"
	helperMigrationJournalPath       = "/var/lib/shuttle/operations"
	helperMigrationWritersPath       = "/var/lib/shuttle/operations/writers"
	helperMigrationBackupStagingPath = "/var/lib/shuttle/backup-staging"
	helperMigrationDrainTimeout      = 2 * time.Minute
	helperMigrationLockWait          = 2 * time.Minute
	helperMigrationPoll              = 25 * time.Millisecond
	helperMigrationMaxIntentBytes    = 16 << 10
	helperMigrationMaxMarkerBytes    = 128 << 10
	helperMigrationMaxProcessBytes   = 32 << 20
)

type helperMigrationPaths struct {
	IntentPath        string
	HistoryDir        string
	JournalPath       string
	WritersPath       string
	BackupStagingPath string
	LockPath          string
	InstalledPath     string
	StagingDir        string
}

func defaultHelperMigrationPaths() helperMigrationPaths {
	return helperMigrationPaths{
		IntentPath:        helperMigrationIntentPath,
		HistoryDir:        helperMigrationHistoryPath,
		JournalPath:       helperMigrationJournalPath,
		WritersPath:       helperMigrationWritersPath,
		BackupStagingPath: helperMigrationBackupStagingPath,
		LockPath:          "/run/shuttle-root.lock",
		InstalledPath:     rootHelperExecutable,
		StagingDir:        filepath.Dir(rootHelperExecutable),
	}
}

type helperMigrationFS struct {
	lstat      func(string) (os.FileInfo, error)
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	readlink   func(string) (string, error)
	stat       func(string) (os.FileInfo, error)
	ownerOK    func(os.FileInfo) bool
	open       func(string, int, os.FileMode) (*os.File, error)
	createTemp func(string, string) (*os.File, error)
	mkdirAll   func(string, os.FileMode) error
	rename     func(string, string) error
	remove     func(string) error
	syncFile   func(*os.File) error
	syncDir    func(string) error
}

const helperMigrationOperationSchema = "shuttle.operation/v1"

type helperMigrationOperationRecord struct {
	Schema              string `json:"schema"`
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	State               string `json:"state"`
	RecoveryRequired    bool   `json:"recovery_required"`
	OwnerKeyFingerprint string `json:"owner_key_fingerprint,omitempty"`
	Principal           string `json:"principal,omitempty"`
	LeaseUntil          string `json:"lease_until,omitempty"`
	Host                string `json:"host,omitempty"`
	HostBootID          string `json:"host_boot_id,omitempty"`
}

// helperMigrationWriterProof is the narrow adapter returned by the parent
// operation-writers implementation. The migration package does not import that
// package because its implementation is owned by the parent worktree.
const helperMigrationWriterProofSchema = "shuttle.operation-writer/v1"

type helperMigrationWriterRecord struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Origin      string `json:"origin"`
}

type helperMigrationWriterProof struct {
	Schema  string                        `json:"schema"`
	Writers []helperMigrationWriterRecord `json:"writers"`
}

type helperMigrationWriterProofReader func(string) (helperMigrationWriterProof, error)

func newOSHelperMigrationFS() helperMigrationFS {
	return helperMigrationFS{
		lstat:      os.Lstat,
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		readlink:   os.Readlink,
		stat:       os.Stat,
		ownerOK:    helperMigrationFileOwnerIsRoot,
		open:       os.OpenFile,
		createTemp: os.CreateTemp,
		mkdirAll:   os.MkdirAll,
		rename:     os.Rename,
		remove:     os.Remove,
		syncFile:   func(file *os.File) error { return file.Sync() },
		syncDir: func(path string) error {
			directory, err := os.Open(path)
			if err != nil {
				return err
			}
			defer directory.Close()
			return directory.Sync()
		},
	}
}

func helperMigrationReadFile(fs helperMigrationFS, path string, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("helper migration read limit is invalid")
	}
	if fs.open != nil {
		file, err := fs.open(path, os.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		body, err := io.ReadAll(io.LimitReader(file, max+1))
		if err != nil {
			return nil, err
		}
		if int64(len(body)) > max {
			return nil, fmt.Errorf("%s exceeds the %d byte limit", path, max)
		}
		return body, nil
	}
	if fs.readFile == nil {
		return nil, errors.New("helper migration file reader is unavailable")
	}
	body, err := fs.readFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", path, max)
	}
	return body, nil
}

func helperMigrationFileOwnerIsRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func helperMigrationRegularRootFile(fs helperMigrationFS, path string, mode os.FileMode, max int64) (os.FileInfo, error) {
	info, err := fs.lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || fs.ownerOK == nil || !fs.ownerOK(info) {
		return nil, fmt.Errorf("%s is not a root-owned regular file with mode %04o", path, mode)
	}
	if max > 0 && info.Size() > max {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", path, max)
	}
	return info, nil
}

func helperMigrationDirectory(fs helperMigrationFS, path string, mode os.FileMode) error {
	info, err := fs.lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || fs.ownerOK == nil || !fs.ownerOK(info) {
		return fmt.Errorf("%s is not a root-owned directory with mode %04o", path, mode)
	}
	return nil
}

func readHelperMigrationIntent(fs helperMigrationFS, path string) (*helperMigrationIntent, error) {
	if _, err := fs.lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect helper migration intent: %w", err)
	}
	if _, err := helperMigrationRegularRootFile(fs, path, 0o600, helperMigrationMaxIntentBytes); err != nil {
		return nil, fmt.Errorf("inspect helper migration intent: %w", err)
	}
	body, err := helperMigrationReadFile(fs, path, helperMigrationMaxIntentBytes)
	if err != nil {
		return nil, fmt.Errorf("read helper migration intent: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var intent helperMigrationIntent
	if err := decoder.Decode(&intent); err != nil {
		return nil, errors.New("decode helper migration intent")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("helper migration intent must contain one JSON document")
	}
	if err := intent.validate(); err != nil {
		return nil, err
	}
	return &intent, nil
}

func writeHelperMigrationIntent(fs helperMigrationFS, path string, intent helperMigrationIntent) error {
	return writeHelperMigrationIntentWithOptions(fs, path, intent, false)
}

func writeHelperMigrationIntentAfterBootChange(fs helperMigrationFS, path string, intent helperMigrationIntent) error {
	return writeHelperMigrationIntentWithOptions(fs, path, intent, true)
}

func writeHelperMigrationIntentWithOptions(fs helperMigrationFS, path string, intent helperMigrationIntent, allowBootChange bool) error {
	if err := intent.validate(); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := fs.mkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create helper migration directory: %w", err)
	}
	if err := helperMigrationDirectory(fs, directory, 0o700); err != nil {
		return fmt.Errorf("inspect helper migration directory: %w", err)
	}
	if current, err := readHelperMigrationIntent(fs, path); err == nil && current != nil {
		if current.ID != intent.ID || current.Source != intent.Source || current.CandidateSHA256 != intent.CandidateSHA256 || current.Host != intent.Host || (!allowBootChange && current.BootID != intent.BootID) || !reflect.DeepEqual(current.Probe, intent.Probe) {
			return errors.New("helper migration intent ownership is immutable")
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := fs.createTemp(directory, ".intent-*.tmp")
	if err != nil {
		return fmt.Errorf("create helper migration intent temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	defer fs.remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	body, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(body, '\n')); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write helper migration intent: %w", err)
	}
	if err := fs.syncFile(temporary); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync helper migration intent: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := fs.rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish helper migration intent: %w", err)
	}
	if err := fs.syncDir(directory); err != nil {
		return fmt.Errorf("sync helper migration directory: %w", err)
	}
	return nil
}

func markHelperMigrationPhase(fs helperMigrationFS, path, candidateDigest, phase string) error {
	intent, err := readHelperMigrationIntent(fs, path)
	if err != nil {
		return err
	}
	if intent == nil {
		return errors.New("helper migration intent is missing")
	}
	if intent.CandidateSHA256 != candidateDigest {
		return errors.New("helper migration candidate digest changed")
	}
	switch phase {
	case helperMigrationPhaseReplaced:
		if intent.Phase == helperMigrationPhaseComplete || intent.Phase == helperMigrationPhaseReplaced {
			return nil
		}
		if intent.Phase != helperMigrationPhaseReady {
			return errors.New("helper migration cannot record replacement from its current phase")
		}
	case helperMigrationPhaseComplete:
		if intent.Phase == helperMigrationPhaseComplete {
			return nil
		}
		if intent.Phase != helperMigrationPhaseReplaced {
			return errors.New("helper migration cannot record completion before replacement")
		}
	default:
		return errors.New("unsupported helper migration phase transition")
	}
	intent.Phase = phase
	return writeHelperMigrationIntent(fs, path, *intent)
}

type helperMigrationBackupMarker struct {
	App         string         `json:"app"`
	OperationID string         `json:"operation_id"`
	Replicas    map[string]int `json:"replicas"`
	Work        string         `json:"work"`
}

// This read-only scan belongs before the coordinator records a mutation phase.
// A journal refusal used to leave an unchanged helper requiring recovery.
var rootHelperUpdatePreflightRuntime = defaultHelperMigrationRuntime

func rootHelperUpdatePreflight(plan rootplan.Plan, record coord.Record) error {
	runtime := rootHelperUpdatePreflightRuntime()
	if plan.Helper.AllowDowngrade {
		if err := refuseHelperRollbackWithPendingDestroy(filepath.Join(runtime.paths.JournalPath, "destroy-cleanup"), runtime.fs); err != nil {
			return err
		}
	}
	proof := helperMigrationOwnReservationProof{
		OperationID: plan.OperationID, OperationKind: plan.OperationKind,
		OwnerKeyFingerprint: plan.OperatorKeyFingerprint, HostFingerprint: plan.RequiredHostFingerprint,
		BootID: record.HostBootID, CandidateSHA256: plan.Helper.PayloadSHA256,
	}
	return inspectRootHelperMigrationStateWithOwnReservation(runtime.paths, runtime.fs, runtime.writerProof, proof)
}

// A rollback must not hand unfinished cleanup to older destroy semantics.
// Uncommitted writeRootFile temporaries are not journals and stay untouched.
// All other entries, including corrupt or unknown evidence, block replacement.
var helperDestroyTemporaryPattern = regexp.MustCompile(`^\.shuttle-root-[0-9]+$`)

func refuseHelperRollbackWithPendingDestroy(path string, fs helperMigrationFS) error {
	if _, err := fs.lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect pending destroy journals: %w", err)
	}
	if err := helperMigrationDirectory(fs, path, 0o700); err != nil {
		return fmt.Errorf("inspect pending destroy journals: %w", err)
	}
	entries, err := fs.readDir(path)
	if err != nil {
		return fmt.Errorf("read pending destroy journals: %w", err)
	}
	for _, entry := range entries {
		if helperDestroyTemporaryPattern.MatchString(entry.Name()) {
			if info, err := helperMigrationRegularRootFile(fs, filepath.Join(path, entry.Name()), 0o600, 0); err == nil && info.Mode() == 0o600 {
				continue
			}
		}
		return errors.New("helper replacement refused while a pending destroy journal exists; recover the destroy with the installed helper first (docs/operations-recovery.md)")
	}
	return nil
}

func inspectRootHelperMigrationState(paths helperMigrationPaths, fs helperMigrationFS) error {
	return inspectRootHelperMigrationStateWithOwnReservation(paths, fs, readMigrationWriterProof, helperMigrationOwnReservationProof{})
}

func inspectRootHelperMigrationStateWithWriterReader(paths helperMigrationPaths, fs helperMigrationFS, reader helperMigrationWriterProofReader) error {
	return inspectRootHelperMigrationStateWithOwnReservation(paths, fs, reader, helperMigrationOwnReservationProof{})
}

func inspectRootHelperMigrationStateWithOwnReservation(paths helperMigrationPaths, fs helperMigrationFS, reader helperMigrationWriterProofReader, own helperMigrationOwnReservationProof) error {
	if err := inspectHelperMigrationJournal(paths, fs, reader, own); err != nil {
		return err
	}
	return inspectHelperMigrationBackups(paths.BackupStagingPath, fs)
}

// Temporary records can survive a crash before rename. They are never
// authoritative journals, but their type, owner and permissions still matter.
var helperMigrationJournalTemporaryPattern = regexp.MustCompile(`^(\.operation-[0-9]+\.tmp|\.reboot-[a-z0-9_]{8})$`)

func inspectHelperMigrationJournal(paths helperMigrationPaths, fs helperMigrationFS, reader helperMigrationWriterProofReader, own helperMigrationOwnReservationProof) error {
	if !own.isZero() {
		if err := own.validate(); err != nil {
			return err
		}
	}
	path := paths.JournalPath
	if _, err := fs.lstat(path); errors.Is(err, os.ErrNotExist) {
		if !own.isZero() {
			return errors.New("helper-update own reservation is missing from the operation journal")
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect operation journal: %w", err)
	}
	if err := helperMigrationDirectory(fs, path, 0o700); err != nil {
		return fmt.Errorf("inspect operation journal: %w", err)
	}
	entries, err := fs.readDir(path)
	if err != nil {
		return fmt.Errorf("read operation journal: %w", err)
	}
	admittedOwn := false
	for _, entry := range entries {
		name := entry.Name()
		if name == "writers" {
			if !entry.IsDir() {
				return errors.New("operation journal writers entry is not a directory")
			}
			continue
		}
		// Baseline archives are written before any deploy writer is admitted.
		// Refusing them made every helper update after a coordinated deploy fail
		// on the recette VPS and leave a recovery_required reservation.
		if name == rootOperationBaselineDirName {
			if !entry.IsDir() {
				return errors.New("operation journal baselines entry is not a directory")
			}
			if err := helperMigrationDirectory(fs, filepath.Join(path, name), 0o700); err != nil {
				return fmt.Errorf("inspect operation baselines: %w", err)
			}
			continue
		}
		// Destroy leaves this root-only directory after its last cleanup journal
		// is removed. Rejecting it broke every later helper update on such hosts.
		if name == "destroy-cleanup" {
			if err := helperMigrationDirectory(fs, filepath.Join(path, name), 0o700); err != nil {
				return fmt.Errorf("inspect operation destroy cleanup: %w", err)
			}
			continue
		}
		if helperMigrationJournalTemporaryPattern.MatchString(name) {
			if _, err := helperMigrationRegularRootFile(fs, filepath.Join(path, name), 0o600, 256<<10); err != nil {
				return fmt.Errorf("inspect operation journal temporary: %w", err)
			}
			continue
		}
		if strings.HasSuffix(name, ".reboot") {
			if err := inspectHelperMigrationRebootCompanion(path, name, fs); err != nil {
				return err
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") || !helperMigrationOperationIDPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			return fmt.Errorf("operation journal contains an unexpected entry %q", name)
		}
		recordPath := filepath.Join(path, name)
		if _, err := helperMigrationRegularRootFile(fs, recordPath, 0o600, 256<<10); err != nil {
			return fmt.Errorf("inspect operation journal record %q: %w", name, err)
		}
		body, err := helperMigrationReadFile(fs, recordPath, 256<<10)
		if err != nil {
			return fmt.Errorf("read operation journal record %q: %w", name, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		var record helperMigrationOperationRecord
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("decode operation journal record %q", name)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("operation journal record %q contains more than one JSON document", name)
		}
		id := strings.TrimSuffix(name, ".json")
		if record.Schema != helperMigrationOperationSchema || record.ID != id {
			return fmt.Errorf("operation journal record %q has invalid identity", name)
		}
		// A record awaiting recovery has no executor left, so it does not stop
		// a helper replacement: the replacement may be the only way to get a
		// helper whose recovery works (see operations.conflict). Its writers
		// must still be closed (inspectHelperMigrationWriters), and only the
		// consistent form is admitted; a half-written state still refuses.
		if record.RecoveryRequired || record.State == "recovery_required" {
			if !record.RecoveryRequired || record.State != "recovery_required" {
				return fmt.Errorf("operation journal record %q requires recovery", name)
			}
			continue
		}
		if record.State == "active" {
			if err := admitHelperMigrationActiveRecord(record, own); err != nil {
				return err
			}
			if admittedOwn {
				return fmt.Errorf("operation journal record %q is active", name)
			}
			admittedOwn = true
			continue
		}
		switch record.State {
		case "completed", "failed", "recovered":
		default:
			return fmt.Errorf("operation journal record %q has an unsupported state", name)
		}
	}
	if !own.isZero() && !admittedOwn {
		return errors.New("helper-update own reservation is missing from the operation journal")
	}
	writersPath := paths.WritersPath
	if writersPath == "" {
		writersPath = filepath.Join(path, "writers")
	}
	if err := inspectHelperMigrationWriters(writersPath, fs, reader); err != nil {
		return err
	}
	return nil
}

func admitHelperMigrationActiveRecord(record helperMigrationOperationRecord, own helperMigrationOwnReservationProof) error {
	name := record.ID + ".json"
	if own.isZero() {
		return fmt.Errorf("operation journal record %q is active", name)
	}
	if err := own.validate(); err != nil {
		return err
	}
	if record.Kind != helperMigrationOwnReservationKind ||
		record.ID != own.OperationID ||
		record.Kind != own.OperationKind ||
		record.OwnerKeyFingerprint != own.OwnerKeyFingerprint ||
		record.Principal != own.OwnerKeyFingerprint ||
		record.Host != own.HostFingerprint ||
		record.HostBootID != own.BootID {
		return fmt.Errorf("operation journal record %q is active", name)
	}
	lease, err := time.Parse(time.RFC3339Nano, record.LeaseUntil)
	if err != nil || !lease.After(time.Now()) {
		return errors.New("helper-update own reservation lease is invalid or expired")
	}
	return nil
}

func helperMigrationOwnReservationPath(paths helperMigrationPaths) string {
	if paths.IntentPath == "" {
		return "/var/lib/shuttle/helper-migration/own-reservation.json"
	}
	return filepath.Join(filepath.Dir(paths.IntentPath), "own-reservation.json")
}

func readHelperMigrationOwnReservationProof(fs helperMigrationFS, paths helperMigrationPaths) (*helperMigrationOwnReservationProof, error) {
	path := helperMigrationOwnReservationPath(paths)
	if _, err := fs.lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect helper-update own reservation proof: %w", err)
	}
	if _, err := helperMigrationRegularRootFile(fs, path, 0o600, helperMigrationMaxIntentBytes); err != nil {
		return nil, fmt.Errorf("inspect helper-update own reservation proof: %w", err)
	}
	body, err := helperMigrationReadFile(fs, path, helperMigrationMaxIntentBytes)
	if err != nil {
		return nil, fmt.Errorf("read helper-update own reservation proof: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var proof helperMigrationOwnReservationProof
	if err := decoder.Decode(&proof); err != nil {
		return nil, errors.New("decode helper-update own reservation proof")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("helper-update own reservation proof must contain one JSON document")
	}
	if err := proof.validate(); err != nil {
		return nil, err
	}
	return &proof, nil
}

func writeHelperMigrationOwnReservationProof(fs helperMigrationFS, path string, proof helperMigrationOwnReservationProof) error {
	proof = canonicalHelperMigrationOwnReservationProof(proof)
	if err := proof.validate(); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := fs.mkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create helper migration directory: %w", err)
	}
	if err := helperMigrationDirectory(fs, directory, 0o700); err != nil {
		return fmt.Errorf("inspect helper migration directory: %w", err)
	}
	temporary, err := fs.createTemp(directory, ".own-reservation-*.tmp")
	if err != nil {
		return fmt.Errorf("create helper-update own reservation temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	defer fs.remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	body, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(body, '\n')); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write helper-update own reservation proof: %w", err)
	}
	if err := fs.syncFile(temporary); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync helper-update own reservation proof: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := fs.rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish helper-update own reservation proof: %w", err)
	}
	if err := fs.syncDir(directory); err != nil {
		return fmt.Errorf("sync helper migration directory: %w", err)
	}
	return nil
}

// admitHelperMigrationOwnReservation is the owned receiving hook the parent
// dispatcher must call from applyRootHelperUpdate while it still holds the
// shared /run/shuttle-root.lock (operations.DefaultLockPath). It persists the
// proof the candidate --help init re-reads, verifies the staged candidate
// digest, and admits only that one active helper-update lease.
//
// Exact caller wiring the parent must add; this worktree cannot edit those
// files:
//
//	rootplan: keep NewHelperUpdate then WithOperationID(id, "helper-update", "").
//	transport: no new action. The reserved helper-update plan is the existing
//	apply envelope.
//	root_helper_linux.go applyRootHelperUpdate, inside the coordinated
//	callback that already holds the journal flock, after staging the candidate
//	and before probeRootHelperCandidate(path, plan.Helper.AllowDowngrade):
//
//	boot, err := readHelperMigrationBootID()
//	if err != nil { return err }
//	if err := admitHelperMigrationOwnReservation(helperMigrationOwnReservationProof{
//	    OperationID:         plan.OperationID,
//	    OperationKind:       plan.OperationKind,
//	    OwnerKeyFingerprint: plan.OperatorKeyFingerprint,
//	    HostFingerprint:     plan.RequiredHostFingerprint,
//	    BootID:              boot,
//	    CandidateSHA256:     plan.Helper.PayloadSHA256,
//	}, stagedCandidatePath); err != nil {
//	    return err
//	}
//
// The candidate probe uses the parent argv and lock proof recorded by init.
func admitHelperMigrationOwnReservation(proof helperMigrationOwnReservationProof, candidatePath string) error {
	return admitHelperMigrationOwnReservationWithRuntime(proof, candidatePath, defaultHelperMigrationRuntime())
}

func admitHelperMigrationOwnReservationWithRuntime(proof helperMigrationOwnReservationProof, candidatePath string, runtime helperMigrationRuntime) error {
	runtime = normalizeHelperMigrationRuntime(runtime)
	proof = canonicalHelperMigrationOwnReservationProof(proof)
	if err := proof.validate(); err != nil {
		return err
	}
	info, err := helperMigrationRegularRootFile(runtime.fs, candidatePath, 0o755, 32<<20)
	if err != nil {
		return fmt.Errorf("inspect helper-update own reservation candidate: %w", err)
	}
	digest, err := helperMigrationFileDigest(candidatePath, info.Size())
	if err != nil {
		return fmt.Errorf("hash helper-update own reservation candidate: %w", err)
	}
	if digest != proof.CandidateSHA256 {
		return errors.New("helper-update own reservation candidate digest does not match the staged helper")
	}
	if err := inspectRootHelperMigrationStateWithOwnReservation(runtime.paths, runtime.fs, runtime.writerProof, proof); err != nil {
		return err
	}
	return writeHelperMigrationOwnReservationProof(runtime.fs, helperMigrationOwnReservationPath(runtime.paths), proof)
}

// validateHelperMigrationOwnReservation is called under the parent's existing
// flock after replacement and phase completion, before completing only this ID.
func validateHelperMigrationOwnReservation(proof helperMigrationOwnReservationProof) error {
	return validateHelperMigrationOwnReservationWithRuntime(proof, defaultHelperMigrationRuntime())
}

func validateHelperMigrationOwnReservationWithRuntime(proof helperMigrationOwnReservationProof, runtime helperMigrationRuntime) error {
	runtime = normalizeHelperMigrationRuntime(runtime)
	proof = canonicalHelperMigrationOwnReservationProof(proof)
	if err := proof.validate(); err != nil {
		return err
	}
	stored, err := readHelperMigrationOwnReservationProof(runtime.fs, runtime.paths)
	if err != nil {
		return err
	}
	if stored == nil || *stored != proof {
		return errors.New("helper-update parent proof differs from the persisted reservation")
	}
	boot, err := runtime.bootID()
	if err != nil {
		return err
	}
	if boot != proof.BootID {
		return errors.New("helper-update parent proof belongs to another boot")
	}
	return inspectRootHelperMigrationStateWithOwnReservation(runtime.paths, runtime.fs, runtime.writerProof, proof)
}

// clearHelperMigrationOwnReservation runs after the parent has durably completed
// this operation. It removes only the matching proof, never the migration intent.
func clearHelperMigrationOwnReservation(proof helperMigrationOwnReservationProof) error {
	return clearHelperMigrationOwnReservationWithFS(proof, newOSHelperMigrationFS(), defaultHelperMigrationPaths())
}

func clearHelperMigrationOwnReservationWithFS(proof helperMigrationOwnReservationProof, fs helperMigrationFS, paths helperMigrationPaths) error {
	stored, err := readHelperMigrationOwnReservationProof(fs, paths)
	if err != nil {
		return err
	}
	if stored == nil {
		return nil
	}
	if *stored != canonicalHelperMigrationOwnReservationProof(proof) {
		return errors.New("cannot clear another helper-update reservation proof")
	}
	if err := fs.remove(helperMigrationOwnReservationPath(paths)); err != nil {
		return err
	}
	return fs.syncDir(filepath.Dir(helperMigrationOwnReservationPath(paths)))
}

func inspectHelperMigrationRebootCompanion(directory, name string, fs helperMigrationFS) error {
	id := strings.TrimSuffix(name, ".reboot")
	if !helperMigrationOperationIDPattern.MatchString(id) {
		return errors.New("invalid reboot companion identity")
	}
	read := func(path string, target any, strict bool) error {
		if _, err := helperMigrationRegularRootFile(fs, path, 0o600, 256<<10); err != nil {
			return err
		}
		body, err := helperMigrationReadFile(fs, path, 256<<10)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		if strict {
			decoder.DisallowUnknownFields()
		}
		if err := decoder.Decode(target); err != nil {
			return err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return errors.New("reboot companion requires one JSON document")
		}
		return nil
	}
	var record helperMigrationOperationRecord
	if err := read(filepath.Join(directory, id+".json"), &record, false); err != nil {
		return fmt.Errorf("reboot companion journal: %w", err)
	}
	if record.Schema != helperMigrationOperationSchema || record.ID != id || record.Kind != "reboot" || record.RecoveryRequired || (record.State != "completed" && record.State != "failed" && record.State != "recovered") || !helperMigrationFingerprintPattern.MatchString(record.Host) || record.Principal != record.OwnerKeyFingerprint || !helperMigrationFingerprintPattern.MatchString(record.OwnerKeyFingerprint) {
		return errors.New("reboot companion is not linked to a terminal reboot identity")
	}
	var intent struct {
		ID          string `json:"id,omitempty"`
		OperationID string `json:"operation_id,omitempty"`
		Host        string `json:"host,omitempty"`
		BootBefore  string `json:"boot_before"`
		Services    []struct {
			Name     string `json:"name"`
			Replicas int    `json:"replicas"`
			Image    string `json:"image"`
		} `json:"services"`
		Postgres      [][]string `json:"postgres"`
		HTTPSRequired *bool      `json:"https_required"`
	}
	if err := read(filepath.Join(directory, name), &intent, true); err != nil {
		return fmt.Errorf("reboot companion shape: %w", err)
	}
	if intent.BootBefore == "" || intent.BootBefore != record.HostBootID || intent.Services == nil || intent.Postgres == nil || intent.HTTPSRequired == nil || (intent.ID != "" && intent.ID != id) || (intent.OperationID != "" && intent.OperationID != id) || (intent.Host != "" && intent.Host != record.Host) {
		return errors.New("reboot companion identity differs from its journal")
	}
	for _, service := range intent.Services {
		if !rootServiceName.MatchString(service.Name) || service.Replicas < 0 || service.Image == "" || strings.ContainsAny(service.Image, "\x00\r\n") {
			return errors.New("invalid reboot companion service")
		}
	}
	for _, cluster := range intent.Postgres {
		if len(cluster) != 3 {
			return errors.New("invalid reboot companion PostgreSQL shape")
		}
		for _, field := range cluster {
			if field == "" || strings.ContainsAny(field, "\x00\r\n") {
				return errors.New("invalid reboot companion PostgreSQL field")
			}
		}
	}
	return nil
}

func inspectHelperMigrationWriters(path string, fs helperMigrationFS, reader helperMigrationWriterProofReader) error {
	if _, err := fs.lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect operation writers: %w", err)
	}
	if err := helperMigrationDirectory(fs, path, 0o700); err != nil {
		return fmt.Errorf("inspect operation writers: %w", err)
	}
	entries, err := fs.readDir(path)
	if err != nil {
		return fmt.Errorf("read operation writers: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}
	if reader == nil {
		return errors.New("operation writers are nonempty but their typed proof reader is not integrated")
	}
	proof, err := reader(path)
	if err != nil {
		return fmt.Errorf("read operation writer proof: %w", err)
	}
	if err := validateHelperMigrationWriterProof(proof); err != nil {
		return err
	}
	return nil
}

func validateHelperMigrationWriterProof(proof helperMigrationWriterProof) error {
	if proof.Schema != helperMigrationWriterProofSchema || len(proof.Writers) == 0 {
		return errors.New("operation writer proof is not the expected versioned contract")
	}
	seen := make(map[string]struct{}, len(proof.Writers))
	for _, writer := range proof.Writers {
		if !helperMigrationOperationIDPattern.MatchString(writer.OperationID) || writer.State != "closed" {
			return errors.New("operation writer proof does not show a closed coordinator writer")
		}
		if writer.Origin != "local-vps" && writer.Origin != "client-origin" && writer.Origin != "remote-runner" && writer.Origin != "no-writers" {
			return errors.New("operation writer proof has an invalid origin")
		}
		if _, ok := seen[writer.OperationID]; ok {
			return errors.New("operation writer proof contains a duplicate operation")
		}
		seen[writer.OperationID] = struct{}{}
	}
	return nil
}

func inspectHelperMigrationBackups(path string, fs helperMigrationFS) error {
	if _, err := fs.lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect backup staging: %w", err)
	}
	if err := helperMigrationDirectory(fs, path, 0o700); err != nil {
		return fmt.Errorf("inspect backup staging: %w", err)
	}
	entries, err := fs.readDir(path)
	if err != nil {
		return fmt.Errorf("read backup staging: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".pending.json") {
			return fmt.Errorf("backup staging contains an unexpected entry %q", name)
		}
		markerPath := filepath.Join(path, name)
		if _, err := helperMigrationRegularRootFile(fs, markerPath, 0o600, helperMigrationMaxMarkerBytes); err != nil {
			return fmt.Errorf("inspect backup marker %q: %w", name, err)
		}
		body, err := helperMigrationReadFile(fs, markerPath, helperMigrationMaxMarkerBytes)
		if err != nil {
			return fmt.Errorf("read backup marker %q: %w", name, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var marker helperMigrationBackupMarker
		if err := decoder.Decode(&marker); err != nil {
			return fmt.Errorf("decode backup marker %q", name)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("backup marker %q contains more than one JSON document", name)
		}
		if !helperMigrationIDPattern.MatchString(marker.OperationID) || !rootAppName.MatchString(marker.App) || len(marker.Replicas) == 0 || marker.Work == "" || len(marker.Work) > 128 || strings.ContainsAny(marker.Work, "\x00\r\n") {
			return fmt.Errorf("backup marker %q has invalid identity", name)
		}
		for service, replicas := range marker.Replicas {
			if !rootServiceName.MatchString(service) || replicas < 0 || replicas > 1000 {
				return fmt.Errorf("backup marker %q contains an unsafe replica record", name)
			}
		}
		return fmt.Errorf("backup marker %q is pending", name)
	}
	return nil
}

type helperMigrationProbeSpec struct {
	CandidatePath            string
	StagingDir               string
	InstalledPath            string
	LockPath                 string
	ExpectedParentExecutable string
	ExpectedParentArgv       []string
	ExpectedCandidateArgv    []string
	ExpectedUID              uint32
}

type helperMigrationProbeObservation struct {
	CandidateInfo      os.FileInfo
	StagingInfo        os.FileInfo
	CandidateOwned     bool
	StagingOwned       bool
	CandidateArgv      []string
	ParentUID          uint32
	ParentPID          int
	ParentExecutable   string
	ParentArgv         []string
	ParentBirth        string
	ParentHasLock      bool
	ParentLockInode    bool
	ParentLockDevice   uint64
	ParentLockInodeNum uint64
}

func helperMigrationProbeProofFromObservation(spec helperMigrationProbeSpec, observation helperMigrationProbeObservation) *helperMigrationProbeProof {
	return &helperMigrationProbeProof{
		CandidatePath:    spec.CandidatePath,
		CandidateArgv:    append([]string(nil), observation.CandidateArgv...),
		ParentUID:        observation.ParentUID,
		ParentPID:        observation.ParentPID,
		ParentExecutable: observation.ParentExecutable,
		ParentArgv:       append([]string(nil), observation.ParentArgv...),
		ParentBirth:      observation.ParentBirth,
		LockDevice:       observation.ParentLockDevice,
		LockInode:        observation.ParentLockInodeNum,
	}
}

// init is intentionally narrow. The old helper invokes a candidate only as
// `shuttle-root --help`, so the candidate is the only code that can persist the
// intent before an old binary renames it into place. Normal CLI help never has
// the exact staging path, root uid, parent argv and parent lock proof together.
func init() {
	if !candidateRootHelperMigrationLaunch() {
		return
	}
	if err := recordCandidateRootHelperMigration(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "root helper migration probe refused: %v\n", err)
		os.Exit(78)
	}
}

func candidateRootHelperMigrationLaunch() bool {
	if len(os.Args) != 2 || os.Args[0] != "shuttle-root" || os.Args[1] != "--help" || os.Geteuid() != 0 {
		return false
	}
	paths := defaultHelperMigrationPaths()
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil || filepath.Dir(executable) != paths.StagingDir || !strings.HasPrefix(filepath.Base(executable), ".shuttle-root.next-") {
		return false
	}
	return true
}

func recordCandidateRootHelperMigration() error {
	paths := defaultHelperMigrationPaths()
	fs := newOSHelperMigrationFS()
	executable, err := fs.readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("read candidate executable identity: %w", err)
	}
	info, err := helperMigrationRegularRootFile(fs, executable, 0o755, 32<<20)
	if err != nil {
		return err
	}
	stage, err := fs.lstat(paths.StagingDir)
	if err != nil {
		return fmt.Errorf("inspect candidate staging directory: %w", err)
	}
	parent := os.Getppid()
	observation, err := helperMigrationProcessObservation(paths, fs, parent)
	if err != nil {
		return err
	}
	observation.CandidateInfo, observation.StagingInfo = info, stage
	observation.CandidateOwned = fs.ownerOK(info)
	observation.StagingOwned = fs.ownerOK(stage)
	observation.CandidateArgv = append([]string(nil), os.Args...)
	spec := helperMigrationProbeSpec{
		CandidatePath:            executable,
		StagingDir:               paths.StagingDir,
		InstalledPath:            paths.InstalledPath,
		LockPath:                 paths.LockPath,
		ExpectedParentExecutable: paths.InstalledPath,
		ExpectedParentArgv:       []string{paths.InstalledPath, "apply"},
		ExpectedCandidateArgv:    []string{"shuttle-root", "--help"},
		ExpectedUID:              0,
	}
	if err := validateHelperMigrationProbe(spec, observation); err != nil {
		return err
	}
	candidateDigest, err := helperMigrationFileDigest(executable, info.Size())
	if err != nil {
		return fmt.Errorf("hash helper migration candidate: %w", err)
	}
	boot, err := readHelperMigrationBootID()
	if err != nil {
		return fmt.Errorf("read helper migration boot identity: %w", err)
	}
	host, err := rootHelperMigrationHostFingerprint()
	if err != nil {
		return err
	}
	own, err := readHelperMigrationOwnReservationProof(fs, paths)
	if err != nil {
		return err
	}
	var ownProof helperMigrationOwnReservationProof
	if own != nil {
		if own.CandidateSHA256 != candidateDigest || own.HostFingerprint != host || own.BootID != boot {
			return errors.New("helper-update own reservation proof does not match this candidate, host, or boot")
		}
		ownProof = *own
	}
	// The candidate must read closed writer inventories like the parent does.
	// A nil reader refused every host that had run one coordinated deploy: the
	// probe exited 78 inside init, and the installed helper only reported that
	// the candidate "does not expose the shuttle-root interface".
	if err := inspectRootHelperMigrationStateWithOwnReservation(paths, fs, readMigrationWriterProof, ownProof); err != nil {
		return err
	}
	source, err := rootHelperMigrationSource(paths.InstalledPath)
	if err != nil {
		return err
	}
	id, err := newHelperMigrationID()
	if err != nil {
		return err
	}
	probe := helperMigrationProbeProofFromObservation(spec, observation)
	intent := helperMigrationIntent{Schema: helperMigrationSchema, ID: id, Source: source, CandidateSHA256: candidateDigest, Host: host, BootID: boot, Phase: helperMigrationPhaseReady, Probe: probe}
	if current, err := readHelperMigrationIntent(fs, paths.IntentPath); err != nil {
		return err
	} else if current != nil {
		if current.Phase == helperMigrationPhaseComplete {
			if err := archiveCompletedHelperMigrationIntent(fs, paths, *current); err != nil {
				return err
			}
		} else if helperMigrationIntentRetryMatches(*current, intent) {
			if current.Phase == helperMigrationPhaseReplaced {
				if err := verifyHelperMigrationInstalledDigestWithFS(fs, paths.InstalledPath, candidateDigest); err != nil {
					return err
				}
			}
			return nil
		} else {
			return fmt.Errorf("helper migration intent %s is already %s and does not match this exact source, host, probe, or lock context", current.ID, current.Phase)
		}
	}
	if err := writeHelperMigrationIntent(fs, paths.IntentPath, intent); err != nil {
		return err
	}
	return nil
}

func rootHelperMigrationHostFingerprint() (string, error) {
	body, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return "", fmt.Errorf("read helper migration host identity: %w", err)
	}
	key, _, _, _, err := gossh.ParseAuthorizedKey(body)
	if err != nil {
		return "", fmt.Errorf("parse helper migration host identity: %w", err)
	}
	return gossh.FingerprintSHA256(key), nil
}

func validateHelperMigrationProbe(spec helperMigrationProbeSpec, observation helperMigrationProbeObservation) error {
	if spec.CandidatePath == "" || filepath.Clean(spec.CandidatePath) != spec.CandidatePath || filepath.Dir(spec.CandidatePath) != spec.StagingDir {
		return errors.New("helper migration candidate is outside the exact staging directory")
	}
	if filepath.Base(spec.CandidatePath) == "" || !strings.HasPrefix(filepath.Base(spec.CandidatePath), ".shuttle-root.next-") {
		return errors.New("helper migration candidate does not have the exact staging name")
	}
	if observation.StagingInfo == nil || !observation.StagingInfo.IsDir() || observation.StagingInfo.Mode()&os.ModeSymlink != 0 || observation.StagingInfo.Mode().Perm() != 0o755 || !observation.StagingOwned {
		return errors.New("helper migration staging directory is not root-owned mode 0755")
	}
	if observation.CandidateInfo == nil || !observation.CandidateInfo.Mode().IsRegular() || observation.CandidateInfo.Mode()&os.ModeSymlink != 0 || observation.CandidateInfo.Mode().Perm() != 0o755 || !observation.CandidateOwned {
		return errors.New("helper migration candidate is not a root-owned executable mode 0755")
	}
	if observation.ParentUID != spec.ExpectedUID || !slicesEqual(observation.ParentArgv, spec.ExpectedParentArgv) || observation.ParentExecutable != spec.ExpectedParentExecutable {
		return errors.New("helper migration probe parent is not the installed root helper apply process")
	}
	if !slicesEqual(spec.ExpectedCandidateArgv, []string{"shuttle-root", "--help"}) || !slicesEqual(observation.CandidateArgv, spec.ExpectedCandidateArgv) {
		return errors.New("helper migration probe candidate argv is not the pure help invocation")
	}
	if !observation.ParentHasLock || !observation.ParentLockInode {
		return errors.New("helper migration probe parent does not hold the installed root-operation lock")
	}
	return nil
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func rootHelperMigrationSource(path string) (string, error) {
	fs := newOSHelperMigrationFS()
	info, err := helperMigrationRegularRootFile(fs, path, 0o755, 32<<20)
	if err != nil {
		return "", err
	}
	digest, err := helperMigrationFileDigest(path, info.Size())
	if err != nil {
		return "", err
	}
	return path + "#" + digest, nil
}

func helperMigrationFileDigest(path string, max int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, max+1); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if max > 0 {
		if info, statErr := file.Stat(); statErr == nil && info.Size() > max {
			return "", errors.New("helper executable exceeds the digest limit")
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func helperMigrationIntentRetryMatches(current, desired helperMigrationIntent) bool {
	if current.Phase != helperMigrationPhaseReady && current.Phase != helperMigrationPhaseReplaced {
		return false
	}
	if current.Source != desired.Source || current.CandidateSHA256 != desired.CandidateSHA256 || current.Host != desired.Host {
		return false
	}
	if current.Probe == nil || desired.Probe == nil {
		return false
	}
	return reflect.DeepEqual(*current.Probe, *desired.Probe)
}

func archiveCompletedHelperMigrationIntent(fs helperMigrationFS, paths helperMigrationPaths, intent helperMigrationIntent) error {
	if intent.Phase != helperMigrationPhaseComplete {
		return errors.New("only a completed helper migration can be archived")
	}
	historyDir := paths.HistoryDir
	if historyDir == "" {
		historyDir = filepath.Join(filepath.Dir(paths.IntentPath), "history")
	}
	if filepath.Clean(historyDir) != filepath.Join(filepath.Dir(paths.IntentPath), "history") {
		return errors.New("helper migration history must remain under the active intent root")
	}
	if err := fs.mkdirAll(historyDir, 0o700); err != nil {
		return fmt.Errorf("create helper migration history directory: %w", err)
	}
	if err := helperMigrationDirectory(fs, historyDir, 0o700); err != nil {
		return fmt.Errorf("inspect helper migration history directory: %w", err)
	}
	archivePath := filepath.Join(historyDir, intent.ID+".json")
	if _, err := fs.lstat(archivePath); err == nil {
		archived, readErr := readHelperMigrationIntent(fs, archivePath)
		if readErr != nil {
			return fmt.Errorf("inspect archived helper migration %s: %w", intent.ID, readErr)
		}
		if archived == nil || !reflect.DeepEqual(*archived, intent) {
			return errors.New("helper migration history already contains different content for this ID")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect helper migration history: %w", err)
	} else if err := writeHelperMigrationIntent(fs, archivePath, intent); err != nil {
		return fmt.Errorf("archive completed helper migration: %w", err)
	}
	if err := fs.remove(paths.IntentPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove archived helper migration intent: %w", err)
	}
	if err := fs.syncDir(filepath.Dir(paths.IntentPath)); err != nil {
		return fmt.Errorf("sync helper migration intent directory after archive: %w", err)
	}
	return nil
}

func boundedHelperProbeDetail(text string) string {
	text = strings.ToValidUTF8(text, "\uFFFD")
	text = strings.Map(func(value rune) rune {
		if unicode.Is(unicode.C, value) {
			return ' '
		}
		return value
	}, text)
	text = strings.Join(strings.Fields(text), " ")
	if len(text) <= 240 {
		return text
	}
	for end := 240; end > 0; end-- {
		if text[end]&0xC0 != 0x80 {
			return text[:end]
		}
	}
	return ""
}

func helperMigrationProcessObservation(paths helperMigrationPaths, fs helperMigrationFS, pid int) (helperMigrationProbeObservation, error) {
	procRoot := "/proc"
	procPath := "self"
	if pid != os.Getpid() {
		procPath = strconv.Itoa(pid)
	}
	status, err := helperMigrationReadFile(fs, filepath.Join(procRoot, procPath, "status"), 16<<10)
	if err != nil {
		return helperMigrationProbeObservation{}, fmt.Errorf("read root helper process identity: %w", err)
	}
	uid, err := procEffectiveUID(status)
	if err != nil {
		return helperMigrationProbeObservation{}, err
	}
	stat, err := helperMigrationReadFile(fs, filepath.Join(procRoot, procPath, "stat"), 16<<10)
	if err != nil {
		return helperMigrationProbeObservation{}, fmt.Errorf("read root helper process birth identity: %w", err)
	}
	birth, err := procStartTime(stat)
	if err != nil {
		return helperMigrationProbeObservation{}, err
	}
	executable, err := fs.readlink(filepath.Join(procRoot, procPath, "exe"))
	if err != nil {
		return helperMigrationProbeObservation{}, fmt.Errorf("read root helper executable identity: %w", err)
	}
	argvBody, err := helperMigrationReadFile(fs, filepath.Join(procRoot, procPath, "cmdline"), 16<<10)
	if err != nil {
		return helperMigrationProbeObservation{}, fmt.Errorf("read root helper argv: %w", err)
	}
	lockHeld, sameInode, lockDevice, lockInode, err := helperMigrationLockProof(procRoot, pid, paths.LockPath, fs)
	if err != nil {
		return helperMigrationProbeObservation{}, err
	}
	return helperMigrationProbeObservation{ParentUID: uid, ParentPID: pid, ParentExecutable: executable, ParentArgv: procArgv(argvBody), ParentBirth: birth, ParentHasLock: lockHeld, ParentLockInode: sameInode, ParentLockDevice: lockDevice, ParentLockInodeNum: lockInode}, nil
}

func procEffectiveUID(status []byte) (uint32, error) {
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "Uid:" {
			uid, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				return 0, errors.New("parse root helper effective UID")
			}
			return uint32(uid), nil
		}
	}
	return 0, errors.New("root helper process UID is unavailable")
}

func procArgv(body []byte) []string {
	parts := strings.Split(string(bytes.TrimRight(body, "\x00")), "\x00")
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func helperMigrationLockHeldByProcess(procRoot string, pid int, lockPath string, fs helperMigrationFS) (bool, bool, error) {
	held, sameInode, _, _, err := helperMigrationLockProof(procRoot, pid, lockPath, fs)
	return held, sameInode, err
}

func helperMigrationLockProof(procRoot string, pid int, lockPath string, fs helperMigrationFS) (bool, bool, uint64, uint64, error) {
	lockInfo, err := fs.lstat(lockPath)
	if err != nil {
		return false, false, 0, 0, fmt.Errorf("inspect root-operation lock: %w", err)
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode()&os.ModeSymlink != 0 || lockInfo.Mode().Perm() != 0o600 || fs.ownerOK == nil || !fs.ownerOK(lockInfo) {
		return false, false, 0, 0, errors.New("root-operation lock is not a root-owned regular mode 0600 file")
	}
	lockStat, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false, 0, 0, errors.New("root-operation lock identity is unavailable")
	}
	entries, err := fs.readDir(filepath.Join(procRoot, strconv.Itoa(pid), "fd"))
	if err != nil {
		return false, false, 0, 0, fmt.Errorf("inspect root helper lock descriptors: %w", err)
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		fdPath := filepath.Join(procRoot, strconv.Itoa(pid), "fd", entry.Name())
		info, statErr := fs.stat(fdPath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return false, false, 0, 0, fmt.Errorf("inspect root helper lock descriptor %s: %w", entry.Name(), statErr)
		}
		fdStat, statOK := info.Sys().(*syscall.Stat_t)
		if !statOK || fdStat.Dev != lockStat.Dev || fdStat.Ino != lockStat.Ino {
			continue
		}
		fdInfo, readErr := helperMigrationReadFile(fs, filepath.Join(procRoot, strconv.Itoa(pid), "fdinfo", entry.Name()), 16<<10)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			return false, false, 0, 0, fmt.Errorf("read root-operation lock proof for descriptor %s: %w", entry.Name(), readErr)
		}
		if !procFlockProofMatches(string(fdInfo), pid, uint64(lockStat.Dev), uint64(lockStat.Ino)) {
			continue
		}
		return true, true, uint64(lockStat.Dev), uint64(lockStat.Ino), nil
	}
	return false, false, uint64(lockStat.Dev), uint64(lockStat.Ino), nil
}

func procFlockProofMatches(body string, pid int, device, inode uint64) bool {
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != "lock:" || fields[2] != "FLOCK" || fields[4] != "WRITE" {
			continue
		}
		owner, err := strconv.Atoi(fields[5])
		if err != nil || owner != pid {
			continue
		}
		major, minor, lockInode, err := parseProcLockDevice(fields[6])
		if err != nil || lockInode != inode {
			continue
		}
		return encodeLinuxDevice(major, minor) == device
	}
	return false
}

func parseProcLockDevice(value string) (uint64, uint64, uint64, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return 0, 0, 0, errors.New("invalid proc lock device")
	}
	major, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return 0, 0, 0, err
	}
	minor, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return 0, 0, 0, err
	}
	inode, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
	return major, minor, inode, nil
}

func encodeLinuxDevice(major, minor uint64) uint64 {
	return ((major & 0xfff) << 8) | (minor & 0xff) | ((minor & 0xffffff00) << 12)
}

func readHelperMigrationBootID() (string, error) {
	body, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	boot := strings.TrimSpace(string(body))
	if boot == "" || strings.ContainsAny(boot, "\x00\r\n") {
		return "", errors.New("invalid host boot identity")
	}
	return boot, nil
}

type helperMigrationProcess struct {
	PID              int
	Birth            string
	Executable       string
	Argv             []string
	ExecutableSHA256 string
}

func readHelperMigrationProcesses() ([]helperMigrationProcess, error) {
	return readHelperMigrationProcessesFromWithExpected("/proc", defaultHelperMigrationPaths().InstalledPath)
}

func readHelperMigrationProcessesFrom(procRoot string) ([]helperMigrationProcess, error) {
	return readHelperMigrationProcessesFromWithExpected(procRoot, defaultHelperMigrationPaths().InstalledPath)
}

func readHelperMigrationProcessesFromWithExpected(procRoot, expectedExecutable string) ([]helperMigrationProcess, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	processes := make([]helperMigrationProcess, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := filepath.Join(procRoot, entry.Name())
		executable, err := os.Readlink(filepath.Join(base, "exe"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read process %d executable identity: %w", pid, err)
		}
		executablePath := strings.TrimSuffix(executable, " (deleted)")
		if expectedExecutable != "" && executablePath != expectedExecutable {
			continue
		}
		stat, err := helperMigrationReadOSFile(filepath.Join(base, "stat"), 16<<10)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read process %d birth identity: %w", pid, err)
		}
		birth, err := procStartTime(stat)
		if err != nil {
			return nil, fmt.Errorf("read process %d birth identity: %w", pid, err)
		}
		argvBody, err := helperMigrationReadOSFile(filepath.Join(base, "cmdline"), 16<<10)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read process %d argv: %w", pid, err)
		}
		digest, err := helperMigrationFileDigest(filepath.Join(base, "exe"), helperMigrationMaxProcessBytes)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read process %d executable: %w", pid, err)
		}
		statAfter, err := helperMigrationReadOSFile(filepath.Join(base, "stat"), 16<<10)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("re-read process %d birth identity: %w", pid, err)
		}
		birthAfter, err := procStartTime(statAfter)
		if err != nil {
			return nil, fmt.Errorf("re-read process %d birth identity: %w", pid, err)
		}
		if birth != birthAfter {
			continue
		}
		processes = append(processes, helperMigrationProcess{PID: pid, Birth: birth, Executable: executable, Argv: procArgv(argvBody), ExecutableSHA256: digest})
	}
	return processes, nil
}

func helperMigrationReadOSFile(path string, max int64) ([]byte, error) {
	return helperMigrationReadFile(helperMigrationFS{open: os.OpenFile}, path, max)
}

func procStartTime(stat []byte) (string, error) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 || end+2 > len(stat) {
		return "", errors.New("parse process birth identity")
	}
	fields := strings.Fields(string(stat[end+2:]))
	if len(fields) <= 19 {
		return "", errors.New("process birth identity is incomplete")
	}
	return fields[19], nil
}

func helperMigrationSourceParts(source string) (string, string, error) {
	separator := strings.LastIndexByte(source, '#')
	if separator <= 0 || separator+1 >= len(source) {
		return "", "", errors.New("helper migration source lacks executable identity")
	}
	path, digest := source[:separator], source[separator+1:]
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !helperMigrationDigestPattern.MatchString(digest) {
		return "", "", errors.New("helper migration source executable identity is invalid")
	}
	return path, digest, nil
}

func oldHelperMigrationProcess(process helperMigrationProcess, intent helperMigrationIntent, currentPID int) bool {
	path, sourceDigest, err := helperMigrationSourceParts(intent.Source)
	if err != nil || process.PID == currentPID || process.Birth == "" || process.ExecutableSHA256 != sourceDigest || strings.TrimSuffix(process.Executable, " (deleted)") != path || !slicesEqual(process.Argv, []string{path, "apply"}) {
		return false
	}
	// If an update is byte-identical, a current generation process has the same
	// digest. The deleted executable identity still distinguishes the old
	// generation from the helper performing finalization.
	if sourceDigest == intent.CandidateSHA256 && !strings.HasSuffix(process.Executable, " (deleted)") {
		return false
	}
	return true
}

func drainOldHelperMigrationProcesses(ctx context.Context, intent helperMigrationIntent, currentPID int, list func() ([]helperMigrationProcess, error), now func() time.Time) error {
	deadline := now().Add(helperMigrationDrainTimeout)
	for {
		processes, err := list()
		if err != nil {
			return fmt.Errorf("inspect helper executors during migration: %w", err)
		}
		found := false
		for _, process := range processes {
			if oldHelperMigrationProcess(process, intent, currentPID) {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		if !now().Before(deadline) {
			return errors.New("old root helper executions did not drain before the migration deadline")
		}
		timer := time.NewTimer(helperMigrationPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type helperMigrationRuntime struct {
	fs          helperMigrationFS
	paths       helperMigrationPaths
	now         func() time.Time
	bootID      func() (string, error)
	currentPID  int
	listProcess func() ([]helperMigrationProcess, error)
	withLock    func(context.Context, time.Duration, func() error) error
	writerProof helperMigrationWriterProofReader
}

func defaultHelperMigrationRuntime() helperMigrationRuntime {
	paths := defaultHelperMigrationPaths()
	return helperMigrationRuntime{
		fs:          newOSHelperMigrationFS(),
		paths:       paths,
		now:         time.Now,
		bootID:      readHelperMigrationBootID,
		currentPID:  os.Getpid(),
		listProcess: readHelperMigrationProcesses,
		withLock: func(ctx context.Context, wait time.Duration, run func() error) error {
			return withHelperMigrationLock(ctx, paths.LockPath, wait, run)
		},
		writerProof: readMigrationWriterProof,
	}
}

func finalizeRootHelperMigration(ctx context.Context, request helperMigrationFinalizeRequest) error {
	return finalizeRootHelperMigrationWithRuntime(ctx, request, defaultHelperMigrationRuntime())
}

func finalizeRootHelperMigrationWithRuntime(ctx context.Context, request helperMigrationFinalizeRequest, runtime helperMigrationRuntime) error {
	runtime = normalizeHelperMigrationRuntime(runtime)
	if !helperMigrationDigestPattern.MatchString(request.CandidateSHA256) {
		return errors.New("helper migration finalization has an invalid candidate digest")
	}
	if request.PlanExpiresAt.IsZero() {
		return errors.New("signed helper migration finalization expiry is required")
	}
	intent, err := readHelperMigrationIntent(runtime.fs, runtime.paths.IntentPath)
	if err != nil {
		return err
	}
	if intent == nil {
		return errors.New("helper migration intent is missing; finalization cannot claim migration")
	}
	if intent.CandidateSHA256 != request.CandidateSHA256 || (request.Host != "" && intent.Host != request.Host) || (request.IntentID != "" && intent.ID != request.IntentID) {
		return errors.New("helper migration finalization does not match the immutable intent")
	}
	if _, _, err := helperMigrationSourceParts(intent.Source); err != nil {
		return err
	}
	if err := verifyHelperMigrationInstalledDigestWithFS(runtime.fs, runtime.paths.InstalledPath, request.CandidateSHA256); err != nil {
		return err
	}
	if intent.Phase != helperMigrationPhaseComplete {
		if err := drainOldHelperMigrationProcesses(ctx, *intent, runtime.currentPID, runtime.listProcess, runtime.now); err != nil {
			return err
		}
	}
	return runtime.withLock(ctx, helperMigrationLockWait, func() error {
		fresh, err := readHelperMigrationIntent(runtime.fs, runtime.paths.IntentPath)
		if err != nil {
			return err
		}
		if fresh == nil || fresh.ID != intent.ID || fresh.Source != intent.Source || fresh.CandidateSHA256 != intent.CandidateSHA256 || fresh.Host != intent.Host || fresh.BootID != intent.BootID {
			return errors.New("helper migration intent changed during finalization")
		}
		if !runtime.now().Before(request.PlanExpiresAt) {
			return errors.New("signed helper migration finalization expired while waiting for the lock")
		}
		if request.Validate != nil {
			if err := request.Validate(); err != nil {
				return fmt.Errorf("revalidate signed helper migration finalization: %w", err)
			}
		}
		boot, err := runtime.bootID()
		if err != nil {
			return fmt.Errorf("read helper migration boot identity after drain: %w", err)
		}
		if boot != fresh.BootID {
			return errors.New("host boot identity changed during helper migration")
		}
		if err := inspectRootHelperMigrationStateWithWriterReader(runtime.paths, runtime.fs, runtime.writerProof); err != nil {
			return err
		}
		if err := verifyHelperMigrationInstalledDigestWithFS(runtime.fs, runtime.paths.InstalledPath, request.CandidateSHA256); err != nil {
			return err
		}
		if fresh.Phase == helperMigrationPhaseComplete {
			return nil
		}
		if fresh.Phase == helperMigrationPhaseReady {
			if err := markHelperMigrationPhase(runtime.fs, runtime.paths.IntentPath, request.CandidateSHA256, helperMigrationPhaseReplaced); err != nil {
				return fmt.Errorf("record helper migration replacement: %w", err)
			}
		}
		if err := markHelperMigrationPhase(runtime.fs, runtime.paths.IntentPath, request.CandidateSHA256, helperMigrationPhaseComplete); err != nil {
			return fmt.Errorf("record helper migration completion: %w", err)
		}
		return nil
	})
}

func normalizeHelperMigrationRuntime(runtime helperMigrationRuntime) helperMigrationRuntime {
	defaults := defaultHelperMigrationRuntime()
	if runtime.fs.lstat == nil {
		runtime.fs = defaults.fs
	}
	if runtime.paths.IntentPath == "" {
		runtime.paths = defaults.paths
	}
	if runtime.now == nil {
		runtime.now = defaults.now
	}
	if runtime.bootID == nil {
		runtime.bootID = defaults.bootID
	}
	if runtime.currentPID == 0 {
		runtime.currentPID = defaults.currentPID
	}
	if runtime.listProcess == nil {
		runtime.listProcess = defaults.listProcess
	}
	if runtime.withLock == nil {
		runtime.withLock = defaults.withLock
	}
	return runtime
}

func reconcileRootHelperMigration(ctx context.Context, request helperMigrationReconcileRequest) error {
	return reconcileRootHelperMigrationWithRuntime(ctx, request, defaultHelperMigrationRuntime())
}

func reconcileRootHelperMigrationWithRuntime(ctx context.Context, request helperMigrationReconcileRequest, runtime helperMigrationRuntime) error {
	runtime = normalizeHelperMigrationRuntime(runtime)
	if !helperMigrationDigestPattern.MatchString(request.CandidateSHA256) {
		return errors.New("helper migration reconciliation has an invalid candidate digest")
	}
	if request.PlanExpiresAt.IsZero() || request.Validate == nil {
		return errors.New("signed helper migration reconciliation expiry and validator are required")
	}
	intent, err := readHelperMigrationIntent(runtime.fs, runtime.paths.IntentPath)
	if err != nil {
		return err
	}
	if intent == nil {
		return errors.New("helper migration intent is missing; reconciliation cannot claim migration")
	}
	if intent.CandidateSHA256 != request.CandidateSHA256 || (request.Host != "" && intent.Host != request.Host) || (request.IntentID != "" && intent.ID != request.IntentID) {
		return errors.New("helper migration reconciliation does not match the immutable intent")
	}
	return runtime.withLock(ctx, helperMigrationLockWait, func() error {
		fresh, err := readHelperMigrationIntent(runtime.fs, runtime.paths.IntentPath)
		if err != nil {
			return err
		}
		if fresh == nil || fresh.ID != intent.ID || fresh.Source != intent.Source || fresh.CandidateSHA256 != intent.CandidateSHA256 || fresh.Host != intent.Host || fresh.BootID != intent.BootID {
			return errors.New("helper migration intent changed during reconciliation")
		}
		if !runtime.now().Before(request.PlanExpiresAt) {
			return errors.New("signed helper migration reconciliation expired while waiting for the lock")
		}
		if err := request.Validate(); err != nil {
			return fmt.Errorf("revalidate signed helper migration reconciliation: %w", err)
		}
		boot, err := runtime.bootID()
		if err != nil {
			return fmt.Errorf("read helper migration boot identity during reconciliation: %w", err)
		}
		if boot == fresh.BootID {
			return errors.New("helper migration reconciliation requires an observed host boot change")
		}
		if err := verifyHelperMigrationInstalledDigestWithFS(runtime.fs, runtime.paths.InstalledPath, request.CandidateSHA256); err != nil {
			return err
		}
		if err := inspectRootHelperMigrationStateWithWriterReader(runtime.paths, runtime.fs, runtime.writerProof); err != nil {
			return err
		}
		if fresh.Phase != helperMigrationPhaseComplete {
			if err := drainOldHelperMigrationProcesses(ctx, *fresh, runtime.currentPID, runtime.listProcess, runtime.now); err != nil {
				return err
			}
		}
		fresh.BootID = boot
		fresh.History = appendBoundedHelperMigrationHistory(fresh.History, helperMigrationHistoryItem{
			At: runtime.now().UTC().Format(time.RFC3339Nano), Action: "reconcile-boot-change", Detail: "verified boot, installed candidate, coordinator journal, and operation writers under the migration lock",
		})
		if err := writeHelperMigrationIntentAfterBootChange(runtime.fs, runtime.paths.IntentPath, *fresh); err != nil {
			return fmt.Errorf("record helper migration reconciliation: %w", err)
		}
		if fresh.Phase == helperMigrationPhaseReady {
			if err := markHelperMigrationPhase(runtime.fs, runtime.paths.IntentPath, request.CandidateSHA256, helperMigrationPhaseReplaced); err != nil {
				return fmt.Errorf("record reconciled helper migration replacement: %w", err)
			}
		}
		if err := markHelperMigrationPhase(runtime.fs, runtime.paths.IntentPath, request.CandidateSHA256, helperMigrationPhaseComplete); err != nil {
			return fmt.Errorf("record reconciled helper migration completion: %w", err)
		}
		return nil
	})
}

func appendBoundedHelperMigrationHistory(history []helperMigrationHistoryItem, item helperMigrationHistoryItem) []helperMigrationHistoryItem {
	history = append(append([]helperMigrationHistoryItem(nil), history...), item)
	if len(history) > helperMigrationHistoryLimit {
		history = history[len(history)-helperMigrationHistoryLimit:]
	}
	return history
}

func verifyHelperMigrationInstalledDigest(path, want string) error {
	fs := newOSHelperMigrationFS()
	return verifyHelperMigrationInstalledDigestWithFS(fs, path, want)
}

func verifyHelperMigrationInstalledDigestWithFS(fs helperMigrationFS, path, want string) error {
	info, err := helperMigrationRegularRootFile(fs, path, 0o755, 32<<20)
	if err != nil {
		return fmt.Errorf("inspect installed root helper: %w", err)
	}
	got, err := helperMigrationFileDigest(path, info.Size())
	if err != nil {
		return fmt.Errorf("hash installed root helper: %w", err)
	}
	if got != want {
		return fmt.Errorf("installed root helper digest %s does not match migration candidate %s", got, want)
	}
	return nil
}

func withHelperMigrationLock(ctx context.Context, path string, wait time.Duration, run func() error) error {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open helper migration lock: %w", err)
	}
	defer lock.Close()
	started := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			return run()
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("take helper migration lock: %w", err)
		}
		if time.Since(started) >= wait {
			return fmt.Errorf("helper migration lock remained busy after waiting %s", time.Since(started).Round(time.Millisecond))
		}
		timer := time.NewTimer(helperMigrationPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func helperMigrationMutationBlocked(action string) bool {
	switch action {
	case "audit", "operations-status", "recovery-plan", "helper-migration-finalize", "helper-migration-reconcile":
		return false
	default:
		return true
	}
}

func refuseRootHelperMutationDuringMigration(action string) error {
	return refuseRootHelperMutationDuringMigrationWithRuntime(action, defaultHelperMigrationRuntime())
}

func refuseRootHelperMutationDuringMigrationWithRuntime(action string, runtime helperMigrationRuntime) error {
	if !helperMigrationMutationBlocked(action) {
		return nil
	}
	intent, err := readHelperMigrationIntent(runtime.fs, runtime.paths.IntentPath)
	if err != nil {
		return fmt.Errorf("inspect helper migration before %s: %w", action, err)
	}
	if intent != nil && intent.Phase != helperMigrationPhaseComplete {
		return fmt.Errorf("root helper mutation %s is refused while migration %s is %s", action, intent.ID, intent.Phase)
	}
	return nil
}

func rootHelperMigrationCapabilitiesReady() error {
	intent, err := readHelperMigrationIntent(newOSHelperMigrationFS(), defaultHelperMigrationPaths().IntentPath)
	if err != nil {
		return err
	}
	if intent != nil && intent.Phase != helperMigrationPhaseComplete {
		return fmt.Errorf("root helper capability advertisement is withheld while migration %s is %s", intent.ID, intent.Phase)
	}
	return nil
}

const rootHelperProbeTimeout = 30 * time.Second

var errHelperProbeInterrupted = errors.New("candidate probe interrupted")
var errHelperProbeUnconfirmed = errors.New("candidate termination is unconfirmed")

// The root lock used to cover an unbounded Run, including pipes inherited by
// children. Keep the leader unreaped until its group has been killed: killing
// a negative PID after Wait could target a newly reused process group instead.
// No process inventory is scanned, and an escaped pipe holder is reported.
func runHelperProbeCommandContext(ctx context.Context, path string) ([]byte, bool, error) {
	return runHelperCandidateCommandContext(ctx, path, "shuttle-root", "--help")
}

func runHelperCandidateCommandContext(ctx context.Context, path, argv0, argument string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rootHelperProbeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, false, errors.Join(errHelperProbeInterrupted, err)
	}
	deadline, _ := ctx.Deadline()
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, false, err
	}
	defer reader.Close()
	defer writer.Close()
	command := exec.Command(path, argument)
	command.Args[0] = argv0
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Until(deadline)
	command.Stdout, command.Stderr = writer, writer
	if err := command.Start(); err != nil {
		return nil, false, err
	}
	_ = writer.Close()
	type capture struct {
		output limitedDebugOutput
		err    error
	}
	collected := make(chan capture, 1)
	go func() {
		result := capture{output: limitedDebugOutput{limit: 64 << 10}}
		_, result.err = io.Copy(&result.output, reader)
		collected <- result
	}()
	// Reserve part of the SAME deadline for SIGKILL and reaping, not an extra
	// timeout after it. Even a kernel-blocked leader cannot hold the root lock.
	remaining := time.Until(deadline)
	stop := time.NewTimer(remaining - min(time.Second, remaining/10))
	defer stop.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	var probeErr error
	exited := false
observing:
	for {
		var info unix.Siginfo
		waitErr := unix.Waitid(unix.P_PID, command.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if waitErr != nil && !errors.Is(waitErr, unix.EINTR) {
			probeErr = errors.Join(errHelperProbeInterrupted, fmt.Errorf("observe candidate exit: %w", waitErr))
			break
		}
		if info.Signo != 0 {
			exited = true
			break
		}
		select {
		case <-stop.C:
			probeErr = errors.Join(errHelperProbeInterrupted, context.DeadlineExceeded)
			break observing
		case <-ctx.Done():
			probeErr = errors.Join(errHelperProbeInterrupted, ctx.Err())
			break observing
		case <-poll.C:
		}
	}
	// Clean up the group on every exit, including a leader killed by a signal
	// and a successful leader that left children holding stdout or stderr.
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		probeErr = errors.Join(probeErr, errHelperProbeInterrupted, fmt.Errorf("kill candidate group: %w", err))
	}
	if !exited {
		if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			probeErr = errors.Join(probeErr, errHelperProbeInterrupted, fmt.Errorf("kill candidate leader: %w", err))
		}
	}
	// Reaping does not depend on group cleanup succeeding. If the kernel has
	// not delivered SIGKILL by the deadline, the reaper remains responsible for
	// this child but the caller releases its lock and reports unconfirmed exit.
	reaped := make(chan error, 1)
	go func() { reaped <- command.Wait() }()
	select {
	case waitErr := <-reaped:
		probeErr = errors.Join(probeErr, waitErr)
	case <-ctx.Done():
		return nil, false, errors.Join(probeErr, errHelperProbeInterrupted, ctx.Err(), errHelperProbeUnconfirmed, errors.New("candidate exit unconfirmed; manual process recovery required"))
	}
	select {
	case result := <-collected:
		return result.output.body, result.output.truncated, errors.Join(probeErr, result.err)
	case <-ctx.Done():
		// Closing our reader releases collection even if a setsid descendant kept
		// the writer. Hunting unrelated processes would itself be unbounded.
		return nil, false, errors.Join(probeErr, errHelperProbeInterrupted, ctx.Err(), errHelperProbeUnconfirmed, errors.New("candidate output still open; a descendant may have escaped its process group; manual process recovery required"))
	}
}

func runHelperProbeWithRetries(ctx context.Context, path string, run func(context.Context, string) ([]byte, bool, error)) ([]byte, bool, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, false, errors.Join(errHelperProbeInterrupted, err)
		}
		body, truncated, err := run(ctx, path)
		if !errors.Is(err, syscall.ETXTBSY) || attempt == 9 {
			return body, truncated, err
		}
		retry := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			retry.Stop()
			return body, truncated, errors.Join(errHelperProbeInterrupted, ctx.Err())
		case <-retry.C:
		}
	}
}

func helperProbeFailure(err error, body []byte) error {
	return helperProbeFailureWithFS(err, body, newOSHelperMigrationFS(), defaultHelperMigrationPaths())
}

func helperProbeFailureWithFS(err error, body []byte, fs helperMigrationFS, paths helperMigrationPaths) error {
	detail := boundedHelperProbeDetail(err.Error() + " " + string(body))
	var exitErr *exec.ExitError
	signaled := errors.As(err, &exitErr) && exitErr.ProcessState.Sys().(syscall.WaitStatus).Signaled()
	if !errors.Is(err, errHelperProbeInterrupted) && !signaled {
		return fmt.Errorf("replacement binary does not expose the shuttle-root interface: %s", detail)
	}
	reason := "candidate probe failed"
	if errors.Is(err, context.DeadlineExceeded) {
		reason = fmt.Sprintf("candidate probe timed out (total limit %s)", rootHelperProbeTimeout)
	}
	message := reason + ": " + detail
	// A signal is not a timeout, and an interrupted probe may not have written
	// any intent. Report only the state actually read, never inferred evidence.
	intent, readErr := readHelperMigrationIntent(fs, paths.IntentPath)
	switch {
	case readErr != nil:
		message += "; cannot read migration intent at " + paths.IntentPath
	case intent != nil:
		message += fmt.Sprintf("; migration intent %s is %s at %s", intent.ID, intent.Phase, paths.IntentPath)
	default:
		message += "; no migration intent exists"
	}
	message += "; see docs/operations-recovery.md#interrupted-helper-probe"
	if errors.Is(err, errHelperProbeUnconfirmed) {
		return fmt.Errorf("%s: %w", message, errHelperProbeUnconfirmed)
	}
	return errors.New(message)
}

func helperProbeFailureBeforeReplacement(proof helperMigrationOwnReservationProof, probeErr error, fs helperMigrationFS, paths helperMigrationPaths) error {
	// This hook runs inside the probe callback, before replaceRootHelper can
	// rename anything. An absent or previously completed intent permits clearing
	// this exact admission once the leader is reaped and output pipes close.
	// This does not prove that no silent detached descendant survives. An
	// unconfirmed leader or open pipe keeps the fence for administrator review.
	if errors.Is(probeErr, errHelperProbeUnconfirmed) {
		return probeErr
	}
	intent, err := readHelperMigrationIntent(fs, paths.IntentPath)
	if err != nil {
		return errors.Join(probeErr, err)
	}
	if intent != nil && intent.Phase != helperMigrationPhaseComplete {
		return fmt.Errorf("helper migration intent remains pending: %w", probeErr)
	}
	if err := clearHelperMigrationOwnReservationWithFS(proof, fs, paths); err != nil {
		return errors.Join(probeErr, err)
	}
	rootLog("helper probe failed before replacement; admission cleared operation=%s", proof.OperationID)
	if _, known := probeErr.(*coord.KnownOutcomeError); known {
		return probeErr
	}
	return fmt.Errorf("helper replacement was not attempted: %w", probeErr)
}
