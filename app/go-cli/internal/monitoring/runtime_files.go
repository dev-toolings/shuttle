package monitoring

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxMaintenanceBytes = 64 << 10
	maxRuntimeReadBytes = 1 << 20
	runtimeFileMode     = os.FileMode(0o600)
	runtimeDirMode      = os.FileMode(0o700)
	archiveFileName     = "incidents-archive.jsonl"
	maxActiveEpisodes   = 256
)

// runtimeDirectory is an opened directory descriptor. Every operation on a
// runtime file is relative to this descriptor, so a later ancestor rename
// cannot redirect the operation to a different directory tree.
type runtimeDirectory struct {
	root *os.Root
}

func (d *runtimeDirectory) Close() error {
	if d == nil || d.root == nil {
		return nil
	}
	err := d.root.Close()
	d.root = nil
	return err
}

func runtimeUID() uint32 {
	return uint32(os.Geteuid())
}

func fileUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func isRootOwnedStickyTemp(info os.FileInfo) bool {
	uid, ok := fileUID(info)
	if !ok || uid != 0 || info.Mode()&os.ModeSticky == 0 {
		return false
	}
	return info.Mode().Perm()&0o022 != 0
}

func validateRuntimeDirectoryInfo(info os.FileInfo, final bool) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("monitoring runtime directory is not a regular directory")
	}
	uid, ok := fileUID(info)
	if !ok {
		return errors.New("monitoring runtime directory owner could not be verified")
	}
	currentUID := runtimeUID()
	perm := info.Mode().Perm()
	if final {
		if uid != currentUID {
			return errors.New("monitoring runtime directory has an unexpected owner")
		}
		if perm&0o077 != 0 {
			return errors.New("monitoring runtime directory is not private")
		}
		return nil
	}
	if uid != 0 && uid != currentUID {
		return errors.New("monitoring runtime directory has an unexpected owner")
	}
	if perm&0o022 != 0 {
		if isRootOwnedStickyTemp(info) {
			return nil
		}
		return errors.New("monitoring runtime directory is writable by group or others")
	}
	return nil
}

func validateRuntimeFileInfo(info os.FileInfo, expectedUID uint32) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("monitoring runtime file must be a regular file")
	}
	uid, ok := fileUID(info)
	if !ok || uid != expectedUID {
		return errors.New("monitoring runtime file has an unexpected owner")
	}
	if info.Mode().Perm() != runtimeFileMode.Perm() {
		return errors.New("monitoring runtime file must have mode 0600")
	}
	return nil
}

func openRuntimeDirectory(path string, create bool) (*runtimeDirectory, error) {
	return openRuntimeDirectoryMode(path, create, true)
}

// openSecretParentDirectory opens the directory of a root secret file. Runtime
// state needs a private final directory, but setup creates /etc/shuttle as a
// root-owned 0755 directory and the documented webhook secret lives there. The
// live recette showed every such secret refused as an unavailable channel. A
// root-owned parent that nobody else can write still prevents a file swap; the
// 0600 file mode keeps the URL private.
func openSecretParentDirectory(path string) (*runtimeDirectory, error) {
	return openRuntimeDirectoryMode(path, false, false)
}

func openRuntimeDirectoryMode(path string, create, privateFinal bool) (*runtimeDirectory, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("monitoring runtime directory must be an absolute clean path")
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := validateRuntimeDirectoryInfo(rootInfo, false); err != nil {
		_ = root.Close()
		return nil, err
	}
	current := &runtimeDirectory{root: root}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = current.Close()
			return nil, errors.New("monitoring runtime directory contains an unsafe component")
		}
		info, statErr := current.root.Lstat(part)
		if os.IsNotExist(statErr) && create {
			statErr = current.root.Mkdir(part, 0o700)
			if os.IsExist(statErr) {
				statErr = nil
			}
			if statErr == nil {
				info, statErr = current.root.Lstat(part)
			}
		}
		if os.IsNotExist(statErr) && !create {
			_ = current.Close()
			return nil, statErr
		}
		if statErr != nil {
			_ = current.Close()
			return nil, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, errors.New("monitoring runtime directory contains a symlink")
		}
		nextRoot, openErr := current.root.OpenRoot(part)
		if openErr != nil {
			_ = current.Close()
			return nil, openErr
		}
		next := &runtimeDirectory{root: nextRoot}
		openedInfo, infoErr := next.root.Stat(".")
		if infoErr != nil {
			_ = next.Close()
			_ = current.Close()
			return nil, infoErr
		}
		isFinal := index == len(parts)-1
		if create && isFinal {
			uid, uidOK := fileUID(openedInfo)
			if uidOK && uid == runtimeUID() && openedInfo.Mode().Perm()&0o077 != 0 {
				file, chmodErr := next.root.Open(".")
				if chmodErr == nil {
					chmodErr = file.Chmod(runtimeDirMode)
					closeErr := file.Close()
					chmodErr = errors.Join(chmodErr, closeErr)
				}
				if chmodErr != nil {
					_ = next.Close()
					_ = current.Close()
					return nil, chmodErr
				}
				openedInfo, infoErr = next.root.Stat(".")
				if infoErr != nil {
					_ = next.Close()
					_ = current.Close()
					return nil, infoErr
				}
			}
		}
		if err := validateRuntimeDirectoryInfo(openedInfo, isFinal && privateFinal); err != nil {
			_ = next.Close()
			_ = current.Close()
			return nil, err
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func ensurePrivateDirectory(directory string) error {
	root, err := openRuntimeDirectory(directory, true)
	if err != nil {
		return err
	}
	return root.Close()
}

func validateExistingPath(path string, rootOwned bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("monitoring runtime path must be an absolute clean path")
	}
	directory, err := openRuntimeDirectory(filepath.Dir(path), false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	info, err := directory.root.Lstat(filepath.Base(path))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("monitoring runtime path must not be a symlink")
	}
	uid, ok := fileUID(info)
	if !ok || (rootOwned && uid != 0) || (!rootOwned && uid != runtimeUID()) {
		return errors.New("monitoring runtime path has an unexpected owner")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != runtimeFileMode.Perm() {
		return errors.New("monitoring runtime path must be a private regular file")
	}
	return nil
}

func openRuntimeFile(directory *runtimeDirectory, name string, flags int, perm os.FileMode, expectedUID uint32, setMode bool) (*os.File, error) {
	if directory == nil || directory.root == nil || name == "" || filepath.Base(name) != name {
		return nil, errors.New("monitoring runtime file name is unsafe")
	}
	file, err := directory.root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
	if err != nil {
		return nil, err
	}
	if setMode {
		if err := file.Chmod(runtimeFileMode); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateRuntimeFileInfo(info, expectedUID); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func readBoundedFile(file *os.File, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("monitoring runtime read limit is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("monitoring runtime file exceeds the read limit")
	}
	return body, nil
}

func readCollectorPath(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("monitoring collector path is empty")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("monitoring collector path must be a regular file")
	}
	return readBoundedFile(file, limit)
}

func readRuntimePath(path string, limit int64, expectedUID uint32, createDirectory bool) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("monitoring runtime path must be an absolute clean path")
	}
	directory, err := openRuntimeDirectory(filepath.Dir(path), createDirectory)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	file, err := openRuntimeFile(directory, filepath.Base(path), os.O_RDONLY, runtimeFileMode, expectedUID, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBoundedFile(file, limit)
}

func readBoundedNoFollow(path string, limit int64) ([]byte, error) {
	return readRuntimePath(path, limit, runtimeUID(), false)
}

func readRootSecret(path string, limit int64) ([]byte, error) {
	return readRuntimePath(path, limit, 0, false)
}

func runtimeTempName() (string, error) {
	var random [12]byte
	if _, err := crand.Read(random[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf(".incidents-%s.partial", hexBytes(random[:])), nil
}

func hexBytes(value []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, current := range value {
		result[index*2] = hex[current>>4]
		result[index*2+1] = hex[current&0x0f]
	}
	return string(result)
}

var (
	runtimeWrite         = func(file *os.File, body []byte) (int, error) { return file.Write(body) }
	runtimeSync          = func(file *os.File) error { return file.Sync() }
	runtimeRename        = func(root *os.Root, oldName, newName string) error { return root.Rename(oldName, newName) }
	runtimeDirectorySync = func(root *os.Root) error {
		file, err := root.Open(".")
		if err != nil {
			return err
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		return errors.Join(syncErr, closeErr)
	}
)

type saveProgress struct {
	started atomic.Bool
	renamed atomic.Bool
}

func (p *saveProgress) markStarted() {
	if p != nil {
		p.started.Store(true)
	}
}

func (p *saveProgress) markRenamed() {
	if p != nil {
		p.renamed.Store(true)
	}
}

func (p *saveProgress) timeoutError() error {
	if p != nil && (p.started.Load() || p.renamed.Load()) {
		return ErrPersistenceUnconfirmed
	}
	return ErrTransactionTimeout
}

func saveIncidentState(ctx context.Context, directory *runtimeDirectory, statePath string, state IncidentState, progress *saveProgress) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if state.Schema == "" {
		state.Schema = incidentSchema
	}
	if state.Incidents == nil {
		state.Incidents = map[string]Incident{}
	}
	if state.Episodes == nil {
		state.Episodes = map[string]Incident{}
	}
	if state.Pending == nil {
		state.Pending = []AlertEvent{}
	}
	if err := archiveCompletedEpisodes(directory, &state); err != nil {
		return err
	}
	if len(state.Episodes) > maxActiveEpisodes {
		return errors.New("monitoring incident episode history exceeds the bound")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data := append(body, '\n')
	if int64(len(data)) > maxIncidentStateBytes {
		return errors.New("monitoring incident state exceeds the read limit")
	}
	if info, statErr := directory.root.Lstat(statePath); statErr == nil {
		if err := validateRuntimeFileInfo(info, runtimeUID()); err != nil {
			return err
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	var temporary *os.File
	var temporaryName string
	for attempt := 0; attempt < 16; attempt++ {
		temporaryName, err = runtimeTempName()
		if err != nil {
			return err
		}
		temporary, err = openRuntimeFile(directory, temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, runtimeFileMode, runtimeUID(), true)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if temporary == nil {
		return errors.New("could not create a unique monitoring state temporary file")
	}
	committed := false
	defer func() {
		if !committed {
			_ = directory.root.Remove(temporaryName)
		}
	}()
	progress.markStarted()
	if written, writeErr := runtimeWrite(temporary, data); writeErr != nil {
		_ = temporary.Close()
		return writeErr
	} else if written != len(data) {
		_ = temporary.Close()
		return io.ErrShortWrite
	}
	if err := runtimeSync(temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := runtimeRename(directory.root, temporaryName, statePath); err != nil {
		return err
	}
	committed = true
	progress.markRenamed()
	return runtimeDirectorySync(directory.root)
}

func episodeFullyAcknowledged(incident Incident, pending []AlertEvent) bool {
	if incident.CheckID == "" || incident.EpisodeID == "" || incident.State != StateRecovered || !incident.IncidentSent || !incident.RecoverySent || incident.RecoveryPending {
		return false
	}
	return !hasPendingEpisode(pending, incident, "incident") && !hasPendingEpisode(pending, incident, "recovery")
}

func archiveCompletedEpisodes(directory *runtimeDirectory, state *IncidentState) error {
	if state.Episodes == nil {
		return nil
	}
	existing, err := loadArchivedEpisodeKeys(directory)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(state.Episodes))
	for key := range state.Episodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	archived := make([]Incident, 0, len(keys))
	remaining := map[string]Incident{}
	for _, key := range keys {
		incident := state.Episodes[key]
		archiveKey := episodeKey(incident.CheckID, incident.EpisodeID)
		if _, already := existing[archiveKey]; already && episodeFullyAcknowledged(incident, state.Pending) {
			continue
		}
		if episodeFullyAcknowledged(incident, state.Pending) {
			archived = append(archived, incident)
			existing[archiveKey] = struct{}{}
			continue
		}
		remaining[key] = incident
	}
	if len(archived) == 0 {
		state.Episodes = remaining
		return nil
	}
	if err := appendArchivedEpisodes(directory, archived); err != nil {
		return err
	}
	state.Episodes = remaining
	return nil
}

func loadArchivedEpisodeKeys(directory *runtimeDirectory) (map[string]struct{}, error) {
	keys := map[string]struct{}{}
	file, err := openRuntimeFile(directory, archiveFileName, os.O_RDONLY, runtimeFileMode, runtimeUID(), false)
	if os.IsNotExist(err) {
		return keys, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), int(maxRuntimeReadBytes))
	for scanner.Scan() {
		var record struct {
			CheckID   string `json:"check_id"`
			EpisodeID string `json:"episode_id"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil || record.CheckID == "" || record.EpisodeID == "" {
			return nil, errors.New("monitoring incident archive is unreadable")
		}
		keys[episodeKey(record.CheckID, record.EpisodeID)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func appendArchivedEpisodes(directory *runtimeDirectory, episodes []Incident) error {
	file, err := openRuntimeFile(directory, archiveFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, runtimeFileMode, runtimeUID(), true)
	if err != nil {
		return err
	}
	for _, episode := range episodes {
		record := map[string]any{
			"check_id":      episode.CheckID,
			"episode_id":    episode.EpisodeID,
			"state":         episode.State,
			"first_seen":    episode.FirstSeen,
			"last_seen":     episode.LastSeen,
			"incident_sent": episode.IncidentSent,
			"recovery_sent": episode.RecoverySent,
		}
		line, marshalErr := json.Marshal(record)
		if marshalErr != nil {
			_ = file.Close()
			return marshalErr
		}
		data := append(line, '\n')
		if written, writeErr := file.Write(data); writeErr != nil {
			_ = file.Close()
			return writeErr
		} else if written != len(data) {
			_ = file.Close()
			return io.ErrShortWrite
		}
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr)
}

type fileStoreSession struct {
	directory *runtimeDirectory
	lockFile  *os.File
	statePath string
	progress  *saveProgress
}

func (s *fileStoreSession) Close() error {
	if s == nil {
		return nil
	}
	var unlockErr, closeErr, directoryErr error
	if s.lockFile != nil {
		unlockErr = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
		closeErr = s.lockFile.Close()
		s.lockFile = nil
	}
	if s.directory != nil {
		directoryErr = s.directory.Close()
		s.directory = nil
	}
	return errors.Join(unlockErr, closeErr, directoryErr)
}

func (s *fileStoreSession) Load(ctx context.Context) (IncidentState, error) {
	if err := ctx.Err(); err != nil {
		return IncidentState{}, err
	}
	file, err := openRuntimeFile(s.directory, s.statePath, os.O_RDONLY, runtimeFileMode, runtimeUID(), false)
	if os.IsNotExist(err) {
		return emptyIncidentState(), nil
	}
	if err != nil {
		return IncidentState{}, err
	}
	defer file.Close()
	body, err := readBoundedFile(file, maxIncidentStateBytes)
	if err != nil {
		return IncidentState{}, err
	}
	return decodeIncidentState(body)
}

func (s *fileStoreSession) Save(ctx context.Context, state IncidentState) error {
	progress := (*saveProgress)(nil)
	if s != nil {
		progress = s.progress
	}
	return saveIncidentState(ctx, s.directory, s.statePath, state, progress)
}

func (s FileStore) begin(ctx context.Context) (*fileStoreSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateStatePath(s.Path); err != nil {
		return nil, err
	}
	directory, err := openRuntimeDirectory(filepath.Dir(s.Path), true)
	if err != nil {
		return nil, err
	}
	lockName := filepath.Base(s.Path) + ".lock"
	lockFile, err := openRuntimeFile(directory, lockName, os.O_RDWR|os.O_CREATE, runtimeFileMode, runtimeUID(), true)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	deadline := time.Now().Add(maxLockWait)
	for {
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return &fileStoreSession{directory: directory, lockFile: lockFile, statePath: filepath.Base(s.Path), progress: &saveProgress{}}, nil
		}
		if err := ctx.Err(); err != nil {
			_ = lockFile.Close()
			_ = directory.Close()
			return nil, err
		}
		if !time.Now().Before(deadline) {
			_ = lockFile.Close()
			_ = directory.Close()
			return nil, errors.New("monitoring incident lock is busy")
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = lockFile.Close()
			_ = directory.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
