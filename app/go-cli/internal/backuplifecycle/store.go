package backuplifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
)

const (
	DefaultRoot    = "/var/lib/shuttle/backups"
	statusFileName = "status.json"
)

var (
	nowUTC      = func() time.Time { return time.Now().UTC() }
	syncFile    = func(file *os.File) error { return file.Sync() }
	syncDirFile = func(file *os.File) error { return file.Sync() }
)

// Store persists the root-owned journal. Root is injectable for isolated
// tests, while production uses the fixed host path and never a workstation
// result directory.
type Store struct {
	Root string
}

func (store Store) root() string {
	if store.Root == "" {
		return DefaultRoot
	}
	return store.Root
}

func (store Store) Path(app string) string {
	return filepath.Join(store.root(), app, "status.json")
}

func (store Store) Load(app string) (Journal, error) {
	if err := validateApp(app); err != nil {
		return Journal{}, err
	}
	appRoot, err := store.openAppRoot(app, false)
	if err != nil {
		return Journal{}, err
	}
	defer appRoot.Close()
	return readJournal(appRoot)
}

func (store Store) Apply(status Status) error {
	if err := Validate(status); err != nil {
		return err
	}
	if err := validateApp(status.App); err != nil {
		return err
	}
	appRoot, err := store.openAppRoot(status.App, true)
	if err != nil {
		return err
	}
	defer appRoot.Close()
	journal, err := readJournal(appRoot)
	if errors.Is(err, os.ErrNotExist) {
		journal = Journal{Schema: JournalSchema, App: status.App}
	} else if err != nil {
		return err
	}
	updated, err := applyStatus(journal, status, nowUTC())
	if err != nil {
		return err
	}
	if reflect.DeepEqual(updated, journal) {
		// A previous BEGIN may have renamed status.json then failed the
		// directory fsync. Returning success here without syncing would
		// acknowledge durable publication that never happened.
		return syncExistingJournal(appRoot)
	}
	body, err := marshalJournal(updated)
	if err != nil {
		return err
	}
	if status.Phase == PhaseSource && len(body) > MaxJournalBytes-journalWriteReserve {
		return errors.New("backup lifecycle journal lacks capacity for a later receipt update")
	}
	return writeJournalRoot(appRoot, body)
}

func applyStatus(journal Journal, status Status, received time.Time) (Journal, error) {
	if journal.Schema == "" {
		journal.Schema = JournalSchema
	}
	if journal.App == "" {
		journal.App = status.App
	}
	if journal.Schema != JournalSchema || journal.App != status.App {
		return Journal{}, errors.New("backup lifecycle journal belongs to another application")
	}
	if journal.LatestAttempt != nil && len(journal.AdmittedAttempts) == 0 {
		if journal.LatestAttemptOrder == 0 {
			journal.LatestAttemptOrder = 1
		}
		journal.AdmittedAttempts = []AttemptAdmission{{AttemptID: journal.LatestAttempt.AttemptID, Order: journal.LatestAttemptOrder}}
	}
	if order, found := admissionOrder(journal, status.AttemptID); found {
		if journal.LatestAttempt == nil || journal.LatestAttempt.AttemptID != status.AttemptID || journal.LatestAttemptOrder != order {
			return Journal{}, errors.New("superseded backup attempt cannot be replayed")
		}
		if *journal.LatestAttempt == status {
			return journal, nil
		}
		if err := ValidateTransition(*journal.LatestAttempt, status); err != nil {
			return Journal{}, err
		}
		journal.LatestAttempt = cloneStatus(status)
		journal.LatestAttemptReceived = received.Format(time.RFC3339Nano)
	} else {
		if status.Phase != PhaseSource {
			return Journal{}, errors.New("unknown backup attempt cannot start after begin")
		}
		if attemptWasAdmitted(journal, status.AttemptID) {
			return Journal{}, errors.New("superseded backup attempt cannot be replayed")
		}
		nextOrder := journal.LatestAttemptOrder + 1
		if nextOrder == 0 {
			nextOrder = 1
		}
		journal.LatestAttempt = cloneStatus(status)
		journal.LatestAttemptOrder = nextOrder
		journal.LatestAttemptReceived = received.Format(time.RFC3339Nano)
		journal.AdmittedAttempts = append(append([]AttemptAdmission{}, journal.AdmittedAttempts...), AttemptAdmission{AttemptID: status.AttemptID, Order: nextOrder})
		compactAdmittedAttempts(&journal)
	}
	if LocalArtifactSuccess(status) && status.State != StateFailed {
		journal.LastSuccess = cloneStatus(status)
		journal.LastSuccessReceived = received.Format(time.RFC3339Nano)
	}
	return journal, nil
}

func admissionOrder(journal Journal, attemptID string) (uint64, bool) {
	for _, admission := range journal.AdmittedAttempts {
		if admission.AttemptID == attemptID {
			return admission.Order, true
		}
	}
	return 0, false
}

func attemptWasAdmitted(journal Journal, attemptID string) bool {
	if _, found := admissionOrder(journal, attemptID); found {
		return true
	}
	hash := attemptIDHash(attemptID)
	for _, existing := range journal.CompactedAttemptHashes {
		if existing == hash {
			return true
		}
	}
	return false
}

func attemptIDHash(attemptID string) string {
	sum := sha256.Sum256([]byte(attemptID))
	return hex.EncodeToString(sum[:compactedAttemptHashLen/2])
}

func compactAdmittedAttempts(journal *Journal) {
	if journal == nil || len(journal.AdmittedAttempts) <= maxAdmittedAttempts {
		return
	}
	drop := len(journal.AdmittedAttempts) - maxRetainedAdmissions
	if drop <= 0 {
		return
	}
	seen := map[string]bool{}
	for _, existing := range journal.CompactedAttemptHashes {
		seen[existing] = true
	}
	for _, admission := range journal.AdmittedAttempts[:drop] {
		hash := attemptIDHash(admission.AttemptID)
		if seen[hash] {
			continue
		}
		journal.CompactedAttemptHashes = append(journal.CompactedAttemptHashes, hash)
		seen[hash] = true
	}
	journal.AdmittedAttempts = append([]AttemptAdmission{}, journal.AdmittedAttempts[drop:]...)
}

func syncExistingJournal(root *os.Root) error {
	if err := rejectUnsafeExisting(root, statusFileName); err != nil {
		return err
	}
	file, err := root.OpenFile(statusFileName, os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	syncErr := syncFile(file)
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return syncRoot(root)
}

func cloneStatus(status Status) *Status {
	copy := status
	return &copy
}

func marshalJournal(journal Journal) ([]byte, error) {
	if err := ValidateJournal(journal); err != nil {
		return nil, err
	}
	body, err := jsonMarshal(journal)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxJournalBytes {
		return nil, errors.New("backup lifecycle journal exceeds the size limit")
	}
	return append(body, '\n'), nil
}

func writeJournalRoot(root *os.Root, body []byte) error {
	return writeAtomicRoot(root, statusFileName, body, MaxJournalBytes)
}

// WriteStatusFile stores a local lifecycle sidecar with the same fsync and
// rename discipline as the remote journal. It does not grant any meaning to
// the workstation file; the collector reads the root-owned Store instead.
func WriteStatusFile(path string, body []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dirRoot, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	defer dirRoot.Close()
	return writeAtomicRoot(dirRoot, filepath.Base(absolute), body, MaxStatusBytes)
}

func writeAtomicRoot(root *os.Root, name string, body []byte, limit int) error {
	if name == "" || strings.Contains(name, string(filepath.Separator)) || name == "." || name == ".." {
		return errors.New("backup lifecycle file name is unsafe")
	}
	if len(body) == 0 || len(body) > limit {
		return errors.New("backup lifecycle file exceeds the size limit")
	}
	if err := rejectUnsafeExisting(root, name); err != nil {
		return err
	}
	temporaryName := fmt.Sprintf(".status.%d.tmp", nowUTC().UnixNano())
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	good := false
	previousName := ""
	defer func() {
		_ = temporary.Close()
		if !good {
			_ = root.Remove(temporaryName)
		}
		if previousName != "" {
			_ = root.Remove(previousName)
		}
	}()
	if info, statErr := root.Lstat(name); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !ownerAllowed(info) {
			return errors.New("backup lifecycle journal is not a bounded regular file")
		}
		previousName = fmt.Sprintf(".status.previous.%d", nowUTC().UnixNano())
		if err := root.Link(name, previousName); err != nil {
			return err
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		return err
	}
	if err := syncFile(temporary); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return err
	}
	if err := syncRoot(root); err != nil {
		if previousName != "" {
			if restoreErr := root.Rename(previousName, name); restoreErr == nil {
				previousName = ""
				_ = syncRoot(root)
			}
		}
		return err
	}
	if previousName != "" {
		if err := root.Remove(previousName); err != nil {
			return err
		}
		previousName = ""
	}
	good = true
	return nil
}

func rejectUnsafeExisting(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownerAllowed(info) {
		return errors.New("backup lifecycle journal is not a bounded regular file")
	}
	return nil
}

func readJournal(root *os.Root) (Journal, error) {
	body, err := readPrivateRegularRoot(root, statusFileName, MaxJournalBytes)
	if err != nil {
		return Journal{}, err
	}
	return DecodeJournal(body)
}

func readPrivateRegularRoot(root *os.Root, name string, limit int) ([]byte, error) {
	if err := rejectUnsafeExisting(root, name); err != nil {
		return nil, err
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownerAllowed(info) || info.Size() > int64(limit) {
		return nil, errors.New("backup lifecycle journal is not a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(body) > limit {
		return nil, errors.New("backup lifecycle journal read exceeded the size limit")
	}
	return body, nil
}

func (store Store) openAppRoot(app string, create bool) (*os.Root, error) {
	if err := validateApp(app); err != nil {
		return nil, err
	}
	storeRoot, err := store.openStoreRoot(create)
	if err != nil {
		return nil, err
	}
	defer storeRoot.Close()
	return openNamedDir(storeRoot, app, create)
}

func (store Store) openStoreRoot(create bool) (*os.Root, error) {
	cleanRoot := filepath.Clean(store.root())
	if cleanRoot == "." || !filepath.IsAbs(cleanRoot) {
		return nil, errors.New("backup lifecycle root must be absolute")
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || untrustedDir(info) {
		root.Close()
		return nil, errors.New("backup lifecycle path has an unsafe ancestor")
	}
	parts := strings.Split(strings.TrimPrefix(cleanRoot, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			root.Close()
			return nil, errors.New("backup lifecycle path has an unsafe ancestor")
		}
		child, statErr := root.Lstat(part)
		if os.IsNotExist(statErr) {
			if !create {
				root.Close()
				return nil, os.ErrNotExist
			}
			next, createErr := createTrustedChild(root, part)
			root.Close()
			if createErr != nil {
				return nil, createErr
			}
			root = next
			continue
		}
		if statErr != nil {
			root.Close()
			return nil, statErr
		}
		if untrustedDir(child) {
			root.Close()
			return nil, errors.New("backup lifecycle path has an unsafe ancestor")
		}
		next, openErr := root.OpenRoot(part)
		if openErr != nil {
			root.Close()
			return nil, openErr
		}
		opened, openedErr := next.Lstat(".")
		if openedErr != nil || untrustedDir(opened) || !sameInode(child, opened) {
			next.Close()
			root.Close()
			return nil, errors.New("backup lifecycle path has an unsafe ancestor")
		}
		root.Close()
		root = next
	}
	return root, nil
}

func createTrustedChild(parent *os.Root, name string) (*os.Root, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, string(filepath.Separator)) {
		return nil, errors.New("backup lifecycle path has an unsafe ancestor")
	}
	if info, err := parent.Lstat(name); err == nil {
		if untrustedDir(info) {
			return nil, errors.New("backup lifecycle path has an unsafe ancestor")
		}
		if err := syncRoot(parent); err != nil {
			return nil, err
		}
		return parent.OpenRoot(name)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := parent.Mkdir(name, 0o700); err != nil {
		return nil, err
	}
	if err := parent.Chmod(name, 0o700); err != nil {
		return nil, err
	}
	if err := syncRoot(parent); err != nil {
		return nil, err
	}
	info, err := parent.Lstat(name)
	if err != nil || untrustedDir(info) {
		return nil, errors.New("backup lifecycle path has an unsafe ancestor")
	}
	return parent.OpenRoot(name)
}

func openNamedDir(parent *os.Root, name string, create bool) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if os.IsNotExist(err) {
		if !create {
			return nil, os.ErrNotExist
		}
		return createTrustedChild(parent, name)
	}
	if err != nil {
		return nil, err
	}
	if untrustedDir(info) {
		return nil, errors.New("backup lifecycle application directory is unsafe")
	}
	if create {
		if err := syncRoot(parent); err != nil {
			return nil, err
		}
	}
	return parent.OpenRoot(name)
}

func syncRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return syncDirFile(file)
}

func untrustedDir(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != euid {
		return true
	}
	if info.Mode().Perm()&0o022 != 0 {
		if stat.Uid == 0 && info.Mode()&os.ModeSticky != 0 {
			return false
		}
		return true
	}
	return false
}

func ownerAllowed(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	euid := uint32(os.Geteuid())
	if euid == 0 {
		return stat.Uid == 0
	}
	return stat.Uid == euid
}

func sameInode(left, right os.FileInfo) bool {
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK {
		return false
	}
	return leftStat.Dev == rightStat.Dev && leftStat.Ino == rightStat.Ino
}

func validateApp(app string) error {
	if !appPattern.MatchString(app) {
		return errors.New("invalid backup lifecycle application")
	}
	return nil
}

// jsonMarshal is a variable so tests can inject a bounded serialization
// failure without touching a live backup or remote filesystem.
var jsonMarshal = func(value any) ([]byte, error) { return json.Marshal(value) }
