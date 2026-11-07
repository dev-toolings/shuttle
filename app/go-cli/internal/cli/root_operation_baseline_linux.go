//go:build linux

package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"golang.org/x/sys/unix"
)

const (
	rootOperationBaselineDirName     = "baselines"
	rootOperationBaselineMaxBytes    = 4 << 20
	rootOperationBackupReplicaFile   = "backup-replicas.json"
	rootOperationBackupReplicaSchema = "shuttle.backup-replica-proof/v1"
)

var (
	rootOperationBaselineArchiveRoot = coord.DefaultRoot
	rootOperationBaselineSourceRoot  = rootAppStateRoot

	rootOperationBaselineIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	rootOperationBaselineHashPattern = regexp.MustCompile(`^(?:sha256:)?[a-f0-9]{64}$`)
)

// preserveRootOperationBaselineArtifacts copies the bounded current.yml and
// previous.yml bytes observed for this operation into a root-only archive
// bound to the operation UUID. It must run before writers are admitted.
// Archives are never removed here: recovery may still need them after the
// live slots rotate.
func preserveRootOperationBaselineArtifacts(operationID, app string, baseline operationwriters.Baseline) error {
	return preserveRootOperationBaselineArtifactsAt(rootOperationBaselineArchiveRoot, rootOperationBaselineSourceRoot, operationID, app, baseline)
}

func preserveRootOperationBaselineArtifactsAt(archiveRoot, sourceRoot, operationID, app string, baseline operationwriters.Baseline) error {
	if err := validateBaselineOperationID(operationID); err != nil {
		return err
	}
	if err := validateBaselineArtifact(baseline.Current); err != nil {
		return err
	}
	if err := validateBaselineArtifact(baseline.Previous); err != nil {
		return err
	}
	current, err := loadRootOperationBaselineSource(sourceRoot, app, "current", baseline.Current)
	if err != nil {
		return err
	}
	previous, err := loadRootOperationBaselineSource(sourceRoot, app, "previous", baseline.Previous)
	if err != nil {
		return err
	}
	if current == nil && previous == nil {
		return ensureAbsentBaselineArchive(archiveRoot, operationID, true, true)
	}
	dir, err := openRootOperationBaselineDir(archiveRoot, operationID, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := publishRootOperationBaselineFile(dir, "current.yml", current); err != nil {
		return err
	}
	if err := publishRootOperationBaselineFile(dir, "previous.yml", previous); err != nil {
		return err
	}
	return nil
}

// readRootOperationBaselineArtifact returns the durable bytes archived for
// one allowlisted role. It authenticates the operation UUID, role, captured
// presence bit, archive type, size and SHA-256, then fails closed.
func readRootOperationBaselineArtifact(operationID, role string, artifact operationwriters.BaselineArtifact) ([]byte, error) {
	return readRootOperationBaselineArtifactAt(rootOperationBaselineArchiveRoot, operationID, role, artifact)
}

func readRootOperationBaselineArtifactAt(archiveRoot, operationID, role string, artifact operationwriters.BaselineArtifact) ([]byte, error) {
	if err := validateBaselineOperationID(operationID); err != nil {
		return nil, err
	}
	filename, err := rootOperationBaselineFilename(role)
	if err != nil {
		return nil, err
	}
	if err := validateBaselineArtifact(artifact); err != nil {
		return nil, err
	}
	dir, err := openRootOperationBaselineDir(archiveRoot, operationID, false)
	if err != nil {
		if os.IsNotExist(err) && !artifact.Present {
			return nil, nil
		}
		if os.IsNotExist(err) {
			return nil, errors.New("archived baseline is missing")
		}
		return nil, err
	}
	defer dir.Close()
	if !artifact.Present {
		if err := refusePresentBaselineFile(dir, filename); err != nil {
			return nil, err
		}
		return nil, nil
	}
	body, err := readRootOperationBaselineFile(dir, filename)
	if err != nil {
		return nil, err
	}
	if !sameRootOperationBaselineDigest(rootOperationBaselineDigest(body), artifact.FullSHA256) {
		return nil, errors.New("archived baseline digest does not match the captured artifact")
	}
	return body, nil
}

func loadRootOperationBaselineSource(sourceRoot, app, role string, artifact operationwriters.BaselineArtifact) ([]byte, error) {
	if !artifact.Present {
		return nil, nil
	}
	filename, err := rootOperationBaselineFilename(role)
	if err != nil {
		return nil, err
	}
	path, err := allowlistedBaselineSourcePath(sourceRoot, app, filename)
	if err != nil {
		return nil, err
	}
	body, observed, err := readRootOperationBaselineSource(path)
	if err != nil {
		return nil, err
	}
	if !observed.Present {
		return nil, errors.New("captured baseline is missing from its source")
	}
	if !sameRootOperationBaselineDigest(observed.FullSHA256, artifact.FullSHA256) {
		return nil, errors.New("source baseline digest does not match the captured artifact")
	}
	return body, nil
}

func allowlistedBaselineSourcePath(sourceRoot, app, filename string) (string, error) {
	if sourceRoot == "" || !rootAppName.MatchString(app) || (filename != "current.yml" && filename != "previous.yml") {
		return "", errors.New("operation baseline path is not allowlisted")
	}
	root := filepath.Clean(sourceRoot)
	path := filepath.Clean(filepath.Join(root, app, filename))
	if path != filepath.Join(root, app, filename) || !baselinePathWithin(root, path) || filepath.Base(path) != filename {
		return "", errors.New("operation baseline path is not allowlisted")
	}
	return path, nil
}

func baselinePathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return true
}

func readRootOperationBaselineSource(path string) ([]byte, operationwriters.BaselineArtifact, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if os.IsNotExist(err) {
		return nil, operationwriters.BaselineArtifact{}, nil
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, operationwriters.BaselineArtifact{}, errors.New("operation baseline source is a symlink")
		}
		return nil, operationwriters.BaselineArtifact{}, err
	}
	file := os.NewFile(uintptr(fd), "baseline-source")
	defer file.Close()
	return readBoundedBaselineRegular(file, "operation baseline source", false)
}

func readWriterBaselineArtifact(path string) (operationwriters.BaselineArtifact, error) {
	_, artifact, err := readRootOperationBaselineSource(path)
	return artifact, err
}

func validateBaselineOperationID(operationID string) error {
	if !rootOperationBaselineIDPattern.MatchString(operationID) || strings.ContainsAny(operationID, "/\\.") {
		return errors.New("invalid operation baseline identifier")
	}
	return nil
}

func rootOperationBaselineFilename(role string) (string, error) {
	switch role {
	case "current":
		return "current.yml", nil
	case "previous":
		return "previous.yml", nil
	default:
		return "", errors.New("invalid operation baseline role")
	}
}

func validateBaselineArtifact(artifact operationwriters.BaselineArtifact) error {
	if artifact.Present == (artifact.FullSHA256 == "") {
		return errors.New("captured baseline presence and digest disagree")
	}
	if artifact.Present && !rootOperationBaselineHashPattern.MatchString(artifact.FullSHA256) {
		return errors.New("captured baseline digest is not a full sha256")
	}
	return nil
}

func rootOperationBaselineDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sameRootOperationBaselineDigest(got, want string) bool {
	if !rootOperationBaselineHashPattern.MatchString(got) || !rootOperationBaselineHashPattern.MatchString(want) {
		return false
	}
	return strings.TrimPrefix(got, "sha256:") == strings.TrimPrefix(want, "sha256:")
}

func ensureAbsentBaselineArchive(archiveRoot, operationID string, current, previous bool) error {
	dir, err := openRootOperationBaselineDir(archiveRoot, operationID, false)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer dir.Close()
	if current {
		if err := refusePresentBaselineFile(dir, "current.yml"); err != nil {
			return err
		}
	}
	if previous {
		if err := refusePresentBaselineFile(dir, "previous.yml"); err != nil {
			return err
		}
	}
	return nil
}

func openRootOperationBaselineDir(archiveRoot, operationID string, create bool) (*os.File, error) {
	if err := validateBaselineOperationID(operationID); err != nil {
		return nil, err
	}
	root := filepath.Clean(archiveRoot)
	if root == "" || root == "." || strings.ContainsRune(root, 0) {
		return nil, errors.New("operation baseline archive root is not allowlisted")
	}
	dirPath := filepath.Join(root, rootOperationBaselineDirName, operationID)
	if filepath.Clean(dirPath) != dirPath || !baselinePathWithin(root, dirPath) {
		return nil, errors.New("operation baseline archive path is not allowlisted")
	}
	if create {
		if err := ensurePrivateBaselineDirectory(root, true); err != nil {
			return nil, err
		}
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, mapBaselineDirOpenError(err)
	}
	defer unix.Close(rootFD)
	baselinesFD, err := openPrivateBaselineDirAt(rootFD, rootOperationBaselineDirName, create)
	if err != nil {
		return nil, err
	}
	defer unix.Close(baselinesFD)
	dirFD, err := openPrivateBaselineDirAt(baselinesFD, operationID, create)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(dirFD), dirPath)
	if err := validatePrivateBaselineDirectory(dir); err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

func openPrivateBaselineDirAt(parentFD int, name string, create bool) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	if errors.Is(err, unix.ENOENT) {
		if !create {
			return -1, os.ErrNotExist
		}
		if err := unix.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
		if err := unix.Fsync(parentFD); err != nil {
			return -1, fmt.Errorf("sync baseline archive parent: %w", err)
		}
		fd, err = unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	}
	if err != nil {
		return -1, mapBaselineDirOpenError(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return -1, errors.New("operation baseline archive is not a private directory")
	}
	if create {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if err := unix.Fsync(fd); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("sync baseline archive directory: %w", err)
		}
	} else if stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("operation baseline archive is not a private directory")
	}
	return fd, nil
}

func mapBaselineDirOpenError(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return os.ErrNotExist
	}
	if errors.Is(err, unix.ELOOP) {
		return errors.New("operation baseline archive is a symlink")
	}
	if errors.Is(err, unix.ENOTDIR) {
		return errors.New("operation baseline archive is not a private directory")
	}
	return err
}

func ensurePrivateBaselineDirectory(path string, create bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if !create {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		if err := syncBaselineDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
		if err != nil {
			return err
		}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("operation baseline archive is not a private directory")
	}
	if create {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	} else if info.Mode().Perm()&0o077 != 0 {
		return errors.New("operation baseline archive is not a private directory")
	}
	return syncBaselineDirectory(path)
}

func validatePrivateBaselineDirectory(dir *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("operation baseline archive is not a private directory")
	}
	if stat.Mode&0o077 != 0 {
		return errors.New("operation baseline archive is not a private directory")
	}
	return nil
}

func publishRootOperationBaselineFile(dir *os.File, name string, body []byte) error {
	if body == nil {
		return refusePresentBaselineFile(dir, name)
	}
	if len(body) > rootOperationBaselineMaxBytes {
		return errors.New("archived baseline exceeds the bounded size")
	}
	existing, err := readRootOperationBaselineFile(dir, name)
	if err == nil {
		if bytes.Equal(existing, body) {
			return nil
		}
		return errors.New("archived baseline already exists with different content")
	}
	if !os.IsNotExist(err) && !errors.Is(err, errBaselineArchiveMissing) {
		return err
	}
	return writeRootOperationBaselineFile(dir, name, body)
}

func refusePresentBaselineFile(dir *os.File, name string) error {
	_, err := readRootOperationBaselineFile(dir, name)
	if err == nil {
		return errors.New("absent baseline role must stay absent")
	}
	if os.IsNotExist(err) || errors.Is(err, errBaselineArchiveMissing) {
		return nil
	}
	return err
}

var errBaselineArchiveMissing = errors.New("archived baseline is missing")

func writeRootOperationBaselineFile(dir *os.File, name string, body []byte) error {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("randomize baseline archive temporary name: %w", err)
	}
	tmpName := fmt.Sprintf(".%s.%s.tmp", name, hex.EncodeToString(random[:]))
	fd, err := unix.Openat(int(dir.Fd()), tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0o600)
	if err != nil {
		return fmt.Errorf("create baseline archive temporary: %w", err)
	}
	file := os.NewFile(uintptr(fd), tmpName)
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = unix.Unlinkat(int(dir.Fd()), tmpName, 0)
		}
	}()
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return fmt.Errorf("write baseline archive: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync baseline archive: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close baseline archive: %w", err)
	}
	if err := unix.Renameat(int(dir.Fd()), tmpName, int(dir.Fd()), name); err != nil {
		return fmt.Errorf("publish baseline archive: %w", err)
	}
	removeTemp = false
	if err := fileSyncDir(dir); err != nil {
		return fmt.Errorf("sync baseline archive directory: %w", err)
	}
	return nil
}

func readRootOperationBaselineFile(dir *os.File, name string) ([]byte, error) {
	if name != "current.yml" && name != "previous.yml" {
		return nil, errors.New("invalid operation baseline role")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, errBaselineArchiveMissing
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.New("archived baseline is a symlink")
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	body, artifact, err := readBoundedBaselineRegular(file, "archived baseline", true)
	if err != nil {
		return nil, err
	}
	if !artifact.Present {
		return nil, errBaselineArchiveMissing
	}
	return body, nil
}

func readBoundedBaselineRegular(file *os.File, label string, requirePrivate bool) ([]byte, operationwriters.BaselineArtifact, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, operationwriters.BaselineArtifact{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, operationwriters.BaselineArtifact{}, fmt.Errorf("%s is not a bounded regular file", label)
	}
	if requirePrivate && stat.Mode&0o077 != 0 {
		return nil, operationwriters.BaselineArtifact{}, fmt.Errorf("%s permissions are not restrictive", label)
	}
	if stat.Size < 0 || stat.Size > rootOperationBaselineMaxBytes {
		return nil, operationwriters.BaselineArtifact{}, fmt.Errorf("%s is not a bounded regular file", label)
	}
	body, err := io.ReadAll(io.LimitReader(file, rootOperationBaselineMaxBytes+1))
	if err != nil || int64(len(body)) > rootOperationBaselineMaxBytes || int64(len(body)) != stat.Size {
		return nil, operationwriters.BaselineArtifact{}, fmt.Errorf("%s cannot be read within the bounded size", label)
	}
	return body, operationwriters.BaselineArtifact{Present: true, FullSHA256: rootOperationBaselineDigest(body)}, nil
}

func syncBaselineDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	return fileSyncDir(file)
}

func fileSyncDir(dir *os.File) error {
	return dir.Sync()
}

type rootOperationBackupReplicaProof struct {
	Schema      string         `json:"schema"`
	OperationID string         `json:"operation_id"`
	App         string         `json:"app"`
	Replicas    map[string]int `json:"replicas"`
}

// preserveRootOperationBackupReplicaProof stores captured replica targets before
// the pending marker is unlinked. A crash after unlink would otherwise leave
// recovery with no scale map and a healthy-looking empty stack.
func preserveRootOperationBackupReplicaProof(operationID, app string, replicas map[string]int) error {
	return preserveRootOperationBackupReplicaProofAt(rootOperationBaselineArchiveRoot, operationID, app, replicas)
}

func readRootOperationBackupReplicaProof(operationID string) (map[string]int, error) {
	return readRootOperationBackupReplicaProofAt(rootOperationBaselineArchiveRoot, operationID)
}

func preserveRootOperationBackupReplicaProofAt(archiveRoot, operationID, app string, replicas map[string]int) error {
	if err := validateBaselineOperationID(operationID); err != nil {
		return err
	}
	if !rootAppName.MatchString(app) {
		return errors.New("invalid backup replica proof application")
	}
	if err := validateBackupReplicaMap(app, replicas); err != nil {
		return err
	}
	body, err := json.Marshal(rootOperationBackupReplicaProof{
		Schema: rootOperationBackupReplicaSchema, OperationID: operationID, App: app, Replicas: copyReplicaMap(replicas),
	})
	if err != nil {
		return err
	}
	dir, err := openRootOperationBaselineDir(archiveRoot, operationID, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	existing, err := readRootOperationNamedFile(dir, rootOperationBackupReplicaFile)
	if err == nil {
		var got rootOperationBackupReplicaProof
		if json.Unmarshal(existing, &got) == nil && got.Schema == rootOperationBackupReplicaSchema && got.OperationID == operationID && got.App == app && replicaMapsEqual(got.Replicas, replicas) {
			return nil
		}
		return errors.New("archived backup replica proof already exists with different content")
	}
	if !os.IsNotExist(err) && !errors.Is(err, errBaselineArchiveMissing) {
		return err
	}
	return writeRootOperationBaselineFile(dir, rootOperationBackupReplicaFile, append(body, '\n'))
}

func readRootOperationBackupReplicaProofAt(archiveRoot, operationID string) (map[string]int, error) {
	if err := validateBaselineOperationID(operationID); err != nil {
		return nil, err
	}
	dir, err := openRootOperationBaselineDir(archiveRoot, operationID, false)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer dir.Close()
	body, err := readRootOperationNamedFile(dir, rootOperationBackupReplicaFile)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, errBaselineArchiveMissing) {
			return nil, nil
		}
		return nil, err
	}
	var proof rootOperationBackupReplicaProof
	if err := json.Unmarshal(body, &proof); err != nil {
		return nil, errors.New("archived backup replica proof is invalid")
	}
	if proof.Schema != rootOperationBackupReplicaSchema || proof.OperationID != operationID {
		return nil, errors.New("archived backup replica proof identity does not match")
	}
	if err := validateBackupReplicaMap(proof.App, proof.Replicas); err != nil {
		return nil, err
	}
	return copyReplicaMap(proof.Replicas), nil
}

func readRootOperationNamedFile(dir *os.File, name string) ([]byte, error) {
	if name != "current.yml" && name != "previous.yml" && name != rootOperationBackupReplicaFile {
		return nil, errors.New("invalid operation baseline role")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, errBaselineArchiveMissing
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.New("archived baseline is a symlink")
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	body, artifact, err := readBoundedBaselineRegular(file, "archived baseline", true)
	if err != nil {
		return nil, err
	}
	if !artifact.Present {
		return nil, errBaselineArchiveMissing
	}
	return body, nil
}

func validateBackupReplicaMap(app string, replicas map[string]int) error {
	if len(replicas) == 0 {
		return errors.New("backup replica proof is empty")
	}
	for service, count := range replicas {
		if !rootServiceName.MatchString(service) || !strings.HasPrefix(service, app+"_") || count < 0 || count > 1000 {
			return errors.New("backup replica proof contains an unsafe service or replica count")
		}
	}
	return nil
}
