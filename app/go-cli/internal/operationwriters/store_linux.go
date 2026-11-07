//go:build linux

package operationwriters

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type writerDir struct {
	root    *os.File
	writers *os.File
}

func openWriterDir(rootPath string) (*writerDir, error) {
	return openWriterDirMode(rootPath, true)
}

func openWriterDirMode(rootPath string, create bool) (*writerDir, error) {
	if err := validateRootAncestors(rootPath); err != nil {
		return nil, err
	}
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
	}
	rootFD, err := openTrustedDirectory(rootPath, how)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%w: writer root contains a symlink or non-directory", ErrInvalidState)
		}
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w: root directory %q does not exist", ErrNotFound, rootPath)
		}
		return nil, fmt.Errorf("open writer root: %w", err)
	}
	root := os.NewFile(uintptr(rootFD), rootPath)
	if err := validateDirectoryFile(root); err != nil {
		_ = root.Close()
		return nil, err
	}

	writersFD, err := unix.Openat(rootFD, "writers", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		if !create {
			_ = root.Close()
			return nil, fmt.Errorf("%w: writer directory does not exist", ErrNotFound)
		}
		if err := unix.Mkdirat(rootFD, "writers", 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = root.Close()
			return nil, fmt.Errorf("create writer directory: %w", err)
		}
		writersFD, err = unix.Openat(rootFD, "writers", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		_ = root.Close()
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%w: writer directory is a symlink or non-directory", ErrInvalidState)
		}
		return nil, fmt.Errorf("open writer directory: %w", err)
	}
	writers := os.NewFile(uintptr(writersFD), filepath.Join(rootPath, "writers"))
	if err := validatePrivateDirectoryFile(writers); err != nil {
		_ = writers.Close()
		_ = root.Close()
		return nil, err
	}
	return &writerDir{root: root, writers: writers}, nil
}

func openTrustedDirectory(rootPath string, how *unix.OpenHow) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, rootPath, how)
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) {
		return fd, err
	}
	abs, absErr := filepath.Abs(rootPath)
	if absErr != nil {
		return -1, absErr
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.ToSlash(abs), "/"), "/") {
		if component == "" || component == "." {
			continue
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
	}
	return current, nil
}

func validateRootAncestors(rootPath string) error {
	if strings.IndexByte(rootPath, 0) >= 0 {
		return fmt.Errorf("%w: writer root contains a NUL byte", ErrInvalidState)
	}
	for _, component := range strings.FieldsFunc(filepath.ToSlash(rootPath), func(r rune) bool { return r == '/' }) {
		if component == ".." {
			return fmt.Errorf("%w: writer root may not contain a parent traversal", ErrInvalidState)
		}
	}
	abs, err := filepath.Abs(rootPath)
	if err != nil {
		return fmt.Errorf("%w: resolve writer root: %v", ErrInvalidState, err)
	}
	for path := filepath.Dir(abs); path != "." && path != filepath.Dir(path); path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: writer ancestor %q does not exist", ErrNotFound, path)
			}
			return fmt.Errorf("stat writer ancestor: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: writer ancestor %q is a symlink", ErrInvalidState, path)
		}
		// A caller supplied test root normally lives directly below the
		// system temporary directory. That directory is an explicit fixture
		// boundary; every directory above and beside it must be non-writable.
		if info.Mode().Perm()&0o022 != 0 && path != filepath.Clean(os.TempDir()) && path != "/tmp" {
			return fmt.Errorf("%w: writer ancestor %q is foreign-writable", ErrInvalidState, path)
		}
	}
	return nil
}

func (d *writerDir) Close() error {
	var first error
	if d.writers != nil {
		first = d.writers.Close()
	}
	if err := d.root.Close(); first == nil {
		first = err
	}
	return first
}

func validateDirectoryFile(file *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fmt.Errorf("stat trusted writer directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: writer root is not a directory", ErrInvalidState)
	}
	if stat.Mode&0o022 != 0 {
		return fmt.Errorf("%w: writer directory is writable by a group or other user", ErrInvalidState)
	}
	return nil
}

func validatePrivateDirectoryFile(file *os.File) error {
	if err := validateDirectoryFile(file); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fmt.Errorf("stat private writer directory: %w", err)
	}
	if stat.Mode&0o077 != 0 {
		return fmt.Errorf("%w: writer directory is not private", ErrInvalidState)
	}
	return nil
}

func readStateAt(dir *writerDir, operationID string, maxBytes int) ([]byte, error) {
	fd, err := unix.Openat(int(dir.writers.Fd()), operationID+".json", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrNotFound
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: writer state is a symlink", ErrInvalidState)
		}
		return nil, fmt.Errorf("open writer state: %w", err)
	}
	file := os.NewFile(uintptr(fd), operationID+".json")
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("stat writer state: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%w: writer state is not a regular file", ErrInvalidState)
	}
	if stat.Mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: writer state permissions are not restrictive", ErrInvalidState)
	}
	if maxBytes <= 0 || maxBytes > MaxStateBytes {
		maxBytes = MaxStateBytes
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read writer state: %w", err)
	}
	if len(data) > maxBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

func writeStateAt(dir *writerDir, operationID string, state State, maxBytes int, syncFn func(*os.File) error) error {
	if syncFn == nil {
		syncFn = syncFile
	}
	data, err := jsonState(state)
	if err != nil {
		return err
	}
	if maxBytes <= 0 || maxBytes > MaxStateBytes {
		maxBytes = MaxStateBytes
	}
	if len(data) > maxBytes {
		return ErrTooLarge
	}

	tmpName, file, err := createStateTemp(dir, operationID)
	if err != nil {
		return err
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = unix.Unlinkat(int(dir.writers.Fd()), tmpName, 0)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write writer state: %w", err)
	}
	if err := syncFn(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync writer state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close writer state: %w", err)
	}
	if err := unix.Renameat(int(dir.writers.Fd()), tmpName, int(dir.writers.Fd()), operationID+".json"); err != nil {
		return fmt.Errorf("replace writer state: %w", err)
	}
	removeTemp = false
	if err := syncFn(dir.writers); err != nil {
		return fmt.Errorf("sync writer directory: %w", err)
	}
	return nil
}

func createStateTemp(dir *writerDir, operationID string) (string, *os.File, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, fmt.Errorf("randomize writer state temporary name: %w", err)
	}
	name := fmt.Sprintf(".%s.%s.tmp", operationID, hex.EncodeToString(random[:]))
	fd, err := unix.Openat(int(dir.writers.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0o600)
	if err != nil {
		return "", nil, fmt.Errorf("create writer state temporary file: %w", err)
	}
	return name, os.NewFile(uintptr(fd), name), nil
}
