//go:build !linux

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
)

type writerDir struct {
	root    *os.File
	writers *os.File
}

func openWriterDir(rootPath string) (*writerDir, error) {
	return openWriterDirMode(rootPath, true)
}

func openWriterDirMode(rootPath string, create bool) (*writerDir, error) {
	if err := validateRootAncestorsOther(rootPath); err != nil {
		return nil, err
	}
	if err := validateDirectoryPath(rootPath); err != nil {
		return nil, err
	}
	root, err := os.Open(rootPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: root directory %q does not exist", ErrNotFound, rootPath)
		}
		return nil, fmt.Errorf("open writer root: %w", err)
	}
	if err := validateDirectoryFileOther(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	writersPath := filepath.Join(rootPath, "writers")
	if err := validateDirectoryPath(writersPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			_ = root.Close()
			return nil, err
		}
		if !create {
			_ = root.Close()
			return nil, fmt.Errorf("%w: writer directory does not exist", ErrNotFound)
		}
		if err := os.Mkdir(writersPath, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			_ = root.Close()
			return nil, fmt.Errorf("create writer directory: %w", err)
		}
	}
	writers, err := os.Open(writersPath)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open writer directory: %w", err)
	}
	if err := validatePrivateDirectoryFileOther(writers); err != nil {
		_ = writers.Close()
		_ = root.Close()
		return nil, err
	}
	return &writerDir{root: root, writers: writers}, nil
}

func validateRootAncestorsOther(rootPath string) error {
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

func validateDirectoryPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: writer directory is a symlink", ErrInvalidState)
	}
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: writer directory is not trusted", ErrInvalidState)
	}
	return nil
}

func validateDirectoryFileOther(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat trusted writer directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: writer directory is not trusted", ErrInvalidState)
	}
	return nil
}

func validatePrivateDirectoryFileOther(file *os.File) error {
	if err := validateDirectoryFileOther(file); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat private writer directory: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: writer directory is not private", ErrInvalidState)
	}
	return nil
}

func readStateAt(dir *writerDir, operationID string, maxBytes int) ([]byte, error) {
	// State lives inside writers/, as on Linux (store_linux.go opens it at the
	// writers directory descriptor). Taking the parent put it beside writers/,
	// so this build read and wrote a layout no Linux host would recognise.
	path := filepath.Join(dir.writers.Name(), operationID+".json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("stat writer state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: writer state is not a restrictive regular file", ErrInvalidState)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open writer state: %w", err)
	}
	defer file.Close()
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
	base := dir.writers.Name()
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("randomize writer state temporary name: %w", err)
	}
	tmpPath := filepath.Join(base, fmt.Sprintf(".%s.%s.tmp", operationID, hex.EncodeToString(random[:])))
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create writer state temporary file: %w", err)
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
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
	if err := os.Rename(tmpPath, filepath.Join(base, operationID+".json")); err != nil {
		return fmt.Errorf("replace writer state: %w", err)
	}
	removeTemp = false
	if err := syncFn(dir.writers); err != nil {
		return fmt.Errorf("sync writer directory: %w", err)
	}
	return nil
}
