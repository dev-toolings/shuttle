//go:build linux

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
)

func TestRootOperationBaselineExactRoundTrip(t *testing.T) {
	archive, source, app, id := baselineArchiveFixture(t)
	current := []byte("services:\n  web:\n    image: example:v1\n")
	previous := []byte("services:\n  web:\n    image: example:v0\n")
	baseline := operationwriters.Baseline{
		Current:  writeBaselineSource(t, source, app, "current", current),
		Previous: writeBaselineSource(t, source, app, "previous", previous),
	}

	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err != nil {
		t.Fatal(err)
	}
	gotCurrent, err := readRootOperationBaselineArtifact(id, "current", baseline.Current)
	if err != nil {
		t.Fatal(err)
	}
	gotPrevious, err := readRootOperationBaselineArtifact(id, "previous", baseline.Previous)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCurrent, current) || !bytes.Equal(gotPrevious, previous) {
		t.Fatalf("round-trip returned different bytes current=%d previous=%d", len(gotCurrent), len(gotPrevious))
	}

	currentPath := filepath.Join(archive, rootOperationBaselineDirName, id, "current.yml")
	previousPath := filepath.Join(archive, rootOperationBaselineDirName, id, "previous.yml")
	assertPrivateBaselineModes(t, filepath.Join(archive, rootOperationBaselineDirName), filepath.Dir(currentPath), currentPath, previousPath)

	rotated := []byte("services:\n  web:\n    image: example:v2\n")
	if err := os.WriteFile(filepath.Join(source, app, "current.yml"), rotated, 0o600); err != nil {
		t.Fatal(err)
	}
	gotCurrent, err = readRootOperationBaselineArtifact(id, "current", baseline.Current)
	if err != nil || !bytes.Equal(gotCurrent, current) {
		t.Fatalf("slot rotation leaked into the archive: err=%v len=%d", err, len(gotCurrent))
	}
}

func TestRootOperationBaselineTamperHashMismatch(t *testing.T) {
	_, source, app, id := baselineArchiveFixture(t)
	current := []byte("services:\n  web:\n    image: example:v1\n")
	baseline := operationwriters.Baseline{Current: writeBaselineSource(t, source, app, "current", current)}
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(rootOperationBaselineArchiveRoot, rootOperationBaselineDirName, id, "current.yml")
	tampered := []byte("services:\n  web:\n    image: example:evil\n")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := readRootOperationBaselineArtifact(id, "current", baseline.Current)
	if err == nil || body != nil {
		t.Fatal("tampered archive was accepted")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tamper error = %v", err)
	}
	assertErrorOmitsSecret(t, err, tampered, current)

	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err == nil {
		t.Fatal("preserve replaced a different archived byte string")
	} else {
		assertErrorOmitsSecret(t, err, tampered, current)
	}

	_ = writeBaselineSource(t, source, app, "current", tampered)
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err == nil {
		t.Fatal("preserve ignored a source that no longer matches the captured artifact")
	} else {
		assertErrorOmitsSecret(t, err, tampered, current)
	}
}

func TestRootOperationBaselineMissing(t *testing.T) {
	_, _, _, id := baselineArchiveFixture(t)
	artifact := operationwriters.BaselineArtifact{Present: true, FullSHA256: rootOperationBaselineDigest([]byte("services: {}\n"))}
	body, err := readRootOperationBaselineArtifact(id, "current", artifact)
	if err == nil || body != nil {
		t.Fatal("missing archive was accepted")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing error = %v", err)
	}

	absent, err := readRootOperationBaselineArtifact(id, "previous", operationwriters.BaselineArtifact{})
	if err != nil || absent != nil {
		t.Fatalf("absent role without an archive = %q %v", absent, err)
	}
}

func TestRootOperationBaselineSymlink(t *testing.T) {
	archive, source, app, id := baselineArchiveFixture(t)
	current := []byte("services:\n  web:\n    image: example:v1\n")
	real := filepath.Join(source, "real.yml")
	if err := os.WriteFile(real, current, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, app), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(source, app, "current.yml")); err != nil {
		t.Fatal(err)
	}
	baseline := operationwriters.Baseline{Current: operationwriters.BaselineArtifact{Present: true, FullSHA256: rootOperationBaselineDigest(current)}}
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err == nil {
		t.Fatal("symlink source was archived")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink source error = %v", err)
	} else {
		assertErrorOmitsSecret(t, err, current)
	}

	if err := os.Remove(filepath.Join(source, app, "current.yml")); err != nil {
		t.Fatal(err)
	}
	baseline.Current = writeBaselineSource(t, source, app, "current", current)
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err != nil {
		t.Fatal(err)
	}
	archived := filepath.Join(archive, rootOperationBaselineDirName, id, "current.yml")
	if err := os.Remove(archived); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, archived); err != nil {
		t.Fatal(err)
	}
	body, err := readRootOperationBaselineArtifact(id, "current", baseline.Current)
	if err == nil || body != nil {
		t.Fatal("symlink archive was accepted")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink archive error = %v", err)
	}
	assertErrorOmitsSecret(t, err, current)
}

func TestRootOperationBaselineInvalidRoleAndID(t *testing.T) {
	_, source, app, id := baselineArchiveFixture(t)
	current := []byte("services:\n  web:\n    image: example:v1\n")
	baseline := operationwriters.Baseline{Current: writeBaselineSource(t, source, app, "current", current)}
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err != nil {
		t.Fatal(err)
	}

	artifact := baseline.Current
	for _, role := range []string{"", "Current", "current.yml", "next", "current/../previous", "../current"} {
		if _, err := readRootOperationBaselineArtifact(id, role, artifact); err == nil {
			t.Fatalf("role %q was accepted", role)
		} else if !strings.Contains(err.Error(), "role") {
			t.Fatalf("role %q error = %v", role, err)
		} else {
			assertErrorOmitsSecret(t, err, current)
		}
	}
	for _, operationID := range []string{"", "not-a-uuid", "018F3A7E-8E3B-4A8C-9A2D-4F2D1C7E9B10", "018f3a7e8e3b4a8c9a2d4f2d1c7e9b10", "../" + id, id + "/../" + id, "foo/bar", "/etc/passwd"} {
		if _, err := readRootOperationBaselineArtifact(operationID, "current", artifact); err == nil {
			t.Fatalf("id %q was accepted", operationID)
		} else if !strings.Contains(err.Error(), "identifier") {
			t.Fatalf("id %q error = %v", operationID, err)
		} else {
			assertErrorOmitsSecret(t, err, current)
		}
		if err := preserveRootOperationBaselineArtifacts(operationID, app, baseline); err == nil {
			t.Fatalf("preserve accepted id %q", operationID)
		} else {
			assertErrorOmitsSecret(t, err, current)
		}
	}
	if err := preserveRootOperationBaselineArtifacts(id, "../etc", baseline); err == nil {
		t.Fatal("preserve accepted an arbitrary app path")
	} else {
		assertErrorOmitsSecret(t, err, current)
	}
	if err := preserveRootOperationBaselineArtifacts(id, app+"/../etc", baseline); err == nil {
		t.Fatal("preserve accepted a nested path app")
	} else {
		assertErrorOmitsSecret(t, err, current)
	}
}

func TestRootOperationBaselineIdempotentReentryAndAbsentRole(t *testing.T) {
	archive, source, app, id := baselineArchiveFixture(t)
	current := []byte("services:\n  web:\n    image: example:v1\n")
	baseline := operationwriters.Baseline{Current: writeBaselineSource(t, source, app, "current", current)}
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err != nil {
		t.Fatal(err)
	}
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err != nil {
		t.Fatal(err)
	}
	previousPath := filepath.Join(archive, rootOperationBaselineDirName, id, "previous.yml")
	if _, err := os.Lstat(previousPath); !os.IsNotExist(err) {
		t.Fatalf("absent previous role created an archive: %v", err)
	}
	got, err := readRootOperationBaselineArtifact(id, "previous", operationwriters.BaselineArtifact{})
	if err != nil || got != nil {
		t.Fatalf("absent previous read = %q %v", got, err)
	}

	if err := os.WriteFile(previousPath, []byte("leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preserveRootOperationBaselineArtifacts(id, app, baseline); err == nil {
		t.Fatal("preserve kept a leftover archive for an absent role")
	} else if !strings.Contains(err.Error(), "absent") {
		t.Fatalf("leftover absent error = %v", err)
	} else {
		assertErrorOmitsSecret(t, err, []byte("leftover"), current)
	}
	if _, err := readRootOperationBaselineArtifact(id, "previous", operationwriters.BaselineArtifact{}); err == nil {
		t.Fatal("read accepted a leftover archive for an absent role")
	}

	if err := os.Remove(previousPath); err != nil {
		t.Fatal(err)
	}
	got, err = readRootOperationBaselineArtifact(id, "current", baseline.Current)
	if err != nil || !bytes.Equal(got, current) {
		t.Fatalf("idempotent re-entry lost current bytes: err=%v len=%d", err, len(got))
	}
	entries, err := os.ReadDir(filepath.Join(archive, rootOperationBaselineDirName, id))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary archive file was left behind: %s", entry.Name())
		}
	}
}

func baselineArchiveFixture(t *testing.T) (archive, source, app, id string) {
	t.Helper()
	archive = t.TempDir()
	source = t.TempDir()
	if err := os.Chmod(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o700); err != nil {
		t.Fatal(err)
	}
	prevArchive, prevSource := rootOperationBaselineArchiveRoot, rootOperationBaselineSourceRoot
	rootOperationBaselineArchiveRoot = archive
	rootOperationBaselineSourceRoot = source
	t.Cleanup(func() {
		rootOperationBaselineArchiveRoot = prevArchive
		rootOperationBaselineSourceRoot = prevSource
	})
	return archive, source, "demo", "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b10"
}

func writeBaselineSource(t *testing.T, source, app, role string, body []byte) operationwriters.BaselineArtifact {
	t.Helper()
	dir := filepath.Join(source, app)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, role+".yml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return operationwriters.BaselineArtifact{Present: true, FullSHA256: rootOperationBaselineDigest(body)}
}

func assertPrivateBaselineModes(t *testing.T, dirs ...string) {
	t.Helper()
	for i, path := range dirs {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s is a symlink", path)
		}
		want := os.FileMode(0o700)
		if i >= 2 {
			want = 0o600
			if !info.Mode().IsRegular() {
				t.Fatalf("%s is not a regular file", path)
			}
		} else if !info.IsDir() {
			t.Fatalf("%s is not a directory", path)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
}

func assertErrorOmitsSecret(t *testing.T, err error, secrets ...[]byte) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	text := err.Error()
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		if strings.Contains(text, string(secret)) {
			t.Fatalf("error printed secret content: %v", err)
		}
	}
}
