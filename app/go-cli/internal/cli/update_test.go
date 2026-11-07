package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/release"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
)

type failingBinaryFilesystem struct {
	binaryFilesystem
	fail       map[string]error
	syncCalls  int
	closeCalls int
}

func (f *failingBinaryFilesystem) injected(step string) error { return f.fail[step] }
func (f *failingBinaryFilesystem) Chmod(file *os.File, mode os.FileMode) error {
	if err := f.injected("chmod"); err != nil {
		return err
	}
	return f.binaryFilesystem.Chmod(file, mode)
}
func (f *failingBinaryFilesystem) Write(file *os.File, data []byte) (int, error) {
	if err := f.injected("write"); err != nil {
		return 0, err
	}
	return f.binaryFilesystem.Write(file, data)
}
func (f *failingBinaryFilesystem) Sync(file *os.File) error {
	f.syncCalls++
	step := []string{"file-sync", "recovery-dir-sync", "publish-dir-sync", "recovery-cleanup-dir-sync"}[f.syncCalls-1]
	if err := f.injected(step); err != nil {
		return err
	}
	return f.binaryFilesystem.Sync(file)
}
func (f *failingBinaryFilesystem) Close(file *os.File) error {
	f.closeCalls++
	step := "temp-close"
	if f.closeCalls > 1 {
		step = "dir-close"
	}
	if err := f.injected(step); err != nil {
		return err
	}
	return f.binaryFilesystem.Close(file)
}
func (f *failingBinaryFilesystem) Link(oldname, newname string) error {
	if err := f.injected("link"); err != nil {
		return err
	}
	return f.binaryFilesystem.Link(oldname, newname)
}
func (f *failingBinaryFilesystem) Rename(oldname, newname string) error {
	if err := f.injected("rename"); err != nil {
		return err
	}
	return f.binaryFilesystem.Rename(oldname, newname)
}
func (f *failingBinaryFilesystem) Remove(path string) error {
	step := "temp-cleanup"
	if strings.HasSuffix(path, recoverySuffix) {
		step = "recovery-cleanup"
	}
	if err := f.injected(step); err != nil {
		return err
	}
	return f.binaryFilesystem.Remove(path)
}

func executableScript(name string) []byte { return []byte("#!/bin/sh\necho " + name + "\n") }

func requireLaunchable(t *testing.T, path string) {
	t.Helper()
	if output, err := exec.Command(path).CombinedOutput(); err != nil {
		t.Fatalf("executable path is not launchable: %v (%s)", err, output)
	}
}

func TestVerifyChecksumHex_ValidMatch(t *testing.T) {
	data := []byte("fake binary contents")
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])

	if err := verifyChecksumHex(hexSum, data); err != nil {
		t.Fatalf("expected verification to succeed, got error: %v", err)
	}
}

func TestTrustedReleaseKeyringRotationAndRevocation(t *testing.T) {
	first, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKeys, oldRevoked := version.ReleaseTrustedKeys, version.ReleaseRevokedKeyIDs
	version.ReleaseTrustedKeys = "old=" + base64.StdEncoding.EncodeToString(first) + ",new=" + base64.StdEncoding.EncodeToString(second)
	version.ReleaseRevokedKeyIDs = ""
	t.Cleanup(func() { version.ReleaseTrustedKeys, version.ReleaseRevokedKeyIDs = oldKeys, oldRevoked })
	if got, err := trustedReleasePublicKey("new"); err != nil || got != base64.StdEncoding.EncodeToString(second) {
		t.Fatalf("bridge key unavailable: %q %v", got, err)
	}
	version.ReleaseRevokedKeyIDs = "old"
	if _, err := trustedReleasePublicKey("old"); err == nil {
		t.Fatal("revoked key accepted")
	}
	if _, err := trustedReleasePublicKey("unknown"); err == nil {
		t.Fatal("unknown key accepted")
	}
}

// TestEmbeddedReleaseTrustProbe runs only in a separately linked test binary.
// The parent test below uses it to prove that ldflags, not mutable in-process
// package variables, carry an old/bridge/new release keyring.
func TestEmbeddedReleaseTrustProbe(t *testing.T) {
	if os.Getenv("DEPLOYSHUTTLE_TRUST_PROBE") == "" {
		return
	}
	allowInsecureUpdateForTests = true
	defer func() { allowInsecureUpdateForTests = false }()
	_, err := fetchManifest()
	if os.Getenv("DEPLOYSHUTTLE_TRUST_PROBE_EXPECT") == "accept" && err != nil {
		t.Fatalf("embedded client rejected expected manifest: %v", err)
	}
	if os.Getenv("DEPLOYSHUTTLE_TRUST_PROBE_EXPECT") == "reject" && err == nil {
		t.Fatal("embedded client accepted manifest that must be rejected")
	}
}

func TestReleaseBuildKeyringBridgeAndRevocation(t *testing.T) {
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checksums := map[string]string{"shuttle-linux-x64": strings.Repeat("a", 64)}
	manifestFor := func(keyID string, private ed25519.PrivateKey) string {
		payload, err := release.CanonicalManifestBytes("v1.2.3", keyID, checksums)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(releaseManifest{
			Version: "v1.2.3", SHA256: checksums, URLs: map[string]string{"shuttle-linux-x64": "https://example.invalid/file"}, KeyID: keyID,
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	var response atomic.Value
	response.Store(manifestFor("new", newPrivate))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(response.Load().(string)))
	}))
	defer server.Close()
	old := base64.StdEncoding.EncodeToString(oldPublic)
	new := base64.StdEncoding.EncodeToString(newPublic)
	// An old release does not accept the new signing key. The bridge release is
	// then built with both keys and accepts it; the later client embeds only the
	// new key and explicitly rejects manifests signed by revoked old.
	runEmbeddedTrustProbe(t, server.URL, "old="+old, "", "reject")
	runEmbeddedTrustProbe(t, server.URL, "old="+old+",new="+new, "", "accept")
	response.Store(manifestFor("old", oldPrivate))
	runEmbeddedTrustProbe(t, server.URL, "new="+new, "old", "reject")
}

func runEmbeddedTrustProbe(t *testing.T, serverURL, trustedKeys, revoked, expected string) {
	t.Helper()
	moduleRoot := filepath.Clean(filepath.Join("..", ".."))
	ldpkg := "github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
	ldflags := fmt.Sprintf("-X %s.ReleaseTrustedKeys=%s -X %s.ReleaseRevokedKeyIDs=%s", ldpkg, trustedKeys, ldpkg, revoked)
	cmd := exec.Command("go", "test", "./internal/cli", "-count=1", "-run", "^TestEmbeddedReleaseTrustProbe$", "-ldflags", ldflags)
	cmd.Dir = moduleRoot
	cmd.Env = append(os.Environ(), "DEPLOYSHUTTLE_TRUST_PROBE=1", "DEPLOYSHUTTLE_TRUST_PROBE_EXPECT="+expected, "SHUTTLE_SITE_URL="+serverURL)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("embedded trust probe %s failed: %v\n%s", expected, err, output)
	}
}

func TestReleaseVersionRejectsDowngradeAndMalformedTags(t *testing.T) {
	for _, bad := range []string{"v1", "v1.2", "v01.2.3", "v1.2.3-beta", "1.2.3"} {
		if validReleaseVersion(bad) {
			t.Fatalf("accepted malformed version %q", bad)
		}
	}
	if got, err := compareReleaseVersions("v1.2.3", "1.2.4"); err != nil || got >= 0 {
		t.Fatalf("downgrade comparison = %d, %v", got, err)
	}
}

func TestDownloadRejectsRedirectAndOversizeWithoutLeakingQuery(t *testing.T) {
	allowInsecureUpdateForTests = true
	t.Cleanup(func() { allowInsecureUpdateForTests = false })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://evil.invalid/payload", http.StatusFound)
			return
		}
		w.Header().Set("Content-Length", "83886081")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	t.Setenv("SHUTTLE_SITE_URL", server.URL)
	if _, err := downloadBinary(server.URL + "/redirect?exp=1&sig=secret"); err == nil || strings.Contains(err.Error(), "sig=secret") {
		t.Fatalf("redirect error leaked URL or succeeded: %v", err)
	}
	if _, err := downloadBinary(server.URL + "/large?exp=1&sig=secret"); err == nil || strings.Contains(err.Error(), "sig=secret") {
		t.Fatalf("size error leaked URL or succeeded: %v", err)
	}
}

func TestDownloadRejectsChunkedOversizeAndTimeout(t *testing.T) {
	allowInsecureUpdateForTests = true
	t.Cleanup(func() { allowInsecureUpdateForTests = false })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chunked":
			for written := 0; written <= maxUpdateDownload; written += 32 << 10 {
				if _, err := w.Write(make([]byte, 32<<10)); err != nil {
					return
				}
			}
		case "/slow":
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte("late"))
		}
	}))
	defer server.Close()
	t.Setenv("SHUTTLE_SITE_URL", server.URL)
	if _, err := downloadBinary(server.URL + "/chunked?sig=SECRET"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("chunked oversized download accepted or leaked URL: %v", err)
	}
	previousClient := updateHTTPClient
	updateHTTPClient = &http.Client{Timeout: 20 * time.Millisecond, CheckRedirect: previousClient.CheckRedirect}
	t.Cleanup(func() { updateHTTPClient = previousClient })
	if _, err := downloadBinary(server.URL + "/slow?sig=SECRET"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("timeout did not fail cleanly: %v", err)
	}
}

func TestFetchManifestRejectsTrailingJSONMalformedSignatureAndUnknownKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checksums := map[string]string{"shuttle-linux-x64": strings.Repeat("a", 64)}
	payload, err := release.CanonicalManifestBytes("v1.2.3", "active", checksums)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	base := map[string]any{
		"version": "v1.2.3", "sha256": checksums, "urls": map[string]string{"shuttle-linux-x64": "https://example.invalid/release"}, "key_id": "active", "signature": signature,
	}
	var response string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(response)) }))
	defer server.Close()
	allowInsecureUpdateForTests = true
	t.Cleanup(func() { allowInsecureUpdateForTests = false })
	t.Setenv("SHUTTLE_SITE_URL", server.URL)
	oldKeys := version.ReleaseTrustedKeys
	version.ReleaseTrustedKeys = "active=" + base64.StdEncoding.EncodeToString(public)
	t.Cleanup(func() { version.ReleaseTrustedKeys = oldKeys })
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	response = string(encoded) + " {}"
	if _, err := fetchManifest(); err == nil {
		t.Fatal("trailing manifest accepted")
	}
	response = "{"
	if _, err := fetchManifest(); err == nil {
		t.Fatal("malformed manifest accepted")
	}
	base["signature"] = "not-a-signature"
	encoded, _ = json.Marshal(base)
	response = string(encoded)
	if _, err := fetchManifest(); err == nil {
		t.Fatal("bad signature accepted through HTTP")
	}
	base["signature"] = signature
	base["key_id"] = "unknown"
	encoded, _ = json.Marshal(base)
	response = string(encoded)
	if _, err := fetchManifest(); err == nil {
		t.Fatal("unknown key accepted through HTTP")
	}
}

func TestReplaceBinaryAtomicAndRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shuttle")
	if err := os.WriteFile(path, executableScript("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(path, executableScript("new")); err != nil {
		t.Fatal(err)
	}
	requireLaunchable(t, path)
	if _, err := os.Lstat(recoveryPath(path)); !os.IsNotExist(err) {
		t.Fatalf("recovery was not finalized: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(link, []byte("bad")); err == nil {
		t.Fatal("symlink replacement accepted")
	}
}

func TestReplaceBinaryPrimitiveFailuresLeaveExecutableLaunchable(t *testing.T) {
	for _, step := range []string{"chmod", "write", "file-sync", "temp-close", "link", "recovery-dir-sync", "rename", "publish-dir-sync", "recovery-cleanup", "recovery-cleanup-dir-sync", "dir-close"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "shuttle")
			if err := os.WriteFile(path, executableScript("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			fs := &failingBinaryFilesystem{binaryFilesystem: osBinaryFilesystem{}, fail: map[string]error{step: os.ErrPermission}}
			replaceBinaryFS = fs
			t.Cleanup(func() { replaceBinaryFS = osBinaryFilesystem{} })
			if err := replaceBinary(path, executableScript("new")); err == nil {
				t.Fatal("injection succeeded")
			}
			requireLaunchable(t, path)
		})
	}
}

func TestReplaceBinaryTempCleanupFailureIsVisible(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shuttle")
	if err := os.WriteFile(path, executableScript("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	replaceBinaryFS = &failingBinaryFilesystem{binaryFilesystem: osBinaryFilesystem{}, fail: map[string]error{"write": os.ErrPermission, "temp-cleanup": os.ErrPermission}}
	t.Cleanup(func() { replaceBinaryFS = osBinaryFilesystem{} })
	err := replaceBinary(path, executableScript("new"))
	if err == nil || !strings.Contains(err.Error(), "additional cleanup failure") {
		t.Fatalf("cleanup error not observable: %v", err)
	}
	requireLaunchable(t, path)
}

func TestRecoveryCleanupSyncFailureSucceedsWithoutRecoveryAndRetriesIdempotently(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shuttle")
	if err := os.WriteFile(path, executableScript("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	replaceBinaryFS = &failingBinaryFilesystem{binaryFilesystem: osBinaryFilesystem{}, fail: map[string]error{"recovery-cleanup-dir-sync": os.ErrPermission}}
	warning, err := completeBinaryReplacement(path, executableScript("new"))
	if err != nil {
		t.Fatalf("post-delete cleanup failure must keep update exit-success: %v", err)
	}
	if !strings.Contains(warning, "no recovery artifact") || !strings.Contains(warning, "must not be used") {
		t.Fatalf("unsafe cleanup warning: %q", warning)
	}
	requireLaunchable(t, path)
	if _, err := os.Lstat(recoveryPath(path)); !os.IsNotExist(err) {
		t.Fatalf("recovery is incorrectly claimed after successful remove: %v", err)
	}
	if err := recoverBinary(path); err == nil {
		t.Fatal("recover succeeded although the artifact was removed")
	}
}

func TestRecoveryCleanupSyncAndDirectoryCloseFailureStaysAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shuttle")
	if err := os.WriteFile(path, executableScript("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	replaceBinaryFS = &failingBinaryFilesystem{binaryFilesystem: osBinaryFilesystem{}, fail: map[string]error{
		"recovery-cleanup-dir-sync": os.ErrPermission,
		"dir-close":                 os.ErrPermission,
	}}
	warning, err := completeBinaryReplacement(path, executableScript("new"))
	if err == nil {
		t.Fatal("double fault was incorrectly converted into success")
	}
	if warning != "" {
		t.Fatalf("double fault produced a success warning: %q", warning)
	}
	if !strings.Contains(err.Error(), "cleanup fsync failed") || !strings.Contains(err.Error(), "close executable directory") {
		t.Fatalf("double fault does not expose both causes: %v", err)
	}
	requireLaunchable(t, path)
	if _, statErr := os.Lstat(recoveryPath(path)); !os.IsNotExist(statErr) {
		t.Fatalf("removed recovery was unexpectedly recreated: %v", statErr)
	}
	if err := recoverBinary(path); err == nil {
		t.Fatal("recover succeeded although the artifact was removed")
	}
}

func TestRecoverBinaryUsesDeterministicRetainedArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shuttle")
	if err := os.WriteFile(path, executableScript("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	replaceBinaryFS = &failingBinaryFilesystem{binaryFilesystem: osBinaryFilesystem{}, fail: map[string]error{"publish-dir-sync": os.ErrPermission}}
	if err := replaceBinary(path, executableScript("new")); err == nil {
		t.Fatal("publish sync failure was accepted")
	}
	replaceBinaryFS = osBinaryFilesystem{}
	t.Cleanup(func() { replaceBinaryFS = osBinaryFilesystem{} })
	if _, err := os.Lstat(recoveryPath(path)); err != nil {
		t.Fatalf("missing deterministic recovery artifact: %v", err)
	}
	if err := recoverBinary(path); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(path).Output()
	if err != nil || string(output) != "old\n" {
		t.Fatalf("recovery did not restore old executable: %q %v", output, err)
	}
	if _, err := os.Lstat(recoveryPath(path)); !os.IsNotExist(err) {
		t.Fatalf("recovery artifact not consumed: %v", err)
	}
}

func TestUpdateRecoverCommandRestoresRetainedArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shuttle")
	if err := os.WriteFile(path, executableScript("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, recoveryPath(path)); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "staged")
	if err := os.WriteFile(staged, executableScript("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	previousExecutable := updateExecutable
	updateExecutable = func() (string, error) { return path, nil }
	t.Cleanup(func() { updateExecutable = previousExecutable })
	command := newUpdateCommand()
	command.SetArgs([]string{"--recover"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(path).Output()
	if err != nil || string(output) != "old\n" {
		t.Fatalf("recover command did not restore artifact: %q %v", output, err)
	}
}

func TestSignedManifestRejectsTamper(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checksums := map[string]string{"shuttle-linux-x64": strings.Repeat("a", 64)}
	payload, err := release.CanonicalManifestBytes("v1.2.3", "key", checksums)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	if err := release.Verify("v1.2.3", "key", checksums, sig, base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	checksums["shuttle-linux-x64"] = strings.Repeat("b", 64)
	if err := release.Verify("v1.2.3", "key", checksums, sig, base64.StdEncoding.EncodeToString(pub)); err == nil {
		t.Fatal("tampered manifest verified")
	}
}

func TestVerifyChecksumHex_HashMismatch(t *testing.T) {
	data := []byte("fake binary contents")
	wrongSum := sha256.Sum256([]byte("different contents"))
	wrongHex := hex.EncodeToString(wrongSum[:])

	err := verifyChecksumHex(wrongHex, data)
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func TestVerifyChecksumHex_CaseInsensitive(t *testing.T) {
	data := []byte("fake binary contents")
	sum := sha256.Sum256(data)
	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))

	if err := verifyChecksumHex(hexSum, data); err != nil {
		t.Fatalf("expected case-insensitive verification to succeed, got error: %v", err)
	}
}

func TestAssertTrustedDownloadURL_AcceptsSiteHost(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", "https://releases.example.com")
	t.Setenv("SHUTTLE_ALLOW_INSECURE_SITE", "")
	if err := assertTrustedDownloadURL("https://releases.example.com/releases/v1.3.0/shuttle-linux-x64?exp=1&sig=abc"); err != nil {
		t.Fatalf("expected the site host to be trusted, got %v", err)
	}
}

func TestAssertTrustedDownloadURL_RejectsForeignHost(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", "https://releases.example.com")
	t.Setenv("SHUTTLE_ALLOW_INSECURE_SITE", "")
	err := assertTrustedDownloadURL("https://evil.example.com/releases/v1.3.0/shuttle-linux-x64")
	if err == nil || !strings.Contains(err.Error(), "evil.example.com") {
		t.Fatalf("expected a foreign host to be refused, got %v", err)
	}
}

func TestAssertTrustedDownloadURL_RejectsPlainHTTP(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", "https://releases.example.com")
	t.Setenv("SHUTTLE_ALLOW_INSECURE_SITE", "")
	if err := assertTrustedDownloadURL("http://releases.example.com/releases/v1.3.0/shuttle-linux-x64"); err == nil {
		t.Fatal("expected plain http to be refused")
	}
}

// Only the test binary can relax HTTPS for its local httptest server; no
// runtime environment variable can weaken a released updater.
func TestAssertTrustedDownloadURL_TestOnlyInsecureHarnessKeepsHostPinned(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", "http://127.0.0.1:3999")
	allowInsecureUpdateForTests = true
	t.Cleanup(func() { allowInsecureUpdateForTests = false })
	if err := assertTrustedDownloadURL("http://127.0.0.1:3999/releases/v0.0.1-e2e/shuttle-linux-x64"); err != nil {
		t.Fatalf("expected the local e2e origin to be trusted, got %v", err)
	}
	if err := assertTrustedDownloadURL("http://127.0.0.1:4000/releases/v0.0.1-e2e/shuttle-linux-x64"); err == nil {
		t.Fatal("expected a different local port to be refused")
	}
}

// A manifest that names a release but no download URLs cannot update anything:
// say what is missing rather than failing later on a lookup by asset name.
func TestFetchManifestRefusesAManifestWithoutDownloadURLs(t *testing.T) {
	checksums := map[string]string{"shuttle-linux-x64": strings.Repeat("a", 64)}
	encoded, err := json.Marshal(map[string]any{"version": "v1.2.3", "sha256": checksums})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(encoded) }))
	defer server.Close()
	allowInsecureUpdateForTests = true
	t.Cleanup(func() { allowInsecureUpdateForTests = false })
	t.Setenv("SHUTTLE_SITE_URL", server.URL)

	if _, err := fetchManifest(); err == nil || !strings.Contains(err.Error(), "no download URLs") {
		t.Fatalf("a manifest with no download URLs must be refused by name, got %v", err)
	}
}

// The updater presents no credential: the signature, not the caller, is what
// makes a manifest trustworthy.
func TestFetchManifestSendsNoCredential(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	allowInsecureUpdateForTests = true
	t.Cleanup(func() { allowInsecureUpdateForTests = false })
	t.Setenv("SHUTTLE_SITE_URL", server.URL)

	if _, err := fetchManifest(); err == nil {
		t.Fatal("a failed manifest request must be reported")
	}
	if authorization != "" {
		t.Fatalf("the updater must send no Authorization header, got %q", authorization)
	}
}
