package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/release"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
	"github.com/spf13/cobra"
)

const maxUpdateDownload = 80 << 20

var updateHTTPClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return fmt.Errorf("too many download redirects")
	}
	return assertTrustedDownloadURL(req.URL.String())
}}

var updateExecutable = os.Executable

// Test-only in-process escape hatch for httptest. A released binary cannot
// enable HTTP with an environment variable.
var allowInsecureUpdateForTests bool

// binaryFilesystem is deliberately narrow so tests can fail a syscall before
// it happens. That proves the updater's error paths for the durable primitive,
// rather than pretending a successful fsync or rename failed afterwards.
type binaryFilesystem interface {
	Lstat(string) (os.FileInfo, error)
	CreateTemp(string, string) (*os.File, error)
	Open(string) (*os.File, error)
	Chmod(*os.File, os.FileMode) error
	Write(*os.File, []byte) (int, error)
	Sync(*os.File) error
	Close(*os.File) error
	Remove(string) error
	Link(string, string) error
	Rename(string, string) error
}

type osBinaryFilesystem struct{}

func (osBinaryFilesystem) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }
func (osBinaryFilesystem) CreateTemp(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}
func (osBinaryFilesystem) Open(path string) (*os.File, error) { return os.Open(path) }
func (osBinaryFilesystem) Chmod(file *os.File, mode os.FileMode) error {
	return file.Chmod(mode)
}
func (osBinaryFilesystem) Write(file *os.File, data []byte) (int, error) { return file.Write(data) }
func (osBinaryFilesystem) Sync(file *os.File) error                      { return file.Sync() }
func (osBinaryFilesystem) Close(file *os.File) error                     { return file.Close() }
func (osBinaryFilesystem) Remove(path string) error                      { return os.Remove(path) }
func (osBinaryFilesystem) Link(oldname, newname string) error            { return os.Link(oldname, newname) }
func (osBinaryFilesystem) Rename(oldname, newname string) error          { return os.Rename(oldname, newname) }

var replaceBinaryFS binaryFilesystem = osBinaryFilesystem{}

// releaseManifest is the response from GET {site}/releases/latest.
type releaseManifest struct {
	Version   string            `json:"version"`
	SHA256    map[string]string `json:"sha256"`
	Assets    map[string]string `json:"assets"`
	URLs      map[string]string `json:"urls"`
	KeyID     string            `json:"key_id"`
	Signature string            `json:"signature"`
}

func newUpdateCommand() *cobra.Command {
	var recover bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update shuttle to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if recover {
				exe, err := updateExecutable()
				if err != nil {
					return fmt.Errorf("cannot locate current binary: %w", err)
				}
				if err := recoverBinary(exe); err != nil {
					return fmt.Errorf("recovery failed: %w", err)
				}
				fmt.Println("✓ Restored the retained previous executable")
				return nil
			}
			return runUpdate()
		},
	}
	cmd.Flags().BoolVar(&recover, "recover", false, "restore the retained previous executable after an interrupted update")
	return cmd
}

func runUpdate() error {
	if siteBaseURL() == "" {
		return errNoDistributionChannel
	}

	asset := assetName()
	if asset == "" {
		return fmt.Errorf("no prebuilt binary for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	fmt.Print("Checking latest version... ")
	manifest, err := fetchManifest()
	if err != nil {
		return fmt.Errorf("failed to check latest version: %w", err)
	}
	fmt.Printf("%s\n", manifest.Version)

	current := version.Version
	if current != "dev" {
		comparison, compareErr := compareReleaseVersions(manifest.Version, current)
		if compareErr != nil {
			return fmt.Errorf("cannot compare release versions: %w", compareErr)
		}
		if comparison < 0 {
			return fmt.Errorf("refusing signed downgrade from %s to %s", current, manifest.Version)
		}
	}
	if current == manifest.Version || "v"+current == manifest.Version || current == "v"+manifest.Version {
		fmt.Printf("\n✓ Already up to date (%s)\n", current)
		return nil
	}
	fmt.Printf("Current: %s → Latest: %s\n", current, manifest.Version)

	url, ok := manifest.URLs[asset]
	if !ok {
		return fmt.Errorf("no download URL for %s in release manifest", asset)
	}
	expectedSHA, ok := manifest.SHA256[asset]
	if !ok {
		return fmt.Errorf("no checksum for %s in release manifest", asset)
	}

	fmt.Printf("Downloading %s ...\n", asset)
	bin, err := downloadBinary(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	if err := verifyChecksumHex(expectedSHA, bin); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	exe, err := updateExecutable()
	if err != nil {
		return fmt.Errorf("cannot locate current binary: %w", err)
	}

	warning, err := completeBinaryReplacement(exe, bin)
	if err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}
	if warning != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	fmt.Printf("\n✓ Updated to %s\n", manifest.Version)
	return nil
}

func fetchManifest() (*releaseManifest, error) {
	base := siteBaseURL()
	if base == "" {
		return nil, errNoDistributionChannel
	}
	if err := assertTrustedDownloadURL(manifestURL()); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, manifestURL(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("release manifest request timed out")
		}
		return nil, fmt.Errorf("release manifest request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d while fetching release manifest", resp.StatusCode)
	}
	var manifest releaseManifest
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("malformed release manifest: trailing JSON")
		}
		return nil, fmt.Errorf("malformed release manifest: %w", err)
	}
	if len(manifest.SHA256) == 0 && len(manifest.Assets) != 0 {
		manifest.SHA256 = manifest.Assets
		manifest.URLs = make(map[string]string, len(manifest.Assets))
		for asset := range manifest.Assets {
			manifest.URLs[asset] = siteBaseURL() + "/releases/latest/download/" + url.PathEscape(asset)
		}
	}
	if !validReleaseVersion(manifest.Version) || len(manifest.SHA256) == 0 {
		return nil, fmt.Errorf("malformed release manifest")
	}
	if len(manifest.URLs) == 0 {
		return nil, fmt.Errorf("release manifest carries no download URLs")
	}
	publicKey, err := trustedReleasePublicKey(manifest.KeyID)
	if err != nil {
		return nil, err
	}
	if err := release.Verify(manifest.Version, manifest.KeyID, manifest.SHA256, manifest.Signature, publicKey); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func trustedReleasePublicKey(keyID string) (string, error) {
	for _, revoked := range strings.Split(version.ReleaseRevokedKeyIDs, ",") {
		if strings.TrimSpace(revoked) == keyID {
			return "", fmt.Errorf("release key %q is revoked", keyID)
		}
	}
	keyring := version.ReleaseTrustedKeys
	if keyring == "" && version.ReleaseKeyID != "" {
		keyring = version.ReleaseKeyID + "=" + version.ReleasePublicKey
	}
	for _, entry := range strings.Split(keyring, ",") {
		id, publicKey, ok := strings.Cut(entry, "=")
		if !ok || id == "" || publicKey == "" || strings.TrimSpace(entry) != entry {
			continue
		}
		if id == keyID {
			return publicKey, nil
		}
	}
	return "", fmt.Errorf("release key %q is not trusted", keyID)
}

var errNoDistributionChannel = errors.New("no release distribution channel is configured")

const publicReleaseOrigin = "https://github.com/dev-toolings/shuttle"

func siteBaseURL() string {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("SHUTTLE_SITE_URL")), "/")
	if base == "" {
		return publicReleaseOrigin
	}
	return base
}

func manifestURL() string {
	if siteBaseURL() == publicReleaseOrigin {
		return siteBaseURL() + "/releases/latest/download/latest.json"
	}
	return siteBaseURL() + "/releases/latest"
}

func assetName() string {
	osTag := ""
	switch runtime.GOOS {
	case "linux":
		osTag = "linux"
	case "darwin":
		osTag = "darwin"
	default:
		return ""
	}
	archTag := ""
	switch runtime.GOARCH {
	case "amd64":
		archTag = "x64"
	case "arm64":
		archTag = "arm64"
	default:
		return ""
	}
	return fmt.Sprintf("shuttle-%s-%s", osTag, archTag)
}

// verifyChecksumHex checks data's sha256 against expectedHex (as supplied by
// the release manifest's sha256 map).
func verifyChecksumHex(expectedHex string, data []byte) error {
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, expectedHex) {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHex, actual)
	}
	return nil
}

// assertTrustedDownloadURL refuses any manifest URL that does not live on the
// configured release origin. URLs are outside the signature, so a spoofed Host
// header on the origin (or a future third-party mirror) could otherwise point
// `shuttle update` at an attacker origin. The signed checksum still pins the
// bytes; this keeps the download itself on the origin the operator chose.
func assertTrustedDownloadURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("unparsable download URL")
	}
	if parsed.User != nil {
		return fmt.Errorf("refusing credentials in download URL")
	}
	if parsed.Scheme != "https" && !allowInsecureUpdateForTests {
		return fmt.Errorf("refusing non-https download URL")
	}
	base := siteBaseURL()
	if base == "" {
		return errNoDistributionChannel
	}
	site, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("unparsable site URL")
	}
	if siteBaseURL() == publicReleaseOrigin && strings.EqualFold(parsed.Host, "release-assets.githubusercontent.com") {
		return nil
	}
	if !strings.EqualFold(parsed.Host, site.Host) {
		return fmt.Errorf("refusing download from %s: expected %s", parsed.Host, site.Host)
	}
	return nil
}

func downloadBinary(rawURL string) ([]byte, error) {
	if err := assertTrustedDownloadURL(rawURL); err != nil {
		return nil, err
	}
	parsed, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := updateHTTPClient.Do(parsed)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("download request timed out")
		}
		return nil, fmt.Errorf("download request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d while downloading release asset", resp.StatusCode)
	}
	if resp.ContentLength > maxUpdateDownload {
		return nil, fmt.Errorf("download exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUpdateDownload+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxUpdateDownload {
		return nil, fmt.Errorf("download exceeds size limit")
	}
	return data, nil
}

func validReleaseVersion(value string) bool {
	_, _, _, ok := parseReleaseVersion(value)
	return ok
}

var releaseVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func parseReleaseVersion(value string) (int, int, int, bool) {
	parts := releaseVersionPattern.FindStringSubmatch(value)
	if parts == nil {
		return 0, 0, 0, false
	}
	var major, minor, patch int
	if _, err := fmt.Sscanf(parts[1]+"."+parts[2]+"."+parts[3], "%d.%d.%d", &major, &minor, &patch); err != nil {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}

func compareReleaseVersions(candidate, current string) (int, error) {
	if !strings.HasPrefix(current, "v") {
		current = "v" + current
	}
	cmj, cmn, cpt, ok := parseReleaseVersion(candidate)
	if !ok {
		return 0, fmt.Errorf("invalid candidate %q", candidate)
	}
	mj, mn, pt, ok := parseReleaseVersion(current)
	if !ok {
		return 0, fmt.Errorf("invalid current %q", current)
	}
	if cmj != mj {
		if cmj < mj {
			return -1, nil
		}
		return 1, nil
	}
	if cmn != mn {
		if cmn < mn {
			return -1, nil
		}
		return 1, nil
	}
	if cpt < pt {
		return -1, nil
	}
	if cpt > pt {
		return 1, nil
	}
	return 0, nil
}

const recoverySuffix = ".recovery"

func recoveryPath(path string) string { return path + recoverySuffix }

// recoveryCleanupWarning means the new executable was already published and
// durably fsynced, but deletion of its recovery hard link could not itself be
// confirmed durable. The artifact has already been removed, so this must never
// be surfaced as an invitation to run --recover.
type recoveryCleanupWarning struct{ cause error }

func (e *recoveryCleanupWarning) Error() string {
	return "updated executable is durable, but recovery cleanup fsync failed after the artifact was removed"
}

func (e *recoveryCleanupWarning) Unwrap() error { return e.cause }

// replacementMultipleError deliberately does not unwrap its components. A
// post-unlink cleanup warning is safe only on its own; exposing it through
// errors.As when a close or other independent cleanup fault also happened
// would incorrectly turn a real failure into exit-success.
type replacementMultipleError struct {
	primary error
	cleanup error
}

func (e *replacementMultipleError) Error() string {
	return fmt.Sprintf("replacement failed: %v; additional cleanup failure: %v", e.primary, e.cleanup)
}

func completeBinaryReplacement(path string, data []byte) (string, error) {
	err := replaceBinary(path, data)
	if err == nil {
		return "", nil
	}
	var warning *recoveryCleanupWarning
	if errors.As(err, &warning) {
		return "update succeeded; no recovery artifact is currently available, so `shuttle update --recover` must not be used. The cleanup fsync was not confirmed; retrying cleanup is safe and idempotent.", nil
	}
	return "", err
}

func replaceBinary(path string, data []byte) (retErr error) {
	fs := replaceBinaryFS
	info, err := fs.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect current executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular executable")
	}
	dir := filepath.Dir(path)
	tmp, err := fs.CreateTemp(dir, "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmpOpen := true
	tmpPublished := false
	var dirFile *os.File
	dirOpen := false
	defer func() {
		var cleanup []error
		if dirOpen {
			if err := fs.Close(dirFile); err != nil {
				cleanup = append(cleanup, fmt.Errorf("close executable directory: %w", err))
			}
		}
		if tmpOpen {
			if err := fs.Close(tmp); err != nil {
				cleanup = append(cleanup, fmt.Errorf("close temporary executable: %w", err))
			}
		}
		if !tmpPublished {
			if err := fs.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanup = append(cleanup, fmt.Errorf("remove temporary executable: %w", err))
			}
		}
		if len(cleanup) != 0 {
			cleanupErr := errors.Join(cleanup...)
			if retErr != nil {
				retErr = &replacementMultipleError{primary: retErr, cleanup: cleanupErr}
			} else {
				retErr = cleanupErr
			}
		}
	}()

	if err := fs.Chmod(tmp, 0o755); err != nil {
		return fmt.Errorf("chmod temporary executable: %w", err)
	}
	if _, err := fs.Write(tmp, data); err != nil {
		return fmt.Errorf("write temporary executable: %w", err)
	}
	if err := fs.Sync(tmp); err != nil {
		return fmt.Errorf("sync new executable: %w", err)
	}
	if err := fs.Close(tmp); err != nil {
		return fmt.Errorf("close temporary executable: %w", err)
	}
	tmpOpen = false

	backupPath := recoveryPath(path)
	if _, err := fs.Lstat(backupPath); err == nil {
		return fmt.Errorf("recovery artifact %s already exists; run `shuttle update --recover` before retrying", backupPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect recovery artifact: %w", err)
	}
	if err := fs.Link(path, backupPath); err != nil {
		return fmt.Errorf("create recovery hard link: %w", err)
	}
	dirFile, err = fs.Open(dir)
	if err != nil {
		return fmt.Errorf("open executable directory: %w", err)
	}
	dirOpen = true
	if err := fs.Sync(dirFile); err != nil {
		return fmt.Errorf("sync recovery link: %w", err)
	}
	if err := fs.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomically publish update: %w", err)
	}
	tmpPublished = true
	if err := fs.Sync(dirFile); err != nil {
		return fmt.Errorf("sync published executable: %w; recovery retained at %s", err, backupPath)
	}
	if err := cleanupRecoveryArtifact(fs, backupPath, dirFile); err != nil {
		return err
	}
	if err := fs.Close(dirFile); err != nil {
		return fmt.Errorf("close executable directory: %w", err)
	}
	dirOpen = false
	return nil
}

// cleanupRecoveryArtifact is idempotent. A successful Remove followed by a
// failed directory sync is a warning, not a rollback path: publication was
// already durable and the recovery name is absent in the running filesystem.
func cleanupRecoveryArtifact(fs binaryFilesystem, backupPath string, dirFile *os.File) error {
	if err := fs.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cleanup recovery artifact %s: %w", backupPath, err)
	}
	if err := fs.Sync(dirFile); err != nil {
		return &recoveryCleanupWarning{cause: fmt.Errorf("sync recovery cleanup: %w", err)}
	}
	return nil
}

func recoverBinary(path string) error {
	fs := replaceBinaryFS
	backupPath := recoveryPath(path)
	info, err := fs.Lstat(backupPath)
	if err != nil {
		return fmt.Errorf("inspect recovery artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("recovery artifact is not a regular executable")
	}
	if err := fs.Rename(backupPath, path); err != nil {
		return fmt.Errorf("restore recovery executable: %w", err)
	}
	dirFile, err := fs.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open executable directory after recovery: %w", err)
	}
	if err := fs.Sync(dirFile); err != nil {
		if closeErr := fs.Close(dirFile); closeErr != nil {
			return fmt.Errorf("sync recovered executable: %w; close also failed: %v", err, closeErr)
		}
		return fmt.Errorf("sync recovered executable: %w", err)
	}
	if err := fs.Close(dirFile); err != nil {
		return fmt.Errorf("close recovered executable directory: %w", err)
	}
	return nil
}
