package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/release"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
)

func TestPublicChannelDefaultOrigin(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", "")
	if got := siteBaseURL(); got != "https://github.com/dev-toolings/shuttle" {
		t.Fatalf("unexpected default origin: %q", got)
	}
}

func TestPublicAssetRedirectTrust(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", "")
	if err := assertTrustedDownloadURL("https://release-assets.githubusercontent.com/example"); err != nil {
		t.Fatal(err)
	}
	if err := assertTrustedDownloadURL("https://untrusted.example/example"); err == nil {
		t.Fatal("untrusted redirect accepted")
	}
	t.Setenv("SHUTTLE_SITE_URL", "https://override.example")
	if err := assertTrustedDownloadURL("https://release-assets.githubusercontent.com/example"); err == nil {
		t.Fatal("public asset host accepted for override")
	}
}

func TestSignedReleaseAssetsGenerateDownloadURLs(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string]string{"shuttle-linux-x64": strings.Repeat("a", 64)}
	payload, err := release.CanonicalManifestBytes("v1.0.0", "test", assets)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"version": "v1.0.0", "assets": assets, "key_id": "test", "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	allowInsecureUpdateForTests = true
	t.Cleanup(func() { allowInsecureUpdateForTests = false })
	t.Setenv("SHUTTLE_SITE_URL", server.URL)
	previous := version.ReleaseTrustedKeys
	version.ReleaseTrustedKeys = "test=" + base64.StdEncoding.EncodeToString(public)
	t.Cleanup(func() { version.ReleaseTrustedKeys = previous })
	manifest, err := fetchManifest()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := manifest.URLs["shuttle-linux-x64"], server.URL+"/releases/latest/download/shuttle-linux-x64"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestReleaseOriginRejectsURLCredentials(t *testing.T) {
	t.Setenv("SHUTTLE_SITE_URL", "https://user:password@example.invalid")
	if _, err := fetchManifest(); err == nil {
		t.Fatal("origin credentials accepted")
	}
}
