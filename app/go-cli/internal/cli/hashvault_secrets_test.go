package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func hashvaultTestPreparation() (hashvaultPreparation, hashvaultManifest) {
	spec := hashvaultSpec{Expose: "env", Target: "database_url", Services: []string{"api"}, UID: "1000", GID: "1000", Mode: "0400"}
	m := hashvaultManifest{Version: "hv-manifest-1", App: "acme-api", Items: map[string]hashvaultSpec{"DATABASE_URL": spec}}
	p := hashvaultPreparation{Version: "hv-preparation-1", ID: strings.Repeat("a", 32), Kind: "swarm", Target: "swarm-main", Env: "prod", App: m.App, Items: map[string]hashvaultPreparedItem{"DATABASE_URL": {Version: 3, Spec: spec, ObjectName: "hv_acme-api_database_url_v3", ObjectID: "object"}}}
	return p, m
}

func TestHashvaultStackReplacesLegacyMountsAndKeepsTheContract(t *testing.T) {
	p, m := hashvaultTestPreparation()
	manifest, err := hashvaultSecretManifest(p, m, p.Target)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{App: "demo", Secrets: config.Secrets{Items: hashvaultSecretItems(&p)}}
	parsed := &composeFile{Raw: map[string]any{"services": map[string]any{"api": map[string]any{"image": "example/api:tag", "secrets": []any{map[string]any{"source": "old_database", "target": "database_url"}, map[string]any{"source": "foreign", "target": "other"}}}}, "secrets": map[string]any{"old_database": map[string]any{"external": true}, "foreign": map[string]any{"external": true}}}}
	body, err := generateSwarmStackWithSecrets(parsed, cfg, nil, manifest)
	if err != nil {
		t.Fatal(err)
	}
	assertRootGlobalSectionsAccept(t, body)
	var root map[string]any
	if err := yaml.Unmarshal([]byte(body), &root); err != nil {
		t.Fatal(err)
	}
	service := root["services"].(map[string]any)["api"].(map[string]any)
	refs := service["secrets"].([]any)
	if len(refs) != 2 {
		t.Fatal("legacy and new mounts overlap", refs)
	}
	for _, raw := range refs {
		ref := raw.(map[string]any)
		if ref["target"] == "database_url" && (ref["source"] != "hv_acme-api_database_url_v3" || ref["uid"] != "1000" || ref["mode"] != 256) {
			t.Fatal(ref)
		}
	}
	labels := rawLabelsToStringMap(service["labels"])
	if labels["io.hashvault.preparation"] != p.ID {
		t.Fatal("rollback snapshot not retained", labels)
	}
	if strings.Contains(body, "SHUTTLE_ENV_SECRETS") {
		t.Fatal("Shuttle rewrote the image's env-file contract")
	}
}

func TestHashvaultDescriptorsCannotChangeTheSignedContract(t *testing.T) {
	p, m := hashvaultTestPreparation()
	changed := p.Items["DATABASE_URL"]
	changed.Spec.UID = "0"
	p.Items["DATABASE_URL"] = changed
	if _, err := hashvaultSecretManifest(p, m, p.Target); err == nil {
		t.Fatal("descriptor changed the file owner")
	}
	p, m = hashvaultTestPreparation()
	p.App = "another-app"
	if _, err := hashvaultSecretManifest(p, m, p.Target); err == nil {
		t.Fatal("descriptor changed the application")
	}
	if err := validateHashvaultSpec("KEY", hashvaultSpec{Expose: "file", Services: []string{"api"}, Mode: "0666"}); err == nil {
		t.Fatal("world-writeable file accepted")
	}
}

func TestHashvaultManifestMustMatchTheCommittedContract(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	path := filepath.Join(dir, "hashvault.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := committedHashvaultManifest(path); err == nil || !strings.Contains(err.Error(), "not committed") {
		t.Fatalf("untracked manifest: %v", err)
	}
	git("add", "hashvault.json")
	git("commit", "-q", "-m", "manifest")
	if raw, err := committedHashvaultManifest(path); err != nil || string(raw) != `{"v":1}` {
		t.Fatalf("committed manifest: %q %v", raw, err)
	}
	if err := os.WriteFile(path, []byte(`{"v":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := committedHashvaultManifest(path); err == nil || !strings.Contains(err.Error(), "differs from HEAD") {
		t.Fatalf("modified manifest: %v", err)
	}
}

func TestHashvaultSyncOutcomeKeepsPendingApartFromFailure(t *testing.T) {
	trailer := "operation=hashvault-sync digest=abc\n"
	for _, tc := range []struct {
		name, stdout, outcome string
		code                  int
		fails                 bool
	}{
		{"confirmed", "\nhashvault-sync=confirmed\n" + trailer, hashvaultSyncConfirmedMarker, 0, false},
		{"pending is not a failure", "\nhashvault-sync=pending\n" + trailer, hashvaultSyncPendingMarker, 0, false},
		{"nothing to confirm is not confirmed", "\nhashvault-sync=no-release\n" + trailer, hashvaultSyncNoReleaseMarker, 0, false},
		{"helper error", "", "", 1, true},
		{"older helper without marker", trailer, "", 0, true},
		{"ambiguous answer", "hashvault-sync=pending\nhashvault-sync=confirmed\n", "", 0, true},
	} {
		outcome, err := hashvaultSyncOutcome(tc.code, tc.stdout, "reason")
		if (err != nil) != tc.fails || outcome != tc.outcome {
			t.Errorf("%s: outcome=%q err=%v", tc.name, outcome, err)
		}
	}
}
