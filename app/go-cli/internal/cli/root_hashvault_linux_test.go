//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestHashvaultSessionUsesOnlyLocalSocketAndKeepsErrorsPrivate(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var loggedOut atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-session" {
			t.Error("machine authentication missing")
		}
		switch r.URL.Path {
		case "/v1/publications/swarm-main/acme-api":
			_ = json.NewEncoder(w).Encode(map[string]any{"publication": nil})
		case "/v1/auth/logout":
			loggedOut.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "private-upstream-value")
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}
	session := &localHashvaultSession{client: &http.Client{Transport: transport}, token: "fixture-session"}
	var active struct {
		Publication *hashvaultRelease `json:"publication"`
	}
	if err := session.call(context.Background(), "GET", "/v1/publications/swarm-main/acme-api", nil, &active); err != nil || active.Publication != nil {
		t.Fatal(active, err)
	}
	if err := session.call(context.Background(), "GET", "/refused", nil, &active); err == nil || strings.Contains(err.Error(), "private-upstream-value") {
		t.Fatal("upstream error leaked or was accepted", err)
	}
	session.close()
	if !loggedOut.Load() || session.token != "" {
		t.Fatal("machine session was retained after logout")
	}
}

func TestHashvaultRollbackReleaseUsesTheRetainedStack(t *testing.T) {
	p, manifest := hashvaultTestPreparation()
	old := "services:\n  api:\n    image: example.com/api@sha256:old\n    labels:\n      io.hashvault.preparation: " + p.ID + "\n      io.hashvault.target: swarm-main\n      io.hashvault.app: " + manifest.App + "\n"
	release, err := hashvaultReleaseFromStack([]byte(old))
	if err != nil || release == nil || release.ID != p.ID || release.Release != rootplan.PayloadDigest([]byte(old)) {
		t.Fatal("retained release coordinates changed", release, err)
	}
	mixed := old + "  worker:\n    labels:\n      io.hashvault.preparation: " + strings.Repeat("b", 32) + "\n      io.hashvault.target: swarm-main\n      io.hashvault.app: " + manifest.App + "\n"
	if _, err := hashvaultReleaseFromStack([]byte(mixed)); err == nil {
		t.Fatal("mixed secret generations accepted")
	}
	if release, err := hashvaultReleaseFromStack([]byte("services:\n  api:\n    image: example.com/api@sha256:old\n")); err != nil || release != nil {
		t.Fatal("legacy release invented a preparation", release, err)
	}
}

func TestHashvaultEnrollmentRefusesLoosePermissionsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "enrollment.json")
	if err := os.WriteFile(file, []byte(`{"socket":"/run/hashvault/api.sock","principal":"machine/shuttle-helper","key_file":"/etc/shuttle/hashvault.key"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootHashvaultEnrollment(file); err == nil {
		t.Fatal("unprotected enrollment accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootHashvaultEnrollment(link); err == nil {
		t.Fatal("symlink enrollment accepted")
	}
}

// hardenedHashvaultStack runs the production pipeline, hardening included:
// hardenService adds a long-syntax tmpfs volume that once made every real
// stack undecodable for the confirmation.
func hardenedHashvaultStack(t *testing.T, version int, preparation string) string {
	t.Helper()
	p, m := hashvaultTestPreparation()
	p.ID = preparation
	item := p.Items["DATABASE_URL"]
	item.Version, item.ObjectName = uint64(version), "hv_acme-api_database_url_v"+strconv.Itoa(version)
	p.Items["DATABASE_URL"] = item
	manifest, err := hashvaultSecretManifest(p, m, p.Target)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{App: "demo", Domain: "demo.example.com"}
	cfg.Secrets.Items = hashvaultSecretItems(&p)
	cf := parseComposeString(t, "services:\n  web:\n    build: .\n    healthcheck: {test: [\"CMD\", \"true\"]}\n  api:\n    build: .\n    healthcheck: {test: [\"CMD\", \"true\"]}\n")
	digest := "registry/app@sha256:" + strings.Repeat("a", 64)
	generated, err := generateSwarmStackWithSecrets(cf, cfg, map[string]string{"web": digest, "api": digest}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	secured, err := secureStack(generated, cfg, "8000")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(secured, "tmpfs") {
		t.Fatal("fixture no longer exercises the hardened tmpfs volume")
	}
	return secured
}

// A rotation or a rollback usually keeps every image, so the convergence wait
// passes on the old tasks. The confirmation must decode the real stack, name
// its own preparation, and refuse tasks that still mount another version.
func TestHashvaultConfirmationReadsHardenedStacksAndWaitsForTheirMounts(t *testing.T) {
	current := hardenedHashvaultStack(t, 3, strings.Repeat("c", 32))
	// After a rollback, current.yml holds the earlier release: it must confirm
	// its own preparation and its own secret version.
	rolledBack := hardenedHashvaultStack(t, 2, strings.Repeat("b", 32))
	task := func(version, mode int) string {
		return `[{"File":{"Name":"database_url","UID":"1000","GID":"1000","Mode":` + strconv.Itoa(mode) + `},"SecretID":"x","SecretName":"hv_acme-api_database_url_v` + strconv.Itoa(version) + `"}]`
	}
	for _, release := range []struct {
		name, stack, preparation string
		served, stale            int
	}{
		{"rotation", current, strings.Repeat("c", 32), 3, 2},
		{"rollback", rolledBack, strings.Repeat("b", 32), 2, 3},
	} {
		identity, err := hashvaultReleaseFromStack([]byte(release.stack))
		if err != nil || identity == nil || identity.ID != release.preparation {
			t.Fatalf("%s: release identity %+v, %v", release.name, identity, err)
		}
		if _, err := rootStackServices("demo", []byte(release.stack)); err != nil {
			t.Fatalf("%s: %v", release.name, err)
		}
		want, err := rootStackSecretMounts("demo", []byte(release.stack))
		if err != nil {
			t.Fatalf("%s: %v", release.name, err)
		}
		for _, tc := range []struct {
			label, line string
			served      bool
		}{
			{"declared version mounted", task(release.served, 0o400), true},
			{"other version still mounted", task(release.stale, 0o400), false},
			{"looser mode", task(release.served, 0o444), false},
			{"no secret at all", "null", false},
		} {
			got, err := parseRootTaskSecrets(tc.line)
			if err != nil {
				t.Fatalf("%s/%s: %v", release.name, tc.label, err)
			}
			if served := rootSecretMountsDiffer(want["api"], got) == ""; served != tc.served {
				t.Errorf("%s/%s: served=%v, want %v", release.name, tc.label, served, tc.served)
			}
		}
	}
}

// Every promotion asks whether its stack is a Hashvault release. A stack that
// is not one, with labels written as a list, must answer "no", not fail.
func TestHashvaultReleaseIgnoresOrdinaryStacks(t *testing.T) {
	release, err := hashvaultReleaseFromStack([]byte("services:\n  web:\n    image: x\n    labels: [\"a=b\"]\n    volumes: [{type: tmpfs, target: /tmp}]\n"))
	if err != nil || release != nil {
		t.Fatalf("ordinary stack: %+v, %v", release, err)
	}
}

func TestRootStackSecretMountsAppliesComposeDefaults(t *testing.T) {
	mounts, err := rootStackSecretMounts("demo", []byte("services:\n  api:\n    image: x\n    secrets: [local, ext]\nsecrets:\n  local: {file: ./s}\n  ext: {external: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []rootSecretMount{{Name: "ext", Target: "ext", UID: "0", GID: "0", Mode: 0o444}, {Name: "demo_local", Target: "local", UID: "0", GID: "0", Mode: 0o444}}
	if reason := rootSecretMountsDiffer(want, mounts["api"]); reason != "" {
		t.Fatal(reason)
	}
	legacy, err := rootStackSecretMounts("demo", []byte("services:\n  api:\n    image: x\n    secrets: [foreign]\nsecrets:\n  foreign: {external: {name: actual-secret}}\n"))
	if err != nil || len(legacy["api"]) != 1 || legacy["api"][0].Name != "actual-secret" {
		t.Fatalf("legacy external name: %+v, %v", legacy, err)
	}
	if _, err := rootStackSecretMounts("demo", []byte("services:\n  api:\n    image: x\n    secrets: [missing]\n")); err == nil {
		t.Fatal("an undeclared secret reference must be refused")
	}
}

// Only a vault that is unavailable or tasks still rolling may read as
// "pending". A stack without a preparation is "nothing to confirm", and a
// stack that cannot be read is a failure.
func TestHashvaultConfirmationClassifiesItsFailures(t *testing.T) {
	dir := t.TempDir()
	ordinary := filepath.Join(dir, "ordinary.yml")
	if err := os.WriteFile(ordinary, []byte("services:\n  web:\n    image: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := confirmRootHashvaultRelease("demo", ordinary, time.Second); !errors.Is(err, errHashvaultNoRelease) {
		t.Fatalf("ordinary stack: %v", err)
	}
	var deferral *hashvaultDeferral
	if err := confirmRootHashvaultRelease("demo", filepath.Join(dir, "missing.yml"), time.Second); err == nil || errors.As(err, &deferral) {
		t.Fatalf("unreadable stack must fail, not defer: %v", err)
	}
	if err := waitRootHashvaultMounts(context.Background(), "demo", []byte("services: [")); err == nil || errors.As(err, &deferral) {
		t.Fatalf("an invalid stack must fail, not defer: %v", err)
	}
	if !errors.As(deferHashvault(errors.New("sealed")), &deferral) || deferHashvault(nil) != nil {
		t.Fatal("deferHashvault does not mark retryable errors")
	}
}
