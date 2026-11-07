package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

type fakeInfraResolver map[string]string

func (f fakeInfraResolver) Resolve(_ context.Context, repo, tag string) (string, error) {
	if digest, ok := f[repo+":"+tag]; ok {
		return digest, nil
	}
	return "", fmt.Errorf("tag not found: %s:%s", repo, tag)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDockerHubInfraResolverUsesTokenAndManifestHead(t *testing.T) {
	seenToken, seenHead := false, false
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "auth.docker.io" {
			seenToken = req.Method == http.MethodGet && req.URL.Scheme == "https" && req.URL.Query().Get("scope") == "repository:library/redis:pull"
			return &http.Response{StatusCode: 200, Body: ioNopCloser(`{"token":"test-token"}`), Header: http.Header{}}, nil
		}
		if req.URL.Host != "registry-1.docker.io" {
			return nil, fmt.Errorf("unexpected host %s", req.URL.Host)
		}
		seenHead = req.Method == http.MethodHead && req.URL.Scheme == "https" && req.Header.Get("Authorization") == "Bearer test-token" && strings.Contains(req.Header.Get("Accept"), "application/vnd.oci.image.index.v1+json")
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{"Docker-Content-Digest": []string{"sha256:" + strings.Repeat("a", 64)}}}, nil
	})}
	resolver := dockerHubInfraResolver{client: client}
	digest, err := resolver.Resolve(context.Background(), "redis", "8-alpine")
	if err != nil || !seenToken || !seenHead || !infraDigestPattern.MatchString(digest) {
		t.Fatalf("resolve=%q err=%v token=%v head=%v", digest, err, seenToken, seenHead)
	}
}

func TestResolvedInfrastructureReferenceRequiresOfficialRepositoryAndDigest(t *testing.T) {
	for _, tc := range []struct {
		repo, tag, digest string
		ok                bool
	}{
		{"redis", "8-alpine", "sha256:" + strings.Repeat("a", 64), true},
		{"evil", "8", "sha256:" + strings.Repeat("a", 64), false},
		{"redis", "8", "sha256:bad", false},
	} {
		_, err := resolvedInfrastructureReference(tc.repo, tc.tag, tc.digest)
		if (err == nil) != tc.ok {
			t.Errorf("%s:%s digest %s err=%v", tc.repo, tc.tag, tc.digest, err)
		}
	}
}

func TestInfrastructureTagsStayOnRetainedMajorAndAnnounceNextMajor(t *testing.T) {
	got, err := infrastructureTag("rabbitmq", "rabbitmq:4.4.0-alpine@sha256:"+strings.Repeat("a", 64), "")
	if err != nil || got != "4-alpine" {
		t.Fatalf("retained rabbitmq tag=%q err=%v", got, err)
	}
	resolver := fakeInfraResolver{
		"rabbitmq:4-alpine": "sha256:" + strings.Repeat("b", 64),
		"rabbitmq:5-alpine": "sha256:" + strings.Repeat("c", 64),
	}
	previous := infraResolverForRun
	infraResolverForRun = resolver
	t.Cleanup(func() { infraResolverForRun = previous })
	gotRef, err := resolveInfrastructureImage(context.Background(), resolver, "rabbitmq", "rabbitmq:4.4.0-alpine@sha256:"+strings.Repeat("a", 64), "")
	if err != nil || gotRef != "rabbitmq:4-alpine@sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("resolved=%q err=%v", gotRef, err)
	}
}

func TestInfrastructureOverridesKeepTheirExplicitTagsAndPinnedReferences(t *testing.T) {
	digest := "sha256:" + strings.Repeat("d", 64)
	if tag, err := infrastructureTag("redis", "", "redis:7.4-alpine"); err != nil || tag != "7.4-alpine" {
		t.Fatalf("explicit Redis tag=%q err=%v", tag, err)
	}
	resolver := fakeInfraResolver{"redis:7.4-alpine": digest}
	resolved, err := resolveInfrastructureImage(context.Background(), resolver, "redis", "", "redis:7.4-alpine")
	if err != nil || resolved != "redis:7.4-alpine@"+digest {
		t.Fatalf("explicit Redis tag resolved as %q, err=%v", resolved, err)
	}
	pinned := "caddy:2.10@" + digest
	cfg := &config.Config{Caddy: config.Caddy{Image: pinned}}
	previous := infraResolverForRun
	infraResolverForRun = fakeInfraResolver{"registry:3": "sha256:" + strings.Repeat("e", 64)}
	t.Cleanup(func() { infraResolverForRun = previous })
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, true); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolvedInfrastructure["caddy"]; got != pinned {
		t.Fatalf("tagged Caddy digest override changed: got %q want %q", got, pinned)
	}
}

func TestConfiguredInfrastructureUsesResolvedDigests(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	resolver := fakeInfraResolver{
		"redis:8-alpine": digest("a"), "redis:9-alpine": digest("e"),
		"rabbitmq:4-alpine": digest("b"), "rabbitmq:5-alpine": digest("f"),
		"registry:3": digest("c"), "registry:4": digest("1"),
		"caddy:2": digest("d"), "caddy:3": digest("2"),
	}
	previous := infraResolverForRun
	infraResolverForRun = resolver
	t.Cleanup(func() { infraResolverForRun = previous })
	cfg := &config.Config{}
	cfg.Production.Redis, cfg.Production.RabbitMQ = true, true
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, true); err != nil {
		t.Fatal(err)
	}
	for repo, wantDigest := range map[string]string{"redis": digest("a"), "rabbitmq": digest("b"), "registry": digest("c"), "caddy": digest("d")} {
		if !strings.HasSuffix(cfg.ResolvedInfrastructure[repo], "@"+wantDigest) {
			t.Errorf("%s reference = %q", repo, cfg.ResolvedInfrastructure[repo])
		}
	}
	if got := redisImageForConfig(cfg); got != cfg.ResolvedInfrastructure["redis"] {
		t.Fatalf("Redis stack image = %q", got)
	}
	if got := infrastructureRabbitServiceWithImage("demo", cfg.Production.RabbitMQImage)["image"]; got != cfg.ResolvedInfrastructure["rabbitmq"] {
		t.Fatalf("RabbitMQ stack image = %v", got)
	}
	if got := caddyImage(cfg.Caddy); got != cfg.ResolvedInfrastructure["caddy"] {
		t.Fatalf("Caddy setup image = %q", got)
	}
}

func TestInfrastructureResolutionKeepsValidRetainedDigestWhenHubFails(t *testing.T) {
	retained := "redis:7.4.5-alpine@sha256:" + strings.Repeat("a", 64)
	got, err := resolveInfrastructureImage(context.Background(), fakeInfraResolver{}, "redis", retained, "")
	if err != nil || got != retained {
		t.Fatalf("fallback=%q err=%v", got, err)
	}
	if _, err := resolveInfrastructureImage(context.Background(), fakeInfraResolver{}, "redis", "", ""); err == nil || !strings.Contains(err.Error(), "cannot resolve current stable image") {
		t.Fatalf("fresh host should fail clearly when Hub is unreachable: %v", err)
	}
}

func TestRetainedInfrastructureAuditDecodesOfficialDigests(t *testing.T) {
	redis := "redis:8-alpine@sha256:" + strings.Repeat("a", 64)
	registry := "registry:3@sha256:" + strings.Repeat("b", 64)
	images, err := decodeRetainedInfrastructureImages(`{"redis":"` + redis + `","registry":"` + registry + `"}`)
	if err != nil || images["redis"] != redis || images["registry"] != registry {
		t.Fatalf("images=%v err=%v", images, err)
	}
	if _, err := decodeRetainedInfrastructureImages(`{"redis":"redis:8-alpine"}`); err == nil {
		t.Fatal("retained tag without a digest was accepted")
	}
}

// The probe runs in sh with a fake docker: a fresh host with Docker but an
// inactive Swarm is absent (no `docker stack ls`), an active manager reports
// what runs, and an unreadable state fails closed.
func TestSetupRetainedStateProbeHandlesSwarmStates(t *testing.T) {
	if _, err := os.Stat("/var/lib/shuttle/apps"); err == nil {
		t.Skip("this machine has /var/lib/shuttle/apps")
	}
	run := func(t *testing.T, swarm string, registry, daemonErrors bool) shuttlessh.Result {
		t.Helper()
		dir := t.TempDir()
		containerList, registryInspect := `echo other`, `exit 1`
		if registry {
			containerList = `echo shuttle-registry`
			registryInspect = `echo "registry:3@sha256:` + strings.Repeat("a", 64) + `"`
		}
		serviceList, serviceInspect := `echo demo_redis`, `echo "redis:8-alpine@sha256:`+strings.Repeat("b", 64)+`"`
		if daemonErrors {
			containerList, serviceList = `echo "daemon error" >&2; exit 1`, `echo "daemon error" >&2; exit 1`
		}
		fake := `#!/bin/sh
case "$1 $2" in
  "info ") exit 0 ;;
  "info --format") echo "` + swarm + `"; exit 0 ;;
  "container ls") ` + containerList + `; exit 0 ;;
  "container inspect") ` + registryInspect + `; exit 0 ;;
  "service ls") ` + serviceList + `; exit 0 ;;
  "service inspect") ` + serviceInspect + `; exit 0 ;;
  "stack ls") echo "stack ls must not run" >&2; exit 9 ;;
esac
exit 3
`
		if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0o755); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("sh", "-s", "--", "demo")
		command.Stdin = strings.NewReader(setupRetainedStateProbe)
		command.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
		var stdout, stderr strings.Builder
		command.Stdout, command.Stderr = &stdout, &stderr
		code := 0
		if err := command.Run(); err != nil {
			code = 1
		}
		return shuttlessh.Result{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	}
	images, err := retainedInfrastructureImagesFromProbe(run(t, "inactive false", false, false))
	if err != nil || len(images) != 0 {
		t.Fatalf("fresh host with inactive Swarm = %v, %v", images, err)
	}
	images, err = retainedInfrastructureImagesFromProbe(run(t, "active true", true, false))
	if err != nil || images["registry"] == "" || images["redis"] == "" || images["caddy"] != "" {
		t.Fatalf("manager with running infra = %v, %v", images, err)
	}
	if _, err := retainedInfrastructureImagesFromProbe(run(t, "active false", false, false)); err == nil {
		t.Fatal("an active worker node without manager access must fail closed")
	}
	// A daemon error while listing must never read as absence.
	if _, err := retainedInfrastructureImagesFromProbe(run(t, "active true", false, true)); err == nil {
		t.Fatal("a daemon error while listing must fail closed")
	}
	if _, err := retainedInfrastructureImagesFromProbe(shuttlessh.Result{Code: 0, Stdout: "redis=redis:8-alpine\nstate=present\n"}); err == nil {
		t.Fatal("a running image without a digest must stop setup")
	}
	if _, err := retainedInfrastructureImagesFromProbe(shuttlessh.Result{Code: 0, Stdout: "weird\n"}); err == nil {
		t.Fatal("an unexpected probe response must fail closed")
	}
}

func ioNopCloser(value string) io.ReadCloser { return io.NopCloser(strings.NewReader(value)) }

// production-host prod, 2026-10-28: the edge deployed by an earlier generation runs
// digest-only. It must not stop setup; Redis in the same form still does.
func TestRetainedProbeAcceptsLegacyDigestOnlyCaddy(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	images, err := retainedInfrastructureImagesFromProbe(shuttlessh.Result{Stdout: "caddy=caddy@" + digest + "\nstate=present\n"})
	if err != nil || images["caddy"] != "" {
		t.Fatalf("legacy caddy edge refused or kept as a major: %v %v", images, err)
	}
	if _, err := retainedInfrastructureImagesFromProbe(shuttlessh.Result{Stdout: "redis=redis@" + digest + "\nstate=present\n"}); err == nil {
		t.Fatal("digest-only redis must still stop setup: its major protects the data")
	}
}

func TestDecodeRetainedImagesDropsLegacyDigestOnlyCaddy(t *testing.T) {
	images, err := decodeRetainedInfrastructureImages(`{"caddy":"caddy@sha256:` + strings.Repeat("b", 64) + `"}`)
	if err != nil || len(images) != 0 {
		t.Fatalf("legacy caddy edge refused on deploy: %v %v", images, err)
	}
}
