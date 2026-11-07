package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeStack(t *testing.T, path string, images ...string) {
	t.Helper()
	body := "services:\n"
	for i, image := range images {
		body += "  s" + string(rune('a'+i)) + ":\n    image: " + image + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Repository names are flat, so `demo-app` + service `agents-api` and
// `demo-app-agents` + service `api` both spell `demo-app-agents-api`. A
// promotion of one used to compute what to delete from its own stacks alone,
// which made the other application's release manifests collateral — and took
// its rollback with them.
func TestRegistryKeepsNeighbouringApplicationDigests(t *testing.T) {
	root := t.TempDir()

	const (
		mine      = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		neighbour = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	writeStack(t, filepath.Join(root, "demo-app", "current.yml"),
		rootRegistryImagePrefix+"demo-app-web@"+mine)
	writeStack(t, filepath.Join(root, "demo-app-agents", "current.yml"),
		rootRegistryImagePrefix+"demo-app-agents-api@"+neighbour)

	keep, err := rootRegistryKeepDigests(
		root,
		filepath.Join(root, "demo-app", "current.yml"),
		filepath.Join(root, "demo-app", "previous.yml"),
	)
	if err != nil {
		t.Fatalf("rootRegistryKeepDigests: %v", err)
	}
	if !keep[mine] {
		t.Error("the deploying application's own digest must be kept")
	}
	if !keep[neighbour] {
		t.Error("a digest another application still references must be kept; deleting it destroys that application's rollback")
	}
}

// An image that does not come from the loopback registry is not this host's to
// account for, and must never enter the keep set.
func TestRegistryKeepSetIgnoresForeignImages(t *testing.T) {
	root := t.TempDir()

	const foreign = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	writeStack(t, filepath.Join(root, "demo-app", "current.yml"), "docker.io/library/redis@"+foreign)

	keep, err := rootRegistryKeepDigests(
		root,
		filepath.Join(root, "demo-app", "current.yml"),
		filepath.Join(root, "demo-app", "previous.yml"),
	)
	if err != nil {
		t.Fatalf("rootRegistryKeepDigests: %v", err)
	}
	if keep[foreign] {
		t.Error("an image pulled from a public registry must not be tracked as a loopback manifest")
	}
}

// A host that has never deployed anything has no state directory, which is a
// normal first run and not an error.
func TestRegistryKeepSetToleratesMissingStateRoot(t *testing.T) {
	keep, err := rootRegistryKeepDigests(filepath.Join(t.TempDir(), "absent"), "/nonexistent/current.yml", "/nonexistent/previous.yml")
	if err != nil {
		t.Fatalf("a missing state root must not fail the promotion: %v", err)
	}
	if len(keep) != 0 {
		t.Errorf("keep = %v, want empty", keep)
	}
}

// Registry sweep tests use the real maintenance path and a loopback HTTP server
// so ownership and URL decisions are observed at the trust boundary.
type registrySweepFixture struct {
	t        *testing.T
	server   *httptest.Server
	catalog  []string
	tags     map[string][]string
	digests  map[string]string
	deletes  []string
	requests []string
	logs     strings.Builder
}

func newRegistrySweepFixture(t *testing.T, catalog []string, tags map[string][]string, digests map[string]string) *registrySweepFixture {
	t.Helper()
	fixture := &registrySweepFixture{t: t, catalog: catalog, tags: tags, digests: digests}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests = append(fixture.requests, r.Method+" "+r.URL.EscapedPath())
		if r.Method == http.MethodDelete {
			fixture.deletes = append(fixture.deletes, r.URL.EscapedPath())
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.Method == http.MethodHead {
			reference := strings.TrimPrefix(r.URL.Path, "/v2/")
			reference = strings.TrimSuffix(reference, "/manifests/"+path.Base(r.URL.Path))
			tag := path.Base(r.URL.Path)
			if digest, ok := fixture.digests[reference+":"+tag]; ok {
				w.Header().Set("Docker-Content-Digest", digest)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case r.URL.Path == "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(registryCatalog{Repositories: fixture.catalog})
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			repository := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/"), "/tags/list")
			_ = json.NewEncoder(w).Encode(registryTags{Tags: fixture.tags[repository]})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	originalURL, originalKeep := rootRegistryBaseURL, rootRegistryKeepRead
	originalVolume, originalSole, originalLog := rootRegistryVolumeMeasure, rootRegistrySoleOperation, rootRegistryLog
	rootRegistryBaseURL = fixture.server.URL
	rootRegistryVolumeMeasure = func() (int64, error) { return 0, nil }
	rootRegistrySoleOperation = func(_ string, fn func() error) error { return fn() }
	rootRegistryLog = func(format string, args ...any) { fmt.Fprintf(&fixture.logs, format+"\n", args...) }
	t.Cleanup(func() {
		fixture.server.Close()
		rootRegistryBaseURL, rootRegistryKeepRead = originalURL, originalKeep
		rootRegistryVolumeMeasure, rootRegistrySoleOperation, rootRegistryLog = originalVolume, originalSole, originalLog
	})
	return fixture
}

func (f *registrySweepFixture) addApp(root, app string, current, previous []string) (string, string) {
	f.t.Helper()
	dir := filepath.Join(root, app)
	currentPath, previousPath := filepath.Join(dir, "current.yml"), filepath.Join(dir, "previous.yml")
	if current != nil {
		writeStack(f.t, currentPath, current...)
	}
	if previous != nil {
		writeStack(f.t, previousPath, previous...)
	}
	return currentPath, previousPath
}

func registryImage(repository, digest string) string {
	return "127.0.0.1:5000/" + repository + "@" + digest
}

func sweepDigest(ch byte) string { return "sha256:" + strings.Repeat(string(ch), 64) }

func TestRootRegistrySweepExactOwnershipAvoidsHyphenPrefixCollision(t *testing.T) {
	root := t.TempDir()
	keep := sweepDigest('a')
	orphan := sweepDigest('b')
	current, previous := filepath.Join(root, "api", "current.yml"), filepath.Join(root, "api", "previous.yml")
	writeStack(t, current, registryImage("api-runtime", keep))
	cache := sweepDigest('c')
	fixture := newRegistrySweepFixture(t, []string{"api-runtime", "api-web"}, map[string][]string{"api-runtime": {"release", "buildcache"}, "api-web": {"release"}}, map[string]string{"api-runtime:release": keep, "api-runtime:buildcache": cache, "api-web:release": orphan})
	if err := maintainRootRegistry("api", current, previous, 0, func() error { return nil }, root, true, "operation"); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 {
		t.Fatalf("DELETEs = %v, want none; api must not index api-web", fixture.deletes)
	}
	for _, request := range fixture.requests {
		if strings.Contains(request, "api-web") {
			t.Fatalf("foreign repository was indexed: %s", request)
		}
	}
}

func TestRootRegistrySweepSharedRepositoriesAreSkippedForBothApps(t *testing.T) {
	root := t.TempDir()
	digest := sweepDigest('a')
	left, _ := filepath.Join(root, "demo-app", "current.yml"), ""
	writeStack(t, left, registryImage("demo-app-agents-api", digest))
	right := filepath.Join(root, "demo-app-agents", "previous.yml")
	writeStack(t, right, registryImage("demo-app-agents-api", digest))
	fixture := newRegistrySweepFixture(t, []string{"demo-app-agents-api"}, map[string][]string{"demo-app-agents-api": {"release"}}, map[string]string{"demo-app-agents-api:release": digest})
	for _, app := range []string{"demo-app", "demo-app-agents"} {
		current, previous := filepath.Join(root, app, "current.yml"), filepath.Join(root, app, "previous.yml")
		if err := maintainRootRegistry(app, current, previous, 0, func() error { return nil }, root, true, "operation"); err != nil {
			t.Fatal(err)
		}
	}
	if len(fixture.deletes) != 0 {
		t.Fatalf("shared repository DELETEs = %v, want none", fixture.deletes)
	}
	if strings.Count(fixture.logs.String(), "shared repository demo-app-agents-api not swept") != 2 {
		t.Fatalf("shared repository should be logged once per app sweep: %s", fixture.logs.String())
	}
}

func TestRootRegistrySweepFreshKeepSetProtectsNewlyRetainedDigest(t *testing.T) {
	root := t.TempDir()
	old, newlyKept := sweepDigest('a'), sweepDigest('b')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", old))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"old", "new"}}, map[string]string{"app-web:old": old, "app-web:new": newlyKept})
	reads := 0
	rootRegistryKeepRead = func(string, string, string) (map[string]bool, error) {
		reads++
		if reads == 1 {
			return map[string]bool{old: true}, nil
		}
		return map[string]bool{old: true, newlyKept: true}, nil
	}
	if err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 {
		t.Fatalf("newly retained digest was deleted: %v", fixture.deletes)
	}
}

func TestRootRegistrySweepCollectorRunsAfterDeletePass(t *testing.T) {
	root := t.TempDir()
	keep, orphan := sweepDigest('a'), sweepDigest('b')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release", "old"}}, map[string]string{"app-web:release": keep, "app-web:old": orphan})
	collectedAfterDelete := false
	collect := func() error {
		collectedAfterDelete = len(fixture.deletes) == 1
		return nil
	}
	if err := maintainRootRegistry("app", current, previous, 0, collect, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if !collectedAfterDelete {
		t.Fatalf("collector did not run after the manifest delete: deletes=%v", fixture.deletes)
	}
}

func TestRootRegistrySweepFailedFreshReadStopsFurtherDeletes(t *testing.T) {
	root := t.TempDir()
	keep, orphan := sweepDigest('a'), sweepDigest('b')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	cache := sweepDigest('c')
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release", "old", "buildcache"}}, map[string]string{"app-web:release": keep, "app-web:old": orphan, "app-web:buildcache": cache})
	rootRegistryVolumeMeasure = func() (int64, error) { return 10, nil }
	reads := 0
	rootRegistryKeepRead = func(string, string, string) (map[string]bool, error) {
		reads++
		if reads == 1 {
			return map[string]bool{keep: true}, nil
		}
		return nil, errors.New("read failed")
	}
	if err := maintainRootRegistry("app", current, previous, 1, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 {
		t.Fatalf("failed re-read allowed deletes: %v", fixture.deletes)
	}
}

func TestRootRegistrySweepEmptyKeepDoesNothing(t *testing.T) {
	root := t.TempDir()
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, "docker.io/library/alpine:latest")
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release"}}, map[string]string{})
	measureCalls := 0
	rootRegistryVolumeMeasure = func() (int64, error) { measureCalls++; return 99, nil }
	if err := maintainRootRegistry("app", current, previous, 1, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 || measureCalls != 0 || strings.Contains(fixture.logs.String(), "not swept, no retained digest could be read from any stack under "+root) == false {
		t.Fatalf("empty keep behavior: deletes=%v logs=%q", fixture.deletes, fixture.logs.String())
	}
}

func TestRootRegistrySweepReReadEmptyStopsAllDeletes(t *testing.T) {
	root := t.TempDir()
	keep, orphan := sweepDigest('a'), sweepDigest('b')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release"}}, map[string]string{"app-web:release": orphan})
	reads := 0
	rootRegistryKeepRead = func(string, string, string) (map[string]bool, error) {
		reads++
		if reads == 1 {
			return map[string]bool{keep: true}, nil
		}
		return map[string]bool{}, nil
	}
	if err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 || !strings.Contains(fixture.logs.String(), "not swept, no retained digest could be read from any stack under "+root) {
		t.Fatalf("empty re-read behavior: deletes=%v logs=%q", fixture.deletes, fixture.logs.String())
	}
}

func TestRootRegistrySweepConcurrentOperationDefersBothDeletePasses(t *testing.T) {
	root := t.TempDir()
	keep, orphan, cache := sweepDigest('a'), sweepDigest('b'), sweepDigest('c')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release", "old", "buildcache"}}, map[string]string{"app-web:release": keep, "app-web:old": orphan, "app-web:buildcache": cache})
	rootRegistryVolumeMeasure = func() (int64, error) { return 10, nil }
	calls := 0
	rootRegistrySoleOperation = func(_ string, fn func() error) error { calls++; return errors.New("foreign active operation") }
	if err := maintainRootRegistry("app", current, previous, 1, func() error { return nil }, root, true, "own-operation"); err != nil {
		t.Fatal(err)
	}
	// The first fenced pass defers; the sweep then stops (a deferral logs and
	// returns nil), so the eviction pass is never attempted and nothing is
	// deleted. The next sweep retries both passes.
	if len(fixture.deletes) != 0 || calls != 1 {
		t.Fatalf("deletes=%v sole-operation calls=%d, want none and one deferred pass", fixture.deletes, calls)
	}
	if !strings.Contains(fixture.logs.String(), "delete pass deferred while another operation is active") {
		t.Fatalf("deferral not logged: %q", fixture.logs.String())
	}
}

func TestRootRegistrySweepCacheEvictionRechecksOwnership(t *testing.T) {
	root := t.TempDir()
	keep, cache := sweepDigest('a'), sweepDigest('c')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release", "buildcache"}}, map[string]string{"app-web:release": keep, "app-web:buildcache": cache})
	rootRegistryVolumeMeasure = func() (int64, error) { return 10, nil }
	// Only the eviction pass has work (release is retained, buildcache is
	// protected from the superseded pass), so the single fenced call is the
	// eviction: the neighbour starts sharing app-web after planning and
	// before the fenced delete.
	calls := 0
	rootRegistrySoleOperation = func(_ string, fn func() error) error {
		calls++
		writeStack(t, filepath.Join(root, "neighbor", "previous.yml"), registryImage("app-web", keep))
		return fn()
	}
	if err := maintainRootRegistry("app", current, previous, 1, func() error { return nil }, root, true, "own-operation"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(fixture.deletes) != 0 {
		t.Fatalf("newly shared cache repository was deleted: calls=%d deletes=%v", calls, fixture.deletes)
	}
}

func TestRootRegistrySweepCacheEvictsOwnedBuildcache(t *testing.T) {
	root := t.TempDir()
	keep, cache := sweepDigest('a'), sweepDigest('c')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release", "buildcache"}}, map[string]string{"app-web:release": keep, "app-web:buildcache": cache})
	rootRegistryVolumeMeasure = func() (int64, error) { return 10, nil }
	if err := maintainRootRegistry("app", current, previous, 1, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fixture.deletes, "/v2/app-web/manifests/"+cache) {
		t.Fatalf("owned buildcache was not evicted: %v", fixture.deletes)
	}
}

func TestRootRegistrySweepPreviousOnlyRepositoryIsOwned(t *testing.T) {
	root := t.TempDir()
	keep, orphan := sweepDigest('a'), sweepDigest('b')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, previous, registryImage("app-legacy", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-legacy"}, map[string][]string{"app-legacy": {"retained", "old"}}, map[string]string{"app-legacy:retained": keep, "app-legacy:old": orphan})
	if err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fixture.deletes, "/v2/app-legacy/manifests/"+orphan) {
		t.Fatalf("previous-only owned repository was not swept: %v", fixture.deletes)
	}
}

func TestRootRegistrySweepValidatesRepositoryAndTagPaths(t *testing.T) {
	root := t.TempDir()
	keep := sweepDigest('a')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("foo--web", keep), registryImage("a__b", keep), registryImage("a/b", keep), registryImage("..", keep), registryImage("A", keep), registryImage("x/../y", keep))
	fixture := newRegistrySweepFixture(t, []string{"foo--web", "a__b", "a/b", "..", "A", "x/../y"}, map[string][]string{"foo--web": {"safe", "../t"}, "a__b": {"safe"}}, map[string]string{"foo--web:safe": sweepDigest('b'), "a__b:safe": sweepDigest('c')})
	if err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	for _, request := range fixture.requests {
		if strings.Contains(request, "/v2/a/b") || strings.Contains(request, "/v2/../") || strings.Contains(request, "/v2/x/../y") || strings.Contains(request, "/manifests/../t") {
			t.Fatalf("untrusted path reached registry: %q", request)
		}
	}
	for _, want := range []string{"GET /v2/foo--web/tags/list", "GET /v2/a__b/tags/list", "HEAD /v2/foo--web/manifests/safe"} {
		if !slices.Contains(fixture.requests, want) {
			t.Errorf("missing allowed request %q in %v", want, fixture.requests)
		}
	}
}

func TestRootRegistrySweepCorruptNeighbourAborts(t *testing.T) {
	root := t.TempDir()
	keep := sweepDigest('a')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	writeStack(t, filepath.Join(root, "neighbor", "current.yml"), "not: [valid")
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release"}}, map[string]string{"app-web:release": sweepDigest('b')})
	if err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, true, "operation"); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 || len(fixture.requests) != 0 {
		t.Fatalf("corrupt neighbour did not fail closed: deletes=%v requests=%v", fixture.deletes, fixture.requests)
	}
}

func TestRootRegistrySweepServiceslessNeighbourAborts(t *testing.T) {
	root := t.TempDir()
	keep := sweepDigest('a')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	writeStack(t, filepath.Join(root, "neighbor", "current.yml"), "version: '3.9'\n")
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release"}}, map[string]string{"app-web:release": sweepDigest('b')})
	if err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, true, "operation"); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 || len(fixture.requests) != 0 {
		t.Fatalf("services-less neighbour did not fail closed: deletes=%v requests=%v", fixture.deletes, fixture.requests)
	}
}

func TestRootRegistrySweepFirstDeployWithoutPreviousFile(t *testing.T) {
	root := t.TempDir()
	keep := sweepDigest('a')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release"}}, map[string]string{"app-web:release": keep})
	if err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(fixture.requests) == 0 {
		t.Fatal("first deploy with absent previous.yml should still sweep")
	}
}

func TestRootRegistrySweepCacheEvictionKeepsRetainedDigest(t *testing.T) {
	// A buildcache tag whose digest a retained stack also references (here a
	// second service of the same release) must never be evicted.
	root := t.TempDir()
	keep, cache := sweepDigest('a'), sweepDigest('c')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep), registryImage("app-web", cache))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release", "buildcache"}}, map[string]string{"app-web:release": keep, "app-web:buildcache": cache})
	rootRegistryVolumeMeasure = func() (int64, error) { return 10, nil }
	if err := maintainRootRegistry("app", current, previous, 1, func() error { return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(fixture.deletes, "/v2/app-web/manifests/"+cache) {
		t.Fatalf("eviction deleted a digest a retained stack references: %v", fixture.deletes)
	}
}

func TestRootRegistrySweepCacheEvictionFailedReReadSkipsCollector(t *testing.T) {
	root := t.TempDir()
	keep, cache := sweepDigest('a'), sweepDigest('c')
	current, previous := filepath.Join(root, "app", "current.yml"), filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	fixture := newRegistrySweepFixture(t, []string{"app-web"}, map[string][]string{"app-web": {"release", "buildcache"}}, map[string]string{"app-web:release": keep, "app-web:buildcache": cache})
	rootRegistryVolumeMeasure = func() (int64, error) { return 10, nil }
	reads := 0
	rootRegistryKeepRead = func(string, string, string) (map[string]bool, error) {
		reads++
		if reads == 1 {
			return map[string]bool{keep: true}, nil
		}
		return nil, errors.New("retained stacks unreadable")
	}
	// The superseded pass always collects once (CollectGarbage is always set);
	// the failed eviction re-read must not trigger the second collection.
	collections := 0
	if err := maintainRootRegistry("app", current, previous, 1, func() error { collections++; return nil }, root, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(fixture.deletes) != 0 || collections != 1 {
		t.Fatalf("a failed eviction re-read must delete nothing and skip its GC: deletes=%v collections=%d", fixture.deletes, collections)
	}
}
