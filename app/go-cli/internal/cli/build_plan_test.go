package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestBuildPlanDeduplicatesEquivalentBuilds(t *testing.T) {
	cf := &composeFile{Services: map[string]composeService{
		"api":       {Build: map[string]any{"context": "apps/api", "dockerfile": "Dockerfile", "target": "prod"}},
		"worker":    {Build: map[string]any{"target": "prod", "dockerfile": "Dockerfile", "context": "apps/api"}},
		"scheduler": {Build: map[string]any{"context": "apps/api", "dockerfile": "Dockerfile", "target": "prod"}},
		"frontend":  {Build: map[string]any{"context": ".", "dockerfile": "apps/web-dome/Dockerfile", "target": "prod"}},
	}}

	plan, err := createBuildPlan(cf, "127.0.0.1:5080", "myapp", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Builds) != 2 {
		t.Fatalf("expected 2 unique builds, got %d: %#v", len(plan.Builds), plan.Builds)
	}
	apiImage := plan.ServiceImages["api"]
	if apiImage == "" || plan.ServiceImages["worker"] != apiImage || plan.ServiceImages["scheduler"] != apiImage {
		t.Fatalf("expected API services to share one image, got %#v", plan.ServiceImages)
	}
	if !strings.HasSuffix(apiImage, ":abc123") {
		t.Fatalf("expected immutable version tag, got %q", apiImage)
	}
	for _, build := range plan.Builds {
		if !strings.HasSuffix(build.CacheImage, ":buildcache") {
			t.Fatalf("expected stable build cache image, got %#v", build)
		}
	}

}

func TestBuildPlanUsesConfiguredSharedBuildService(t *testing.T) {
	cf := &composeFile{Services: map[string]composeService{
		"web":    {Build: map[string]any{"context": "."}},
		"worker": {Build: map[string]any{"context": "."}},
	}}
	build := config.Build{Services: map[string]config.BuildService{
		"runtime": {Context: ".", Dockerfile: "Dockerfile.prod", Services: []string{"web", "worker"}},
	}}

	plan, err := createConfiguredBuildPlan(cf, build, "127.0.0.1:5081", "myapp", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Builds) != 1 {
		t.Fatalf("expected one configured build, got %#v", plan.Builds)
	}
	if got := plan.Builds[0]; got.Service != "runtime" || !strings.HasSuffix(got.Image, "/myapp-runtime:abc123") || len(got.Services) != 2 {
		t.Fatalf("unexpected planned build: %#v", got)
	}
	if plan.ServiceImages["web"] != plan.ServiceImages["worker"] {
		t.Fatalf("expected shared immutable image, got %#v", plan.ServiceImages)
	}
}

func TestRegistryImageExistsUsesManifestHead(t *testing.T) {
	var method string
	var accept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		accept = r.Header.Get("Accept")
		if r.URL.Path != "/v2/myapp-api/manifests/abc123" {
			t.Fatalf("unexpected registry path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exists, err := registryImageExists(strings.TrimPrefix(server.URL, "http://") + "/myapp-api:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("expected registry image to exist")
	}
	if method != http.MethodHead {
		t.Fatalf("expected HEAD, got %q", method)
	}
	if !strings.Contains(accept, "application/vnd.oci.image.index.v1+json") {
		t.Fatalf("expected OCI accept header, got %q", accept)
	}
}

func TestBuildCacheCandidatesMigrateFromLegacyLatest(t *testing.T) {
	got := buildCacheCandidates("127.0.0.1:5080/myapp-api:buildcache")
	if len(got) != 2 || got[0] != "127.0.0.1:5080/myapp-api:buildcache" || got[1] != "127.0.0.1:5080/myapp-api:latest" {
		t.Fatalf("unexpected cache candidates: %#v", got)
	}
}

func TestBuildPlanWiresColdAndWarmRegistryCache(t *testing.T) {
	cachePresent := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/manifests/buildcache") && !strings.HasSuffix(r.URL.Path, "/api/manifests/latest") {
			t.Fatalf("unexpected registry lookup %s", r.URL.Path)
		}
		if cachePresent && strings.HasSuffix(r.URL.Path, "/api/manifests/buildcache") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	registry := strings.TrimPrefix(server.URL, "http://")
	plan := buildPlan{Builds: []plannedBuild{{
		Service:    "api",
		Services:   []string{"api"},
		Image:      registry + "/api:abc123",
		CacheImage: registry + "/api:buildcache",
		Spec:       &buildSpec{Context: ".", Dockerfile: "Dockerfile"},
	}}}
	cf := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}
	var invocations [][]string
	previousRunner := dockerBuildRunner
	dockerBuildRunner = func(args []string) error {
		invocations = append(invocations, append([]string(nil), args...))
		return nil
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	if err := buildPlannedImagesWithOptions(cf, plan, false, buildExecutionOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(invocations) != 1 || slices.Contains(invocations[0], "--cache-from") {
		t.Fatalf("cold build must not import an unavailable registry cache: %#v", invocations)
	}

	cachePresent = true
	if err := buildPlannedImagesWithOptions(cf, plan, false, buildExecutionOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(invocations) != 2 || !slices.Contains(invocations[1], "--cache-from") || !slices.Contains(invocations[1], plan.Builds[0].CacheImage) {
		t.Fatalf("warm build must import the published registry cache: %#v", invocations)
	}
}

func TestBuildPlanSkipsDockerInvocationInDryRunAndPropagatesBuildFailure(t *testing.T) {
	plan := buildPlan{Builds: []plannedBuild{{
		Service:  "api",
		Services: []string{"api"},
		Image:    "127.0.0.1:5080/app-api:abc123",
		Spec:     &buildSpec{Context: ".", Dockerfile: "Dockerfile"},
	}}}
	cf := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}
	called := 0
	previousRunner := dockerBuildRunner
	dockerBuildRunner = func([]string) error {
		called++
		return errors.New("build engine failed")
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	if err := buildPlannedImagesWithOptions(cf, plan, true, buildExecutionOptions{}); err != nil {
		t.Fatalf("dry-run should not invoke Docker: %v", err)
	}
	if called != 0 {
		t.Fatalf("dry-run invoked Docker %d times", called)
	}
	if err := buildPlannedImagesWithOptions(cf, plan, false, buildExecutionOptions{}); err == nil || !strings.Contains(err.Error(), "build engine failed") {
		t.Fatalf("build failure was not propagated: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected exactly one real build invocation, got %d", called)
	}
}

func TestEphemeralBuildPlanUsesPersistentLocalCacheWithoutHostRegistryLookup(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	registry := strings.TrimPrefix(server.URL, "http://")
	plan := buildPlan{Builds: []plannedBuild{{
		Service:    "api",
		Services:   []string{"api"},
		Image:      registry + "/api:abc123",
		CacheImage: registry + "/api:buildcache",
		Spec:       &buildSpec{Context: ".", Dockerfile: "Dockerfile"},
	}}}
	cf := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}
	var invocation []string
	previousRunner := dockerBuildRunner
	dockerBuildRunner = func(args []string) error {
		invocation = append([]string(nil), args...)
		return nil
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	cacheDir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(cacheDir, "api"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "api", "index.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := buildExecutionOptions{
		Builder:           "shuttle-demo-run-builder",
		LocalCacheDir:     cacheDir,
		SkipRegistryCache: true,
	}
	if err := buildPlannedImagesWithOptions(cf, plan, false, options); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("ephemeral Buildx builder must not resolve a host-loopback registry cache, got %d requests", requests)
	}
	serviceCacheDir := filepath.Join(cacheDir, "api")
	if !slices.Contains(invocation, "type=local,src="+serviceCacheDir) ||
		!slices.Contains(invocation, "type=local,dest="+serviceCacheDir+",mode=max") {
		t.Fatalf("ephemeral build did not import/export its persistent app cache: %#v", invocation)
	}
	if slices.Contains(invocation, plan.Builds[0].CacheImage) {
		t.Fatalf("ephemeral build must not pass the host registry cache to its isolated builder: %#v", invocation)
	}
}

func TestLocalPublishedImageTagsAreExactAndDeduplicated(t *testing.T) {
	plan := buildPlan{Builds: []plannedBuild{
		{
			Image:      "127.0.0.1:5080/myapp-api:abc123",
			CacheImage: "127.0.0.1:5080/myapp-api:buildcache",
		},
		{
			Image:      "127.0.0.1:5080/myapp-api:abc123",
			CacheImage: "127.0.0.1:5080/myapp-api:buildcache",
		},
		{
			Image:      "127.0.0.1:5080/myapp-frontend:abc123",
			CacheImage: "127.0.0.1:5080/myapp-frontend:buildcache",
		},
	}}

	got := localPublishedImageTags(plan)
	want := []string{
		"127.0.0.1:5080/myapp-api:abc123",
		"127.0.0.1:5080/myapp-api:buildcache",
		"127.0.0.1:5080/myapp-frontend:abc123",
		"127.0.0.1:5080/myapp-frontend:buildcache",
	}
	if len(got) != len(want) {
		t.Fatalf("unexpected tags: got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tag %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLocalImageInspectDistinguishesAbsentFromDaemonFailure(t *testing.T) {
	exitErr := errors.New("exit status 1")

	exists, err := classifyLocalImageInspect("example:missing", []byte("Error: No such image: example:missing"), exitErr)
	if exists || err != nil {
		t.Fatalf("missing image should be a clean absence, got exists=%v err=%v", exists, err)
	}

	exists, err = classifyLocalImageInspect("example:unknown", []byte("permission denied while connecting to Docker"), exitErr)
	if exists || err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("daemon failure must be reported, got exists=%v err=%v", exists, err)
	}
}

func TestLocalImageCleanupRemovesOnlyTagsCreatedByThisDeploy(t *testing.T) {
	present := map[string]bool{
		"registry.example/app:preexisting": true,
		"registry.example/app:created":     false,
	}
	var removed []string
	cleanup, err := prepareLocalImageCleanupWithLookup(
		[]string{"registry.example/app:preexisting", "registry.example/app:created"},
		false,
		func(tag string) (bool, error) { return present[tag], nil },
		func(tag string) error {
			removed = append(removed, tag)
			present[tag] = false
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	present["registry.example/app:created"] = true // the build/push created it
	if err := cleanup.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != "registry.example/app:created" {
		t.Fatalf("cleanup removed unexpected tags: %#v", removed)
	}
	if !present["registry.example/app:preexisting"] {
		t.Fatal("cleanup removed a tag that existed before the deploy")
	}
}

func TestLocalImageCleanupPrunesPreexistingTagsWhenOptedIn(t *testing.T) {
	present := map[string]bool{
		"registry.example/app:shipped-by-make": true,
		"registry.example/app:created":         false,
	}
	var removed []string
	cleanup, err := prepareLocalImageCleanupWithLookup(
		[]string{"registry.example/app:shipped-by-make", "registry.example/app:created"},
		true,
		func(tag string) (bool, error) { return present[tag], nil },
		func(tag string) error {
			removed = append(removed, tag)
			present[tag] = false
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	present["registry.example/app:created"] = true // the build/push created it
	if err := cleanup.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("opt-in pruning must remove every published tag, got %#v", removed)
	}
}

func TestInterruptCleanupRunsActionsInReverseOrder(t *testing.T) {
	interrupts := newInterruptCleanup()
	defer interrupts.Stop()

	var order []string
	interrupts.Add(func() error { order = append(order, "images"); return nil })
	interrupts.Add(func() error { order = append(order, "registry"); return errors.New("stop failed") })
	interrupts.Run()

	// Registry first, then images: an interrupt must unwind like the defers do.
	if len(order) != 2 || order[0] != "registry" || order[1] != "images" {
		t.Fatalf("unexpected cleanup order: %#v", order)
	}
}

func TestInterruptCleanupIsNilSafeAndStopsOnce(t *testing.T) {
	var absent *interruptCleanup
	absent.Add(func() error { t.Fatal("nil guard must not register actions"); return nil })
	absent.Run()
	absent.Stop()

	interrupts := newInterruptCleanup()
	interrupts.Stop()
	interrupts.Stop() // a second Stop must not panic on the closed channel
}

func TestLocalImageCleanupFailureIsRetainedAlongsideDeployFailure(t *testing.T) {
	deployErr := errors.New("build failed")
	mergeCleanupError(&deployErr, errors.New("remove local tag failed"))
	if deployErr == nil || !strings.Contains(deployErr.Error(), "build failed") || !strings.Contains(deployErr.Error(), "remove local tag failed") {
		t.Fatalf("expected combined deploy/cleanup error, got %v", deployErr)
	}
}

func TestRegistryImageExistsReportsMissingManifest(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	exists, err := registryImageExists(strings.TrimPrefix(server.URL, "http://") + "/nested/myapp-api:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("expected missing registry image")
	}
}

func TestRegistryManifestURLRejectsUntaggedImage(t *testing.T) {
	if _, err := registryManifestURL("127.0.0.1:5080/myapp-api"); err == nil {
		t.Fatal("expected an invalid image error")
	}
}

func TestParseBuildSpecSortsBuildArgs(t *testing.T) {
	spec, err := parseBuildSpec(map[string]any{
		"context":    "apps/web",
		"dockerfile": "Dockerfile.prod",
		"target":     "release",
		"args": map[string]any{
			"ZZ": "two",
			"AA": "one",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Context != "apps/web" || spec.Dockerfile != "Dockerfile.prod" {
		t.Fatalf("unexpected spec: %#v", spec)
	}
	want := []string{
		"--target", "release",
		"--build-arg", "AA=one",
		"--build-arg", "ZZ=two",
	}
	if len(spec.BuildArgs) != len(want) {
		t.Fatalf("unexpected build-arg length: got %d, want %d", len(spec.BuildArgs), len(want))
	}
	for i := range want {
		if spec.BuildArgs[i] != want[i] {
			t.Fatalf("unexpected build-arg at %d: got %q, want %q", i, spec.BuildArgs[i], want[i])
		}
	}
}

func TestBuildPlanRegistryCacheExportWiresCacheToAndSkipsInline(t *testing.T) {
	cachePresent := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cachePresent && strings.HasSuffix(r.URL.Path, "/api/manifests/buildcache") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	registry := strings.TrimPrefix(server.URL, "http://")
	// Spec is nil on purpose: the compose path builds its plan from the compose
	// file alone, and the options must survive that routing.
	plan := buildPlan{Builds: []plannedBuild{{
		Service:    "api",
		Services:   []string{"api"},
		Image:      registry + "/api:abc123",
		CacheImage: registry + "/api:buildcache",
	}}}
	cf := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}
	var invocations [][]string
	previousRunner := dockerBuildRunner
	dockerBuildRunner = func(args []string) error {
		invocations = append(invocations, append([]string(nil), args...))
		return nil
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })
	options := buildExecutionOptions{RegistryCacheExport: true}

	if err := buildPlannedImagesWithOptions(cf, plan, false, options); err != nil {
		t.Fatal(err)
	}
	if len(invocations) != 1 {
		t.Fatalf("expected one build invocation, got %#v", invocations)
	}
	cold := invocations[0]
	if !slices.Contains(cold, "--cache-to") || !slices.Contains(cold, "type=registry,ref="+plan.Builds[0].CacheImage+",mode=max,image-manifest=true,oci-mediatypes=true") {
		t.Fatalf("cold build must export a mode=max registry cache: %#v", cold)
	}
	if slices.Contains(cold, "--cache-from") || slices.Contains(cold, "BUILDKIT_INLINE_CACHE=1") {
		t.Fatalf("cold build must neither import an absent cache nor request inline cache: %#v", cold)
	}

	cachePresent = true
	if err := buildPlannedImagesWithOptions(cf, plan, false, options); err != nil {
		t.Fatal(err)
	}
	warm := invocations[1]
	if !slices.Contains(warm, "type=registry,ref="+plan.Builds[0].CacheImage) {
		t.Fatalf("warm build must import the registry cache: %#v", warm)
	}
}

// --skip-build reuses an image this workstation already built. Run without that
// build, the push reached `docker push` for an image the daemon never held and
// failed on its own terms ("exit status 1"), naming neither the flag nor the
// image — measured on a deploy that only meant to re-publish an unchanged stack.
func TestPushPlannedImagesRefusesAnImageTheDaemonDoesNotHold(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	registry := strings.TrimPrefix(server.URL, "http://")
	plan := buildPlan{Builds: []plannedBuild{{
		Service:  "api",
		Services: []string{"api"},
		Image:    registry + "/api:abc123",
	}}}
	previousPush, previousExists := dockerPushRunner, dockerImageExistsRunner
	pushed := false
	dockerPushRunner = func(string) error {
		pushed = true
		return nil
	}
	dockerImageExistsRunner = func(string) bool { return false }
	t.Cleanup(func() { dockerPushRunner, dockerImageExistsRunner = previousPush, previousExists })

	err := pushPlannedImagesWithOptions(plan, false)
	if err == nil {
		t.Fatal("pushing an image the daemon does not hold must fail before docker does")
	}
	if !strings.Contains(err.Error(), "--skip-build") {
		t.Errorf("the error must name the flag that leads here: %v", err)
	}
	if pushed {
		t.Error("nothing may be pushed once the image is known to be missing")
	}
}

func TestPushPlannedImagesPublishesLocalBuildEvenWhenRegistryTagExists(t *testing.T) {
	manifest := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
	aliasPath := fmt.Sprintf("/v2/api/manifests/retained-sha256-%x", sha256.Sum256([]byte(manifest)))
	var preserved atomic.Bool
	var preserveStatus atomic.Int32
	preserveStatus.Store(http.StatusCreated)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			if r.URL.Path != aliasPath || string(body) != manifest || r.Header.Get("Content-Type") != "application/vnd.oci.image.manifest.v1+json" {
				t.Errorf("old manifest was not preserved intact at its content alias: %s %q", r.URL.Path, body)
			}
			preserved.Store(preserveStatus.Load() == http.StatusCreated)
			w.WriteHeader(int(preserveStatus.Load()))
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, manifest)
	}))
	defer server.Close()
	plan := buildPlan{Builds: []plannedBuild{{
		Service: "api", Services: []string{"api"},
		Image: strings.TrimPrefix(server.URL, "http://") + "/api:abc123",
	}}}
	previousPush, previousExists := dockerPushRunner, dockerImageExistsRunner
	t.Cleanup(func() { dockerPushRunner, dockerImageExistsRunner = previousPush, previousExists })
	for _, local := range []bool{true, false} {
		pushed := false
		dockerImageExistsRunner = func(string) bool { return local }
		dockerPushRunner = func(string) error {
			if !preserved.Load() {
				t.Error("the old manifest must be protected before its tag is overwritten")
			}
			pushed = true
			return nil
		}
		if err := pushPlannedImagesWithOptions(plan, false); err != nil {
			t.Fatal(err)
		}
		if pushed != local {
			t.Fatalf("local build present=%v: pushed=%v; an existing registry tag cannot prove the rebuilt contents match, while a registry-only retry must remain supported", local, pushed)
		}
	}
	preserveStatus.Store(http.StatusInternalServerError)
	dockerImageExistsRunner = func(string) bool { return true }
	pushed := false
	dockerPushRunner = func(string) error { pushed = true; return nil }
	if err := pushPlannedImagesWithOptions(plan, false); err == nil || pushed {
		t.Fatalf("a failed retention write must prevent overwriting the old release: err=%v pushed=%v", err, pushed)
	}
}

func TestPushPlannedImagesSkipsCacheTagWhenCacheExportedDuringBuild(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	registry := strings.TrimPrefix(server.URL, "http://")
	plan := buildPlan{Builds: []plannedBuild{{
		Service:    "api",
		Services:   []string{"api"},
		Image:      registry + "/api:abc123",
		CacheImage: registry + "/api:buildcache",
	}}}
	var pushed, tagged []string
	previousPush, previousTag, previousExists := dockerPushRunner, dockerTagRunner, dockerImageExistsRunner
	dockerPushRunner = func(imageTag string) error {
		pushed = append(pushed, imageTag)
		return nil
	}
	dockerTagRunner = func(source string, target string) error {
		tagged = append(tagged, target)
		return nil
	}
	dockerImageExistsRunner = func(string) bool { return true }
	t.Cleanup(func() {
		dockerPushRunner, dockerTagRunner, dockerImageExistsRunner = previousPush, previousTag, previousExists
	})

	if err := pushPlannedImagesWithOptions(plan, false); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pushed, []string{plan.Builds[0].Image}) || len(tagged) != 0 {
		t.Fatalf("cache export must push only the immutable image: pushed=%#v tagged=%#v", pushed, tagged)
	}

	pushed, tagged = nil, nil
	if err := pushPlannedImagesWithOptions(plan, true); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pushed, plan.Builds[0].CacheImage) || !slices.Contains(tagged, plan.Builds[0].CacheImage) {
		t.Fatalf("inline path must keep tagging and pushing the cache image: pushed=%#v tagged=%#v", pushed, tagged)
	}
}
