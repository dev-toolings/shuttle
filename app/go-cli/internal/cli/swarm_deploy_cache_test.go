package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestSwarmCachePolicyExportsMaxModeCacheAndLeavesTheCacheTagIntact drives the
// exact policy the Swarm deploy uses through both halves it feeds: the build
// arguments and the push. Before this was wired, the Swarm path always passed a
// builder, which routed every build to the inline-cache arguments (mode=min) and
// then republished :buildcache from the final image — so the compiled-extension
// and composer stages, which only exist behind COPY --from, were never
// restorable from the registry.
var cacheTestReleaseDigest = "sha256:" + strings.Repeat("c", 64)

func TestSwarmCachePolicyExportsMaxModeCacheAndLeavesTheCacheTagIntact(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/manifests/buildcache") {
			// A mode=max export is an OCI image manifest and not a runnable
			// image; image-manifest=true is what keeps this probe answering 200.
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/manifests/abc123") {
			// Direct push mode cross-checks BuildKit's metadata digest
			// against the registry HEAD digest of the release tag.
			w.Header().Set("Docker-Content-Digest", cacheTestReleaseDigest)
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
		Image:      registry + "/demo-api:abc123",
		CacheImage: registry + "/demo-api:buildcache",
		Spec:       &buildSpec{Context: ".", Dockerfile: "Dockerfile"},
	}}}
	cf := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}
	policy := swarmCachePolicyFor("shuttle-demo", "")

	var invocations [][]string
	previousRunner := dockerBuildRunner
	dockerBuildRunner = func(args []string) error {
		invocations = append(invocations, append([]string(nil), args...))
		for index, arg := range args {
			if arg == "--metadata-file" && index+1 < len(args) {
				return os.WriteFile(args[index+1], []byte(`{"containerimage.digest":"`+cacheTestReleaseDigest+`"}`), 0600)
			}
		}
		return nil
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	if err := buildPlannedImagesWithOptions(cf, plan, false, policy.Build); err != nil {
		t.Fatal(err)
	}
	if len(invocations) != 1 {
		t.Fatalf("expected one build invocation, got %#v", invocations)
	}
	build := invocations[0]
	if !slices.Contains(build, "--builder") || !slices.Contains(build, "shuttle-demo") {
		t.Fatalf("swarm build must run on the managed builder: %#v", build)
	}
	wantCacheTo := "type=registry,ref=" + plan.Builds[0].CacheImage + ",mode=max,image-manifest=true,oci-mediatypes=true"
	if !slices.Contains(build, "--cache-to") || !slices.Contains(build, wantCacheTo) {
		t.Fatalf("swarm build must export a mode=max registry cache: %#v", build)
	}
	if !slices.Contains(build, "type=registry,ref="+plan.Builds[0].CacheImage) {
		t.Fatalf("swarm build must import the published registry cache: %#v", build)
	}
	if slices.Contains(build, "BUILDKIT_INLINE_CACHE=1") {
		t.Fatalf("swarm build must not fall back to inline cache: %#v", build)
	}

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

	if err := pushPlannedImagesWithOptions(plan, policy.PushCacheTags); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pushed, []string{plan.Builds[0].Image}) {
		t.Fatalf("swarm push must publish the immutable image only: %#v", pushed)
	}
	if len(tagged) != 0 {
		t.Fatalf("re-tagging %s would overwrite the mode=max cache manifest with a mode=min one: %#v", plan.Builds[0].CacheImage, tagged)
	}
}

func TestSwarmCachePolicyNeverCombinesACacheExportWithACacheTagPush(t *testing.T) {
	policy := swarmCachePolicyFor("shuttle-demo", "")
	if policy.Build.Builder != "shuttle-demo" || !policy.Build.RegistryCacheExport {
		t.Fatalf("swarm builds must export a registry cache from the managed builder: %#v", policy)
	}
	if policy.Build.RegistryCacheExport && policy.PushCacheTags {
		t.Fatal("a build that exports :buildcache must not have it overwritten by the push")
	}
}
