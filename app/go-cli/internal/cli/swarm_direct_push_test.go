package cli

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestSwarmDirectPushPreservesBeforeBuildAndSkipsDockerPush(t *testing.T) {
	policy := swarmCachePolicyFor("shuttle-demo", "")
	plan := buildPlan{Builds: []plannedBuild{
		{Image: "127.0.0.1:51234/demo-api:abc123"},
		{Image: "127.0.0.1:51234/demo-worker:abc123"},
	}}
	var events []string
	_, err := runSwarmLocalBuildAndPush(
		plan,
		false,
		policy.Build.Push,
		func(image string) error {
			events = append(events, "preserve "+image)
			return nil
		},
		func() error {
			events = append(events, "build")
			return nil
		},
		func() error {
			events = append(events, "docker push")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"preserve 127.0.0.1:51234/demo-api:abc123",
		"preserve 127.0.0.1:51234/demo-worker:abc123",
		"build",
	}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("unexpected local Swarm build sequence: got %#v, want %#v", events, want)
	}
}

func TestSwarmDirectPushRejectsMetadataDigestMismatchBeforePromotion(t *testing.T) {
	metadataDigest := "sha256:" + strings.Repeat("a", 64)
	headDigest := "sha256:" + strings.Repeat("b", 64)
	registry := "127.0.0.1:51234"
	previousClient := registryTagDigestHTTPClient
	registryTagDigestHTTPClient = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodHead || r.URL.Path != "/v2/demo-api/manifests/abc123" {
			t.Errorf("unexpected digest request: %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Docker-Content-Digest": []string{headDigest}},
			Body:       http.NoBody,
			Request:    r,
		}, nil
	})}
	t.Cleanup(func() { registryTagDigestHTTPClient = previousClient })
	plan := buildPlan{Builds: []plannedBuild{{
		Service:    "api",
		Services:   []string{"api"},
		Image:      registry + "/demo-api:abc123",
		CacheImage: registry + "/demo-api:buildcache",
		Spec:       &buildSpec{Context: ".", Dockerfile: "Dockerfile"},
	}}}
	compose := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}
	previousRunner := dockerBuildRunner
	var metadataFile string
	dockerBuildRunner = func(args []string) error {
		for index, arg := range args {
			if arg == "--metadata-file" && index+1 < len(args) {
				metadataFile = args[index+1]
				return os.WriteFile(metadataFile, []byte(`{"containerimage.digest":"`+metadataDigest+`"}`), 0600)
			}
		}
		return fmt.Errorf("Buildx did not receive --metadata-file: %#v", args)
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	options := buildExecutionOptions{
		Builder:             "shuttle-demo",
		Push:                true,
		SkipRegistryCache:   true,
		RegistryCacheExport: true,
	}
	promoted := false
	_, err := runSwarmLocalBuildAndPush(plan, false, options.Push,
		func(string) error { return nil },
		func() error { return buildPlannedImagesWithOptions(compose, plan, false, options) },
		func() error { return nil },
	)
	if err == nil {
		promoted = true
	}
	if err == nil || !strings.Contains(err.Error(), metadataDigest) || !strings.Contains(err.Error(), headDigest) {
		t.Fatalf("digest mismatch must fail with both identities, got %v", err)
	}
	if promoted {
		t.Fatal("metadata mismatch must fail before promotion")
	}
	if metadataFile == "" {
		t.Fatal("Buildx did not receive a metadata file path")
	}
	if _, err := os.Stat(metadataFile); !os.IsNotExist(err) {
		t.Fatalf("per-build metadata file was not removed after the build: stat err=%v", err)
	}
}

func TestSwarmDirectPushCleanupDoesNotInspectOrRemoveUnloadedTags(t *testing.T) {
	plan := buildPlan{Builds: []plannedBuild{{
		Image:      "127.0.0.1:51234/demo-api:abc123",
		CacheImage: "127.0.0.1:51234/demo-api:buildcache",
	}}}
	tags := localPublishedImageTagsForBuildMode(plan, true)
	if len(tags) != 0 {
		t.Fatalf("BuildKit-pushed images must not enter local cleanup: %#v", tags)
	}
	lookups, removals := 0, 0
	cleanup, err := prepareLocalImageCleanupWithLookup(tags, false,
		func(string) (bool, error) {
			lookups++
			return true, nil
		},
		func(string) error {
			removals++
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if lookups != 0 || removals != 0 {
		t.Fatalf("cleanup touched images that were never loaded: lookups=%d removals=%d", lookups, removals)
	}
}

func TestSwarmSkipBuildRunsExistingImageReuseCheck(t *testing.T) {
	plan := buildPlan{Builds: []plannedBuild{{Image: "127.0.0.1:51234/demo-api:abc123"}}}

	buildCalls := 0
	pushCheckCalls := 0
	_, err := runSwarmLocalBuildAndPush(plan, true, true,
		func(string) error { t.Fatal("skip-build must not preserve an image it does not overwrite"); return nil },
		func() error { buildCalls++; return nil },
		func() error { pushCheckCalls++; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if buildCalls != 0 || pushCheckCalls != 1 {
		t.Fatalf("skip-build did not run the existing image reuse check: build calls=%d reuse checks=%d", buildCalls, pushCheckCalls)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestSwarmDirectPushRejectsMissingMetadataDigest(t *testing.T) {
	registry := "127.0.0.1:51234"
	previousClient := registryTagDigestHTTPClient
	registryTagDigestHTTPClient = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("no registry HEAD expected when the metadata digest is missing: %s %s", r.Method, r.URL.Path)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	})}
	t.Cleanup(func() { registryTagDigestHTTPClient = previousClient })
	plan := buildPlan{Builds: []plannedBuild{{
		Service:    "api",
		Services:   []string{"api"},
		Image:      registry + "/demo-api:abc123",
		CacheImage: registry + "/demo-api:buildcache",
		Spec:       &buildSpec{Context: ".", Dockerfile: "Dockerfile"},
	}}}
	compose := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}
	options := buildExecutionOptions{Builder: "shuttle-demo", Push: true, SkipRegistryCache: true, RegistryCacheExport: true}
	for name, body := range map[string]string{"missing key": `{"buildx.build.ref":"x"}`, "empty file": ""} {
		previousRunner := dockerBuildRunner
		dockerBuildRunner = func(args []string) error {
			for index, arg := range args {
				if arg == "--metadata-file" && index+1 < len(args) {
					return os.WriteFile(args[index+1], []byte(body), 0600)
				}
			}
			return fmt.Errorf("Buildx did not receive --metadata-file: %#v", args)
		}
		err := buildPlannedImagesWithOptions(compose, plan, false, options)
		dockerBuildRunner = previousRunner
		if err == nil || !strings.Contains(err.Error(), "containerimage.digest") || !strings.Contains(err.Error(), plan.Builds[0].Image) {
			t.Fatalf("%s: a push without a metadata digest must fail naming the image, got %v", name, err)
		}
	}
}

// The digest promoted must be the one BuildKit pushed and the registry
// confirmed; a tag rewritten between the push check and the stack resolution
// is refused before promotion.
func TestSwarmDirectPushPromotesOnlyTheVerifiedDigest(t *testing.T) {
	verified := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	images := map[string]string{"web": "127.0.0.1:37199/demo-web:abc123"}
	set := newPushedDigestSet()
	set.record("127.0.0.1:37199/demo-web:abc123", verified)
	if err := set.verify(images, map[string]string{"web": "127.0.0.1:5000/demo-web@" + verified}); err != nil {
		t.Fatalf("verified digest refused: %v", err)
	}
	err := set.verify(images, map[string]string{"web": "127.0.0.1:5000/demo-web@" + other})
	if err == nil || !strings.Contains(err.Error(), "refusing to promote an unverified digest") {
		t.Fatalf("rewritten tag was not refused: %v", err)
	}
	var none *pushedDigestSet
	if err := none.verify(images, map[string]string{"web": "x@" + other}); err != nil {
		t.Fatalf("a deploy without direct push must not be checked: %v", err)
	}
}

// --skip-build pushes the daemon's image with docker push, so its local tags
// keep the usual cleanup and the push timing is a real push.
func TestSwarmBuildKitPushesOnlyWhenBuildingLocally(t *testing.T) {
	push := buildExecutionOptions{Push: true}
	if !swarmBuildKitPushes(push, false, false) {
		t.Fatal("local push-mode build must count as a BuildKit push")
	}
	if swarmBuildKitPushes(push, false, true) {
		t.Fatal("--skip-build must keep docker push semantics")
	}
	if swarmBuildKitPushes(push, true, false) {
		t.Fatal("the SSH remote build has its own transport")
	}
	if swarmBuildKitPushes(buildExecutionOptions{}, false, false) {
		t.Fatal("--load builds are not BuildKit pushes")
	}
}
