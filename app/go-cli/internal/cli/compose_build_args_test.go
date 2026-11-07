package cli

import (
	"slices"
	"strings"
	"testing"
)

func TestDockerBuildCommandArgsPublishesImportableInlineCache(t *testing.T) {
	args := dockerBuildCommandArgs(
		"registry.example/app:commit",
		"Dockerfile",
		"registry.example/app:buildcache",
		[]string{"--target", "prod"},
		".",
	)

	want := []string{
		"build",
		"--pull",
		"--provenance=false",
		"-t", "registry.example/app:commit",
		"-f", "Dockerfile",
		"--cache-from", "registry.example/app:buildcache",
		"--build-arg", "BUILDKIT_INLINE_CACHE=1",
		"--target", "prod",
		".",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("unexpected docker build arguments:\n got: %#v\nwant: %#v", args, want)
	}
}

func TestDockerBuildRegistryCacheCommandArgsExportsMaxModeCache(t *testing.T) {
	warm := dockerBuildRegistryCacheCommandArgs(
		"registry.example/app:commit",
		"Dockerfile",
		"registry.example/app:buildcache",
		"registry.example/app:buildcache",
		[]string{"--target", "prod"},
		".",
	)
	want := []string{
		"build",
		"--pull",
		"--provenance=false",
		"-t", "registry.example/app:commit",
		"-f", "Dockerfile",
		"--cache-from", "type=registry,ref=registry.example/app:buildcache",
		"--cache-to", "type=registry,ref=registry.example/app:buildcache,mode=max,image-manifest=true,oci-mediatypes=true",
		"--target", "prod",
		".",
	}
	if !slices.Equal(warm, want) {
		t.Fatalf("unexpected warm registry-cache arguments:\n got: %#v\nwant: %#v", warm, want)
	}
	if slices.Contains(warm, "BUILDKIT_INLINE_CACHE=1") {
		t.Fatalf("registry cache export must not also request inline cache: %#v", warm)
	}

	cold := dockerBuildRegistryCacheCommandArgs(
		"registry.example/app:commit",
		"Dockerfile",
		"",
		"registry.example/app:buildcache",
		nil,
		".",
	)
	wantCold := []string{
		"build",
		"--pull",
		"--provenance=false",
		"-t", "registry.example/app:commit",
		"-f", "Dockerfile",
		"--cache-to", "type=registry,ref=registry.example/app:buildcache,mode=max,image-manifest=true,oci-mediatypes=true",
		".",
	}
	if !slices.Equal(cold, wantCold) {
		t.Fatalf("cold build must still export the registry cache:\n got: %#v\nwant: %#v", cold, wantCold)
	}
}

func TestDockerBuildxCommandUsesRunScopedBuilder(t *testing.T) {
	args := dockerBuildxCommandArgs("shuttle-demo-run-builder", "registry/app:commit", "Dockerfile", "", nil, ".")
	want := []string{"buildx", "build", "--builder", "shuttle-demo-run-builder", "--load", "--pull", "--provenance=false", "-t", "registry/app:commit", "-f", "Dockerfile", "--build-arg", "BUILDKIT_INLINE_CACHE=1", "."}
	if !slices.Equal(args, want) {
		t.Fatalf("unexpected docker buildx arguments:\n got: %#v\nwant: %#v", args, want)
	}
}

func TestDockerBuildxCommandPersistsEphemeralRunCachePerApplication(t *testing.T) {
	args := dockerBuildxCommandArgsWithLocalCache(
		"shuttle-demo-run-builder",
		"127.0.0.1:51234/demo-api:abc123",
		"Dockerfile",
		"127.0.0.1:51234/demo-api:buildcache",
		"/cache/deploy-shuttle/buildkit/demo",
		true,
		nil,
		".",
	)
	want := []string{
		"buildx", "build", "--builder", "shuttle-demo-run-builder", "--load", "--pull", "--provenance=false",
		"-t", "127.0.0.1:51234/demo-api:abc123", "-f", "Dockerfile",
		"--cache-from", "127.0.0.1:51234/demo-api:buildcache",
		"--cache-from", "type=local,src=/cache/deploy-shuttle/buildkit/demo",
		"--cache-to", "type=local,dest=/cache/deploy-shuttle/buildkit/demo,mode=max",
		"--build-arg", "BUILDKIT_INLINE_CACHE=1", ".",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("unexpected persistent-cache buildx arguments:\n got: %#v\nwant: %#v", args, want)
	}
}

func TestDockerBuildxRegistryCacheCommandArgsExportsMaxModeCacheThroughTheBuilder(t *testing.T) {
	warm := dockerBuildxRegistryCacheCommandArgs(
		"shuttle-demo",
		"127.0.0.1:51234/demo-api:abc123",
		"Dockerfile",
		"127.0.0.1:51234/demo-api:buildcache",
		"127.0.0.1:51234/demo-api:buildcache",
		"",
		[]string{"--target", "prod"},
		".",
		dockerBuildxOutputOptions{},
	)
	want := []string{
		"buildx", "build", "--builder", "shuttle-demo", "--load", "--pull", "--provenance=false",
		"-t", "127.0.0.1:51234/demo-api:abc123", "-f", "Dockerfile",
		"--cache-from", "type=registry,ref=127.0.0.1:51234/demo-api:buildcache",
		"--cache-to", "type=registry,ref=127.0.0.1:51234/demo-api:buildcache,mode=max,image-manifest=true,oci-mediatypes=true",
		"--target", "prod",
		".",
	}
	if !slices.Equal(warm, want) {
		t.Fatalf("unexpected warm buildx registry-cache arguments:\n got: %#v\nwant: %#v", warm, want)
	}
	// Inline cache is mode=min by construction: it only records chains for the
	// layers of the final image, which excludes every COPY --from stage.
	if slices.Contains(warm, "BUILDKIT_INLINE_CACHE=1") {
		t.Fatalf("registry cache export must not fall back to inline cache: %#v", warm)
	}

	cold := dockerBuildxRegistryCacheCommandArgs(
		"shuttle-demo",
		"127.0.0.1:51234/demo-api:abc123",
		"Dockerfile",
		"",
		"127.0.0.1:51234/demo-api:buildcache",
		"",
		nil,
		".",
		dockerBuildxOutputOptions{},
	)
	if slices.Contains(cold, "--cache-from") {
		t.Fatalf("cold build must not import an absent cache: %#v", cold)
	}
	if !slices.Contains(cold, "--cache-to") {
		t.Fatalf("cold build must still seed the registry cache: %#v", cold)
	}
}

func TestDockerBuildxRegistryCacheCommandArgsHonoursMinMode(t *testing.T) {
	args := dockerBuildxRegistryCacheCommandArgs(
		"shuttle-demo",
		"127.0.0.1:51234/demo-web:abc123",
		"Dockerfile",
		"127.0.0.1:51234/demo-web:buildcache",
		"127.0.0.1:51234/demo-web:buildcache",
		"min",
		nil,
		".",
		dockerBuildxOutputOptions{},
	)
	want := "type=registry,ref=127.0.0.1:51234/demo-web:buildcache,mode=min,image-manifest=true,oci-mediatypes=true"
	if !slices.Contains(args, want) {
		t.Fatalf("build_cache_mode min must export a mode=min registry cache: %#v", args)
	}
}

func TestSwarmRegistryCacheBuildArgsPushWithMetadataAndKeepCacheFlags(t *testing.T) {
	policy := swarmCachePolicyFor("shuttle-demo", "")
	args := dockerBuildxRegistryCacheCommandArgs(
		"shuttle-demo",
		"127.0.0.1:51234/demo-api:abc123",
		"Dockerfile",
		"127.0.0.1:51234/demo-api:buildcache",
		"127.0.0.1:51234/demo-api:buildcache",
		"",
		[]string{"--target", "prod"},
		".",
		dockerBuildxOutputOptions{Push: policy.Build.Push, MetadataFile: "/tmp/shuttle-build-metadata-api.json"},
	)
	if !slices.Contains(args, "--push") || slices.Contains(args, "--load") {
		t.Fatalf("Swarm local builds must push without loading into Docker: %#v", args)
	}
	if !slices.Contains(args, "--metadata-file") || !slices.Contains(args, "/tmp/shuttle-build-metadata-api.json") {
		t.Fatalf("Swarm local builds must report BuildKit metadata: %#v", args)
	}
	for _, required := range []string{
		"--pull",
		"--provenance=false",
		"type=registry,ref=127.0.0.1:51234/demo-api:buildcache",
		"type=registry,ref=127.0.0.1:51234/demo-api:buildcache,mode=max,image-manifest=true,oci-mediatypes=true",
		"--target",
		"prod",
	} {
		if !slices.Contains(args, required) {
			t.Fatalf("Swarm direct push lost required argument %q: %#v", required, args)
		}
	}
}

func TestComposeModeBuildArgsStillLoadWithoutPushing(t *testing.T) {
	args := dockerBuildxCommandArgs("shuttle-demo", "registry.example/demo:abc123", "Dockerfile", "", nil, ".")
	if !slices.Contains(args, "--load") || slices.Contains(args, "--push") {
		t.Fatalf("Compose-mode builds must keep loading images into Docker: %#v", args)
	}
}

// Captured builds pin plain progress so an inherited BUILDKIT_PROGRESS cannot
// change the parsed format; builds without capture are left as they were.
func TestCapturedBuildsPinPlainProgress(t *testing.T) {
	buildx := withPlainBuildProgress([]string{"buildx", "build", "--builder", "b", "--push", "-t", "x", "."})
	if len(buildx) < 3 || buildx[2] != "--progress=plain" {
		t.Fatalf("buildx args must carry --progress=plain right after build: %#v", buildx)
	}
	plain := withPlainBuildProgress([]string{"build", "--pull", "-t", "x", "."})
	if plain[1] != "--progress=plain" {
		t.Fatalf("docker build args must carry --progress=plain: %#v", plain)
	}
	kept := withPlainBuildProgress([]string{"buildx", "build", "--progress=rawjson", "."})
	if strings.Count(strings.Join(kept, " "), "--progress") != 1 {
		t.Fatalf("an explicit --progress must not be duplicated: %#v", kept)
	}
}

// An explicit --progress of another format is replaced, never kept.
func TestCapturedBuildsReplaceAnyOtherProgressFormat(t *testing.T) {
	for _, args := range [][]string{
		{"buildx", "build", "--progress=rawjson", "-t", "x", "."},
		{"buildx", "build", "--progress", "tty", "-t", "x", "."},
		{"build", "--progress=auto", "-t", "x", "."},
	} {
		got := withPlainBuildProgress(args)
		count := 0
		for _, arg := range got {
			if strings.HasPrefix(arg, "--progress") {
				count++
				if arg != "--progress=plain" {
					t.Fatalf("%v kept %q", args, arg)
				}
			}
			if arg == "tty" {
				t.Fatalf("%v kept the value of a separate --progress: %v", args, got)
			}
		}
		if count != 1 {
			t.Fatalf("%v gives %d progress flags: %v", args, count, got)
		}
	}
}
