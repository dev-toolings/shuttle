package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDockerBuildxRemoteBuildPushesWithoutRegistryCacheExport(t *testing.T) {
	args := dockerBuildxRemoteCommandArgs(
		"shuttle-demo-remote",
		"127.0.0.1:5000/demo-web:abc123",
		"Dockerfile",
		[]string{"--platform", "linux/amd64"},
		".",
	)
	if !slices.Contains(args, "--push") || slices.Contains(args, "--load") {
		t.Fatalf("remote build must push from BuildKit and never load to the laptop: %#v", args)
	}
	if slices.Contains(args, "--cache-from") || slices.Contains(args, "--cache-to") || slices.Contains(args, "mode=max") {
		t.Fatalf("remote build must keep cache in the persistent runner volume: %#v", args)
	}
}

func TestConfigureRemoteBuildPlanSeparatesRunnerAndDeployReferences(t *testing.T) {
	plan := buildPlan{Builds: []plannedBuild{{
		Image:      "127.0.0.1:53124/demo-web:abc123",
		CacheImage: "127.0.0.1:53124/demo-web:buildcache",
	}}}
	// The reference rewrite is exercised through the same primitive used by the
	// deploy after it opens the runner tunnel. This test does not contact Docker.
	plan.Builds[0].BuildImage = rewriteRegistryReference(plan.Builds[0].Image, "127.0.0.1:5000")
	plan.Builds[0].BuildCacheImage = rewriteRegistryReference(plan.Builds[0].CacheImage, "127.0.0.1:5000")
	if plan.Builds[0].Image == plan.Builds[0].BuildImage || plan.Builds[0].CacheImage == plan.Builds[0].BuildCacheImage {
		t.Fatalf("runner and deploy references must be distinct when their tunnel ports differ: %#v", plan.Builds[0])
	}
	if !strings.HasPrefix(plan.Builds[0].BuildImage, "127.0.0.1:5000/") || !strings.HasPrefix(plan.Builds[0].BuildCacheImage, "127.0.0.1:5000/") {
		t.Fatalf("runner references do not use the runner loopback: %#v", plan.Builds[0])
	}
}

func TestRemoteBuildReferencesCannotFallBackToLaptopRegistry(t *testing.T) {
	runner := &fakeRemoteBuildRunner{registry: "127.0.0.1:5000"}
	plan := buildPlan{Builds: []plannedBuild{{BuildImage: "registry.example/demo:abc123", BuildCacheImage: "127.0.0.1:5000/demo:buildcache"}}}
	if err := validateRemoteBuildReferences(plan, runner); err == nil || !strings.Contains(err.Error(), "runner registry tunnel") {
		t.Fatalf("laptop or public registry reference was accepted: %v", err)
	}
}

func TestRemoteBuildFailureNamesTheRunner(t *testing.T) {
	previous := remoteDockerBuildRunner
	remoteDockerBuildRunner = func(string, string, []string) error { return errors.New("connection refused") }
	t.Cleanup(func() { remoteDockerBuildRunner = previous })
	err := buildImageWithSpecWithOptions(buildSpec{Context: ".", Dockerfile: "Dockerfile"}, "127.0.0.1:5000/demo:abc", "", false, buildExecutionOptions{
		RemoteBuilder:    "shuttle-demo-remote",
		RemoteDockerHost: "ssh://build@builder.example:22",
	})
	if err == nil || !strings.Contains(err.Error(), "remote build runner ssh://build@builder.example:22") {
		t.Fatalf("remote failure did not identify the runner: %v", err)
	}
}

func TestReadBuildMetadataDigestParsesBuildxOutputAndAllowsAbsentKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.json")
	want := "sha256:" + strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(`{"containerimage.digest":"`+want+`","containerimage.config.digest":"sha256:`+strings.Repeat("b", 64)+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readBuildMetadataDigest(path)
	if err != nil || got != want {
		t.Fatalf("metadata digest = %q, %v; want %q", got, err, want)
	}

	if err := os.WriteFile(path, []byte(`{"buildx.build.ref":"builder/abc"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = readBuildMetadataDigest(path)
	if err != nil || got != "" {
		t.Fatalf("absent metadata digest = %q, %v; want empty digest without error", got, err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = readBuildMetadataDigest(path)
	if err != nil || got != "" {
		t.Fatalf("empty metadata file digest = %q, %v; want empty digest without error", got, err)
	}
}

type fakeRemoteBuildRunner struct{ registry string }

func (r *fakeRemoteBuildRunner) RegistryAddress() string { return r.registry }
