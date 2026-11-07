package ssh

import "testing"

const RemoteBuildKitImage = "moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3"

func TestExistingBuildKitDigestRemainsValid(t *testing.T) {
	old := "moby/buildkit:v0.32.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|host"
	if err := validateRuntimeBuilderIdentity([]byte(old)); err != nil {
		t.Fatalf("existing digest-pinned BuildKit rejected: %v", err)
	}
}

func TestRuntimeImageMustMatchStoredBuilder(t *testing.T) {
	runner := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.40", User: "build", Port: 22}, prepared: true, builderImage: RemoteBuildKitImage}
	runner.dockerRun = func([]string) ([]byte, error) {
		return []byte("moby/buildkit:v0.32.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|host"), nil
	}
	if err := runner.validateRuntimeBuilder("shuttle-demo-remote", true); err == nil {
		t.Fatal("accepted runtime image different from stored builder")
	}
}
