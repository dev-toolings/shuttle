package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A monorepo app builds from the repository root (`context: ../..`) with a
// dockerfile relative to that context, as Compose reads it, while shuttle runs
// in the app directory.
func TestBuildResolvesDockerfileAgainstContext(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(app)

	var invocation []string
	previousRunner := dockerBuildRunner
	dockerBuildRunner = func(args []string) error {
		invocation = append([]string(nil), args...)
		return nil
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	spec := buildSpec{Context: "../..", Dockerfile: "apps/web/Dockerfile"}
	if err := buildImageWithSpecWithOptions(spec, "registry/web:abc123", "", false, buildExecutionOptions{Builder: "shuttle-web"}); err != nil {
		t.Fatal(err)
	}
	at := slices.Index(invocation, "-f")
	if at < 0 || invocation[at+1] != filepath.Join("../..", "apps/web/Dockerfile") {
		t.Fatalf("dockerfile must be resolved against the context: %#v", invocation)
	}
}

func TestResolveBuildDockerfileKeepsWorkingDirectoryPathsAndAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile.prod"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	// Older configs relied on the working directory; the file exists only there.
	if got := resolveBuildDockerfile(buildSpec{Context: "apps/api", Dockerfile: "Dockerfile.prod"}); got != "Dockerfile.prod" {
		t.Fatalf("working-directory dockerfile = %q", got)
	}
	absolute := filepath.Join(dir, "Dockerfile.prod")
	if got := resolveBuildDockerfile(buildSpec{Context: "apps/api", Dockerfile: absolute}); got != absolute {
		t.Fatalf("absolute dockerfile = %q", got)
	}
	if got := resolveBuildDockerfile(buildSpec{Context: ".", Dockerfile: "Dockerfile.prod"}); got != "Dockerfile.prod" {
		t.Fatalf("root-context dockerfile = %q", got)
	}
}
