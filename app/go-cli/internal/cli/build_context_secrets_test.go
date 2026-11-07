package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitContext(t *testing.T, gitignore, dockerignore string, files ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	write := func(name, content string) {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", gitignore)
	if dockerignore != "" {
		write(".dockerignore", dockerignore)
	}
	for _, file := range files {
		write(file, "x")
	}
	return dir
}

// A secret Git ignores and .dockerignore lets through is refused by name; the
// same tree with the file excluded builds.
func TestBuildRefusesASecretGitIgnoresButDockerShips(t *testing.T) {
	dir := gitContext(t, ".env.local\nbackup.sql\n", "node_modules/\n", ".env.local", "backup.sql", "src/app.js")
	err := refuseIgnoredSecretsInBuildContext(buildSpec{Context: dir, Dockerfile: "Dockerfile"})
	if err == nil || !strings.Contains(err.Error(), ".env.local, backup.sql") || !strings.Contains(err.Error(), ".dockerignore") {
		t.Fatalf("want a refusal naming both files, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".dockerignore"), []byte(".env.*\n*.sql\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := refuseIgnoredSecretsInBuildContext(buildSpec{Context: dir, Dockerfile: "Dockerfile"}); err != nil {
		t.Fatalf("excluded secrets must not block the build: %v", err)
	}
}

// What is not refused: templates, dependency trees, tracked files (the
// operator's choice) and contexts outside Git.
func TestBuildContextGuardIgnoresWhatIsNotAnOperatorSecret(t *testing.T) {
	dir := gitContext(t, ".env.example\nnode_modules/\n", "", ".env.example", "node_modules/lib/test/key.pem")
	if err := refuseIgnoredSecretsInBuildContext(buildSpec{Context: dir}); err != nil {
		t.Fatalf("templates and dependency fixtures are not secrets: %v", err)
	}
	if err := refuseIgnoredSecretsInBuildContext(buildSpec{Context: t.TempDir()}); err != nil {
		t.Fatalf("a context outside Git cannot be classified: %v", err)
	}
}

func TestDockerignoreSemantics(t *testing.T) {
	for _, tc := range []struct {
		patterns []string
		file     string
		want     bool
	}{
		{[]string{".env.*"}, ".env.local", true},
		{[]string{".env.*"}, "config/.env.local", false},
		{[]string{"**/.env.*"}, "config/.env.local", true},
		{[]string{"secrets"}, "secrets/prod.key", true},
		{[]string{"/certs/*.pem"}, "certs/site.pem", true},
		{[]string{"*.pem", "!site.pem"}, "site.pem", false},
		{[]string{"*.sql", "!keep.sql", "*"}, "keep.sql", true},
		{[]string{"data/[a-c]*.dump"}, "data/b1.dump", true},
		{nil, ".env", false},
	} {
		if got := dockerignoreExcludes(tc.patterns, tc.file); got != tc.want {
			t.Errorf("%v on %s: want %v, got %v", tc.patterns, tc.file, tc.want, got)
		}
	}
}
