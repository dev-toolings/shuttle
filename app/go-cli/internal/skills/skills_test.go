package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledHostEnvIsTheSkillAgentsFollow(t *testing.T) {
	body, err := BundledHostEnv()
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, need := range []string{
		"name: shuttle-host-env",
		"secrets.backend: host",
		"shuttle --install skills",
		"shuttle skills install",
		".env.example",
		"deploy.env_push",
	} {
		if !strings.Contains(text, need) {
			t.Errorf("bundled skill missing %q", need)
		}
	}
	if strings.Contains(text, "Copy to .env and fill in the values") {
		t.Fatal("the skill must not tell anyone to copy production values onto a workstation")
	}
}

func TestInstallWritesEveryUserHarness(t *testing.T) {
	home := t.TempDir()
	result, err := Install(Request{Home: home, Scope: ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Written) != len(userHarnessSkillDirs) {
		t.Fatalf("user install wrote %d files, want %d: %#v", len(result.Written), len(userHarnessSkillDirs), result.Written)
	}
	body, err := BundledHostEnv()
	if err != nil {
		t.Fatal(err)
	}
	for i, dest := range result.Written {
		if i > 0 && dest <= result.Written[i-1] {
			t.Fatalf("written paths must be sorted, got %#v", result.Written)
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Fatalf("read %s: %v", dest, err)
		}
		if string(got) != string(body) {
			t.Fatalf("%s does not match the bundled skill", dest)
		}
		if !strings.HasPrefix(dest, home) {
			t.Fatalf("user install escaped home: %s", dest)
		}
	}
}

func TestInstallWritesEveryProjectHarness(t *testing.T) {
	project := t.TempDir()
	result, err := Install(Request{ProjectDir: project, Scope: ScopeProject})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Written) != len(projectHarnessSkillDirs) {
		t.Fatalf("project install wrote %d files, want %d", len(result.Written), len(projectHarnessSkillDirs))
	}
	for _, dest := range result.Written {
		if !strings.HasPrefix(dest, project) {
			t.Fatalf("project install escaped checkout: %s", dest)
		}
	}
}

func TestInstallAllIsUserPlusProjectWithoutOverlapConfusion(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	result, err := Install(Request{Home: home, ProjectDir: project, Scope: ScopeAll})
	if err != nil {
		t.Fatal(err)
	}
	want := len(userHarnessSkillDirs) + len(projectHarnessSkillDirs)
	if len(result.Written) != want {
		t.Fatalf("all-scope wrote %d files, want %d", len(result.Written), want)
	}
}

func TestInstallRefreshesAStaleCopyAndReplacesASymlink(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", HostEnvName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(dest, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(Request{Home: home, Scope: ScopeUser}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := BundledHostEnv()
	if string(got) != string(body) {
		t.Fatal("install must overwrite a stale skill with the bundled text")
	}

	other := filepath.Join(t.TempDir(), "elsewhere.md")
	if err := os.WriteFile(other, []byte("elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(Request{Home: home, Scope: ScopeUser}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("install must replace a symlink with a regular file it owns")
	}
	elsewhere, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if string(elsewhere) != "elsewhere\n" {
		t.Fatal("replacing the symlink must not rewrite the old target")
	}
}

func TestInstallRejectsAnUnknownScopeAndAMissingTree(t *testing.T) {
	if _, err := Install(Request{Home: t.TempDir(), Scope: "global"}); err == nil || !strings.Contains(err.Error(), "unknown skills install scope") {
		t.Fatalf("unknown scope: %v", err)
	}
	if _, err := Install(Request{Scope: ScopeUser}); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Fatalf("user scope without home: %v", err)
	}
	if _, err := Install(Request{Scope: ScopeProject}); err == nil || !strings.Contains(err.Error(), "project directory") {
		t.Fatalf("project scope without checkout: %v", err)
	}
}
