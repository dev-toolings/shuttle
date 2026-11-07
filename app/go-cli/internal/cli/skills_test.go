package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/skills"
)

func TestSkillsInstallWritesUserAndProjectHarnesses(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)

	cmd := newSkillsInstallCommand()
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, "skill="+skills.HostEnvName) {
		t.Fatalf("install report missing skill name:\n%s", body)
	}
	userCopy := filepath.Join(home, ".claude", "skills", skills.HostEnvName, "SKILL.md")
	projectCopy := filepath.Join(project, ".claude", "skills", skills.HostEnvName, "SKILL.md")
	for _, path := range []string{userCopy, projectCopy} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
		if !strings.Contains(string(got), "secrets.backend: host") {
			t.Fatalf("%s is not the bundled skill", path)
		}
	}
}

func TestRootInstallFlagInstallsSkills(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)

	root := NewRootCommand()
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetArgs([]string{"--install", "skills"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".grok", "skills", skills.HostEnvName, "SKILL.md")); err != nil {
		t.Fatalf("root --install skills must write user harnesses: %v", err)
	}
	if _, err := os.Stat(filepath.Join(project, ".cursor", "skills", skills.HostEnvName, "SKILL.md")); err != nil {
		t.Fatalf("root --install skills must write project harnesses: %v", err)
	}
}

func TestRootInstallRejectsUnknownTarget(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{"--install", "prompts"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown install target") {
		t.Fatalf("got %v", err)
	}
}

func TestSkillsInstallRejectsUnknownScope(t *testing.T) {
	cmd := newSkillsInstallCommand()
	cmd.SetArgs([]string{"--scope", "global"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown skills install scope") {
		t.Fatalf("got %v", err)
	}
}
