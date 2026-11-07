package skills

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HostEnvName is the directory every harness looks up. It is the skill's
// public identity, not an implementation detail: Claude, Grok, Cursor, Codex,
// OpenCode and Agents all resolve skills by that folder name.
const HostEnvName = "shuttle-host-env"

//go:embed hostenv/SKILL.md
var hostEnvSkill embed.FS

// Scope selects which trees receive the bundled skill.
const (
	ScopeAll     = "all"
	ScopeUser    = "user"
	ScopeProject = "project"
)

// Request names where to write. Home is the operator's home directory (user
// harnesses, every project they open). ProjectDir is one checkout (teammates
// and repo-local agents). An empty field is skipped even if the scope asked
// for it, so a test can install one side without inventing the other.
type Request struct {
	Home       string
	ProjectDir string
	Scope      string
}

// Result lists every SKILL.md the install wrote, sorted, so the same request
// always prints the same report.
type Result struct {
	Written []string
}

// userHarnessSkillDirs are relative to the home directory. They match the
// lookup paths the local coding harnesses actually use. Creating a directory
// for a harness the operator has not installed yet is deliberate: the skill
// is there the day they do.
var userHarnessSkillDirs = []string{
	".agents/skills",
	".claude/skills",
	".codex/skills",
	".config/opencode/skills",
	".cursor/skills",
	".grok/skills",
}

// projectHarnessSkillDirs are relative to a checkout. OpenCode's project
// tree is `.opencode/skills`, not `.config/opencode`.
var projectHarnessSkillDirs = []string{
	".agents/skills",
	".claude/skills",
	".codex/skills",
	".cursor/skills",
	".grok/skills",
	".opencode/skills",
}

// BundledHostEnv returns the SKILL.md Shuttle ships. Install writes this
// exact body; nothing edits it on the way to disk.
func BundledHostEnv() ([]byte, error) {
	return hostEnvSkill.ReadFile("hostenv/SKILL.md")
}

// Install writes the bundled host-env skill into the requested harness
// trees. It overwrites an older copy so `shuttle skills install` after an
// upgrade refreshes the text agents will follow.
func Install(req Request) (Result, error) {
	scope := strings.TrimSpace(req.Scope)
	if scope == "" {
		scope = ScopeAll
	}
	switch scope {
	case ScopeAll, ScopeUser, ScopeProject:
	default:
		return Result{}, fmt.Errorf("unknown skills install scope %q; expected %s, %s or %s", scope, ScopeAll, ScopeUser, ScopeProject)
	}
	body, err := BundledHostEnv()
	if err != nil {
		return Result{}, fmt.Errorf("read bundled %s skill: %w", HostEnvName, err)
	}
	var dests []string
	if scope == ScopeAll || scope == ScopeUser {
		if strings.TrimSpace(req.Home) == "" {
			return Result{}, fmt.Errorf("skills install scope %s needs a home directory", scope)
		}
		dests = append(dests, skillFiles(req.Home, userHarnessSkillDirs)...)
	}
	if scope == ScopeAll || scope == ScopeProject {
		if strings.TrimSpace(req.ProjectDir) == "" {
			return Result{}, fmt.Errorf("skills install scope %s needs a project directory", scope)
		}
		dests = append(dests, skillFiles(req.ProjectDir, projectHarnessSkillDirs)...)
	}
	sort.Strings(dests)
	written := make([]string, 0, len(dests))
	for _, dest := range dests {
		if err := writeSkillFile(dest, body); err != nil {
			return Result{}, err
		}
		written = append(written, dest)
	}
	return Result{Written: written}, nil
}

func skillFiles(root string, harnessDirs []string) []string {
	files := make([]string, 0, len(harnessDirs))
	for _, dir := range harnessDirs {
		files = append(files, filepath.Join(root, dir, HostEnvName, "SKILL.md"))
	}
	return files
}

func writeSkillFile(dest string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(dest), err)
	}
	// A leftover symlink would send the bundled text into whoever it pointed
	// at. Remove it so the install owns a regular file in the harness tree.
	info, err := os.Lstat(dest)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(dest); err != nil {
			return fmt.Errorf("replace symlink %s: %w", dest, err)
		}
	}
	if err := os.WriteFile(dest, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}
