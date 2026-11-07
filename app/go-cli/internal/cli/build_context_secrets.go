package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// refuseIgnoredSecretsInBuildContext stops a build whose context would carry a
// secret the project already keeps out of Git.
//
// Git and Docker read two different ignore files. A `.env.local`, a key pair
// or a database dump that `.gitignore` hides is still sent to BuildKit unless
// `.dockerignore` names it too, and a `COPY . .` then bakes it into a layer
// that is pushed to the VPS registry and kept for every rollback. With a remote
// builder the context itself also crosses SSH. FrankenDeploy met the same leak
// when it uploaded working trees and answered by shipping only what Git ships
// (yoanbernabeu/frankendeploy#115). Shuttle keeps its context as Docker defines
// it, because generated assets and vendored files legitimately live there, and
// refuses instead the one case that is never intended: a file Git ignores,
// whose name says it is a secret, that `.dockerignore` lets through.
//
// Files Git tracks are the operator's explicit choice and `doctor` reports a
// tracked `.env` separately. Dependency trees (node_modules, vendor) ship test
// keys and sample env files that are not the operator's secrets. A context
// outside any Git checkout cannot be classified and is left alone.
func refuseIgnoredSecretsInBuildContext(spec buildSpec) error {
	contextDir := spec.Context
	if contextDir == "" {
		contextDir = "."
	}
	ignored, ok := gitIgnoredFiles(contextDir)
	if !ok {
		return nil
	}
	var candidates []string
	for _, file := range ignored {
		if secretLikeContextPath(file) {
			candidates = append(candidates, file)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	patterns, err := readBuildIgnorePatterns(contextDir, spec.Dockerfile)
	if err != nil {
		return err
	}
	var leaked []string
	for _, file := range candidates {
		if !dockerignoreExcludes(patterns, file) {
			leaked = append(leaked, file)
		}
	}
	if len(leaked) == 0 {
		return nil
	}
	sort.Strings(leaked)
	return fmt.Errorf("build context %s would send %s to the image builder: Git ignores %s but .dockerignore does not, so a COPY would bake it into an image layer kept on the VPS for every rollback; add it to .dockerignore (or delete it) and deploy again", contextDir, strings.Join(leaked, ", "), pluralIt(len(leaked)))
}

func pluralIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// gitIgnoredFiles lists the untracked files Git ignores under dir, relative to
// dir. ok is false when git is missing or dir is not inside a work tree.
func gitIgnoredFiles(dir string) ([]string, bool) {
	if err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return nil, false
	}
	out, err := exec.Command("git", "-C", dir, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", ".").Output()
	if err != nil {
		return nil, false
	}
	var files []string
	for _, entry := range bytes.Split(out, []byte{0}) {
		if len(entry) > 0 {
			files = append(files, filepath.ToSlash(string(entry)))
		}
	}
	return files, true
}

var secretContextNames = regexp.MustCompile(`^(\.env|\.env\..+|id_rsa|id_ecdsa|id_ed25519|.+\.(pem|key|p12|pfx)|.+\.(sql|sql\.gz|dump))$`)

// secretContextTemplates are env files meant to be shared, not secrets.
var secretContextTemplates = map[string]bool{".env.example": true, ".env.sample": true, ".env.dist": true, ".env.template": true}

func secretLikeContextPath(file string) bool {
	for _, part := range strings.Split(path.Dir(file), "/") {
		if part == "node_modules" || part == "vendor" {
			return false
		}
	}
	name := path.Base(file)
	return !secretContextTemplates[name] && secretContextNames.MatchString(name)
}

// readBuildIgnorePatterns returns the ignore file BuildKit applies: a
// Dockerfile-specific `<Dockerfile>.dockerignore` wins over the context's
// `.dockerignore`. No file means nothing is excluded.
func readBuildIgnorePatterns(contextDir, dockerfile string) ([]string, error) {
	candidates := []string{}
	if dockerfile != "" {
		candidates = append(candidates, dockerfile+".dockerignore")
		if !filepath.IsAbs(dockerfile) {
			candidates = append(candidates, filepath.Join(contextDir, dockerfile)+".dockerignore")
		}
	}
	candidates = append(candidates, filepath.Join(contextDir, ".dockerignore"))
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", candidate, err)
		}
		var patterns []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			patterns = append(patterns, line)
		}
		return patterns, nil
	}
	return nil, nil
}

// dockerignoreExcludes applies .dockerignore semantics to a slash-separated
// path relative to the context: patterns are evaluated in order, the last
// match wins, `!` re-includes, and a pattern that matches a parent directory
// excludes everything below it. `**` spans directories, `*` and `?` do not.
// A pattern that does not compile matches nothing, which errs toward refusing
// the build rather than toward shipping the file.
func dockerignoreExcludes(patterns []string, file string) bool {
	excluded := false
	for _, raw := range patterns {
		negate := strings.HasPrefix(raw, "!")
		pattern := strings.TrimPrefix(raw, "!")
		pattern = strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(pattern)), "/")
		if pattern == "" {
			continue
		}
		re, err := dockerignoreRegexp(pattern)
		if err != nil {
			continue
		}
		matched := false
		for candidate := file; candidate != "." && candidate != "/" && candidate != ""; candidate = path.Dir(candidate) {
			if re.MatchString(candidate) {
				matched = true
				break
			}
		}
		if matched {
			excluded = !negate
		}
	}
	return excluded
}

func dockerignoreRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := strings.IndexByte(pattern[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unterminated class in %q", pattern)
			}
			class := pattern[i+1 : i+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i += end
		case '\\':
			if i+1 < len(pattern) {
				i++
				b.WriteString(regexp.QuoteMeta(string(pattern[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
