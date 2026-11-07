// Package detect analyses a project directory to identify the technology stack
// and produce an appropriate DeployShuttle configuration preset.
package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type Stack struct {
	Preset     string
	Framework  string
	Language   string
	HasDocker  bool
	HasCompose bool
	HasCaddy   bool
	Domain     string
	Workers    []string
	Signals    []string // human-readable detection reasons
}

func Analyze(dir string) Stack {
	s := Stack{}
	s.HasDocker = fileExists(dir, "Dockerfile") || fileExists(dir, "dockerfile")
	s.HasCompose = fileExists(dir, "docker-compose.yml") || fileExists(dir, "docker-compose.yaml") ||
		fileExists(dir, "compose.yml") || fileExists(dir, "compose.yaml")
	s.HasCaddy = fileExists(dir, "Caddyfile") || grepFile(dir, "docker-compose.yml", "caddy") ||
		grepFile(dir, "compose.yml", "caddy")

	switch {
	case detectNextJS(dir):
		s.Preset = "nextjs"
		s.Framework = "Next.js"
		s.Language = "TypeScript/JavaScript"
		s.Signals = append(s.Signals, "next.config found")
	case detectTanStackStart(dir):
		s.Preset = "tanstack-start"
		s.Framework = "TanStack Start"
		s.Language = "TypeScript/JavaScript"
		s.Signals = append(s.Signals, "package.json with @tanstack/*-start dependency")
	case detectLaravel(dir):
		s.Preset = "laravel"
		s.Framework = "Laravel"
		s.Language = "PHP"
		s.Workers = []string{`"*-queue"`, `"*-horizon"`, `"*-scheduler"`, `"*-worker"`}
		s.Signals = append(s.Signals, "artisan + composer.json/laravel detected")
	case detectSymfony(dir):
		s.Preset = "symfony"
		s.Framework = "Symfony"
		s.Language = "PHP"
		s.Signals = append(s.Signals, "bin/console + symfony detected")
	case detectHono(dir):
		s.Preset = "hono"
		s.Framework = "Hono"
		s.Language = "TypeScript/JavaScript"
		s.Signals = append(s.Signals, "package.json with hono dependency")
	case detectFastify(dir):
		s.Preset = "fastify"
		s.Framework = "Fastify"
		s.Language = "TypeScript/JavaScript"
		s.Signals = append(s.Signals, "package.json with fastify dependency")
	case detectFastAPI(dir):
		s.Preset = "fastapi"
		s.Framework = "FastAPI"
		s.Language = "Python"
		s.Signals = append(s.Signals, "fastapi dependency in requirements.txt/pyproject.toml")
	case detectNodeAPI(dir):
		s.Preset = "node-api"
		s.Framework = "Node.js API"
		s.Language = "TypeScript/JavaScript"
		s.Signals = append(s.Signals, "package.json with server entrypoint")
	case detectGo(dir):
		s.Preset = "node-api"
		s.Framework = "Go"
		s.Language = "Go"
		s.Signals = append(s.Signals, "go.mod detected")
	case detectDockerSwarm(dir):
		s.Preset = "docker-swarm"
		s.Framework = "Docker Swarm"
		s.Language = ""
		s.Workers = []string{`"*_worker"`, `"*_consumer"`}
		s.Signals = append(s.Signals, "docker-compose with deploy.replicas / swarm mode")
	default:
		if s.HasDocker {
			s.Preset = "node-api"
			s.Framework = "Docker"
			s.Language = ""
			s.Signals = append(s.Signals, "Dockerfile present, stack not identified precisely")
		}
	}

	if s.HasDocker {
		s.Signals = append(s.Signals, "Dockerfile found")
	}
	if s.HasCompose {
		s.Signals = append(s.Signals, "docker-compose found")
	}
	if s.HasCaddy {
		s.Signals = append(s.Signals, "Caddy reverse proxy detected")
	}

	return s
}

func detectNextJS(dir string) bool {
	for _, f := range []string{"next.config.js", "next.config.ts", "next.config.mjs"} {
		if fileExists(dir, f) {
			return true
		}
	}
	if pkgHasDep(dir, "next") {
		return true
	}
	return false
}

func detectLaravel(dir string) bool {
	if !fileExists(dir, "artisan") {
		return false
	}
	if fileExists(dir, "composer.json") {
		return grepFile(dir, "composer.json", "laravel")
	}
	return false
}

func detectSymfony(dir string) bool {
	if !fileExists(dir, "bin/console") {
		return false
	}
	if fileExists(dir, "symfony.lock") {
		return true
	}
	if fileExists(dir, "composer.json") {
		return grepFile(dir, "composer.json", "symfony/framework-bundle")
	}
	return false
}

// detectTanStackStart matches the framework packages rather than the router
// alone: @tanstack/react-router is common in plain SPAs that are not Start apps.
func detectTanStackStart(dir string) bool {
	for _, dep := range []string{"@tanstack/react-start", "@tanstack/solid-start", "@tanstack/start"} {
		if pkgHasDep(dir, dep) {
			return true
		}
	}
	return false
}

func detectHono(dir string) bool {
	return pkgHasDep(dir, "hono")
}

func detectFastify(dir string) bool {
	return pkgHasDep(dir, "fastify")
}

func detectFastAPI(dir string) bool {
	for _, f := range []string{"requirements.txt", "pyproject.toml"} {
		if grepFile(dir, f, "fastapi") {
			return true
		}
	}
	return false
}

func detectNodeAPI(dir string) bool {
	if !fileExists(dir, "package.json") {
		return false
	}
	if pkgHasDep(dir, "next") {
		return false
	}
	pkg := readFile(dir, "package.json")
	for _, hint := range []string{"express", "fastify", "koa", "hono", "elysia", "hapi", "nestjs", "@nestjs/core"} {
		if strings.Contains(pkg, hint) {
			return true
		}
	}
	if strings.Contains(pkg, `"start"`) || strings.Contains(pkg, "server") {
		return true
	}
	return false
}

func detectGo(dir string) bool {
	return fileExists(dir, "go.mod")
}

func detectDockerSwarm(dir string) bool {
	for _, f := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		content := readFile(dir, f)
		if content == "" {
			continue
		}
		if strings.Contains(content, "deploy:") && strings.Contains(content, "replicas:") {
			return true
		}
	}
	return false
}

func fileExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func readFile(dir, name string) string {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(data)
}

func grepFile(dir, name, substr string) bool {
	return strings.Contains(strings.ToLower(readFile(dir, name)), strings.ToLower(substr))
}

func pkgHasDep(dir, dep string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return false
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return false
	}
	if _, ok := pkg.Dependencies[dep]; ok {
		return true
	}
	if _, ok := pkg.DevDependencies[dep]; ok {
		return true
	}
	return false
}
