package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestAnalyzeDetectsFrameworkPresets(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		preset    string
		framework string
	}{
		{
			name:      "hono",
			files:     map[string]string{"package.json": `{"dependencies":{"hono":"^4.6.0"}}`},
			preset:    "hono",
			framework: "Hono",
		},
		{
			name:      "fastify",
			files:     map[string]string{"package.json": `{"dependencies":{"fastify":"^5.0.0"}}`},
			preset:    "fastify",
			framework: "Fastify",
		},
		{
			name:      "tanstack-start",
			files:     map[string]string{"package.json": `{"dependencies":{"@tanstack/react-start":"^1.0.0"}}`},
			preset:    "tanstack-start",
			framework: "TanStack Start",
		},
		{
			name:      "fastapi requirements",
			files:     map[string]string{"requirements.txt": "fastapi==0.115.0\nuvicorn\n"},
			preset:    "fastapi",
			framework: "FastAPI",
		},
		{
			name:      "fastapi pyproject",
			files:     map[string]string{"pyproject.toml": "[project]\nname = \"api\"\ndependencies = [\"fastapi[standard]\"]\n"},
			preset:    "fastapi",
			framework: "FastAPI",
		},
		{
			name:      "nextjs wins over node dependencies",
			files:     map[string]string{"package.json": `{"dependencies":{"next":"15.0.0","hono":"^4.6.0"}}`},
			preset:    "nextjs",
			framework: "Next.js",
		},
		{
			name:      "generic node api",
			files:     map[string]string{"package.json": `{"dependencies":{"express":"^4.19.0"}}`},
			preset:    "node-api",
			framework: "Node.js API",
		},
		{
			name:      "laravel",
			files:     map[string]string{"artisan": "#!/usr/bin/env php\n", "composer.json": `{"require":{"laravel/framework":"^11.0"}}`},
			preset:    "laravel",
			framework: "Laravel",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stack := Analyze(writeProject(t, tt.files))
			if stack.Preset != tt.preset || stack.Framework != tt.framework {
				t.Fatalf("Analyze = preset %q / framework %q, want %q / %q", stack.Preset, stack.Framework, tt.preset, tt.framework)
			}
			if len(stack.Signals) == 0 {
				t.Fatal("expected at least one detection signal")
			}
		})
	}
}

func TestAnalyzeIgnoresUnrelatedPythonProject(t *testing.T) {
	stack := Analyze(writeProject(t, map[string]string{"requirements.txt": "django==5.1\n"}))
	if stack.Preset != "" {
		t.Fatalf("expected no preset for a non-FastAPI Python project, got %q", stack.Preset)
	}
}

func TestAnalyzeReportsDockerSignals(t *testing.T) {
	stack := Analyze(writeProject(t, map[string]string{
		"Dockerfile":         "FROM oven/bun:1\n",
		"docker-compose.yml": "services:\n  caddy:\n    image: caddy:2\n",
	}))
	if !stack.HasDocker || !stack.HasCompose || !stack.HasCaddy {
		t.Fatalf("expected docker/compose/caddy detection, got %+v", stack)
	}
	if stack.Preset != "node-api" || stack.Framework != "Docker" {
		t.Fatalf("expected the generic Docker fallback, got preset %q / framework %q", stack.Preset, stack.Framework)
	}
}
