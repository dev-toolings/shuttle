package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/images"
)

type registryTransport func(*http.Request) (*http.Response, error)

func (f registryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise the same token, tag-list and manifest exchanges as a v2 registry.
func fakeImageRegistry(r *http.Request) (*http.Response, error) {
	status, body := 200, ""
	headers := http.Header{}
	switch {
	case r.URL.Host == "auth.docker.io" || (r.URL.Host == "ghcr.io" && r.URL.Path == "/token"):
		if !strings.HasPrefix(r.URL.Query().Get("scope"), "repository:") || !strings.HasSuffix(r.URL.Query().Get("scope"), ":pull") {
			status = 400
		} else {
			body = `{"token":"test-token"}`
		}
	case r.Header.Get("Authorization") != "Bearer test-token":
		status = 401
	case strings.HasSuffix(r.URL.Path, "/tags/list"):
		switch {
		case strings.Contains(r.URL.Path, "frankenphp"):
			body = `{"tags":["1.2.0-php8.4","1.9.0-php8.4","1.10.0-php8.4-rc1"]}`
		case strings.Contains(r.URL.Path, "oven/bun"):
			body = `{"tags":["1.2.0-alpine","1.10.0-alpine"]}`
		case strings.Contains(r.URL.Path, "library/node"):
			body = `{"tags":["24.1.0-alpine"]}`
		case strings.Contains(r.URL.Path, "library/python"):
			body = `{"tags":["3.11.0-slim-trixie"]}`
		case strings.Contains(r.URL.Path, "astral-sh/uv"):
			body = `{"tags":["0.13.0-python3.11-trixie-slim"]}`
		default:
			status = 404
		}
	case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/"):
		valid := map[string]bool{
			"/v2/dunglas/frankenphp/manifests/1.9.0-php8.4":            true,
			"/v2/oven/bun/manifests/1.10.0-alpine":                     true,
			"/v2/library/node/manifests/24.1.0-alpine":                 true,
			"/v2/library/python/manifests/3.11.0-slim-trixie":          true,
			"/v2/astral-sh/uv/manifests/0.13.0-python3.11-trixie-slim": true,
		}
		if !valid[r.URL.Path] {
			status = 404
		} else {
			headers.Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
		}
	default:
		status = 404
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func init() {
	resolver := images.Resolver{Client: &http.Client{Transport: registryTransport(fakeImageRegistry)}}
	resolveTemplateImage = resolver.Resolve
}

func TestResolvedImagesLandInDockerfile(t *testing.T) {
	body, err := resolveDockerfileImages(context.Background(), "FROM __SHUTTLE_BUN_IMAGE__\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "oven/bun:1.10.0-alpine@sha256:"+strings.Repeat("a", 64)) {
		t.Fatal(body)
	}
}
func TestUnreachableRegistryNamesImage(t *testing.T) {
	old := resolveTemplateImage
	defer func() { resolveTemplateImage = old }()
	resolver := images.Resolver{Client: &http.Client{Transport: registryTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })}}
	resolveTemplateImage = resolver.Resolve
	_, err := resolveDockerfileImages(context.Background(), "FROM __SHUTTLE_BUN_IMAGE__", nil)
	if err == nil || !strings.Contains(err.Error(), "oven/bun") {
		t.Fatalf("unexpected error: %v", err)
	}
}
func TestDeclaredImageIsUsedWithoutRegistry(t *testing.T) {
	old := resolveTemplateImage
	defer func() { resolveTemplateImage = old }()
	resolveTemplateImage = func(context.Context, string, string, string) (string, error) { return "", errors.New("offline") }
	declared := "oven/bun:1.8.0-alpine@sha256:" + strings.Repeat("b", 64)
	body, err := resolveDockerfileImages(context.Background(), "FROM __SHUTTLE_BUN_IMAGE__", []string{declared})
	if err != nil || body != "FROM "+declared {
		t.Fatalf("body=%q err=%v", body, err)
	}
}
func TestInitLeavesExistingDockerfileWithoutResolution(t *testing.T) {
	withTempDir(t, func(string) {
		if err := os.WriteFile("Dockerfile", []byte("existing\n"), 0644); err != nil {
			t.Fatal(err)
		}
		old := resolveTemplateImage
		defer func() { resolveTemplateImage = old }()
		resolveTemplateImage = func(context.Context, string, string, string) (string, error) {
			return "", errors.New("must not resolve")
		}
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "hono", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--email", ""})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile("Dockerfile")
		if err != nil || string(body) != "existing\n" {
			t.Fatalf("body=%q err=%v", body, err)
		}
	})
}

func TestPythonAndUVTemplatesUseSameMinor(t *testing.T) {
	body, err := resolveDockerfileImages(context.Background(), "FROM __SHUTTLE_PYTHON_IMAGE__\nFROM __SHUTTLE_UV_IMAGE__\n", nil)
	if err != nil || !strings.Contains(body, "python:3.11.0-slim-trixie@") || !strings.Contains(body, "-python3.11-trixie-slim@") {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestInitHonorsImageFlags(t *testing.T) {
	withTempDir(t, func(string) {
		old := resolveTemplateImage
		defer func() { resolveTemplateImage = old }()
		resolveTemplateImage = func(context.Context, string, string, string) (string, error) {
			return "", errors.New("unexpected registry lookup")
		}
		bun := "oven/bun:1.8.0-alpine@sha256:" + strings.Repeat("b", 64)
		node := "node:24.2.0-alpine@sha256:" + strings.Repeat("c", 64)
		cmd := newInitCommand()
		cmd.SetArgs([]string{"--preset", "hono", "--app", "demo", "--domain", "demo.example.com", "--host", "203.0.113.10", "--email", "", "--image", bun, "--image", node})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile("Dockerfile")
		if err != nil || !strings.Contains(string(body), bun) || !strings.Contains(string(body), node) {
			t.Fatalf("body=%s err=%v", body, err)
		}
	})
}
