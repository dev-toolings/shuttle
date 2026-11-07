package cli

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/images"
)

type templateImage struct{ placeholder, repository, major, suffix string }

var templateImages = []templateImage{
	{"__SHUTTLE_FRANKENPHP_IMAGE__", "dunglas/frankenphp", "1", "-php8.4"},
	{"__SHUTTLE_BUN_IMAGE__", "oven/bun", "1", "-alpine"},
	{"__SHUTTLE_NODE_IMAGE__", "node", "24", "-alpine"},
	{"__SHUTTLE_PYTHON_IMAGE__", "python", "3", "-slim-trixie"},
	{"__SHUTTLE_UV_IMAGE__", "ghcr.io/astral-sh/uv", "0", ""},
}
var resolveTemplateImage = func(ctx context.Context, repo, major, suffix string) (string, error) {
	return (images.Resolver{}).Resolve(ctx, repo, major, suffix)
}

func resolveDockerfileImages(ctx context.Context, body string, declared []string) (string, error) {
	overrides := map[string]string{}
	for _, reference := range declared {
		matched := false
		for _, image := range templateImages {
			if images.ValidPinned(image.repository, reference) {
				if overrides[image.repository] != "" {
					return "", fmt.Errorf("duplicate --image for %s", image.repository)
				}
				overrides[image.repository] = reference
				matched = true
				break
			}
		}
		if !matched {
			return "", fmt.Errorf("invalid --image %q: expected a supported repository with tag and sha256 digest", reference)
		}
	}
	pythonMinor := ""
	for _, image := range templateImages {
		if !strings.Contains(body, image.placeholder) {
			continue
		}
		if image.repository == "ghcr.io/astral-sh/uv" && pythonMinor == "" {
			return "", fmt.Errorf("uv image requires a Python runtime image to select the matching minor")
		}
		identity := overrides[image.repository]
		if identity == "" {
			var err error
			suffix := image.suffix
			if image.repository == "ghcr.io/astral-sh/uv" && pythonMinor != "" {
				suffix = "-python" + pythonMinor + "-trixie-slim"
			}
			identity, err = resolveTemplateImage(ctx, image.repository, image.major, suffix)
			if err != nil {
				return "", fmt.Errorf("resolve %s: %w", image.repository, err)
			}
		}
		if !images.ValidPinned(image.repository, identity) {
			return "", fmt.Errorf("invalid resolved image for %s", image.repository)
		}
		if image.repository == "python" {
			// A virtual environment copied from the uv stage needs the same Python minor.
			match := regexp.MustCompile(`^python:([0-9]+\.[0-9]+)`).FindStringSubmatch(identity)
			if match == nil {
				return "", fmt.Errorf("Python image must name a major and minor version")
			}
			pythonMinor = match[1]
		}
		if image.repository == "ghcr.io/astral-sh/uv" && pythonMinor != "" && !strings.Contains(strings.SplitN(identity, "@", 2)[0], "-python"+pythonMinor+"-") {
			return "", fmt.Errorf("uv image must use Python %s to match runtime image", pythonMinor)
		}
		body = strings.ReplaceAll(body, image.placeholder, identity)
	}
	return body, nil
}
