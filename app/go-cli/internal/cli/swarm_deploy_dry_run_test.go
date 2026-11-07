package cli

import (
	"regexp"
	"strings"
	"testing"
)

func TestDryRunServiceImagesAreDeterministicPinnedPlaceholders(t *testing.T) {
	tagged := "127.0.0.1:41234/demo-web:deadbeef"
	pinned := "docker.io/library/redis@sha256:" + strings.Repeat("b", 64)

	first := dryRunServiceImages(map[string]string{"web": tagged, "redis": pinned})
	second := dryRunServiceImages(map[string]string{"web": tagged, "redis": pinned})

	if first["web"] != second["web"] {
		t.Fatalf("placeholder digest must be deterministic: %q != %q", first["web"], second["web"])
	}
	if !regexp.MustCompile(`^127\.0\.0\.1:41234/demo-web@sha256:[a-f0-9]{64}$`).MatchString(first["web"]) {
		t.Fatalf("planned tag was not converted to a pinned reference: %q", first["web"])
	}
	if first["redis"] != pinned {
		t.Fatalf("an already pinned image must remain unchanged: %q", first["redis"])
	}
}

func TestDryRunStackRedactsEnvironmentValues(t *testing.T) {
	stack := `services:
  map-form:
    environment:
      API_TOKEN: top-secret-map
      PORT: "8080"
  list-form:
    environment:
      - DATABASE_URL=top-secret-list
      - INHERITED_SECRET
  empty: {}
`

	redacted, err := redactDryRunStack(stack)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"top-secret-map", "top-secret-list", `PORT: "8080"`} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("dry-run leaked %q:\n%s", secret, redacted)
		}
	}
	for _, visible := range []string{"API_TOKEN:", "DATABASE_URL=<redacted>", "INHERITED_SECRET=<redacted>"} {
		if !strings.Contains(redacted, visible) {
			t.Fatalf("dry-run lost environment key %q:\n%s", visible, redacted)
		}
	}
}

func TestDryRunBuildArgsRedactExpandedValues(t *testing.T) {
	args := []string{"buildx", "build", "--build-arg", "PUBLIC_HOST=example.com", "--build-arg", "TOKEN=top-secret", "."}
	redacted := strings.Join(redactDryRunBuildArgs(args), " ")
	if strings.Contains(redacted, "example.com") || strings.Contains(redacted, "top-secret") {
		t.Fatalf("dry-run leaked build arguments: %s", redacted)
	}
	if !strings.Contains(redacted, "PUBLIC_HOST=<redacted>") || !strings.Contains(redacted, "TOKEN=<redacted>") {
		t.Fatalf("dry-run lost build argument names: %s", redacted)
	}
}
