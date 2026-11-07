package cli

import (
	"strings"
	"testing"
)

// The shared edge is a Swarm stack, so caddy_network must be an overlay. The
// step used to be `inspect || create`, which silently accepted a bridge left by
// a previous generation of tooling: nothing was created, and every service that
// later tried to attach failed far from the cause.
func TestSetupRefusesANonOverlayEdgeNetwork(t *testing.T) {
	body := setupDockerCommand(setupModeFresh)
	for _, want := range []string{
		`edge_driver=$(docker network inspect caddy_network --format '{{.Driver}}')`,
		`if [ "$edge_driver" != overlay ]; then`,
		"docker network create --driver overlay --attachable caddy_network",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docker step must contain %q, got:\n%s", want, body)
		}
	}
	if strings.Contains(body, "docker network inspect caddy_network >/dev/null 2>&1 || docker network create") {
		t.Fatal("the unguarded inspect-or-create form must be gone")
	}
}
