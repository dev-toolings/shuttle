package cli

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Shuttle converts a compose file's `tmpfs:` into the long-form Swarm mount
// that `docker stack deploy` actually honours. That conversion reads the key
// off the parsed service — so if parsing drops it, the whole mechanism is
// unreachable from a user's compose file and every read-only container is
// silently reduced to /tmp. It then crash-loops on the first write anywhere
// else, with the compose file plainly saying it asked for that path.
func TestComposeTmpfsSurvivesParsing(t *testing.T) {
	source := []byte(`services:
  api:
    image: demo/api
    tmpfs:
      - /run/app-secrets
      - /var/cache/app
`)
	var file composeFile
	if err := yaml.Unmarshal(source, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	round, err := yaml.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, path := range []string{"/run/app-secrets", "/var/cache/app"} {
		if !strings.Contains(string(round), path) {
			t.Errorf("%s was dropped by the round trip; the tmpfs conversion would never see it:\n%s", path, round)
		}
	}
}

// And once it survives, the conversion produces the mount alongside the
// mandatory /tmp.
func TestDeclaredTmpfsBecomesAMount(t *testing.T) {
	mounts, err := serviceTmpfs([]any{"/run/app-secrets"})
	if err != nil {
		t.Fatalf("serviceTmpfs: %v", err)
	}
	targets := map[string]bool{}
	for _, mount := range mounts {
		entry, _ := mount.(map[string]any)
		targets[strings.TrimSpace(entry["target"].(string))] = true
	}
	if !targets["/run/app-secrets"] {
		t.Errorf("the declared path is missing from %v", targets)
	}
	if !targets[mandatoryTmpfsPath] {
		t.Errorf("%s must always be mounted, got %v", mandatoryTmpfsPath, targets)
	}
}
