//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

var rootStackObjectRead infrastructureDockerRead = rootDockerRead

// A signed volume declaration says nothing about an existing Docker volume's
// driver. Inspect the object that Docker will mount before any stack mutation.
func validateRootStackObjects(ctx context.Context, app string, payload []byte, read infrastructureDockerRead) error {
	var doc map[string]any
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return fmt.Errorf("read stack objects: %w", err)
	}
	for _, section := range []string{"volumes", "secrets"} {
		keys, objects, err := rootStackObjects(doc, section)
		if err != nil {
			return err
		}
		kind := strings.TrimSuffix(section, "s")
		for _, key := range keys {
			definition, _ := objects[key].(map[string]any)
			external, _ := definition["external"].(bool)
			name := ""
			if value, ok := definition["name"].(string); ok {
				name = value
			}
			if old, ok := definition["external"].(map[string]any); ok {
				external = true
				if name == "" {
					name, _ = old["name"].(string)
				}
			}
			if name == "" {
				if external {
					name = key
				} else {
					name = app + "_" + key
				}
			}
			if !namedVolume.MatchString(name) {
				return fmt.Errorf("%s %q has an invalid object name", kind, name)
			}
			shared := false
			if kind == "volume" && !strings.HasPrefix(name, app+"_") {
				// The running shared edge is authoritative for an adopted certificate
				// volume; its name is not necessarily one Shuttle generated.
				shared = name == "shuttle-edge_shuttle_caddy_data" || name == "shuttle-edge_shuttle_caddy_config"
				if !shared {
					edge, err := read(ctx, "service", "inspect", "--format", "{{json .Spec.TaskTemplate.ContainerSpec.Mounts}}", "shuttle-edge_caddy")
					var mounts []struct {
						Type   string
						Source string
						Target string
					}
					if err != nil || json.Unmarshal([]byte(edge), &mounts) != nil {
						return fmt.Errorf("volume %s is outside application namespace", name)
					}
					for _, mount := range mounts {
						if mount.Type == "volume" && mount.Source == name && (mount.Target == "/data" || mount.Target == "/config") {
							shared = true
						}
					}
					if !shared {
						return fmt.Errorf("volume %s is outside application namespace", name)
					}
				}
			}
			out, err := read(ctx, kind, "inspect", "--format", "{{json .}}", name)
			if err != nil {
				if dockerObjectAbsent(kind, name, err.Error()) && (!external || kind == "secret" && applicationSecretInNamespace(app, name)) {
					continue
				}
				return fmt.Errorf("inspect %s %s: %w", kind, name, err)
			}
			if kind == "volume" {
				var volume struct {
					Driver  string
					Options map[string]string
					Labels  map[string]string
				}
				if err := json.Unmarshal([]byte(out), &volume); err != nil {
					return fmt.Errorf("inspect volume %s: invalid response", name)
				}
				if volume.Driver != "local" || len(volume.Options) != 0 {
					return fmt.Errorf("volume %s has an unsafe driver or options", name)
				}
				if owner := volume.Labels[shuttleOwnerLabel]; owner != "" && owner != app && !shared {
					return fmt.Errorf("volume %s belongs to another application", name)
				}
				if owner := volume.Labels["com.docker.stack.namespace"]; owner != "" && owner != app && !shared {
					return fmt.Errorf("volume %s belongs to another application", name)
				}
			} else {
				var secret struct {
					Spec struct{ Labels map[string]string }
				}
				if err := json.Unmarshal([]byte(out), &secret); err != nil {
					return fmt.Errorf("inspect secret %s: invalid response", name)
				}
				owner := secret.Spec.Labels[shuttleOwnerLabel]
				if owner != app && (owner != "" || !applicationSecretInNamespace(app, name)) {
					return fmt.Errorf("secret %s is not owned by application %s", name, app)
				}
			}
		}
	}
	return nil
}
