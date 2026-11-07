package cli

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var digestImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
var namedVolume = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// validateRootStack is the policy for a stack entering the host. Everything the
// host already retains is judged by validateRetainedRootStack instead, so a
// policy added here can never block the rollback or the recovery of an
// application that is serving: the stack was signed and applied under the
// policy of its time, and it leaves with the next two releases.
func validateRootStack(payload []byte) error {
	if err := validateRetainedRootStack(payload); err != nil {
		return err
	}
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return errors.New("stack payload is not valid YAML")
	}
	services, _ := document["services"].(map[string]any)
	for _, name := range slices.Sorted(maps.Keys(services)) {
		if service, ok := services[name].(map[string]any); ok {
			if _, exists := service["env_file"]; exists {
				return fmt.Errorf("service %s uses forbidden field env_file", name)
			}
		}
	}
	return validateRootStackGlobalSections(document)
}

// validateRetainedRootStack holds the checks every deployable stack must pass,
// including one retained from an earlier release.
func validateRetainedRootStack(payload []byte) error {
	if len(payload) == 0 || len(payload) > maxRootPayload || bytes.Contains(payload, []byte("${")) {
		return errors.New("stack payload is empty, oversized, or contains unresolved variables")
	}
	var document map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&document); err != nil {
		return errors.New("stack payload is not valid YAML")
	}
	services, ok := document["services"].(map[string]any)
	if !ok || len(services) == 0 {
		return errors.New("stack payload has no services")
	}
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("service %s is invalid", name)
		}
		image, _ := service["image"].(string)
		if !digestImage.MatchString(image) {
			return fmt.Errorf("service %s image is not pinned by digest", name)
		}
		for _, forbidden := range []string{"privileged", "ports", "network_mode", "pid", "ipc", "devices", "cap_add", "configs"} {
			if _, exists := service[forbidden]; exists {
				return fmt.Errorf("service %s uses forbidden field %s", name, forbidden)
			}
		}
		if networks, exists := service["networks"]; exists && referencesHostNetwork(networks) {
			return fmt.Errorf("service %s uses the forbidden host network", name)
		}
		if readOnly, _ := service["read_only"].(bool); !readOnly {
			return fmt.Errorf("service %s must use read_only: true", name)
		}
		// Swarm ignores security_opt, so checking its YAML presence gave false
		// assurance. Doctor checks the running daemon's no-new-privileges default.
		caps, _ := service["cap_drop"].([]any)
		if !containsYAMLString(caps, "ALL") {
			return fmt.Errorf("service %s must drop all capabilities", name)
		}
		if healthcheck, ok := service["healthcheck"].(map[string]any); !ok || len(healthcheck) == 0 {
			return fmt.Errorf("service %s must define a healthcheck", name)
		}
		// The short `tmpfs:` key never reaches a Swarm service, so a stack that
		// still carries one is relying on writable paths it will not get.
		if _, exists := service["tmpfs"]; exists {
			return fmt.Errorf("service %s declares tmpfs, which docker stack deploy ignores; use a type: tmpfs volume", name)
		}
		if volumes, ok := service["volumes"].([]any); ok {
			for _, rawVolume := range volumes {
				// A tmpfs mount carries no host state, so it is checked on its
				// own terms: it must not shadow a system directory or grant
				// exec/suid, which would weaken read_only: true.
				if isTmpfsMount(rawVolume) {
					if err := validateRootTmpfsMount(name, rawVolume); err != nil {
						return err
					}
					continue
				}
				source, target, valid := rootVolumeSourceTarget(rawVolume)
				if !valid || !namedVolume.MatchString(source) || !strings.HasPrefix(target, "/") {
					return fmt.Errorf("service %s uses a non-named or invalid volume", name)
				}
				if target == "/var/run/docker.sock" || target == "/run/docker.sock" {
					return fmt.Errorf("service %s mounts the Docker socket", name)
				}
			}
		} else if _, exists := service["volumes"]; exists {
			return fmt.Errorf("service %s has an invalid volumes definition", name)
		}
		deploy, ok := service["deploy"].(map[string]any)
		if !ok {
			return fmt.Errorf("service %s must define deploy limits", name)
		}
		resources, _ := deploy["resources"].(map[string]any)
		limits, _ := resources["limits"].(map[string]any)
		cpu, hasCPU := limits["cpus"]
		memory, hasMemory := limits["memory"]
		if !hasCPU || !hasMemory || strings.TrimSpace(fmt.Sprint(cpu)) == "" || strings.TrimSpace(fmt.Sprint(memory)) == "" {
			return fmt.Errorf("service %s must define CPU and memory limits", name)
		}
	}
	if networks, ok := document["networks"].(map[string]any); ok {
		for key, raw := range networks {
			if strings.EqualFold(strings.TrimSpace(key), "host") || declaresHostNetwork(raw) {
				return errors.New("stack declares the forbidden host network")
			}
		}
	}
	return nil
}

// validateRootStackGlobalSections reads only what a compose file carries through
// the renderer unchanged, so the client runs it too, before any build: a refusal
// at the helper would come after the build, the push and the secrets.
func validateRootStackGlobalSections(document map[string]any) error {
	if err := validateRootStackVolumes(document); err != nil {
		return err
	}
	if err := validateRootStackSecrets(document); err != nil {
		return err
	}
	return validateRootStackNetworks(document)
}

// rootStackObjects returns a global section in name order, so that the same
// stack is always refused with the same message.
func rootStackObjects(document map[string]any, section string) ([]string, map[string]any, error) {
	raw, declared := document[section]
	if !declared || raw == nil {
		return nil, nil, nil
	}
	objects, ok := raw.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("stack %s section is invalid", section)
	}
	return slices.Sorted(maps.Keys(objects)), objects, nil
}

// validateRootStackSecrets keeps secrets on the typed operations. Those publish
// a value and the stack refers to it as external; a `file` secret would instead
// make root read a host path, without the checks of the secrets-host operation.
// Global configs are refused for the same reason: no service may mount one, so
// a declared config can only be a host file read for nothing.
func validateRootStackSecrets(document map[string]any) error {
	if configs, _, err := rootStackObjects(document, "configs"); err != nil {
		return err
	} else if len(configs) > 0 {
		return fmt.Errorf("stack declares config %s, whose file source root would read", configs[0])
	}
	names, secrets, err := rootStackObjects(document, "secrets")
	if err != nil {
		return err
	}
	for _, name := range names {
		secret, ok := secrets[name].(map[string]any)
		if !ok {
			return fmt.Errorf("secret %s has an invalid definition", name)
		}
		for _, key := range slices.Sorted(maps.Keys(secret)) {
			if key != "external" && key != "name" && key != "labels" {
				return fmt.Errorf("secret %s sets %s, only an external secret is allowed", name, key)
			}
		}
		switch external := secret["external"].(type) {
		case bool:
			if !external {
				return fmt.Errorf("secret %s is not external", name)
			}
		case map[string]any:
			// The deprecated `external: {name: x}` form, see rootStackSecretMounts.
		default:
			return fmt.Errorf("secret %s is not external", name)
		}
	}
	return nil
}

// validateRootStackNetworks keeps a stack on the two drivers a compose file
// normally names. macvlan, ipvlan or a plugin attach a service to a host
// interface, which is the host network by another name.
func validateRootStackNetworks(document map[string]any) error {
	names, networks, err := rootStackObjects(document, "networks")
	if err != nil {
		return err
	}
	for _, name := range names {
		if networks[name] == nil {
			continue
		}
		network, ok := networks[name].(map[string]any)
		if !ok {
			return fmt.Errorf("network %s has an invalid definition", name)
		}
		if driver, exists := network["driver"]; exists && driver != "overlay" && driver != "bridge" {
			return fmt.Errorf("network %s uses a driver other than overlay or bridge", name)
		}
	}
	return nil
}

// validateRootStackVolumes closes the path around the service mount check: the
// service only names a volume, and the local driver's options decide what that
// name mounts. `type: none, o: bind, device: /etc` is a bind mount that the
// service-level check cannot see, and `docker stack deploy` runs as root. A
// volume driver is host code for the same reason, so only `local` is allowed.
func validateRootStackVolumes(document map[string]any) error {
	names, volumes, err := rootStackObjects(document, "volumes")
	if err != nil {
		return err
	}
	for _, name := range names {
		if volumes[name] == nil {
			continue
		}
		volume, ok := volumes[name].(map[string]any)
		if !ok {
			return fmt.Errorf("volume %s has an invalid definition", name)
		}
		if _, exists := volume["driver_opts"]; exists {
			return fmt.Errorf("volume %s sets driver_opts, which can mount a host path", name)
		}
		if driver, exists := volume["driver"]; exists && driver != "local" {
			return fmt.Errorf("volume %s uses a driver other than local", name)
		}
	}
	return nil
}

func referencesHostNetwork(raw any) bool {
	switch networks := raw.(type) {
	case []any:
		for _, network := range networks {
			if strings.EqualFold(strings.TrimSpace(fmt.Sprint(network)), "host") {
				return true
			}
		}
	case map[string]any:
		for network := range networks {
			if strings.EqualFold(strings.TrimSpace(network), "host") {
				return true
			}
		}
	}
	return false
}

func declaresHostNetwork(raw any) bool {
	network, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(fmt.Sprint(network["name"])), "host") {
		return true
	}
	if external, ok := network["external"].(map[string]any); ok {
		return strings.EqualFold(strings.TrimSpace(fmt.Sprint(external["name"])), "host")
	}
	return false
}

func rootVolumeSourceTarget(raw any) (string, string, bool) {
	switch volume := raw.(type) {
	case string:
		source, remainder, ok := strings.Cut(volume, ":")
		if !ok {
			return "", "", false
		}
		target, _, _ := strings.Cut(remainder, ":")
		return source, target, true
	case map[string]any:
		kind := strings.TrimSpace(fmt.Sprint(volume["type"]))
		if kind != "" && kind != "volume" {
			return "", "", false
		}
		source := strings.TrimSpace(fmt.Sprint(volume["source"]))
		target := strings.TrimSpace(fmt.Sprint(volume["target"]))
		return source, target, source != "" && target != ""
	default:
		return "", "", false
	}
}

func containsYAMLString(values []any, expected string) bool {
	for _, value := range values {
		if candidate, ok := value.(string); ok && strings.EqualFold(candidate, expected) {
			return true
		}
	}
	return false
}

// isTmpfsMount reports whether a compose volume entry is a tmpfs mount.
func isTmpfsMount(raw any) bool {
	mount, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	return strings.TrimSpace(fmt.Sprint(mount["type"])) == "tmpfs"
}

// validateRootTmpfsMount rejects any writable mount that would weaken
// read_only: true. The signed helper is the authority here: it re-checks what
// the client built, so a hand-crafted stack cannot mount an exec/suid
// filesystem or shadow a directory whose contents the image needs.
func validateRootTmpfsMount(name string, raw any) error {
	mount, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("service %s has an invalid tmpfs mount", name)
	}
	target := strings.TrimSpace(fmt.Sprint(mount["target"]))
	if !rootTmpfsPath.MatchString(target) || strings.Contains(target, "..") {
		return fmt.Errorf("service %s uses an invalid tmpfs target: %s", name, target)
	}
	switch target {
	case "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/var", "/var/run", "/run", "/proc", "/sys", "/dev":
		return fmt.Errorf("service %s shadows the system directory %s with tmpfs", name, target)
	}
	if source := strings.TrimSpace(fmt.Sprint(mount["source"])); source != "" && source != "<nil>" {
		return fmt.Errorf("service %s gives a tmpfs mount a source", name)
	}
	options, ok := mount["tmpfs"].(map[string]any)
	if !ok {
		return fmt.Errorf("service %s has a tmpfs mount without size limits", name)
	}
	size, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(options["size"])))
	if err != nil || size <= 0 || size > 512*1024*1024 {
		return fmt.Errorf("service %s has a tmpfs mount without a sane size limit", name)
	}
	return nil
}

var rootTmpfsPath = regexp.MustCompile(`^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)
