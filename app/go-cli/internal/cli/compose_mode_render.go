package cli

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

// The compose strategy renders a project `docker compose` runs as an existing
// account of the host. Nothing privileged reads it, so nothing here is a
// promise made to a helper: it is the file that will run, and the invariants
// the swarm renderer enforces through the helper are enforced here by the
// renderer itself — every service hardened, every image accounted for, no
// variable left for the host to interpolate against an environment nobody
// controls.

// composeAppLabel scopes the images this strategy builds. It is what the
// remote prune filters on, so an image somebody else loaded on the same
// daemon is never Shuttle's to delete.
const composeAppLabel = "dev.shuttle.app"

// composeSecretsEnvFile and composeSecretsDir are where the materialised
// secrets live inside a release directory, relative to the compose file, which
// is how Compose resolves env_file and file secrets.
const (
	composeSecretsEnvFile = "secrets.env"
	composeSecretsDir     = "secrets"
)

// composeSecretsPlan says which declared secret reaches which service, and how.
type composeSecretsPlan struct {
	// Env maps a service to the keys it receives as environment variables.
	Env map[string][]string
	// File maps a service to the keys it receives under /run/secrets/<KEY>.
	File map[string][]string
	// Keys is every declared key, sorted, which is what the host script reads.
	Keys []string
}

// planComposeSecrets reads secrets.items into the shape the renderer and the
// host script share. Sorted everywhere: the same configuration must render the
// same project.
func planComposeSecrets(cfg *config.Config) composeSecretsPlan {
	plan := composeSecretsPlan{Env: map[string][]string{}, File: map[string][]string{}}
	for key := range cfg.Secrets.Items {
		plan.Keys = append(plan.Keys, key)
	}
	sort.Strings(plan.Keys)
	for _, key := range plan.Keys {
		item := cfg.Secrets.Items[key]
		for _, service := range item.Services {
			if item.ExposeMode() == "env" {
				plan.Env[service] = append(plan.Env[service], key)
			} else {
				plan.File[service] = append(plan.File[service], key)
			}
		}
	}
	for _, keys := range plan.Env {
		sort.Strings(keys)
	}
	for _, keys := range plan.File {
		sort.Strings(keys)
	}
	return plan
}

// generateComposeProject renders the compose file the host will run.
//
// images maps each built service to the immutable tag it was built as; every
// other service keeps the image it declares, which must be pinned by digest.
// The result carries no `${`: every variable was expanded here, from the
// operator's environment after loadDotenv, and every literal dollar sign is
// escaped so the host's Compose cannot re-interpolate a value — a password
// containing `$` would otherwise change between the desk and the container.
func generateComposeProject(cf *composeFile, cfg *config.Config, images map[string]string, secrets composeSecretsPlan) (string, error) {
	root, _ := deepCopyAny(cf.Raw).(map[string]any)
	if len(root) == 0 {
		data, _ := yaml.Marshal(cf)
		_ = yaml.Unmarshal(data, &root)
	}
	if root == nil {
		root = map[string]any{"services": map[string]any{}}
	}
	// `-p` names the project; a top-level name would compete with it.
	delete(root, "name")
	for key := range root {
		if strings.HasPrefix(key, "x-") {
			delete(root, key)
		}
	}
	services, _ := root["services"].(map[string]any)
	if len(services) == 0 {
		return "", errors.New("compose project has no services")
	}
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		service, ok := services[name].(map[string]any)
		if !ok {
			return "", fmt.Errorf("service %s is invalid", name)
		}
		built := false
		if image, ok := images[name]; ok {
			delete(service, "build")
			service["image"] = image
			built = true
		} else if _, hasBuild := service["build"]; hasBuild {
			return "", fmt.Errorf("service %s declares a build but no image was planned for it", name)
		}
		// Local env files do not exist on the host: inline them, with the
		// compose environment winning as Compose itself would have it.
		envFiles := normalizeEnvFiles(service["env_file"])
		delete(service, "env_file")
		if len(envFiles) > 0 {
			merged, err := environmentFromEnvFiles(service["environment"], envFiles)
			if err != nil {
				return "", fmt.Errorf("service %s: %w", name, err)
			}
			service["environment"] = merged
		}
		// A secret delivered as an environment variable must not be shadowed
		// by a compose `environment` entry of the same name — typically the
		// `KEY=${KEY}` line that carried it under docker compose today, which
		// would now inline as empty and win over the env file.
		if keys := secrets.Env[name]; len(keys) > 0 {
			service["environment"] = withoutEnvironmentKeys(service["environment"], keys)
			service["env_file"] = []any{composeSecretsEnvFile}
		}
		if keys := secrets.File[name]; len(keys) > 0 {
			references, _ := service["secrets"].([]any)
			for _, key := range keys {
				references = append(references, map[string]any{"source": key, "target": key})
				ensureNamedObject(root, "secrets", key, map[string]any{"file": "./" + composeSecretsDir + "/" + key})
			}
			service["secrets"] = references
		}
		if err := hardenService(name, service, !built); err != nil {
			return "", err
		}
		// Survives a reboot of a host nobody watches, which on-failure with a
		// bounded count does not; a crash loop is visible in `shuttle status`
		// and costs a restart delay, not an outage nobody is told about.
		service["restart"] = "unless-stopped"
		limits := cfg.ServiceLimits(name)
		// Only resources under deploy: Compose ignores update_config,
		// rollback_config and labels there, and an ignored key in the file the
		// operator reads is a promise the file does not keep.
		service["deploy"] = map[string]any{
			"resources": map[string]any{
				"limits":       map[string]any{"cpus": limits.CPUs, "memory": limits.Memory},
				"reservations": map[string]any{"memory": config.ServiceMemoryReservation},
			},
		}
	}
	// An overlay network only exists on a Swarm node; a compose file written
	// for the swarm strategy declares one, and `docker compose up` on a plain
	// daemon fails to create it. The driver is dropped so Compose creates its
	// default bridge network under the same name: service discovery by name
	// works the same, and the containers stay on one network per project.
	if networks, ok := root["networks"].(map[string]any); ok {
		for _, raw := range networks {
			network, ok := raw.(map[string]any)
			if !ok || network["driver"] != "overlay" {
				continue
			}
			delete(network, "driver")
		}
	}
	// `volumes: {uploads:}` and friends parse as nil entries; they are kept as
	// empty mappings so the section still declares them once re-encoded.
	for _, section := range []string{"volumes", "networks", "secrets"} {
		entries, ok := root[section].(map[string]any)
		if !ok {
			continue
		}
		for name, value := range entries {
			if value == nil {
				entries[name] = map[string]any{}
			}
		}
	}
	expanded, err := expandComposeScalars(root)
	if err != nil {
		return "", err
	}
	encoded, err := yaml.Marshal(expanded)
	if err != nil {
		return "", err
	}
	return "# Generated by shuttle (compose strategy)\n" + string(encoded), nil
}

// withoutEnvironmentKeys drops the named keys from a compose environment in
// either of its two spellings, leaving the rest untouched.
func withoutEnvironmentKeys(environment any, keys []string) any {
	drop := make(map[string]bool, len(keys))
	for _, key := range keys {
		drop[key] = true
	}
	switch typed := environment.(type) {
	case map[string]any:
		for key := range typed {
			if drop[key] {
				delete(typed, key)
			}
		}
		if len(typed) == 0 {
			return nil
		}
		return typed
	case []any:
		kept := make([]any, 0, len(typed))
		for _, entry := range typed {
			text, ok := entry.(string)
			if ok {
				key, _, _ := strings.Cut(text, "=")
				if drop[strings.TrimSpace(key)] {
					continue
				}
			}
			kept = append(kept, entry)
		}
		if len(kept) == 0 {
			return nil
		}
		return kept
	default:
		return environment
	}
}

// expandComposeScalars walks every string of the document and resolves it
// with expandComposeValue. Maps, lists and scalars keep their shape.
func expandComposeScalars(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			expanded, err := expandComposeScalars(item)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			typed[key] = expanded
		}
		return typed, nil
	case []any:
		for index, item := range typed {
			expanded, err := expandComposeScalars(item)
			if err != nil {
				return nil, err
			}
			typed[index] = expanded
		}
		return typed, nil
	case string:
		return expandComposeValue(typed)
	default:
		return value, nil
	}
}

// expandComposeValue resolves Compose interpolation locally and returns the
// value in the form the host must receive: every dollar sign doubled, so the
// host's Compose reads it as a literal.
//
// `$$` is a literal dollar. `${VAR}`, `${VAR:-default}`, `${VAR-default}` and
// `$VAR` read the environment loaded from the operator's .env. `${VAR:?msg}`
// with an unset or empty variable is an error naming the variable — the
// swarm path resolved it to an empty string, which is the silence the
// operator wrote the guard to prevent. Any other `$` is a literal.
func expandComposeValue(source string) (string, error) {
	if !strings.Contains(source, "$") {
		return source, nil
	}
	var out strings.Builder
	for i := 0; i < len(source); i++ {
		if source[i] != '$' {
			out.WriteByte(source[i])
			continue
		}
		if i+1 < len(source) && source[i+1] == '$' {
			out.WriteByte('$')
			i++
			continue
		}
		if i+1 < len(source) && source[i+1] == '{' {
			end := strings.IndexByte(source[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated ${ in %q", source)
			}
			expanded, err := expandComposeBraced(source[i+2 : i+end])
			if err != nil {
				return "", err
			}
			out.WriteString(expanded)
			i += end
			continue
		}
		name := composeVariableName(source[i+1:])
		if name == "" {
			out.WriteByte('$')
			continue
		}
		out.WriteString(os.Getenv(name))
		i += len(name)
	}
	return strings.ReplaceAll(out.String(), "$", "$$"), nil
}

func composeVariableName(rest string) string {
	end := 0
	for end < len(rest) {
		c := rest[end]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (end > 0 && c >= '0' && c <= '9') {
			end++
			continue
		}
		break
	}
	return rest[:end]
}

func expandComposeBraced(inner string) (string, error) {
	name := composeVariableName(inner)
	if name == "" {
		return "", fmt.Errorf("invalid variable reference ${%s}", inner)
	}
	rest := inner[len(name):]
	value, set := os.LookupEnv(name)
	switch {
	case rest == "":
		return value, nil
	case strings.HasPrefix(rest, ":-"):
		if value == "" {
			return rest[2:], nil
		}
		return value, nil
	case strings.HasPrefix(rest, "-"):
		if !set {
			return rest[1:], nil
		}
		return value, nil
	case strings.HasPrefix(rest, ":?"):
		if value == "" {
			return "", fmt.Errorf("variable %s is required and not set: %s", name, strings.TrimSpace(rest[2:]))
		}
		return value, nil
	case strings.HasPrefix(rest, "?"):
		if !set {
			return "", fmt.Errorf("variable %s is required and not set: %s", name, strings.TrimSpace(rest[1:]))
		}
		return value, nil
	default:
		return "", fmt.Errorf("unsupported variable reference ${%s}", inner)
	}
}

// composePrimaryPublishesPort reports whether the published service maps the
// host port the origin proof will dial. Without it the direct proof can only
// fail, after a build and a transfer, on a fact the compose file states.
func composePrimaryPublishesPort(cf *composeFile, primary string, port int) bool {
	service, ok := cf.Services[primary]
	if !ok {
		return false
	}
	for _, entry := range service.Ports {
		switch typed := entry.(type) {
		case string:
			if composePublishedHostPort(typed) == port {
				return true
			}
		case int:
			if typed == port {
				return true
			}
		case map[string]any:
			published := fmt.Sprint(typed["published"])
			if value, err := strconv.Atoi(published); err == nil && value == port {
				return true
			}
		}
	}
	return false
}

// composePublishedHostPort reads the host port out of a short-form ports entry:
// "80:80", "0.0.0.0:80:80", "80" (which publishes an ephemeral host port, so
// it is not the fixed port the proof needs), "80-81:80-81".
func composePublishedHostPort(entry string) int {
	entry, _, _ = strings.Cut(entry, "/")
	parts := strings.Split(entry, ":")
	if len(parts) < 2 {
		return 0
	}
	host := parts[len(parts)-2]
	if strings.Contains(host, "-") {
		host, _, _ = strings.Cut(host, "-")
	}
	value, err := strconv.Atoi(host)
	if err != nil {
		return 0
	}
	return value
}
