package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/images"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

type infraResolver interface {
	Resolve(ctx context.Context, repo, tag string) (digest string, err error)
}

type dockerHubInfraResolver struct{ client *http.Client }

var infraDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func newDockerHubInfraResolver() infraResolver {
	return dockerHubInfraResolver{client: &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (r dockerHubInfraResolver) Resolve(ctx context.Context, repo, tag string) (string, error) {
	if !officialInfrastructureRepository(repo) || tag == "" || strings.ContainsAny(tag, "/@ \t\r\n") {
		return "", errors.New("invalid official infrastructure image")
	}
	return (images.Resolver{Client: r.client}).ResolveTag(ctx, repo, tag)
}

var infraResolverForRun infraResolver = newDockerHubInfraResolver()
var infraFallbackAttn sync.Once

func infrastructureDefaults(repo string) (major, suffix string) {
	switch repo {
	case "redis":
		return "8", "-alpine"
	case "rabbitmq":
		return "4", "-alpine"
	case "caddy":
		return "2", ""
	case "registry":
		return "3", ""
	default:
		return "", ""
	}
}

func infrastructureTag(repo, retained, override string) (string, error) {
	major, suffix := infrastructureDefaults(repo)
	if override != "" {
		if strings.Contains(override, "@sha256:") {
			// Legacy digest-only config entries from init are migrated by selecting
			// the default tag. A versioned tag in the reference remains explicit.
			base := strings.SplitN(override, "@", 2)[0]
			if strings.Contains(base, ":") {
				tag, err := officialTag(repo, base)
				if err != nil {
					return "", err
				}
				return tag, nil
			} else {
				override = ""
			}
		}
		if override != "" {
			tag, err := officialTag(repo, override)
			if err != nil {
				return "", err
			}
			return tag, nil
		}
	}
	if retained != "" {
		tag, err := officialTag(repo, retained)
		if err != nil {
			return "", fmt.Errorf("read retained %s image: %w", repo, err)
		}
		major = leadingMajor(tag)
		return major + suffix, nil
	}
	return major + suffix, nil
}

func officialTag(repo, reference string) (string, error) {
	if strings.Contains(reference, "@") {
		reference = strings.SplitN(reference, "@", 2)[0]
	}
	colon := strings.LastIndex(reference, ":")
	if colon < 0 || reference[:colon] != repo {
		return "", fmt.Errorf("image %q is not an official %s reference", reference, repo)
	}
	tag := reference[colon+1:]
	if tag == "" || strings.ContainsAny(tag, "/ \t\r\n") || leadingMajor(tag) == "" {
		return "", fmt.Errorf("image %q has no supported numeric major tag", reference)
	}
	return tag, nil
}

func leadingMajor(tag string) string {
	match := regexp.MustCompile(`^[0-9]+`).FindString(tag)
	return match
}

func resolveInfrastructureImage(ctx context.Context, resolver infraResolver, repo, retained, override string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tag, err := infrastructureTag(repo, retained, override)
	if err != nil {
		return "", err
	}
	if retained != "" {
		if old, oldErr := officialTag(repo, retained); oldErr == nil && leadingMajor(tag) != leadingMajor(old) {
			return "", fmt.Errorf("%s major change %s -> %s requires an explicit data migration", repo, leadingMajor(old), leadingMajor(tag))
		}
	}
	digest, err := resolver.Resolve(ctx, repo, tag)
	if err != nil {
		if validRetainedInfrastructureReference(repo, retained) {
			infraFallbackAttn.Do(func() {
				output.Attn("Docker Hub is unreachable; keeping infrastructure at the retained running digests")
			})
			return retained, nil
		}
		return "", fmt.Errorf("cannot resolve current stable image %s:%s: %w", repo, tag, err)
	}
	currentMajor, _ := strconv.Atoi(leadingMajor(tag))
	if currentMajor > 0 {
		nextTag := strconv.Itoa(currentMajor+1) + suffixForInfrastructure(repo)
		if newerDigest, lookupErr := resolver.Resolve(ctx, repo, nextTag); lookupErr == nil && infraDigestPattern.MatchString(newerDigest) {
			fmt.Printf("%s %d is available; Shuttle stays on %d until an explicit migration\n", repo, currentMajor+1, currentMajor)
		}
	}
	return resolvedInfrastructureReference(repo, tag, digest)
}

func validRetainedInfrastructureReference(repo, reference string) bool {
	if reference == "" {
		return false
	}
	tag, err := officialTag(repo, reference)
	if err != nil {
		return false
	}
	return infraDigestPattern.MatchString(strings.TrimPrefix(reference, repo+":"+tag+"@")) && strings.Contains(reference, "@sha256:")
}

func suffixForInfrastructure(repo string) string {
	_, suffix := infrastructureDefaults(repo)
	return suffix
}

func resolveConfiguredInfrastructure(ctx context.Context, cfg *config.Config, includeShared bool, retainedImages ...map[string]string) error {
	if cfg.ResolvedInfrastructure == nil {
		cfg.ResolvedInfrastructure = make(map[string]string)
	}
	selected := []struct{ repo, retained, override string }{}
	retained := map[string]string{}
	if len(retainedImages) > 0 {
		retained = retainedImages[0]
	}
	if cfg.Production.Redis {
		redisRetained := retained["redis"]
		if redisRetained == "" && strings.Contains(cfg.Production.RedisImage, "@sha256:") {
			redisRetained = cfg.Production.RedisImage
		}
		selected = append(selected, struct{ repo, retained, override string }{"redis", redisRetained, cfg.Production.RedisImage})
	}
	if cfg.Production.RabbitMQ {
		selected = append(selected, struct{ repo, retained, override string }{"rabbitmq", retained["rabbitmq"], cfg.Production.RabbitMQImage})
	}
	selected = append(selected, struct{ repo, retained, override string }{"registry", retained["registry"], ""})
	if includeShared {
		selected = append(selected, struct{ repo, retained, override string }{"caddy", retained["caddy"], cfg.Caddy.Image})
	}
	for _, image := range selected {
		// An explicit Redis or RabbitMQ override that already carries a digest
		// is an identity the user chose (for example a Redis 7.4 kept for its
		// data): it is used exactly, never moved by resolution. Tag-only
		// overrides are resolved like the defaults. Caddy's digest-only form is
		// the legacy `init` default and is handled as unset elsewhere.
		if strings.Contains(image.override, "@sha256:") && (image.repo == "redis" || image.repo == "rabbitmq" || strings.Contains(strings.SplitN(image.override, "@", 2)[0], ":")) {
			if !validRetainedInfrastructureReference(image.repo, image.override) {
				return fmt.Errorf("resolve %s infrastructure image: configured image %q is not an official %s reference with a valid digest", image.repo, image.override, image.repo)
			}
			cfg.ResolvedInfrastructure[image.repo] = image.override
			continue
		}
		resolved, err := resolveInfrastructureImage(ctx, infraResolverForRun, image.repo, image.retained, image.override)
		if err != nil {
			return fmt.Errorf("resolve %s infrastructure image: %w", image.repo, err)
		}
		cfg.ResolvedInfrastructure[image.repo] = resolved
	}
	if cfg.ResolvedInfrastructure["caddy"] != "" {
		cfg.Caddy.Image = cfg.ResolvedInfrastructure["caddy"]
	}
	if cfg.ResolvedInfrastructure["rabbitmq"] != "" {
		cfg.Production.RabbitMQImage = cfg.ResolvedInfrastructure["rabbitmq"]
	}
	return nil
}

func readRetainedInfrastructureImages(cfg *config.Config) (map[string]string, error) {
	body, err := runSignedStackAudit(cfg, "infra-images", "", 0)
	if err != nil {
		return nil, fmt.Errorf("read retained infrastructure images: %w", err)
	}
	return decodeRetainedInfrastructureImages(body)
}

// setupRetainedStateProbe runs over setup's own verified session (root on a
// fresh host, the administrator through sudo on --adopt), so it needs neither
// the root helper nor a local trusted identity: on 2026-10-28 the review found
// that requiring the signed audit here broke `setup --adopt --unmanaged` and
// legacy adoption, and that `docker stack ls` fails on a host whose Swarm is
// not active yet. It reports what runs, which is what resolution must keep:
// the major in use and no downgrade. Anything it cannot read stops setup.
const setupRetainedStateProbe = `set -eu
app="$1"
state=absent
if [ -e /var/lib/shuttle/apps ]; then
  manifest=$(find /var/lib/shuttle/apps -mindepth 2 -maxdepth 2 -type f -name current.yml -print -quit) || { echo "retained app manifests cannot be inspected" >&2; exit 1; }
  if [ -n "$manifest" ]; then state=present; fi
fi
if command -v docker >/dev/null 2>&1; then
  docker info >/dev/null 2>&1 || { echo "Docker is installed but its state cannot be inspected" >&2; exit 1; }
  # Listings, not inspect exit codes: a failed inspect cannot tell "absent"
  # from a daemon error, and absence must be proven, never assumed.
  containers=$(docker container ls -a --format '{{.Names}}') || { echo "Docker containers cannot be listed" >&2; exit 1; }
  if printf '%s\n' "$containers" | grep -Fx shuttle-registry >/dev/null; then
    state=present
    image=$(docker container inspect --format '{{.Config.Image}}' shuttle-registry) || { echo "the shuttle-registry container cannot be inspected" >&2; exit 1; }
    printf 'registry=%s\n' "$image"
  fi
  swarm=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}') || { echo "Docker Swarm state cannot be inspected" >&2; exit 1; }
  case "$swarm" in
    "inactive "*) ;;
    "active true")
      services=$(docker service ls --format '{{.Name}}') || { echo "Swarm services cannot be listed" >&2; exit 1; }
      for service in "${app}_redis:redis" "${app}_rabbitmq:rabbitmq" "shuttle-edge_caddy:caddy"; do
        name=${service%%:*}; key=${service##*:}
        if printf '%s\n' "$services" | grep -Fx "$name" >/dev/null; then
          state=present
          image=$(docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' "$name") || { echo "service $name cannot be inspected" >&2; exit 1; }
          printf '%s=%s\n' "$key" "$image"
        fi
      done ;;
    *) echo "Docker Swarm is in state '$swarm'; setup needs an inactive node or a reachable manager" >&2; exit 1 ;;
  esac
fi
printf 'state=%s\n' "$state"
`

var runSetupRetainedStateProbe = func(client *shuttlessh.Client, app string, sudo bool) shuttlessh.Result {
	command := "sh -s -- " + shell.Escape(app)
	if sudo {
		command = "sudo -n " + command
	}
	return client.RunWithStdin(command, []byte(setupRetainedStateProbe))
}

// retainedInfrastructureImagesFromProbe turns the probe output into the
// running references. Every reported reference must be an official image with
// a valid digest; otherwise setup stops rather than resolve around it.
func retainedInfrastructureImagesFromProbe(result shuttlessh.Result) (map[string]string, error) {
	if result.Code != 0 {
		return nil, fmt.Errorf("setup could not establish whether the host has retained Shuttle state: %s", strings.TrimSpace(result.Stderr))
	}
	images := map[string]string{}
	state := ""
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			return nil, errors.New("setup could not establish whether the host has retained Shuttle state: unexpected probe response")
		}
		switch key {
		case "state":
			state = value
		case "redis", "rabbitmq", "caddy", "registry":
			// Shuttle generations before v0.0.58 deployed the shared edge as
			// `caddy@sha256:<digest>`, the same digest-only form `init` wrote
			// into configs. On 2026-10-28 `setup --adopt` on production-host prod
			// refused that edge as unofficial. It is the official image by
			// digest; it only carries no major, so the default major (Caddy
			// 2, the only one) applies. Redis and RabbitMQ keep the refusal:
			// their running major is what protects their data.
			if key == "caddy" && legacyDigestOnlyCaddy(value) {
				continue
			}
			if !validRetainedInfrastructureReference(key, value) {
				return nil, fmt.Errorf("setup found %s running as %q, which is not an official image pinned by digest; fix or remove it before setup", key, value)
			}
			images[key] = value
		default:
			return nil, errors.New("setup could not establish whether the host has retained Shuttle state: unexpected probe response")
		}
	}
	if state != "absent" && state != "present" {
		return nil, errors.New("setup could not establish whether the host has retained Shuttle state: unexpected probe response")
	}
	return images, nil
}

func retainedInfrastructureImagesForSetup(cfg *config.Config, client *shuttlessh.Client, sudo bool) (map[string]string, error) {
	return retainedInfrastructureImagesFromProbe(runSetupRetainedStateProbe(client, cfg.App, sudo))
}

func decodeRetainedInfrastructureImages(body string) (map[string]string, error) {
	images := map[string]string{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &images); err != nil {
		return nil, fmt.Errorf("decode retained infrastructure images: %w", err)
	}
	for repo, image := range images {
		// Same legacy edge as in retainedInfrastructureImagesFromProbe: no
		// major to keep, so the default applies.
		if repo == "caddy" && legacyDigestOnlyCaddy(image) {
			delete(images, repo)
			continue
		}
		if !officialInfrastructureRepository(repo) || !validRetainedInfrastructureReference(repo, image) {
			return nil, fmt.Errorf("retained %s image is not an official digest reference", repo)
		}
	}
	return images, nil
}

func officialInfrastructureRepository(repo string) bool {
	switch repo {
	case "redis", "rabbitmq", "caddy", "registry":
		return true
	}
	return false
}

func resolvedInfrastructureReference(repo, tag, digest string) (string, error) {
	if !officialInfrastructureRepository(repo) || tag == "" || strings.ContainsAny(tag, "/@ \t\r\n") || !infraDigestPattern.MatchString(digest) {
		return "", errors.New("invalid resolved infrastructure image")
	}
	return repo + ":" + tag + "@" + digest, nil
}

func legacyDigestOnlyCaddy(reference string) bool {
	digest, ok := strings.CutPrefix(reference, "caddy@")
	return ok && infraDigestPattern.MatchString(digest)
}
