package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"gopkg.in/yaml.v3"
)

const (
	redisImage  = "redis:8-alpine"
	rabbitImage = "rabbitmq:4-alpine"
)

// infrastructureRuntime describes a service Shuttle generates itself, rather
// than one a compose file declares.
//
// The uid and gid appear in three places that have to agree: the user the
// container runs as, the owner the root helper gives the data volume, and the
// owner of the mounted password. They come from this one table because a
// disagreement between any two of them is silent until the container starts.
//
// Running as a real uid is not a preference here. Every service is generated
// with cap_drop: ALL, so uid 0 has no CAP_DAC_OVERRIDE, and both images seed
// their data directory owned by their own account — redis:/data as 999:1000,
// rabbitmq:/var/lib/rabbitmq as 100:101. Left as root the container cannot
// write its own data directory and exits, which is a crash loop no
// configuration can escape.
//
// versionEnv names the variable the official image sets to its exact upstream
// version (REDIS_VERSION=7.4.11). The root helper reads it from the pulled image
// to accept a newer patch of a retained runtime: a tag is chosen by whoever
// writes the reference and proves nothing, the image configuration does.
// Redis 8 omits this variable, so versionBinary allows only its fixed server
// version probe. RabbitMQ keeps the metadata requirement until a binary probe
// is verified for its official image.
type infrastructureRuntime struct {
	service       string
	image         string
	target        string
	uid           int
	gid           int
	versionEnv    string
	versionBinary string
}

// user is the value written to the stack, and the value the helper re-checks.
func (r infrastructureRuntime) user() string { return fmt.Sprintf("%d:%d", r.uid, r.gid) }

var infrastructureRuntimes = []infrastructureRuntime{
	{service: "redis", image: redisImage, target: "/data", uid: 999, gid: 1000, versionEnv: "REDIS_VERSION", versionBinary: "redis-server"},
	{service: "rabbitmq", image: rabbitImage, target: "/var/lib/rabbitmq", uid: 100, gid: 101, versionEnv: "RABBITMQ_VERSION"},
}

func infrastructureRuntimeFor(service string) infrastructureRuntime {
	for _, runtime := range infrastructureRuntimes {
		if runtime.service == service {
			return runtime
		}
	}
	panic("unknown infrastructure service " + service)
}

// deploySwarmToHost applies the signed stack and returns the stack it applied,
// so the caller can verify that what runs afterwards is what was sent. The
// declared application secrets were resolved from the encrypted local store
// before the build: their values travel in their own signed operation, and only
// their derived names reach the stack. Under secrets.backend: host they are
// resolved here instead, by the helper, on the VPS — nothing travels at all and
// the stack still receives only names. An application that declares none
// produces the stack it always did.
func deploySwarmToHost(cfg *config.Config, group config.ServerGroup, host string, parsed *composeFile, images map[string]string, webPort string, manifest secretManifest, secretPayload []byte, operationID string, operation *remoteOperation, outcomeOut ...*promotionOutcome) (string, error) {
	client, err := connectSSH(group, host)
	if err != nil {
		return "", err
	}
	// The helper now genuinely waits for the release to be running before it
	// returns, so this one SSH session has to outlive the waits the signed plan
	// authorises it to perform. The transport deadline is a flat two minutes,
	// which was dormant only because the convergence check used to return in
	// milliseconds; at deploy.promotion_slo_seconds above roughly 150 it would
	// now cut the session while the helper is still working, report a failed
	// promotion for a deploy that succeeded, and leave the helper holding the
	// application's executor lock for the retry to queue behind.
	client.SetOperationTimeout(rootHelperOperationTimeout(cfg.Deploy.PromotionSLOSeconds))
	// The signing identity is loaded before the stack is generated, not after,
	// because the host backend cannot name the secret objects its stack mounts
	// until the helper has told it which version of each value the VPS holds —
	// and asking the helper anything requires a signed plan.
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return "", err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return "", err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return "", err
	}
	// Published before the stack that mounts them: a service referencing an
	// external secret that does not exist yet never converges.
	if cfg.UsesHashvaultSecrets() && manifest.Hashvault == nil {
		if operation != nil {
			operation.secretsPhaseAttempted = true
		}
		manifest, err = prepareHashvaultSecrets(cfg, client, identity, privateKey, operationID)
		if err != nil {
			return "", err
		}
	} else if cfg.UsesHostSecrets() {
		if operation != nil {
			operation.secretsPhaseAttempted = true
		}
		manifest, err = publishHostApplicationSecrets(cfg, client, identity, privateKey, operationID)
		if err != nil {
			return "", err
		}
	} else if len(secretPayload) > 0 {
		if operation != nil {
			operation.secretsPhaseAttempted = true
		}
		if err := pushApplicationSecrets(cfg.App, client, identity, privateKey, secretPayload, operationID); err != nil {
			return "", err
		}
	}
	stackConfig := *cfg
	stackConfig.Secrets.Items = applicationSecretItems(cfg)
	if manifest.Hashvault != nil {
		stackConfig.Secrets.Items = hashvaultSecretItems(manifest.Hashvault)
	}
	stack, err := generateSwarmStackWithSecrets(parsed, &stackConfig, images, manifest)
	if err != nil {
		return "", err
	}
	stack, err = secureStack(stack, cfg, webPort)
	if err != nil {
		return "", err
	}
	// The promotion budget travels with the plan so the root helper sizes its
	// own waits (stack convergence, shared-edge reload) from the same figure the
	// client measures against, instead of from constants that could exceed it.
	// retention.registry_cache travels the same way: only the helper can measure
	// the registry volume, and only a signed figure may authorise it to delete
	// registry content to get back under that cap.
	plan, err := rootplan.NewStackAction("stack-apply", cfg.App, rootplan.PayloadDigest([]byte(stack)), cfg.Deploy.PromotionSLOSeconds, cfg.Retention.RegistryCacheBytes(), identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 5*time.Minute, cfg.ResolvedInfrastructure["registry"])
	if err == nil {
		plan, err = bindOperationPlan(plan, operationID, "deploy", cfg.App)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return "", err
	}
	envelope, err := encodeRootHelperEnvelope(plan, []byte(stack))
	if err != nil {
		return "", err
	}
	// Marked here, right before the signed plan leaves the client, and not
	// earlier: a failure while loading the identity, rendering, validating or
	// signing the stack never reached the helper and must still end through
	// operation-refuse rather than recovery_required (DEV-DEPL-42).
	if operation != nil {
		operation.promotionAttempted = true
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		return "", stackPromotionError(result.Stderr)
	}
	if len(outcomeOut) > 0 && outcomeOut[0] != nil {
		*outcomeOut[0] = promotionOutcomeFromPromoteResponse(result.Stdout)
	}
	reportRootHelperWarnings(result.Stderr)
	return stack, nil
}

// stackPromoteResponse is what the helper prints on stdout after a successful
// stack-apply. It is printed on every success: before DEV-DEPL-83 only a first
// release printed anything, and a missing body meant "not a first release".
type stackPromoteResponse struct {
	FirstRelease bool `json:"first_release"`
	// Mode is the promotion mode the helper chose before it deployed, "legacy"
	// or "capped". A helper that predates the field does not send it.
	Mode string `json:"mode,omitempty"`
}

// promotionOutcome is what the client keeps of the helper's response: the two
// facts the rest of the promotion depends on.
type promotionOutcome struct {
	FirstRelease bool
	Mode         config.PromotionMode
}

// promotionOutcomeFromPromoteResponse parses the helper's response. A body that
// is not JSON, and a body without a mode, give the legacy mode: the client then
// spends the budget exactly as it did before the helper reported one.
func promotionOutcomeFromPromoteResponse(body string) promotionOutcome {
	var response stackPromoteResponse
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &response) != nil {
		return promotionOutcome{Mode: config.PromotionModeLegacy}
	}
	return promotionOutcome{FirstRelease: response.FirstRelease, Mode: config.ParsePromotionMode(response.Mode)}
}

func firstReleaseFromPromoteResponse(body string) bool {
	return promotionOutcomeFromPromoteResponse(body).FirstRelease
}

func secureStack(body string, cfg *config.Config, webPort string) (string, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(body), &root); err != nil {
		return "", err
	}
	services, _ := root["services"].(map[string]any)
	if len(services) == 0 {
		return "", errors.New("generated stack has no services")
	}
	if cfg.Production.Redis {
		services["redis"] = infrastructureRedisService(cfg.App, redisImageForConfig(cfg))
		ensureNamedObject(root, "volumes", cfg.App+"_redis_data", map[string]any{"name": cfg.App + "_redis_data"})
		ensureNamedObject(root, "secrets", cfg.App+"_redis_password_v1", map[string]any{"external": true})
	}
	if cfg.Production.RabbitMQ {
		image := cfg.Production.RabbitMQImage
		if image == "" {
			image = rabbitImage
		}
		services["rabbitmq"] = infrastructureRabbitServiceWithImage(cfg.App, image)
		ensureNamedObject(root, "volumes", cfg.App+"_rabbitmq_data", map[string]any{"name": cfg.App + "_rabbitmq_data"})
		ensureNamedObject(root, "secrets", cfg.App+"_rabbitmq_password_v1", map[string]any{"external": true})
	}
	managed, err := managedCredentialMounts(cfg)
	if err != nil {
		return "", err
	}
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("service %s is invalid", name)
		}
		for _, reference := range managed[name] {
			service["secrets"] = appendComposeSecret(service["secrets"], reference)
			ensureNamedObject(root, "secrets", fmt.Sprint(reference["source"]), map[string]any{"external": true})
		}
		delete(service, "build")
		delete(service, "ports")
		delete(service, "depends_on")
		// `docker stack deploy` ignores env_file, so dropping it silently left a
		// service without the configuration its compose file declares and only
		// failed later, inside the container. Materialize it into environment
		// instead, per service: a service that opts out with `env_file: []`
		// keeps receiving nothing, and an explicit environment entry still wins
		// over the file, which is Compose's own precedence.
		envFiles := normalizeEnvFiles(service["env_file"])
		delete(service, "env_file")
		if len(envFiles) > 0 {
			merged, err := environmentFromEnvFiles(service["environment"], envFiles)
			if err != nil {
				return "", fmt.Errorf("service %s: %w", name, err)
			}
			service["environment"] = merged
		}
		if err := hardenService(name, service, true); err != nil {
			return "", err
		}
		deploy, _ := service["deploy"].(map[string]any)
		if deploy == nil {
			deploy = map[string]any{}
			service["deploy"] = deploy
		}
		if name == cfg.PrimaryServiceName() {
			// Reached for an internal application too: it publishes no route,
			// but it still needs migrations and maintenance commands.

			// One replica, on purpose. Shuttle targets a single node, so a second
			// replica adds no failure domain: both tasks die with the host. Zero
			// downtime already comes from update_config below, where start-first
			// brings the new task up and waits for it to be healthy before the old
			// one is stopped. With parallelism: 1 a second replica only means a
			// second health-gated cold start, paid sequentially after the first —
			// pure promotion latency, which is what made a PHP stack blow past the
			// convergence deadline.
			deploy["replicas"] = 1
			labels, _ := deploy["labels"].(map[string]any)
			if labels == nil {
				labels = map[string]any{}
			}
			// No domain label on an internal stack: the root helper derives the
			// Caddy route from that label alone, so withholding it is what makes
			// "no route" a property of the signed stack rather than a promise
			// made by the CLI.
			if !cfg.IsInternal() {
				labels["dev.shuttle.domain"] = domainString(cfg.Domain)
				labels["dev.shuttle.port"] = webPort
				// Only non-default routing travels: a configuration that says
				// nothing must produce the stack it always produced. The mode is
				// read through the same helper the origin proof reads it with, so
				// the rendered route and the proof of that route cannot disagree
				// about what this application serves.
				if cfg.EffectiveTLSMode() == config.TLSModeOff {
					labels["dev.shuttle.tls"] = config.TLSModeOff
				}
				if cidrs := cfg.TrustedCIDRs(); len(cidrs) > 0 {
					labels["dev.shuttle.allow_cidrs"] = strings.Join(cidrs, ",")
				}
				// Order is significant — Caddy matches in order — so the list
				// travels as written, not as a map that Go would reorder.
				if len(cfg.Caddy.PathRoutes) > 0 {
					encoded, err := json.Marshal(cfg.Caddy.PathRoutes)
					if err != nil {
						return "", err
					}
					labels["dev.shuttle.path_routes"] = string(encoded)
				}
				// Extra hostnames travel on the published service too: the
				// helper derives every site of the application from that one
				// service's labels, so a host it cannot see is a host it will
				// not serve. Order is kept as written, like the path routes.
				if len(cfg.Caddy.HostRoutes) > 0 {
					encoded, err := json.Marshal(cfg.Caddy.HostRoutes)
					if err != nil {
						return "", err
					}
					labels["dev.shuttle.host_routes"] = string(encoded)
				}
				// The gate travels with the route it protects. Bcrypt hashes,
				// never a clear password: they are what Caddy's basic_auth
				// reads, and a label is not a secret store.
				if len(cfg.Caddy.BasicAuth.Users) > 0 {
					encoded, err := json.Marshal(cfg.Caddy.BasicAuth.Users)
					if err != nil {
						return "", err
					}
					labels["dev.shuttle.basic_auth"] = string(encoded)
				}
				if len(cfg.Caddy.BasicAuth.PublicPaths) > 0 {
					encoded, err := json.Marshal(cfg.Caddy.BasicAuth.PublicPaths)
					if err != nil {
						return "", err
					}
					labels["dev.shuttle.basic_auth_public_paths"] = string(encoded)
				}
				if cfg.Caddy.DomainBasicAuth != nil {
					labels["dev.shuttle.domain_basic_auth"] = strconv.FormatBool(*cfg.Caddy.DomainBasicAuth)
				}
				// A map, so json.Marshal sorts the keys for us: the same
				// configuration must produce the same label on every run, or
				// the edge reloads for a change nobody made.
				if len(cfg.Caddy.Headers) > 0 {
					encoded, err := json.Marshal(cfg.Caddy.Headers)
					if err != nil {
						return "", err
					}
					labels["dev.shuttle.headers"] = string(encoded)
				}
			}
			if cfg.Database.Managed() {
				labels[managedPostgresLabel] = "true"
				secret := cfg.App + "_postgres_password_v1"
				// The published service keeps the mount it always had, unless
				// the operator named the services that need the database. Then
				// what they wrote is what is mounted — including this service,
				// if they listed it.
				if _, declared := cfg.Secrets.Items["POSTGRES_PASSWORD"]; !declared {
					service["secrets"] = appendSecretReference(service["secrets"], secret, "POSTGRES_PASSWORD")
				}
				ensureNamedObject(root, "secrets", secret, map[string]any{"external": true})
				// Declared roles and databases travel on the same service, in the
				// order they were written. Without them the label is absent and the
				// stack is what it always was: the helper provisions the single
				// role and database derived from the application name.
				declared := managedDatabasePlanFromConfig(cfg.Database)
				if !declared.empty() {
					encoded, err := encodeManagedDatabasePlan(declared)
					if err != nil {
						return "", err
					}
					labels[managedDatabaseLabel] = encoded
					for _, role := range declared.Roles {
						// The application's own role is the one already mounted
						// above; a second secret for it would be a second password
						// for the same login.
						if role.Name == config.DerivedDatabaseIdentifier(cfg.App) {
							continue
						}
						roleSecret, err := checkedManagedRoleSecretName(cfg.App, role.Name)
						if err != nil {
							return "", err
						}
						if _, named := cfg.Secrets.Items[managedRoleSecretTarget(role.Name)]; !named {
							service["secrets"] = appendSecretReference(service["secrets"], roleSecret, managedRoleSecretTarget(role.Name))
						}
						ensureNamedObject(root, "secrets", roleSecret, map[string]any{"external": true})
					}
				}
			}
			// Declared maintenance commands ride on the published service's
			// labels, so the command the helper executes is part of the stack
			// that was signed and applied. `shuttle run` then names an
			// operation; it never sends a command line.
			if len(cfg.Operations) > 0 {
				encoded, err := json.Marshal(cfg.Operations)
				if err != nil {
					return "", err
				}
				labels["dev.shuttle.operations"] = string(encoded)
			}
			// An internal stack with no managed database has nothing to declare;
			// emitting an empty map would only add noise to the signed payload.
			if len(labels) > 0 {
				deploy["labels"] = labels
			}
		}
		// start-first everywhere, except where a service says it cannot survive
		// it: a task holding an exclusive lock on a mounted volume never yields
		// it to its own replacement. See config.Service.UpdateOrder.
		order := cfg.UpdateOrder(name)
		// The monitor (deploy.update_monitor_seconds, 5 s unless the project says
		// otherwise) is how long Swarm watches a replacement task before it calls
		// the update done; it used to be a fixed 10 s on every promotion. The
		// width of the rollout is per service and defaults to the one-at-a-time
		// 1; the rollback keeps 1 whatever the update uses, since it is the path
		// taken when something is already wrong.
		deploy["update_config"] = map[string]any{
			"parallelism":    cfg.UpdateParallelism(name),
			"order":          order,
			"failure_action": "rollback",
			"monitor":        strconv.Itoa(cfg.EffectiveUpdateMonitorSeconds()) + "s",
		}
		deploy["rollback_config"] = map[string]any{"parallelism": 1, "order": order}
		deploy["restart_policy"] = swarmRestartPolicy(deploy)
		limits := cfg.ServiceLimits(name)
		deploy["resources"] = map[string]any{
			"limits":       map[string]any{"cpus": limits.CPUs, "memory": limits.Memory},
			"reservations": map[string]any{"memory": config.ServiceMemoryReservation},
		}
	}
	encoded, err := yaml.Marshal(root)
	return string(encoded), err
}

func swarmRestartPolicy(deploy map[string]any) map[string]any {
	// A clean host shutdown sends SIGTERM, which application tasks can exit with
	// status 0; bounded on-failure retries can also strand them when native
	// dependencies are not ready during boot. Match compose mode's reboot
	// behavior (compose_mode_render.go:150). Swarm jobs still stop on success.
	condition := "any"
	delay := "5s"
	maxAttempts := 0
	if mode, _ := deploy["mode"].(string); mode == "replicated-job" || mode == "global-job" {
		condition = "on-failure"
		delay = "1s"
		maxAttempts = 3
	}
	return map[string]any{"condition": condition, "delay": delay, "max_attempts": maxAttempts}
}

func redisImageForConfig(cfg *config.Config) string {
	if cfg != nil {
		if image := cfg.ResolvedInfrastructure["redis"]; image != "" {
			return image
		}
		if image := strings.TrimSpace(cfg.Production.RedisImage); image != "" {
			return image
		}
	}
	return redisImage
}

// hardenService applies the per-service hardening every strategy imposes:
// a healthcheck, a read-only root filesystem, every capability dropped,
// tmpfs mounts (always /tmp) and capped json-file logging. security_opt enforces
// no-new-privileges only with Compose; Swarm relies on the daemon default.
//
// It is one function on purpose. The Swarm stack and the compose project are
// rendered by different code, and the invariant that hardening applies to
// every service in every stack (invariants, rule 7) is only an invariant if
// both renderers cannot drift apart on it. requireDigest is the one thing
// they legitimately disagree on: a Swarm stack references every image by the
// digest the registry resolved, while the compose strategy references the
// images it built by an immutable tag whose identity it proves separately —
// its non-built images are still pinned.
func hardenService(name string, service map[string]any, requireDigest bool) error {
	image, _ := service["image"].(string)
	if requireDigest && !strings.Contains(image, "@sha256:") {
		return fmt.Errorf("service %s must use an image pinned by digest", name)
	}
	if _, ok := service["healthcheck"]; !ok {
		return fmt.Errorf("service %s must define a healthcheck", name)
	}
	service["read_only"] = true
	service["cap_drop"] = []any{"ALL"}
	// Keep this for Compose. docker stack deploy ignores it; it is not proof
	// of effective Swarm protection (DEV-DEPL-76).
	service["security_opt"] = []any{"no-new-privileges:true"}
	writable, err := serviceTmpfs(service["tmpfs"])
	if err != nil {
		return fmt.Errorf("service %s: %w", name, err)
	}
	delete(service, "tmpfs")
	service["volumes"] = append(existingVolumes(service["volumes"]), writable...)
	service["logging"] = map[string]any{"driver": "json-file", "options": map[string]any{"max-size": "10m", "max-file": "3"}}
	return nil
}

func appendSecretReference(current any, source, target string) []any {
	values, _ := current.([]any)
	return append(values, map[string]any{"source": source, "target": target, "mode": 0o400})
}

func ensureNamedObject(root map[string]any, section, name string, value any) {
	objects, _ := root[section].(map[string]any)
	if objects == nil {
		objects = map[string]any{}
		root[section] = objects
	}
	objects[name] = value
}

func domainString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []string:
		if len(typed) > 0 {
			return strings.TrimSpace(typed[0])
		}
	case []any:
		if len(typed) > 0 {
			return strings.TrimSpace(fmt.Sprint(typed[0]))
		}
	}
	return ""
}

// infrastructureSecretReference mounts a password the generated service can
// actually read. A Swarm secret defaults to root ownership, so a 0400 file is
// unreadable by the unprivileged account these services run as — the command
// below would `cat` nothing and the container would come up without a password.
func infrastructureSecretReference(runtime infrastructureRuntime, source, target string) []any {
	return []any{map[string]any{
		"source": source,
		"target": target,
		"uid":    strconv.Itoa(runtime.uid),
		"gid":    strconv.Itoa(runtime.gid),
		"mode":   0o400,
	}}
}

// managedCredentialObject names the Docker Secret holding the credential of a
// service Shuttle provisions itself, and reports whether that service is on.
func managedCredentialObject(cfg *config.Config, key string) (string, bool) {
	switch key {
	case "REDIS_PASSWORD":
		return cfg.App + "_redis_password_v1", cfg.Production.Redis
	case "RABBITMQ_PASSWORD":
		return cfg.App + "_rabbitmq_password_v1", cfg.Production.RabbitMQ
	case "POSTGRES_PASSWORD":
		return cfg.App + "_postgres_password_v1", cfg.Database.Managed()
	}
	// A per-role database password. The role's own services need it exactly as
	// much as the application's do, and it travelled to the published service
	// alone — so a second application in the same stack, on its own role, had
	// the address of a database it had no password for.
	if role, ok := managedRoleFromCredentialKey(cfg, key); ok {
		name, err := checkedManagedRoleSecretName(cfg.App, role)
		if err != nil {
			return "", false
		}
		return name, cfg.Database.Managed()
	}
	return "", false
}

// managedRoleFromCredentialKey recovers the declared role a POSTGRES_PASSWORD_*
// key names. Matched against the declared roles rather than parsed loosely: a
// key naming a role that does not exist must not silently become an application
// secret Shuttle then looks for in the local store.
func managedRoleFromCredentialKey(cfg *config.Config, key string) (string, bool) {
	for _, role := range cfg.Database.Roles {
		if key == managedRoleSecretTarget(role.Name) {
			return role.Name, true
		}
	}
	return "", false
}

// managedCredentialMounts maps each application service to the credentials it
// declared it needs.
//
// Shuttle provisions Redis, RabbitMQ and PostgreSQL and generates their
// passwords on the host, then had no way to hand any of them to the application.
// Redis was published as password-authenticated and the password reached the
// Redis container and nothing else, so an application could not connect to the
// service Shuttle ran for it. The database password did travel, but only to the
// published service, which on a stack whose web tier talks to an API is the one
// service that never opens a connection.
//
// The generated infrastructure services are skipped: they mount their own
// credential, owned by the account they run as.
func managedCredentialMounts(cfg *config.Config) (map[string][]map[string]any, error) {
	mounts := map[string][]map[string]any{}
	keys := make([]string, 0, len(cfg.Secrets.Items))
	for key := range cfg.Secrets.Items {
		keys = append(keys, key)
	}
	// Sorted: a service receiving two credentials must receive them in the same
	// order on every run, or the stack changes without the configuration doing so.
	sort.Strings(keys)
	for _, key := range keys {
		object, enabled := managedCredentialObject(cfg, key)
		if object == "" {
			continue
		}
		item := cfg.Secrets.Items[key]
		if !enabled {
			return nil, fmt.Errorf("secret %s is declared but the service it belongs to is not enabled", key)
		}
		for _, service := range item.Services {
			if service == "redis" || service == "rabbitmq" {
				continue
			}
			reference := map[string]any{"source": object, "target": key, "mode": 0o400}
			if uid, gid, declared := item.Owner(); declared {
				reference["uid"] = strconv.Itoa(uid)
				reference["gid"] = strconv.Itoa(gid)
			}
			mounts[service] = append(mounts[service], reference)
		}
	}
	return mounts, nil
}

func infrastructureRedisService(app, image string) map[string]any {
	runtime := infrastructureRuntimeFor("redis")
	runtime.image = image
	secret := app + "_redis_password_v1"
	return map[string]any{
		"image": runtime.image,
		// The image's entrypoint chowns its data directory and drops to the
		// redis account, but only when its first argument is `redis-server`.
		// Reading the password from a file needs a shell, so that branch is
		// never taken and the user has to be declared here instead.
		"user":        runtime.user(),
		"command":     []any{"/bin/sh", "-ec", "exec redis-server --appendonly yes --requirepass \"$$(cat /run/secrets/REDIS_PASSWORD)\""},
		"healthcheck": map[string]any{"test": []any{"CMD-SHELL", "redis-cli -a \"$$(cat /run/secrets/REDIS_PASSWORD)\" ping | grep -Fx PONG"}, "interval": "2s", "timeout": "1s", "retries": 10},
		"volumes":     []any{app + "_redis_data:" + runtime.target},
		"secrets":     infrastructureSecretReference(runtime, secret, "REDIS_PASSWORD"),
	}
}

func infrastructureRabbitService(app string) map[string]any {
	return infrastructureRabbitServiceWithImage(app, rabbitImage)
}

func infrastructureRabbitServiceWithImage(app, image string) map[string]any {
	runtime := infrastructureRuntimeFor("rabbitmq")
	password := app + "_rabbitmq_password_v1"
	return map[string]any{
		"image":       image,
		"user":        runtime.user(),
		"command":     []any{"/bin/sh", "-ec", rabbitEntrypointScript("/run/secrets/RABBITMQ_PASSWORD", "/etc/rabbitmq/conf.d", "/tmp/shuttle-rabbitmq-conf.d")},
		"healthcheck": map[string]any{"test": []any{"CMD", "rabbitmq-diagnostics", "-q", "ping"}, "interval": "3s", "timeout": "2s", "retries": 10},
		"volumes":     []any{app + "_rabbitmq_data:" + runtime.target},
		"secrets":     infrastructureSecretReference(runtime, password, "RABBITMQ_PASSWORD"),
	}
}

// rabbitEntrypointScript reads the mounted password without putting it in the
// stack, process arguments or environment. The official image rejects its
// deprecated RABBITMQ_DEFAULT_*_FILE variables, so keep the image's conf.d
// defaults, remove the guest loopback setting, write the credentials on /tmp,
// and let RabbitMQ load them as configuration. The secret is generated as
// base64url without a newline; refuse other bytes because this value is written
// unquoted into a Cuttlefish config file. Dollar signs are doubled for Swarm's
// stack interpolation and restored by Docker before the shell runs.
// The script must never contain "${": the root helper refuses any stack
// payload holding it as an unresolved variable (validateRootStack), which is
// how the first VM deploy of this script failed on 2026-10-27. Brace-free
// forms (basename, a byte count through wc) keep it acceptable.
func rabbitEntrypointScript(secretPath, defaultConfDir, generatedConfDir string) string {
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
	}
	script := fmt.Sprintf(`set -eu
umask 077
secret_file=%s
default_conf_dir=%s
generated_conf_dir=%s
export LC_ALL=C

if [ ! -f "$secret_file" ] || [ ! -r "$secret_file" ]; then
  printf 'missing or unreadable secret: RABBITMQ_PASSWORD\n' >&2
  exit 1
fi

password=
if IFS= read -r password < "$secret_file"; then
  printf 'invalid secret: RABBITMQ_PASSWORD must not contain a newline\n' >&2
  exit 1
fi
if [ -z "$password" ]; then
  printf 'invalid secret: RABBITMQ_PASSWORD is empty\n' >&2
  exit 1
fi
if ! secret_bytes=$(wc -c < "$secret_file") || ! password_bytes=$(printf %%s "$password" | wc -c); then
  printf 'could not validate secret: RABBITMQ_PASSWORD\n' >&2
  exit 1
fi
if [ "$secret_bytes" -ne "$password_bytes" ]; then
  printf 'invalid secret: RABBITMQ_PASSWORD contains unsupported bytes\n' >&2
  exit 1
fi
case "$password" in
  *[!A-Za-z0-9_-]*)
    printf 'invalid secret: RABBITMQ_PASSWORD contains unsupported characters\n' >&2
    exit 1
    ;;
esac

mkdir -p "$generated_conf_dir"
for source_file in "$default_conf_dir"/*.conf; do
  [ -f "$source_file" ] || continue
  file_name=$(basename "$source_file")
  sed '/^[[:space:]]*loopback_users[.]guest[[:space:]]*=/d' "$source_file" > "$generated_conf_dir/$file_name"
done
printf 'default_user = shuttle\n' > "$generated_conf_dir/90-shuttle-credentials.conf"
printf 'default_pass = %%s\n' "$password" >> "$generated_conf_dir/90-shuttle-credentials.conf"
export RABBITMQ_CONFIG_FILES="$generated_conf_dir"
exec docker-entrypoint.sh rabbitmq-server
`, quote(secretPath), quote(defaultConfDir), quote(generatedConfDir))
	return strings.ReplaceAll(script, "$", "$$")
}

// mandatoryTmpfsPath is writable on every service. read_only: true is not
// negotiable, so anything a container must write needs an explicit tmpfs.
const mandatoryTmpfsPath = "/tmp"

// tmpfsBytes is the default size of a writable mount. Explicit Compose sizes
// are preserved within the signed helper's existing 512 MiB ceiling.
const tmpfsBytes = 64 * 1024 * 1024
const maxTmpfsBytes = 512 * 1024 * 1024

// tmpfsPathPattern keeps a declared mount to an absolute, traversal-free path.
var tmpfsPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

// serviceTmpfs turns the tmpfs paths a compose file declares into long-form
// Swarm mounts, always including /tmp.
//
// The short `tmpfs:` key exists in Compose but `docker stack deploy` drops it
// silently, so a service that relies on it starts with nothing writable and
// crash-loops under read_only: true. Only the long `type: tmpfs` volume form
// survives into a Swarm service spec.
//
// These mounts are what makes read_only: true usable: a FrankenPHP image cannot
// boot without writing its Caddy PKI to /data, and Symfony and Laravel need
// their var/ and storage/ trees.
func serviceTmpfs(declared any) ([]any, error) {
	paths := []string{mandatoryTmpfsPath}
	seen := map[string]bool{mandatoryTmpfsPath: true}
	sizes := map[string]int{mandatoryTmpfsPath: tmpfsBytes}
	explicit := map[string]bool{}
	if declared != nil {
		entries, ok := declared.([]any)
		if !ok {
			return nil, errors.New("tmpfs must be a list")
		}
		for _, entry := range entries {
			text, ok := entry.(string)
			if !ok {
				return nil, errors.New("tmpfs entries must be strings")
			}
			// Swarm legacy Compose accepts the bounded size but drops mode and
			// other tmpfs options. Writable mountpoints must be prepared in the
			// image; generated PHP images use sticky, world-writable cache dirs.
			path, options, _ := strings.Cut(strings.TrimSpace(text), ":")
			if !tmpfsPathPattern.MatchString(path) || strings.Contains(path, "..") {
				return nil, fmt.Errorf("tmpfs path is not an absolute, traversal-free path: %q", text)
			}
			switch path {
			case "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/var", "/var/run", "/run", "/proc", "/sys", "/dev":
				return nil, fmt.Errorf("tmpfs must not shadow the system directory %q", path)
			}
			size, declaredSize, err := declaredTmpfsSize(options)
			if err != nil {
				return nil, fmt.Errorf("tmpfs %s: %w", path, err)
			}
			if _, exists := sizes[path]; !exists {
				sizes[path] = tmpfsBytes
			}
			if declaredSize {
				if explicit[path] && sizes[path] != size {
					return nil, fmt.Errorf("tmpfs %s has conflicting sizes", path)
				}
				sizes[path] = size
				explicit[path] = true
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			paths = append(paths, path)
		}
	}
	mounts := make([]any, 0, len(paths))
	for _, path := range paths {
		mounts = append(mounts, map[string]any{
			"type":   "tmpfs",
			"target": path,
			"tmpfs":  map[string]any{"size": sizes[path]},
		})
	}
	return mounts, nil
}

// declaredTmpfsSize preserves Compose's byte or binary-unit size declaration.
// A small /tmp can fill with Chromium's shared-memory files without a cgroup
// OOM, leaving CDP calls stalled. Silently forcing it back to 64 MiB makes
// every deployment reintroduce that failure despite a larger declared size.
func declaredTmpfsSize(options string) (int, bool, error) {
	size, declared := tmpfsBytes, false
	for _, option := range strings.Split(options, ",") {
		name, value, hasValue := strings.Cut(strings.TrimSpace(option), "=")
		if name != "size" {
			continue
		}
		if !hasValue {
			return 0, false, errors.New("size requires a value")
		}
		bytes, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			bytes, err = config.ParseByteSize(value)
		}
		if err != nil || bytes <= 0 || bytes > maxTmpfsBytes {
			return 0, false, fmt.Errorf("size must be between 1 byte and 512 MiB: %q", value)
		}
		if declared && size != int(bytes) {
			return 0, false, errors.New("conflicting size options")
		}
		size, declared = int(bytes), true
	}
	return size, declared, nil
}

// existingVolumes returns the named volumes already declared, so adding the
// writable mounts never drops them.
func existingVolumes(declared any) []any {
	volumes, ok := declared.([]any)
	if !ok {
		return nil
	}
	return volumes
}

// environmentFromEnvFiles merges env_file contents under an existing
// environment mapping. Values already declared in the compose environment take
// precedence, matching Compose's own resolution order.
func environmentFromEnvFiles(existing any, files []string) (map[string]any, error) {
	merged := map[string]any{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read env_file %s: %w", file, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
			merged[key] = value
		}
	}
	switch typed := existing.(type) {
	case map[string]any:
		for key, value := range typed {
			merged[key] = value
		}
	case []any:
		for _, entry := range typed {
			text, ok := entry.(string)
			if !ok {
				continue
			}
			key, value, ok := strings.Cut(text, "=")
			if !ok {
				continue
			}
			merged[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return merged, nil
}
