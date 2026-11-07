package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version int    `yaml:"version" json:"version"`
	App     string `yaml:"app" json:"app"`
	Domain  any    `yaml:"domain" json:"domain"`
	// Expose declares whether the application is reachable from the internet.
	// "public" (the default) publishes it on a domain through the shared edge.
	// "internal" deploys it with no domain, no route and no origin proof: the
	// stack is reachable only from the other services on the node. A background
	// worker or a private API otherwise had to invent a public hostname it did
	// not want, just to satisfy a deploy-time check.
	Expose         string                 `yaml:"expose,omitempty" json:"expose,omitempty"`
	Server         *ServerShorthand       `yaml:"server,omitempty" json:"server,omitempty"`
	Servers        map[string]ServerGroup `yaml:"servers,omitempty" json:"servers"`
	Build          Build                  `yaml:"build,omitempty" json:"build"`
	Deploy         Deploy                 `yaml:"deploy,omitempty" json:"deploy"`
	Services       map[string]Service     `yaml:"services,omitempty" json:"services,omitempty"`
	Accessories    map[string]Accessory   `yaml:"accessories,omitempty" json:"accessories,omitempty"`
	Secrets        Secrets                `yaml:"secrets,omitempty" json:"secrets"`
	Env            Env                    `yaml:"env,omitempty" json:"env,omitempty"`
	Proxy          Proxy                  `yaml:"proxy,omitempty" json:"proxy"`
	Registry       Registry               `yaml:"registry,omitempty" json:"registry"`
	Database       DatabaseConfig         `yaml:"database,omitempty" json:"database,omitempty"`
	Notifications  Notifications          `yaml:"notifications,omitempty" json:"notifications"`
	Caddy          Caddy                  `yaml:"caddy,omitempty" json:"caddy,omitempty"`
	Dev            Dev                    `yaml:"dev,omitempty" json:"dev,omitempty"`
	Provision      Provision              `yaml:"provision,omitempty" json:"provision,omitempty"`
	Setup          SetupConfig            `yaml:"setup,omitempty" json:"setup,omitempty"`
	Production     ProductionConfig       `yaml:"production,omitempty" json:"production,omitempty"`
	Retention      RetentionConfig        `yaml:"retention,omitempty" json:"retention,omitempty"`
	Readiness      ReadinessConfig        `yaml:"readiness,omitempty" json:"readiness,omitempty"`
	Monitoring     *MonitoringConfig      `yaml:"monitoring,omitempty" json:"monitoring,omitempty"`
	Infrastructure InfrastructureConfig   `yaml:"infrastructure,omitempty" json:"infrastructure,omitempty"`
	// Operations are the maintenance commands an operator declares once and can
	// then run against the deployment: a migration, a search reindex, a cache
	// warmup. They exist because `deploy` has no shell, no sudo and no Docker
	// socket on the host, and the shared services an application needs — a
	// search engine on an overlay network, for instance — are not reachable
	// from outside the node at all. Without a declared operation there is no
	// way to run a console command after `setup`, which is not a posture, just
	// a gap.
	//
	// The command is carried in the signed stack, so `shuttle run <name>` names
	// an operation and never a command line.
	Operations             map[string]Operation `yaml:"operations,omitempty" json:"operations,omitempty"`
	ResolvedInfrastructure map[string]string    `yaml:"-" json:"-"`
}

type SetupConfig struct {
	SLOSeconds int `yaml:"slo_seconds,omitempty" json:"slo_seconds,omitempty"`
	// SwapMode is "managed" (the default) on a VM/VPS and "host" when the
	// kernel boundary owns swap, as it does for an unprivileged LXC.
	SwapMode string `yaml:"swap_mode,omitempty" json:"swap_mode,omitempty"`
	// AppArmorMode is "managed" on a VM/VPS and "host" when an outer LXC
	// boundary owns profile loading. Utilities stay installed in both modes.
	AppArmorMode string `yaml:"apparmor_mode,omitempty" json:"apparmor_mode,omitempty"`
	// OperatorUser is the administrator configured by setup. It is required
	// for fresh setup and adoption without a retained administrator; ordinary
	// deploy commands do not require it. Its sudo rule is root-equivalent.
	OperatorUser string `yaml:"operator_user,omitempty" json:"operator_user,omitempty"`
	// OperatorPublicKey must name a public key distinct from deploy's key. The
	// path is resolved relative to config.json (or may use ~/).
	OperatorPublicKey string `yaml:"operator_public_key,omitempty" json:"operator_public_key,omitempty"`
	// RetainedUsers are accounts that already exist on the host and must still
	// be able to log in once setup has closed everything else. They are signed
	// into AllowUsers and nothing more: Shuttle creates none of them, installs
	// no key, writes no sudo rule and leaves their group memberships alone.
	//
	// The list exists because a VPS is rarely one person's. The signed baseline
	// used to name deploy and the declared operator and nobody else, so every
	// colleague with an account on a shared pre-production host lost SSH the
	// moment `setup` committed — silently, since nothing in the plan said so.
	RetainedUsers []string `yaml:"retained_users,omitempty" json:"retained_users,omitempty"`
}

// InfrastructureConfig describes an optional project-owned infrastructure
// lifecycle. Terraform owns the PVE resource; pvecli supplies API-backed
// inventory and the out-of-band SSH host-key proof used before first contact.
type InfrastructureConfig struct {
	Driver            string `yaml:"driver,omitempty" json:"driver,omitempty"`
	PVECLIConfig      string `yaml:"pvecli_config,omitempty" json:"pvecli_config,omitempty"`
	TerraformResource string `yaml:"terraform_resource,omitempty" json:"terraform_resource,omitempty"`
	GuestType         string `yaml:"guest_type,omitempty" json:"guest_type,omitempty"`
	GuestID           int    `yaml:"guest_id,omitempty" json:"guest_id,omitempty"`
	AnsiblePlaybook   string `yaml:"ansible_playbook,omitempty" json:"ansible_playbook,omitempty"`
	InventoryTag      string `yaml:"inventory_tag,omitempty" json:"inventory_tag,omitempty"`
	PublicKey         string `yaml:"public_key,omitempty" json:"public_key,omitempty"`
	AllowRecreate     bool   `yaml:"allow_recreate,omitempty" json:"allow_recreate,omitempty"`
}

type ProductionConfig struct {
	Redis         bool   `yaml:"redis,omitempty" json:"redis,omitempty"`
	RabbitMQ      bool   `yaml:"rabbitmq,omitempty" json:"rabbitmq,omitempty"`
	RedisImage    string `yaml:"redis_image,omitempty" json:"redis_image,omitempty"`
	RabbitMQImage string `yaml:"-" json:"-"`
}

type RetentionConfig struct {
	// RegistryCache caps the on-VPS registry volume, which exists only to hold
	// this host's build cache and the two release manifests `deploy.retain`
	// keeps. It is enforced after every promotion by the root helper: the
	// `mode=max` cache a Swarm build exports is rewritten on each deploy, so
	// without a cap the volume grows by one whole cache manifest per release
	// until `min_free_percent` refuses every further deploy.
	RegistryCache string `yaml:"registry_cache,omitempty" json:"registry_cache,omitempty"`
	// Backups is the number of newest host PostgreSQL archives to keep. Zero
	// means the historical default of seven, so existing configs keep working.
	Backups    int `yaml:"postgres_backups,omitempty" json:"postgres_backups,omitempty"`
	MinFreePct int `yaml:"min_free_percent,omitempty" json:"min_free_percent,omitempty"`
}

// RegistryCacheBytes is the parsed form of RegistryCache. Validation has already
// refused anything unparseable or out of range, so callers get a usable budget
// or zero, which every consumer reads as "no cap stated".
func (r RetentionConfig) RegistryCacheBytes() int64 {
	bytes, err := ParseByteSize(r.RegistryCache)
	if err != nil {
		return 0
	}
	return bytes
}

type ReadinessConfig struct {
	Preset          string   `yaml:"preset,omitempty" json:"preset,omitempty"`
	HealthcheckPath string   `yaml:"healthcheck_path,omitempty" json:"healthcheck_path,omitempty"`
	WorkerServices  []string `yaml:"worker_services,omitempty" json:"worker_services,omitempty"`
	Ignore          []string `yaml:"ignore,omitempty" json:"ignore,omitempty"`
}

// Provision holds non-secret host runtime settings. The selected provisioning
// profile remains the authority for whether each component is applied.
type Provision struct {
	ApplicationUsers []ApplicationUser `yaml:"application_users,omitempty" json:"application_users,omitempty"`
	PHPFPM           PHPFPM            `yaml:"php_fpm,omitempty" json:"php_fpm,omitempty"`
	NVM              NVM               `yaml:"nvm,omitempty" json:"nvm,omitempty"`
}

// ApplicationUser is a declarative, non-secret Unix account. Public SSH keys
// are permitted here; private keys and credentials are never configuration.
type ApplicationUser struct {
	Name           string   `yaml:"name" json:"name"`
	Home           string   `yaml:"home,omitempty" json:"home,omitempty"`
	Groups         []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	Shell          string   `yaml:"shell,omitempty" json:"shell,omitempty"`
	System         bool     `yaml:"system,omitempty" json:"system,omitempty"`
	AuthorizedKeys []string `yaml:"authorized_keys,omitempty" json:"authorized_keys,omitempty"`
	Docker         bool     `yaml:"docker,omitempty" json:"docker,omitempty"`
	Sudo           bool     `yaml:"sudo,omitempty" json:"sudo,omitempty"`
}

type PHPFPM struct {
	Version      string     `yaml:"version,omitempty" json:"version,omitempty"`
	PoolUser     string     `yaml:"pool_user,omitempty" json:"pool_user,omitempty"`
	PoolGroup    string     `yaml:"pool_group,omitempty" json:"pool_group,omitempty"`
	PM           string     `yaml:"pm,omitempty" json:"pm,omitempty"`
	MaxChildren  int        `yaml:"max_children,omitempty" json:"max_children,omitempty"`
	StartServers int        `yaml:"start_servers,omitempty" json:"start_servers,omitempty"`
	MinSpare     int        `yaml:"min_spare_servers,omitempty" json:"min_spare_servers,omitempty"`
	MaxSpare     int        `yaml:"max_spare_servers,omitempty" json:"max_spare_servers,omitempty"`
	MaxRequests  int        `yaml:"max_requests,omitempty" json:"max_requests,omitempty"`
	Opcache      PHPOpcache `yaml:"opcache,omitempty" json:"opcache,omitempty"`
}

type PHPOpcache struct {
	Enabled               *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MemoryConsumption     int   `yaml:"memory_consumption,omitempty" json:"memory_consumption,omitempty"`
	InternedStringsBuffer int   `yaml:"interned_strings_buffer,omitempty" json:"interned_strings_buffer,omitempty"`
	MaxAcceleratedFiles   int   `yaml:"max_accelerated_files,omitempty" json:"max_accelerated_files,omitempty"`
	ValidateTimestamps    *bool `yaml:"validate_timestamps,omitempty" json:"validate_timestamps,omitempty"`
	RevalidateFreq        int   `yaml:"revalidate_freq,omitempty" json:"revalidate_freq,omitempty"`
	SaveComments          *bool `yaml:"save_comments,omitempty" json:"save_comments,omitempty"`
	FastShutdown          *bool `yaml:"fast_shutdown,omitempty" json:"fast_shutdown,omitempty"`
}

type NVM struct {
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
	NodeVersion string `yaml:"node_version,omitempty" json:"node_version,omitempty"`
}

type ServerShorthand struct {
	Host string `yaml:"host" json:"host"`
	User string `yaml:"user" json:"user"`
	Port int    `yaml:"port,omitempty" json:"port,omitempty"`
	// HostKey is the VPS's ED25519 host key fingerprint, SHA256:…, obtained
	// out of band (provider console, or ssh-keyscan checked against it). It is
	// what deploy.strategy: compose pins the SSH connection to, since no
	// `setup` ever ran to record one; under swarm the record belongs to setup
	// and the key is refused here so the two cannot disagree.
	HostKey string `yaml:"host_key,omitempty" json:"host_key,omitempty"`
	VPN     VPN    `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	Access  Access `yaml:"access,omitempty" json:"access,omitempty"`
}

type ServerGroup struct {
	Hosts   []string `yaml:"hosts" json:"hosts"`
	User    string   `yaml:"user" json:"user"`
	Port    int      `yaml:"port,omitempty" json:"port,omitempty"`
	HostKey string   `yaml:"host_key,omitempty" json:"host_key,omitempty"`
	VPN     VPN      `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	Access  Access   `yaml:"access,omitempty" json:"access,omitempty"`
}

type VPN struct {
	Required  bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Interface string `yaml:"interface,omitempty" json:"interface,omitempty"`
	CheckHost string `yaml:"check_host,omitempty" json:"check_host,omitempty"`
	CheckPort int    `yaml:"check_port,omitempty" json:"check_port,omitempty"`
}

// Access declares the expected administrative exposure of a server. It is
// deliberately separate from VPN reachability: a deploy may use a VPN merely
// as a route, while private-tailscale is a security posture that also requires
// interface-scoped SSH and no unexpected public TCP allow rules.
type Access struct {
	Mode                  string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Interface             string   `yaml:"interface,omitempty" json:"interface,omitempty"`
	AllowedUsers          []string `yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`
	AllowedPublicTCPPorts []int    `yaml:"allowed_public_tcp_ports,omitempty" json:"allowed_public_tcp_ports,omitempty"`
	DockerAccess          *bool    `yaml:"docker_access,omitempty" json:"docker_access,omitempty"`
}

type Build struct {
	Dockerfile string                  `yaml:"dockerfile,omitempty" json:"dockerfile"`
	Context    string                  `yaml:"context,omitempty" json:"context"`
	Target     string                  `yaml:"target,omitempty" json:"target,omitempty"`
	Platform   string                  `yaml:"platform,omitempty" json:"platform,omitempty"`
	Args       map[string]string       `yaml:"args,omitempty" json:"args,omitempty"`
	Services   map[string]BuildService `yaml:"services,omitempty" json:"services,omitempty"`
	// Runner selects where BuildKit runs. An absent value keeps the historical
	// local builder path. The remaining fields are meaningful only for runner:
	// ssh and are deliberately flat so the JSON contract stays easy to inspect.
	Runner               string `yaml:"runner,omitempty" json:"runner,omitempty"`
	Host                 string `yaml:"host,omitempty" json:"host,omitempty"`
	User                 string `yaml:"user,omitempty" json:"user,omitempty"`
	Port                 int    `yaml:"port,omitempty" json:"port,omitempty"`
	HostKey              string `yaml:"host_key,omitempty" json:"host_key,omitempty"`
	IdentityFile         string `yaml:"identity_file,omitempty" json:"identity_file,omitempty"`
	RegistryIdentityFile string `yaml:"registry_identity_file,omitempty" json:"registry_identity_file,omitempty"`
}

// BuildService defines one immutable image and the compose services that use
// it. When build.services is absent, Shuttle keeps inferring build groups from
// docker-compose.yml for backwards compatibility.
type BuildService struct {
	Context    string            `yaml:"context,omitempty" json:"context,omitempty"`
	Dockerfile string            `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	Target     string            `yaml:"target,omitempty" json:"target,omitempty"`
	Platform   string            `yaml:"platform,omitempty" json:"platform,omitempty"`
	Args       map[string]string `yaml:"args,omitempty" json:"args,omitempty"`
	Services   []string          `yaml:"services" json:"services"`
}

type Deploy struct {
	Strategy string `yaml:"strategy,omitempty" json:"strategy"`
	Path     string `yaml:"path,omitempty" json:"path,omitempty"`
	Timeout  int    `yaml:"timeout,omitempty" json:"timeout"`
	// Retain is how many past versions stay on the deployment host: image tags
	// and their releases/<version>.yml snapshot. Every deploy publishes new
	// commit-qualified tags, so without a cap the host fills up one release at
	// a time. The live version and the one a rollback would restore are always
	// kept, whatever this is set to. Default 5.
	Retain       int       `yaml:"retain,omitempty" json:"retain"`
	AutoRollback *bool     `yaml:"auto_rollback,omitempty" json:"auto_rollback"`
	Hooks        Hooks     `yaml:"hooks,omitempty" json:"hooks"`
	BlueGreen    Blue      `yaml:"blue_green,omitempty" json:"blue_green"`
	Concurrency  int       `yaml:"concurrency,omitempty" json:"concurrency"`
	Swarm        Swarm     `yaml:"swarm,omitempty" json:"swarm"`
	EnvSchema    EnvSchema `yaml:"env_schema,omitempty" json:"env_schema,omitempty"`
	Raw          []string  `yaml:"-" json:"-"`
	ComposeFiles []string  `yaml:"compose_files,omitempty" json:"compose_files,omitempty"`
	// Profiles activates Compose-profiled services. Services without profiles are
	// always included; profiled services are excluded unless one of their
	// profiles is explicitly enabled here or through `shuttle deploy --profile`.
	Profiles []string `yaml:"profiles,omitempty" json:"profiles,omitempty"`
	EnvFile  string   `yaml:"env_file,omitempty" json:"env_file,omitempty"`
	// EnvPush controls what a deploy does to the .env already on the host:
	// "merge" (default) ships the local file but carries over keys that only
	// exist remotely, "never" leaves an existing remote .env untouched, and
	// "overwrite" replaces it. Use "never" when the host owns its configuration
	// (managed database endpoints, per-host URLs that also exist locally with a
	// dev value).
	EnvPush string `yaml:"env_push,omitempty" json:"env_push,omitempty"`
	// PruneBuildCache controls cleanup of the local Docker build cache after a
	// successful deploy: "off" (never), "capped" (cap total cache size, keeps
	// recent layers for fast rebuilds) or "all" (wipe everything). Default "off"
	// so one project never evicts another project's shared daemon cache implicitly.
	PruneBuildCache string `yaml:"prune_build_cache,omitempty" json:"prune_build_cache,omitempty"`
	// BuildCacheKeep is the max build-cache size kept when PruneBuildCache is
	// "capped" (e.g. "30GB", "512MB"). Default "30GB".
	BuildCacheKeep string `yaml:"build_cache_keep,omitempty" json:"build_cache_keep,omitempty"`
	// BuildCacheMode is the BuildKit mode of the registry cache a Swarm build
	// exports. "max" (the default, also when empty) also exports every intermediate stage, which is
	// what keeps a compiled dependency stage restorable after a local cache
	// eviction. "min" exports only the layers of the final image: right for a
	// Dockerfile whose intermediate stage is rebuilt on every commit anyway
	// (`COPY . .` then a framework build), where max mode compresses and
	// uploads hundreds of megabytes no later build can reuse.
	BuildCacheMode string `yaml:"build_cache_mode,omitempty" json:"build_cache_mode,omitempty"`
	// PruneLocalImages lets a deploy remove the exact tags it publishes even
	// when they already existed locally. Default false: a tag that predates the
	// run belongs to whoever built it (a Makefile target, a manual build), and
	// deleting it would be a surprise. Turn it on when the same registry tags
	// are produced by several tools and pile up in the local image store.
	PruneLocalImages bool `yaml:"prune_local_images,omitempty" json:"prune_local_images,omitempty"`
	// PromotionSLOSeconds is the maximum expected duration for promoting images
	// that have already been built and pushed to a healthy production stack.
	// It is reported separately from source-to-image build time.
	PromotionSLOSeconds int `yaml:"promotion_slo_seconds,omitempty" json:"promotion_slo_seconds,omitempty"`
	// promotionSLOSetByProject records that the project wrote
	// promotion_slo_seconds itself, before applyDefaults filled the preset's
	// figure in. Only that case is worth a warning about a budget too short for
	// the rollout: a project on the shipped default never chose it.
	promotionSLOSetByProject bool
	// UpdateMonitorSeconds is Swarm's update_config.monitor on every service:
	// how long a replaced task has to stay up before the update counts as
	// successful, and before failure_action: rollback stops being able to undo
	// it. Omitted or 0 means 5 s; otherwise 2 to 60.
	UpdateMonitorSeconds int `yaml:"update_monitor_seconds,omitempty" json:"update_monitor_seconds,omitempty"`
	// TotalSLOSeconds is the source-to-production command budget, including
	// builds, transfers, promotion, cache maintenance, and registry shutdown.
	TotalSLOSeconds int `yaml:"total_slo_seconds,omitempty" json:"total_slo_seconds,omitempty"`
	// AvailabilityURL enables an external HTTP probe during promotion. A 2xx is
	// healthy; a configured Basic Auth site may instead prove availability with
	// a 401 carrying a Basic challenge. Every other response or request error
	// makes the zero-downtime contract fail.
	AvailabilityURL        string `yaml:"availability_url,omitempty" json:"availability_url,omitempty"`
	AvailabilityIntervalMS int    `yaml:"availability_interval_ms,omitempty" json:"availability_interval_ms,omitempty"`
	// EdgeProxy declares that public DNS for the application domain points at a
	// CDN or WAF (Cloudflare orange cloud, Fastly, …) instead of the VPS. The
	// origin proof then dials the VPS by IP with the domain's SNI and Host, and
	// additionally requires the public edge to answer a cache-busted request.
	EdgeProxy bool `yaml:"edge_proxy,omitempty" json:"edge_proxy,omitempty"`
	// EdgeRanges optionally pins the CIDRs the edge is allowed to resolve to.
	// A domain that drifts to any other network then fails the origin proof
	// instead of passing on an unrelated 200.
	EdgeRanges     []string `yaml:"edge_ranges,omitempty" json:"edge_ranges,omitempty"`
	LocalArtifacts string   `yaml:"local_artifacts,omitempty" json:"local_artifacts,omitempty"`
	// PrimaryService names the Compose service Shuttle publishes: the one that
	// gets the Caddy route, the domain and port labels, and the managed
	// PostgreSQL password. It defaults to "web", which is what the generated
	// presets emit, but an existing application is not required to rename its
	// service to adopt Shuttle. A Symfony API whose service is called `api`
	// keeps that name in its own compose file, its logs and its Swarm service
	// DNS; only this key tells Shuttle which one to expose.
	PrimaryService string `yaml:"primary_service,omitempty" json:"primary_service,omitempty"`
	// Compose holds what only deploy.strategy: compose reads. A pointer, so a
	// configuration that never mentions it is marshalled exactly as before.
	Compose *ComposeDeploy `yaml:"compose,omitempty" json:"compose,omitempty"`
}

// ComposeDeploy configures the strategy that deploys with `docker compose` as
// an existing account of the host, with no setup and no root helper.
type ComposeDeploy struct {
	// Project is the Compose project name. It defaults to shuttle-<app>, which
	// keeps Shuttle's containers apart from a project somebody runs by hand
	// on the same host: `--remove-orphans` is scoped by project name, and a
	// name shared with a hand-run stack would make a deploy delete it.
	Project string `yaml:"project,omitempty" json:"project,omitempty"`
	// Build says where the images are built. "local" builds on this machine
	// with buildx and streams the archive to the host; "host" drives the
	// host's own daemon over SSH (DOCKER_HOST=ssh://) so the build runs
	// natively there and nothing travels. "auto", the default, is local when
	// the two share an architecture and host when they do not — an
	// Apple-silicon laptop cannot build a Bun front end for an x86 host under
	// emulation, and an image built for the wrong architecture fails at exec.
	Build string `yaml:"build,omitempty" json:"build,omitempty"`
}

// Compose build locations.
const (
	ComposeBuildAuto  = "auto"
	ComposeBuildLocal = "local"
	ComposeBuildHost  = "host"
)

// ComposeBuild resolves deploy.compose.build with its default.
func (cfg *Config) ComposeBuild() string {
	if cfg.Deploy.Compose != nil && strings.TrimSpace(cfg.Deploy.Compose.Build) != "" {
		return strings.TrimSpace(cfg.Deploy.Compose.Build)
	}
	return ComposeBuildAuto
}

// Deploy strategies. swarm is the product: a signed stack applied by the root
// helper on a host setup hardened. compose is the strategy for a host nobody
// may change: Shuttle builds locally and runs `docker compose` over SSH as an
// account that already exists, and nothing privileged enforces anything.
const (
	StrategySwarm   = "swarm"
	StrategyCompose = "compose"
)

// UsesCompose reports whether the configuration deploys through the compose
// strategy. Every strategy-conditional rule reads this, so "compose" is spelled
// in one place.
func (cfg *Config) UsesCompose() bool {
	return cfg != nil && cfg.Deploy.Strategy == StrategyCompose
}

// ComposeProjectName resolves deploy.compose.project, with the default that
// keeps Shuttle's project apart from anything else on the host.
func (cfg *Config) ComposeProjectName() string {
	if cfg.Deploy.Compose != nil {
		if name := strings.TrimSpace(cfg.Deploy.Compose.Project); name != "" {
			return name
		}
	}
	return "shuttle-" + cfg.App
}

// hostKeyFingerprintPattern is the exact shape the SSH client pins on: the
// literal SHA256: prefix and 43 base64 characters. Anything else is refused at
// the desk rather than cleaned.
var hostKeyFingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// composeProjectPattern mirrors what Compose accepts for a project name.
var composeProjectPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// PrimaryServiceName is the single place that resolves the published service
// name. Everything that used to hard-code "web" goes through it, so the default
// stays identical for configurations that never set the key.
func (cfg *Config) PrimaryServiceName() string {
	if cfg == nil {
		return DefaultPrimaryService
	}
	if name := strings.TrimSpace(cfg.Deploy.PrimaryService); name != "" {
		return name
	}
	return DefaultPrimaryService
}

// DefaultPrimaryService is the service name the generated presets emit.
const DefaultPrimaryService = "web"

// Exposure values for Config.Expose.
const (
	ExposePublic   = "public"
	ExposeInternal = "internal"
)

// IsInternal reports whether the application publishes no public route.
func (cfg *Config) IsInternal() bool {
	return cfg != nil && strings.TrimSpace(cfg.Expose) == ExposeInternal
}

// composeServiceName mirrors the Compose Specification's service-name charset.
// It is deliberately stricter than Compose: the name also becomes a Swarm
// service DNS label (`<stack>_<service>`), so it must survive DNS.
var composeServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

type Hooks struct {
	PreDeploy  []string `yaml:"pre_deploy,omitempty" json:"pre_deploy"`
	Switch     []string `yaml:"switch,omitempty" json:"switch"`
	PostDeploy []string `yaml:"post_deploy,omitempty" json:"post_deploy"`
	Pre        []string `yaml:"pre,omitempty" json:"-"`
	Post       []string `yaml:"post,omitempty" json:"-"`
}

type Blue struct {
	DrainTimeout   int `yaml:"drain_timeout,omitempty" json:"drain_timeout"`
	ReadinessDelay int `yaml:"readiness_delay,omitempty" json:"readiness_delay"`
}

type Swarm struct {
	Replicas int         `yaml:"replicas,omitempty" json:"replicas"`
	Mode     string      `yaml:"mode,omitempty" json:"mode,omitempty"`
	Nodes    []SwarmNode `yaml:"nodes,omitempty" json:"nodes,omitempty"`
}

// SwarmNode maps a configured server host to its desired Swarm role. The
// first manager is the bootstrap authority; additional managers and workers
// join it through one-time Docker join tokens.
type SwarmNode struct {
	Host          string `yaml:"host" json:"host"`
	Role          string `yaml:"role" json:"role"`
	AdvertiseAddr string `yaml:"advertise_addr,omitempty" json:"advertise_addr,omitempty"`
}

type Service struct {
	Port        int         `yaml:"port,omitempty" json:"port,omitempty"`
	Command     string      `yaml:"command,omitempty" json:"command"`
	Replicas    int         `yaml:"replicas,omitempty" json:"replicas,omitempty"`
	Healthcheck Healthcheck `yaml:"healthcheck,omitempty" json:"healthcheck"`
	// Resources caps what one task of this service may use. Shuttle applies a
	// deliberate default to every service, but the default is sized for a small
	// stateless app: a PHP worker pool and a Next.js server that prerenders
	// thousands of pages do not fit the same box, and a limit below the runtime's
	// own heap setting is an OOM kill on a timer rather than a safety net.
	Resources Resources `yaml:"resources,omitempty" json:"resources,omitempty"`
	// UpdateOrder overrides Swarm's rolling-update order for this service only.
	// Shuttle generates `start-first` everywhere, because that is what buys zero
	// downtime on a single node. A service that holds an exclusive lock on a
	// mounted volume cannot survive it: the replacement task starts while the
	// outgoing one still owns the file, fails to acquire it, and exits — Swarm
	// then rolls the whole stack back. A Mercure hub on a BoltDB file is the
	// case this exists for.
	//
	// Empty means `start-first`. The published service may not opt out: it is
	// the one behind Caddy, and stop-first there is a gap in service.
	UpdateOrder string `yaml:"update_order,omitempty" json:"update_order,omitempty"`
	// UpdateParallelism is how many tasks of this service Swarm replaces at once
	// (update_config.parallelism). Omitted means 1, the one-at-a-time rollout
	// Shuttle has always generated; an explicit 0 replaces all tasks at once.
	// It is a pointer for that reason: 0 is a value, not "unset". With
	// start-first, each task replaced at once is a second copy of the service
	// in memory, which the pre-deploy memory guard counts.
	UpdateParallelism *int `yaml:"update_parallelism,omitempty" json:"update_parallelism,omitempty"`
}

// UpdateOrderStartFirst and UpdateOrderStopFirst are the two Swarm rolling
// update orders Shuttle will emit.
const (
	UpdateOrderStartFirst = "start-first"
	UpdateOrderStopFirst  = "stop-first"
)

// Swarm update monitor bounds and shipped default. The monitor is the window
// after a replacement task starts in which a failure still triggers
// failure_action: rollback; it was a hard-coded 10 s, and Swarm only reports a
// service as updated once it has elapsed. Five seconds is enough to catch a task
// that dies on its first request, and takes five seconds off every promotion.
const (
	MinUpdateMonitorSeconds     = 2
	MaxUpdateMonitorSeconds     = 60
	DefaultUpdateMonitorSeconds = 5
	// DefaultUpdateParallelism is the one-at-a-time rollout of every service.
	DefaultUpdateParallelism = 1
)

// EffectiveUpdateMonitorSeconds resolves deploy.update_monitor_seconds, treating
// omitted and 0 as the default like the other deploy budgets, so a Config built
// without Load renders the same stack as a loaded one.
func (cfg *Config) EffectiveUpdateMonitorSeconds() int {
	if cfg == nil || cfg.Deploy.UpdateMonitorSeconds == 0 {
		return DefaultUpdateMonitorSeconds
	}
	return cfg.Deploy.UpdateMonitorSeconds
}

// UpdateParallelism resolves update_config.parallelism for one service name,
// including services that carry no entry in the configuration at all: nil is 1,
// an explicit 0 is "all tasks at once", and N is N.
func (cfg *Config) UpdateParallelism(name string) int {
	if cfg == nil {
		return DefaultUpdateParallelism
	}
	if parallelism := cfg.Services[name].UpdateParallelism; parallelism != nil {
		return *parallelism
	}
	return DefaultUpdateParallelism
}

// Registry cache export modes accepted by deploy.build_cache_mode.
const (
	BuildCacheModeMax = "max"
	BuildCacheModeMin = "min"
)

// validateBuildCacheMode accepts deploy.build_cache_mode. Empty stays empty
// rather than being defaulted, so a configuration that never names the field
// loads exactly as before; the build reads empty as "max".
func validateBuildCacheMode(mode string) error {
	switch mode {
	case "", BuildCacheModeMax, BuildCacheModeMin:
		return nil
	}
	return fmt.Errorf("deploy.build_cache_mode must be %q or %q, got %q", BuildCacheModeMax, BuildCacheModeMin, mode)
}

// UpdateOrder resolves the rolling-update order for one service name, including
// services that carry no entry in the configuration at all.
func (cfg *Config) UpdateOrder(name string) string {
	if cfg == nil {
		return UpdateOrderStartFirst
	}
	if order := strings.TrimSpace(cfg.Services[name].UpdateOrder); order != "" {
		return order
	}
	return UpdateOrderStartFirst
}

// Resources are Swarm task limits, in Compose's own syntax so the values can be
// copied straight out of a compose file.
// Operation is one declared maintenance command.
type Operation struct {
	// Service is the Compose service whose running container executes it.
	Service string `yaml:"service" json:"service"`
	// Command is an argv, never a shell string: it is passed to `docker exec`
	// as separate arguments, so there is no shell to quote against and no way
	// for an argument to become a second command.
	Command      []string `yaml:"command" json:"command"`
	BackupBefore bool     `yaml:"backup_before,omitempty" json:"backup_before,omitempty"`
}

var operationName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func validateOperations(cfg *Config) error {
	names := make([]string, 0, len(cfg.Operations))
	for name := range cfg.Operations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		operation := cfg.Operations[name]
		if operation.BackupBefore && !cfg.Database.Managed() {
			return fmt.Errorf("operations.%s.backup_before requires a managed PostgreSQL database (database block)", name)
		}
		if !operationName.MatchString(name) {
			return fmt.Errorf("invalid operation name %q: use lowercase letters, digits and hyphens", name)
		}
		if !composeServiceName.MatchString(operation.Service) {
			return fmt.Errorf("operations.%s.service %q is not a valid service name", name, operation.Service)
		}
		if len(operation.Command) == 0 {
			return fmt.Errorf("operations.%s.command must not be empty", name)
		}
		for index, argument := range operation.Command {
			// No control characters: the argv travels through a signed stack
			// label and is read back by the privileged helper, so it stays
			// something a human can read in `docker service inspect`.
			if argument == "" || strings.ContainsAny(argument, "\r\n\x00") {
				return fmt.Errorf("operations.%s.command[%d] must be a non-empty single-line argument", name, index)
			}
		}
	}
	return nil
}

type Resources struct {
	// CPUs is a fraction of one core, e.g. "0.5", "1.0", "2".
	CPUs string `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	// Memory is a byte size with a unit, e.g. "768M", "2G".
	Memory string `yaml:"memory,omitempty" json:"memory,omitempty"`
}

// Default task limits. They are what Shuttle applied unconditionally before
// these keys existed, so an untouched configuration produces the same stack.
const (
	DefaultServiceCPUs       = "1.0"
	DefaultServiceMemory     = "768M"
	ServiceMemoryReservation = "64M"
	// MinServiceMemoryBytes is Docker's own floor for a memory limit. Below it
	// the daemon refuses the task, so catching it here turns a mid-deploy
	// rejection into a validation error.
	MinServiceMemoryBytes = 6 << 20
)

// Limits resolves the effective task limits, falling back to the defaults.
func (s Service) Limits() Resources {
	resolved := Resources{CPUs: strings.TrimSpace(s.Resources.CPUs), Memory: strings.TrimSpace(s.Resources.Memory)}
	if resolved.CPUs == "" {
		resolved.CPUs = DefaultServiceCPUs
	}
	if resolved.Memory == "" {
		resolved.Memory = DefaultServiceMemory
	}
	return resolved
}

// ServiceLimits resolves the limits for one service name, including services
// that carry no entry in the configuration at all.
func (cfg *Config) ServiceLimits(name string) Resources {
	if cfg == nil {
		return Service{}.Limits()
	}
	return cfg.Services[name].Limits()
}

// serviceCPUs accepts a bare decimal. Compose also accepts it as a string, and
// Swarm converts it to nano-CPUs, so anything else is rejected here rather than
// by the daemon halfway through a promotion.
var serviceCPUs = regexp.MustCompile(`^(?:0*[1-9][0-9]*|0)(?:\.[0-9]+)?$`)

// sortedServiceNames keeps validation errors deterministic: reporting whichever
// service Go's map iteration reached first would make the same configuration
// fail with a different message on each run.
func sortedServiceNames(services map[string]Service) []string {
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validateServiceUpdateOrder keeps the override narrow on purpose. It exists so
// a lock-holding service can step aside before its replacement starts; it is not
// a general knob, and it may never be pointed at the published service.
func validateServiceUpdateOrder(name string, service Service, primary string) error {
	order := strings.TrimSpace(service.UpdateOrder)
	if order == "" {
		return nil
	}
	if order != UpdateOrderStartFirst && order != UpdateOrderStopFirst {
		return fmt.Errorf("services.%s.update_order %q must be %q or %q", name, order, UpdateOrderStartFirst, UpdateOrderStopFirst)
	}
	if order == UpdateOrderStopFirst && name == primary {
		return fmt.Errorf("services.%s.update_order: the published service cannot update %s — that is a gap in service, not a rolling update", name, UpdateOrderStopFirst)
	}
	return nil
}

// validateServiceUpdateParallelism refuses a negative rollout width. Zero is a
// value (every task at once), so only below zero is an error.
func validateServiceUpdateParallelism(name string, service Service) error {
	if service.UpdateParallelism != nil && *service.UpdateParallelism < 0 {
		return fmt.Errorf("services.%s.update_parallelism must be 0 (all tasks at once) or a positive number, got %d", name, *service.UpdateParallelism)
	}
	return nil
}

// validateUpdateMonitor bounds deploy.update_monitor_seconds. Below two seconds
// Swarm would call a task that has only just started a success; above a minute
// every promotion pays for the window. 0 is the default, which Load has already
// replaced by the time it validates, and which EffectiveUpdateMonitorSeconds
// resolves for a Config that never went through Load.
func validateUpdateMonitor(seconds int) error {
	if seconds != 0 && (seconds < MinUpdateMonitorSeconds || seconds > MaxUpdateMonitorSeconds) {
		return fmt.Errorf("deploy.update_monitor_seconds must be between %d and %d seconds, got %d", MinUpdateMonitorSeconds, MaxUpdateMonitorSeconds, seconds)
	}
	return nil
}

func validateServiceResources(name string, service Service) error {
	if value := strings.TrimSpace(service.Resources.CPUs); value != "" {
		if !serviceCPUs.MatchString(value) {
			return fmt.Errorf("services.%s.resources.cpus %q must be a positive decimal such as 0.5 or 2", name, value)
		}
		if amount, err := strconv.ParseFloat(value, 64); err != nil || amount <= 0 {
			return fmt.Errorf("services.%s.resources.cpus %q must be greater than zero", name, value)
		}
	}
	if value := strings.TrimSpace(service.Resources.Memory); value != "" {
		bytes, err := ParseByteSize(value)
		if err != nil {
			return fmt.Errorf("services.%s.resources.memory: %w", name, err)
		}
		if bytes < MinServiceMemoryBytes {
			return fmt.Errorf("services.%s.resources.memory %q is below Docker's %dMiB floor", name, value, MinServiceMemoryBytes>>20)
		}
	}
	return nil
}

type Healthcheck struct {
	Type     string `yaml:"type,omitempty" json:"type"`
	Path     string `yaml:"path,omitempty" json:"path,omitempty"`
	Command  string `yaml:"command,omitempty" json:"command,omitempty"`
	Interval int    `yaml:"interval,omitempty" json:"interval"`
	Timeout  int    `yaml:"timeout,omitempty" json:"timeout"`
	Retries  int    `yaml:"retries,omitempty" json:"retries"`
}

type Accessory struct {
	Preset  string            `yaml:"preset,omitempty" json:"preset,omitempty"`
	Image   string            `yaml:"image,omitempty" json:"image,omitempty"`
	Port    any               `yaml:"port,omitempty" json:"port,omitempty"`
	Volumes []string          `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	Env     map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

type Secrets struct {
	File string `yaml:"file,omitempty" json:"file"`
	// Backend names where the values live, which is a different question from
	// where they are mounted: every backend ends as a Docker Secret under
	// /run/secrets. "swarm" reads the encrypted local store, so the operator
	// holds a copy of every credential on their workstation. "host" reads them
	// on the VPS and the workstation never sees one.
	Backend   string                `yaml:"backend,omitempty" json:"backend"`
	Host      SecretsHost           `yaml:"host,omitempty" json:"host,omitempty"`
	Hashvault SecretsHashvault      `yaml:"hashvault,omitempty" json:"hashvault,omitzero"`
	Items     map[string]SecretItem `yaml:"items,omitempty" json:"items,omitempty"`
	// Driver is retained only so legacy configuration fails with an actionable
	// migration error instead of being silently ignored by yaml.Unmarshal.
	Driver string `yaml:"driver,omitempty" json:"driver,omitempty"`
}

// SecretsHost configures the host-side backend.
//
// EnvFile is read by the root helper on the VPS, never by the CLI: it is the
// answer to a deployment whose credentials already live on the server and are
// meant to stay there. Copying them to the workstation so that Shuttle could
// send them back is the movement this backend exists to avoid — every copy is
// somewhere else they can leak from, and a laptop is a worse vault than a
// root-owned file on the machine that already serves them.
type SecretsHost struct {
	EnvFile string `yaml:"env_file,omitempty" json:"env_file,omitempty"`
}

// SecretsHashvault names a local manifest and a registered vault target. The
// manager's root-owned enrollment chooses socket, principal and signing key;
// an application configuration never supplies those privileged paths.
type SecretsHashvault struct {
	Target      string `yaml:"target,omitempty" json:"target,omitempty"`
	Manifest    string `yaml:"manifest,omitempty" json:"manifest,omitempty"`
	Preparation string `yaml:"preparation,omitempty" json:"preparation,omitempty"`
}

type SecretItem struct {
	Services []string `yaml:"services" json:"services"`
	Expose   string   `yaml:"expose,omitempty" json:"expose"`
	// UID and GID own the mounted file. A Swarm secret is owned by root
	// otherwise, so an image that drops privileges cannot read its own
	// credential at a restrictive mode, and the usual workaround is a root
	// phase in the entrypoint that copies the file and chowns it — which
	// needs CAP_CHOWN, which Shuttle drops from every service.
	//
	// Declaring the account instead lets the file arrive readable by it and
	// by nobody else. Pointers, so "not declared" and "uid 0" stay different
	// questions: a configuration that says nothing keeps the mode it had.
	UID *int `yaml:"uid,omitempty" json:"uid,omitempty"`
	GID *int `yaml:"gid,omitempty" json:"gid,omitempty"`
}

// Owner reports the account a mounted secret belongs to, and whether one was
// declared at all. A declared uid with no gid uses the uid for both, which is
// what a dedicated service account looks like.
func (item SecretItem) Owner() (uid int, gid int, declared bool) {
	if item.UID == nil {
		return 0, 0, false
	}
	gid = *item.UID
	if item.GID != nil {
		gid = *item.GID
	}
	return *item.UID, gid, true
}

type Env struct {
	Clear  map[string]string `yaml:"clear,omitempty" json:"clear,omitempty"`
	Secret []string          `yaml:"secret,omitempty" json:"secret,omitempty"`
}

type EnvSchema map[string]EnvVarSchema

type EnvVarSchema struct {
	Type     string   `yaml:"type,omitempty" json:"type,omitempty"`
	Required bool     `yaml:"required,omitempty" json:"required,omitempty"`
	Default  string   `yaml:"default,omitempty" json:"default,omitempty"`
	Pattern  string   `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Allowed  []string `yaml:"allowed,omitempty" json:"allowed,omitempty"`
}

type Proxy struct {
	Driver  string            `yaml:"driver,omitempty" json:"driver"`
	SSL     ProxySSL          `yaml:"ssl,omitempty" json:"ssl"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type ProxySSL struct {
	Provider string `yaml:"provider,omitempty" json:"provider"`
	Email    string `yaml:"email,omitempty" json:"email,omitempty"`
}

type Registry struct {
	Driver      string `yaml:"driver,omitempty" json:"driver"`
	URL         string `yaml:"url,omitempty" json:"url,omitempty"`
	Username    string `yaml:"username,omitempty" json:"username,omitempty"`
	PasswordEnv string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
}

type Notifications struct {
	Webhooks []string `yaml:"webhooks,omitempty" json:"webhooks,omitempty"`
}

type Caddy struct {
	// DataVolume names an existing Docker volume to mount as Caddy's /data,
	// instead of the volume Shuttle would create. /data holds the ACME account
	// and every issued certificate, so an edge that adopts an existing
	// deployment must be able to adopt its certificates too: starting on an
	// empty store means re-issuing every hostname at once, against a certificate
	// authority that rate-limits, during the cutover window.
	DataVolume string `yaml:"data_volume,omitempty" json:"data_volume,omitempty"`
	// Mounts are extra host paths the edge needs to serve files it does not
	// generate: a maintenance page, a media root, release artifacts.
	Mounts []CaddyMount `yaml:"mounts,omitempty" json:"mounts,omitempty"`
	// Env are plain environment variables for the edge container, readable from
	// a Caddyfile as {env.NAME}. Never put a credential here; use SecretEnv.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	// SecretEnv maps an environment variable name to an existing Docker Swarm
	// secret. The secret stays a file, mounted under /run/secrets and never
	// written to disk unencrypted; an entrypoint reads it into the environment
	// at start so a Caddyfile placeholder such as {env.CLOUDFLARE_API_TOKEN}
	// resolves. This is what a DNS-01 challenge needs, and mounting the secret
	// without exporting it is a silent failure: the placeholder expands to an
	// empty string and renewals fail long after the deploy reported success.
	SecretEnv     map[string]string `yaml:"secret_env,omitempty" json:"secret_env,omitempty"`
	ConfDir       string            `yaml:"conf_dir,omitempty" json:"conf_dir,omitempty"`
	ReloadCommand string            `yaml:"reload_command,omitempty" json:"reload_command,omitempty"`
	Network       string            `yaml:"network,omitempty" json:"network,omitempty"`
	// TLSMode selects how the shared edge terminates this application. "acme"
	// (the default) obtains a certificate. "off" serves the origin over plain
	// HTTP, which is what a CDN or a tunnel in front of it requires: that edge
	// already terminated TLS, and no inbound path exists for an ACME challenge
	// to arrive on, so requesting a certificate can only fail while breaking
	// the hop that does work.
	TLSMode string `yaml:"tls_mode,omitempty" json:"tls_mode,omitempty"`
	// TrustedCIDRs restricts the site to these client networks. It is how the
	// access control an operator already had in front of the origin survives
	// the move to the shared edge, instead of being dropped in silence.
	TrustedCIDRs []string          `yaml:"trusted_cidrs,omitempty" json:"trusted_cidrs,omitempty"`
	TLSSnippet   string            `yaml:"tls_snippet,omitempty" json:"tls_snippet,omitempty"`
	Routes       map[string]string `yaml:"routes,omitempty" json:"routes,omitempty"`
	// PathRoutes sends matching request paths to another service of the same
	// stack, in the order given. Without it a domain reaches exactly one
	// service, which describes a single-process application and not the
	// monorepos Shuttle is asked to deploy: an API and a front end behind one
	// hostname had no expressible shape at all. Order is significant, because
	// Caddy matches in order; everything unmatched falls through to the
	// published service.
	PathRoutes []CaddyPathRoute `yaml:"path_routes,omitempty" json:"path_routes,omitempty"`
	// HostRoutes publish further hostnames on the same application, each one
	// proxied to a service of the same stack. A domain names one site; a
	// Laravel monorepo that serves its front end, its API and its back office
	// on three hostnames had to be three applications, or nothing. Each host
	// carries its own path routes and headers, and every host must resolve
	// to the VPS exactly like the domain does.
	HostRoutes []CaddyHostRoute `yaml:"host_routes,omitempty" json:"host_routes,omitempty"`
	// Headers are response headers added to this application's site, on top of
	// the baseline the shared edge already sets, and overriding it by name.
	//
	// It exists because the useful headers cannot be chosen for an application
	// Shuttle did not build. A default Content-Security-Policy either breaks
	// every app that loads a CDN or an inline script, or permits enough to
	// protect nothing; the same is true of Permissions-Policy, where denying a
	// capability an app actually uses fails silently in the browser. Only the
	// operator knows, so only the operator declares it.
	Headers   map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Email     string            `yaml:"email,omitempty" json:"email,omitempty"`
	BasicAuth CaddyBasicAuth    `yaml:"basic_auth,omitempty" json:"basic_auth,omitempty"`
	// DomainBasicAuth controls whether the primary application domain imports
	// the shared Basic Auth gate. It defaults to true for backwards
	// compatibility; host routes can still opt into the same gate individually.
	DomainBasicAuth *bool `yaml:"domain_basic_auth,omitempty" json:"domain_basic_auth,omitempty"`
	// IPAllowlist, when non-empty, restricts the site to these clients. Entries are
	// regex fragments (e.g. "203\\.0\\.113\\.4" or "2a01:cb0c:[0-9a-f:]+") joined
	// into a single alternation.
	//
	// NOTE: the shared edge of Shuttle v2 renders neither IPAllowlist nor
	// HealthPath — only caddy.trusted_cidrs (dev.shuttle.allow_cidrs) and
	// caddy.basic_auth (dev.shuttle.basic_auth) reach a fragment. The old
	// "takes precedence over BasicAuth" note described the legacy renderer and
	// was wrong here: a configuration relying on it would be served unguarded.
	IPAllowlist []string `yaml:"ip_allowlist,omitempty" json:"ip_allowlist,omitempty"`
	// HealthPath, when set (e.g. "/healthz"), is left open (no auth / no IP filter)
	// so external monitors can probe it. Applies only in IPAllowlist mode.
	HealthPath string `yaml:"health_path,omitempty" json:"health_path,omitempty"`
	// Host, when set, is the machine that owns conf_dir and runs Caddy: a
	// dedicated edge host serving several projects. Empty (the default) keeps
	// the historical behavior: the routing fragment is written on the deploy
	// host itself.
	Host string `yaml:"host,omitempty" json:"host,omitempty"`
	// User and Port are the SSH credentials of that edge host. Both fall back
	// to the deploy server group's own user/port, which is the common case.
	User  string `yaml:"user,omitempty" json:"user,omitempty"`
	Port  int    `yaml:"port,omitempty" json:"port,omitempty"`
	Image string `yaml:"image,omitempty" json:"image,omitempty"`
}

type CaddyBasicAuth struct {
	Users []CaddyBasicAuthUser `yaml:"users,omitempty" json:"users,omitempty"`
	// PublicPaths are served without the gate. A browser fetches some files
	// without credentials whatever the page holds: the PWA manifest, the
	// service worker's own precache (credentials: "omit"). Behind basic_auth
	// those requests get a 401 with WWW-Authenticate, and Safari answers each
	// one with a new password prompt, so a gated PWA prompts in a loop. Only
	// public build output belongs here; "/" and "/*" are refused because they
	// would open the whole site.
	PublicPaths []string `yaml:"public_paths,omitempty" json:"public_paths,omitempty"`
}

type CaddyBasicAuthUser struct {
	Username string `yaml:"username" json:"username"`
	Hash     string `yaml:"hash" json:"hash"`
}

type Dev struct {
	SSL    bool     `yaml:"ssl,omitempty" json:"ssl"`
	Domain string   `yaml:"domain,omitempty" json:"domain,omitempty"`
	Ports  DevPorts `yaml:"ports,omitempty" json:"ports,omitempty"`
}

type DevPorts struct {
	HTTP  int `yaml:"http,omitempty" json:"http"`
	HTTPS int `yaml:"https,omitempty" json:"https"`
}

func Load(path string, env string) (*Config, error) {
	if path == "" {
		found, err := FindDefault()
		if err != nil {
			return nil, err
		}
		path = found
	}

	cfg, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	if env != "" {
		extension := filepath.Ext(path)
		base := strings.TrimSuffix(filepath.Base(path), extension)
		overlay := filepath.Join(filepath.Dir(path), fmt.Sprintf("%s.%s%s", base, env, extension))
		if _, err := os.Stat(overlay); err == nil {
			// Both files are validated on their own first, so an unknown field
			// in an overlay is still an error and still names its own file.
			if _, err := loadFile(overlay); err != nil {
				return nil, err
			}
			cfg, err = mergeOverlay(path, overlay)
			if err != nil {
				return nil, err
			}
		}
	}
	applyDefaults(cfg)
	return cfg, validate(cfg)
}

// FindDefault locates the project configuration, preferring config.json and
// falling back to an existing shuttle.yml.
func FindDefault() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		for _, name := range []string{"config.json", "shuttle.yml"} {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("config.json not found (legacy shuttle.yml was not found either)")
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Deploy budget bounds. A budget is a measurement target the operator owns, so
// the only values refused are the ones that could not describe a real Swarm
// promotion: below MinDeploySLOSeconds every internal wait derived from it
// collapses to sub-second deadlines, and above MaxDeploySLOSeconds a signed
// stack promotion could hold the root-operation lock for a quarter of an hour.
const (
	MinDeploySLOSeconds = 10
	MaxDeploySLOSeconds = 600
)

// DefaultDeploySLOSeconds is the deploy budget Shuttle ships for a readiness
// preset. The figures come from measured single-node Swarm promotions on Debian
// 13: a Hono release is source-to-production in 8.1 s (build 1.66 s, push 0 s,
// promotion 6.4 s), while a FrankenPHP release pays for a PHP runtime that only
// answers once its opcache is warm — 10 to 23 s for a skeleton and 18 to 41 s
// for a real application once the registry cache, the build-time warmup and the
// 30 s PHP healthcheck are in place. 45 s covers the measured PHP range with
// margin; 30 s covers every JavaScript and Python preset the same way.
func DefaultDeploySLOSeconds(preset string) int {
	switch preset {
	case "laravel", "symfony":
		return 45
	default:
		return 30
	}
}

// DeployWaitBudget is how one promotion budget is spent across the four waits a
// promotion performs one after another.
type DeployWaitBudget struct {
	// StackConvergence bounds `docker service ls` polling after the signed
	// stack promotion, on the root helper.
	StackConvergence time.Duration
	// CaddyReload bounds the whole shared-edge reload, also on the root helper.
	CaddyReload time.Duration
	// OriginProof bounds the proof that this VPS serves the new release, over
	// whichever scheme caddy.tls_mode derives for the origin — plus, behind an
	// edge, the single public request that follows it.
	OriginProof time.Duration
	// Availability bounds the post-promotion wait for the public health URL to
	// answer when no probe was running before the promotion.
	Availability time.Duration
}

// FirstReleaseStackConvergenceFloor covers cold image pulls and first starts.
// The 2026-10-28 VM acceptance run found RabbitMQ still Starting after the
// normal 16.5 s share on a first release, whose total SLO is not evaluated.
const FirstReleaseStackConvergenceFloor = 120 * time.Second

// Total is the longest a promotion may legitimately wait.
func (budget DeployWaitBudget) Total() time.Duration {
	return budget.StackConvergence + budget.CaddyReload + budget.OriginProof + budget.Availability
}

// DeployWaits derives every internal promotion wait from the promotion budget
// instead of letting each site pick its own constant.
//
// The shares exist because those waits are sequential, so independent constants
// silently add up: 25 s of stack convergence, 30 s of Caddy reload, 30 s of
// origin proof and 10 s of availability authorised 95 s of waiting inside a
// budget advertised as 30 s. A deploy could therefore be reported as missing
// its own SLO while every component was still inside its own timeout, which
// made the budget unfalsifiable. Expressed as shares of one budget, the waits
// can never outlast what the command promises, and raising the budget for a
// slow framework raises them together.
func DeployWaits(promotionSLOSeconds int) DeployWaitBudget {
	if promotionSLOSeconds < MinDeploySLOSeconds {
		promotionSLOSeconds = MinDeploySLOSeconds
	}
	if promotionSLOSeconds > MaxDeploySLOSeconds {
		promotionSLOSeconds = MaxDeploySLOSeconds
	}
	budget := time.Duration(promotionSLOSeconds) * time.Second
	// Convergence dominates because it is the only wait that covers real work
	// (image pull, container start, healthcheck). A first hostname can also
	// require ACME issuance during the origin proof; the operator must budget
	// for that explicitly, without silently extending the proof's deadline.
	return DeployWaitBudget{
		StackConvergence: budget * 55 / 100,
		CaddyReload:      budget * 15 / 100,
		OriginProof:      budget * 20 / 100,
		Availability:     budget * 10 / 100,
	}
}

func validateDeploySLO(field string, seconds int) error {
	if seconds < MinDeploySLOSeconds || seconds > MaxDeploySLOSeconds {
		return fmt.Errorf("%s must be between %d and %d seconds, got %d", field, MinDeploySLOSeconds, MaxDeploySLOSeconds, seconds)
	}
	return nil
}

// Setup budget bounds and shipped default. Like the deploy budgets, the setup
// budget is a measurement the command reports rather than a gate it fails on,
// so it is bounded for sanity instead of pinned: a first `apt` run on a cold
// provider image legitimately takes longer than one on a warm mirror, and an
// operator must be able to say so. The floor is the shortest run that could
// describe a real convergence (base packages, Docker, PostgreSQL, reboot); the
// ceiling keeps the figure recognisable as a budget.
const (
	MinSetupSLOSeconds     = 120
	MaxSetupSLOSeconds     = 7200
	DefaultSetupSLOSeconds = 600
)

func validateSetupSLO(seconds int) error {
	if seconds < MinSetupSLOSeconds || seconds > MaxSetupSLOSeconds {
		return fmt.Errorf("setup.slo_seconds must be between %d and %d seconds, got %d", MinSetupSLOSeconds, MaxSetupSLOSeconds, seconds)
	}
	return nil
}

var setupOperatorUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validateSetupOperator(value SetupConfig) error {
	user := strings.TrimSpace(value.OperatorUser)
	key := strings.TrimSpace(value.OperatorPublicKey)
	if (user == "") != (key == "") {
		return errors.New("setup.operator_user and setup.operator_public_key must be declared together")
	}
	// Retained accounts are checked whether or not an operator is declared: a
	// deployment-only configuration carries them too, and the list is what
	// `shuttle doctor` audits AllowUsers against.
	if err := ValidateRetainedUsers(value.RetainedUsers, user); err != nil {
		return err
	}
	if user == "" {
		return nil
	}
	if !setupOperatorUserPattern.MatchString(user) || user == "root" || user == "deploy" {
		return errors.New("setup.operator_user must be a lowercase Unix account other than root or deploy")
	}
	if strings.ContainsAny(value.OperatorPublicKey, "\r\n\x00") {
		return errors.New("setup.operator_public_key must name one local public-key file")
	}
	return nil
}

// MaxAllowedSSHUsers is the size of the AllowUsers list the root helper accepts
// in a signed baseline. It is restated here so a configuration that would be
// refused by the helper is refused at the desk, with the bound named, rather
// than at the last step of a setup that has already changed the host.
const MaxAllowedSSHUsers = 8

// ValidateRetainedUsers checks the accounts setup keeps able to log in.
//
// Exported because the CLI merges --retain-user flags into the list after the
// configuration was loaded and validated, and the merged list has to pass the
// same rules: every entry is emitted verbatim into an sshd directive, so it is
// refused rather than cleaned, and the total must fit the helper's bound with
// deploy and the operator counted in.
func ValidateRetainedUsers(retained []string, operatorUser string) error {
	seen := map[string]bool{}
	for _, user := range retained {
		if user != strings.TrimSpace(user) || !setupOperatorUserPattern.MatchString(user) || user == "root" || user == "deploy" {
			return fmt.Errorf("setup.retained_users entry %q must be a lowercase Unix account other than root or deploy", user)
		}
		if user == operatorUser {
			return fmt.Errorf("setup.retained_users names the operator %q; an account is either retained as it is or configured as the operator, not both", user)
		}
		if seen[user] {
			return fmt.Errorf("setup.retained_users repeats %q", user)
		}
		seen[user] = true
	}
	total := 1 + len(retained)
	if operatorUser != "" {
		total++
	}
	if total > MaxAllowedSSHUsers {
		return fmt.Errorf("setup.retained_users would make AllowUsers name %d accounts; the signed baseline accepts at most %d including deploy and the operator", total, MaxAllowedSSHUsers)
	}
	return nil
}

// AllowedSSHUsers is the exact SSH account policy a converged host must
// expose. Sorted output keeps the signed plan deterministic.
func (cfg *Config) AllowedSSHUsers() []string {
	users := []string{"deploy"}
	if user := strings.TrimSpace(cfg.Setup.OperatorUser); user != "" {
		users = append(users, user)
	}
	users = append(users, cfg.Setup.RetainedUsers...)
	sort.Strings(users)
	return slices.Compact(users)
}

// Registry cache budget bounds. The floor is roughly one `mode=max` cache
// manifest of a PHP image (1 to 2 GB) plus the two release manifests Shuttle
// retains, below which the cap would evict the cache on every single deploy and
// turn every build cold. The ceiling only exists so a typo cannot state a
// budget larger than any VPS disk the product targets.
const (
	MinRegistryCacheBytes = 3 << 30
	MaxRegistryCacheBytes = 512 << 30
)

// ParseByteSize reads the human sizes Shuttle accepts for on-disk budgets.
//
// The suffixes are read as binary multiples, which is what BuildKit and Docker
// already do for the identical `build_cache_keep` figure; using decimal
// multiples here would make two settings written "5GB" in the same file mean
// two different numbers of bytes.
func ParseByteSize(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, errors.New("size is empty")
	}
	upper := strings.ToUpper(trimmed)
	multipliers := []struct {
		suffix string
		factor int64
	}{
		{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"TB", 1 << 40},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40}, {"B", 1},
	}
	for _, candidate := range multipliers {
		if !strings.HasSuffix(upper, candidate.suffix) {
			continue
		}
		digits := strings.TrimSpace(strings.TrimSuffix(upper, candidate.suffix))
		amount, err := strconv.ParseInt(digits, 10, 64)
		if err != nil || amount <= 0 || amount > (1<<62)/candidate.factor {
			return 0, fmt.Errorf("invalid size %q", value)
		}
		return amount * candidate.factor, nil
	}
	return 0, fmt.Errorf("invalid size %q: expected a unit such as 5GB", value)
}

func validateRegistryCache(value string) error {
	bytes, err := ParseByteSize(value)
	if err != nil {
		return fmt.Errorf("retention.registry_cache: %w", err)
	}
	if bytes < MinRegistryCacheBytes || bytes > MaxRegistryCacheBytes {
		return fmt.Errorf("retention.registry_cache must be between %dGB and %dGB, got %s", MinRegistryCacheBytes>>30, MaxRegistryCacheBytes>>30, value)
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.Setup.SLOSeconds == 0 {
		cfg.Setup.SLOSeconds = DefaultSetupSLOSeconds
	}
	if cfg.Setup.SwapMode == "" {
		cfg.Setup.SwapMode = "managed"
	}
	if cfg.Setup.AppArmorMode == "" {
		cfg.Setup.AppArmorMode = "managed"
	}
	if cfg.Server != nil && len(cfg.Servers) == 0 {
		cfg.Servers = map[string]ServerGroup{
			"default": {Hosts: []string{cfg.Server.Host}, User: cfg.Server.User, Port: cfg.Server.Port, HostKey: cfg.Server.HostKey, VPN: cfg.Server.VPN, Access: cfg.Server.Access},
		}
	}
	for name, group := range cfg.Servers {
		if group.Port == 0 {
			group.Port = 22
		}
		if group.VPN.Required && group.VPN.CheckPort == 0 {
			group.VPN.CheckPort = group.Port
		}
		if group.Access.Mode == "private-tailscale" {
			if group.Access.Interface == "" {
				group.Access.Interface = "tailscale0"
			}
			if len(group.Access.AllowedUsers) == 0 && group.User != "" {
				group.Access.AllowedUsers = []string{group.User}
			}
			// Shuttle executes Docker commands directly as the configured deploy
			// user. Keep that capability explicit in the access posture instead of
			// silently producing a hardened account that cannot deploy.
			if group.Access.DockerAccess == nil {
				enabled := true
				group.Access.DockerAccess = &enabled
			}
		}
		if len(group.Access.AllowedPublicTCPPorts) == 0 {
			group.Access.AllowedPublicTCPPorts = []int{80, 443}
		}
		cfg.Servers[name] = group
	}
	if cfg.Build.Dockerfile == "" {
		cfg.Build.Dockerfile = "Dockerfile"
	}
	if cfg.Build.Context == "" {
		cfg.Build.Context = "."
	}
	if cfg.Build.EffectiveRunner() == BuildRunnerSSH && cfg.Build.Port == 0 {
		cfg.Build.Port = 22
	}
	if cfg.Deploy.Strategy == "" {
		cfg.Deploy.Strategy = "swarm"
	}
	if cfg.Deploy.Timeout == 0 {
		cfg.Deploy.Timeout = 120
	}
	if cfg.Deploy.Retain == 0 {
		cfg.Deploy.Retain = 2
	}
	if cfg.Deploy.Concurrency == 0 {
		cfg.Deploy.Concurrency = 5
	}
	if cfg.Deploy.PruneBuildCache == "" {
		cfg.Deploy.PruneBuildCache = "off"
	}
	if cfg.Deploy.BuildCacheKeep == "" {
		// 5GB is too small for the PHP presets this tool ships. A FrankenPHP
		// image is around 1GB and its compiled-extension layer gets evicted
		// between deploys, so every deploy recompiles them: measured at 137 to
		// 147 s per deploy, which blows the 30 s SLO the product enforces.
		// Raising the budget brought the same deploys back to 12 to 15 s.
		cfg.Deploy.BuildCacheKeep = "5GB"
	}
	if cfg.Deploy.AutoRollback == nil {
		enabled := true
		cfg.Deploy.AutoRollback = &enabled
	}
	// The budget follows the framework, not the tool. A Hono release promotes in
	// 8 s end to end while a FrankenPHP one spends most of its promotion waiting
	// for the PHP runtime to answer its first request, so a single figure could
	// only be wrong for one of them.
	if cfg.Deploy.TotalSLOSeconds == 0 {
		cfg.Deploy.TotalSLOSeconds = DefaultDeploySLOSeconds(cfg.Readiness.Preset)
	}
	cfg.Deploy.promotionSLOSetByProject = cfg.Deploy.PromotionSLOSeconds != 0
	if cfg.Deploy.PromotionSLOSeconds == 0 {
		cfg.Deploy.PromotionSLOSeconds = DefaultDeploySLOSeconds(cfg.Readiness.Preset)
	}
	if cfg.Deploy.UpdateMonitorSeconds == 0 {
		cfg.Deploy.UpdateMonitorSeconds = DefaultUpdateMonitorSeconds
	}
	if cfg.Retention.RegistryCache == "" {
		cfg.Retention.RegistryCache = "5GB"
	}
	if cfg.Retention.Backups == 0 {
		// Configs written before this setting was enforced all meant the shipped
		// seven-archive policy, so omission must preserve that behavior.
		cfg.Retention.Backups = 7
	}
	if cfg.Retention.MinFreePct == 0 {
		cfg.Retention.MinFreePct = 20
	}
	if (cfg.Deploy.Strategy == "compose" || cfg.Deploy.Strategy == "swarm" || cfg.Deploy.Strategy == "blue-green") && len(cfg.Deploy.ComposeFiles) == 0 {
		cfg.Deploy.ComposeFiles = []string{"docker-compose.yml"}
	}
	if cfg.Secrets.File == "" {
		cfg.Secrets.File = ".shuttle/secrets.enc"
	}
	if len(cfg.Secrets.Items) > 0 && cfg.Secrets.Backend == "" {
		// No Docker Secret exists without Swarm, so under compose the only
		// backend that can hold a value is the host's own file.
		if cfg.UsesCompose() {
			cfg.Secrets.Backend = SecretsBackendHost
		} else {
			cfg.Secrets.Backend = SecretsBackendSwarm
		}
	}
	for key, item := range cfg.Secrets.Items {
		if item.Expose == "" {
			item.Expose = "file"
			cfg.Secrets.Items[key] = item
		}
	}
	if cfg.Caddy.ConfDir == "" {
		cfg.Caddy.ConfDir = "/opt/caddy/conf.d"
	}
	if cfg.Caddy.ReloadCommand == "" {
		cfg.Caddy.ReloadCommand = "docker service update --force caddy_caddy"
	}
	if cfg.Caddy.Network == "" {
		cfg.Caddy.Network = "caddy_network"
	}
	if cfg.Monitoring != nil {
		cfg.Monitoring.NormalizeMonitoringForApp(cfg.App)
	}
}

var appNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validate(cfg *Config) error {
	if cfg.Version != 2 {
		return fmt.Errorf("unsupported configuration version %d: Shuttle requires version: 2", cfg.Version)
	}
	if cfg.App == "" {
		return errors.New("app is required")
	}
	if !appNamePattern.MatchString(cfg.App) {
		return fmt.Errorf("invalid app %q: use lowercase letters, digits, and hyphens", cfg.App)
	}
	if err := validateProduction(cfg.Production); err != nil {
		return err
	}
	switch strings.TrimSpace(cfg.Expose) {
	case "", ExposePublic, ExposeInternal:
	default:
		return fmt.Errorf("invalid expose %q: expected %s or %s", cfg.Expose, ExposePublic, ExposeInternal)
	}
	// The domain every extra hostname is checked against; empty for an internal
	// application, which may declare none of either.
	primaryDomain := ""
	if cfg.IsInternal() {
		// A domain on an internal application is a contradiction, not a harmless
		// leftover: it would be the one value an operator trusts to tell them
		// where the app is reachable, and nothing would serve it.
		if cfg.Domain != nil && strings.TrimSpace(fmt.Sprint(cfg.Domain)) != "" {
			return errors.New("an internal application must not declare a domain")
		}
		if len(cfg.Caddy.Routes) > 0 {
			return errors.New("an internal application must not declare caddy.routes")
		}
		if len(cfg.Caddy.HostRoutes) > 0 {
			return errors.New("an internal application must not declare caddy.host_routes")
		}
		// The availability probe is an HTTP call made from the operator's
		// machine. Against an application that publishes nothing it can only
		// ever fail, and it would roll back a healthy promotion.
		if strings.TrimSpace(cfg.Deploy.AvailabilityURL) != "" {
			return errors.New("an internal application must not declare deploy.availability_url")
		}
	} else {
		if cfg.Domain == nil {
			return errors.New("domain is required")
		}
		domain, ok := cfg.Domain.(string)
		if !ok || strings.TrimSpace(domain) == "" || strings.ContainsAny(domain, "/:@") {
			return errors.New("domain must be one DNS hostname")
		}
		primaryDomain = strings.TrimSpace(domain)
	}
	primary := cfg.PrimaryServiceName()
	if !composeServiceName.MatchString(primary) {
		return fmt.Errorf("invalid deploy.primary_service %q: use lowercase letters, digits, and -._", primary)
	}
	web, ok := cfg.Services[primary]
	if !ok || web.Port < 1 || web.Port > 65535 {
		return fmt.Errorf("services.%s.port is required and must be valid", primary)
	}
	if web.Healthcheck.Path == "" || !strings.HasPrefix(web.Healthcheck.Path, "/") || strings.ContainsAny(web.Healthcheck.Path, "\r\n") {
		return fmt.Errorf("services.%s.healthcheck.path must be an absolute HTTP path", primary)
	}
	for _, name := range sortedServiceNames(cfg.Services) {
		if err := validateServiceResources(name, cfg.Services[name]); err != nil {
			return err
		}
		if err := validateServiceUpdateOrder(name, cfg.Services[name], primary); err != nil {
			return err
		}
		if err := validateServiceUpdateParallelism(name, cfg.Services[name]); err != nil {
			return err
		}
	}
	if err := validateOperations(cfg); err != nil {
		return err
	}
	if cfg.Server == nil {
		return errors.New("Shuttle requires the singular server block; legacy servers groups are not supported")
	}
	if len(cfg.Servers) == 0 {
		return errors.New("server is required")
	}
	if len(cfg.Servers) != 1 {
		return errors.New("Shuttle supports exactly one server group")
	}
	for _, group := range cfg.Servers {
		if len(group.Hosts) != 1 {
			return errors.New("Shuttle supports exactly one VPS")
		}
		if strings.TrimSpace(group.Hosts[0]) == "" {
			return errors.New("Shuttle requires one non-empty VPS address")
		}
	}
	if !cfg.UsesCompose() {
		if err := validateSwarmTopology(cfg.Deploy.Swarm, cfg.Servers); err != nil {
			return err
		}
	}
	for name, group := range cfg.Servers {
		if err := validateServerUser(name, group, cfg.UsesCompose()); err != nil {
			return err
		}
		if !reflect.DeepEqual(group.VPN, VPN{}) {
			return errors.New("legacy VPN settings are not supported in Shuttle")
		}
		access := group.Access
		if access.Mode != "" || access.Interface != "" || len(access.AllowedUsers) > 0 || access.DockerAccess != nil {
			return errors.New("legacy operator access profiles are not supported in Shuttle")
		}
		if err := validateAccess(name, group); err != nil {
			return err
		}
	}
	switch cfg.Deploy.Strategy {
	case StrategySwarm, StrategyCompose:
	default:
		return fmt.Errorf("Shuttle supports deploy.strategy: swarm or compose, got %q", cfg.Deploy.Strategy)
	}
	if err := validateBuildRunner(cfg); err != nil {
		return err
	}
	if cfg.UsesCompose() {
		if err := validateComposeStrategy(cfg); err != nil {
			return err
		}
	} else {
		if cfg.Deploy.Swarm.Mode == "multi-node" || len(cfg.Deploy.Swarm.Nodes) > 1 {
			return errors.New("Shuttle supports only a single-node Swarm")
		}
		for name, group := range cfg.Servers {
			if strings.TrimSpace(group.HostKey) != "" {
				return fmt.Errorf("server group %q declares host_key, which only deploy.strategy: compose reads; under swarm the host key is recorded by shuttle setup", name)
			}
		}
		if cfg.Deploy.Compose != nil {
			return errors.New("deploy.compose only applies to deploy.strategy: compose")
		}
	}
	if len(cfg.Deploy.Profiles) > 0 {
		return errors.New("Compose profiles are not supported in Shuttle")
	}
	if len(cfg.Deploy.Hooks.Pre) > 0 || len(cfg.Deploy.Hooks.PreDeploy) > 0 || len(cfg.Deploy.Hooks.Switch) > 0 || len(cfg.Deploy.Hooks.Post) > 0 || len(cfg.Deploy.Hooks.PostDeploy) > 0 {
		return errors.New("deployment hooks are not supported in Shuttle")
	}
	if !reflect.DeepEqual(cfg.Deploy.BlueGreen, Blue{}) {
		return errors.New("blue-green settings are not supported in Shuttle")
	}
	if !reflect.DeepEqual(cfg.Provision, Provision{}) || !reflect.DeepEqual(cfg.Dev, Dev{}) {
		return errors.New("legacy provisioning and development profiles are not supported in Shuttle")
	}
	if !reflect.DeepEqual(cfg.Proxy, Proxy{}) || !reflect.DeepEqual(cfg.Registry, Registry{}) || !reflect.DeepEqual(cfg.Notifications, Notifications{}) || len(cfg.Accessories) > 0 {
		return errors.New("legacy proxy, registry, notification, and accessory settings are not supported in Shuttle")
	}
	if err := validateSetupSLO(cfg.Setup.SLOSeconds); err != nil {
		return err
	}
	if cfg.Setup.SwapMode != "managed" && cfg.Setup.SwapMode != "host" {
		return fmt.Errorf("setup.swap_mode must be managed or host, got %q", cfg.Setup.SwapMode)
	}
	if cfg.Setup.AppArmorMode != "managed" && cfg.Setup.AppArmorMode != "host" {
		return fmt.Errorf("setup.apparmor_mode must be managed or host, got %q", cfg.Setup.AppArmorMode)
	}
	if err := validateSetupOperator(cfg.Setup); err != nil {
		return err
	}
	if err := validateInfrastructure(cfg.Infrastructure); err != nil {
		return err
	}
	// Both budgets are measurements the deploy reports, not gates it fails on,
	// so they are bounded for sanity instead of pinned to one shipped value: an
	// operator whose application legitimately takes longer must be able to say
	// so without their configuration being rejected.
	if err := validateDeploySLO("deploy.total_slo_seconds", cfg.Deploy.TotalSLOSeconds); err != nil {
		return err
	}
	if err := validateDeploySLO("deploy.promotion_slo_seconds", cfg.Deploy.PromotionSLOSeconds); err != nil {
		return err
	}
	// The promotion is one phase of the total, and every internal wait is sized
	// from the promotion budget. A promotion budget above the total would let
	// those waits alone outlast the command budget they belong to.
	if cfg.Deploy.PromotionSLOSeconds > cfg.Deploy.TotalSLOSeconds {
		return fmt.Errorf("deploy.promotion_slo_seconds (%d) must not exceed deploy.total_slo_seconds (%d)", cfg.Deploy.PromotionSLOSeconds, cfg.Deploy.TotalSLOSeconds)
	}
	if err := validateUpdateMonitor(cfg.Deploy.UpdateMonitorSeconds); err != nil {
		return err
	}
	if cfg.Deploy.Retain != 2 {
		return errors.New("deploy.retain must be 2")
	}
	if err := validateBuildCacheMode(cfg.Deploy.BuildCacheMode); err != nil {
		return err
	}
	if cfg.Retention.Backups < 1 || cfg.Retention.Backups > 7 {
		return errors.New("retention.postgres_backups must be between 1 and 7")
	}
	if cfg.Retention.MinFreePct != 20 {
		return errors.New("retention.min_free_percent must be 20")
	}
	// registry_cache is no longer pinned to the shipped figure because it is now
	// enforced on the VPS after every promotion: a cap that evicts real data has
	// to follow the disk the operator actually bought.
	if err := validateRegistryCache(cfg.Retention.RegistryCache); err != nil {
		return err
	}
	if cfg.Deploy.LocalArtifacts != "" && cfg.Deploy.LocalArtifacts != "ephemeral" {
		return fmt.Errorf("invalid deploy.local_artifacts %q: expected ephemeral", cfg.Deploy.LocalArtifacts)
	}
	if cfg.Secrets.Driver != "" {
		return errors.New("secrets.driver is no longer supported; use secrets.backend: swarm and secrets.items")
	}
	if cfg.Secrets.Backend != "" && cfg.Secrets.Backend != SecretsBackendSwarm && cfg.Secrets.Backend != SecretsBackendHost && cfg.Secrets.Backend != SecretsBackendHashvault {
		return fmt.Errorf("invalid secrets.backend %q: expected %s, %s or %s", cfg.Secrets.Backend, SecretsBackendSwarm, SecretsBackendHost, SecretsBackendHashvault)
	}
	if cfg.UsesHashvaultSecrets() {
		if cfg.Deploy.Strategy != "swarm" {
			return errors.New("secrets.backend: hashvault requires deploy.strategy: swarm; use hashvault prepare/render hooks for other strategies")
		}
		if cfg.Secrets.Hashvault.Target == "" || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(cfg.Secrets.Hashvault.Target) {
			return errors.New("secrets.hashvault.target must name a registered target")
		}
		if cfg.Secrets.Hashvault.Manifest == "" {
			cfg.Secrets.Hashvault.Manifest = "hashvault.json"
		}
		if len(cfg.Secrets.Items) > 0 {
			return errors.New("secrets.backend: hashvault uses hashvault.json as its service contract; remove secrets.items")
		}
	} else if cfg.Secrets.Hashvault.Target != "" || cfg.Secrets.Hashvault.Manifest != "" || cfg.Secrets.Hashvault.Preparation != "" {
		return errors.New("secrets.hashvault requires secrets.backend: hashvault")
	}
	if err := validateSecretsHost(cfg); err != nil {
		return err
	}
	if len(cfg.Env.Secret) > 0 {
		return errors.New("env.secret is no longer supported; declare scoped entries under secrets.items")
	}
	if len(cfg.Secrets.Items) > 0 {
		if cfg.UsesCompose() && cfg.Secrets.Backend != SecretsBackendHost {
			return fmt.Errorf("deploy.strategy: compose publishes no Docker Secret, so secrets.items requires secrets.backend: host, got %q", cfg.Secrets.Backend)
		}
		if err := validateSecretItems(cfg.Secrets.Items); err != nil {
			return err
		}
		if count := len(cfg.Secrets.Items) - len(InfrastructureSecretKeys); count > MaxApplicationSecrets {
			return fmt.Errorf("secrets.items declares %d application secrets, above the %d Shuttle carries", count, MaxApplicationSecrets)
		}
		for key, item := range cfg.Secrets.Items {
			expectedService, expectedExpose, enabled := "", "file", false
			switch key {
			case "REDIS_PASSWORD", "RABBITMQ_PASSWORD", "POSTGRES_PASSWORD":
				// A credential for a service Shuttle provisions itself. Its
				// value is generated on the host and never held locally, but
				// the application still has to read it: Shuttle published a
				// password-protected Redis and mounted the password nowhere the
				// application could reach, so the service it ran was unusable by
				// the stack it ran it for.
				//
				// services therefore names the application services that mount
				// it. The backing service is accepted too, so the historical
				// spelling keeps validating, and it changes nothing: a generated
				// service already mounts its own credential.
				if err := validateManagedCredentialItem(key, item, cfg); err != nil {
					return err
				}
				continue
			case "APP_KEY":
				// Laravel raises MissingAppKeyException on every request without
				// it, so this is not an application secret the operator may keep
				// elsewhere: the framework does not boot at all. Its /up probe
				// still answers 200, so leaving APP_KEY unmanaged produced a
				// deployment that reported success while serving 500s. It is
				// exposed as an environment variable because that is the only
				// form Laravel reads it in.
				//
				// That rule describes a Laravel application published as the
				// primary service, and only that. A stack whose primary is a
				// TanStack front end with Laravel as a secondary service still
				// has an APP_KEY, and it is an ordinary application secret: the
				// operator names the service and the form, like any other.
				if cfg.Readiness.Preset != "laravel" {
					if err := validateApplicationSecretItem(key, item); err != nil {
						return err
					}
					continue
				}
				expectedService, expectedExpose, enabled = cfg.PrimaryServiceName(), "env", true
			default:
				// A per-role database password is a managed credential too: its
				// value is generated on the host, and it is named after a role
				// the configuration declares.
				if cfg.declaresManagedRoleCredential(key) {
					if err := validateManagedCredentialItem("POSTGRES_PASSWORD", item, cfg); err != nil {
						return fmt.Errorf("secret %s: %w", key, err)
					}
					continue
				}
				// An application secret: its value lives in the encrypted local
				// store, is published as a Docker Secret by the root helper, and
				// is mounted under /run/secrets. Infrastructure credentials keep
				// the treatment below — generated on the host, never held here —
				// so the two are not interchangeable.
				if err := validateApplicationSecretItem(key, item); err != nil {
					return err
				}
				continue
			}
			if !enabled || len(item.Services) != 1 || item.Services[0] != expectedService || item.ExposeMode() != expectedExpose {
				return fmt.Errorf("secret %s must target only enabled service %s as %s", key, expectedService, expectedExpose)
			}
		}
	}
	if err := validateCaddyPathRoutes(cfg.Caddy.PathRoutes); err != nil {
		return err
	}
	if err := validateCaddyHeaders(cfg.Caddy.Headers); err != nil {
		return err
	}
	if err := validateCaddyHostRoutes(primaryDomain, cfg.Caddy.HostRoutes, len(cfg.Caddy.BasicAuth.Users) > 0); err != nil {
		return err
	}
	switch strings.TrimSpace(cfg.Caddy.TLSMode) {
	case "", TLSModeACME, TLSModeOff:
	default:
		return fmt.Errorf("invalid caddy.tls_mode %q: expected %s or %s", cfg.Caddy.TLSMode, TLSModeACME, TLSModeOff)
	}
	// Parsed here as well as in the signed operation. Refusing a malformed
	// entry at the desk beats refusing it on the host, where the operator has
	// already committed to a deploy.
	for _, entry := range cfg.TrustedCIDRs() {
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return fmt.Errorf("caddy.trusted_cidrs entry %q is not a CIDR", entry)
		}
	}
	if len(cfg.TrustedCIDRs()) > 32 {
		return errors.New("caddy.trusted_cidrs is limited to 32 networks")
	}
	if strings.TrimSpace(cfg.Caddy.Host) != "" && len(cfg.Caddy.Routes) == 0 {
		return errors.New("caddy.host is set but caddy.routes is empty: shuttle would write no routing fragment anywhere")
	}
	if err := cfg.Deploy.EnvSchema.ValidateEnvSchema(); err != nil {
		return err
	}
	if err := validateDatabaseConfig(cfg.App, cfg.Database); err != nil {
		return err
	}
	if cfg.Monitoring != nil {
		if err := cfg.Monitoring.ValidateMonitoringForApp(cfg.App); err != nil {
			return err
		}
	}
	if err := validateCaddyRuntime(cfg.Caddy); err != nil {
		return err
	}
	if err := validateCaddyImages(cfg.Caddy); err != nil {
		return err
	}
	if err := validateProvision(cfg.Provision); err != nil {
		return err
	}
	if err := validateCaddyBasicAuth(cfg.Caddy.BasicAuth); err != nil {
		return err
	}
	return nil
}

var configuredRedisImagePattern = regexp.MustCompile(`^redis:[0-9][A-Za-z0-9._-]*(?:@sha256:[0-9a-f]{64})?$`)

func validateProduction(value ProductionConfig) error {
	image := strings.TrimSpace(value.RedisImage)
	if image == "" {
		return nil
	}
	if !value.Redis {
		return errors.New("production.redis_image requires production.redis: true")
	}
	if !configuredRedisImagePattern.MatchString(image) {
		return errors.New("production.redis_image must use an official Redis numeric tag, optionally with a sha256 digest")
	}
	return nil
}

// validateServerUser is the account rule of each strategy. Under swarm the
// deploy account is the least-privilege identity the root helper trusts, and
// nothing else may connect. Under compose there is no helper: the account is
// whichever existing login of the host may run docker, named by the operator,
// and only root is refused — a root login is what this strategy exists to
// avoid needing.
func validateServerUser(name string, group ServerGroup, compose bool) error {
	if !compose {
		if group.User != "deploy" {
			return fmt.Errorf("server group %q must use the least-privilege deploy user", name)
		}
		return nil
	}
	if !validUnixAccountName(group.User) || group.User == "root" {
		return fmt.Errorf("server group %q must name an existing non-root account of the host that may run docker (deploy.strategy: compose), got %q", name, group.User)
	}
	return nil
}

// validateComposeStrategy holds every refusal specific to deploy.strategy:
// compose. Each one names a key that would promise something this strategy
// cannot deliver: an edge that is not deployed, a credential the root helper
// would have generated, an ownership Compose does not apply. Refusing them is
// what keeps a compose configuration honest about what will run.
func validateComposeStrategy(cfg *Config) error {
	for name, group := range cfg.Servers {
		key := strings.TrimSpace(group.HostKey)
		if key == "" {
			return fmt.Errorf("server group %q: deploy.strategy: compose requires server.host_key, the VPS's ED25519 host key fingerprint (SHA256:…) obtained out of band, because no shuttle setup records one", name)
		}
		if key != group.HostKey || !hostKeyFingerprintPattern.MatchString(key) {
			return fmt.Errorf("server group %q: host_key %q is not an ED25519 SHA256 fingerprint (SHA256: followed by 43 base64 characters)", name, group.HostKey)
		}
	}
	if !reflect.DeepEqual(cfg.Deploy.Swarm, Swarm{}) {
		return errors.New("deploy.swarm does not apply to deploy.strategy: compose")
	}
	if cfg.Deploy.Compose != nil {
		if project := cfg.Deploy.Compose.Project; project != "" && !composeProjectPattern.MatchString(project) {
			return fmt.Errorf("invalid deploy.compose.project %q: use lowercase letters, digits, - and _", project)
		}
		switch cfg.ComposeBuild() {
		case ComposeBuildAuto, ComposeBuildLocal, ComposeBuildHost:
		default:
			return fmt.Errorf("invalid deploy.compose.build %q: expected auto, local or host", cfg.Deploy.Compose.Build)
		}
	}
	if cfg.Production.Redis || cfg.Production.RabbitMQ {
		return errors.New("production.redis and production.rabbitmq do not apply to deploy.strategy: compose: their passwords are generated by the root helper, which this strategy never installs; declare the service in the compose file instead")
	}
	if !reflect.DeepEqual(cfg.Database, DatabaseConfig{}) {
		return errors.New("database does not apply to deploy.strategy: compose: no PostgreSQL is installed on a host this strategy leaves untouched")
	}
	for key, item := range cfg.Secrets.Items {
		if InfrastructureSecretKeys[key] {
			return fmt.Errorf("secret %s is a credential the root helper generates, which deploy.strategy: compose never installs; read it from the host file like any other key", key)
		}
		if item.UID != nil || item.GID != nil {
			return fmt.Errorf("secret %s declares uid/gid, which Compose does not apply to a file secret; drop the owner or mount it as expose: env", key)
		}
	}
	caddy := cfg.Caddy
	for _, refused := range []struct {
		set bool
		key string
	}{
		{len(caddy.Routes) > 0, "caddy.routes"},
		{len(caddy.PathRoutes) > 0, "caddy.path_routes"},
		{len(caddy.HostRoutes) > 0, "caddy.host_routes"},
		{len(caddy.BasicAuth.Users) > 0, "caddy.basic_auth"},
		{caddy.DomainBasicAuth != nil, "caddy.domain_basic_auth"},
		{len(caddy.Headers) > 0, "caddy.headers"},
		{len(caddy.Mounts) > 0, "caddy.mounts"},
		{len(caddy.Env) > 0, "caddy.env"},
		{len(caddy.SecretEnv) > 0, "caddy.secret_env"},
		{strings.TrimSpace(caddy.DataVolume) != "", "caddy.data_volume"},
		{strings.TrimSpace(caddy.TLSSnippet) != "", "caddy.tls_snippet"},
		{strings.TrimSpace(caddy.Host) != "", "caddy.host"},
		{len(caddy.IPAllowlist) > 0, "caddy.ip_allowlist"},
		{strings.TrimSpace(caddy.HealthPath) != "", "caddy.health_path"},
		{strings.TrimSpace(caddy.Image) != "", "caddy.image"},
		{len(caddy.TrustedCIDRs) > 0, "caddy.trusted_cidrs"},
	} {
		if refused.set {
			return fmt.Errorf("%s does not apply to deploy.strategy: compose: no shared edge is deployed, so nothing would enforce it; only caddy.tls_mode is read, for the origin proof", refused.key)
		}
	}
	if strings.TrimSpace(cfg.Setup.OperatorUser) != "" || len(cfg.Setup.RetainedUsers) > 0 {
		return errors.New("setup.operator_user and setup.retained_users do not apply to deploy.strategy: compose: no setup runs, so nothing would create or retain them")
	}
	return nil
}

func validateProvision(value Provision) error {
	seenUsers := map[string]bool{}
	for index, user := range value.ApplicationUsers {
		prefix := fmt.Sprintf("provision.application_users[%d]", index)
		if !validUnixAccountName(user.Name) {
			return fmt.Errorf("%s.name contains invalid account %q", prefix, user.Name)
		}
		if seenUsers[user.Name] {
			return fmt.Errorf("%s.name duplicates application user %q", prefix, user.Name)
		}
		seenUsers[user.Name] = true
		if user.Home != "" && !validProvisionPath(user.Home) {
			return fmt.Errorf("%s.home must be a clean absolute path", prefix)
		}
		if user.Shell != "" && !validProvisionShell(user.Shell) {
			return fmt.Errorf("%s.shell must be an executable path below /bin, /usr/bin, or /usr/sbin", prefix)
		}
		seenGroups := map[string]bool{}
		for _, group := range user.Groups {
			if !validUnixAccountName(group) {
				return fmt.Errorf("%s.groups contains invalid group %q", prefix, group)
			}
			if seenGroups[group] {
				return fmt.Errorf("%s.groups contains duplicate group %q", prefix, group)
			}
			seenGroups[group] = true
		}
		if user.System && (user.Docker || user.Sudo || len(user.AuthorizedKeys) > 0) {
			return fmt.Errorf("%s system accounts cannot have Docker, sudo, or authorized_keys", prefix)
		}
		for keyIndex, key := range user.AuthorizedKeys {
			if !validAuthorizedKey(key) {
				return fmt.Errorf("%s.authorized_keys[%d] is not a supported single-line public SSH key", prefix, keyIndex)
			}
		}
	}
	if err := validatePHPFPM(value.PHPFPM); err != nil {
		return err
	}
	if err := validateNVM(value.NVM); err != nil {
		return err
	}
	return nil
}

func validateInfrastructure(value InfrastructureConfig) error {
	if reflect.DeepEqual(value, InfrastructureConfig{}) {
		return nil
	}
	if value.Driver != "pvecli" {
		return fmt.Errorf("infrastructure.driver must be pvecli, got %q", value.Driver)
	}
	if !validProjectRelativePath(value.PVECLIConfig) {
		return errors.New("infrastructure.pvecli_config must be a clean project-relative path")
	}
	resourcePattern := regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(?:\["[A-Za-z0-9_-]+"\])?$`)
	if !resourcePattern.MatchString(value.TerraformResource) {
		return errors.New("infrastructure.terraform_resource must name one exact Terraform resource")
	}
	if value.GuestType != "lxc" {
		return fmt.Errorf("infrastructure.guest_type must be lxc, got %q", value.GuestType)
	}
	if value.GuestID < 100 {
		return errors.New("infrastructure.guest_id must be at least 100")
	}
	if value.AnsiblePlaybook != "" && !validProjectRelativePath(value.AnsiblePlaybook) {
		return errors.New("infrastructure.ansible_playbook must be a clean project-relative path")
	}
	if value.InventoryTag != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).MatchString(value.InventoryTag) {
		return errors.New("infrastructure.inventory_tag contains unsupported characters")
	}
	if strings.TrimSpace(value.PublicKey) == "" || strings.ContainsAny(value.PublicKey, "\r\n\x00") {
		return errors.New("infrastructure.public_key must name the operator public-key file")
	}
	return nil
}

func validProjectRelativePath(value string) bool {
	return value != "" && !filepath.IsAbs(value) && filepath.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, ".."+string(filepath.Separator)) && !strings.ContainsAny(value, "\r\n\x00")
}

func validProvisionPath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsAny(value, "\t\r\n")
}

func validProvisionShell(value string) bool {
	if !validProvisionPath(value) {
		return false
	}
	return strings.HasPrefix(value, "/bin/") || strings.HasPrefix(value, "/usr/bin/") || strings.HasPrefix(value, "/usr/sbin/")
}

func validAuthorizedKey(value string) bool {
	if strings.ContainsAny(value, "\r\n") {
		return false
	}
	parts := strings.Fields(value)
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	keyTypes := map[string]bool{"ssh-ed25519": true, "ssh-rsa": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true, "sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true}
	if !keyTypes[parts[0]] {
		return false
	}
	for _, r := range parts[1] {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	if _, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
		return true
	}
	_, err := base64.RawStdEncoding.DecodeString(parts[1])
	return err == nil
}

func validatePHPFPM(value PHPFPM) error {
	if value.Version != "" && !validPHPVersion(value.Version) {
		return fmt.Errorf("provision.php_fpm.version must be major.minor")
	}
	for field, account := range map[string]string{"pool_user": value.PoolUser, "pool_group": value.PoolGroup} {
		if account != "" && !validUnixAccountName(account) {
			return fmt.Errorf("provision.php_fpm.%s contains invalid account %q", field, account)
		}
	}
	if value.PM != "" && value.PM != "dynamic" && value.PM != "ondemand" && value.PM != "static" {
		return fmt.Errorf("provision.php_fpm.pm %q is invalid: expected dynamic, ondemand, or static", value.PM)
	}
	for field, number := range map[string]int{"max_children": value.MaxChildren, "start_servers": value.StartServers, "min_spare_servers": value.MinSpare, "max_spare_servers": value.MaxSpare, "max_requests": value.MaxRequests} {
		if number < 0 {
			return fmt.Errorf("provision.php_fpm.%s must not be negative", field)
		}
	}
	if value.PM == "dynamic" {
		if value.MaxChildren > 0 && value.MaxSpare > value.MaxChildren {
			return errors.New("provision.php_fpm.max_spare_servers must not exceed max_children")
		}
		if value.MinSpare > 0 && value.MaxSpare > 0 && value.MinSpare > value.MaxSpare {
			return errors.New("provision.php_fpm.min_spare_servers must not exceed max_spare_servers")
		}
		if value.StartServers > 0 && value.MaxChildren > 0 && value.StartServers > value.MaxChildren {
			return errors.New("provision.php_fpm.start_servers must not exceed max_children")
		}
	} else if value.StartServers > 0 || value.MinSpare > 0 || value.MaxSpare > 0 {
		return errors.New("provision.php_fpm start_servers and spare server settings require pm: dynamic")
	}
	for field, number := range map[string]int{"memory_consumption": value.Opcache.MemoryConsumption, "interned_strings_buffer": value.Opcache.InternedStringsBuffer, "max_accelerated_files": value.Opcache.MaxAcceleratedFiles, "revalidate_freq": value.Opcache.RevalidateFreq} {
		if number < 0 {
			return fmt.Errorf("provision.php_fpm.opcache.%s must not be negative", field)
		}
	}
	return nil
}

func validPHPVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validateNVM(value NVM) error {
	if value.Version == "" && value.NodeVersion == "" {
		return nil
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(value.Version) {
		return errors.New("provision.nvm.version must be a pinned vMAJOR.MINOR.PATCH release")
	}
	if !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`).MatchString(value.NodeVersion) {
		return errors.New("provision.nvm.node_version must be a numeric Node.js version")
	}
	return nil
}

func validateAccess(name string, group ServerGroup) error {
	switch group.Access.Mode {
	case "", "public":
	default:
		if group.Access.Mode == "private-tailscale" {
			return fmt.Errorf("servers.%s.access.mode private-tailscale is temporarily disabled; use public access until the integration is reintroduced", name)
		}
		return fmt.Errorf("servers.%s.access.mode %q is invalid: expected public", name, group.Access.Mode)
	}
	for _, port := range group.Access.AllowedPublicTCPPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("servers.%s.access.allowed_public_tcp_ports contains invalid port %d", name, port)
		}
		if port == group.Port {
			return fmt.Errorf("servers.%s.access.allowed_public_tcp_ports must not include SSH port %d", name, port)
		}
	}
	// 80 and 443 are required, not exclusive. Requiring the list to be exactly
	// those two made every other listener on the host unreachable and
	// undeclarable at once: the generated firewall opens what this list says,
	// so an analytics container or an internal tool that a host legitimately
	// publishes was cut with no configuration able to say otherwise. What has
	// to stay guaranteed is that the edge can serve, which is the two being
	// present — a shorter list is a host that cannot answer, and that is still
	// refused.
	ports := append([]int(nil), group.Access.AllowedPublicTCPPorts...)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	if !slices.Contains(ports, 80) || !slices.Contains(ports, 443) {
		return fmt.Errorf("servers.%s.access.allowed_public_tcp_ports must contain 80 and 443", name)
	}
	if group.Access.Mode != "private-tailscale" {
		return nil
	}
	if strings.TrimSpace(group.Access.Interface) == "" {
		return fmt.Errorf("servers.%s.access.interface is required for private-tailscale", name)
	}
	if len(group.Access.AllowedUsers) == 0 {
		return fmt.Errorf("servers.%s.access.allowed_users is required for private-tailscale", name)
	}
	if group.Access.DockerAccess == nil || !*group.Access.DockerAccess {
		return fmt.Errorf("servers.%s.access.docker_access must be true: Shuttle executes system Docker commands as the deploy user", name)
	}
	deployUserAllowed := false
	for _, allowedUser := range group.Access.AllowedUsers {
		if !validUnixAccountName(allowedUser) {
			return fmt.Errorf("servers.%s.access.allowed_users contains invalid account %q", name, allowedUser)
		}
		if allowedUser == group.User {
			deployUserAllowed = true
		}
	}
	if group.User != "" && !deployUserAllowed {
		return fmt.Errorf("servers.%s.access.allowed_users must include deploy user %q", name, group.User)
	}
	return nil
}

func validUnixAccountName(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || r == '_' || (i > 0 && ((r >= '0' && r <= '9') || r == '-')) {
			continue
		}
		return false
	}
	return true
}

var secretKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func ValidSecretKey(key string) bool { return secretKeyPattern.MatchString(key) }

// InfrastructureSecretKeys are the credentials Shuttle generates on the host
// itself. They are never held in the local store, and an application secret may
// not borrow one of their names.
var InfrastructureSecretKeys = map[string]bool{"REDIS_PASSWORD": true, "RABBITMQ_PASSWORD": true, "POSTGRES_PASSWORD": true}

// MaxApplicationSecrets bounds what one deploy carries to the host.
const MaxApplicationSecrets = 32

// The accepted values of secrets.backend. They are constants rather than string
// literals repeated at each reader because the choice is consulted in four
// places — the default, the validator, the deploy-time resolver and the helper
// capability it requires — and a backend that three of them agree on and the
// fourth spells differently fails as a missing secret at convergence, which
// names neither the typo nor the file it is in.
const (
	SecretsBackendSwarm     = "swarm"
	SecretsBackendHost      = "host"
	SecretsBackendHashvault = "hashvault"
)

// maxHostSecretsEnvFileLength bounds the path the root helper is asked to open.
const maxHostSecretsEnvFileLength = 512

// UsesHostSecrets reports whether the declared application secrets are read on
// the VPS instead of from the encrypted local store.
func (cfg *Config) UsesHostSecrets() bool {
	return cfg.Secrets.Backend == SecretsBackendHost
}

func (cfg *Config) UsesHashvaultSecrets() bool { return cfg.Secrets.Backend == SecretsBackendHashvault }

// validateSecretsHost holds the host backend to the shape the root helper will
// accept, at the desk rather than over SSH.
//
// The path is refused unless it is absolute and free of traversal. The helper
// re-checks both, because it is a trust boundary and not a second opinion, but
// a configuration error that only surfaces as a refused root operation costs an
// operator a full deploy to read.
func validateSecretsHost(cfg *Config) error {
	path := strings.TrimSpace(cfg.Secrets.Host.EnvFile)
	if !cfg.UsesHostSecrets() {
		if path != "" {
			return errors.New("secrets.host.env_file requires secrets.backend: host")
		}
		return nil
	}
	if len(cfg.ApplicationSecretKeys()) == 0 {
		return errors.New("secrets.backend: host declares no application secret under secrets.items")
	}
	if path == "" {
		return errors.New("secrets.backend: host requires secrets.host.env_file, the path the root helper reads on the VPS")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("secrets.host.env_file %q must be an absolute path on the VPS, not a path on this machine", path)
	}
	if len(path) > maxHostSecretsEnvFileLength {
		return fmt.Errorf("secrets.host.env_file is %d characters, above the %d Shuttle carries", len(path), maxHostSecretsEnvFileLength)
	}
	for _, element := range strings.Split(path, "/") {
		if element == ".." {
			return fmt.Errorf("secrets.host.env_file %q must not traverse directories", path)
		}
	}
	if strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("secrets.host.env_file must not contain control characters")
	}
	return nil
}

// maxApplicationSecretNameLength is what is left for an application secret key
// once the derived Docker Secret name has taken the application, the separators
// and the version fragment.
const maxApplicationSecretNameLength = 40

// ApplicationSecretKeys lists the declared secrets Shuttle carries from the
// local store, sorted, so the same configuration always produces the same
// sequence of operations.
func (cfg *Config) ApplicationSecretKeys() []string {
	keys := make([]string, 0, len(cfg.Secrets.Items))
	for key := range cfg.Secrets.Items {
		// A per-role database password is generated on the host like every
		// other managed credential, so it is not looked for in the local store.
		// Missing this made declaring one stop the deploy with an instruction
		// to store a value Shuttle is the one that creates.
		if InfrastructureSecretKeys[key] || cfg.declaresManagedRoleCredential(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// ExposeMode is how a secret reaches the container. It defaults to file: a
// secret nobody asked to see in the environment stays under /run/secrets.
func (item SecretItem) ExposeMode() string {
	if strings.TrimSpace(item.Expose) == "" {
		return "file"
	}
	return item.Expose
}

// validateManagedCredentialItem checks a credential belonging to a service
// Shuttle provisions itself.
// ManagedRoleSecretTarget is where a declared role's password is mounted. It
// mirrors the name the stack generator emits; both sides derive it from the
// role, so neither can name a file the other does not.
func ManagedRoleSecretTarget(role string) string {
	return "POSTGRES_PASSWORD_" + strings.ToUpper(role)
}

// declaresManagedRoleCredential reports whether a secrets.items key names the
// password of a role this configuration declares.
func (cfg *Config) declaresManagedRoleCredential(key string) bool {
	for _, role := range cfg.Database.Roles {
		if key == ManagedRoleSecretTarget(role.Name) {
			return true
		}
	}
	return false
}

func validateManagedCredentialItem(key string, item SecretItem, cfg *Config) error {
	enabled, backing := false, ""
	switch key {
	case "REDIS_PASSWORD":
		enabled, backing = cfg.Production.Redis, "redis"
	case "RABBITMQ_PASSWORD":
		enabled, backing = cfg.Production.RabbitMQ, "rabbitmq"
	case "POSTGRES_PASSWORD":
		enabled, backing = cfg.Database.Managed(), ""
	}
	if !enabled {
		return fmt.Errorf("secret %s is declared but the service it belongs to is not enabled", key)
	}
	if item.ExposeMode() != "file" {
		// The value is generated on the host and mounted; it is never carried
		// as an environment variable, where it would show in `docker inspect`.
		return fmt.Errorf("secret %s must be exposed as a file, got %q", key, item.Expose)
	}
	if len(item.Services) == 0 {
		return fmt.Errorf("secret %s must name the services that read it", key)
	}
	if item.UID == nil && item.GID != nil {
		return fmt.Errorf("secret %s declares gid without uid; declare both or neither", key)
	}
	for label, value := range map[string]*int{"uid": item.UID, "gid": item.GID} {
		if value != nil && (*value < 0 || *value > maxSecretOwnerID) {
			return fmt.Errorf("secret %s %s is %d, outside the 0..%d range", key, label, *value, maxSecretOwnerID)
		}
	}
	if backing != "" && len(item.Services) == 1 && item.Services[0] == backing {
		// The historical spelling: the credential named only its own service,
		// which mounts it whether or not it is declared.
		return nil
	}
	return nil
}

func validateApplicationSecretItem(key string, item SecretItem) error {
	if len(key) > maxApplicationSecretNameLength {
		return fmt.Errorf("secret %s has a name of %d characters, above the %d that fit in a derived Docker Secret name", key, len(key), maxApplicationSecretNameLength)
	}
	if item.ExposeMode() != "file" && item.ExposeMode() != "env" {
		return fmt.Errorf("secret %s expose must be file or env, got %q", key, item.Expose)
	}
	// Refused rather than clamped: an out-of-range account is a typo, and
	// mounting the file for a different one than the operator wrote would be
	// the silent failure this field exists to remove.
	for label, value := range map[string]*int{"uid": item.UID, "gid": item.GID} {
		if value != nil && (*value < 0 || *value > maxSecretOwnerID) {
			return fmt.Errorf("secret %s %s is %d, outside the 0..%d range", key, label, *value, maxSecretOwnerID)
		}
	}
	if item.UID == nil && item.GID != nil {
		return fmt.Errorf("secret %s declares gid without uid; declare both or neither", key)
	}
	if item.ExposeMode() == "env" && item.UID != nil {
		return fmt.Errorf("secret %s is exposed as env, where file ownership means nothing; drop uid or expose it as a file", key)
	}
	return nil
}

// maxSecretOwnerID is the highest account id a secret may be given. Linux
// allows more, but an id above this is a mistyped uid, not a service account.
const maxSecretOwnerID = 65535

func validateSecretItems(items map[string]SecretItem) error {
	for key, item := range items {
		if !ValidSecretKey(key) {
			return fmt.Errorf("invalid secret key %q: expected [A-Z_][A-Z0-9_]*", key)
		}
		if len(item.Services) == 0 {
			return fmt.Errorf("secret %s services must not be empty", key)
		}
		if item.ExposeMode() != "file" && item.ExposeMode() != "env" {
			return fmt.Errorf("secret %s expose must be file or env, got %q", key, item.Expose)
		}
		seen := map[string]bool{}
		for _, service := range item.Services {
			if strings.TrimSpace(service) == "" {
				return fmt.Errorf("secret %s contains an empty service", key)
			}
			if seen[service] {
				return fmt.Errorf("secret %s lists service %q more than once", key, service)
			}
			seen[service] = true
		}
	}
	return nil
}

// mergeOverlay layers an environment file over a base configuration, using what
// each file actually says rather than what its decoded struct implies.
//
// The previous implementation merged two decoded Configs, which silently
// destroyed the base: a Go struct cannot distinguish "absent" from "zero", so
// every one of the sixty-odd fields an overlay did not restate was marshalled
// as its zero value and overwrote a good value with it. An overlay declaring
// only a domain and a host reset `version` to 0 and the deploy stopped on
// "Shuttle requires version: 2" — which was the lucky case, because it failed
// loudly. `app`, `deploy.retain`, `secrets.backend` and `services.<n>.port`
// have no such guard: they would have been quietly blanked, and the operator
// would have read the consequences off a deployed stack.
//
// Merging the parsed documents instead makes an overlay mean what it looks
// like it means: only the keys it contains are replaced.
func mergeOverlay(basePath, overlayPath string) (*Config, error) {
	baseDocument, err := decodeDocument(basePath)
	if err != nil {
		return nil, err
	}
	overlayDocument, err := decodeDocument(overlayPath)
	if err != nil {
		return nil, err
	}
	deepMerge(baseDocument, overlayDocument)
	merged, err := yaml.Marshal(baseDocument)
	if err != nil {
		return nil, err
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(merged))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// decodeDocument reads a configuration file as the mapping it literally is.
func decodeDocument(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	document := map[string]any{}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	return document, nil
}

func deepMerge(dst map[string]any, src map[string]any) {
	for key, srcVal := range src {
		if srcNested, ok := srcVal.(map[string]any); ok {
			if dstNested, ok := dst[key].(map[string]any); ok {
				deepMerge(dstNested, srcNested)
				continue
			}
		}
		dst[key] = srcVal
	}
}

// AllowedPublicTCPPorts is the sorted, deduplicated set of TCP ports the host
// may expose. It is the single source for the generated firewall rules and for
// the audit that checks them, so the policy applied and the policy verified
// cannot drift apart.
func (cfg *Config) AllowedPublicTCPPorts() []int {
	ports := []int{80, 443}
	for _, group := range cfg.Servers {
		ports = append(ports, group.Access.AllowedPublicTCPPorts...)
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

// The accepted values of caddy.tls_mode. They are constants rather than string
// literals repeated at each reader because three separate places used to decide
// what the default meant on their own — the validator, the label emitted onto
// the published service, and the scheme the root helper renders — and a fourth,
// the origin proof, never asked at all and assumed HTTPS. That disagreement is
// how a plain-HTTP origin behind a CDN was promoted and then declared dead on a
// port nothing was ever asked to listen on.
const (
	TLSModeACME = "acme"
	TLSModeOff  = "off"
)

// EffectiveTLSMode is what the shared edge actually serves for this
// application, with the empty default collapsed onto the mode it means. It is
// the only place anything is allowed to read a TLS mode from, so that "derived
// from configuration" cannot quietly become "assumed by whoever needed it".
//
// The answer is a property of the application and not of a hostname:
// caddy.host_routes carries no tls_mode field, and the root helper decodes one
// dev.shuttle.tls label into a single scheme that it applies to the domain's
// site and to every host route alike. A per-hostname mode would be a capability
// the renderer does not have, so nothing here may pretend to offer one.
func (cfg *Config) EffectiveTLSMode() string {
	if strings.TrimSpace(cfg.Caddy.TLSMode) == TLSModeOff {
		return TLSModeOff
	}
	return TLSModeACME
}

// DomainBasicAuthEnabled reports whether the primary domain imports the
// application's shared Basic Auth gate. An absent value preserves the original
// behavior, where declaring caddy.basic_auth gated the primary domain.
func (cfg *Config) DomainBasicAuthEnabled() bool {
	return cfg.Caddy.DomainBasicAuth == nil || *cfg.Caddy.DomainBasicAuth
}

// TrustedCIDRs is the sorted, deduplicated client allow-list for the shared
// edge. Sorting here is what makes the generated route deterministic: the same
// allow-list has to render the same fragment, or every deploy reloads the edge
// for a change nobody made.
func (cfg *Config) TrustedCIDRs() []string {
	entries := make([]string, 0, len(cfg.Caddy.TrustedCIDRs))
	for _, entry := range cfg.Caddy.TrustedCIDRs {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	slices.Sort(entries)
	return slices.Compact(entries)
}

// CaddyPathRoute sends one path prefix to one service of the same stack.
type CaddyPathRoute struct {
	// Path is a Caddy path matcher such as "/api/*". It is written into the
	// edge configuration verbatim, so it is validated rather than cleaned.
	Path string `yaml:"path" json:"path"`
	// Service is a Compose service of this stack. The edge reaches it by its
	// Swarm DNS name, so it is the service name and not a hostname.
	Service string `yaml:"service" json:"service"`
	Port    int    `yaml:"port" json:"port"`
}

// CaddyHostRoute publishes one more hostname on the application and sends it
// to one service of the same stack. It is the shape of a monorepo whose front
// end, API and back office answer on their own hostnames while being one
// deployable: one stack, one edge network, several sites.
type CaddyHostRoute struct {
	// Host is the extra DNS hostname. It must resolve to the VPS like the
	// domain does, because the shared edge obtains a certificate for it.
	Host string `yaml:"host" json:"host"`
	// Service is a Compose service of this stack, reached by its Swarm DNS name.
	Service string `yaml:"service" json:"service"`
	Port    int    `yaml:"port" json:"port"`
	// PathRoutes are this host's own per-path handlers, with the same rules as
	// caddy.path_routes. Everything unmatched falls through to Service.
	PathRoutes []CaddyPathRoute `yaml:"path_routes,omitempty" json:"path_routes,omitempty"`
	// Headers are this host's own response headers, with the same rules as
	// caddy.headers. The domain's headers do not carry over.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	// HealthPath, when set, is probed on this host after promotion, like the
	// domain's healthcheck path and over the same scheme caddy.tls_mode derives
	// — a host route carries no TLS mode of its own, because the shared edge
	// renders one scheme for every site of an application. Without it only DNS
	// is proven: the host must point at the VPS, but nothing is requested from it.
	HealthPath string `yaml:"health_path,omitempty" json:"health_path,omitempty"`
	// BasicAuth puts this host behind the same gate as the domain: the users
	// of caddy.basic_auth, no others. A host cannot declare its own users,
	// because two lists of who may enter one application is a configuration
	// whose answer nobody can trust.
	BasicAuth bool `yaml:"basic_auth,omitempty" json:"basic_auth,omitempty"`
}

// maxCaddyHostRoutes bounds a label the root-owned edge parses.
const maxCaddyHostRoutes = 16

// maxCaddyBasicAuthUsers bounds a label the root-owned edge parses.
const maxCaddyBasicAuthUsers = 8

// maxCaddyBasicAuthPublicPaths bounds the ungated list for the same reason.
const maxCaddyBasicAuthPublicPaths = 16

// caddyBasicAuthUser and caddyBasicAuthHash are deliberately narrow: both
// values are written into a Caddyfile the root-owned edge loads. A bcrypt hash
// is the only thing Caddy's basic_auth accepts by default, and nothing in its
// alphabet can open a block or end a line.
var caddyBasicAuthUser = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
var caddyBasicAuthHash = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)

// validateCaddyBasicAuth checks the gate the shared edge will enforce. Until
// the route fragment rendered it, a "protected" pre-production was public in
// silence; now that it is rendered, a malformed entry must be refused at the
// desk rather than written into the edge.
func validateCaddyBasicAuth(auth CaddyBasicAuth) error {
	if len(auth.Users) > maxCaddyBasicAuthUsers {
		return fmt.Errorf("caddy.basic_auth.users is limited to %d entries", maxCaddyBasicAuthUsers)
	}
	seen := map[string]bool{}
	for i, user := range auth.Users {
		if user.Username == "" {
			return fmt.Errorf("caddy.basic_auth.users[%d].username is required", i)
		}
		if user.Hash == "" {
			return fmt.Errorf("caddy.basic_auth.users[%d].hash is required", i)
		}
		if !caddyBasicAuthUser.MatchString(user.Username) {
			return fmt.Errorf("caddy.basic_auth.users[%d].username %q must match %s", i, user.Username, caddyBasicAuthUser)
		}
		if seen[user.Username] {
			return fmt.Errorf("caddy.basic_auth.users[%d].username %q is declared twice", i, user.Username)
		}
		seen[user.Username] = true
		if !caddyBasicAuthHash.MatchString(user.Hash) {
			return fmt.Errorf("caddy.basic_auth.users[%d].hash is not a bcrypt hash", i)
		}
	}
	if len(auth.PublicPaths) > 0 && len(auth.Users) == 0 {
		return errors.New("caddy.basic_auth.public_paths needs caddy.basic_auth.users: there is no gate to open")
	}
	if len(auth.PublicPaths) > maxCaddyBasicAuthPublicPaths {
		return fmt.Errorf("caddy.basic_auth.public_paths is limited to %d entries", maxCaddyBasicAuthPublicPaths)
	}
	seenPaths := map[string]bool{}
	for i, path := range auth.PublicPaths {
		if !caddyPathMatcher.MatchString(path) || strings.Contains(path, "..") {
			return fmt.Errorf("caddy.basic_auth.public_paths[%d] %q must be an absolute path matcher like /sw.js or /_next/static/*", i, path)
		}
		if path == "/" || path == "/*" {
			return fmt.Errorf("caddy.basic_auth.public_paths[%d] %q would remove the gate from the whole site", i, path)
		}
		if seenPaths[path] {
			return fmt.Errorf("caddy.basic_auth.public_paths[%d] %q is declared twice", i, path)
		}
		seenPaths[path] = true
	}
	return nil
}

// caddyPathMatcher is deliberately narrow. The value ends up in a Caddyfile
// loaded by the root-owned edge, where a brace or a newline does not fail —
// it opens a block the operator never wrote.
var caddyPathMatcher = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*\*?$`)

// caddyRouteService mirrors the Compose service naming the signed stack uses.
var caddyRouteService = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// maxCaddyHeaders bounds a label the root-owned edge parses.
const maxCaddyHeaders = 16

// caddyHeaderName is deliberately narrow: the value is written into a Caddyfile
// the root edge loads, where a brace or a newline does not fail — it opens a
// block the operator never wrote.
var caddyHeaderName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

func validateCaddyHeaders(headers map[string]string) error {
	return validateCaddyHeadersAt("caddy.headers", headers)
}

// validateCaddyHeadersAt checks one headers map; field names it in errors, so
// a host route's headers are reported where the operator wrote them.
func validateCaddyHeadersAt(field string, headers map[string]string) error {
	if len(headers) > maxCaddyHeaders {
		return fmt.Errorf("%s declares %d headers, above the %d Shuttle carries", field, len(headers), maxCaddyHeaders)
	}
	// Sorted, so two configurations that differ report the same first error and
	// a map's iteration order never decides which one an operator sees.
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !caddyHeaderName.MatchString(name) {
			return fmt.Errorf("%s name %q is not a header name", field, name)
		}
		value := headers[name]
		if len(value) > 1024 {
			return fmt.Errorf("%s value for %s is %d bytes, above the 1024 Shuttle carries", field, name, len(value))
		}
		// Refused rather than escaped: a value that has to be rewritten to be
		// safe is not the value the operator meant to write.
		if strings.ContainsAny(value, "\r\n\x00\"{}") {
			return fmt.Errorf("%s value for %s contains a character that would change the edge configuration", field, name)
		}
		for _, r := range value {
			if r < 0x20 || r > 0x7e {
				return fmt.Errorf("%s value for %s is not printable ASCII", field, name)
			}
		}
	}
	return nil
}

func validateCaddyPathRoutes(routes []CaddyPathRoute) error {
	return validateCaddyPathRoutesAt("caddy.path_routes", routes)
}

// validateCaddyPathRoutesAt checks one path route list; field names it in
// errors, so a host route's paths are reported where the operator wrote them.
func validateCaddyPathRoutesAt(field string, routes []CaddyPathRoute) error {
	if len(routes) > 16 {
		return fmt.Errorf("%s is limited to 16 entries", field)
	}
	seen := map[string]bool{}
	for _, route := range routes {
		if !caddyPathMatcher.MatchString(route.Path) {
			return fmt.Errorf("%s path %q must start with / and hold only unreserved characters, optionally ending in *", field, route.Path)
		}
		if seen[route.Path] {
			return fmt.Errorf("%s declares %q twice: the second entry could never match", field, route.Path)
		}
		seen[route.Path] = true
		if !caddyRouteService.MatchString(route.Service) {
			return fmt.Errorf("%s service %q is not a valid Compose service name", field, route.Service)
		}
		if route.Port < 1 || route.Port > 65535 {
			return fmt.Errorf("%s port %d for %q is out of range", field, route.Port, route.Path)
		}
	}
	return nil
}

// validateCaddyHostRoutes checks the extra hostnames against the domain they
// sit beside. Every value ends up in a label the root-owned edge parses and
// writes into a Caddyfile, so it is validated here, at the desk, with the
// same rules the helper applies again on the host.
//
// gated says whether caddy.basic_auth declares any user: a host that asks for
// the gate when there is none would be published open while claiming otherwise.
func validateCaddyHostRoutes(domain string, routes []CaddyHostRoute, gated bool) error {
	if len(routes) > maxCaddyHostRoutes {
		return fmt.Errorf("caddy.host_routes is limited to %d entries", maxCaddyHostRoutes)
	}
	seen := map[string]bool{}
	for i, route := range routes {
		field := fmt.Sprintf("caddy.host_routes[%d]", i)
		host := route.Host
		if strings.TrimSpace(host) == "" || strings.ContainsAny(host, "/:@ \t\r\n") || host != strings.ToLower(host) {
			return fmt.Errorf("%s.host %q must be one lowercase DNS hostname", field, host)
		}
		if host == domain {
			return fmt.Errorf("%s.host %q is already the application domain", field, host)
		}
		if seen[host] {
			return fmt.Errorf("%s.host %q is declared twice: the second entry could never be served", field, host)
		}
		seen[host] = true
		if !caddyRouteService.MatchString(route.Service) {
			return fmt.Errorf("%s.service %q is not a valid Compose service name", field, route.Service)
		}
		if route.Port < 1 || route.Port > 65535 {
			return fmt.Errorf("%s.port %d for %q is out of range", field, route.Port, host)
		}
		if err := validateCaddyPathRoutesAt(field+".path_routes", route.PathRoutes); err != nil {
			return err
		}
		if err := validateCaddyHeadersAt(field+".headers", route.Headers); err != nil {
			return err
		}
		if path := route.HealthPath; path != "" && (!strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n")) {
			return fmt.Errorf("%s.health_path must be an absolute HTTP path", field)
		}
		if route.BasicAuth && !gated {
			return fmt.Errorf("%s.basic_auth requires caddy.basic_auth.users", field)
		}
	}
	return nil
}
