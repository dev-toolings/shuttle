package readiness

import (
	"errors"
	"fmt"
	"strconv"

	deployconfig "github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

type Config struct {
	Version int
	App     AppConfig
	Checks  CheckConfig
	Docker  DockerConfig
	Access  AccessConfig
	// Set only by callers that establish Shuttle's container-only application
	// deployment contract. EmptyConfig retains standalone host-runtime audits.
	ContainerizedApplication bool
}
type AppConfig struct{ Domain, HealthcheckPath string }
type CheckConfig struct{ Profile, Ignore []string }
type DockerConfig struct{ AllowDockerSocket, AllowRoot, WorkerServices []string }
type AccessConfig struct {
	Host, Mode                                      string
	SSHPort                                         int
	DeployUser                                      string
	AllowedSSHUsers                                 []string
	TailscaleInterface                              string
	Private                                         bool
	AllowedPublicTCPPorts                           []string
	TailscaleSSH, TailscaleAutoUpdate, DockerAccess *bool
}

func EmptyConfig() Config { return Config{Version: 2} }

func LoadConfig(path string) (Config, string, error) {
	if path == "" {
		found, err := deployconfig.FindDefault()
		if err != nil {
			return EmptyConfig(), "", err
		}
		path = found
	}
	if path == "" {
		return EmptyConfig(), "", errors.New("config.json not found")
	}
	resolved, err := deployconfig.Load(path, "")
	if err != nil {
		return EmptyConfig(), "", err
	}
	group, host, err := readinessServer(resolved)
	if err != nil {
		return EmptyConfig(), "", err
	}
	dockerAccess := false
	cfg := Config{
		ContainerizedApplication: resolved.Deploy.Strategy == "swarm",
		Version:                  2,
		App:                      AppConfig{Domain: readinessDomain(resolved.Domain), HealthcheckPath: resolved.Readiness.HealthcheckPath},
		Checks:                   CheckConfig{Profile: readinessProfiles(resolved), Ignore: append([]string(nil), resolved.Readiness.Ignore...)},
		Docker:                   DockerConfig{WorkerServices: append([]string(nil), resolved.Readiness.WorkerServices...)},
		Access:                   AccessConfig{Host: host, Mode: "public", SSHPort: group.Port, DeployUser: "deploy", AllowedSSHUsers: resolved.AllowedSSHUsers(), DockerAccess: &dockerAccess},
	}
	if resolved.Setup.SwapMode == "host" && !containsString(cfg.Checks.Ignore, "system.swap_missing") {
		cfg.Checks.Ignore = append(cfg.Checks.Ignore, "system.swap_missing")
	}
	if resolved.Setup.AppArmorMode == "host" && !containsString(cfg.Checks.Ignore, "system.apparmor_inactive") {
		cfg.Checks.Ignore = append(cfg.Checks.Ignore, "system.apparmor_inactive")
	}
	for _, port := range group.Access.AllowedPublicTCPPorts {
		cfg.Access.AllowedPublicTCPPorts = append(cfg.Access.AllowedPublicTCPPorts, strconv.Itoa(port))
	}
	return cfg, path, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func readinessServer(cfg *deployconfig.Config) (deployconfig.ServerGroup, string, error) {
	for _, group := range cfg.Servers {
		if len(group.Hosts) == 1 {
			return group, group.Hosts[0], nil
		}
	}
	return deployconfig.ServerGroup{}, "", errors.New("Shuttle readiness requires exactly one VPS")
}

func readinessDomain(value any) string {
	if domain, ok := value.(string); ok {
		return domain
	}
	return fmt.Sprint(value)
}

func readinessProfiles(cfg *deployconfig.Config) []string {
	profiles := []string{"system", "security", "filesystem", "docker", "firewall", "secrets", "reverse-proxy", "ssh", "access", "tls", "dns", "monitoring", "backups", "postgresql"}
	if cfg.Production.Redis {
		profiles = append(profiles, "redis")
	}
	switch cfg.Readiness.Preset {
	case "laravel", "symfony":
		profiles = append(profiles, "php")
	case "nextjs", "node-api", "hono", "fastify", "tanstack-start":
		profiles = append(profiles, "node")
	}
	return profiles
}
