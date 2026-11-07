package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

const (
	BuildRunnerLocal = "local"
	BuildRunnerSSH   = "ssh"
)

// EffectiveRunner resolves the omitted runner to the historical local path.
// Keeping the zero value meaningful means old configurations marshal exactly as
// they did before programmable builders existed.
func (b Build) EffectiveRunner() string {
	if strings.TrimSpace(b.Runner) == "" {
		return BuildRunnerLocal
	}
	return strings.TrimSpace(b.Runner)
}

func (b Build) UsesSSH() bool { return b.EffectiveRunner() == BuildRunnerSSH }

func (b Build) HasSSHSettings() bool {
	return b.Host != "" || b.User != "" || b.Port != 0 || b.HostKey != "" || b.IdentityFile != "" || b.RegistryIdentityFile != ""
}

func validateBuildRunner(cfg *Config) error {
	build := cfg.Build
	switch build.EffectiveRunner() {
	case BuildRunnerLocal:
		if build.HasSSHSettings() {
			return errors.New("build.runner: local is the default and cannot be combined with SSH builder fields")
		}
		return nil
	case BuildRunnerSSH:
		if cfg.UsesCompose() {
			return errors.New("build.runner: ssh is supported only with deploy.strategy: swarm; deploy.strategy: compose has no remote BuildKit path")
		}
		if strings.TrimSpace(build.Host) == "" {
			return errors.New("build.host is required when build.runner is ssh")
		}
		if build.Host != strings.TrimSpace(build.Host) || !validBuildRunnerHost(build.Host) {
			return fmt.Errorf("build.host %q is not a clean SSH hostname or address", build.Host)
		}
		if !validUnixAccountName(build.User) || build.User == "root" {
			return fmt.Errorf("build.user must name a dedicated non-root Unix account, got %q", build.User)
		}
		if build.Port < 1 || build.Port > 65535 {
			return fmt.Errorf("build.port must be between 1 and 65535, got %d", build.Port)
		}
		if !hostKeyFingerprintPattern.MatchString(build.HostKey) {
			return errors.New("build.host_key must be an ED25519 SHA256 fingerprint (SHA256: followed by 43 base64 characters)")
		}
		if err := validateBuildIdentityPath("build.identity_file", build.IdentityFile); err != nil {
			return err
		}
		if isDeployIdentityPath(build.IdentityFile) {
			return errors.New("build.identity_file must be separate from the deploy SSH identity; choose a dedicated builder key")
		}
		if err := validateBuildIdentityPath("build.registry_identity_file", build.RegistryIdentityFile); err != nil {
			return err
		}
		if sameBuildIdentityPath(build.IdentityFile, build.RegistryIdentityFile) {
			return errors.New("build.identity_file and build.registry_identity_file must be separate credentials")
		}
		for name, group := range cfg.Servers {
			if len(group.Hosts) == 1 && sameEndpointHost(build.Host, group.Hosts[0]) {
				return fmt.Errorf("build runner %s targets production server group %q; use a dedicated build guest", build.Host, name)
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported build.runner %q; expected %s or %s", build.Runner, BuildRunnerLocal, BuildRunnerSSH)
	}
}

func validBuildRunnerHost(value string) bool {
	if value == "" || strings.ContainsAny(value, "\r\n\x00/@ \t\\") {
		return false
	}
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		return net.ParseIP(strings.Trim(value, "[]")) != nil
	}
	if strings.Contains(value, ":") {
		return net.ParseIP(value) != nil
	}
	if strings.ContainsAny(value, "*?[]") {
		return false
	}
	return true
}

func validateBuildIdentityPath(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required for runner: ssh", field)
	}
	if value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s must be one private-key path, not key content", field)
	}
	if strings.Contains(value, "-----BEGIN") || strings.Contains(value, "PRIVATE KEY-----") {
		return fmt.Errorf("%s must be a private-key path, not key content", field)
	}
	if filepath.Clean(value) == "." || value == "/" {
		return fmt.Errorf("%s must name a private-key file", field)
	}
	return nil
}

func sameBuildIdentityPath(left, right string) bool {
	if left == right {
		return true
	}
	clean := func(value string) string {
		value = strings.TrimPrefix(value, "~/")
		return filepath.Clean(value)
	}
	return clean(left) == clean(right)
}

func isDeployIdentityPath(value string) bool {
	value = filepath.ToSlash(strings.TrimSpace(value))
	return value == "~/.ssh/id_shuttle" || strings.HasSuffix(value, "/.ssh/id_shuttle")
}

func sameEndpointHost(left, right string) bool {
	normalize := func(value string) string {
		value = strings.TrimSpace(strings.Trim(value, "[]"))
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
		return strings.ToLower(strings.TrimSuffix(value, "."))
	}
	return normalize(left) == normalize(right)
}
