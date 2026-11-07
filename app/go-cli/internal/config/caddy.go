package config

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

var caddyImageReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+|@sha256:[A-Fa-f0-9]{64})$`)

func validateCaddyImages(value Caddy) error {
	image := strings.TrimSpace(value.Image)
	if image != "" {
		if !caddyImageReference.MatchString(image) || !(strings.HasPrefix(image, "caddy:") || strings.HasPrefix(image, "caddy@sha256:")) {
			return fmt.Errorf("caddy.image must use an official Caddy tag or sha256 digest")
		}
	}
	return nil
}

// CaddyMount is one extra host path made available to the shared edge.
type CaddyMount struct {
	Source   string `yaml:"source" json:"source"`
	Target   string `yaml:"target" json:"target"`
	ReadOnly *bool  `yaml:"read_only,omitempty" json:"read_only,omitempty"`
}

// IsReadOnly defaults to true. A mount into the edge is for serving files, and
// an edge that can write to the host is a much larger blast radius than one
// that cannot, so read-write has to be asked for explicitly.
func (m CaddyMount) IsReadOnly() bool {
	return m.ReadOnly == nil || *m.ReadOnly
}

var (
	dockerObjectName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	envVariableName  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// forbiddenMountSources are host paths that must never reach the edge. Mounting
// any of them hands a container that terminates public TLS either the host's
// identity (/etc, /root), its control plane (/run holds the Docker socket), or
// its kernel interfaces. The list is a floor, not a substitute for review.
var forbiddenMountSources = []string{"/", "/etc", "/root", "/home", "/boot", "/dev", "/proc", "/sys", "/run", "/var/run", "/var/lib/docker", "/usr", "/bin", "/sbin", "/lib"}

// reservedMountTargets are paths the generated stack already owns. Shadowing
// one would silently replace the Caddyfile, the routes, or the certificate
// store with whatever the host happens to hold.
var reservedMountTargets = []string{"/etc/caddy", "/etc/caddy/Caddyfile", "/etc/caddy/conf.d", "/data", "/config", "/run/secrets", "/tmp"}

func validateCaddyRuntime(value Caddy) error {
	// Every value below is validated exactly as written, never trimmed first:
	// validating a cleaned string and then emitting a different one is how a
	// checked configuration turns into an unchecked stack.
	if value.DataVolume != "" && !dockerObjectName.MatchString(value.DataVolume) {
		return fmt.Errorf("caddy.data_volume %q is not a valid Docker volume name", value.DataVolume)
	}
	for index, mount := range value.Mounts {
		prefix := fmt.Sprintf("caddy.mounts[%d]", index)
		source := mount.Source
		target := mount.Target
		if err := validateCleanAbsolutePath(prefix+".source", source); err != nil {
			return err
		}
		if err := validateCleanAbsolutePath(prefix+".target", target); err != nil {
			return err
		}
		if slices.Contains(forbiddenMountSources, source) {
			return fmt.Errorf("%s.source %q is a host path the edge must never mount", prefix, source)
		}
		if slices.Contains(reservedMountTargets, target) {
			return fmt.Errorf("%s.target %q would shadow a path the edge already owns", prefix, target)
		}
	}
	for name, literal := range value.Env {
		if !envVariableName.MatchString(name) {
			return fmt.Errorf("caddy.env key %q must match [A-Z_][A-Z0-9_]*", name)
		}
		if strings.ContainsAny(literal, "\r\n") {
			return fmt.Errorf("caddy.env value for %q must not contain a newline", name)
		}
	}
	for name, secret := range value.SecretEnv {
		if !envVariableName.MatchString(name) {
			return fmt.Errorf("caddy.secret_env key %q must match [A-Z_][A-Z0-9_]*", name)
		}
		if !dockerObjectName.MatchString(secret) {
			return fmt.Errorf("caddy.secret_env[%s] %q is not a valid Docker secret name", name, secret)
		}
		if _, clash := value.Env[name]; clash {
			return fmt.Errorf("caddy.env and caddy.secret_env both define %q", name)
		}
	}
	return nil
}

// validateCleanAbsolutePath rejects anything that is not already the canonical
// form of an absolute path, rather than cleaning it: a value that has to be
// rewritten to be safe is a value the operator did not mean to write.
func validateCleanAbsolutePath(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.ContainsAny(value, "\r\n:") {
		return fmt.Errorf("%s %q must be a clean absolute path", field, value)
	}
	return nil
}
