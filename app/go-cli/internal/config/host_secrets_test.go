package config

import (
	"strings"
	"testing"
)

// The credentials of a running server already live on that server. Copying them
// to a workstation so that Shuttle could send them back is a movement with no
// destination: every copy is somewhere else they can leak from.
func TestLoadAcceptsHostBackedSecrets(t *testing.T) {
	cfg, err := loadYAML(t, validConfig+`secrets:
  backend: host
  host:
    env_file: /opt/demo/.env
  items:
    JWT_SECRET_KEY:
      services: [web]
      expose: env
`)
	if err != nil {
		t.Fatalf("the host backend must be accepted: %v", err)
	}
	if !cfg.UsesHostSecrets() {
		t.Fatal("a configuration declaring backend: host must report that it uses it")
	}
	if cfg.Secrets.Host.EnvFile != "/opt/demo/.env" {
		t.Fatalf("the declared path must survive loading, got %q", cfg.Secrets.Host.EnvFile)
	}
}

// A misspelled backend used to be told only what was supported, which is the
// half of the answer the operator already had. Naming both accepted values
// turns the message into the fix.
func TestLoadNamesEveryAcceptedSecretsBackend(t *testing.T) {
	_, err := loadYAML(t, validConfig+`secrets:
  backend: vault
  items:
    JWT_SECRET_KEY:
      services: [web]
`)
	if err == nil || !strings.Contains(err.Error(), "swarm") || !strings.Contains(err.Error(), "host") {
		t.Fatalf("the error must name both accepted backends, got %v", err)
	}
}

// The path is read on the VPS by the root helper. Without one there is nothing
// to read, and the failure would otherwise surface as a refused root operation
// costing a full deploy to see.
func TestHostBackendRequiresThePathItReads(t *testing.T) {
	_, err := loadYAML(t, validConfig+`secrets:
  backend: host
  items:
    JWT_SECRET_KEY:
      services: [web]
`)
	if err == nil || !strings.Contains(err.Error(), "secrets.host.env_file") {
		t.Fatalf("the error must name the missing key, got %v", err)
	}
}

// A relative path would resolve against whatever directory the helper happens
// to run in, which is not a decision anybody made. It is also the spelling an
// operator reaches for when they think the file is read on their own machine.
func TestHostBackendRefusesAPathThatIsNotOnTheServer(t *testing.T) {
	_, err := loadYAML(t, validConfig+`secrets:
  backend: host
  host:
    env_file: .env
  items:
    JWT_SECRET_KEY:
      services: [web]
`)
	if err == nil || !strings.Contains(err.Error(), "absolute path on the VPS") {
		t.Fatalf("a relative path must be refused, got %v", err)
	}
	if _, err := loadYAML(t, validConfig+`secrets:
  backend: host
  host:
    env_file: /opt/demo/../../etc/shadow
  items:
    JWT_SECRET_KEY:
      services: [web]
`); err == nil || !strings.Contains(err.Error(), "traverse directories") {
		t.Fatalf("a traversing path must be refused, got %v", err)
	}
}

// A path declared under the local-store backend is read by nobody. Accepting it
// silently would let an operator believe their credentials stay on the server
// while every one of them is being read off their workstation.
func TestHostPathIsRefusedWithoutTheHostBackend(t *testing.T) {
	_, err := loadYAML(t, validConfig+`secrets:
  backend: swarm
  host:
    env_file: /opt/demo/.env
  items:
    JWT_SECRET_KEY:
      services: [web]
`)
	if err == nil || !strings.Contains(err.Error(), "requires secrets.backend: host") {
		t.Fatalf("a host path without the host backend must be refused, got %v", err)
	}
}

// Naming a backend for a set of secrets that does not exist is a configuration
// that does nothing, and the operator meant it to do something.
func TestHostBackendRequiresDeclaredSecrets(t *testing.T) {
	_, err := loadYAML(t, validConfig+`secrets:
  backend: host
  host:
    env_file: /opt/demo/.env
`)
	if err == nil || !strings.Contains(err.Error(), "declares no application secret") {
		t.Fatalf("expected the empty declaration to be refused, got %v", err)
	}
}
