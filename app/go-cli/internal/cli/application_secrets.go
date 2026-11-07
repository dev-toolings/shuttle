package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/secrets"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// applicationSecretPayloadVersion is the format of the material a deploy sends
// to the root helper.
const applicationSecretPayloadVersion = 1

// maxApplicationSecretBytes bounds one secret. A PEM keypair is a few kilobytes;
// anything of this size is a file that took a wrong turn.
const maxApplicationSecretBytes = 64 * 1024

// maxApplicationSecretPayloadBytes bounds one deploy's worth of material.
const maxApplicationSecretPayloadBytes = 1 << 20

// applicationSecretPayload carries the secret material to the host.
//
// It is the only place a value ever appears: not in the plan, which is signed,
// logged and printed, and not in the stack, which is written to disk on the VPS
// and shown by `--dry-run`. Values are base64 so a PEM key survives the trip
// with its newlines intact.
type applicationSecretPayload struct {
	Version int               `json:"version"`
	App     string            `json:"app"`
	Secrets map[string]string `json:"secrets"`
}

// applicationSecretObjectName is the spelling Docker accepts for a secret name.
var applicationSecretObjectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// applicationSecretSwarmName derives the Docker Secret name from the
// application, the declared key and the store version of the value.
//
// Derived, never supplied: the operator names the secret in their configuration
// and Shuttle names the object. The version fragment is a hash of the store's
// random version identifier, not of the value, so rotating a secret produces a
// new object — which is what makes Swarm roll the service — while the name
// still says nothing about what it holds.
func applicationSecretSwarmName(app, key, version string) (string, error) {
	if strings.TrimSpace(version) == "" {
		return "", fmt.Errorf("secret %s has no version in the local store; run `shuttle secrets set %s` once to version it", key, key)
	}
	digest := sha256.Sum256([]byte(version))
	return swarmSecretObjectName(app, key, hex.EncodeToString(digest[:])[:hostSecretVersionLength])
}

// applicationSecretItems is the subset of secrets.items Shuttle carries from the
// local store. Infrastructure credentials are generated on the host and are
// deliberately absent.
func applicationSecretItems(cfg *config.Config) map[string]config.SecretItem {
	items := map[string]config.SecretItem{}
	for _, key := range cfg.ApplicationSecretKeys() {
		items[key] = cfg.Secrets.Items[key]
	}
	if len(items) == 0 {
		return nil
	}
	return items
}

// resolveApplicationSecrets reads the declared secrets from the encrypted local
// store and returns what the stack needs (names) and what the host needs
// (material), separately.
//
// A declared secret that is missing or empty stops the deploy. An empty
// credential produces a container that starts, authenticates against nothing and
// fails later, which is worse than not deploying.
func resolveApplicationSecrets(cfg *config.Config, store secrets.Store) (secretManifest, []byte, error) {
	keys := cfg.ApplicationSecretKeys()
	if len(keys) == 0 {
		return secretManifest{}, nil, nil
	}
	manifest := secretManifest{Version: applicationSecretPayloadVersion, Secrets: map[string]secretManifestEntry{}}
	payload := applicationSecretPayload{Version: applicationSecretPayloadVersion, App: cfg.App, Secrets: map[string]string{}}
	total := 0
	for _, key := range keys {
		entry, found, err := store.Get(key)
		if err != nil {
			return secretManifest{}, nil, err
		}
		if !found {
			return secretManifest{}, nil, fmt.Errorf("secret %s is declared in secrets.items but is not in the local secret store; run `shuttle secrets set %s`", key, key)
		}
		if entry.Value == "" {
			return secretManifest{}, nil, fmt.Errorf("secret %s is empty in the local secret store", key)
		}
		if len(entry.Value) > maxApplicationSecretBytes {
			return secretManifest{}, nil, fmt.Errorf("secret %s is %d bytes, above the %d Shuttle carries", key, len(entry.Value), maxApplicationSecretBytes)
		}
		// The environment is a flat list of lines. A PEM key exported into it
		// arrives truncated or mangled, so the multi-line case is refused here
		// rather than discovered inside the container.
		if cfg.Secrets.Items[key].ExposeMode() == "env" && strings.ContainsAny(entry.Value, "\n\r") {
			return secretManifest{}, nil, fmt.Errorf("secret %s is multi-line and cannot be exposed as an environment variable; declare expose: file and read it from /run/secrets/%s", key, key)
		}
		total += len(entry.Value)
		if total > maxApplicationSecretPayloadBytes {
			return secretManifest{}, nil, fmt.Errorf("the declared application secrets exceed the %d bytes one deploy carries", maxApplicationSecretPayloadBytes)
		}
		name, err := applicationSecretSwarmName(cfg.App, key, entry.Version)
		if err != nil {
			return secretManifest{}, nil, err
		}
		manifest.Secrets[key] = secretManifestEntry{Name: name, Version: entry.Version}
		payload.Secrets[name] = base64.StdEncoding.EncodeToString([]byte(entry.Value))
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return secretManifest{}, nil, errors.New("encode application secrets")
	}
	return manifest, body, nil
}

func applicationSecretNamespace(app string) string {
	return app + "_"
}

func applicationSecretInNamespace(app, name string) bool {
	return applicationSecretObjectName.MatchString(name) && strings.HasPrefix(name, applicationSecretNamespace(app))
}

func infrastructureSecretName(app, service string) string {
	return applicationSecretNamespace(app) + service + "_password_v1"
}

// parseApplicationSecretPayload re-validates, inside the signed operation,
// everything the client claimed.
//
// Every name is checked against the application in the signed plan, so no
// request can publish a secret another application would read, and the three
// infrastructure credentials are refused outright: they are generated on the
// host and must never arrive from a client.
func parseApplicationSecretPayload(app string, payload []byte) (map[string][]byte, error) {
	if len(payload) == 0 || len(payload) > 2*maxApplicationSecretPayloadBytes {
		return nil, errors.New("application secret payload is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded applicationSecretPayload
	if err := decoder.Decode(&decoded); err != nil {
		return nil, errors.New("application secret payload is not valid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("application secret payload must contain exactly one JSON document")
	}
	if decoded.Version != applicationSecretPayloadVersion {
		return nil, fmt.Errorf("unsupported application secret payload version %d", decoded.Version)
	}
	if decoded.App != app {
		return nil, errors.New("application secret payload names another application")
	}
	if len(decoded.Secrets) == 0 || len(decoded.Secrets) > config.MaxApplicationSecrets {
		return nil, fmt.Errorf("application secret payload must carry between 1 and %d secrets", config.MaxApplicationSecrets)
	}
	resolved := map[string][]byte{}
	for name, encoded := range decoded.Secrets {
		if !applicationSecretInNamespace(app, name) {
			return nil, fmt.Errorf("application secret name %q is not derived from %s", name, app)
		}
		for _, reserved := range []string{infrastructureSecretName(app, "redis"), infrastructureSecretName(app, "rabbitmq"), infrastructureSecretName(app, "postgres")} {
			if name == reserved {
				return nil, fmt.Errorf("application secret %q uses an infrastructure credential name, which is generated on this host", name)
			}
		}
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("application secret %q is not valid base64", name)
		}
		if len(value) == 0 || len(value) > maxApplicationSecretBytes {
			return nil, fmt.Errorf("application secret %q is empty or oversized", name)
		}
		resolved[name] = value
	}
	return resolved, nil
}

// sortedApplicationSecretNames orders the work, so the same payload always
// produces the same sequence of privileged commands.
func sortedApplicationSecretNames(resolved map[string][]byte) []string {
	names := make([]string, 0, len(resolved))
	for name := range resolved {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// resolveDeployApplicationSecrets opens the local store only when the
// configuration declares an application secret. A project that declares none
// never prompts for a passphrase and never touches the store.
//
// Neither does one on the host backend: there is no local store to open, no
// passphrase to ask for and no material to carry, so this returns nothing and
// the names are resolved later, against the host, once the deploy has a signing
// identity. The pre-build check that a declared secret actually exists still
// happens — it just cannot happen here, because only the VPS knows.
func resolveDeployApplicationSecrets(cfg *config.Config) (secretManifest, []byte, error) {
	if cfg.UsesHashvaultSecrets() {
		m, _, err := readHashvaultManifest(cfg)
		if err != nil {
			return secretManifest{}, nil, err
		}
		if cfg.Secrets.Hashvault.Preparation == "" {
			return secretManifest{}, nil, nil
		}
		raw, err := os.ReadFile(cfg.Secrets.Hashvault.Preparation)
		if err != nil {
			return secretManifest{}, nil, err
		}
		var p hashvaultPreparation
		if err := json.Unmarshal(raw, &p); err != nil {
			return secretManifest{}, nil, err
		}
		manifest, err := hashvaultSecretManifest(p, m, cfg.Secrets.Hashvault.Target)
		return manifest, nil, err
	}
	if len(cfg.ApplicationSecretKeys()) == 0 || cfg.UsesHostSecrets() {
		return secretManifest{}, nil, nil
	}
	store, err := applicationSecretStore(cfg)
	if err != nil {
		return secretManifest{}, nil, err
	}
	return resolveApplicationSecrets(cfg, store)
}

// pushApplicationSecrets sends the material to the root helper inside its own
// signed operation, over the same verified transport as the stack.
func pushApplicationSecrets(app string, client *ssh.Client, identity trustedHostIdentity, privateKey ed25519.PrivateKey, payload []byte, operationID string) error {
	plan, err := rootplan.NewSecretsAction(app, rootplan.PayloadDigest(payload), identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 5*time.Minute)
	if err == nil {
		plan, err = bindOperationPlan(plan, operationID, "deploy", app)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return err
	}
	envelope, err := encodeRootHelperEnvelope(plan, payload)
	if err != nil {
		return err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		// The helper's diagnostics name secrets, never their contents.
		return fmt.Errorf("publishing application secrets failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}
