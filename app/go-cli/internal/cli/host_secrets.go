package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// hostSecretsResponseVersion is the format of the answer the root helper sends
// back after reading the declared keys on the VPS.
const hostSecretsResponseVersion = 1

// maxHostSecretsEnvFileBytes bounds the file the helper reads. An environment
// file is a few kilobytes; anything of this size is not one, and the helper
// should say so rather than spend a deploy budget reading it.
const maxHostSecretsEnvFileBytes = 1 << 20

// hostSecretVersionLength is how much of the value digest names the object.
// Twelve hex characters is what the local-store backend already spends on its
// version fragment, and the two backends produce comparable names on purpose:
// an operator reading `docker secret ls` should not be able to tell which
// backend published a secret, because it makes no difference to what is mounted.
const hostSecretVersionLength = 12

// hostSecretVersion is the fragment shape the client accepts back from the
// helper. The client builds a Docker object name out of it, so it is checked
// before it is concatenated, not after the name is refused.
var hostSecretVersion = regexp.MustCompile(`^[a-f0-9]{12}$`)

// hostSecretsResponse is what the helper prints after publishing.
//
// It carries a digest per key and never a value. The client cannot name the
// Docker Secret objects its stack will mount without knowing which version of
// each value the host holds, and a truncated hash answers exactly that question
// and no other: it changes when the value changes, and it discloses nothing
// about what the value is.
type hostSecretsResponse struct {
	Version int               `json:"version"`
	App     string            `json:"app"`
	Secrets map[string]string `json:"secrets"`
	Missing []string          `json:"missing,omitempty"`
}

// hostSecretVersionFragment derives the version of a value from the value.
//
// The local store versions a secret with a random identifier it stores next to
// it, because it can. The host backend has nowhere to keep one: the operator
// edits a plain environment file, and any identifier Shuttle wrote beside it
// would be one more thing to keep in step with an edit nobody told Shuttle
// about. Hashing the value means an edit is the version change.
func hostSecretVersionFragment(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:hostSecretVersionLength]
}

// swarmSecretObjectName composes the Docker Secret name from an application, a
// declared key and an already-derived version fragment.
//
// Both backends end here, so the object naming has one definition. They differ
// only in where the fragment comes from, and that difference must not be able
// to grow into two spellings of the same name — a client that derives one and a
// helper that derives another publish a secret nothing mounts, and the service
// waits for it forever.
func swarmSecretObjectName(app, key, fragment string) (string, error) {
	if !hostSecretVersion.MatchString(fragment) {
		return "", fmt.Errorf("secret %s has an invalid version fragment", key)
	}
	name := applicationSecretNamespace(app) + strings.ToLower(key) + "_v" + fragment
	if len(name) > maxDockerSecretName || !applicationSecretObjectName.MatchString(name) {
		return "", fmt.Errorf("secret %s derives the Docker Secret name %q, which Docker will not accept", key, name)
	}
	return name, nil
}

// parseHostSecretEnvFile extracts exactly the declared keys from an environment
// file, and reports the ones it did not find.
//
// Only the declared keys are read. The file on a real server holds far more
// than the secrets an application declares — database hosts, feature flags,
// whole unrelated sections — and none of that is this operation's business.
// Taking the file wholesale would publish as a credential every line somebody
// ever added to it.
func parseHostSecretEnvFile(body []byte, keys []string) (map[string]string, []string) {
	wanted := map[string]bool{}
	for _, key := range keys {
		wanted[key] = true
	}
	found := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !wanted[key] {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		// A key present but empty is not a key that is present. An empty
		// credential produces a container that starts, authenticates against
		// nothing and fails later, which is worse than not deploying.
		if value == "" {
			continue
		}
		found[key] = value
	}
	missing := []string{}
	for _, key := range keys {
		if _, ok := found[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	return found, missing
}

// parseHostSecretsResponse re-validates the helper's answer before the client
// turns it into object names.
func parseHostSecretsResponse(app string, keys []string, body []byte) (secretManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var decoded hostSecretsResponse
	if err := decoder.Decode(&decoded); err != nil {
		return secretManifest{}, errors.New("the root helper's host secret response is not valid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return secretManifest{}, errors.New("the root helper's host secret response must contain exactly one JSON document")
	}
	if decoded.Version != hostSecretsResponseVersion {
		return secretManifest{}, fmt.Errorf("unsupported host secret response version %d", decoded.Version)
	}
	if decoded.App != app {
		return secretManifest{}, errors.New("the root helper's host secret response names another application")
	}
	if len(decoded.Missing) > 0 {
		return secretManifest{}, fmt.Errorf("secrets.items declares %s, which secrets.host.env_file on the VPS does not set; add them there, or drop them from secrets.items", strings.Join(decoded.Missing, ", "))
	}
	manifest := secretManifest{Version: applicationSecretPayloadVersion, Secrets: map[string]secretManifestEntry{}}
	for _, key := range keys {
		fragment, ok := decoded.Secrets[key]
		if !ok {
			return secretManifest{}, fmt.Errorf("the root helper published no version for secret %s", key)
		}
		name, err := swarmSecretObjectName(app, key, fragment)
		if err != nil {
			return secretManifest{}, err
		}
		manifest.Secrets[key] = secretManifestEntry{Name: name, Version: fragment}
	}
	return manifest, nil
}

// publishHostApplicationSecrets asks the helper to read the declared keys on the
// VPS, publish them, and report their versions.
//
// It runs before the stack that mounts them, for the same reason the local-store
// backend does: a service referencing an external secret that does not exist yet
// never converges.
func publishHostApplicationSecrets(cfg *config.Config, client *ssh.Client, identity trustedHostIdentity, privateKey ed25519.PrivateKey, operationID string) (secretManifest, error) {
	keys := cfg.ApplicationSecretKeys()
	if len(keys) == 0 {
		return secretManifest{}, nil
	}
	plan, err := rootplan.NewHostSecretsAction(cfg.App, cfg.Secrets.Host.EnvFile, keys, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 5*time.Minute)
	if err == nil {
		plan, err = bindOperationPlan(plan, operationID, "deploy", cfg.App)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return secretManifest{}, err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return secretManifest{}, err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		// The helper's diagnostics name keys and paths, never values.
		return secretManifest{}, fmt.Errorf("publishing host secrets failed: %s", strings.TrimSpace(result.Stderr))
	}
	body, err := hostSecretsResponseBody(result.Stdout)
	if err != nil {
		return secretManifest{}, err
	}
	return parseHostSecretsResponse(cfg.App, keys, body)
}

// hostSecretsResponseBody strips the trailing receipt every root operation
// prints, so what is decoded is the JSON the helper produced and nothing else.
func hostSecretsResponseBody(stdout string) ([]byte, error) {
	marker := "\noperation=secrets-host "
	index := strings.LastIndex(stdout, marker)
	if index < 0 {
		return nil, errors.New("the root helper did not answer the host secret request")
	}
	return []byte(strings.TrimSpace(stdout[:index])), nil
}

// dryRunHostSecretManifest names the objects a real deploy would mount, without
// asking the host what it holds.
//
// A dry run is read-only, so it cannot learn the version of a value it is not
// allowed to go and read. It uses a deterministic placeholder instead, exactly
// as the planned images do: the printed stack stays structurally valid and
// passes the same hardening checks, and it does not claim that the object it
// names exists.
func dryRunHostSecretManifest(cfg *config.Config) (secretManifest, error) {
	keys := cfg.ApplicationSecretKeys()
	if len(keys) == 0 {
		return secretManifest{}, nil
	}
	manifest := secretManifest{Version: applicationSecretPayloadVersion, Secrets: map[string]secretManifestEntry{}}
	for _, key := range keys {
		fragment := hostSecretVersionFragment("dry-run/" + cfg.App + "/" + key)
		name, err := swarmSecretObjectName(cfg.App, key, fragment)
		if err != nil {
			return secretManifest{}, err
		}
		manifest.Secrets[key] = secretManifestEntry{Name: name, Version: fragment}
	}
	return manifest, nil
}
