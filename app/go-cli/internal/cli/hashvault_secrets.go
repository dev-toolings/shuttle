package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

type hashvaultSpec struct {
	Expose   string   `json:"expose"`
	Target   string   `json:"target,omitempty"`
	Services []string `json:"services"`
	UID      string   `json:"uid,omitempty"`
	GID      string   `json:"gid,omitempty"`
	Mode     string   `json:"mode,omitempty"`
}

type hashvaultManifest struct {
	Version string                   `json:"version"`
	App     string                   `json:"app"`
	Items   map[string]hashvaultSpec `json:"items"`
}

type hashvaultPreparedItem struct {
	Version    uint64        `json:"version"`
	Spec       hashvaultSpec `json:"spec"`
	ObjectName string        `json:"object_name"`
	ObjectID   string        `json:"object_id"`
}

type hashvaultPreparation struct {
	Version string                           `json:"version"`
	ID      string                           `json:"id"`
	Target  string                           `json:"target"`
	Kind    string                           `json:"kind"`
	Env     string                           `json:"env"`
	App     string                           `json:"app"`
	Items   map[string]hashvaultPreparedItem `json:"items"`
	By      string                           `json:"by"`
	At      string                           `json:"at"`
}

// Confirmation budgets. They live here, outside the linux-only helper, because
// the client's transport deadlines must count them.
//
// During a promotion the confirmation runs inside the signed-stack session,
// whose deadline must stay under the helper's ten-minute watchdog (see
// rootHelperOperationTimeout). It is kept short on purpose: a release whose
// tasks are still rolling keeps its confirmation pending, which is safe, and
// `shuttle secrets sync` waits longer in its own session.
const (
	hashvaultPromotionConfirmBudget = 45 * time.Second
	hashvaultSyncConfirmBudget      = 3*time.Minute + 30*time.Second
	rootHashvaultVaultCallBudget    = 30 * time.Second
	// hashvaultSyncStackWait is syncRootHashvault's convergence check before
	// the confirmation.
	hashvaultSyncStackWait = 30 * time.Second
)

var hashvaultID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hashvaultKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
var hashvaultApp = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var hashvaultFile = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var hashvaultService = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// committedHashvaultManifest returns the manifest bytes as committed at HEAD.
//
// hashvault.json is the reviewed service contract: it decides which services
// receive which secret, with which owner and mode, in production. Signing the
// working copy let a modified or untracked file drive a preparation nobody
// committed. The committed bytes are what gets signed, and a working copy that
// differs is refused instead of silently ignored, so the operator never deploys
// a contract other than the one on screen.
func committedHashvaultManifest(path string) ([]byte, error) {
	local, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read hashvault manifest: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// "HEAD:./name" resolves relative to -C, so the manifest may live in any
	// directory of the repository.
	committed, err := exec.Command("git", "-C", filepath.Dir(abs), "show", "HEAD:./"+filepath.Base(abs)).Output()
	if err != nil {
		return nil, fmt.Errorf("hashvault manifest %s is not committed: commit it before deploying", path)
	}
	if !bytes.Equal(local, committed) {
		return nil, fmt.Errorf("hashvault manifest %s differs from HEAD: commit or revert the change before deploying", path)
	}
	return committed, nil
}

func readHashvaultManifest(cfg *config.Config) (hashvaultManifest, []byte, error) {
	raw, err := committedHashvaultManifest(cfg.Secrets.Hashvault.Manifest)
	if err != nil {
		return hashvaultManifest{}, nil, err
	}
	if len(raw) > 256<<10 {
		return hashvaultManifest{}, nil, errors.New("hashvault manifest exceeds 256 KiB")
	}
	var m hashvaultManifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return m, nil, errors.New("hashvault manifest has trailing data")
	}
	if m.Version != "hv-manifest-1" || !hashvaultApp.MatchString(m.App) || len(m.Items) == 0 {
		return m, nil, errors.New("invalid hashvault manifest")
	}
	for key, spec := range m.Items {
		if err := validateHashvaultSpec(key, spec); err != nil {
			return m, nil, err
		}
	}
	return m, raw, nil
}

func validateHashvaultSpec(key string, spec hashvaultSpec) error {
	if spec.Mode != "" {
		mode, err := strconv.ParseUint(spec.Mode, 8, 32)
		if err != nil || len(spec.Mode) != 4 || spec.Mode[0] != '0' || mode&0o133 != 0 {
			return errors.New("invalid hashvault file mode")
		}
	}
	if !hashvaultKey.MatchString(key) || len(spec.Services) == 0 || (spec.Expose != "env" && spec.Expose != "file") {
		return fmt.Errorf("invalid hashvault contract for %s", key)
	}
	if spec.Target != "" && (!hashvaultFile.MatchString(spec.Target) || (spec.Expose == "env" && spec.Target != strings.ToLower(key))) {
		return fmt.Errorf("invalid hashvault mount for %s", key)
	}
	for _, service := range spec.Services {
		if !hashvaultService.MatchString(service) {
			return errors.New("invalid hashvault service")
		}
	}
	for _, owner := range []string{spec.UID, spec.GID} {
		if owner != "" {
			if _, err := strconv.ParseUint(owner, 10, 32); err != nil {
				return errors.New("invalid hashvault file owner")
			}
		}
	}
	return nil
}

// Only metadata travels to the manager. The signed digest binds the exact
// application contract to the operator's authenticated deployment operation.
func prepareHashvaultSecrets(cfg *config.Config, client *ssh.Client, identity trustedHostIdentity, key ed25519.PrivateKey, operationID string) (secretManifest, error) {
	m, raw, err := readHashvaultManifest(cfg)
	if err != nil {
		return secretManifest{}, err
	}
	plan, err := rootplan.NewHashvaultAction(cfg.App, cfg.Secrets.Hashvault.Target, rootplan.PayloadDigest(raw), identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 5*time.Minute)
	if err == nil {
		plan, err = bindOperationPlan(plan, operationID, "deploy", cfg.App)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, key)
	}
	if err != nil {
		return secretManifest{}, err
	}
	envelope, err := encodeRootHelperEnvelope(plan, raw)
	if err != nil {
		return secretManifest{}, err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		return secretManifest{}, fmt.Errorf("preparing hashvault secrets failed: %s", strings.TrimSpace(result.Stderr))
	}
	marker := strings.LastIndex(result.Stdout, "\noperation=secrets-hashvault ")
	if marker < 0 {
		return secretManifest{}, errors.New("root helper did not return a hashvault preparation")
	}
	var p hashvaultPreparation
	decoder := json.NewDecoder(strings.NewReader(result.Stdout[:marker]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return secretManifest{}, err
	}
	return hashvaultSecretManifest(p, m, cfg.Secrets.Hashvault.Target)
}

func hashvaultSecretManifest(p hashvaultPreparation, m hashvaultManifest, target string) (secretManifest, error) {
	if p.Version != "hv-preparation-1" || !hashvaultID.MatchString(p.ID) || p.Kind != "swarm" || p.Target != target || p.App != m.App || len(p.Items) != len(m.Items) {
		return secretManifest{}, errors.New("hashvault preparation does not match the signed contract")
	}
	out := secretManifest{Version: applicationSecretPayloadVersion, Secrets: map[string]secretManifestEntry{}, Hashvault: &p}
	for key, expected := range m.Items {
		if err := validateHashvaultSpec(key, expected); err != nil {
			return out, err
		}
		item, ok := p.Items[key]
		if !ok || item.Version == 0 || item.ObjectID == "" || item.ObjectName != "hv_"+p.App+"_"+item.Spec.Target+"_v"+strconv.FormatUint(item.Version, 10) || len(item.ObjectName) > 64 {
			return out, errors.New("invalid hashvault secret reference")
		}
		if expected.Target == "" {
			expected.Target = strings.ToLower(key)
		}
		if expected.UID == "" {
			expected.UID = "0"
		}
		if expected.GID == "" {
			expected.GID = "0"
		}
		if expected.Mode == "" {
			expected.Mode = "0400"
		}
		a, _ := json.Marshal(expected)
		b, _ := json.Marshal(item.Spec)
		if !bytes.Equal(a, b) {
			return out, errors.New("hashvault changed the declared mounts or owners")
		}
		out.Secrets[key] = secretManifestEntry{Name: item.ObjectName, Version: strconv.FormatUint(item.Version, 10)}
	}
	return out, nil
}

func hashvaultSecretItems(p *hashvaultPreparation) map[string]config.SecretItem {
	out := map[string]config.SecretItem{}
	for key, item := range p.Items {
		uid, _ := strconv.Atoi(item.Spec.UID)
		gid, _ := strconv.Atoi(item.Spec.GID)
		out[key] = config.SecretItem{Services: item.Spec.Services, Expose: item.Spec.Expose, UID: &uid, GID: &gid}
	}
	return out
}

func rawLabelsToStringMap(raw any) map[string]string {
	out := map[string]string{}
	switch labels := raw.(type) {
	case map[string]any:
		for key, value := range labels {
			out[key] = fmt.Sprint(value)
		}
	case map[string]string:
		for key, value := range labels {
			out[key] = value
		}
	case []any:
		for _, value := range labels {
			key, val, _ := strings.Cut(fmt.Sprint(value), "=")
			out[key] = val
		}
	}
	return out
}

// Replace owned references and legacy mounts on the same file targets. Other
// application secrets stay in the stack. This also removes a key which was
// deleted from hashvault.json without touching a foreign mount.
func removeHashvaultMounts(raw any, service string, p *hashvaultPreparation) []any {
	targets := map[string]bool{}
	for _, item := range p.Items {
		if slices.Contains(item.Spec.Services, service) {
			targets[item.Spec.Target] = true
		}
	}
	refs, _ := raw.([]any)
	out := []any{}
	for _, ref := range refs {
		source, target := "", ""
		switch value := ref.(type) {
		case string:
			source, target = value, value
		case map[string]any:
			source = fmt.Sprint(value["source"])
			if value["target"] != nil {
				target = fmt.Sprint(value["target"])
			} else {
				target = source
			}
		}
		if !targets[target] && !strings.HasPrefix(source, "hv_"+p.App+"_") {
			out = append(out, ref)
		}
	}
	return out
}
