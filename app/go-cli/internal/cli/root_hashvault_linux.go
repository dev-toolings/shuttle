//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"gopkg.in/yaml.v3"
)

const rootHashvaultConfig = "/etc/shuttle/hashvault.json"

type rootHashvaultEnrollment struct {
	Socket    string `json:"socket"`
	Principal string `json:"principal"`
	KeyFile   string `json:"key_file"`
}

type localHashvaultSession struct {
	client *http.Client
	token  string
}

func readRootHashvaultEnrollment(path string) (rootHashvaultEnrollment, error) {
	var c rootHashvaultEnrollment
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || info.Mode().Perm()&0o077 != 0 {
		return c, errors.New("hashvault enrollment must be a root-owned regular file with mode 0600")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, err
	}
	if !filepath.IsAbs(c.Socket) || !filepath.IsAbs(c.KeyFile) || !strings.HasPrefix(c.Principal, "machine/") || strings.ContainsAny(c.Socket+c.KeyFile+c.Principal, "\r\n\x00") {
		return c, errors.New("invalid hashvault machine enrollment")
	}
	key, err := os.Lstat(c.KeyFile)
	if err != nil {
		return c, err
	}
	keyStat, ok := key.Sys().(*syscall.Stat_t)
	if !ok || !key.Mode().IsRegular() || keyStat.Uid != 0 || key.Mode().Perm()&0o077 != 0 {
		return c, errors.New("hashvault machine key must be root-owned with mode 0600")
	}
	return c, nil
}

func openLocalHashvault(ctx context.Context, c rootHashvaultEnrollment) (*localHashvaultSession, error) {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", c.Socket)
	}}
	s := &localHashvaultSession{client: &http.Client{Transport: transport, Timeout: 10 * time.Minute}}
	var challenge struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	}
	if err := s.call(ctx, "POST", "/v1/auth/challenge", map[string]string{"principal": c.Principal}, &challenge); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("/run", "shuttle-hashvault-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	filename := filepath.Join(dir, "challenge")
	if err := os.WriteFile(filename, []byte(challenge.Message), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-Y", "sign", "-q", "-n", "hashvault-login", "-f", c.KeyFile, filename)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, errors.New("hashvault machine could not sign its authentication challenge")
	}
	signature, err := os.ReadFile(filename + ".sig")
	if err != nil {
		return nil, err
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := s.call(ctx, "POST", "/v1/auth/login", map[string]string{"id": challenge.ID, "principal": c.Principal, "signature": string(signature)}, &login); err != nil {
		return nil, err
	}
	if login.Token == "" {
		return nil, errors.New("hashvault returned no machine session")
	}
	s.token = login.Token
	return s, nil
}

func (s *localHashvaultSession) call(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://hashvault"+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("hashvault local socket is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("hashvault refused %s %s (HTTP %d); verify enrollment, IAM permissions and vault unseal", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
}

func (s *localHashvaultSession) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.call(ctx, "POST", "/v1/auth/logout", nil, nil)
	s.token = ""
	s.client.CloseIdleConnections()
}

func applyRootHashvault(plan rootplan.Plan, payload []byte, out io.Writer) error {
	return withCoordinatedRootOperation(plan, false, func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		if plan.Hashvault == nil || rootplan.PayloadDigest(payload) != plan.Hashvault.PayloadSHA256 {
			return errors.New("hashvault request is incomplete")
		}
		var manifest hashvaultManifest
		if err := json.Unmarshal(payload, &manifest); err != nil {
			return err
		}
		enrollment, err := readRootHashvaultEnrollment(rootHashvaultConfig)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		session, err := openLocalHashvault(ctx, enrollment)
		if err != nil {
			return err
		}
		defer session.close()
		var p hashvaultPreparation
		if err := session.call(ctx, "POST", "/v1/preparations", map[string]any{"target": plan.Hashvault.Target, "manifest": json.RawMessage(payload)}, &p); err != nil {
			return err
		}
		if _, err := hashvaultSecretManifest(p, manifest, plan.Hashvault.Target); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(p)
	})
}

type hashvaultRelease struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	App     string `json:"app"`
	Release string `json:"release"`
}

func hashvaultReleaseFromStack(body []byte) (*hashvaultRelease, error) {
	var stack rootHashvaultStack
	if err := yaml.Unmarshal(body, &stack); err != nil {
		return nil, err
	}
	var result *hashvaultRelease
	for _, service := range stack.Services {
		labels := rawLabelsToStringMap(service.Labels)
		if labels["io.hashvault.preparation"] == "" {
			continue
		}
		item := hashvaultRelease{ID: labels["io.hashvault.preparation"], Target: labels["io.hashvault.target"], App: labels["io.hashvault.app"], Release: rootplan.PayloadDigest(body)}
		if !hashvaultID.MatchString(item.ID) || !hashvaultApp.MatchString(item.Target) || !hashvaultApp.MatchString(item.App) {
			return nil, errors.New("invalid hashvault release labels")
		}
		if result != nil && *result != item {
			return nil, errors.New("stack mixes hashvault preparations")
		}
		result = &item
	}
	return result, nil
}

// errHashvaultNoRelease: the stack carries no Hashvault preparation labels.
// A promotion of an ordinary stack ignores it; an explicit sync reports it,
// because "nothing to confirm" is not "confirmed".
var errHashvaultNoRelease = errors.New(errHashvaultNoReleaseText)

// hashvaultDeferral marks a confirmation that may succeed later without any
// repair: the vault is sealed or unreachable, or the tasks do not serve the
// declared mounts yet. Everything else (unreadable stack, broken enrollment,
// failed write) is a real failure and must not be reported as pending.
type hashvaultDeferral struct{ err error }

func (d *hashvaultDeferral) Error() string { return d.err.Error() }
func (d *hashvaultDeferral) Unwrap() error { return d.err }

func deferHashvault(err error) error {
	if err == nil {
		return nil
	}
	return &hashvaultDeferral{err: err}
}

// Confirmation follows successful convergence, including a rollback. If the
// vault becomes sealed meanwhile, keep a metadata-only retry record. A healthy
// release must not be torn down just because bookkeeping is temporarily offline.
//
// budget bounds the whole confirmation (mount wait and vault calls): it is
// counted in the client's transport deadline, so it must not grow silently.
func confirmRootHashvaultRelease(app, stackFile string, budget time.Duration) error {
	body, err := os.ReadFile(stackFile)
	if err != nil {
		return err
	}
	release, err := hashvaultReleaseFromStack(body)
	if err != nil {
		return err
	}
	if release == nil {
		return errHashvaultNoRelease
	}
	pending := filepath.Join(rootAppStateRoot, app, "hashvault-confirm.json")
	raw, err := json.Marshal(release)
	if err != nil {
		return err
	}
	if err := writeRootFile(pending, raw, 0o600); err != nil {
		return err
	}
	// The pending record is written first on purpose: if the tasks are still
	// rolling, the confirmation stays pending and `shuttle secrets sync`
	// re-checks the mounts before trying again.
	confirmCtx, cancelConfirm := context.WithTimeout(context.Background(), budget)
	defer cancelConfirm()
	if err := waitRootHashvaultMounts(confirmCtx, app, body); err != nil {
		return err
	}
	enrollment, err := readRootHashvaultEnrollment(rootHashvaultConfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(confirmCtx, rootHashvaultVaultCallBudget)
	defer cancel()
	session, err := openLocalHashvault(ctx, enrollment)
	if err != nil {
		return deferHashvault(err)
	}
	defer session.close()
	var active struct {
		Publication *struct {
			ID string `json:"preparation_id"`
		} `json:"publication"`
	}
	if err := session.call(ctx, "GET", "/v1/publications/"+url.PathEscape(release.Target)+"/"+url.PathEscape(release.App), nil, &active); err != nil {
		return deferHashvault(err)
	}
	previous := ""
	if active.Publication != nil {
		previous = active.Publication.ID
	}
	// A 409 means the publication moved between the two calls; the next
	// attempt re-reads it, so it is a deferral too.
	if err := session.call(ctx, "POST", "/v1/preparations/"+release.ID+"/confirm", map[string]string{"release": release.Release, "previous": previous}, nil); err != nil {
		return deferHashvault(err)
	}
	return os.Remove(pending)
}

// syncRootHashvault retries a deferred confirmation.
//
// Returning every failure from the coordinated phase marked the operation
// recovery_required, so one sealed vault fenced every later deploy, rollback
// and sync of the application. Three outcomes are now kept apart:
//
//   - deferral (vault sealed or unreachable, mounts not served yet): nothing
//     needs repair, the phase completes with a warning and the client is told
//     "pending";
//   - no Hashvault preparation on the current release: nothing to do, reported
//     as such, never as "confirmed";
//   - anything else is a real failure and fails the phase. It changed nothing,
//     and `shuttle operations recover` releases it by observation only.
func syncRootHashvault(plan rootplan.Plan, out io.Writer) error {
	outcome := ""
	var deferred error
	err := withCoordinatedRootOperation(plan, false, func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		if plan.Hashvault == nil {
			return errors.New("hashvault sync is incomplete")
		}
		app := plan.Hashvault.App
		stackFile := filepath.Join(rootAppStateRoot, app, "current.yml")
		if err := waitRootStack(app, stackFile, time.Time{}, hashvaultSyncStackWait); err != nil {
			return err
		}
		err := confirmRootHashvaultRelease(app, stackFile, hashvaultSyncConfirmBudget)
		var deferral *hashvaultDeferral
		switch {
		case err == nil:
			outcome = hashvaultSyncConfirmedMarker
		case errors.Is(err, errHashvaultNoRelease):
			outcome = hashvaultSyncNoReleaseMarker
		case errors.As(err, &deferral):
			outcome, deferred = hashvaultSyncPendingMarker, err
			return coord.Warn(err)
		default:
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if deferred != nil {
		rootLog("app=%s hashvault confirmation still pending: %s", plan.Hashvault.App, deferred)
		fmt.Fprintln(os.Stderr, "hashvault confirmation still pending: "+deferred.Error())
	}
	if outcome == hashvaultSyncNoReleaseMarker {
		fmt.Fprintln(os.Stderr, errHashvaultNoRelease.Error())
	}
	_, err = fmt.Fprintln(out, "\n"+outcome)
	return err
}
