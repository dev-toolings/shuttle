//go:build linux

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

// applyRootHostSecrets publishes, as Docker Secrets, the declared keys read from
// a file the VPS already holds, and answers with the version of each.
//
// This is the one operation that opens a path the caller named, so it is also
// the one that has to be careful about what a path can be. It refuses a symlink,
// anything that is not a regular file, and a file the world can write: the first
// two because the path an operator signed should resolve to the file they meant,
// and the third because a credential is only worth what the weakest account able
// to rewrite it is worth.
//
// No value is written anywhere but into `docker secret create` — not to disk,
// not to the log, not into an error message, and not into the answer, which
// carries digests.
func applyRootHostSecrets(plan rootplan.Plan, out io.Writer) error {
	return withCoordinatedRootOperation(plan, false, func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		if plan.HostSecrets == nil {
			return fmt.Errorf("host secrets operation is incomplete")
		}
		app := plan.HostSecrets.App
		body, err := readHostSecretsEnvFile(plan.HostSecrets.EnvFile)
		if err != nil {
			return err
		}
		found, missing := parseHostSecretEnvFile(body, plan.HostSecrets.Keys)
		versions := map[string]string{}
		names := make([]string, 0, len(found))
		byName := map[string][]byte{}
		for key, value := range found {
			fragment := hostSecretVersionFragment(value)
			name, err := swarmSecretObjectName(app, key, fragment)
			if err != nil {
				return err
			}
			versions[key] = fragment
			names = append(names, name)
			byName[name] = []byte(value)
		}
		// Sorted, so the same file always produces the same sequence of
		// privileged commands.
		sort.Strings(names)
		for _, name := range names {
			// The name carries the version of the value, so an existing secret
			// already holds exactly what this operation would write. Docker
			// secrets are immutable; an edited value arrives under a new name.
			if exec.Command("/usr/bin/docker", "secret", "inspect", name).Run() == nil {
				continue
			}
			command := exec.Command("/usr/bin/docker", "secret", "create", "--label", shuttleOwnerLabel+"="+app, name, "-")
			command.Stdin = bytes.NewReader(byName[name])
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			output, err := command.CombinedOutput()
			if err != nil {
				// docker prints the name it was given, never the material it
				// read from stdin.
				return fmt.Errorf("create host secret %s: %s", name, strings.TrimSpace(string(output)))
			}
		}
		answer, err := json.Marshal(hostSecretsResponse{Version: hostSecretsResponseVersion, App: app, Secrets: versions, Missing: missing})
		if err != nil {
			return fmt.Errorf("encode host secret response")
		}
		fmt.Fprintf(out, "%s\n", answer)
		return nil
	})
}

// readHostSecretsEnvFile opens the declared path without following a symlink
// and returns its bytes.
//
// O_NOFOLLOW covers the final element only, which is the element an attacker
// with write access to the directory can swap. The directories above it are
// root-owned on a converged host, and a helper that tried to audit every
// component would be re-implementing a guarantee the filesystem already gives.
func readHostSecretsEnvFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// The path is in the signed plan, so naming it discloses nothing the
		// operator did not already write, and an operator debugging a refused
		// deploy needs to see which path the helper actually tried.
		return nil, fmt.Errorf("open host secrets env_file %s: it must exist on this host and must not be a symlink", path)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat host secrets env_file %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("host secrets env_file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("host secrets env_file %s is world-writable (mode %#o); a credential is worth what the weakest account able to rewrite it is worth", path, info.Mode().Perm())
	}
	if info.Size() > maxHostSecretsEnvFileBytes {
		return nil, fmt.Errorf("host secrets env_file %s is %d bytes, above the %d Shuttle reads", path, info.Size(), maxHostSecretsEnvFileBytes)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxHostSecretsEnvFileBytes+1))
	if err != nil || len(body) > maxHostSecretsEnvFileBytes {
		return nil, fmt.Errorf("read host secrets env_file %s", path)
	}
	return body, nil
}
