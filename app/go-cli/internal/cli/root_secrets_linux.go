//go:build linux

package cli

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

// applyRootSecrets publishes an application's declared secrets as Docker
// Secrets, from material that arrived inside a signed operation.
//
// Nothing here writes a value anywhere but into `docker secret create`: not to
// disk, not to the log, not into an error message. The names are re-derived from
// the application in the signed plan, so one application can never publish a
// secret another one would mount.
func applyRootSecrets(plan rootplan.Plan, payload []byte) error {
	return withCoordinatedRootOperation(plan, false, func() error {
		if err := verifyRootOperationIdentity(plan); err != nil {
			return err
		}
		if plan.Secrets == nil {
			return fmt.Errorf("secrets operation is incomplete")
		}
		resolved, err := parseApplicationSecretPayload(plan.Secrets.App, payload)
		if err != nil {
			return err
		}
		for _, name := range sortedApplicationSecretNames(resolved) {
			// The name carries the version of the value, so an existing secret
			// already holds exactly what this operation would write. Docker
			// secrets are immutable; a changed value arrives under a new name.
			if exec.Command("/usr/bin/docker", "secret", "inspect", name).Run() == nil {
				continue
			}
			command := exec.Command("/usr/bin/docker", "secret", "create", "--label", shuttleOwnerLabel+"="+plan.Secrets.App, name, "-")
			command.Stdin = bytes.NewReader(resolved[name])
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			output, err := command.CombinedOutput()
			if err != nil {
				// docker prints the name it was given, never the material it read
				// from stdin.
				return fmt.Errorf("create application secret %s: %s", name, strings.TrimSpace(string(output)))
			}
		}
		return nil
	})
}
