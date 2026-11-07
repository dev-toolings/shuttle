//go:build linux

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// rootEmergencyInfrastructureReadBudget bounds every docker read the emergency
// rollback makes to learn what Redis and RabbitMQ run. It sits inside the
// client's SSH deadline, which is still counting, so a daemon that does not
// answer costs seconds and not minutes. Running out of it is not an excuse to
// downgrade: an unread service blocks the rollback (see below). A variable so
// a test can prove the shared deadline without waiting for it.
var rootEmergencyInfrastructureReadBudget = 6 * time.Second

// rootEmergencyRollbackManifestName is the temporary manifest carrying the
// decision, kept beside effective.yml in the root-owned state directory.
const rootEmergencyRollbackManifestName = "emergency-rollback.yml"

// rootEmergencyDockerRead is a variable so the decision is testable without a
// Docker daemon, as the recovery runtime does with its dockerRead.
var rootEmergencyDockerRead infrastructureDockerRead = rootDockerRead

// rootEmergencyLog is rootLog, replaceable so a test can read the journal lines
// a decision leaves behind.
var rootEmergencyLog = rootLog

// emergencyLiveImage is the only shape a running image may have to be written
// into the rollback manifest: a plain reference, nothing a YAML scalar or a
// docker argument could read differently.
var emergencyLiveImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)

// emergencyRollbackManifest decides which manifest explicit and emergency
// rollback deploy, and returns it with a cleanup to run once the
// attempt is over. ok=false means: do not run `docker stack deploy` at all.
//
// DEV-DEPL-46 (VM, 2026-10-27): previous.yml pinned redis 8.10.1 while the
// service had been updated to 8.10.3; a deploy whose web server died at start
// failed promotion and this path redeployed previous.yml as is, which
// downgraded Redis on its persistent data. Reapplying an older stateful image
// over newer data can corrupt it, and the emergency path cannot refuse the way
// `operations recover` does: the release is already failing, so there is no
// operator to ask. Leaving a stateful service on the image it runs is the one
// choice that cannot damage its data, so that is the default, and recover or
// the next deploy remain the explicit, journaled paths to change it.
//
// For each Redis or RabbitMQ service the rollback manifest declares, the live
// image (the service's current spec) is read and compared with the manifest's:
//
//   - the manifest image is applied only when both are official images pinned
//     by digest, same major, and the manifest version is strictly newer;
//   - in every other case the live image is written into a NEW manifest and
//     the reason is journaled. A major change is thus never applied silently;
//   - a service Docker does not know has nothing to
//     protect and keeps the manifest image.
//
// Nominal case (every live image equals the manifest's, or no live service):
// the returned file is rollbackFile itself, byte for byte what runs today, and
// nothing is written. previous.yml and current.yml are never touched here: the
// adjusted manifest is a separate 0600 file in the state directory.
//
// The rollback FAILS CLOSED. It is skipped and logged loudly when the manifest
// cannot be read or parsed, when a service's live image could not be read (so
// there is nothing to keep), or when a service needed protection and the
// adjusted manifest cannot be built or verified. Falling back to the
// unadjusted manifest would be the downgrade this exists to prevent; the
// failing release keeps serving, which is the state the operator already has
// to deal with. An unreadable or unparseable manifest is not a harmless case
// either: rootStackServices is stricter than docker (lowercase names, digest
// pins), so a manifest it rejects may still be valid for docker and would
// bypass the protection. previous.yml is always a copy of a current.yml that
// passed validateRetainedRootStack, so a failure here means corruption or an
// unexpected shape, never a normal input.
func emergencyRollbackManifest(root, app, rollbackFile string) (file string, cleanup func(), ok bool) {
	noop := func() {}
	body, err := os.ReadFile(rollbackFile)
	if err != nil {
		rootEmergencyLog("app=%s emergency rollback SKIPPED: cannot read %s, so the running Redis/RabbitMQ cannot be protected from a downgrade (%v); the failing release keeps serving", app, rollbackFile, err)
		return "", noop, false
	}
	services, err := rootStackServices(app, body)
	if err != nil {
		rootEmergencyLog("app=%s emergency rollback SKIPPED: %s is not in the shape the helper validated (%v), so the running Redis/RabbitMQ cannot be protected from a downgrade; the failing release keeps serving", app, rollbackFile, err)
		return "", noop, false
	}
	retained := make(map[string]string, len(services))
	for _, service := range services {
		retained[service.Name] = service.Image
	}
	ctx, cancel := context.WithTimeout(context.Background(), rootEmergencyInfrastructureReadBudget)
	defer cancel()

	keep := make(map[string]recoveryInfrastructureImageProof)
	var unreadable []string
	for _, runtime := range infrastructureRuntimes {
		retainedImage, present := retained[runtime.service]
		if !present {
			continue
		}
		assessment := assessInfrastructureService(ctx, rootEmergencyDockerRead, app, runtime, retainedImage)
		switch assessment.Verdict {
		case infrastructureImageUseRetained:
			rootEmergencyLog("app=%s emergency rollback applies %s %s (live %s): same major, retained version %s is newer than live %s", app, runtime.service, retainedImage, assessment.Live, assessment.RetainedVersion, assessment.LiveVersion)
		case infrastructureImageKeepLive:
			keep[runtime.service] = recoveryInfrastructureImageProof{Live: assessment.Live, Retained: retainedImage}
			rootEmergencyLog("app=%s emergency rollback keeps %s %s instead of retained %s: same major, live version %s is not older than retained %s", app, runtime.service, assessment.Live, retainedImage, assessment.LiveVersion, assessment.RetainedVersion)
		case infrastructureImageRefused:
			if assessment.Live == "" || !emergencyLiveImage.MatchString(assessment.Live) {
				unreadable = append(unreadable, fmt.Sprintf("%s: %s", runtime.service, assessment.Refusal))
				continue
			}
			keep[runtime.service] = recoveryInfrastructureImageProof{Live: assessment.Live, Retained: retainedImage}
			rootEmergencyLog("app=%s emergency rollback keeps %s %s instead of retained %s: %s", app, runtime.service, assessment.Live, retainedImage, assessment.Refusal)
		}
	}
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		rootEmergencyLog("app=%s emergency rollback SKIPPED: the running image of a stateful service could not be established, and redeploying the previous release could downgrade its data (%s); the failing release keeps serving, run `shuttle operations recover` or redeploy by hand", app, strings.Join(unreadable, "; "))
		return "", noop, false
	}
	if len(keep) == 0 {
		return rollbackFile, noop, true
	}

	adjusted, err := replaceKeptInfrastructureImages(body, keep)
	if err == nil {
		err = validateOnlyKeptInfrastructureImagesDiffer(body, adjusted, keep)
	}
	if err == nil {
		// The exact bytes that will be deployed, and waited on afterwards:
		// waitRootStack reads the same file, so it must still parse as a
		// digest-pinned stack.
		_, err = rootStackServices(app, adjusted)
	}
	path := filepath.Join(root, rootEmergencyRollbackManifestName)
	if err == nil {
		err = writeRootFile(path, adjusted, 0o600)
	}
	if err != nil {
		_ = os.Remove(path)
		rootEmergencyLog("app=%s emergency rollback SKIPPED: cannot build the manifest that keeps the running Redis/RabbitMQ (%v); redeploying the previous release as is could downgrade stateful data, so the failing release keeps serving", app, err)
		return "", noop, false
	}
	return path, func() { _ = os.Remove(path) }, true
}
