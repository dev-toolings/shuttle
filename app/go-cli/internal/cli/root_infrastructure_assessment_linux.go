//go:build linux

package cli

import (
	"context"
	"fmt"
	"strings"
)

// infrastructureDockerRead is the read-only docker seam shared by the two
// paths that decide what to do with a running Redis or RabbitMQ: `operations
// recover` and the emergency rollback of a failed promotion.
type infrastructureDockerRead func(context.Context, ...string) (string, error)

type infrastructureImageVerdict int

const (
	// infrastructureImageAbsent: the service does not exist yet, so there is
	// no running data to protect and the manifest image stands.
	infrastructureImageAbsent infrastructureImageVerdict = iota
	// infrastructureImageSame: the running and the manifest image are identical.
	infrastructureImageSame
	// infrastructureImageKeepLive: official, digest-pinned, same major, and
	// the running version is equal or newer than the manifest's.
	infrastructureImageKeepLive
	// infrastructureImageUseRetained: same conditions, and the manifest's
	// version is strictly newer than the running one.
	infrastructureImageUseRetained
	// infrastructureImageRefused: the manifest image cannot be applied over
	// what runs without a decision only an operator can take (major change,
	// unofficial or unpinned image, unreadable version, docker error).
	// Refusal says why, in the wording `operations recover` has always used.
	infrastructureImageRefused
)

type infrastructureImageAssessment struct {
	Verdict         infrastructureImageVerdict
	Live            string
	Retained        string
	LiveVersion     string
	RetainedVersion string
	Refusal         string
}

// assessInfrastructureService compares what a stateful infrastructure service
// runs now with the image a retained manifest would put back. It reads local
// docker metadata only (service spec, image configuration) and never contacts a
// registry. The retained image is passed untouched: it is echoed verbatim in
// the proofs and refusals recovery journals.
//
// The decision lives here, once, because recovery and the emergency rollback
// must agree on what "newer", "same major" and "official" mean: two copies
// would drift, and the drift would be a data downgrade on one path only.
func assessInfrastructureService(ctx context.Context, read infrastructureDockerRead, app string, runtime infrastructureRuntime, retainedImage string) infrastructureImageAssessment {
	serviceName := app + "_" + runtime.service
	result := infrastructureImageAssessment{Retained: retainedImage}
	refuse := func(message string) infrastructureImageAssessment {
		result.Verdict = infrastructureImageRefused
		result.Refusal = message
		return result
	}
	liveImage, err := read(ctx, "service", "inspect", "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}", serviceName)
	if err != nil {
		if dockerObjectAbsent("service", serviceName, err.Error()) {
			result.Verdict = infrastructureImageAbsent
			return result
		}
		return refuse(fmt.Sprintf("cannot inspect running %s service %s: %v", runtime.service, serviceName, err))
	}
	liveImage = strings.TrimSpace(liveImage)
	if liveImage == "" {
		return refuse(fmt.Sprintf("cannot inspect running %s service %s: Docker returned an empty image", runtime.service, serviceName))
	}
	result.Live = liveImage
	if liveImage == strings.TrimSpace(retainedImage) {
		result.Verdict = infrastructureImageSame
		return result
	}
	if err := validateRecoveryInfrastructureImage(runtime, liveImage); err != nil {
		return refuse(refusalToReplaceInfrastructure(runtime.service, liveImage, retainedImage, err))
	}
	if err := validateRecoveryInfrastructureImage(runtime, retainedImage); err != nil {
		return refuse(refusalToReplaceInfrastructure(runtime.service, liveImage, retainedImage, err))
	}
	liveVersion, err := readRecoveryInfrastructureVersion(ctx, read, runtime, "live", liveImage)
	if err != nil {
		return refuse(err.Error())
	}
	retainedVersion, err := readRecoveryInfrastructureVersion(ctx, read, runtime, "retained", retainedImage)
	if err != nil {
		return refuse(err.Error())
	}
	result.LiveVersion, result.RetainedVersion = liveVersion, retainedVersion
	liveParts, liveOK := parseInfrastructureVersion(liveVersion)
	retainedParts, retainedOK := parseInfrastructureVersion(retainedVersion)
	if !liveOK {
		return refuse(fmt.Sprintf("cannot read the version of live %s %s: version %q is not a release version", runtime.service, liveImage, liveVersion))
	}
	if !retainedOK {
		return refuse(fmt.Sprintf("cannot read the version of retained %s %s: version %q is not a release version", runtime.service, retainedImage, retainedVersion))
	}
	if liveParts[0] != retainedParts[0] {
		change := fmt.Errorf("major change %s -> %s requires an explicit data migration", liveVersion, retainedVersion)
		return refuse(refusalToReplaceInfrastructure(runtime.service, liveImage, retainedImage, change))
	}
	if compareInfrastructureVersions(liveParts, retainedParts) >= 0 {
		result.Verdict = infrastructureImageKeepLive
		return result
	}
	result.Verdict = infrastructureImageUseRetained
	return result
}
