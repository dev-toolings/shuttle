package cli

import (
	"fmt"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
)

// Nothing on the client ever observed release identity. The two gates that run
// after a promotion — proveDirectOrigin and the availability probe — assert a
// 2xx on the health path plus the shared edge's own headers, and the PREVIOUS
// release answers all of that byte for byte. The cache-busting nonce defeats an
// edge cache, not a stale origin. So a promotion in which zero services
// actually updated was indistinguishable from a complete one, and for an
// internal application it was worse than incomplete: proveDirectOrigin returns
// early with no domain to prove and deploy.availability_url is forbidden, which
// made `shuttle deploy` on an internal stack "submit the signed stack, sleep,
// print complete, exit 0" end to end.
//
// This file closes that. The CLI holds the digests it just published; the
// signed status audit already reports, per service,
// Spec.TaskTemplate.ContainerSpec.Image — which is precisely the field swarmkit
// reverts when it completes a rollback. Comparing the two is the one
// post-promotion check that names the release rather than describing the site.
//
// It runs unconditionally: not behind IsInternal(), not behind
// AvailabilityURL. It is the only gate an internal application can ever have,
// and it is also the only one that works on a host whose root helper predates
// the convergence fix, because it needs no new root capability and no new plan
// field.

// parseStackServiceImages reads the signed status audit, whose rows are
// rootStackStatusFormat (Name, Image, Replicas) and whose last line is the
// helper's own "operation=... digest=..." receipt.
//
// Anything that is not a three-column row is skipped rather than parsed, which
// is what makes the receipt line, a blank line and any future preamble harmless
// instead of a spurious failed deploy.
func parseStackServiceImages(body string) map[string]string {
	images := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		image := strings.TrimSpace(fields[1])
		if name == "" || image == "" {
			continue
		}
		images[name] = image
	}
	return images
}

// compareAppliedReleaseImages returns one complaint per service that is not
// running the release just applied, in stack order, or nil when every service
// is.
//
// Iteration is over the applied stack and never over what the host reports: a
// service `--prune` is removing can still be listed for a moment, and demanding
// that it carry an image the stack no longer declares would fail every deploy
// that drops a service.
//
// The comparison is rootImageMatches, so it is digest against digest wherever
// both sides carry one. That matters twice here. `docker stack services`
// unconditionally strips the digest off a NamedTagged reference, so the
// generated redis and rabbitmq services report redis:7.4.5-alpine with no
// digest at all and are matched on the tagged reference instead. And Shuttle's
// own release images are digest-only — 127.0.0.1:5000/<repo>@sha256:… — so that
// fallback is refused for them, which is what keeps the check meaningful for
// precisely the images that change between two releases.
func compareAppliedReleaseImages(wanted []rootStackService, reported map[string]string) []string {
	complaints := []string{}
	for _, want := range wanted {
		name := want.Service
		if want.Primary {
			name += " (published service)"
		}
		running, listed := reported[want.Service]
		if !listed {
			complaints = append(complaints, fmt.Sprintf("%s: swarm does not report this service", name))
			continue
		}
		if rootImageMatches(want.Image, running) {
			continue
		}
		complaints = append(complaints, fmt.Sprintf("%s: still on %s, this release is %s", name, rootReleaseMarker(running), rootReleaseMarker(want.Image)))
	}
	if len(complaints) == 0 {
		return nil
	}
	return complaints
}

// verifyPromotedRelease asks the host what it is running and refuses to call
// the promotion done unless that is the release that was just applied.
//
// The two halves are treated differently on purpose. A MISMATCH is positive
// evidence that the promotion did not take, so it fails the command. An audit
// that could not be READ is the absence of evidence: the promotion itself has
// already been accepted by a root helper that (since the convergence fix) does
// not return until the running tasks carry the applied images, so failing here
// would turn one flaky SSH read into a failed deploy of a healthy release. It
// is reported loudly instead, because on a host whose helper predates that fix
// this is the only release-identifying check there is.
//
// It does not roll back on failure. The release did not take, which means the
// previous one is what is serving; submitting a rollback on top would re-apply
// a stack that is already running and rotate the retained stack files for
// nothing.
func verifyPromotedRelease(cfg *config.Config, stack string) error {
	wanted, err := rootStackServices(cfg.App, []byte(stack))
	if err != nil {
		return fmt.Errorf("the applied stack could not be read back for verification: %w", err)
	}
	body, err := runSignedStackAudit(cfg, "status", "", 0)
	if err != nil {
		output.Attn("Release identity: not verified (%v); run `shuttle status` to see what is serving", err)
		return nil
	}
	complaints := compareAppliedReleaseImages(wanted, parseStackServiceImages(body))
	if len(complaints) == 0 {
		output.OK("Release identity verified: %d service(s) run the images this deploy published", len(wanted))
		return nil
	}
	return fmt.Errorf("the promoted release is not what is running (the previous release is still serving; nothing was rolled back):\n  %s", strings.Join(complaints, "\n  "))
}
