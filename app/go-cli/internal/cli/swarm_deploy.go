package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"gopkg.in/yaml.v3"
)

func singleVPS(cfg *config.Config) (config.ServerGroup, string, error) {
	for _, group := range cfg.Servers {
		if len(group.Hosts) == 1 {
			return group, group.Hosts[0], nil
		}
	}
	return config.ServerGroup{}, "", errors.New("Shuttle requires exactly one VPS")
}

type stackRefusedBeforeMutation struct {
	reason  string
	message string
}

func (e *stackRefusedBeforeMutation) Error() string { return e.message }

func stackPromotionError(stderr string) error {
	message := "signed stack promotion failed: " + strings.TrimSpace(stderr)
	if reason, ok := refusedBeforeMutationReason(stderr); ok {
		return &stackRefusedBeforeMutation{reason: reason, message: message}
	}
	return errors.New(message)
}

func recordStackPromotionRefusal(operation *remoteOperation, err error) {
	var refusal *stackRefusedBeforeMutation
	if operation != nil && errors.As(err, &refusal) {
		operation.refusedBeforeMutation = true
		operation.refusalReason = refusal.reason
	}
}

// rootHelperOperationMargin is what the client allows the privileged helper on
// top of the two waits the signed plan authorises: the registry sweep, the
// image-store prune and the round trips around them. It is generous on purpose,
// because being wrong in this direction produces a client-side timeout on a
// deploy that worked, with no diagnosis at all.
const rootHelperOperationMargin = 2 * time.Minute

// rootHelperOperationTimeout is how long one signed stack operation may hold its
// SSH session.
//
// The two waits that run under the root-operation lock are stack convergence
// and the shared-edge reload; the client's deadline has to cover both plus the
// housekeeping that follows, or an honest convergence wait starts failing
// deploys that succeed. The Hashvault confirmation runs in the same session
// after promotion and is counted too (45 s; zero work for other backends, but
// a longer client deadline costs nothing). At the 600 s ceiling this yields
// 420 + 45 + 120 = 585 s,
// which stays inside the helper's own ten-minute watchdog, so when something
// really is stuck, the message the operator gets is the helper's, which names
// the service, rather than an opaque "SSH operation timed out".
func rootHelperOperationTimeout(promotionSLOSeconds int) time.Duration {
	// The 2026-10-28 Ubuntu 24.04 and Debian 13 first-release deploys showed a
	// cold RabbitMQ task still Starting after the planned 16.5 s wait. The helper
	// gives first releases up to a 120 s convergence floor; and since
	// DEV-DEPL-83 a later release may run in the capped mode, whose convergence
	// reaches 410 s. The client learns neither the mode nor first_release until
	// the call returns, so every SSH ceiling covers the longer of the two helper
	// waits (convergence plus the edge reload), then the confirmation and the
	// margin.
	return config.SwarmWorstCaseHelperWait(promotionSLOSeconds) + hashvaultPromotionConfirmBudget + rootHelperOperationMargin
}

func resolveRemoteRegistryDigests(images map[string]string, localRegistry string) (map[string]string, error) {
	resolved := make(map[string]string, len(images))
	for service, image := range images {
		digest, err := registryTagDigest(image, localRegistry)
		if err != nil {
			return nil, fmt.Errorf("resolve digest for %s: %w", service, err)
		}
		repositoryTag := strings.TrimPrefix(image, localRegistry+"/")
		repository := repositoryTag[:strings.LastIndex(repositoryTag, ":")]
		resolved[service] = "127.0.0.1:5000/" + repository + "@" + digest
	}
	return resolved, nil
}

var registryTagDigestHTTPClient = &http.Client{Timeout: 5 * time.Second}

func registryTagDigest(image string, localRegistry string) (string, error) {
	prefix := localRegistry + "/"
	if !strings.HasPrefix(image, prefix) {
		return "", fmt.Errorf("image %s was not published through the verified registry tunnel", image)
	}
	repositoryTag := strings.TrimPrefix(image, prefix)
	separator := strings.LastIndex(repositoryTag, ":")
	if separator <= 0 || separator == len(repositoryTag)-1 {
		return "", fmt.Errorf("image %s does not use an immutable release tag", image)
	}
	repository, tag := repositoryTag[:separator], repositoryTag[separator+1:]
	request, _ := http.NewRequest(http.MethodHead, "http://"+localRegistry+"/v2/"+repository+"/manifests/"+tag, nil)
	request.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	response, err := registryTagDigestHTTPClient.Do(request)
	if err != nil {
		return "", err
	}
	_ = response.Body.Close()
	digest := strings.TrimSpace(response.Header.Get("Docker-Content-Digest"))
	if response.StatusCode/100 != 2 || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return "", fmt.Errorf("registry did not return a sha256 digest for %s", image)
	}
	return digest, nil
}

// swarmState represents the deployment state for Swarm deployments.
type swarmState struct {
	Version    string     `json:"version"`
	DeployedAt string     `json:"deployed_at"`
	Strategy   string     `json:"strategy"`
	Stack      string     `json:"stack"`
	Previous   *swarmPrev `json:"previous,omitempty"`
}

type secretManifest struct {
	Hashvault *hashvaultPreparation          `json:"hashvault,omitempty"`
	Version   int                            `json:"version"`
	Secrets   map[string]secretManifestEntry `json:"secrets"`
}

type secretManifestEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type swarmPrev struct {
	Version    string `json:"version"`
	DeployedAt string `json:"deployed_at"`
}

// swarmStackFile mirrors the Docker stack YAML structure for Swarm deploys.
type swarmStackFile struct {
	Version  string                   `yaml:"version"`
	Services map[string]swarmStackSvc `yaml:"services"`
	Networks map[string]any           `yaml:"networks,omitempty"`
	Volumes  map[string]any           `yaml:"volumes,omitempty"`
	Secrets  map[string]any           `yaml:"secrets,omitempty"`
}

type swarmStackSvc struct {
	Image       string            `yaml:"image"`
	Environment any               `yaml:"environment,omitempty"`
	EnvFile     any               `yaml:"env_file,omitempty"`
	Volumes     []string          `yaml:"volumes,omitempty"`
	Expose      []string          `yaml:"expose,omitempty"`
	Networks    []string          `yaml:"networks,omitempty"`
	Command     any               `yaml:"command,omitempty"`
	DependsOn   any               `yaml:"depends_on,omitempty"`
	Deploy      *swarmDeploy      `yaml:"deploy,omitempty"`
	Healthcheck any               `yaml:"healthcheck,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Secrets     []any             `yaml:"secrets,omitempty"`
}

type swarmDeploy struct {
	Replicas       int                `yaml:"replicas"`
	UpdateConfig   *swarmUpdateConfig `yaml:"update_config,omitempty"`
	RollbackConfig *swarmUpdateConfig `yaml:"rollback_config,omitempty"`
	RestartPolicy  *swarmRestart      `yaml:"restart_policy,omitempty"`
	Labels         map[string]string  `yaml:"labels,omitempty"`
}

type swarmUpdateConfig struct {
	Parallelism   int    `yaml:"parallelism"`
	Delay         string `yaml:"delay"`
	Order         string `yaml:"order"`
	FailureAction string `yaml:"failure_action,omitempty"`
}

type swarmRestart struct {
	Condition   string `yaml:"condition"`
	Delay       string `yaml:"delay"`
	MaxAttempts int    `yaml:"max_attempts"`
}

func deploySwarm(cfg *config.Config, skipBuild bool, dryRun bool, memoryPolicy memoryBudgetPolicy, commandStartedAt ...time.Time) (deployErr error) {
	var operation *remoteOperation
	// Registered first, executed last: writer cleanup contributes to deployErr
	// before the durable reservation can be finalized.
	defer func() { operation.finish(&deployErr) }()
	totalStartedAt := time.Now()
	if len(commandStartedAt) == 1 && !commandStartedAt[0].IsZero() {
		totalStartedAt = commandStartedAt[0]
	}
	loadDeployDotenv(cfg)
	inputs, err := checkDeployInputs(cfg)
	if err != nil {
		return err
	}
	parsed, secretNames, secretPayload, buildServices := inputs.parsed, inputs.secretNames, inputs.secretPayload, inputs.buildServices

	output.Header("Found %d services to build: %s", len(buildServices), strings.Join(buildServices, ", "))
	output.Detail("Strategy: swarm (docker stack deploy with rolling updates)")
	// Advice, never a refusal: a budget the project wrote itself that is too short
	// for this stack's own healthchecks. The shipped defaults never trigger it.
	if warning := cfg.PromotionSLOWarning(maxRenderedStartPeriod(parsed)); warning != "" {
		output.Attn("%s", warning)
	}

	version := detectVersion()
	group, host, err := singleVPS(cfg)
	if err != nil {
		return err
	}
	var remoteBuild *ssh.BuildRunner
	if cfg.Build.UsesSSH() {
		remoteBuild, err = newSSHBuildRunner(cfg, group, host)
		if err != nil {
			return err
		}
	}

	// The runner lease excludes other clients before stopping its previous
	// daemon. Bootstrap and registry writes wait for the VPS reservation below.
	var interrupts *interruptCleanup
	builderCleanup := func() error {
		if remoteBuild != nil {
			return remoteBuild.Close()
		}
		return stopPersistentBuilder(cfg.App)
	}
	if remoteBuild != nil && !dryRun {
		interrupts = newInterruptCleanup()
		defer interrupts.Stop()
		interrupts.Add(builderCleanup)
		defer func() { mergeOperationCleanupError(&deployErr, operation, builderCleanup()) }()
		if err := remoteBuild.Prepare(); err != nil {
			return err
		}
		if err := remoteBuild.AcquireLease(cfg.App, host, group.Port); err != nil {
			return err
		}
		if err := remoteBuild.StopBuilder(remoteBuild.BuilderName()); err != nil {
			return err
		}
	}
	registryClient, err := connectSSH(group, host)
	if err != nil {
		return err
	}
	if remoteBuild != nil {
		if verifiedHost := remoteBuild.VerifiedProductionHost(); verifiedHost != "" {
			registryClient.Host = verifiedHost
		} else if err := registryClient.FreezeResolvedEndpoint(); err != nil {
			return fmt.Errorf("freeze verified production endpoint for runner tunnel: %w", err)
		}
	}
	// Any routing feature the installed privileged helper cannot interpret must
	// stop here, before builds, pushes or a Caddy reload. Unknown labels are not
	// a compatibility strategy: an old helper can silently render a different
	// access policy from the one the operator reviewed.
	if err := ensureRootHelperCapabilitiesWithClient(group, host, registryClient, deployRootHelperCapabilities(cfg)); err != nil {
		return err
	}
	var operationID string
	var operationIdentity trustedHostIdentity
	var operationKey ed25519.PrivateKey
	if !dryRun {
		operationIdentity, err = loadTrustedHostIdentity(host, group.Port)
		if err != nil {
			return err
		}
		privatePath, _, keyErr := ensureRootOperationKeyPair()
		if keyErr != nil {
			return keyErr
		}
		operationKey, err = rootplan.ReadPrivateKey(privatePath)
		if err != nil {
			return err
		}
		operation, err = beginRemoteOperation(registryClient, operationIdentity, operationKey, "deploy", cfg.App)
		if err != nil {
			return err
		}
		operationID = operation.id
		if remoteBuild != nil {
			if err := operation.registerSSHRunner(remoteBuild); err != nil {
				return err
			}
		}
		if remoteBuild == nil {
			interrupts = newInterruptCleanup()
			defer interrupts.Stop()
			interrupts.Add(builderCleanup)
			defer func() { mergeOperationCleanupError(&deployErr, operation, builderCleanup()) }()
			if err := builderCleanup(); err != nil {
				return err
			}
		}
	}
	// The memory guard comes first, before the build and before any reclaim is
	// launched: it only reads, and a stack the host cannot hold must be refused
	// before anything is spent on it.
	if err := ensureRemoteMemoryBudget(registryClient, parsed, cfg, memoryPolicy); err != nil {
		return err
	}
	// A local build overlaps the reclaim: the build runs on the workstation and
	// only reads the registry, the reclaim prunes the daemon's image store on the
	// VPS, so neither waits for the other (12 s measured for the reclaim alone,
	// DEV-DEPL-85). Every other path has no build to hide it behind, or builds on
	// the VPS itself, and keeps the reclaim strictly first.
	overlapReclaim := !dryRun && !skipBuild && remoteBuild == nil
	// A dry run shows the plan without touching the host, and a reclaim is a
	// signed root operation that deletes images: it is exactly what the flag
	// promises not to do, so it does not run. The guards only read.
	if !dryRun && !overlapReclaim {
		if err := reclaimRemoteImageStore(cfg, group, host, registryClient, operationID); err != nil {
			return err
		}
	}
	// The overlapped path runs the disk guard after the reclaim has finished: the
	// guard has to measure a host that has already been cleaned (see
	// reclaimRemoteImageStore).
	if !overlapReclaim {
		if err := ensureRemoteDiskBudget(registryClient); err != nil {
			return err
		}
	}
	registryAddr := "127.0.0.1:5000"
	if !dryRun {
		localRegistryPort, err := allocateLoopbackPort()
		if err != nil {
			return fmt.Errorf("allocate registry tunnel port: %w", err)
		}
		registryForward, err := registryClient.StartLocalForward(localRegistryPort, 5000)
		if err != nil {
			return fmt.Errorf("open verified registry tunnel: %w", err)
		}
		// Every registry write of this deploy goes through that one tunnel. If its
		// SSH transport died mid-run, pushes were silently truncated, so the error
		// has to reach the operator instead of being dropped by a bare defer.
		defer func() { mergeOperationCleanupError(&deployErr, operation, registryForward.Close()) }()
		registryAddr = fmt.Sprintf("127.0.0.1:%d", localRegistryPort)
		if remoteBuild != nil {
			if err := remoteBuild.StartRegistryTunnel(registryClient, registryClient.Host, group.User, group.Port, cfg.App); err != nil {
				return err
			}
		}
	}
	plan, err := createConfiguredBuildPlan(parsed, cfg.Build, registryAddr, cfg.App, version)
	if err != nil {
		return err
	}
	if remoteBuild != nil {
		if err := configureRemoteBuildPlan(&plan, remoteBuild); err != nil {
			return err
		}
		if err := validateRemoteBuildReferences(plan, remoteBuild); err != nil {
			return err
		}
	}
	webPort := detectWebPort(parsed, cfg)
	cachePolicy := swarmCachePolicyFor(persistentBuilderName(cfg.App), cfg.Deploy.BuildCacheMode)
	cachePolicy.Build.Operation = operation
	cachePolicy.Build.PushedDigests = newPushedDigestSet()
	if remoteBuild != nil {
		cachePolicy.Build = remoteBuildOptions(remoteBuild)
	} else {
		// Keep the BuildKit transcript on the client for local builds so a slow
		// healthy release can explain a moved base image or one expensive cached
		// instruction without inspecting image layers on the production node.
		cachePolicy.Build.ProgressResults = &buildProgressResults{}
	}
	if !dryRun && remoteBuild == nil {
		// --skip-build still pushes the daemon's image with docker push, so its
		// local tags keep today's cleanup; only a BuildKit push leaves none.
		cleanup, err := prepareLocalImageCleanup(localPublishedImageTagsForBuildMode(plan, swarmBuildKitPushes(cachePolicy.Build, remoteBuild != nil, skipBuild)), cfg.Deploy.PruneLocalImages)
		if err != nil {
			return err
		}
		// The shared registry path has no ephemeral artifacts to hang an
		// interrupt handler on, so it gets its own.
		interrupts.Add(cleanup.Cleanup)
		defer func() { mergeOperationCleanupError(&deployErr, operation, cleanup.Cleanup()) }()
	}

	if !dryRun && !skipBuild {
		if remoteBuild != nil {
			if err := remoteBuild.EnsureBuilder(remoteBuild.BuilderName()); err != nil {
				return err
			}
		} else if err := ensurePersistentBuilder(cfg.App); err != nil {
			return err
		}
	}

	if dryRun {
		if !skipBuild {
			if err := buildPlannedImagesWithOptions(parsed, plan, true, cachePolicy.Build); err != nil {
				return err
			}
		}
		fmt.Println("\n[dry-run] Would build, push through a verified SSH tunnel, and deploy via Swarm")
		fmt.Printf("[dry-run] Version: %s\n", version)
		// The printed stack is the stack a real deploy would apply: the derived
		// secret names are in it, and no value ever is.
		stackYAML, err := renderPlaceholderStack(cfg, parsed, plan.ServiceImages, secretNames, webPort)
		if err != nil {
			return err
		}
		if stackYAML == "" {
			fmt.Printf("[dry-run] Would prepare hashvault target %s using %s before stack deploy. No secret versions were resolved or created.\n", cfg.Secrets.Hashvault.Target, cfg.Secrets.Hashvault.Manifest)
			return nil
		}
		stackYAML, err = redactDryRunStack(stackYAML)
		if err != nil {
			return err
		}
		fmt.Printf("\n[dry-run] Generated Swarm stack YAML (planned images use deterministic placeholder digests; environment values are redacted):\n%s\n", stackYAML)
		return nil
	}

	retainedInfrastructure, err := readRetainedInfrastructureImages(cfg)
	if err != nil {
		return err
	}
	if err := resolveConfiguredInfrastructure(context.Background(), cfg, false, retainedInfrastructure); err != nil {
		return err
	}
	if err := infrastructureSecurityCheck(cfg, false); err != nil {
		return err
	}

	// Lease renewal supervises the client-side build. With an overlapped reclaim
	// it stays stopped while the reclaim runs: the reclaim is a root phase that
	// renews its own lease under the executor flock, and a renewal racing it would
	// be a second control call on the same operation. It starts as soon as the
	// reclaim finishes, while the build continues, so the reservation is renewed
	// for the whole overlap.
	stopLeaseRenewal := func() error { return nil }
	startLeaseRenewal := func() { stopLeaseRenewal = operation.keepAlive(builderCleanup) }
	defer func() { mergeOperationCleanupError(&deployErr, operation, stopLeaseRenewal()) }()
	if !overlapReclaim {
		startLeaseRenewal()
	}
	var pushStartedAt time.Time
	var buildDuration time.Duration
	if remoteBuild != nil {
		if !skipBuild {
			for _, build := range plan.Builds {
				if err := preserveRegistryManifest(build.Image); err != nil {
					return fmt.Errorf("preserve previous %s before remote build push: %w", build.Image, err)
				}
			}
			buildStartedAt := time.Now()
			if err := buildPlannedImagesWithOptions(parsed, plan, false, cachePolicy.Build); err != nil {
				return err
			}
			buildDuration = time.Since(buildStartedAt)
		}
		pushStartedAt = time.Now()
	} else if overlapReclaim {
		// The first build fills the builder's cache with no output flag and no
		// registry cache export, while the reclaim runs on the VPS. Once the
		// reclaim is joined and the disk guard has measured the cleaned host,
		// the second build is a cached --push with --metadata-file and the
		// registry cache export; its digest check below is the release identity
		// check, on the pushed image, exactly as before.
		cacheOnly, publish := swarmOverlapBuildOptions(cachePolicy.Build)
		pushStartedAt, err = runSwarmOverlappedBuildAndPush(plan, swarmOverlappedBuild{
			StartReclaim: func() *imageStoreReclaim {
				return startImageStoreReclaim(func() error {
					return reclaimRemoteImageStore(cfg, group, host, registryClient, operationID)
				})
			},
			Build: func() error {
				buildStartedAt := time.Now()
				buildErr := buildPlannedImagesWithOptions(parsed, plan, false, cacheOnly)
				buildDuration = time.Since(buildStartedAt)
				return buildErr
			},
			StartLeaseRenewal: startLeaseRenewal,
			DiskGuard:         func() error { return ensureRemoteDiskBudget(registryClient) },
			Preserve:          func(image string) error { return preserveRegistryManifest(image) },
			Publish:           func() error { return buildPlannedImagesWithOptions(parsed, plan, false, publish) },
		})
		if err != nil {
			return err
		}
	} else {
		pushStartedAt, err = runSwarmLocalBuildAndPush(plan, skipBuild, cachePolicy.Build.Push,
			func(image string) error { return preserveRegistryManifest(image) },
			func() error {
				buildStartedAt := time.Now()
				buildErr := buildPlannedImagesWithOptions(parsed, plan, false, cachePolicy.Build)
				buildDuration = time.Since(buildStartedAt)
				return buildErr
			},
			func() error { return pushPlannedImagesForOperation(plan, cachePolicy.PushCacheTags, operation) },
		)
		if err != nil {
			return err
		}
	}
	serviceImages, err := resolveRemoteRegistryDigests(plan.ServiceImages, registryAddr)
	if err != nil {
		return err
	}
	if err := cachePolicy.Build.PushedDigests.verify(plan.ServiceImages, serviceImages); err != nil {
		return err
	}
	pushDuration := time.Since(pushStartedAt)
	if overlapReclaim {
		// The push is the second, cached build: it started after the reclaim was
		// joined, so this span is its own cost plus the digest resolution.
		output.Detail("Timing push: %s (cached BuildKit build and push, digest resolution included)", formatDeployDuration(pushDuration))
	} else if swarmBuildKitPushes(cachePolicy.Build, remoteBuild != nil, skipBuild) {
		// BuildKit pushed during the build, so its upload is inside the build
		// timing; what remains here is the digest resolution.
		output.Detail("Timing push: included in build (BuildKit direct push); digest resolution %s", formatDeployDuration(pushDuration))
	} else {
		output.Detail("Timing push: %s", formatDeployDuration(pushDuration))
	}

	if err := stopLeaseRenewal(); err != nil {
		return err
	}
	if err := operation.renewBeforePromotion(); err != nil {
		return err
	}

	// Step 4: Deploy to each server
	promotionStartedAt := time.Now()
	var availability *availabilityProbe
	if cfg.Deploy.AvailabilityURL != "" {
		availabilityGated := availabilityURLIsGated(cfg)
		preflight := newAvailabilityProbe(cfg.Deploy.AvailabilityURL, cfg.Deploy.AvailabilityIntervalMS, availabilityGated)
		if preflight.CheckNow() == nil {
			availability = startAvailabilityProbe(cfg.Deploy.AvailabilityURL, cfg.Deploy.AvailabilityIntervalMS, availabilityGated)
		}
	}
	// The helper reports whether this was a first release and which promotion
	// mode it ran in (DEV-DEPL-83). The origin proof and the availability wait
	// below spend the same mode's shares of the budget; a response without a
	// mode leaves it legacy.
	var promotion promotionOutcome
	appliedStack, err := deploySwarmToHost(cfg, group, host, parsed, serviceImages, webPort, secretNames, secretPayload, operationID, operation, &promotion)
	firstRelease := promotion.FirstRelease
	if err != nil {
		recordStackPromotionRefusal(operation, err)
		if availability != nil {
			availability.Stop()
		}
		return err
	}
	operation.promotion = "applied-unverified"
	// Before the origin proof, deliberately. Both post-promotion gates below
	// are satisfied by the release that was already serving. The previous one
	// answers the health path with the same headers, so a promotion that
	// silently did not take has to be named here or it is never named at all.
	// Putting it first also keeps the diagnosis honest: a stale origin is
	// reported as "still on the previous release" instead of as an origin-proof
	// failure that sends the operator looking at Caddy.
	if err := verifyPromotedRelease(cfg, appliedStack); err != nil {
		if availability != nil {
			availability.Stop()
		}
		return err
	}
	if err := proveDirectOriginInMode(cfg, host, promotion.Mode); err != nil {
		if availability != nil {
			availability.Stop()
		}
		return fmt.Errorf("origin proof failed, %s: %w", submitRecoveryRollbackWithinOperation(cfg, operation), err)
	}
	if availability == nil && cfg.Deploy.AvailabilityURL != "" {
		if err := waitForPublicAvailability(cfg, promotion.Mode); err != nil {
			return fmt.Errorf("public availability never came back, %s: %w", submitRecoveryRollbackWithinOperation(cfg, operation), err)
		}
		availability = startAvailabilityProbe(cfg.Deploy.AvailabilityURL, cfg.Deploy.AvailabilityIntervalMS, availabilityURLIsGated(cfg))
	}
	promotionDuration := time.Since(promotionStartedAt)
	availabilityResult := availabilityProbeResult{}
	if availability != nil {
		availabilityResult = availability.Stop()
	}
	if cfg.Deploy.AvailabilityURL != "" {
		output.Detail("Availability: %d samples, %d failures", availabilityResult.Samples, availabilityResult.Failures)
		if availabilityResult.Failures > 0 {
			return fmt.Errorf("zero-downtime contract missed, %s: %d/%d availability probes failed (first: %s)", submitRecoveryRollbackWithinOperation(cfg, operation), availabilityResult.Failures, availabilityResult.Samples, availabilityResult.FirstFailure)
		}
		output.OK("Zero-downtime verified: %d/%d probes succeeded", availabilityResult.Samples, availabilityResult.Samples)
	}
	output.Detail("Timing promotion: %s", formatDeployDuration(promotionDuration))

	operation.promotion = "verified"
	if !skipBuild && remoteBuild == nil {
		pruneLocalBuildCacheAfterPromotion(cfg)
	}

	fmt.Println()
	totalDuration := time.Since(totalStartedAt)
	if firstRelease {
		output.Detail("Timing total: %s (first release, SLO not evaluated)", formatDeployDuration(totalDuration))
	} else {
		output.Detail("Timing total: %s", formatDeployDuration(totalDuration))
	}
	// Both budgets are reported here, together, after every real gate has already
	// passed. Reporting the promotion budget earlier and returning on it was what
	// made the total budget unreachable: an over-budget promotion aborted the
	// command before the total was ever compared, so anything reading the total
	// line never saw it.
	return finishSwarmDeploy(cfg.Deploy, promotionDuration, totalDuration,
		deployStageDurations{Build: buildDuration, Push: pushDuration, Promotion: promotionDuration, Total: totalDuration},
		cachePolicy.Build.ProgressResults.snapshot(), firstRelease)
}

// submitRecoveryRollback asks the host to go back to the retained previous
// stack and reports, in words the error message can carry, what is actually
// known about the outcome.
//
// The three call sites used to read `_ = rollbackStack(cfg, false)` followed by
// a message asserting "promotion rolled back". Nobody read that error, and even
// if they had, the rollback could not have proven the claim: it goes through the
// same signed action whose convergence wait used to return on a replica count.
// So Shuttle told operators, during an incident, that production had been
// restored, with no evidence at all, and an operator who believed it did not
// go and look. The wait is honest now, so the rollback's exit status finally
// means something; the wording follows what is actually observed rather than
// what was hoped.
func submitRecoveryRollback(cfg *config.Config) string {
	return submitRecoveryRollbackWithinOperation(cfg, nil)
}

func submitRecoveryRollbackWithinOperation(cfg *config.Config, operation *remoteOperation) string {
	if err := rollbackStackWithinOperation(cfg, false, operation); err != nil {
		return fmt.Sprintf("and the rollback to the previous release FAILED (%v); check `shuttle status` before anything else", err)
	}
	if operation != nil {
		operation.promotion = "rolled-back"
	}
	return "the previous release was restored"
}

// finishSwarmDeploy is the terminal decision of a healthy promotion: report the
// budgets, then succeed. It returns an error type only so the deploy path can
// keep a single return; it has no failing branch by design, because everything
// that can legitimately fail a deploy has already run, which now includes the
// two checks that were missing when that sentence was first written: the host
// waited until the running tasks carried the applied images, and the client read
// back which images those are.
func finishSwarmDeploy(deploy config.Deploy, promotion, total time.Duration, stages deployStageDurations, builds []buildProgressReport, firstReleaseValues ...bool) error {
	reportDeploySLO(measureDeploySLO(deploy, promotion, total, firstReleaseValues...), deploySLOReportContext{Stages: stages, Builds: builds})
	output.OK("Swarm deploy complete (rolling updates)")
	return nil
}

// waitForPublicAvailability blocks until the public health URL answers, or until
// the share of the promotion budget reserved for this wait runs out. It is the
// last gate of a promotion and a real one: an application that never answers is
// a failed release and the caller rolls it back.
func waitForPublicAvailability(cfg *config.Config, mode config.PromotionMode) error {
	probe := newAvailabilityProbe(cfg.Deploy.AvailabilityURL, cfg.Deploy.AvailabilityIntervalMS, availabilityURLIsGated(cfg))
	deadline := time.Now().Add(promotionWaitsFor(cfg, mode).Availability)
	for {
		err := probe.CheckNow()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("public availability did not become healthy: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// deploySLOOutcome is one measured deploy phase compared to its budget.
type deploySLOOutcome struct {
	Label    string
	Field    string
	Measured time.Duration
	Budget   time.Duration
	Missed   bool
}

// deployStageDurations are the measured stages of one Swarm deploy. Total is
// the whole deploy timer, which starts before the build; whatever the tracked
// stages do not cover (setup, tunnel, plan, preflight) is reported as "setup
// and other steps" instead of being silently given to a tracked stage.
type deployStageDurations struct {
	Build     time.Duration
	Push      time.Duration
	Promotion time.Duration
	Total     time.Duration
}

// deploySLOReportContext carries the measured stages and parsed BuildKit
// summaries needed to explain a Swarm SLO miss. Compose's existing report call
// has no complete stage breakdown, so the shared reporter does not invent a
// dominant stage for its total-SLO warning.
type deploySLOReportContext struct {
	Stages deployStageDurations
	Builds []buildProgressReport
}

func (d deployStageDurations) dominant() (string, time.Duration) {
	name, duration := "", time.Duration(0)
	for _, stage := range []struct {
		name     string
		duration time.Duration
	}{
		{name: "build", duration: d.Build},
		{name: "push", duration: d.Push},
		{name: "promotion", duration: d.Promotion},
		{name: "setup and other steps", duration: d.Total - d.Build - d.Push - d.Promotion},
	} {
		if stage.duration > duration {
			name, duration = stage.name, stage.duration
		}
	}
	return name, duration
}

// measureDeploySLO compares a finished promotion against the configured budgets
// and returns measurements only, never an error.
//
// That signature is the correction. A deploy that reaches this point has been
// promoted, has been verified to be running the images it published, has passed
// its origin proof and is serving production traffic; the budgets are
// service-level *objectives* over that success. Turning them into a
// gate meant a working release was reported as a failed command, which pushed
// operators to roll back something healthy and made Shuttle look broken next to
// tools that simply wait for Docker to converge. Genuine failures (rollback,
// unhealthy application, negative origin proof, failed availability probes)
// are still errors, raised by the checks that run before this one.
func measureDeploySLO(deploy config.Deploy, promotion, total time.Duration, firstReleaseValues ...bool) []deploySLOOutcome {
	firstRelease := len(firstReleaseValues) > 0 && firstReleaseValues[0]
	outcomes := make([]deploySLOOutcome, 0, 2)
	for _, candidate := range []deploySLOOutcome{
		{Label: "Promotion SLO", Field: "deploy.promotion_slo_seconds", Measured: promotion, Budget: time.Duration(deploy.PromotionSLOSeconds) * time.Second},
		{Label: "Total deploy SLO", Field: "deploy.total_slo_seconds", Measured: total, Budget: time.Duration(deploy.TotalSLOSeconds) * time.Second},
	} {
		if candidate.Budget <= 0 {
			continue
		}
		if firstRelease && candidate.Field == "deploy.total_slo_seconds" {
			continue
		}
		candidate.Missed = candidate.Measured > candidate.Budget
		outcomes = append(outcomes, candidate)
	}
	return outcomes
}

// reportDeploySLO reports missed objectives after the release is proven
// healthy. Swarm supplies the client-side phase measurements; without that
// context, only a promotion outcome can name a stage from its own measurement.
func reportDeploySLO(outcomes []deploySLOOutcome, contexts ...deploySLOReportContext) {
	var context deploySLOReportContext
	if len(contexts) > 0 {
		context = contexts[0]
	}
	for _, outcome := range outcomes {
		if !outcome.Missed {
			output.OK("%s met: %s <= %s", outcome.Label, formatDeployDuration(outcome.Measured), formatDeployDuration(outcome.Budget))
			continue
		}
		// Each budget names its own stage: a promotion SLO miss is about the
		// promotion, only the total SLO miss is explained by the stage that
		// dominated the whole deploy.
		stage, duration := context.Stages.dominant()
		if outcome.Field == "deploy.promotion_slo_seconds" {
			stage, duration = "promotion", outcome.Measured
		}
		cause := ""
		if stage == "build" {
			cause = buildProgressCause(context.Builds)
		}
		stageDetail := ""
		if stage != "" {
			stageDetail = fmt.Sprintf(": %s took %s", stage, formatDeployDuration(duration))
			if cause != "" {
				stageDetail += " " + cause
			}
		}
		// On 2026-10-27 a healthy release missed its total SLO because an
		// upstream Python tag moved and BuildKit rebuilt a 3.36 GB browser layer.
		// The old warning suggested raising the budget and sent the operator to
		// diff layers by hand. Name the measured bottleneck and available build
		// evidence before stating which budget was missed.
		output.Attn("%s missed: %s > %s%s. The release is healthy and serving; %s is the budget.",
			outcome.Label, formatDeployDuration(outcome.Measured), formatDeployDuration(outcome.Budget), stageDetail, outcome.Field)
	}
}

func buildProgressCause(builds []buildProgressReport) string {
	var selected *buildProgressReport
	for i := range builds {
		if builds[i].Summary.Steps == 0 {
			continue
		}
		if selected == nil || builds[i].Duration > selected.Duration {
			selected = &builds[i]
		}
	}
	if selected == nil {
		return ""
	}
	var parts []string
	if cause := selected.Summary.RebuildCause(); cause != "" {
		parts = append(parts, cause)
	}
	if selected.Summary.SlowestLabel != "" {
		parts = append(parts, fmt.Sprintf("slowest step %s %s",
			truncateBuildStepLabel(selected.Summary.SlowestLabel, 100), formatDeployDuration(selected.Summary.Slowest)))
	}
	if selected.Summary.Push > 0 {
		parts = append(parts, "registry push "+formatDeployDuration(selected.Summary.Push)+" of it")
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, "; ") + ")"
}

// swarmCachePolicy keeps the build-side and push-side halves of the registry
// cache decision in one value, because they are only ever correct together: a
// build that exports a mode=max cache manifest under :buildcache must be
// followed by a push that leaves that tag alone.
type swarmCachePolicy struct {
	Build         buildExecutionOptions
	PushCacheTags bool
}

// swarmCachePolicyFor is the single place the Swarm deploy decides how its
// builds use the cache. The persistent docker-container builder shares the host
// network namespace, so it can reach the SSH-tunnelled registry and export a
// mode=max cache to it; that export is what keeps the intermediate stages of a
// multi-stage Dockerfile restorable after a local cache eviction or on another
// machine. Publishing an inline :buildcache alias afterwards would replace that
// manifest with a mode=min one, so it is off. cacheMode is
// deploy.build_cache_mode: a project may narrow the export to "min".
func swarmCachePolicyFor(builder string, cacheMode string) swarmCachePolicy {
	return swarmCachePolicy{
		Build:         buildExecutionOptions{Builder: builder, Push: true, RegistryCacheExport: true, RegistryCacheMode: cacheMode},
		PushCacheTags: false,
	}
}

// swarmBuildKitPushes reports whether this deploy's images leave the
// workstation through BuildKit's direct push: the local persistent builder in
// push mode, building now. --skip-build pushes an existing daemon image with
// docker push instead, and the SSH remote build has its own transport.
func swarmBuildKitPushes(options buildExecutionOptions, remote, skipBuild bool) bool {
	return options.Push && !remote && !skipBuild
}

func runSwarmLocalBuildAndPush(plan buildPlan, skipBuild bool, pushedByBuildKit bool, preserve func(string) error, build func() error, push func() error) (time.Time, error) {
	if !skipBuild {
		if pushedByBuildKit {
			for _, image := range plan.Builds {
				if err := preserve(image.Image); err != nil {
					return time.Time{}, fmt.Errorf("preserve previous %s before BuildKit push: %w", image.Image, err)
				}
			}
		}
		if err := build(); err != nil {
			return time.Time{}, err
		}
	}
	pushStartedAt := time.Now()
	if skipBuild || !pushedByBuildKit {
		if err := push(); err != nil {
			return time.Time{}, err
		}
	}
	return pushStartedAt, nil
}

// reclaimRemoteImageStore asks the root helper to sweep the images of the
// releases this application has moved past, before the free-disk guard runs.
// The order is the point: a guard that measures first and never reclaims turns
// a host that is 80 % full of its own past releases into a host that can no
// longer deploy, and therefore can no longer clean itself up.
//
// A sweep that fails on the host is a deferral, not a failure: the helper
// completes its phase with a warning (printed here as shuttle-root warning) and
// the deploy goes on, because the guard that follows gates on what the disk
// actually holds after this ran, whether this ran or not. What does fail the
// deploy is the helper refusing the request (identity, signature, operation
// state) and a helper that predates the operation, which is worth its own
// line: the fix is `shuttle helper update`, and the operator would otherwise
// see the guard refuse a host the current release could have cleaned.
func reclaimRemoteImageStore(cfg *config.Config, group config.ServerGroup, host string, client *ssh.Client, operationID string) error {
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return fmt.Errorf("image store cleanup failed: %w", err)
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return fmt.Errorf("image store cleanup failed: %w", err)
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return fmt.Errorf("image store cleanup failed: %w", err)
	}
	plan, err := rootplan.NewStackReclaim(cfg.App, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
	if err == nil && operationID != "" {
		plan, err = bindOperationPlan(plan, operationID, "deploy", cfg.App)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return fmt.Errorf("image store cleanup failed: %w", err)
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return fmt.Errorf("image store cleanup failed: %w", err)
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code == 0 {
		reportRootHelperReclaims(result.Stderr)
		if !reportRootHelperWarnings(result.Stderr) {
			output.Detail("Image store: superseded release images reclaimed")
		}
		return nil
	}
	reason := strings.TrimSpace(result.Stderr)
	if rootHelperLacksOperation(reason) {
		return errors.New("image store cleanup requires an updated root helper; run shuttle helper update")
	}
	return fmt.Errorf("image store cleanup failed: %s", reason)
}

// rootHelperLacksOperation recognises a helper that does not know an action.
//
// Two strings, because the refusal happens at two depths and the fleet runs
// both. A helper that parses the action but has no branch for it says
// "unsupported signed root operation". A helper whose rootplan predates the
// action refuses it earlier, in Verify, as an "unsupported root-operation
// contract", and that is what every host set up before this release answers,
// so matching only the later string would leave the one message that names the
// fix (`shuttle setup`) unreachable on the only hosts that need it.
func rootHelperLacksOperation(stderr string) bool {
	return strings.Contains(stderr, "unsupported signed root operation") || strings.Contains(stderr, "unsupported root-operation contract")
}

// rootMinFreeDiskPercent is the free-disk floor below which a deploy is
// refused, by this client preflight and by the root helper (which checks it
// again on the host). One constant for both, so the two never drift.
const rootMinFreeDiskPercent = 20

func ensureRemoteDiskBudget(client *ssh.Client) error {
	result := client.Run("df -P / | awk 'NR==2 {gsub(/%/, \"\", $5); print 100-$5}'")
	remaining, err := strconv.Atoi(strings.TrimSpace(result.Stdout))
	if result.Code != 0 || err != nil {
		return errors.New("cannot verify remote free-disk policy")
	}
	if remaining < rootMinFreeDiskPercent {
		return fmt.Errorf("deployment refused: %d%% disk free, minimum is %d%%", remaining, rootMinFreeDiskPercent)
	}
	return nil
}

func isLegacySecretsEnvFile(ref string) bool {
	cleaned := filepath.Clean(strings.TrimSpace(ref))
	return filepath.Base(cleaned) == ".env.secrets"
}

func validateConfiguredSecretServices(parsed *composeFile, cfg *config.Config) error {
	for key, item := range cfg.Secrets.Items {
		for _, service := range item.Services {
			if _, ok := parsed.Services[service]; !ok {
				if (service == "redis" && cfg.Production.Redis) || (service == "rabbitmq" && cfg.Production.RabbitMQ) {
					continue
				}
				return fmt.Errorf("secret %s references unknown or inactive service %q", key, service)
			}
		}
	}

	return nil
}

// maxRenderedStartPeriod is the longest healthcheck start_period any service of
// the compose file renders into the stack. A service without one contributes
// nothing: Docker's own default is no grace period at all.
func maxRenderedStartPeriod(parsed *composeFile) time.Duration {
	var longest time.Duration
	if parsed == nil {
		return longest
	}
	for _, service := range parsed.Services {
		health, _ := service.Healthcheck.(map[string]any)
		raw, _ := health["start_period"].(string)
		if period, err := time.ParseDuration(strings.TrimSpace(raw)); err == nil && period > longest {
			longest = period
		}
	}
	return longest
}

// validateHostRouteServices refuses, before anything is built, a host route
// that names a service the merged compose file does not define. The edge would
// load the route and answer every request on that host with a bad gateway
// against a Swarm DNS name that never existed, after a full build and push.
func validateHostRouteServices(parsed *composeFile, cfg *config.Config) error {
	if cfg.IsInternal() {
		return nil
	}
	for i, host := range cfg.Caddy.HostRoutes {
		if _, ok := parsed.Services[host.Service]; !ok {
			return fmt.Errorf("caddy.host_routes[%d].service %q is not in the compose file", i, host.Service)
		}
		for j, route := range host.PathRoutes {
			if _, ok := parsed.Services[route.Service]; !ok {
				return fmt.Errorf("caddy.host_routes[%d].path_routes[%d].service %q is not in the compose file", i, j, route.Service)
			}
		}
	}
	return nil
}

func formatDeployDuration(duration time.Duration) string {
	return duration.Round(10 * time.Millisecond).String()
}

// loadDeployDotenv loads .env for build-arg expansion.
func loadDeployDotenv(cfg *config.Config) {
	envFile := cfg.Deploy.EnvFile
	if envFile == "" {
		envFile = ".env"
	}
	loadDotenv(envFile)
}

// deployInputs is what a deploy can establish from the workstation alone.
type deployInputs struct {
	parsed        *composeFile
	secretNames   secretManifest
	secretPayload []byte
	buildServices []string
}

// checkDeployInputs refuses everything a deploy can refuse without the host.
// `infra recreate` calls it before destroying the guest, so a refusal added
// here protects both paths; one added after it in deploySwarm leaves recreate
// with no retained stack to roll back to.
func checkDeployInputs(cfg *config.Config) (deployInputs, error) {
	if err := validateDeployEnvironment(cfg); err != nil {
		return deployInputs{}, err
	}
	parsed, err := parseDeployableComposeFiles(cfg)
	if err != nil {
		return deployInputs{}, err
	}
	for name, service := range parsed.Services {
		if len(service.Profiles) > 0 {
			return deployInputs{}, fmt.Errorf("service %q uses Compose profiles, which Shuttle does not support", name)
		}
	}
	if err := validateConfiguredSecretServices(parsed, cfg); err != nil {
		return deployInputs{}, err
	}
	// Swarm mounts files; it does not export them. Custom images used to fail
	// at startup without any explanation here. Neither a preset name nor a
	// Dockerfile proves the runtime image's behaviour (including --skip-build),
	// so warn rather than reject an image whose application may read the files.
	// Generated PHP presets already implement this contract in their entrypoint.
	for _, key := range cfg.ApplicationSecretKeys() {
		item := cfg.Secrets.Items[key]
		if item.ExposeMode() == "env" {
			output.Attn("secret %s (expose: env) for services %s: Swarm only mounts /run/secrets/%s and sets SHUTTLE_ENV_SECRETS; Shuttle cannot verify that the image exports it. Keep the Shuttle PHP preset entrypoint, implement an entrypoint that exports the listed files before exec, or use expose: file and read the mounted file in the application", key, strings.Join(item.Services, ", "), key)
		}
	}
	if err := validateHostRouteServices(parsed, cfg); err != nil {
		return deployInputs{}, err
	}
	// Resolved before anything is built. A declared secret that is missing from
	// the local store has to stop the deploy at the desk, not after a full image
	// build and a push, and the store is opened once so an operator is asked for
	// their passphrase once.
	secretNames, secretPayload, err := resolveDeployApplicationSecrets(cfg)
	if err != nil {
		return deployInputs{}, err
	}
	for _, ref := range collectComposeEnvFiles(parsed) {
		if isLegacySecretsEnvFile(ref) {
			return deployInputs{}, errors.New(".env.secrets is no longer supported; configure scoped Docker Secrets under secrets.items")
		}
	}
	buildServices := findBuildServices(parsed)
	if len(cfg.Build.Services) > 0 {
		buildServices = configuredBuildServices(cfg.Build)
	}
	if len(buildServices) == 0 {
		return deployInputs{}, fmt.Errorf("no services with build: found in %s", deployComposeFiles(cfg)[0])
	}
	return deployInputs{parsed: parsed, secretNames: secretNames, secretPayload: secretPayload, buildServices: buildServices}, nil
}

// renderPlaceholderStack renders the stack a deploy would apply without the
// host: images get placeholder digests and host secrets placeholder names. It
// returns "" for a hashvault target that is not prepared yet, whose secret
// items are unknown until the deploy prepares it.
func renderPlaceholderStack(cfg *config.Config, parsed *composeFile, images map[string]string, secretNames secretManifest, webPort string) (string, error) {
	stackConfig := *cfg
	stackConfig.Secrets.Items = applicationSecretItems(cfg)
	if cfg.UsesHashvaultSecrets() {
		if secretNames.Hashvault == nil {
			return "", nil
		}
		stackConfig.Secrets.Items = hashvaultSecretItems(secretNames.Hashvault)
	}
	// A dry run never pushes images, so its build tags cannot be resolved to
	// registry digests. Give every planned image a deterministic placeholder
	// digest instead: the stack remains structurally valid and passes the exact
	// hardening checks a real stack does, without claiming that the placeholder
	// exists in the registry. It cannot ask the host which version of each value
	// it holds either: placeholder object names keep the stack valid without
	// claiming those objects exist.
	if cfg.UsesHostSecrets() {
		var err error
		secretNames, err = dryRunHostSecretManifest(cfg)
		if err != nil {
			return "", err
		}
	}
	stack, err := generateSwarmStackWithSecrets(parsed, &stackConfig, dryRunServiceImages(images), secretNames)
	if err != nil {
		return "", err
	}
	return secureStack(stack, cfg, webPort)
}

func deployComposeFiles(cfg *config.Config) []string {
	if len(cfg.Deploy.ComposeFiles) == 0 {
		return []string{"docker-compose.yml"}
	}
	return cfg.Deploy.ComposeFiles
}

// parseDeployableComposeFiles parses the compose files and refuses what the
// helper would refuse. The helper only sees the stack after the build, the push
// and the secrets; `infra recreate` would reach it after destroying the guest
// that retained the stacks to roll back to.
func parseDeployableComposeFiles(cfg *config.Config) (*composeFile, error) {
	parsed, err := parseComposeFiles(deployComposeFiles(cfg))
	if err != nil {
		return nil, err
	}
	if err := validateRootStackGlobalSections(parsed.Raw); err != nil {
		return nil, fmt.Errorf("compose file cannot be deployed through the root helper: %w", err)
	}
	return parsed, nil
}

func generateSwarmStackWithSecrets(cf *composeFile, cfg *config.Config, imageOverrides map[string]string, manifest secretManifest) (string, error) {
	root, _ := deepCopyAny(cf.Raw).(map[string]any)
	if len(root) == 0 {
		// Unit callers can construct composeFile directly. File-backed deploys
		// always take the Raw path above; this fallback only retains the fields
		// available on the in-memory test fixture.
		data, _ := yaml.Marshal(cf)
		_ = yaml.Unmarshal(data, &root)
	}
	if root == nil {
		root = map[string]any{"services": map[string]any{}}
	}
	// The Compose Spec top-level "name" is not part of the stack schema: docker
	// stack deploy takes the stack name from its own argument. Docker tolerated
	// the extra key for years and 29.7 rejects it outright with "(root)
	// Additional property name is not allowed", which breaks every swarm deploy
	// whose compose file sets it. Dropping it here keeps one compose file usable
	// by both docker compose and docker stack deploy.
	delete(root, "name")
	// Top-level extension keys (x-*) are where a compose file keeps its YAML
	// anchors: a shared build block, a common environment. Compose declares
	// them ignored, and the anchors were already resolved into the services
	// that reference them, so the key carries nothing the stack needs. It does
	// carry what the stack must not: a build argument such as
	// ${VITE_REVERB_HOST:-bo.domebao.com} survived there, verbatim, after the
	// services' own build blocks had been removed, and the root helper refused
	// the whole payload for an unresolved variable in a key nobody deploys.
	for key := range root {
		if strings.HasPrefix(key, "x-") {
			delete(root, key)
		}
	}
	services, _ := root["services"].(map[string]any)
	if services == nil {
		services = map[string]any{}
		root["services"] = services
	}
	for service, image := range imageOverrides {
		rawService, ok := services[service].(map[string]any)
		if !ok {
			continue
		}
		delete(rawService, "build")
		rawService["image"] = image
	}

	if len(cfg.Secrets.Items) > 0 {
		topSecrets, _ := root["secrets"].(map[string]any)
		if topSecrets == nil {
			topSecrets = map[string]any{}
			root["secrets"] = topSecrets
		}
		envKeysByService := map[string][]string{}
		for _, rawService := range services {
			if service, ok := rawService.(map[string]any); ok {
				cleaned := removeEnvSecretAllowlist(service["environment"])
				if cleaned == nil {
					// Assigning a nil interface here serializes as
					// `environment: null`, which Docker Stack rejects. A service
					// that declared no environment should keep declaring none.
					delete(service, "environment")
				} else {
					service["environment"] = cleaned
				}
			}
		}
		keys := make([]string, 0, len(cfg.Secrets.Items))
		if manifest.Hashvault != nil {
			for name, raw := range services {
				service, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				service["secrets"] = removeHashvaultMounts(service["secrets"], name, manifest.Hashvault)
				labels := rawLabelsToStringMap(service["labels"])
				labels["io.hashvault.preparation"] = manifest.Hashvault.ID
				labels["io.hashvault.target"] = manifest.Hashvault.Target
				labels["io.hashvault.app"] = manifest.Hashvault.App
				service["labels"] = labels
			}
		}
		for key := range cfg.Secrets.Items {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			item := cfg.Secrets.Items[key]
			entry, ok := manifest.Secrets[key]
			if !ok || strings.TrimSpace(entry.Name) == "" {
				return "", fmt.Errorf("secret %s has not been pushed to Swarm", key)
			}
			topSecrets[entry.Name] = map[string]any{"external": true}
			for _, serviceName := range item.Services {
				rawService, ok := services[serviceName].(map[string]any)
				if !ok {
					return "", fmt.Errorf("secret %s references unknown service %q", key, serviceName)
				}
				// 0444 unless an owner was declared. A Swarm secret belongs
				// to root, so a stricter mode without an owner would lock the
				// file away from the very service that needs it, which is why
				// the historical default is world-readable inside the
				// container. Naming the account is what makes 0400 usable.
				reference := map[string]any{"source": entry.Name, "target": key, "mode": 0o444}
				if uid, gid, declared := item.Owner(); declared {
					reference["uid"] = strconv.Itoa(uid)
					reference["gid"] = strconv.Itoa(gid)
					reference["mode"] = 0o400
				}
				if manifest.Hashvault != nil {
					spec := manifest.Hashvault.Items[key].Spec
					mode, err := strconv.ParseUint(spec.Mode, 8, 32)
					if err != nil {
						return "", errors.New("invalid hashvault file mode")
					}
					reference["target"], reference["mode"] = spec.Target, mode
				}
				rawService["secrets"] = appendComposeSecret(rawService["secrets"], reference)
				if item.Expose == "env" && manifest.Hashvault == nil {
					envKeysByService[serviceName] = append(envKeysByService[serviceName], key)
				}
			}
		}
		for serviceName, envKeys := range envKeysByService {
			rawService := services[serviceName].(map[string]any)
			rawService["environment"] = setEnvSecretAllowlist(rawService["environment"], strings.Join(envKeys, ","))
		}
	}

	attachCaddyNetwork(root, services, cfg)

	out, _ := yaml.Marshal(root)
	header := fmt.Sprintf("# Generated by shuttle (swarm strategy)\n# App: %s\n\n", cfg.App)
	return header + string(out), nil
}

// dryRunServiceImages replaces build tags with deterministic, syntactically
// valid digest references. No digest is presented as real: the dry-run heading
// calls them placeholders, and this map is never used outside the non-mutating
// branch. Keeping the repository makes the generated stack useful to inspect.
func dryRunServiceImages(images map[string]string) map[string]string {
	result := make(map[string]string, len(images))
	for service, image := range images {
		if strings.Contains(image, "@sha256:") {
			result[service] = image
			continue
		}
		repository := image
		if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
			repository = repository[:colon]
		}
		digest := sha256.Sum256([]byte(image))
		result[service] = fmt.Sprintf("%s@sha256:%x", repository, digest)
	}
	return result
}

// redactDryRunStack removes every container environment value from the stack
// printed to a terminal. The real stack is generated and hardened first, so
// this presentation-only copy cannot weaken validation or the applied payload.
// Keys remain visible because they are the useful part of a configuration
// review; values often came from .env.production and must never reach logs or
// shell history.
func redactDryRunStack(stack string) (string, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(stack), &root); err != nil {
		return "", fmt.Errorf("redact dry-run stack: %w", err)
	}
	services, _ := root["services"].(map[string]any)
	for _, raw := range services {
		service, _ := raw.(map[string]any)
		switch environment := service["environment"].(type) {
		case map[string]any:
			for key := range environment {
				environment[key] = "<redacted>"
			}
		case []any:
			for i, rawEntry := range environment {
				entry, ok := rawEntry.(string)
				if !ok {
					environment[i] = "<redacted>"
					continue
				}
				key, _, found := strings.Cut(entry, "=")
				if found {
					environment[i] = key + "=<redacted>"
				} else {
					environment[i] = entry + "=<redacted>"
				}
			}
		}
	}
	redacted, err := yaml.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("encode redacted dry-run stack: %w", err)
	}
	return string(redacted), nil
}

// attachCaddyNetwork puts every service targeted by a Caddy route on the proxy
// network. The generated Caddy config reaches the app by service name, so a
// service that is not on that network answers 502. The raw compose passthrough
// cannot assume the project declares the network itself, and docker stack deploy
// drops any attachment added out of band on the next deploy, so it has to be
// part of the generated stack.
// caddyNetworkTargets names the services the shared edge proxies, in a stable
// order.
//
// The edge reaches an application by Swarm DNS name, and it can only do that
// from a network they share. Attachment used to depend on the legacy
// caddy.routes list, so an application that published a domain and declared
// path routes, the modern spelling, joined nothing. The helper still wrote
// the route, and Caddy still loaded it, so the edge answered every request with
// a bad gateway against a name it could not resolve:
//
//	dial tcp: lookup app_web on 127.0.0.11:53: no such host
//
// Derived from what the edge will actually be told to proxy: the published
// service, and each service a path route names. An internal application
// publishes nothing and therefore joins nothing.
func caddyNetworkTargets(cfg *config.Config) []string {
	seen := map[string]bool{}
	for _, target := range cfg.Caddy.Routes {
		name := strings.TrimSpace(target)
		if index := strings.LastIndex(name, ":"); index > 0 {
			name = name[:index]
		}
		if name != "" {
			seen[name] = true
		}
	}
	if !cfg.IsInternal() {
		if name := strings.TrimSpace(cfg.PrimaryServiceName()); name != "" {
			seen[name] = true
		}
		for _, route := range cfg.Caddy.PathRoutes {
			if name := strings.TrimSpace(route.Service); name != "" {
				seen[name] = true
			}
		}
		// Every extra hostname is one more thing the edge proxies, and so is
		// each of its path routes: the same bad gateway waits behind a host
		// whose service never joined.
		for _, host := range cfg.Caddy.HostRoutes {
			if name := strings.TrimSpace(host.Service); name != "" {
				seen[name] = true
			}
			for _, route := range host.PathRoutes {
				if name := strings.TrimSpace(route.Service); name != "" {
					seen[name] = true
				}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	// Sorted: the generated stack must be identical on every run.
	sort.Strings(names)
	return names
}

func attachCaddyNetwork(root map[string]any, services map[string]any, cfg *config.Config) {
	network := strings.TrimSpace(cfg.Caddy.Network)
	if network == "" || len(services) == 0 {
		return
	}
	targets := caddyNetworkTargets(cfg)
	if len(targets) == 0 {
		return
	}
	attached := false
	for _, name := range targets {
		service, ok := services[name].(map[string]any)
		if !ok {
			continue
		}
		// Naming any network makes Compose drop the implicit default, which would
		// cut this service off from its siblings, so default is restated here.
		service["networks"] = appendComposeNetwork(service["networks"], network, "default")
		attached = true
	}
	if !attached {
		return
	}
	networks, _ := root["networks"].(map[string]any)
	if networks == nil {
		networks = map[string]any{}
		root["networks"] = networks
	}
	if _, present := networks[network]; !present {
		networks[network] = map[string]any{"external": true, "name": network}
	}
}

func appendComposeNetwork(existing any, names ...string) any {
	result := []any{}
	seen := map[string]bool{}
	add := func(value any) {
		if name, ok := value.(string); ok {
			if seen[name] {
				return
			}
			seen[name] = true
		}
		result = append(result, value)
	}
	switch typed := existing.(type) {
	case []any:
		for _, item := range typed {
			add(item)
		}
	case []string:
		for _, item := range typed {
			add(item)
		}
	case map[string]any:
		// The long form (networks: {edge: {aliases: [...]}}) is left untouched
		// beyond adding the missing keys, so aliases and options survive.
		for _, name := range names {
			if _, present := typed[name]; !present {
				typed[name] = nil
			}
		}
		return typed
	case nil:
	default:
		add(typed)
	}
	for _, name := range names {
		add(name)
	}
	return result
}

func appendComposeSecret(existing any, value map[string]any) []any {
	result := []any{}
	switch typed := existing.(type) {
	case []any:
		result = append(result, typed...)
	case []string:
		for _, item := range typed {
			result = append(result, item)
		}
	case nil:
	default:
		result = append(result, typed)
	}
	return append(result, value)
}

func removeEnvSecretAllowlist(existing any) any {
	const name = "SHUTTLE_ENV_SECRETS"
	switch typed := existing.(type) {
	case map[string]any:
		delete(typed, name)
		return typed
	case []any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok || (value != name && !strings.HasPrefix(value, name+"=")) {
				result = append(result, item)
			}
		}
		return result
	case []string:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			if item != name && !strings.HasPrefix(item, name+"=") {
				result = append(result, item)
			}
		}
		return result
	default:
		return existing
	}
}

func setEnvSecretAllowlist(existing any, allowlist string) any {
	existing = removeEnvSecretAllowlist(existing)
	const name = "SHUTTLE_ENV_SECRETS"
	switch typed := existing.(type) {
	case map[string]any:
		typed[name] = allowlist
		return typed
	case []any:
		return append(typed, name+"="+allowlist)
	case nil:
		return map[string]any{name: allowlist}
	default:
		return []any{typed, name + "=" + allowlist}
	}
}

func collectComposeEnvFiles(cf *composeFile) []string {
	seen := map[string]bool{}
	var refs []string
	for _, svc := range cf.Services {
		for _, ref := range normalizeEnvFiles(svc.EnvFile) {
			if ref == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	return refs
}

func normalizeEnvFiles(value any) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		files := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				files = append(files, s)
			}
		}
		return files
	default:
		return nil
	}
}

// detectWebPort extracts the port for the published service from the parsed
// compose file, falling back to that service's configured Port, then 3000.
// The service is named by deploy.primary_service and defaults to "web".
func detectWebPort(parsed *composeFile, cfg *config.Config) string {
	primary := cfg.PrimaryServiceName()
	for name, svc := range parsed.Services {
		if name != primary {
			continue
		}
		if len(svc.Expose) > 0 {
			return svc.Expose[0]
		}
		if len(svc.Ports) > 0 {
			switch port := svc.Ports[0].(type) {
			case string:
				if idx := strings.LastIndex(port, ":"); idx >= 0 {
					return port[idx+1:]
				}
				return port
			case map[string]any:
				if target, ok := port["target"]; ok {
					return fmt.Sprintf("%v", target)
				}
			}
		}
	}

	if webSvc, ok := cfg.Services[primary]; ok && webSvc.Port != 0 {
		return fmt.Sprintf("%d", webSvc.Port)
	}

	return "3000"
}
