package cli

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

var composeHostConnector = connectComposeHost

// deployCompose is the compose strategy end to end: build on this machine,
// stream the images to the host, render and upload the project, `docker
// compose up` as the configured account, prove what runs, keep the previous
// release, and delete what this run created locally.
//
// It deliberately mirrors deploySwarm step for step where the two agree, and
// says where they do not: nothing here is signed, nothing runs as root, and
// the hardening in the rendered file is enforced by nobody but the renderer.
func deployCompose(cfg *config.Config, skipBuild bool, dryRun bool, commandStartedAt ...time.Time) (deployErr error) {
	totalStartedAt := time.Now()
	if len(commandStartedAt) == 1 && !commandStartedAt[0].IsZero() {
		totalStartedAt = commandStartedAt[0]
	}
	envFile := cfg.Deploy.EnvFile
	if envFile == "" {
		envFile = ".env"
	}
	loadDotenv(envFile)
	if err := validateDeployEnvironment(cfg); err != nil {
		return err
	}
	composeFiles := cfg.Deploy.ComposeFiles
	if len(composeFiles) == 0 {
		composeFiles = []string{"docker-compose.yml"}
	}
	parsed, err := parseComposeFiles(composeFiles)
	if err != nil {
		return err
	}
	for name, service := range parsed.Services {
		if len(service.Profiles) > 0 {
			return fmt.Errorf("service %q uses Compose profiles, which Shuttle does not support", name)
		}
	}
	if err := validateConfiguredSecretServices(parsed, cfg); err != nil {
		return err
	}
	for _, ref := range collectComposeEnvFiles(parsed) {
		if isLegacySecretsEnvFile(ref) {
			return errors.New(".env.secrets is no longer supported; configure scoped secrets under secrets.items")
		}
	}
	if !cfg.IsInternal() {
		port := 80
		if cfg.EffectiveTLSMode() == config.TLSModeACME {
			port = 443
		}
		if !composePrimaryPublishesPort(parsed, cfg.PrimaryServiceName(), port) {
			return fmt.Errorf("service %s must publish host port %d (ports: [\"%d:<container port>\"]): with no shared edge, the origin proof dials the VPS on that port and nothing else answers there", cfg.PrimaryServiceName(), port, port)
		}
	}
	buildServices := findBuildServices(parsed)
	if len(cfg.Build.Services) > 0 {
		buildServices = configuredBuildServices(cfg.Build)
	}
	if len(buildServices) == 0 {
		return fmt.Errorf("no services with build: found in %s", composeFiles[0])
	}
	output.Header("Found %d services to build: %s", len(buildServices), strings.Join(buildServices, ", "))
	output.Detail("Strategy: compose (docker compose as %s, no setup, no root helper)", composeAccount(cfg))

	version := detectVersion()
	// Source aliases stay available for --skip-build, but every attempt gets
	// its own images, manifest and secrets so recovery can reuse current intact.
	releaseVersion := version + "-" + timestampVersion(time.Now().UTC())
	host, err := composeHostConnector(cfg)
	if err != nil {
		return err
	}
	warnComposeMemoryBudget(host, parsed, cfg)
	buildOnHost := resolveComposeBuildLocation(cfg.ComposeBuild(), host.platform, localPlatform()) == config.ComposeBuildHost
	if buildOnHost {
		if err := host.verifyDockerSSHTransport(); err != nil {
			return err
		}
		output.Detail("Build location: the host's daemon over SSH (%s, native %s); nothing is transferred", composeAccount(cfg), host.platform)
	} else {
		output.Detail("Build location: this machine, for %s; images are streamed over SSH", host.platform)
	}

	var interrupts *interruptCleanup
	if !dryRun {
		interrupts = newInterruptCleanup()
		defer interrupts.Stop()
		if !buildOnHost {
			builderCleanup := func() error { return stopPersistentBuilder(cfg.App) }
			interrupts.Add(builderCleanup)
			defer func() { mergeCleanupError(&deployErr, builderCleanup()) }()
			if err := builderCleanup(); err != nil {
				return err
			}
		}
	}

	plan, err := createConfiguredBuildPlan(parsed, cfg.Build, "shuttle", cfg.App, version)
	if err != nil {
		return err
	}
	// No registry: no cache tag to publish, so none is listed among the tags
	// this run creates and removes.
	for index := range plan.Builds {
		plan.Builds[index].CacheImage = ""
	}
	tags := localPublishedImageTags(plan)
	if !dryRun && !buildOnHost {
		// Unconditional: the owner of this strategy asked that nothing built
		// for a deploy survive it on the workstation, and the tags are
		// Shuttle's own namespace.
		cleanup, err := prepareLocalImageCleanup(tags, true)
		if err != nil {
			return err
		}
		interrupts.Add(cleanup.Cleanup)
		defer func() { mergeCleanupError(&deployErr, cleanup.Cleanup()) }()
	}
	buildOptions := buildExecutionOptions{
		SkipRegistryCache: true,
		ExtraArgs:         []string{"--platform", host.platform, "--label", composeAppLabel + "=" + cfg.App},
		// `--pull` re-resolves every base image on every build, a registry
		// round trip per stage. A Dockerfile whose bases are all pinned by
		// digest cannot receive anything new from it, so it is skipped there
		// and kept everywhere else, where an unpinned tag may have moved.
		SkipPullWhenPinned: true,
	}
	if !buildOnHost {
		buildOptions.Builder = persistentBuilderName(cfg.App)
		if !dryRun && !skipBuild {
			if err := ensurePersistentBuilder(cfg.App); err != nil {
				return err
			}
		}
	}

	secrets := planComposeSecrets(cfg)
	release := host.releaseDir(releaseVersion)
	attemptImages := composeAttemptImages(plan.ServiceImages, releaseVersion)
	project, err := generateComposeProject(parsed, cfg, attemptImages, secrets)
	if err != nil {
		return err
	}

	// Retention keeps source aliases for --skip-build as well as immutable
	// attempt tags. These comments carry no secret and remain valid YAML.
	for _, tag := range tags {
		project += "# shuttle-source-image: " + tag + "\n"
	}

	if dryRun {
		if !skipBuild {
			if buildOnHost {
				fmt.Printf("[dry-run] Builds below run on the host daemon: DOCKER_HOST=ssh://%s\n", composeAccount(cfg))
			}
			if err := buildPlannedImagesWithOptions(parsed, plan, true, buildOptions); err != nil {
				return err
			}
		}
		redacted, err := redactDryRunStack(project)
		if err != nil {
			return err
		}
		fmt.Println("\n[dry-run] Would build on this machine, stream the images over SSH, and run docker compose as " + composeAccount(cfg))
		fmt.Printf("[dry-run] Version: %s\n", version)
		fmt.Printf("[dry-run] Host key: %s\n", host.cfgHostKey())
		fmt.Printf("[dry-run] Platform: %s\n", host.platform)
		fmt.Printf("[dry-run] Project: %s\n", host.project())
		fmt.Printf("[dry-run] Release directory: %s\n", release)
		for _, build := range plan.Builds {
			fmt.Printf("[dry-run] Image %s for %s\n", build.Image, joinServices(build.Services))
		}
		if len(secrets.Keys) > 0 {
			fmt.Printf("[dry-run] Secrets read on the host from %s: %s\n", cfg.Secrets.Host.EnvFile, strings.Join(secrets.Keys, ", "))
		}
		fmt.Printf("[dry-run] Remote steps, in order:\n  %s\n  docker load  (streamed)\n  %s\n  %s\n  %s\n",
			composePrepareReleaseCommand(release), composeUpCommand(host.project(), host.composeFile(release), config.DeployWaits(cfg.Deploy.PromotionSLOSeconds).StackConvergence), composeRotateCommand(host.releaseRoot(), releaseVersion, version), composeRetainCommand(host.releaseRoot(), cfg.App))
		fmt.Printf("\n[dry-run] Generated compose project (environment values are redacted):\n%s\n", redacted)
		status := host.run(composeStatusCommand(host.project()))
		fmt.Printf("[dry-run] Containers already under project %s:\n%s\n", host.project(), strings.TrimSpace(status.Stdout))
		return nil
	}

	if err := host.acquireLock("deploy"); err != nil {
		return err
	}
	defer func() { mergeCleanupError(&deployErr, host.releaseLock()) }()

	var remoteIDs map[string]string
	if buildOnHost {
		if !skipBuild {
			// The docker CLI reaches the host's daemon through its own SSH
			// transport for the duration of the builds and nothing else:
			// every other docker call of this run is local.
			if err := os.Setenv("DOCKER_HOST", "ssh://"+composeAccount(cfg)); err != nil {
				return err
			}
			var unknown atomic.Bool
			buildOptions.HostBuildRun = func(args []string, capture *buildProgressCapture) error {
				err, uncertain := runComposeHostBuild(args, capture)
				if uncertain {
					unknown.Store(true)
				}
				return err
			}
			buildErr := buildPlannedImagesWithOptions(parsed, plan, false, buildOptions)
			_ = os.Unsetenv("DOCKER_HOST")
			if buildErr != nil {
				host.lock.unknown = unknown.Load()
				return buildErr
			}
		}
		remoteIDs, _, err = host.imageIDs(tags)
		if err != nil {
			if skipBuild {
				return fmt.Errorf("%w: --skip-build only reuses images the host still holds for this exact version", err)
			}
			return err
		}
	} else {
		if !skipBuild {
			if err := buildPlannedImagesWithOptions(parsed, plan, false, buildOptions); err != nil {
				return err
			}
		}
		localIdentities, err := localImageIdentities(tags)
		if err != nil {
			if skipBuild {
				return fmt.Errorf("%w: --skip-build only reuses images this workstation still holds, and the compose strategy removes them after every deploy, so run the deploy without it", err)
			}
			return err
		}

		// Transfer: one archive, streamed, never written to disk on either side.
		transferStartedAt := time.Now()
		size, err := localImageSize(tags)
		if err != nil {
			return err
		}
		output.Step("Streaming %d image(s), %s, to %s...", len(tags), formatMemoryBytes(size), host.address)
		if err := host.loadImages(tags, size); err != nil {
			return err
		}
		var remoteIdentities map[string]string
		remoteIDs, remoteIdentities, err = host.imageIDs(tags)
		if err != nil {
			return err
		}
		for _, tag := range tags {
			if remoteIdentities[tag] != localIdentities[tag] {
				return fmt.Errorf("image %s does not have the layers it was built with once loaded on the host; the transfer is not trusted", tag)
			}
		}
		output.Detail("Timing transfer: %s", formatDeployDuration(time.Since(transferStartedAt)))
	}

	// Give new images immutable references before selecting any running
	// attempt references that can safely be reused.
	if err := host.tagAttemptImages(plan.ServiceImages, attemptImages, remoteIDs); err != nil {
		return err
	}

	// Same ID and immutable reference means the service configuration stays
	// unchanged. Mutable source aliases must transition to an attempt once.
	attemptIDs := make(map[string]string, len(attemptImages))
	for service, source := range plan.ServiceImages {
		attemptIDs[attemptImages[service]] = remoteIDs[source]
	}
	if running := host.run(composeContainerImagesCommand(host.project())); running.Code != 0 {
		output.Attn("What the project runs could not be read (%s); every built service will be recreated", strings.TrimSpace(running.Stderr))
	} else if images, reused := reuseRunningImages(attemptImages, attemptIDs, parseComposeContainerImages(running.Stdout)); len(reused) > 0 {
		project, err = generateComposeProject(parsed, cfg, images, secrets)
		if err != nil {
			return err
		}
		for _, tag := range tags {
			project += "# shuttle-source-image: " + tag + "\n"
		}
		output.Detail("Unchanged image: %s keep the reference already running, so compose leaves them as they are", strings.Join(reused, ", "))
	}

	promotionStartedAt := time.Now()
	var availability *availabilityProbe
	if cfg.Deploy.AvailabilityURL != "" {
		availabilityGated := availabilityURLIsGated(cfg)
		preflight := newAvailabilityProbe(cfg.Deploy.AvailabilityURL, cfg.Deploy.AvailabilityIntervalMS, availabilityGated)
		if preflight.CheckNow() == nil {
			availability = startAvailabilityProbe(cfg.Deploy.AvailabilityURL, cfg.Deploy.AvailabilityIntervalMS, availabilityGated)
		}
	}
	stopProbe := func() {
		if availability != nil {
			availability.Stop()
			availability = nil
		}
	}
	if err := host.applyRelease(releaseVersion, project, secrets); err != nil {
		stopProbe()
		return fmt.Errorf("%w; %s", err, host.recover())
	}
	// The containers are compared against the host's own ID of each image:
	// same daemon, same image store, same reading.
	wanted := map[string]string{}
	for service, image := range plan.ServiceImages {
		wanted[service] = remoteIDs[image]
	}
	if err := host.verifyRelease(wanted); err != nil {
		stopProbe()
		return fmt.Errorf("%w; %s", err, host.recover())
	}
	if err := proveDirectOrigin(cfg, host.address); err != nil {
		stopProbe()
		return fmt.Errorf("origin proof failed: %w; %s", err, host.recover())
	}
	if availability == nil && cfg.Deploy.AvailabilityURL != "" {
		if err := waitForPublicAvailability(cfg, config.PromotionModeLegacy); err != nil {
			return fmt.Errorf("public availability never came back: %w; %s", err, host.recover())
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
			// Expected under this strategy: `compose up` recreates a service
			// in place, so the probe sees the gap. It is reported, never
			// hidden, and it does not roll a healthy release back.
			output.Attn("The compose strategy recreates services in place; %d/%d probes failed during the switch (first: %s)", availabilityResult.Failures, availabilityResult.Samples, availabilityResult.FirstFailure)
		}
	}
	// The release is proven: only now does `current` move, so a failure above
	// left `current` on what was serving.
	if result := host.run(composeRotateCommand(host.releaseRoot(), releaseVersion, version)); result.Code != 0 {
		return fmt.Errorf("record the release as current: %s", strings.TrimSpace(result.Stderr))
	}
	if result := host.run(composeLockedRetentionCommand(host.releaseRoot(), cfg.App, host.lock.id)); result.Code != 0 {
		output.Attn("Remote retention did not complete: %s", strings.TrimSpace(result.Stderr))
	}
	output.Detail("Timing promotion: %s", formatDeployDuration(promotionDuration))

	if !skipBuild && !buildOnHost {
		pruneLocalBuildCacheAfterPromotion(cfg)
		if cfg.Deploy.PruneBuildCache == "all" {
			removePersistentBuilder(cfg.App)
		}
	}
	fmt.Println()
	totalDuration := time.Since(totalStartedAt)
	output.Detail("Timing total: %s", formatDeployDuration(totalDuration))
	reportDeploySLO(measureDeploySLO(cfg.Deploy, promotionDuration, totalDuration))
	output.OK("Compose deploy complete (%s as %s)", host.project(), composeAccount(cfg))
	return nil
}

// warnComposeMemoryBudget measures, and does not gate: `compose up` recreates
// a service in place, so the sum of the limits is a ceiling the host must
// hold, not a second copy of the stack the swarm rolling update needs room
// for. The figures come from the preflight report, not from a session of
// their own.
func warnComposeMemoryBudget(host composeHost, parsed *composeFile, cfg *config.Config) {
	limits, err := stackMemoryLimits(parsed, cfg)
	if err != nil {
		output.Attn("Memory budget not measured: %v", err)
		return
	}
	totalBytes, availableBytes, err := parseMemInfo(host.memInfo)
	if err != nil {
		output.Attn("Memory budget not measured: %v", err)
		return
	}
	decision := evaluateMemoryBudget(totalBytes, availableBytes, limits)
	if decision.Refused {
		output.Attn("Memory budget exceeded: %s. The compose strategy recreates services in place, so this is a warning; stop whatever else holds that memory before relying on the limits", decision.Shortfall())
		return
	}
	output.Detail("%s", decision.Summary())
}

func composeAccount(cfg *config.Config) string {
	group, host, err := singleVPS(cfg)
	if err != nil {
		return "?"
	}
	// Docker opens its own SSH connection: omitting this port silently sends
	// cross-architecture builds to port 22 after a successful preflight.
	if group.Port != 22 {
		host = net.JoinHostPort(host, strconv.Itoa(group.Port))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return group.User + "@" + host
}

// verifyDockerSSHTransport checks that the host key OpenSSH holds for the
// host is the one config.json pins, since the docker CLI's ssh:// transport
// trusts known_hosts and not Shuttle's own client.
func (h composeHost) verifyDockerSSHTransport() error {
	group, _, _ := singleVPS(h.cfg)
	endpoint := h.address
	// OpenSSH indexes nonstandard ports as [host]:port, including DNS names.
	if group.Port != 22 {
		endpoint = "[" + h.address + "]:" + strconv.Itoa(group.Port)
	}
	listing, err := exec.Command("ssh-keygen", "-lF", endpoint).CombinedOutput()
	if err != nil || !knownHostsHoldsFingerprint(string(listing), h.cfgHostKey()) {
		return fmt.Errorf("a host build drives the daemon through `docker` over SSH, which trusts ~/.ssh/known_hosts: it must hold %s for %s under ED25519 (`ssh-keygen -lF %s`), and it does not; connect once by hand after checking the fingerprint against the provider console, then deploy again", h.cfgHostKey(), endpoint, endpoint)
	}
	return nil
}

func (h composeHost) cfgHostKey() string {
	group, _, _ := singleVPS(h.cfg)
	return group.HostKey
}

// connectComposeHost pins the SSH connection to the fingerprint config.json
// declares, records it on first contact, and refuses a config whose key no
// longer matches what was trusted — the one way a silently edited config.json
// can be caught.
func connectComposeHost(cfg *config.Config) (composeHost, error) {
	group, address, err := singleVPS(cfg)
	if err != nil {
		return composeHost{}, err
	}
	recorded, found, err := loadComposeHostIdentity(address, group.Port)
	if err != nil {
		return composeHost{}, err
	}
	if found && recorded.HostKeyFingerprint != group.HostKey {
		return composeHost{}, fmt.Errorf("server.host_key %s differs from the fingerprint first trusted for %s:%d (%s); if the host really was reinstalled, remove its record under the shuttle configuration directory and deploy again", group.HostKey, address, group.Port, recorded.HostKeyFingerprint)
	}
	client, err := ssh.NewClientExactWithFingerprint(address, group.User, group.Port, group.HostKey)
	if err != nil {
		return composeHost{}, err
	}
	result := composeRemoteRunner(client, composePreflightCommand)
	if result.Code != 0 {
		return composeHost{}, fmt.Errorf("host preflight failed on %s: %s", address, strings.TrimSpace(result.Stderr))
	}
	report, err := parseComposePreflight(result.Stdout)
	if err != nil {
		return composeHost{}, err
	}
	host := composeHost{client: client, cfg: cfg, user: report.User, address: address, home: report.Home}
	if err := checkComposePreflight(report, cfg, host.releaseRoot()); err != nil {
		return composeHost{}, err
	}
	host.platform, _ = composePlatform(report.Arch)
	host.memInfo = report.MemInfo
	if !found {
		if err := saveTrustedHostIdentity(trustedHostIdentity{Version: 2, Host: address, Port: group.Port, HostKeyFingerprint: group.HostKey, Mode: hostIdentityModeCompose}); err != nil {
			return composeHost{}, fmt.Errorf("record the trusted host key: %w", err)
		}
	}
	return host, nil
}

// dockerSaveStream opens `docker save` over the tags and hands back a gzip
// stream of it: nothing touches the disk, and `docker load` reads gzip.
var dockerSaveStream = func(tags []string) (io.ReadCloser, func() error, error) {
	command := exec.Command("docker", append([]string{"save"}, tags...)...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	reader, writer := io.Pipe()
	go func() {
		compressor, err := gzip.NewWriterLevel(writer, gzip.BestSpeed)
		if err != nil {
			writer.CloseWithError(err)
			return
		}
		if _, err := io.Copy(compressor, stdout); err != nil {
			writer.CloseWithError(err)
			return
		}
		if err := compressor.Close(); err != nil {
			writer.CloseWithError(err)
			return
		}
		writer.Close()
	}()
	return reader, command.Wait, nil
}

func (h composeHost) loadImages(tags []string, size int64) error {
	stream, wait, err := dockerSaveStream(tags)
	if err != nil {
		return fmt.Errorf("docker save: %w", err)
	}
	h.client.SetOperationTimeout(composeTransferTimeout(size))
	result := h.observe(composeRemoteStreamRunner(h.client, "docker load", stream))
	_ = stream.Close()
	saveErr := wait()
	if result.Code != 0 || saveErr != nil {
		if result.OutcomeUnknown {
			return errors.New("docker load outcome unknown; Compose lock retained")
		}
		recovery := h.run(composeLoadRecoveryCommand(h.cfg.App, tags))
		note := ""
		if recovery.Code != 0 {
			note = "; and the partial load could not be cleaned: " + strings.TrimSpace(recovery.Stderr)
		}
		if saveErr != nil {
			return fmt.Errorf("docker save failed: %v%s", saveErr, note)
		}
		return fmt.Errorf("docker load on the host failed: %s%s", strings.TrimSpace(result.Stderr), note)
	}
	return nil
}

// imageIDs reads, for every loaded tag, the host daemon's image ID and the
// image's content identity.
func (h composeHost) imageIDs(tags []string) (ids map[string]string, identities map[string]string, err error) {
	result := h.run(composeImageIDsCommand(tags))
	if result.Code != 0 {
		return nil, nil, fmt.Errorf("the host does not hold every loaded image: %s", strings.TrimSpace(result.Stderr))
	}
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	if len(lines) != len(tags) {
		return nil, nil, fmt.Errorf("the host reported %d image rows for %d tags", len(lines), len(tags))
	}
	ids = make(map[string]string, len(tags))
	identities = make(map[string]string, len(tags))
	for index, tag := range tags {
		id, identity, found := strings.Cut(strings.TrimSpace(lines[index]), "\t")
		if !found || id == "" || identity == "" {
			return nil, nil, fmt.Errorf("the host reported an unreadable image row for %s: %q", tag, lines[index])
		}
		ids[tag] = id
		identities[tag] = identity
	}
	return ids, identities, nil
}

// applyRelease writes the release directory, materialises the secrets there,
// and runs the promotion.
func (h composeHost) applyRelease(version, project string, secrets composeSecretsPlan) error {
	release := h.releaseDir(version)
	if result := h.run(composePrepareReleaseCommand(release)); result.Code != 0 {
		return fmt.Errorf("prepare %s: %s", release, strings.TrimSpace(result.Stderr))
	}
	if result := h.observe(h.client.UploadContent(project, h.composeFile(release), 0o600)); result.Code != 0 {
		return fmt.Errorf("upload the compose project: %s", strings.TrimSpace(result.Stderr))
	}
	if len(secrets.Keys) > 0 {
		envKeys, fileKeys := secrets.exposeKeys()
		script := composeSecretsScript(h.cfg.Secrets.Host.EnvFile, release, secrets.Keys, envKeys, fileKeys)
		if result := h.observe(composeRemoteStdinRunner(h.client, "sh -s", []byte(script))); result.Code != 0 {
			return fmt.Errorf("materialise the declared secrets on the host: %s", strings.TrimSpace(result.Stderr))
		}
	}
	waits := config.DeployWaits(h.cfg.Deploy.PromotionSLOSeconds)
	h.client.SetOperationTimeout(composeUpTimeout(h.cfg.Deploy.PromotionSLOSeconds))
	output.Step("docker compose up (project %s, waiting up to %s for health)...", h.project(), formatDeployDuration(waits.StackConvergence))
	if result := h.run(composeUpCommand(h.project(), h.composeFile(release), waits.StackConvergence)); result.Code != 0 {
		return fmt.Errorf("docker compose up failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

// exposeKeys splits the declared keys by how they are delivered, for the host
// script, sorted and deduplicated.
func (p composeSecretsPlan) exposeKeys() (env []string, file []string) {
	seenEnv, seenFile := map[string]bool{}, map[string]bool{}
	for _, keys := range p.Env {
		for _, key := range keys {
			if !seenEnv[key] {
				seenEnv[key] = true
				env = append(env, key)
			}
		}
	}
	for _, keys := range p.File {
		for _, key := range keys {
			if !seenFile[key] {
				seenFile[key] = true
				file = append(file, key)
			}
		}
	}
	sort.Strings(env)
	sort.Strings(file)
	return env, file
}

func (h composeHost) verifyRelease(wanted map[string]string) error {
	result := h.run(composeContainerImagesCommand(h.project()))
	if result.Code != 0 {
		return fmt.Errorf("read back what the project runs: %s", strings.TrimSpace(result.Stderr))
	}
	complaints := compareComposeRelease(wanted, parseComposeContainerImages(result.Stdout))
	if len(complaints) > 0 {
		return fmt.Errorf("the release is not what is running:\n  %s", strings.Join(complaints, "\n  "))
	}
	output.OK("Release identity verified: %d service(s) run the images this deploy built", len(wanted))
	return nil
}

// recover puts the host back after a failed promotion, in the words of what
// was observed. With a `current` release it is re-applied; on a first deploy
// there is nothing to go back to and the project is taken down so nothing
// half-started keeps the ports.
func (h composeHost) recover() string {
	if h.lock != nil && h.lock.unknown {
		return "remote outcome unknown; lock retained, inspect the host before recovery"
	}
	if h.cfg.Deploy.AutoRollback != nil && !*h.cfg.Deploy.AutoRollback {
		return "deploy.auto_rollback is off: the host was left as it is, check `shuttle status`"
	}
	root := h.releaseRoot()
	current := h.run("set -eu; cd " + shell.Escape(root) + " && test -L current && readlink current")

	if current.Code != 0 || strings.TrimSpace(current.Stdout) == "" {
		if result := h.run(composeDownCommand(h.project(), false)); result.Code != 0 {
			return fmt.Sprintf("and no previous release exists; taking the project down also FAILED (%s) — check `shuttle status` before anything else", strings.TrimSpace(result.Stderr))
		}
		return "no previous release exists, so the project was taken down"
	}
	waits := config.DeployWaits(h.cfg.Deploy.PromotionSLOSeconds)
	h.client.SetOperationTimeout(composeUpTimeout(h.cfg.Deploy.PromotionSLOSeconds))
	previous := root + "/" + strings.TrimSpace(current.Stdout)
	if result := h.run(composeUpCommand(h.project(), h.composeFile(previous), waits.StackConvergence)); result.Code != 0 {
		return fmt.Sprintf("and the return to release %s FAILED (%s) — check `shuttle status` before anything else", strings.TrimSpace(current.Stdout), strings.TrimSpace(result.Stderr))
	}

	return "release " + strings.TrimSpace(current.Stdout) + " was restored"
}

// localImageIdentities and localImageSize read the content identity and the
// weight of what was just built, through the same seam the builder uses.
func localImageIdentities(tags []string) (map[string]string, error) {
	identities := make(map[string]string, len(tags))
	for _, tag := range tags {
		out, err := dockerBuilderRunner("image", "inspect", "--format", composeImageIdentityFormat, tag)
		if err != nil {
			return nil, fmt.Errorf("image %s is not in the local daemon: %s", tag, strings.TrimSpace(string(out)))
		}
		identities[tag] = strings.TrimSpace(string(out))
	}
	return identities, nil
}

func localImageSize(tags []string) (int64, error) {
	var total int64
	for _, tag := range tags {
		out, err := dockerBuilderRunner("image", "inspect", "--format", "{{.Size}}", tag)
		if err != nil {
			return 0, fmt.Errorf("image %s size: %s", tag, strings.TrimSpace(string(out)))
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("image %s reported an unreadable size %q", tag, strings.TrimSpace(string(out)))
		}
		total += size
	}
	return total, nil
}

// removePersistentBuilder is the "all" of prune_build_cache under this
// strategy: the builder and the state volume buildx keeps for it go, so no
// volume this deploy created outlives it. The next build is cold.
func removePersistentBuilder(app string) {
	name := persistentBuilderName(app)
	if _, err := dockerBuilderRunner("buildx", "inspect", name); err != nil {
		return
	}
	output.Step("Removing BuildKit builder %s and its state volume...", name)
	if out, err := dockerBuilderRunner("buildx", "rm", "--force", name); err != nil {
		output.Attn("BuildKit builder %s could not be removed: %s", name, strings.TrimSpace(string(out)))
	}
}

// ── the other commands under this strategy ──────────────────────────────────

func composeStatus(cfg *config.Config) (string, error) {
	host, err := connectComposeHost(cfg)
	if err != nil {
		return "", err
	}
	result := host.run(composeStatusCommand(host.project()))
	if result.Code != 0 {
		return "", fmt.Errorf("docker compose ps failed: %s", strings.TrimSpace(result.Stderr))
	}
	return result.Stdout, nil
}

func composeLogs(cfg *config.Config, service string, lines int) (string, error) {
	host, err := connectComposeHost(cfg)
	if err != nil {
		return "", err
	}
	result := host.run(composeLogsCommand(host.project(), service, lines))
	if result.Code != 0 {
		return "", fmt.Errorf("docker compose logs failed: %s", strings.TrimSpace(result.Stderr))
	}
	return result.Stdout, nil
}

// composeRun executes a declared operation. There is no helper to keep the
// command out of the caller's hands under this strategy — the account can run
// anything on the daemon anyway — but the name is still all that is typed,
// and the argv still comes from the configuration, word by word.
func composeRun(cfg *config.Config, name string) (string, error) {
	operation := cfg.Operations[name]
	host, err := connectComposeHost(cfg)
	if err != nil {
		return "", err
	}
	host.client.SetOperationTimeout(10 * time.Minute)
	result := host.run(composeExecCommand(host.project(), operation.Service, operation.Command))
	body := result.Stdout
	if result.Stderr != "" {
		body += result.Stderr
	}
	if result.Code != 0 {
		return body, fmt.Errorf("operation %s exited %d", name, result.Code)
	}
	return body, nil
}

func composeRollback(cfg *config.Config, dryRun bool) (rollbackErr error) {
	if dryRun {
		fmt.Printf("[dry-run] Would run docker compose up on the previous release of %s as %s, then swap current and previous.\n", cfg.ComposeProjectName(), composeAccount(cfg))
		return nil
	}
	host, err := composeHostConnector(cfg)
	if err != nil {
		return err
	}
	if err := host.acquireLock("rollback"); err != nil {
		return err
	}
	defer func() { mergeCleanupError(&rollbackErr, host.releaseLock()) }()
	root := host.releaseRoot()
	previous := host.run("set -eu; cd " + shell.Escape(root) + " && test -L previous && readlink previous")
	if previous.Code != 0 || strings.TrimSpace(previous.Stdout) == "" {
		return errors.New("no previous release is retained on the host; nothing to roll back to")
	}
	waits := config.DeployWaits(cfg.Deploy.PromotionSLOSeconds)
	host.client.SetOperationTimeout(composeUpTimeout(cfg.Deploy.PromotionSLOSeconds))
	target := root + "/" + strings.TrimSpace(previous.Stdout)
	output.Step("Rolling back to release %s...", strings.TrimSpace(previous.Stdout))
	if result := host.run(composeUpCommand(host.project(), host.composeFile(target), waits.StackConvergence)); result.Code != 0 {
		return fmt.Errorf("docker compose up on the previous release failed: %s", strings.TrimSpace(result.Stderr))
	}
	if result := host.run(composeSwapCommand(root)); result.Code != 0 {
		return fmt.Errorf("the previous release is running but the links could not be swapped: %s", strings.TrimSpace(result.Stderr))
	}
	output.OK("Release %s restored", strings.TrimSpace(previous.Stdout))
	return nil
}

func composeDestroy(cfg *config.Config, volumes bool) (destroyErr error) {
	host, err := composeHostConnector(cfg)
	if err != nil {
		return err
	}
	if err := host.acquireLock("destroy"); err != nil {
		return err
	}
	defer func() { mergeCleanupError(&destroyErr, host.releaseLock()) }()
	host.client.SetOperationTimeout(5 * time.Minute)
	if result := host.run(composeDownCommand(host.project(), volumes)); result.Code != 0 {
		return fmt.Errorf("docker compose down failed: %s", strings.TrimSpace(result.Stderr))
	}
	if result := host.run(`set -eu; cd ` + shell.Escape(host.releaseRoot()) + `; for item in * .[!.]* ..?*; do [ "$item" = .lock ] && continue; [ -e "$item" ] || [ -L "$item" ] || continue; rm -rf -- "$item"; done`); result.Code != 0 {
		return fmt.Errorf("the project is down but its releases could not be removed: %s", strings.TrimSpace(result.Stderr))
	}
	if result := host.run(composeLoadRecoveryCommand(cfg.App, nil)); result.Code != 0 {
		output.Attn("Images built for %s were not all removed: %s", cfg.App, strings.TrimSpace(result.Stderr))
	}
	return nil
}
