package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"gopkg.in/yaml.v3"
)

// dockerBuildRunner is kept behind a narrow seam so the cache command wiring
// can be verified without invoking a Docker daemon.
var dockerBuildRunner = func(args []string) error {
	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func dockerBuildRunnerWithProgress(args []string, capture *buildProgressCapture) error {
	return runWithBuildProgress(exec.Command("docker", args...), os.Stdout, os.Stderr, capture)
}

// withPlainBuildProgress pins --progress=plain on a build whose output is
// parsed: an inherited BUILDKIT_PROGRESS=tty or rawjson would otherwise
// change the format and silently disable the diagnostics.
func withPlainBuildProgress(args []string) []string {
	// Any explicit --progress (tty, rawjson, auto) is replaced: the parser only
	// reads plain output.
	cleaned := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--progress" {
			index++
			continue
		}
		if strings.HasPrefix(arg, "--progress=") {
			continue
		}
		cleaned = append(cleaned, arg)
	}
	args = cleaned
	insert := 1
	if len(args) > 1 && args[0] == "buildx" && args[1] == "build" {
		insert = 2
	}
	if len(args) < insert {
		return args
	}
	out := make([]string, 0, len(args)+1)
	out = append(out, args[:insert]...)
	out = append(out, "--progress=plain")
	return append(out, args[insert:]...)
}

// runWithBuildProgress runs a build with its output teed to the given
// terminal writers and the progress parser. Its error is the command's own
// result: the tee never fails a write, so neither a display error nor a
// parsing problem can change it.
func runWithBuildProgress(cmd *exec.Cmd, stdout, stderr io.Writer, capture *buildProgressCapture) error {
	cmd.Stdout = buildProgressTee{terminal: stdout, capture: capture}
	cmd.Stderr = buildProgressTee{terminal: stderr, capture: capture}
	return cmd.Run()
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]any            `yaml:"volumes,omitempty"`
	Networks map[string]any            `yaml:"networks,omitempty"`

	// Raw is the untyped document exactly as parsed. The typed fields above only
	// model what shuttle needs to reason about (builds, ports, healthchecks); a
	// compose file legitimately carries much more (mem_limit, cpus, cpu_shares,
	// ulimits, sysctls, deploy, ...). Regenerating a production compose from the
	// typed struct silently dropped all of it, so generateProdCompose works on
	// Raw instead and only mutates what it must.
	Raw map[string]any `yaml:"-"`
}

type composeService struct {
	Build         any               `yaml:"build,omitempty"`
	Image         string            `yaml:"image,omitempty"`
	ContainerName string            `yaml:"container_name,omitempty"`
	Environment   any               `yaml:"environment,omitempty"`
	Volumes       []string          `yaml:"volumes,omitempty"`
	Expose        []string          `yaml:"expose,omitempty"`
	Ports         []any             `yaml:"ports,omitempty"`
	DependsOn     any               `yaml:"depends_on,omitempty"`
	Restart       string            `yaml:"restart,omitempty"`
	Networks      []string          `yaml:"networks,omitempty"`
	EnvFile       any               `yaml:"env_file,omitempty"`
	Labels        map[string]string `yaml:"labels,omitempty"`
	Command       any               `yaml:"command,omitempty"`
	Healthcheck   any               `yaml:"healthcheck,omitempty"`
	// Tmpfs must survive parsing, or the conversion that turns it into the
	// long-form Swarm mount reads a key that never arrives. Without this field
	// a service that declares a writable path gets silently reduced to /tmp,
	// and under read_only: true it crash-loops on the first write to anywhere
	// else, with the compose file plainly saying it asked for that path.
	Tmpfs    any      `yaml:"tmpfs,omitempty"`
	Profiles []string `yaml:"profiles,omitempty"`
}

func parseComposeFile(path string) (*composeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &cf.Raw); err != nil {
		return nil, err
	}
	return &cf, nil
}

func parseComposeFiles(paths []string) (*composeFile, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one compose file is required")
	}

	var merged map[string]any
	for _, path := range paths {
		parsed, err := parseComposeFile(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if merged == nil {
			merged = parsed.Raw
			continue
		}
		merged = mergeComposeMap(merged, parsed.Raw)
	}

	data, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshal merged compose files: %w", err)
	}
	var result composeFile
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode merged compose files: %w", err)
	}
	result.Raw = merged
	return &result, nil
}

func mergeComposeMap(base map[string]any, override map[string]any) map[string]any {
	for key, value := range override {
		current, exists := base[key]
		if !exists {
			base[key] = value
			continue
		}
		currentMap, currentIsMap := current.(map[string]any)
		overrideMap, overrideIsMap := value.(map[string]any)
		if currentIsMap && overrideIsMap {
			base[key] = mergeComposeMap(currentMap, overrideMap)
			continue
		}
		currentList, currentIsList := current.([]any)
		overrideList, overrideIsList := value.([]any)
		if currentIsList && overrideIsList {
			base[key] = append(currentList, overrideList...)
			continue
		}
		base[key] = value
	}
	return base
}

func findBuildServices(cf *composeFile) []string {
	var services []string
	for name, svc := range cf.Services {
		if svc.Build != nil {
			services = append(services, name)
		}
	}
	return services
}

func buildServiceImageWithCacheOptions(cf *composeFile, serviceName string, imageTag string, cacheImage string, dryRun bool, options buildExecutionOptions) error {
	svc := cf.Services[serviceName]
	spec, err := parseBuildSpec(svc.Build)
	if err != nil {
		return fmt.Errorf("unsupported build format for service %s: %w", serviceName, err)
	}
	return buildImageWithSpecWithOptions(spec, imageTag, cacheImage, dryRun, options)
}

func buildImageWithSpecWithOptions(spec buildSpec, imageTag string, cacheImage string, dryRun bool, options buildExecutionOptions) error {
	if err := refuseIgnoredSecretsInBuildContext(spec); err != nil {
		return err
	}
	spec.Dockerfile = resolveBuildDockerfile(spec)
	if len(options.ExtraArgs) > 0 {
		spec.BuildArgs = append(append([]string(nil), spec.BuildArgs...), options.ExtraArgs...)
	}
	if options.RemoteBuilder != "" {
		cmdArgs := dockerBuildxRemoteCommandArgs(options.RemoteBuilder, imageTag, spec.Dockerfile, spec.BuildArgs, spec.Context)
		if options.SkipPullWhenPinned && dockerfileBasesPinned(spec.Dockerfile) {
			cmdArgs = withoutArg(cmdArgs, "--pull")
		}
		if dryRun {
			prefix := []string{"--host", options.RemoteDockerHost}
			fmt.Printf("[dry-run] docker %s\n", strings.Join(redactDryRunBuildArgs(append(prefix, cmdArgs...)), " "))
			return nil
		}
		var err error
		if options.RemoteDockerRun != nil {
			err = options.RemoteDockerRun(cmdArgs)
		} else {
			err = remoteDockerBuildRunner(options.RemoteDockerHost, options.RemoteDockerSSHCommand, cmdArgs)
		}
		if err != nil {
			return fmt.Errorf("remote build runner %s: %w", options.RemoteDockerHost, err)
		}
		return nil
	}
	// Disable the default BuildKit provenance wrapper so the mutable cache tag
	// points at a manifest that `docker build --cache-from` can import.
	// Deployment tags remain immutable and keep the exact same image contents.
	cmdArgs := dockerBuildCommandArgs(imageTag, spec.Dockerfile, cacheImage, spec.BuildArgs, spec.Context)
	switch {
	case options.Builder != "" && options.CacheOnly:
		cmdArgs = dockerBuildxCacheOnlyCommandArgs(options.Builder, imageTag, spec.Dockerfile, cacheImage, spec.BuildArgs, spec.Context)
	case options.Builder == "" && options.RegistryCacheToRef != "":
		cmdArgs = dockerBuildRegistryCacheCommandArgs(imageTag, spec.Dockerfile, cacheImage, options.RegistryCacheToRef, spec.BuildArgs, spec.Context)
	case options.Builder != "" && options.LocalCacheDir != "":
		// Run-scoped builders are discarded after the deploy, so their cache has
		// to survive on local disk; they never export to the registry.
		cmdArgs = dockerBuildxCommandArgsWithLocalCache(options.Builder, imageTag, spec.Dockerfile, cacheImage, options.LocalCacheDir, options.ImportLocalCache, spec.BuildArgs, spec.Context)
	case options.Builder != "" && options.RegistryCacheToRef != "":
		cmdArgs = dockerBuildxRegistryCacheCommandArgs(options.Builder, imageTag, spec.Dockerfile, cacheImage, options.RegistryCacheToRef, options.RegistryCacheMode, spec.BuildArgs, spec.Context, dockerBuildxOutputOptions{Push: options.Push, MetadataFile: options.MetadataFile})
	case options.Builder != "":
		cmdArgs = dockerBuildxCommandArgs(options.Builder, imageTag, spec.Dockerfile, cacheImage, spec.BuildArgs, spec.Context)
	}

	if options.SkipPullWhenPinned && dockerfileBasesPinned(spec.Dockerfile) {
		cmdArgs = withoutArg(cmdArgs, "--pull")
	}
	if options.progressCapture != nil {
		cmdArgs = withPlainBuildProgress(cmdArgs)
	}

	if dryRun {
		fmt.Printf("[dry-run] docker %s\n", strings.Join(redactDryRunBuildArgs(cmdArgs), " "))
		return nil
	}

	if options.Operation != nil {
		command := exec.Command("docker", cmdArgs...)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if options.progressCapture != nil {
			command.Stdout = buildProgressTee{terminal: os.Stdout, capture: options.progressCapture}
			command.Stderr = buildProgressTee{terminal: os.Stderr, capture: options.progressCapture}
		}
		return runClientWriter(options.Operation, command)
	}
	if options.HostBuildRun != nil {
		return options.HostBuildRun(cmdArgs, options.progressCapture)
	}
	if options.progressCapture != nil {
		return dockerBuildRunnerWithProgress(cmdArgs, options.progressCapture)
	}
	return dockerBuildRunner(cmdArgs)
}

// resolveBuildDockerfile returns the path docker should read. Compose resolves
// a relative dockerfile against the build context, while `docker build -f`
// resolves it against the working directory, so `context: ../..` with
// `dockerfile: apps/web/Dockerfile` failed with "lstat apps". A path that only
// exists relative to the working directory is kept for older configs.
func resolveBuildDockerfile(spec buildSpec) string {
	if spec.Dockerfile == "" || filepath.IsAbs(spec.Dockerfile) {
		return spec.Dockerfile
	}
	inContext := filepath.Join(spec.Context, spec.Dockerfile)
	if _, err := os.Stat(inContext); err == nil {
		return inContext
	}
	if _, err := os.Stat(spec.Dockerfile); err == nil {
		return spec.Dockerfile
	}
	return inContext
}

// dockerfileBasesPinned reports whether every FROM of the Dockerfile names an
// image by digest. A FROM that names an earlier stage is not a base. Anything
// unreadable is "not pinned": the conservative answer keeps --pull.
func dockerfileBasesPinned(path string) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	stages := map[string]bool{}
	found := false
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		image := fields[1]
		if strings.HasPrefix(image, "--") && len(fields) > 2 {
			image = fields[2]
		}
		if len(fields) >= 4 && strings.EqualFold(fields[len(fields)-2], "AS") {
			stages[strings.ToLower(fields[len(fields)-1])] = true
		}
		if stages[strings.ToLower(image)] {
			continue
		}
		found = true
		if !strings.Contains(image, "@sha256:") {
			return false
		}
	}
	return found
}

func withoutArg(args []string, drop string) []string {
	kept := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != drop {
			kept = append(kept, arg)
		}
	}
	return kept
}

// redactDryRunBuildArgs keeps the command useful to inspect without printing
// values expanded from the operator's environment. Build arguments are not a
// secret transport, but real projects still use them for tokens; a preview
// must not turn that mistake into a terminal/history leak.
func redactDryRunBuildArgs(args []string) []string {
	redacted := append([]string(nil), args...)
	for i := 0; i+1 < len(redacted); i++ {
		if redacted[i] != "--build-arg" {
			continue
		}
		key, _, found := strings.Cut(redacted[i+1], "=")
		if found {
			redacted[i+1] = key + "=<redacted>"
		}
		i++
	}
	return redacted
}

func dockerBuildxCommandArgs(builder string, imageTag string, dockerfile string, cacheImage string, buildArgs []string, context string) []string {
	cmdArgs := []string{"buildx", "build", "--builder", builder, "--load", "--pull", "--provenance=false", "-t", imageTag, "-f", dockerfile}
	if cacheImage != "" {
		cmdArgs = append(cmdArgs, "--cache-from", cacheImage)
	}
	cmdArgs = append(cmdArgs, "--build-arg", "BUILDKIT_INLINE_CACHE=1")
	cmdArgs = append(cmdArgs, buildArgs...)
	return append(cmdArgs, context)
}

// dockerBuildxCommandArgsWithLocalCache keeps a run-scoped Buildx builder
// warm across deployments. The directory is app-scoped and intentionally not
// removed with the ephemeral registry/builder artifacts.
func dockerBuildxCommandArgsWithLocalCache(builder string, imageTag string, dockerfile string, cacheImage string, localCacheDir string, importLocalCache bool, buildArgs []string, context string) []string {
	cmdArgs := []string{"buildx", "build", "--builder", builder, "--load", "--pull", "--provenance=false", "-t", imageTag, "-f", dockerfile}
	if cacheImage != "" {
		cmdArgs = append(cmdArgs, "--cache-from", cacheImage)
	}
	if importLocalCache {
		cmdArgs = append(cmdArgs, "--cache-from", "type=local,src="+localCacheDir)
	}
	cmdArgs = append(cmdArgs,
		"--cache-to", "type=local,dest="+localCacheDir+",mode=max",
		"--build-arg", "BUILDKIT_INLINE_CACHE=1",
	)
	cmdArgs = append(cmdArgs, buildArgs...)
	return append(cmdArgs, context)
}

// dockerBuildxRegistryCacheCommandArgs is the persistent-builder counterpart of
// dockerBuildRegistryCacheCommandArgs. The Swarm path always runs with a
// builder, so without this variant every deploy fell back to the inline cache
// of dockerBuildxCommandArgs, mode=min by construction. Inline cache only
// records chains for layers present in the final image, and in the PHP
// Dockerfiles this tool ships, the `extensions` (PECL compilation, 15-20 s) and
// `builder` (composer install) stages exist only behind COPY --from, so they
// were never restorable from the registry and were recompiled on every local
// cache eviction and on every other machine.
//
// On demo-agent on 2026-10-27, a code-only deploy took 72 seconds end to end
// with all 16 build steps cached. The report listed a 57 second build, 17.5
// seconds importing cache, and 53.9 seconds exporting the 6.8 GB image to OCI
// and importing it into Docker. The following docker push reported "Layer
// already exists" for every layer. Swarm opts into direct BuildKit push to
// remove that redundant daemon round trip, with a 70 to 80 second end-to-end
// operator target; other build paths keep --load.
// image-manifest=true + oci-mediatypes=true store the cache as an OCI image
// manifest, which a plain registry:2/3 accepts and which HEAD
// /v2/.../manifests/ still resolves. cacheMode is deploy.build_cache_mode;
// empty means "max".
type dockerBuildxOutputOptions struct {
	Push         bool
	MetadataFile string
}

func dockerBuildxRegistryCacheCommandArgs(builder string, imageTag string, dockerfile string, cacheFromRef string, cacheToRef string, cacheMode string, buildArgs []string, context string, outputOptions dockerBuildxOutputOptions) []string {
	if cacheMode == "" {
		cacheMode = config.BuildCacheModeMax
	}
	outputFlag := "--load"
	if outputOptions.Push {
		outputFlag = "--push"
	}
	cmdArgs := []string{"buildx", "build", "--builder", builder, outputFlag, "--pull", "--provenance=false", "-t", imageTag, "-f", dockerfile}
	if outputOptions.MetadataFile != "" {
		cmdArgs = append(cmdArgs, "--metadata-file", outputOptions.MetadataFile)
	}
	if cacheFromRef != "" {
		cmdArgs = append(cmdArgs, "--cache-from", "type=registry,ref="+cacheFromRef)
	}
	cmdArgs = append(cmdArgs, "--cache-to", "type=registry,ref="+cacheToRef+",mode="+cacheMode+",image-manifest=true,oci-mediatypes=true")
	cmdArgs = append(cmdArgs, buildArgs...)
	return append(cmdArgs, context)
}

// dockerBuildxCacheOnlyCommandArgs is the first of the two builds of an
// overlapped Swarm deploy: it builds into the builder's own cache and has no
// output flag, so nothing is exported to the Docker daemon, pushed, or written to
// the registry cache. It reads the registry cache the same way
// dockerBuildxRegistryCacheCommandArgs does, so the second build, which differs
// from this one only in --push, --metadata-file and --cache-to, is answered
// entirely from the cache this one filled.
func dockerBuildxCacheOnlyCommandArgs(builder string, imageTag string, dockerfile string, cacheFromRef string, buildArgs []string, context string) []string {
	cmdArgs := []string{"buildx", "build", "--builder", builder, "--pull", "--provenance=false", "-t", imageTag, "-f", dockerfile}
	if cacheFromRef != "" {
		cmdArgs = append(cmdArgs, "--cache-from", "type=registry,ref="+cacheFromRef)
	}
	cmdArgs = append(cmdArgs, buildArgs...)
	return append(cmdArgs, context)
}

func dockerBuildCommandArgs(imageTag string, dockerfile string, cacheImage string, buildArgs []string, context string) []string {
	cmdArgs := []string{"build", "--pull", "--provenance=false", "-t", imageTag, "-f", dockerfile}
	if cacheImage != "" {
		cmdArgs = append(cmdArgs, "--cache-from", cacheImage)
	}
	cmdArgs = append(cmdArgs, "--build-arg", "BUILDKIT_INLINE_CACHE=1")
	cmdArgs = append(cmdArgs, buildArgs...)
	return append(cmdArgs, context)
}

// dockerBuildRegistryCacheCommandArgs exports the build cache to the registry
// in mode=max instead of relying on inline cache. Inline cache only records the
// final image's layers, so after a local cache eviction every intermediate
// stage of a multi-stage Dockerfile (dependency installs, compilers) rebuilds
// from scratch; mode=max keeps those stages restorable from the local registry.
// image-manifest=true stores the cache as an OCI image manifest so a plain
// registry:2 accepts it and existence probes keep working.
func dockerBuildRegistryCacheCommandArgs(imageTag string, dockerfile string, cacheFromRef string, cacheToRef string, buildArgs []string, context string) []string {
	cmdArgs := []string{"build", "--pull", "--provenance=false", "-t", imageTag, "-f", dockerfile}
	if cacheFromRef != "" {
		cmdArgs = append(cmdArgs, "--cache-from", "type=registry,ref="+cacheFromRef)
	}
	cmdArgs = append(cmdArgs, "--cache-to", "type=registry,ref="+cacheToRef+",mode=max,image-manifest=true,oci-mediatypes=true")
	cmdArgs = append(cmdArgs, buildArgs...)
	return append(cmdArgs, context)
}

// pruneLocalBuildCache reclaims local disk used by the Docker build cache after
// a successful deploy. Behaviour is driven by cfg.Deploy.PruneBuildCache:
//
//	off:    do nothing
//	capped: cap total build-cache size (keeps recent layers for fast rebuilds)
//	all:    wipe the entire build cache
func pruneLocalBuildCache(cfg *config.Config) error {
	builder := persistentBuilderName(cfg.App)
	switch cfg.Deploy.PruneBuildCache {
	case "", "off":
		return nil
	case "all":
		output.Step("Pruning local build cache (all)...")
		return localBuildCachePruner("buildx", "prune", "--builder", builder, "-af")
	default: // "capped"
		keep := cfg.Deploy.BuildCacheKeep
		if keep == "" {
			keep = "5GB"
		}
		output.Step("Pruning local build cache (keep %s)...", keep)
		return localBuildCachePruner("buildx", "prune", "--builder", builder, "-f", "--max-used-space", keep)
	}
}

// localBuildCachePruner is a narrow seam over the docker CLI so the prune
// outcome can be verified without a Docker daemon.
var localBuildCachePruner = func(args ...string) error {
	return exec.Command("docker", args...).Run()
}

// pruneLocalBuildCacheAfterPromotion runs the prune once the release is
// promoted and verified, and never turns its failure into a deploy failure.
//
// The prune is a `docker buildx prune` on the operator's own machine: it
// touches nothing on the VPS. It used to return its error as the deploy's
// error, and in the swarm path that also set cleanupFailed, so the operation
// finished with operation-abort and the host journal record moved to
// recovery_required. Every later deploy of the app was then refused until
// someone hand-edited /var/lib/shuttle/operations/*.json, all because a laptop
// cache could not be pruned (docker daemon restarted, builder already gone).
// A verified release is live whatever the laptop's disk looks like, so the
// failure is reported with the manual command and the deploy completes.
func pruneLocalBuildCacheAfterPromotion(cfg *config.Config) {
	if err := pruneLocalBuildCache(cfg); err != nil {
		output.Attn("Release verified, but the local build cache prune failed: %v", err)
		output.Detail("Reclaim the space manually: docker buildx prune --builder %s", persistentBuilderName(cfg.App))
	}
}

func persistentBuilderName(app string) string {
	return "shuttle-" + app
}

// dockerBuilderRunner is a narrow seam over the docker CLI so the builder
// lifecycle (creation flags, restart, shutdown and the host-network migration)
// can be verified without a Docker daemon.
var dockerBuilderRunner = func(args ...string) ([]byte, error) {
	return exec.Command("docker", args...).CombinedOutput()
}

// The docker-container driver runs BuildKit inside its own network namespace,
// so its 127.0.0.1 is the container's loopback, not the host's. shuttle reaches
// the remote registry through an SSH tunnel bound to the *host* loopback
// (127.0.0.1:<random port>), which a bridged BuildKit simply cannot dial: every
// deploy failed the registry cache import with "connect: connection refused"
// and rebuilt every stage from scratch. Sharing the host namespace puts the
// tunnel back in reach.
//
// Security trade-off, deliberate: network=host also exposes every service
// listening on the developer's loopback (databases, dev servers, agent sockets)
// to anything running in a build stage. shuttle is a deploy CLI a developer
// runs on their own workstation against their own Dockerfile, so the blast
// radius stays inside a trust boundary they already own, but this is not a
// setting to copy into shared or untrusted build infrastructure.
const persistentBuilderNetworkDriverOpt = "network=host"

// persistentBuilderUsesHostNetwork reports whether an existing builder already
// lives in the host network namespace. Two signals, because they can disagree:
// "docker buildx inspect" prints the *stored* driver options that a future
// bootstrap will apply (verified to survive container removal), while the
// container's HostConfig.NetworkMode is what the currently running BuildKit
// actually got (verified to print literally "bridge" or "host"). A builder
// created before this flag existed keeps its namespace across restarts
// otherwise, because driver options are frozen when the builder is created.
func persistentBuilderUsesHostNetwork(name string) bool {
	inspected, err := dockerBuilderRunner("buildx", "inspect", name)
	if err != nil || !strings.Contains(string(inspected), `network="host"`) {
		return false
	}
	mode, err := dockerBuilderRunner("inspect", buildkitContainerName(name), "--format", "{{.HostConfig.NetworkMode}}")
	if err != nil {
		// The node has no container yet (never bootstrapped, or pruned). The
		// stored driver option above decides what the next bootstrap gets.
		return true
	}
	return strings.TrimSpace(string(mode)) == "host"
}

// buildkitContainerName mirrors buildx's own naming for the single node it
// creates per builder.
func buildkitContainerName(name string) string {
	return "buildx_buildkit_" + name + "0"
}

func ensurePersistentBuilder(app string) error {
	name := persistentBuilderName(app)
	_, inspectErr := dockerBuilderRunner("buildx", "inspect", name)
	exists := inspectErr == nil
	if exists && !persistentBuilderUsesHostNetwork(name) {
		// Migration for builders created before the network=host fix: driver
		// options are frozen at create time, so the only way out of the wrong
		// network namespace is to drop the builder and make a new one. Only the
		// local build cache is lost; the registry cache is untouched.
		output.Step("Recreating BuildKit builder %s on the host network...", name)
		if out, err := dockerBuilderRunner("buildx", "rm", name); err != nil {
			return fmt.Errorf("recreate persistent BuildKit builder: %s", strings.TrimSpace(string(out)))
		}
		exists = false
	}
	if exists {
		// A docker-container builder is a cache object, not a workstation
		// daemon. Stop any instance left by the previous command before
		// bootstrapping this run so every deploy gets a fresh BuildKit process.
		// The builder metadata and cache volume survive the stop.
		if out, err := dockerBuilderRunner("buildx", "stop", name); err != nil {
			return fmt.Errorf("stop previous BuildKit builder: %s", strings.TrimSpace(string(out)))
		}
	}
	if !exists {
		out, err := dockerBuilderRunner("buildx", "create", "--name", name, "--driver", "docker-container", "--driver-opt", persistentBuilderNetworkDriverOpt)
		if err != nil {
			return fmt.Errorf("create persistent BuildKit builder: %s", strings.TrimSpace(string(out)))
		}
	}
	if out, err := dockerBuilderRunner("buildx", "inspect", "--bootstrap", name); err != nil {
		return fmt.Errorf("bootstrap persistent BuildKit builder: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// stopPersistentBuilder makes the local BuildKit process strictly run-scoped.
// The buildx builder definition and its cache volume remain available for the
// next deploy; only the daemon container is stopped. Missing builders are a
// successful no-op so cleanup is safe after a partial create or bootstrap.
func stopPersistentBuilder(app string) error {
	name := persistentBuilderName(app)
	if _, err := dockerBuilderRunner("buildx", "inspect", name); err != nil {
		return nil
	}
	out, err := dockerBuilderRunner("buildx", "stop", name)
	if err != nil {
		return fmt.Errorf("stop BuildKit builder %s: %s", name, strings.TrimSpace(string(out)))
	}
	return nil
}

// dockerPushRunner and dockerTagRunner are kept behind narrow seams so the
// cache-tag skip in pushPlannedImagesWithOptions can be verified without a
// Docker daemon.
func dockerPushForOperation(imageTag string, operation *remoteOperation) error {
	if operation == nil {
		return dockerPush(imageTag)
	}
	command := exec.Command("docker", "push", imageTag)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return runClientWriter(operation, command)
}

var dockerPushRunner = func(imageTag string) error {
	cmd := exec.Command("docker", "push", imageTag)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

var dockerTagRunner = func(source string, target string) error {
	cmd := exec.Command("docker", "tag", source, target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// dockerImageExistsRunner reports whether the local daemon holds the tag. A
// push can only send what the daemon has, and --skip-build is the one path that
// reaches the push without having produced it.
var dockerImageExistsRunner = func(imageTag string) bool {
	return exec.Command("docker", "image", "inspect", imageTag).Run() == nil
}

func dockerPush(imageTag string) error {
	return dockerPushRunner(imageTag)
}

func dockerImageExists(imageTag string) bool {
	return dockerImageExistsRunner(imageTag)
}

func dockerTag(source string, target string) error {
	return dockerTagRunner(source, target)
}

// shuttleOwnsProxy reports whether shuttle manages a centralized reverse proxy
// on the target host. It is true only when the config declares Caddy routes:
// the very condition that makes the deploy write a conf.d snippet and reload
// Caddy. When it is false the project's own compose file carries the reverse
// proxy (and its published ports), and must be left alone.
func deepCopyAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCopyAny(val)
		}
		return out
	case map[any]any:
		out := make(map[any]any, len(t))
		for k, val := range t {
			out[k] = deepCopyAny(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deepCopyAny(val)
		}
		return out
	default:
		return v
	}
}

// mergeEnvFiles rewrites a service's env_file so it lists exactly the env files
// that exist on the remote host. Entries shuttle does not ship are dropped and
// returned: keeping them would make `docker compose` fail on the host with
// "env file not found", since only the configured non-secret .env is uploaded.
//
// Returns a nil value when the existing entry uses a shape we cannot safely
// rewrite (the mapping form with `path:`/`required:`), leaving it untouched.
// withoutCaddyDeps strips depends_on references to the caddy service that the
// centralized-proxy rewrite has just removed. Returns nil when nothing is left.
// setServiceLabel adds a label without discarding the labels already declared,
// handling both the mapping and the "key=value" list form.
// expandShellVar handles ${VAR:-default}, ${VAR:?error}, ${VAR} and $VAR patterns.
func expandShellVar(val string) string {
	if !strings.Contains(val, "$") {
		return val
	}
	// Extract variable name from patterns like ${VAR:-default} or ${VAR:?msg}
	if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
		inner := val[2 : len(val)-1]
		var varName, defaultVal string
		if idx := strings.Index(inner, ":-"); idx >= 0 {
			varName = inner[:idx]
			defaultVal = inner[idx+2:]
		} else if idx := strings.Index(inner, ":?"); idx >= 0 {
			varName = inner[:idx]
		} else {
			varName = inner
		}
		if v := os.Getenv(varName); v != "" {
			return v
		}
		return defaultVal
	}
	return os.ExpandEnv(val)
}

func loadDotenv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, "\"'")
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}
