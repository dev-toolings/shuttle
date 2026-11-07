package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
)

type plannedBuild struct {
	Service  string
	Services []string
	Image    string
	// BuildImage is the registry reference visible from the machine running
	// BuildKit. It normally equals Image. A remote runner sees its own loopback
	// tunnel while Image stays on the deploy client's VPS tunnel for digest
	// resolution and the exact Swarm reference.
	BuildImage string
	Spec       *buildSpec
	// CacheImage is a mutable cache pointer only. Production always deploys the
	// immutable commit-qualified Image above.
	CacheImage      string
	BuildCacheImage string
}

type buildSpec struct {
	Context    string
	Dockerfile string
	BuildArgs  []string
}

// buildExecutionOptions describes the local BuildKit state available to one
// deployment. The default path uses the daemon builder and registry cache;
// run-scoped artifact deployments additionally import/export an app-scoped
// local cache because their builder is intentionally removed after each run.
type buildExecutionOptions struct {
	Operation *remoteOperation
	Builder   string
	// Push publishes the persistent-builder output directly from BuildKit.
	// MetadataFile is assigned per planned build so parallel builds never share it.
	Push         bool
	MetadataFile string
	// PushedDigests records the digest each BuildKit push was verified
	// against, so the deploy promotes exactly that digest (see
	// pushedDigestSet). Shared by pointer across the per-build copies.
	PushedDigests     *pushedDigestSet
	LocalCacheDir     string
	ImportLocalCache  bool
	SkipRegistryCache bool
	// Remote fields select the verified SSH Docker transport. Empty values keep
	// the existing local command path byte-for-byte identical.
	RemoteBuilder          string
	RemoteDockerHost       string
	RemoteDockerSSHCommand string
	RemoteDockerRun        func([]string) error
	// RegistryCacheExport replaces the inline cache with a registry cache export
	// (mode=max), which also covers the intermediate stages of multi-stage
	// Dockerfiles. It applies to both the builder-less path (which needs the
	// containerd image store on the local daemon) and the persistent
	// docker-container builder used by the Swarm deploy (which does not).
	// RegistryCacheToRef is filled per build from plannedBuild.CacheImage.
	RegistryCacheExport bool
	RegistryCacheToRef  string
	// RegistryCacheMode is the BuildKit cache mode of that export, "max" or
	// "min" (deploy.build_cache_mode). Empty means "max".
	RegistryCacheMode string
	// CacheOnly builds into the persistent builder's cache and nothing else: no
	// output flag (no --load, no --push), no registry cache export and no
	// metadata file. A Swarm deploy runs it while the stack-reclaim finishes on
	// the VPS, then runs the same build again with Push and the cache export,
	// which BuildKit answers from the cache it just filled (DEV-DEPL-85).
	CacheOnly bool
	// CachedPublish marks that second run in the output: it does not rebuild,
	// it pushes what the CacheOnly run built.
	CachedPublish bool
	// ExtraArgs are appended to every build of the run, verbatim, before the
	// context. The compose strategy uses it for the `--label` that scopes its
	// remote prune to the images it built; the swarm strategy passes none, so
	// its commands are the ones they always were.
	ExtraArgs []string
	// SkipPullWhenPinned drops `--pull` from a build whose Dockerfile pins
	// every base image by digest: the pull could not change what is built.
	SkipPullWhenPinned bool
	// ProgressResults is set by local Swarm deploys. Compose builds use their
	// ownership label to enable the same per-build capture.
	ProgressResults *buildProgressResults
	// progressCapture belongs to one planned build and is filled by the command
	// runner while it tees output to the terminal.
	progressCapture *buildProgressCapture
	HostBuildRun    func([]string, *buildProgressCapture) error
}

func parseBuildSpec(build any) (buildSpec, error) {
	spec := buildSpec{Context: ".", Dockerfile: "Dockerfile"}
	switch value := build.(type) {
	case string:
		spec.Context = value
		return spec, nil
	case map[string]any:
		if context, ok := value["context"].(string); ok && strings.TrimSpace(context) != "" {
			spec.Context = context
		}
		if dockerfile, ok := value["dockerfile"].(string); ok && strings.TrimSpace(dockerfile) != "" {
			spec.Dockerfile = dockerfile
		}
		if target, ok := value["target"].(string); ok && strings.TrimSpace(target) != "" {
			spec.BuildArgs = append(spec.BuildArgs, "--target", target)
		}

		if args, ok := value["args"]; ok {
			if argMap, ok := args.(map[string]any); ok {
				keys := make([]string, 0, len(argMap))
				for key := range argMap {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					val := argMap[key]
					expanded := expandShellVar(fmt.Sprintf("%v", val))
					spec.BuildArgs = append(spec.BuildArgs, "--build-arg", fmt.Sprintf("%s=%s", key, expanded))
				}
			}
		}

		return spec, nil
	default:
		return buildSpec{}, fmt.Errorf("unsupported build format %T", build)
	}
}

func buildPlannedImagesWithOptions(cf *composeFile, plan buildPlan, dryRun bool, options buildExecutionOptions) error {
	if len(plan.Builds) == 0 {
		return nil
	}
	progressResults := options.ProgressResults
	if progressResults == nil && composeLocalBuildUsesLabel(options.ExtraArgs) {
		progressResults = &buildProgressResults{}
	}
	// The second run of an overlapped deploy only pushes what the first built.
	verb, timing := "Building", "build"
	if options.CachedPublish {
		verb, timing = "Publishing", "publish"
	}
	output.Step("%s %d unique images in parallel...", verb, len(plan.Builds))
	var wg sync.WaitGroup
	errs := make(chan error, len(plan.Builds))
	for buildIndex, build := range plan.Builds {
		build := build
		buildIndex := buildIndex
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			output.Step("%s %s for %s...", verb, build.Service, joinServices(build.Services))
			cacheImage := ""
			if !dryRun && !options.SkipRegistryCache {
				for _, candidate := range buildCacheCandidates(build.CacheImage) {
					exists, err := registryImageExists(candidate)
					if err != nil {
						output.Attn("Build cache lookup failed for %s: %v; continuing without it", candidate, err)
						break
					}
					if exists {
						cacheImage = candidate
						output.Detail("Using registry build cache %s", cacheImage)
						break
					}
				}
			}
			buildOptions := options
			if progressResults != nil {
				buildOptions.progressCapture = newBuildProgressCapture()
			}
			metadataFile := ""
			if options.Push {
				if dryRun {
					metadataFile = filepath.Join(os.TempDir(), fmt.Sprintf("shuttle-build-metadata-dry-run-%d.json", buildIndex))
				} else {
					file, err := os.CreateTemp("", "shuttle-build-metadata-*.json")
					if err != nil {
						errs <- fmt.Errorf("create build metadata file for %s: %w", build.Image, err)
						return
					}
					metadataFile = file.Name()
					if err := file.Close(); err != nil {
						_ = os.Remove(metadataFile)
						errs <- fmt.Errorf("close build metadata file for %s: %w", build.Image, err)
						return
					}
					defer os.Remove(metadataFile)
				}
			}
			buildOptions.MetadataFile = metadataFile
			if err := buildPlannedImageWithOptions(cf, build, cacheImage, dryRun, buildOptions); err != nil {
				// A failed build is when the step table helps most: it shows how
				// far the cache carried the build before the failing step.
				if buildOptions.progressCapture != nil {
					if detail := buildOptions.progressCapture.Summary().Detail(build.Service); detail != "" {
						output.Detail("%s", detail)
					}
				}
				errs <- fmt.Errorf("build %s: %w", build.Service, err)
				return
			}
			if options.Push && !dryRun {
				metadataDigest, err := readBuildMetadataDigest(metadataFile)
				if err != nil {
					errs <- fmt.Errorf("read BuildKit metadata for %s: %w", build.Image, err)
					return
				}
				// In push mode BuildKit always records containerimage.digest. An
				// empty value (missing key or empty file) means the push did not
				// behave as expected, so the release identity cross-check must
				// fail closed instead of being skipped.
				if metadataDigest == "" {
					errs <- fmt.Errorf("BuildKit metadata for %s has no containerimage.digest: cannot cross-check the pushed release identity", build.Image)
					return
				}
				registry := firstRegistry(build.Image)
				headDigest, err := registryTagDigest(build.Image, registry)
				if err != nil {
					errs <- fmt.Errorf("read registry HEAD digest for %s: %w", build.Image, err)
					return
				}
				if metadataDigest != headDigest {
					errs <- fmt.Errorf("BuildKit metadata digest %s does not match registry HEAD digest %s for %s", metadataDigest, headDigest, build.Image)
					return
				}
				options.PushedDigests.record(build.Image, metadataDigest)
			}
			buildDuration := time.Since(started)
			output.Detail("Timing %s.%s: %s", timing, build.Service, formatDeployDuration(buildDuration))
			if buildOptions.progressCapture != nil {
				summary := buildOptions.progressCapture.Summary()
				if detail := summary.Detail(build.Service); detail != "" {
					output.Detail("%s", detail)
				}
				progressResults.add(buildProgressReport{Service: build.Service, Duration: buildDuration, Summary: summary})
			}
		}()
	}
	wg.Wait()
	close(errs)
	if err, ok := <-errs; ok {
		return err
	}
	return nil
}

// Compose deploy builds carry a private ownership label so the strategy can
// prune exactly its own local images. That label is also the stable marker for
// enabling the same bounded diagnosis as Swarm without changing unrelated
// build-plan callers such as cache maintenance.
func composeLocalBuildUsesLabel(args []string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--label" && strings.HasPrefix(args[index+1], composeAppLabel+"=") {
			return true
		}
	}
	return false
}

func buildPlannedImageWithOptions(cf *composeFile, build plannedBuild, cacheImage string, dryRun bool, options buildExecutionOptions) error {
	if options.RegistryCacheExport {
		if options.RemoteBuilder != "" {
			options.RegistryCacheToRef = firstNonEmpty(build.BuildCacheImage, build.CacheImage)
		} else {
			options.RegistryCacheToRef = build.CacheImage
		}
	}
	imageTag := build.Image
	if options.RemoteBuilder != "" {
		imageTag = firstNonEmpty(build.BuildImage, build.Image)
		cacheImage = rewriteRegistryReference(cacheImage, firstRegistry(build.BuildCacheImage))
	}
	if build.Spec == nil {
		if options.LocalCacheDir != "" {
			return fmt.Errorf("local cache requires an explicit build specification for %s", build.Service)
		}
		return buildServiceImageWithCacheOptions(cf, build.Service, imageTag, cacheImage, dryRun, options)
	}
	if options.LocalCacheDir != "" {
		// Independent images can build concurrently. Give each one its own local
		// cache exporter directory so BuildKit never has two writers for a single
		// local cache index, while retaining it across ephemeral runs.
		options.LocalCacheDir = filepath.Join(options.LocalCacheDir, safeArtifactName(build.Service))
		options.ImportLocalCache = localBuildCacheExists(options.LocalCacheDir)
	}
	return buildImageWithSpecWithOptions(*build.Spec, imageTag, cacheImage, dryRun, options)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstRegistry(value string) string {
	if slash := strings.IndexByte(value, '/'); slash > 0 {
		return value[:slash]
	}
	return ""
}

func rewriteRegistryReference(image, registry string) string {
	if image == "" || registry == "" {
		return image
	}
	slash := strings.IndexByte(image, '/')
	if slash <= 0 {
		return image
	}
	return registry + image[slash:]
}

func localBuildCacheExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "index.json"))
	return err == nil
}

func buildCacheCandidates(cacheImage string) []string {
	if cacheImage == "" {
		return nil
	}
	candidates := []string{cacheImage}
	if strings.HasSuffix(cacheImage, ":buildcache") {
		// v2.2.6 and earlier published a mutable :latest tag. Use it once as
		// migration cache, then every successful build refreshes :buildcache.
		candidates = append(candidates, strings.TrimSuffix(cacheImage, ":buildcache")+":latest")
	}
	return candidates
}

// pushCacheTags must be false when the build already exported a registry cache
// manifest under the :buildcache ref: tagging and pushing the deployment image
// over it would replace the mode=max cache with its final-stage layers only.
func pushPlannedImagesWithOptions(plan buildPlan, pushCacheTags bool) error {
	return pushPlannedImagesForOperation(plan, pushCacheTags, nil)
}

func pushPlannedImagesForOperation(plan buildPlan, pushCacheTags bool, operation *remoteOperation) error {

	var wg sync.WaitGroup
	errs := make(chan error, len(plan.Builds))
	for _, build := range plan.Builds {
		build := build
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The Git version is not a content identity: an ignored build context
			// or a refreshed base image can rebuild differently under the same
			// tag. Prefer the local build and let Docker deduplicate its layers;
			// skipping on a registry HEAD once reported a successful promotion
			// while the VPS still served the previous application. A registry-only
			// retry remains valid when local cleanup has removed the image.
			// --skip-build is meant for a retry: the build already ran here and
			// only the push or the promotion failed. Reached without that build,
			// the image exists nowhere and `docker push` fails on its own terms
			// ("exit status 1"), naming neither the flag nor the missing image.
			if !dockerImageExists(build.Image) {
				exists, err := registryImageExists(build.Image)
				if err != nil {
					errs <- fmt.Errorf("check %s: %w", build.Image, err)
					return
				}
				if exists {
					output.Detail("Registry already has %s; reusing published image", build.Image)
					return
				}
				errs <- fmt.Errorf("%s is in neither the registry nor the local Docker daemon: --skip-build requires an image from an earlier build or a prior publish, so run the deploy without it", build.Image)
				return
			}
			output.Step("Pushing %s for %s...", build.Image, joinServices(build.Services))
			if err := preserveRegistryManifest(build.Image); err != nil {
				errs <- fmt.Errorf("preserve previous %s before push: %w", build.Image, err)
				return
			}
			if err := dockerPushForOperation(build.Image, operation); err != nil {
				errs <- fmt.Errorf("push %s: %w", build.Image, err)
				return
			}
			if !pushCacheTags {
				return
			}
			if err := dockerTag(build.Image, build.CacheImage); err != nil {
				errs <- fmt.Errorf("tag cache %s: %w", build.CacheImage, err)
				return
			}
			if err := dockerPushForOperation(build.CacheImage, operation); err != nil {
				errs <- fmt.Errorf("push cache %s: %w", build.CacheImage, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	if err, ok := <-errs; ok {
		return err
	}
	return nil
}

// A reused Git tag may be the last tag naming a retained release. Preserve its
// manifest before overwriting it, or the registry's --delete-untagged collector
// removes a rollback image even though the retained stack still names its
// digest. The normal digest-based retention policy removes this alias when
// neither retained stack needs it; no image layers are copied or downloaded.
func preserveRegistryManifest(image string) error {
	manifestURL, err := registryManifestURL(image)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, manifestURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("read previous manifest: %s", resp.Status)
	}
	const limit = 4 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > limit {
		return fmt.Errorf("previous manifest must contain 1 to %d bytes", limit)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if advertised := resp.Header.Get("Docker-Content-Digest"); advertised != "" && advertised != "sha256:"+digest {
		return fmt.Errorf("previous manifest does not match its advertised digest")
	}
	aliasURL := manifestURL[:strings.LastIndex(manifestURL, "/")+1] + "retained-sha256-" + digest
	put, err := http.NewRequest(http.MethodPut, aliasURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	put.Header.Set("Content-Type", resp.Header.Get("Content-Type"))
	preserved, err := client.Do(put)
	if err != nil {
		return err
	}
	defer preserved.Body.Close()
	if preserved.StatusCode != http.StatusCreated {
		return fmt.Errorf("preserve previous manifest: %s", preserved.Status)
	}
	return nil
}

// localPublishedImageTags returns only the exact local tags created for a
// publish. The registry retains these manifests for remote pulls and build
// cache; this list is solely for removing their daemon-side tag references.
func localPublishedImageTags(plan buildPlan) []string {
	return localPublishedImageTagsForBuildMode(plan, false)
}

// localPublishedImageTagsForBuildMode returns daemon tags only when the build
// output was loaded locally. BuildKit --push leaves no image tags in the Docker
// daemon, so inspecting or removing them would add noise to deploy cleanup.
func localPublishedImageTagsForBuildMode(plan buildPlan, pushedByBuildKit bool) []string {
	if pushedByBuildKit {
		return nil
	}
	seen := make(map[string]struct{}, len(plan.Builds)*2)
	tags := make([]string, 0, len(plan.Builds)*2)
	for _, build := range plan.Builds {
		for _, tag := range []string{build.Image, build.CacheImage} {
			if tag == "" {
				continue
			}
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
	}
	return tags
}

// localImageCleanup removes only daemon tags first created by this publish. It
// never mutates the registry, its persistent volume, or Docker's global cache.
type localImageCleanup struct {
	tags        []string
	imageExists func(string) (bool, error)
	removeImage func(string) error
}

func localImageExists(tag string) (bool, error) {
	cmd := exec.Command("docker", "image", "inspect", tag)
	combined, err := cmd.CombinedOutput()
	return classifyLocalImageInspect(tag, combined, err)
}

func classifyLocalImageInspect(tag string, combined []byte, err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	message := strings.ToLower(string(combined))
	if strings.Contains(message, "no such image") {
		return false, nil
	}
	return false, fmt.Errorf("inspect local image %s: %w: %s", tag, err, strings.TrimSpace(string(combined)))
}

// prepareLocalImageCleanup records only tags that do not exist before this
// deploy. A retry or --skip-build therefore never removes an operator-owned
// tag that Shuttle merely consumed.
//
// pruneExisting drops that guard: the deploy then owns every tag it publishes,
// including one another tool left behind under the same name. It is opt-in
// (deploy.prune_local_images) because the guard is what keeps a Makefile target
// or a manual build from losing its image to an unrelated deploy.
func prepareLocalImageCleanup(tags []string, pruneExisting bool) (localImageCleanup, error) {
	return prepareLocalImageCleanupWithLookup(tags, pruneExisting, localImageExists, func(tag string) error {
		return exec.Command("docker", "image", "rm", tag).Run()
	})
}

func prepareLocalImageCleanupWithLookup(tags []string, pruneExisting bool, imageExists func(string) (bool, error), removeImage func(string) error) (localImageCleanup, error) {
	cleanup := localImageCleanup{
		tags:        make([]string, 0, len(tags)),
		imageExists: imageExists,
		removeImage: removeImage,
	}
	for _, tag := range tags {
		if pruneExisting {
			cleanup.tags = append(cleanup.tags, tag)
			continue
		}
		exists, err := imageExists(tag)
		if err != nil {
			return localImageCleanup{}, err
		}
		if !exists {
			cleanup.tags = append(cleanup.tags, tag)
		}
	}
	return cleanup, nil
}

func (c localImageCleanup) Cleanup() error {
	var failures []string
	for _, tag := range c.tags {
		exists, err := c.imageExists(tag)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if !exists {
			continue
		}
		if err := c.removeImage(tag); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", tag, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("remove local publish images: %s", strings.Join(failures, "; "))
	}
	return nil
}

func mergeCleanupError(deployErr *error, cleanupErr error) {
	if cleanupErr == nil {
		return
	}
	if *deployErr == nil {
		*deployErr = cleanupErr
		return
	}
	*deployErr = fmt.Errorf("%w; cleanup also failed: %v", *deployErr, cleanupErr)
}

func registryImageExists(image string) (bool, error) {
	manifestURL, err := registryManifestURL(image)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest(http.MethodHead, manifestURL, nil)
	if err != nil {
		return false, fmt.Errorf("create registry request: %w", err)
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("query registry manifest: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("registry manifest returned %s", resp.Status)
	}
}

func registryManifestURL(image string) (string, error) {
	slash := strings.IndexByte(image, '/')
	colon := strings.LastIndexByte(image, ':')
	if slash <= 0 || colon <= slash+1 || colon == len(image)-1 {
		return "", fmt.Errorf("invalid tagged registry image %q", image)
	}
	registry := image[:slash]
	repository := image[slash+1 : colon]
	reference := image[colon+1:]
	return fmt.Sprintf("http://%s/v2/%s/manifests/%s", registry, repository, url.PathEscape(reference)), nil
}

func joinServices(services []string) string {
	result := ""
	for index, service := range services {
		if index > 0 {
			result += ", "
		}
		result += service
	}
	return result
}

type buildPlan struct {
	Builds        []plannedBuild
	ServiceImages map[string]string
}

func configuredBuildServices(build config.Build) []string {
	seen := make(map[string]struct{})
	var services []string
	for _, definition := range build.Services {
		for _, service := range definition.Services {
			if _, exists := seen[service]; exists {
				continue
			}
			seen[service] = struct{}{}
			services = append(services, service)
		}
	}
	sort.Strings(services)
	return services
}

func createBuildPlan(cf *composeFile, registryAddr string, app string, version string) (buildPlan, error) {
	services := findBuildServices(cf)
	sort.Strings(services)
	groups := make(map[string][]string)
	for _, service := range services {
		key, err := canonicalBuildKey(cf.Services[service].Build)
		if err != nil {
			return buildPlan{}, fmt.Errorf("build %s: %w", service, err)
		}
		groups[key] = append(groups[key], service)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := buildPlan{ServiceImages: make(map[string]string, len(services))}
	for _, key := range keys {
		members := groups[key]
		representative := members[0]
		repository := fmt.Sprintf("%s/%s-%s", registryAddr, app, representative)
		image := fmt.Sprintf("%s:%s", repository, version)
		result.Builds = append(result.Builds, plannedBuild{
			Service: representative, Services: members, Image: image, BuildImage: image, CacheImage: repository + ":buildcache", BuildCacheImage: repository + ":buildcache",
		})
		for _, service := range members {
			result.ServiceImages[service] = image
		}
	}
	return result, nil
}

// createConfiguredBuildPlan uses build.services when present. Each configured
// key becomes one immutable image, which may be referenced by several compose
// services. The existing compose-derived grouping remains the fallback.
func createConfiguredBuildPlan(cf *composeFile, build config.Build, registryAddr string, app string, version string) (buildPlan, error) {
	if len(build.Services) == 0 {
		return createBuildPlan(cf, registryAddr, app, version)
	}

	keys := make([]string, 0, len(build.Services))
	for name := range build.Services {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	result := buildPlan{ServiceImages: make(map[string]string)}
	assigned := make(map[string]string)
	for _, name := range keys {
		definition := build.Services[name]
		if len(definition.Services) == 0 {
			return buildPlan{}, fmt.Errorf("build.services.%s.services is required", name)
		}
		spec := buildSpec{Context: definition.Context, Dockerfile: definition.Dockerfile}
		if spec.Context == "" {
			spec.Context = "."
		}
		if spec.Dockerfile == "" {
			spec.Dockerfile = "Dockerfile"
		}
		if definition.Target != "" {
			spec.BuildArgs = append(spec.BuildArgs, "--target", definition.Target)
		}
		argKeys := make([]string, 0, len(definition.Args))
		for key := range definition.Args {
			argKeys = append(argKeys, key)
		}
		sort.Strings(argKeys)
		for _, key := range argKeys {
			spec.BuildArgs = append(spec.BuildArgs, "--build-arg", fmt.Sprintf("%s=%s", key, expandShellVar(definition.Args[key])))
		}
		services := append([]string(nil), definition.Services...)
		sort.Strings(services)
		for _, service := range services {
			if _, ok := cf.Services[service]; !ok {
				return buildPlan{}, fmt.Errorf("build.services.%s references unknown compose service %q", name, service)
			}
			if previous, exists := assigned[service]; exists {
				return buildPlan{}, fmt.Errorf("compose service %q is assigned to both build.services.%s and build.services.%s", service, previous, name)
			}
			assigned[service] = name
		}
		image := fmt.Sprintf("%s/%s-%s:%s", registryAddr, app, name, version)
		cacheImage := fmt.Sprintf("%s/%s-%s:buildcache", registryAddr, app, name)
		result.Builds = append(result.Builds, plannedBuild{Service: name, Services: services, Image: image, BuildImage: image, CacheImage: cacheImage, BuildCacheImage: cacheImage, Spec: &spec})
		for _, service := range services {
			result.ServiceImages[service] = image
		}
	}
	return result, nil
}

func canonicalBuildKey(build any) (string, error) {
	normalized := map[string]any{"context": ".", "dockerfile": "Dockerfile"}
	switch value := build.(type) {
	case string:
		normalized["context"] = value
	case map[string]any:
		for key, item := range value {
			normalized[key] = item
		}
	default:
		return "", fmt.Errorf("unsupported build format %T", build)
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// pushedDigestSet holds, per published tag, the digest BuildKit pushed and the
// registry confirmed. The deploy later resolves the same tag again to build the
// stack's image@digest references; without this record a tag rewritten between
// the two reads would be promoted unverified (review of DEV-DEPL-53 part A).
type pushedDigestSet struct {
	mu      sync.Mutex
	digests map[string]string
}

func newPushedDigestSet() *pushedDigestSet {
	return &pushedDigestSet{digests: map[string]string{}}
}

func (s *pushedDigestSet) record(image, digest string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.digests[image] = digest
}

// verify fails when a resolved service reference does not carry the digest that
// was verified at push time for its image. resolved maps service to
// repository@digest, images maps service to the published tag.
func (s *pushedDigestSet) verify(images, resolved map[string]string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for service, image := range images {
		want, ok := s.digests[image]
		if !ok {
			continue
		}
		ref := resolved[service]
		got := ref[strings.LastIndex(ref, "@")+1:]
		if got != want {
			return fmt.Errorf("%s resolves to %s but BuildKit pushed and verified %s for %s: refusing to promote an unverified digest", service, got, want, image)
		}
	}
	return nil
}
