package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

// Existing platforms own their mounts, database, edge and upgrade protocol.
// This explicit operator mode transports images and calls that protocol. It
// never submits an exceptional stack to the signed helper or runs setup.
type existingStackConfig struct {
	Retention existingStackRetention `json:"retention,omitempty"`
	Version   int                    `json:"version"`
	App       string                 `json:"app"`
	Stack     string                 `json:"stack"`
	Server    struct {
		Host         string `json:"host"`
		User         string `json:"user"`
		Port         int    `json:"port"`
		HostKey      string `json:"host_key"`
		IdentityFile string `json:"identity_file"`
		Sudo         bool   `json:"sudo"`
	} `json:"server"`
	Registry       string            `json:"registry"`
	Build          config.Build      `json:"build"`
	Manifest       map[string]string `json:"manifest"`
	Apply          []string          `json:"apply"`
	VerifyImage    []string          `json:"verify_image,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds"`
}

var existingStackName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
var existingManifestKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var existingHostKey = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func newExistingStackDeployCommand() *cobra.Command {
	var path string
	var dryRun bool
	cmd := &cobra.Command{
		Use: "existing-stack", Args: cobra.NoArgs,
		Short: "Transfer images to an existing single-node Swarm and call its declared upgrader",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Runtime failures already name the failed operation; Cobra usage obscured that message.
			cmd.SilenceUsage = true
			// main prints the returned error once; cobra printing it too showed every
			// recovery line twice.
			cmd.SilenceErrors = true
			cfg, err := loadExistingStackConfig(path)
			if err != nil {
				return err
			}
			return deployExistingStack(cfg, dryRun)
		},
	}
	cmd.Flags().StringVar(&path, "config", "", "existing-stack JSON configuration (required)")
	_ = cmd.MarkFlagRequired("config")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "verify the target and print the plan without changing it")
	return cmd
}

func loadExistingStackConfig(path string) (*existingStackConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg existingStackConfig
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("expected one JSON configuration")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *existingStackConfig) validate() error {
	if cfg.Retention.count() < 1 {
		return errors.New("retention.keep_releases must be at least 1")
	}
	if err := cfg.Retention.validateBuildCache(); err != nil {
		return err
	}
	if cfg.Version != 1 || !existingStackName.MatchString(cfg.App) || !existingStackName.MatchString(cfg.Stack) {
		return errors.New("existing-stack requires version: 1 and valid app/stack names")
	}
	if strings.TrimSpace(cfg.Server.Host) == "" || !existingStackName.MatchString(cfg.Server.User) || cfg.Server.User == "root" ||
		!existingHostKey.MatchString(cfg.Server.HostKey) {
		return errors.New("existing-stack requires an existing non-root SSH account and a pinned ED25519 host_key")
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 22
	}
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return errors.New("invalid SSH port")
	}
	host, port, err := net.SplitHostPort(cfg.Registry)
	ip := net.ParseIP(host)
	registryPort, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || ip.To4() == nil || !ip.IsLoopback() || portErr != nil || registryPort < 1 || registryPort > 65535 {
		return errors.New("existing-stack registry must be an existing loopback address with an explicit port")
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 900
	}
	if cfg.TimeoutSeconds < 30 || cfg.TimeoutSeconds > 3600 {
		return errors.New("timeout_seconds must be between 30 and 3600")
	}
	if len(cfg.Build.Services) == 0 || len(cfg.Manifest) != len(cfg.Build.Services) || len(cfg.Apply) == 0 || !filepath.IsAbs(cfg.Apply[0]) {
		return errors.New("declare builds, one manifest entry per build, and an absolute apply executable")
	}
	seen := map[string]bool{}
	for key, build := range cfg.Manifest {
		if !existingManifestKey.MatchString(key) || seen[build] {
			return errors.New("manifest keys and build assignments must be unique")
		}
		if _, ok := cfg.Build.Services[build]; !ok {
			return fmt.Errorf("manifest references unknown build %q", build)
		}
		seen[build] = true
	}
	services := map[string]bool{}
	for name, build := range cfg.Build.Services {
		if !existingStackName.MatchString(name) || len(build.Services) == 0 {
			return fmt.Errorf("invalid build %q", name)
		}
		for _, service := range build.Services {
			if !existingStackName.MatchString(service) || services[service] {
				return fmt.Errorf("invalid or duplicate service %q", service)
			}
			services[service] = true
		}
	}
	if !strings.Contains(strings.Join(cfg.Apply, " "), "{{manifest}}") {
		return errors.New("apply must consume {{manifest}}")
	}
	return nil
}

func (cfg *existingStackConfig) docker(args ...string) string {
	argv := append([]string{"docker"}, args...)
	if cfg.Server.Sudo {
		argv = append([]string{"sudo", "-n", "--"}, argv...)
	}
	return existingStackArgv(argv, nil)
}

func existingStackArgv(args []string, replacements map[string]string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		for key, value := range replacements {
			arg = strings.ReplaceAll(arg, "{{"+key+"}}", value)
		}
		quoted[i] = shell.Escape(arg)
	}
	return strings.Join(quoted, " ")
}

func deployExistingStack(cfg *existingStackConfig, dryRun bool) (deployErr error) {
	client, err := ssh.NewClientExactWithIdentity(cfg.Server.Host, cfg.Server.User, cfg.Server.Port, cfg.Server.HostKey, cfg.Server.IdentityFile)
	if err != nil {
		return err
	}
	if err := client.VerifyHostKey(); err != nil {
		return err
	}
	client.SetOperationTimeout(30 * time.Second)
	run := func(command string) (string, error) {
		result := client.Run(command)
		if result.Code != 0 {
			return "", fmt.Errorf("existing-stack remote operation failed: %s", strings.TrimSpace(result.Stderr))
		}
		return strings.TrimSpace(result.Stdout), nil
	}
	info, err := run(cfg.docker("info", "--format", "{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}} {{.Architecture}}"))
	if err != nil {
		return err
	}
	fields := strings.Fields(info)
	if len(fields) != 3 || fields[0] != "active" || fields[1] != "true" {
		return errors.New("target must already be an active Swarm manager")
	}
	platform, err := composePlatform(fields[2])
	if err != nil {
		return err
	}
	nodes, err := run(cfg.docker("node", "ls", "-q"))
	if err != nil {
		return err
	}
	if len(strings.Fields(nodes)) != 1 {
		return errors.New("existing-stack supports exactly one Swarm node")
	}
	cf := &composeFile{Services: map[string]composeService{}}
	var serviceNames []string
	for _, build := range cfg.Build.Services {
		for _, service := range build.Services {
			cf.Services[service] = composeService{}
			serviceNames = append(serviceNames, cfg.Stack+"_"+service)
		}
	}
	sort.Strings(serviceNames)
	args := append([]string{"service", "inspect", "--format", "{{index .Spec.Labels \"com.docker.stack.namespace\"}}"}, serviceNames...)
	owners, err := run(cfg.docker(args...))
	if err != nil {
		return err
	}
	if len(strings.Fields(owners)) != len(serviceNames) {
		return errors.New("target services are missing")
	}
	for _, owner := range strings.Fields(owners) {
		if owner != cfg.Stack {
			return errors.New("a target service belongs to another stack")
		}
	}
	version := existingStackVersion(detectVersion(), time.Now().UTC())
	// Fresh tags prevent a second build of the same commit from replacing the
	// identity an earlier deployment's rollback descriptor still references.
	for name, build := range cfg.Build.Services {
		for key, value := range build.Args {
			build.Args[key] = strings.ReplaceAll(value, "{{version}}", version)
		}
		cfg.Build.Services[name] = build
	}
	plan, err := createConfiguredBuildPlan(cf, cfg.Build, cfg.Registry, cfg.App, version)
	if err != nil {
		return err
	}
	for i := range plan.Builds {
		plan.Builds[i].CacheImage = ""
		plan.Builds[i].BuildCacheImage = ""
		if _, err := os.Stat(plan.Builds[i].Spec.Dockerfile); err != nil {
			return fmt.Errorf("build %s Dockerfile: %w", plan.Builds[i].Service, err)
		}
		if err := refuseIgnoredSecretsInBuildContext(*plan.Builds[i].Spec); err != nil {
			return err
		}
	}
	tags := localPublishedImageTags(plan)
	output.Header("Existing stack %s on %s (%s)", cfg.Stack, cfg.Server.Host, platform)
	if dryRun {
		for _, build := range plan.Builds {
			output.Detail("Build %s -> %s; update existing services: %s", build.Service, build.Image, strings.Join(build.Services, ", "))
		}
		output.Detail("Stream images over verified SSH, publish to %s, call declared upgrader with a digest manifest; no setup or stack rendering", cfg.Registry)
		return nil
	}
	cleanup, err := prepareLocalImageCleanup(tags, true)
	if err != nil {
		return err
	}
	defer func() { mergeCleanupError(&deployErr, cleanup.Cleanup()) }()
	interrupts := newInterruptCleanup()
	defer interrupts.Stop()
	interrupts.Add(cleanup.Cleanup)
	builderApp := cfg.App
	if len(builderApp) > 20 {
		builderApp = builderApp[:20]
	}
	// A stable builder keeps its BuildKit cache between deploys: unchanged
	// layers are reused and an unchanged image keeps its digest, so Swarm
	// leaves its service alone. The cache is capped after every run.
	builderApp += "-existing"
	builder := persistentBuilderName(builderApp)
	unlockBuilder, err := lockExistingBuilder(builder)
	if err != nil {
		return err
	}
	defer func() { mergeCleanupError(&deployErr, unlockBuilder()) }()
	if err := ensurePersistentBuilder(builderApp); err != nil {
		return err
	}
	releaseBuilder := func() error {
		pruneErr := pruneExistingBuilderCache(builder, cfg.Retention.buildCacheBytes())
		return errors.Join(pruneErr, stopPersistentBuilder(builderApp))
	}
	interrupts.Add(releaseBuilder)
	defer func() { mergeCleanupError(&deployErr, releaseBuilder()) }()
	if err := buildPlannedImagesWithOptions(cf, plan, false, buildExecutionOptions{Builder: builder, SkipRegistryCache: true, ExtraArgs: []string{"--platform", platform}}); err != nil {
		return err
	}
	localIDs := map[string]string{}
	for _, image := range tags {
		body, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", image).Output()
		if err != nil {
			return fmt.Errorf("inspect local image %s: %w", image, err)
		}
		localIDs[image] = strings.TrimSpace(string(body))
		if len(cfg.VerifyImage) > 0 {
			argv := append([]string(nil), cfg.VerifyImage...)
			for i, arg := range argv {
				argv[i] = strings.ReplaceAll(arg, "{{image}}", image)
			}
			check := exec.Command(argv[0], argv[1:]...)
			check.Stdout = os.Stdout
			check.Stderr = os.Stderr
			if err := check.Run(); err != nil {
				return fmt.Errorf("project image verification failed for %s: %w", image, err)
			}
		}
	}
	reused, err := existingReusableImages(cfg, plan, run)
	if err != nil {
		return err
	}
	var transfer []string
	for _, build := range plan.Builds {
		if reused[build.Service] == "" {
			transfer = append(transfer, build.Image)
		}
	}
	if len(transfer) > 0 {
		size, err := localImageSize(transfer)
		if err != nil {
			return err
		}
		stream, wait, err := dockerSaveStream(transfer)
		if err != nil {
			return err
		}
		client.SetOperationTimeout(composeTransferTimeout(size))
		result := client.RunWithReader(cfg.docker("load"), stream)
		_ = stream.Close()
		saveErr := wait()
		if result.Code != 0 || saveErr != nil {
			return fmt.Errorf("image transfer failed (save: %v): %s", saveErr, strings.TrimSpace(result.Stderr))
		}
		client.SetOperationTimeout(time.Duration(cfg.TimeoutSeconds) * time.Second)
	}
	digests := map[string]string{}
	for _, build := range plan.Builds {
		if running := reused[build.Service]; running != "" {
			// Same layers and config as the running release: tag it for this
			// release's retention and keep its digest so Swarm changes nothing.
			output.Step("%s unchanged; keeping the running image %s", build.Service, running)
			if _, err := run(cfg.docker("tag", running, build.Image)); err != nil {
				return err
			}
			if _, err := run(cfg.docker("push", build.Image)); err != nil {
				return err
			}
			digests[build.Service] = running
			continue
		}
		id, err := run(cfg.docker("image", "inspect", "--format", "{{.Id}}", build.Image))
		if err != nil {
			return err
		}
		if id != localIDs[build.Image] {
			return fmt.Errorf("loaded image identity mismatch for %s", build.Image)
		}
		output.Step("Publishing %s to the host registry...", build.Service)
		if _, err := run(cfg.docker("push", build.Image)); err != nil {
			return err
		}
		refs, err := run(cfg.docker("image", "inspect", "--format", "{{range .RepoDigests}}{{println .}}{{end}}", build.Image))
		if err != nil {
			return err
		}
		repository := strings.TrimSuffix(build.Image, ":"+version)
		for _, ref := range strings.Fields(refs) {
			if strings.HasPrefix(ref, repository+"@sha256:") && digestImage.MatchString(ref) {
				digests[build.Service] = ref
			}
		}
		if digests[build.Service] == "" {
			return fmt.Errorf("no immutable host registry digest for %s", build.Service)
		}
	}
	manifest, err := existingStackManifest(cfg.Manifest, digests)
	if err != nil {
		return err
	}
	// Uploads stay in the operator's home. Host secrets are never downloaded.
	home, err := run("printf '%s' \"$HOME\"")
	if err != nil || !strings.HasPrefix(home, "/") {
		return errors.New("cannot resolve operator home")
	}
	release := home + "/.shuttle/" + cfg.App + "/existing-stack/" + version
	if _, err := run("install -d -m 0700 " + shell.Escape(release)); err != nil {
		return err
	}
	manifestPath := release + "/images.env"
	if result := client.UploadContent(manifest, manifestPath, 0600); result.Code != 0 {
		return fmt.Errorf("upload manifest: %s", result.Stderr)
	}
	apply := existingStackArgv(cfg.Apply, map[string]string{"manifest": manifestPath, "version": version})
	if cfg.Server.Sudo {
		apply = "sudo -n -- " + apply
	}
	output.Step("Applying the platform's declared upgrade; backup, migrations and rollback remain platform-owned...")
	result := client.Run(apply)
	if result.Code != 0 {
		return fmt.Errorf("platform upgrade failed; inspect the platform's rollback state: %s", strings.TrimSpace(result.Stderr))
	}
	if err := completeExistingStackRelease(cfg, plan, digests, run); err != nil {
		return err
	}
	output.OK("Existing stack %s upgraded to %s; all %d service image digests verified", cfg.Stack, version, len(serviceNames))
	return nil
}

// existingStackVersion gives every run a timestamped release tag. A dirty
// checkout's version already ends with one; a second would only lengthen it.
func existingStackVersion(base string, now time.Time) string {
	if existingReleaseTag.MatchString(base) {
		return base
	}
	return base + "-" + timestampVersion(now)
}

func existingStackManifest(mapping, digests map[string]string) (string, error) {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var body strings.Builder
	for _, key := range keys {
		ref := digests[mapping[key]]
		if !existingManifestKey.MatchString(key) || !digestImage.MatchString(ref) {
			return "", fmt.Errorf("invalid digest manifest entry %s", key)
		}
		fmt.Fprintf(&body, "%s=%s\n", key, ref)
	}
	return body.String(), nil
}

func completeExistingStackRelease(cfg *existingStackConfig, plan buildPlan, digests map[string]string, run existingRemoteRun) error {
	for service, image := range plan.ServiceImages {
		active, err := run(cfg.docker("service", "inspect", "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}", cfg.Stack+"_"+service))
		if err != nil {
			return err
		}
		buildName := ""
		for _, build := range plan.Builds {
			if build.Image == image {
				buildName = build.Service
				break
			}
		}
		if active != digests[buildName] {
			return fmt.Errorf("service %s does not run the declared digest", service)
		}
	}
	finishExistingStack(cfg, localPublishedImageTags(plan), run)
	return nil
}
