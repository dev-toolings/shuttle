package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

const existingDefaultBuildCache = "20GB"

func (r existingStackRetention) buildCacheBytes() int64 {
	value := r.BuildCache
	if value == "" {
		value = existingDefaultBuildCache
	}
	bytes, err := config.ParseByteSize(value)
	if err != nil {
		return 0
	}
	return bytes
}

func (r existingStackRetention) validateBuildCache() error {
	if r.BuildCache == "" {
		return nil
	}
	if bytes, err := config.ParseByteSize(r.BuildCache); err != nil || bytes <= 0 {
		return errors.New("retention.build_cache must be a positive size such as 20GB")
	}
	return nil
}

// The builder is shared by every existing-stack run of one app, and bootstrap
// restarts its BuildKit process. Serialize runs on this workstation so a
// second deploy cannot stop the first one's build.
func lockExistingBuilder(builder string) (func() error, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("builder lock: %w", err)
	}
	dir = filepath.Join(dir, "shuttle", "locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("builder lock: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(dir, builder+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("builder lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another existing-stack deploy is using builder %s", builder)
	}
	return func() error {
		unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return errors.Join(unlockErr, file.Close())
	}, nil
}

// Keeps the most recently used cache records within the budget. A failed prune
// leaves a larger cache, never a broken deploy.
func pruneExistingBuilderCache(builder string, maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}
	if _, err := dockerBuilderRunner("buildx", "inspect", builder); err != nil {
		return nil
	}
	out, err := dockerBuilderRunner("buildx", "prune", "--builder", builder, "--force", "--max-used-space", strconv.FormatInt(maxBytes, 10))
	if err != nil {
		return fmt.Errorf("prune BuildKit cache of %s: %s", builder, strings.TrimSpace(string(out)))
	}
	return nil
}

// Layers plus runtime config identify what a container runs; the creation
// timestamp, which changes on every build, does not.
const existingImageFingerprint = "{{json .RootFS.Layers}} {{json .Config}} {{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}"

var localImageFingerprint = func(image string) (string, error) {
	body, err := exec.Command("docker", "image", "inspect", "--format", existingImageFingerprint, image).Output()
	if err != nil {
		return "", fmt.Errorf("inspect local image %s: %w", image, err)
	}
	return strings.TrimSpace(string(body)), nil
}

// existingReusableImages maps each build whose fresh image matches what all of
// its services already run to that running digest. Keeping the digest spares
// the transfer and, above all, the task restart: an ingress publishing host
// ports cannot start its replacement first, so every restart drops traffic.
func existingReusableImages(cfg *existingStackConfig, plan buildPlan, run existingRemoteRun) (map[string]string, error) {
	reused := map[string]string{}
	for _, build := range plan.Builds {
		at := strings.LastIndex(build.Image, ":")
		if at < 0 || len(build.Services) == 0 {
			continue
		}
		repository := build.Image[:at]
		running := ""
		for _, service := range build.Services {
			ref, err := run(cfg.docker("service", "inspect", "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}", cfg.Stack+"_"+service))
			if err != nil {
				return nil, err
			}
			ref = existingDigestRef(ref)
			if ref == "" || (running != "" && ref != running) {
				running = ""
				break
			}
			running = ref
		}
		if running == "" || !strings.HasPrefix(running, repository+"@") {
			continue
		}
		local, err := localImageFingerprint(build.Image)
		if err != nil {
			return nil, err
		}
		// An image missing from the host store is not reusable, not an error.
		remote, err := run(cfg.docker("image", "inspect", "--format", existingImageFingerprint, running))
		if err != nil || remote != local {
			continue
		}
		reused[build.Service] = running
	}
	return reused, nil
}

// existingDigestRef normalizes "repo:tag@sha256:x" and "repo@sha256:x" to the
// tagless digest form, or returns "" for a reference without a digest.
func existingDigestRef(ref string) string {
	name, digest, ok := strings.Cut(strings.TrimSpace(ref), "@")
	if !ok {
		return ""
	}
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	normalized := name + "@" + digest
	if !digestImage.MatchString(normalized) {
		return ""
	}
	return normalized
}
