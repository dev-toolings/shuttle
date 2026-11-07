package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// remoteDockerBuildRunner keeps Docker's context transfer on the deploy
// client's Buildx path while directing the daemon and BuildKit to the verified
// runner. The prepared PATH wrapper prevents Docker from selecting an agent or
// an unrelated known_hosts entry.
var remoteDockerBuildRunner = func(host, sshCommand string, args []string) error {
	if strings.TrimSpace(host) == "" || strings.TrimSpace(sshCommand) == "" {
		return fmt.Errorf("verified build runner Docker transport is not prepared")
	}
	command := exec.Command("docker", append([]string{"--host", host}, args...)...)
	// Docker resolves its ssh helper from PATH inside the child process. The
	// prepared wrapper is therefore selected here without relying on the
	// DOCKER_SSH_COMMAND variable, which Docker's SSH connection helper ignores.
	command.Env = sanitizedRemoteDockerEnvironment(filepath.Dir(sshCommand))
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func sanitizedRemoteDockerEnvironment(wrapperDir string) []string {
	blocked := map[string]bool{
		"DOCKER_HOST": true, "DOCKER_CONTEXT": true, "DOCKER_SSH_COMMAND": true,
		"DOCKER_CONFIG": true, "BUILDX_BUILDER": true, "BUILDX_CONFIG": true,
		"BUILDKIT_HOST": true, "BUILDKIT_PROGRESS": true, "SSH_AUTH_SOCK": true,
		"GIT_SSH": true, "GIT_SSH_COMMAND": true,
	}
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok && !blocked[key] {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "PATH="+wrapperDir)
	return environment
}

func newSSHBuildRunner(cfg *config.Config, group config.ServerGroup, productionHost string) (*ssh.BuildRunner, error) {
	productionIdentity, err := loadTrustedHostIdentity(productionHost, group.Port)
	if err != nil {
		return nil, err
	}
	runner, err := ssh.NewBuildRunner(ssh.BuildRunnerConfig{
		Host:                 cfg.Build.Host,
		User:                 cfg.Build.User,
		Port:                 cfg.Build.Port,
		HostKey:              cfg.Build.HostKey,
		IdentityFile:         cfg.Build.IdentityFile,
		RegistryIdentityFile: cfg.Build.RegistryIdentityFile,
	})
	if err != nil {
		return nil, err
	}
	if err := runner.SetProductionTarget(productionHost, group.User, group.Port, productionIdentity.HostKeyFingerprint); err != nil {
		_ = runner.Close()
		return nil, err
	}
	if err := runner.SetBuilderIdentity(cfg.App, productionHost, group.Port); err != nil {
		_ = runner.Close()
		return nil, err
	}
	return runner, nil
}

func remoteBuildkitBuilderName(app string) string {
	return "shuttle-" + app + "-remote"
}

func remoteBuildOptions(runner *ssh.BuildRunner) buildExecutionOptions {
	if runner == nil {
		return buildExecutionOptions{}
	}
	return buildExecutionOptions{
		RemoteBuilder:          runner.BuilderName(),
		RemoteDockerHost:       runner.DockerHost(),
		RemoteDockerSSHCommand: runner.DockerSSHCommand(),
		RemoteDockerRun:        runner.RunDocker,
		// The remote docker-container volume is the cache. Exporting mode=max
		// through the production registry would make that registry a build cache
		// transport and is deliberately outside the SSH runner contract.
		SkipRegistryCache: true,
	}
}

func configureRemoteBuildPlan(plan *buildPlan, runner *ssh.BuildRunner) error {
	if runner == nil {
		return nil
	}
	registry := runner.RegistryAddress()
	for index := range plan.Builds {
		build := &plan.Builds[index]
		build.BuildImage = rewriteRegistryReference(firstNonEmpty(build.Image, build.BuildImage), registry)
		build.BuildCacheImage = rewriteRegistryReference(firstNonEmpty(build.CacheImage, build.BuildCacheImage), registry)
	}
	return nil
}

func dockerBuildxRemoteCommandArgs(builder, imageTag, dockerfile string, buildArgs []string, context string) []string {
	if builder == "" {
		return nil
	}
	cmdArgs := []string{"buildx", "build", "--builder", builder, "--push", "--pull", "--provenance=false", "-t", imageTag, "-f", dockerfile}
	cmdArgs = append(cmdArgs, buildArgs...)
	return append(cmdArgs, context)
}

func readBuildMetadataDigest(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", nil
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(body, &metadata); err != nil {
		return "", fmt.Errorf("decode BuildKit metadata: %w", err)
	}
	rawDigest, ok := metadata["containerimage.digest"]
	if !ok {
		return "", nil
	}
	var digest string
	if err := json.Unmarshal(rawDigest, &digest); err != nil {
		return "", fmt.Errorf("decode containerimage.digest: %w", err)
	}
	if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("invalid containerimage.digest %q", digest)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
		return "", fmt.Errorf("invalid containerimage.digest %q: %w", digest, err)
	}
	return digest, nil
}

type remoteBuildRegistry interface {
	RegistryAddress() string
}

func validateRemoteBuildReferences(plan buildPlan, runner remoteBuildRegistry) error {
	if runner == nil {
		return nil
	}
	for _, build := range plan.Builds {
		for field, value := range map[string]string{"image": build.BuildImage, "cache": build.BuildCacheImage} {
			if value == "" {
				continue
			}
			if !strings.HasPrefix(value, runner.RegistryAddress()+"/") {
				return fmt.Errorf("remote build %s reference %s does not use the runner registry tunnel: %s", field, value, runner.RegistryAddress())
			}
		}
	}
	return nil
}
