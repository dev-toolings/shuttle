package readiness

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

type collectionShell struct{ bin, failure, mode string }

func (a collectionShell) Run(command string, timeout time.Duration) execx.Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+a.bin+":"+os.Getenv("PATH"), "SHUTTLE_TEST_FAILURE="+a.failure, "SHUTTLE_TEST_MODE="+a.mode)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := execx.Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		result.ExitCode = 1
	}
	return result
}

func TestDockerCollectionPropagatesEverySourceFailure(t *testing.T) {
	bin := t.TempDir()
	stub := `#!/bin/sh
stage=$1
case "$*" in *label!=*) echo "invalid filter label!" >&2; exit 45 ;; esac
if [ "$1" = service ] || [ "$1" = image ]; then stage="$1-$2"; fi
if [ "$stage" = "$SHUTTLE_TEST_FAILURE" ]; then echo 'collection failed' >&2; exit 42; fi
case "$stage" in
info) echo "$SHUTTLE_TEST_MODE" ;;
service-ls|ps) echo abc ;;
service-inspect|inspect)
 case "$*" in
 *'index .Config.Labels'*) echo no ;;
 *'|{{'*) printf 'web||sha256:test\n' ;;
 *RestartPolicy*) printf 'web\talways\n' ;;
 *Healthcheck*) printf 'web\t{"Test":["CMD","true"]}\n' ;;
 *Mounts*) printf 'web\t[]\n' ;;
 *) exit 43 ;;
 esac ;;
image-inspect) echo 1000 ;;
*) exit 44 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	checks := []Check{checkDockerRestartPolicies, checkDockerHealthchecks, checkDockerRunningAsRoot, checkDockerSockExposed}
	for _, mode := range []string{"true", "false"} {
		for _, check := range checks {
			healthy := check(collectionShell{bin: bin, mode: mode})
			if healthy.Status != Passed {
				t.Fatalf("shell fixture must first prove success: %+v", healthy)
			}
			stages := []string{"info", "ps", "inspect"}
			if mode == "true" {
				stages = append(stages, "service-ls", "service-inspect")
			}
			if healthy.ID == "docker.containers_running_as_root" {
				stages = append(stages, "image-inspect")
			}
			for _, stage := range stages {
				got := check(collectionShell{bin: bin, failure: stage, mode: mode})
				if got.Status != Skipped || got.SkipReason != EvidenceUnavailable {
					t.Errorf("%s mode=%s stage=%s: %+v", got.ID, mode, stage, got)
				}
			}
		}
	}
}

func TestPublishedPortCollectorUsesLiteralTemplateSeparators(t *testing.T) {
	bin := t.TempDir()
	// docker inspect renders Go templates without decoding backslash escapes;
	// unlike docker ps, a literal backslash-t stays a literal backslash-t.
	stub := `#!/bin/sh
case "$1 $2" in
"info --format") echo true ;;
"info ") : ;;
"ps --format") : ;;
"service ls") echo abc ;;
"service inspect") printf '%s\n' "$4" | sed 's/{{.Spec.Name}}/edge/g; s/{{json .Endpoint.Spec.Ports}}/null/g' ;;
*) exit 42 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	result := (collectionShell{bin: bin}).Run(dockerPublicPortsCommand, time.Second)
	if result.ExitCode != 0 {
		t.Fatalf("collector failed: %+v", result)
	}
	if exposures := dockerPublicTCPExposures(result.Stdout, map[string]bool{}); len(exposures) != 0 {
		t.Fatalf("valid service with no published ports was rejected: %q %+v", result.Stdout, exposures)
	}
}
