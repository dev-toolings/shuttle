//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestStackRollbackPassesDiskReserve(t *testing.T) {
	for _, freePercent := range []uint64{19, 1} {
		t.Run(strconv.FormatUint(freePercent, 10)+" percent", func(t *testing.T) {
			isolateRootStackPreflight(t)
			preRunFilesystem = func(string) (uint64, uint64, error) { return freePercent, 100, nil }
			rootStackPhase = func(_ rootplan.Plan, run func(context.Context) error) error { return run(context.Background()) }
			current := rootStackPreflightCurrentPath("demo")
			if err := os.MkdirAll(filepath.Dir(current), 0o700); err != nil {
				t.Fatal(err)
			}
			previous := filepath.Join(filepath.Dir(current), "previous.yml")
			retained := rootStackPreflightPayload(t, config.ProductionConfig{})
			if err := os.WriteFile(previous, retained, 0o600); err != nil {
				t.Fatal(err)
			}
			oldDeploy := rootStackDeployOutput
			t.Cleanup(func() { rootStackDeployOutput = oldDeploy })
			calls := 0
			rootStackDeployOutput = func(command *exec.Cmd) ([]byte, error) {
				calls++
				body, err := os.ReadFile(command.Args[len(command.Args)-2])
				if err != nil || string(body) != string(retained) {
					t.Fatalf("rollback did not submit the retained manifest: %v", err)
				}
				// Prove admission through the real preflight and disk check,
				// stopping at Docker submission without touching a host.
				return []byte("disk reserve accepted"), errors.New("test stop")
			}
			err := applyRootStack(rootplan.Plan{Action: "stack-rollback", Stack: &rootplan.StackOperation{App: "demo"}}, nil)
			if calls != 1 || err == nil || err.Error() != "docker stack deploy failed: disk reserve accepted" {
				t.Fatalf("rollback at %d%% free did not pass disk admission: calls=%d err=%v", freePercent, calls, err)
			}
		})
	}
}

func TestStackRollbackRefusesBelowDiskReserve(t *testing.T) {
	isolateRootStackPreflight(t)
	// 0.99 percent is below the recovery reserve even though space remains.
	preRunFilesystem = func(string) (uint64, uint64, error) { return 99, 10000, nil }
	rootStackPhase = func(_ rootplan.Plan, run func(context.Context) error) error { return run(context.Background()) }
	err := applyRootStack(rootplan.Plan{Action: "stack-rollback", Stack: &rootplan.StackOperation{App: "demo"}}, nil)
	if err == nil || err.Error() != "rollback refused: less than 1 percent disk space remains" {
		t.Fatalf("rollback below its disk reserve was not refused: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(rootStackPreflightCurrentPath("demo"))); !os.IsNotExist(err) {
		t.Fatalf("refused rollback created application state: %v", err)
	}
}

func TestStackApplyStillRefusesNineteenPercentFree(t *testing.T) {
	for _, phaseCheck := range []bool{false, true} {
		name := "preflight"
		if phaseCheck {
			name = "phase recheck"
		}
		t.Run(name, func(t *testing.T) {
			isolateRootStackPreflight(t)
			payload := rootStackPreflightPayload(t, config.ProductionConfig{})
			plan := rootStackPreflightPlan(t, payload, time.Now())
			oldRegistry, oldImage := rootStackRegistryImage, rootRegistryImage
			t.Cleanup(func() { rootStackRegistryImage, rootRegistryImage = oldRegistry, oldImage })
			// No registry convergence is needed to exercise either disk check.
			registryImage := plan.Stack.RegistryImage
			rootStackRegistryImage = func() (string, error) { return registryImage, nil }
			plan.Stack.RegistryImage = ""
			reads, phases := 0, 0
			preRunFilesystem = func(string) (uint64, uint64, error) {
				reads++
				if phaseCheck && reads == 1 {
					return 20, 100, nil
				}
				return 19, 100, nil
			}
			rootStackPhase = func(_ rootplan.Plan, run func(context.Context) error) error {
				phases++
				return run(context.Background())
			}
			err := applyRootStack(plan, payload)
			if err == nil || !strings.Contains(err.Error(), "deployment refused: less than 20 percent disk space remains") {
				t.Fatalf("apply at 19%% free was not refused: %v", err)
			}
			wantPhases := 0
			if phaseCheck {
				wantPhases = 1
			}
			if phases != wantPhases || reads != wantPhases+1 {
				t.Fatalf("wrong disk gate exercised: phases=%d reads=%d", phases, reads)
			}
		})
	}
}
