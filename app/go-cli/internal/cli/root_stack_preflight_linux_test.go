//go:build linux

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

const testStackOperationID = "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b10"

func rootStackPreflightPlan(t *testing.T, payload []byte, now time.Time) rootplan.Plan {
	t.Helper()
	fingerprint := "SHA256:" + strings.Repeat("a", 43)
	registryImage := "registry:3@sha256:" + strings.Repeat("e", 64)
	plan, err := rootplan.NewStackAction("stack-apply", "demo", rootplan.PayloadDigest(payload), 30, 0, fingerprint, fingerprint, now, 5*time.Minute, registryImage)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = rootplan.WithOperationID(plan, testStackOperationID, "deploy", "demo")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func rootStackPreflightPayload(t *testing.T, production config.ProductionConfig) []byte {
	t.Helper()
	cfg := &config.Config{Version: 2, App: "demo", Domain: "demo.example.com", Production: production}
	if production.Redis && production.RedisImage == "" {
		if err := resolveConfiguredInfrastructure(context.Background(), cfg, false); err != nil {
			t.Fatal(err)
		}
	}
	body := `services:
  web:
    image: demo@sha256:` + strings.Repeat("a", 64) + `
    healthcheck: {test: ["CMD", "true"]}
`
	stack, err := secureStack(body, cfg, "8080")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(stack)
}

func isolateRootStackPreflight(t *testing.T) {
	t.Helper()
	oldCurrentPath := rootStackPreflightCurrentPath
	oldMutationGuard, oldIdentity, oldReservation := preRunMutationGuard, preRunVerifyIdentity, preRunReservation
	oldFilesystem, oldPhase := preRunFilesystem, rootStackPhase
	oldImageVersion := infrastructureImageVersion
	oldObjectRead := rootStackObjectRead
	rootStackObjectRead = func(_ context.Context, args ...string) (string, error) {
		return "", errors.New("Error response from daemon: No such " + args[0] + ": " + args[len(args)-1])
	}
	stateRoot := filepath.Join(t.TempDir(), "apps")
	rootStackPreflightCurrentPath = func(app string) string { return filepath.Join(stateRoot, app, "current.yml") }
	preRunMutationGuard = func(string) error { return nil }
	preRunVerifyIdentity = func(rootplan.Plan) error { return nil }
	preRunReservation = func(context.Context, rootplan.Plan) error { return nil }
	preRunFilesystem = func(string) (uint64, uint64, error) { return 100, 100, nil }
	rootStackPhase = func(rootplan.Plan, func(context.Context) error) error { return nil }
	infrastructureImageVersion = func(string, string) (string, error) {
		return "", errors.New("pre-flight must never pull infrastructure images")
	}
	t.Cleanup(func() {
		rootStackPreflightCurrentPath = oldCurrentPath
		preRunMutationGuard, preRunVerifyIdentity, preRunReservation = oldMutationGuard, oldIdentity, oldReservation
		preRunFilesystem, rootStackPhase = oldFilesystem, oldPhase
		infrastructureImageVersion = oldImageVersion
		rootStackObjectRead = oldObjectRead
	})
}

func TestRootStackPreflightRefusesForeignVolumeBeforePhase(t *testing.T) {
	isolateRootStackPreflight(t)
	payload := []byte(strings.Replace(validRootStack(), "    read_only: true\n", "    volumes: [data:/data]\n    read_only: true\n", 1) + "volumes:\n  data: {external: true, name: otherapp_data}\n")
	phaseCalled := false
	rootStackPhase = func(rootplan.Plan, func(context.Context) error) error { phaseCalled = true; return nil }
	err := applyRootStack(rootStackPreflightPlan(t, payload, time.Now()), payload)
	if err == nil || !strings.Contains(err.Error(), "otherapp_data") || phaseCalled {
		t.Fatalf("foreign volume must be refused before phase: err=%v phase=%t", err, phaseCalled)
	}
}

func TestRootStackPreflightRefusesBeforeOpeningPhaseOrWritingState(t *testing.T) {
	isolateRootStackPreflight(t)
	base := rootStackPreflightPayload(t, config.ProductionConfig{})
	oldRedis := "redis:7.4.5-alpine@sha256:" + strings.Repeat("b", 64)
	oldRedisPayload := rootStackPreflightPayload(t, config.ProductionConfig{Redis: true, RedisImage: oldRedis})
	unofficialRedis := "registry.invalid/redis:7.4.6@sha256:" + strings.Repeat("c", 64)
	unofficialRedisPayload := rootStackPreflightPayload(t, config.ProductionConfig{Redis: true, RedisImage: unofficialRedis})
	majorPayload := rootStackPreflightPayload(t, config.ProductionConfig{Redis: true})
	imageLookups := 0
	infrastructureImageVersion = func(string, string) (string, error) {
		imageLookups++
		return "", errors.New("pre-flight must never pull infrastructure images")
	}

	cases := []struct {
		name            string
		payload         []byte
		prepare         func(t *testing.T, stateRoot string)
		retainedPresent bool
		wantReason      string
	}{
		{name: "identity", payload: base, prepare: func(t *testing.T, _ string) {
			preRunVerifyIdentity = func(rootplan.Plan) error { return errors.New("host identity mismatch") }
		}, wantReason: "host identity mismatch"},
		{name: "mutation guard", payload: base, prepare: func(t *testing.T, _ string) {
			preRunMutationGuard = func(string) error { return errors.New("helper migration is active") }
		}, wantReason: "helper migration is active"},
		{name: "live reservation", payload: base, prepare: func(t *testing.T, _ string) {
			preRunReservation = func(context.Context, rootplan.Plan) error { return errors.New("operation reservation is not live") }
		}, wantReason: "operation reservation is not live"},
		{name: "disk", payload: base, prepare: func(t *testing.T, _ string) {
			preRunFilesystem = func(string) (uint64, uint64, error) { return 19, 100, nil }
		}, wantReason: "less than 20 percent disk space"},
		{name: "invalid stack", payload: []byte("services: {}\n"), wantReason: "stack payload has no services"},
		{name: "implicit major change", payload: majorPayload, retainedPresent: true, prepare: func(t *testing.T, stateRoot string) {
			appDir := filepath.Join(stateRoot, "demo")
			if err := os.MkdirAll(appDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(appDir, "current.yml"), oldRedisPayload, 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantReason: "major change 7 -> 8 requires an explicit data migration"},
		{name: "first deploy with older official infrastructure pin", payload: oldRedisPayload},
		{name: "candidate is not an official pinned image", payload: unofficialRedisPayload, retainedPresent: true, prepare: func(t *testing.T, stateRoot string) {
			appDir := filepath.Join(stateRoot, "demo")
			if err := os.MkdirAll(appDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(appDir, "current.yml"), oldRedisPayload, 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantReason: "is not an official redis image pinned by digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := filepath.Join(t.TempDir(), "apps")
			rootStackPreflightCurrentPath = func(app string) string { return filepath.Join(stateRoot, app, "current.yml") }
			preRunMutationGuard = func(string) error { return nil }
			preRunVerifyIdentity = func(rootplan.Plan) error { return nil }
			preRunReservation = func(context.Context, rootplan.Plan) error { return nil }
			preRunFilesystem = func(string) (uint64, uint64, error) { return 100, 100, nil }
			phaseCalls := 0
			rootStackPhase = func(rootplan.Plan, func(context.Context) error) error { phaseCalls++; return nil }
			if tc.prepare != nil {
				tc.prepare(t, stateRoot)
			}
			plan := rootStackPreflightPlan(t, tc.payload, time.Now())
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			oldStderr := os.Stderr
			os.Stderr = write
			applyErr := applyRootStack(plan, tc.payload)
			_ = write.Close()
			os.Stderr = oldStderr
			marker, readErr := io.ReadAll(read)
			_ = read.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.wantReason == "" {
				if applyErr != nil || len(marker) != 0 || phaseCalls != 1 {
					t.Fatalf("first deploy with a signed official digest should pass pre-flight: err=%v marker=%q phases=%d", applyErr, marker, phaseCalls)
				}
				return
			}
			if applyErr == nil || !strings.Contains(string(marker), rootPreflightRefusalMarker) || !strings.Contains(string(marker), tc.wantReason) {
				t.Fatalf("pre-flight refusal marker or error missing: err=%v marker=%q", applyErr, marker)
			}
			if phaseCalls != 0 {
				t.Fatalf("refusal opened the stack phase %d times", phaseCalls)
			}
			if !tc.retainedPresent {
				if _, err := os.Stat(filepath.Join(stateRoot, "demo")); !os.IsNotExist(err) {
					t.Fatalf("pre-flight created application state before the phase: %v", err)
				}
			}
		})
	}
	if imageLookups != 0 {
		t.Fatalf("pre-flight attempted %d infrastructure image lookups", imageLookups)
	}
}

func TestRootStackPreflightUsesFreshFiveMinutePlanAndSkipsRemoval(t *testing.T) {
	isolateRootStackPreflight(t)
	payload := rootStackPreflightPayload(t, config.ProductionConfig{})
	now := time.Now()
	plan := rootStackPreflightPlan(t, payload, now)
	phaseCalls := 0
	rootStackPhase = func(_ rootplan.Plan, _ func(context.Context) error) error { phaseCalls++; return nil }
	if err := applyRootStack(plan, payload); err != nil {
		t.Fatalf("fresh five-minute stack plan failed pre-flight: %v", err)
	}
	if phaseCalls != 1 {
		t.Fatalf("valid stack opened the coordinated phase %d times", phaseCalls)
	}

	remove, err := rootplan.NewStackRemove("demo", "SHA256:"+strings.Repeat("a", 43), "SHA256:"+strings.Repeat("a", 43), now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	remove, err = rootplan.WithOperationID(remove, testStackOperationID, "deploy", "demo")
	if err != nil {
		t.Fatal(err)
	}
	preRunMutationGuard = func(string) error { t.Fatal("remove plan ran the stack pre-flight mutation guard"); return nil }
	preRunVerifyIdentity = func(rootplan.Plan) error {
		t.Fatal("remove plan ran stack pre-flight identity verification")
		return nil
	}
	preRunReservation = func(context.Context, rootplan.Plan) error {
		t.Fatal("remove plan checked a stack pre-flight reservation")
		return nil
	}
	if err := applyRootStack(remove, nil); err != nil {
		t.Fatalf("remove path changed: %v", err)
	}
	if phaseCalls != 2 {
		t.Fatalf("remove did not reach its existing coordinated phase: %d", phaseCalls)
	}
}

func TestStackReclaimPinsSwarmTaskHistoryMutation(t *testing.T) {
	oldValue, oldCommand := swarmTaskHistoryValue, swarmTaskHistoryCommand
	t.Cleanup(func() { swarmTaskHistoryValue, swarmTaskHistoryCommand = oldValue, oldCommand })
	var inspected []string
	var updated []string
	swarmTaskHistoryValue = func(_ time.Duration, name string, args ...string) (string, error) {
		inspected = append([]string{name}, args...)
		return "5", nil
	}
	swarmTaskHistoryCommand = func(name string, args ...string) error {
		updated = append([]string{name}, args...)
		return nil
	}
	if err := ensureSwarmTaskHistoryLimit(); err != nil {
		t.Fatal(err)
	}
	wantInspect := []string{"/usr/bin/docker", "info", "--format", "{{.Swarm.Cluster.Spec.Orchestration.TaskHistoryRetentionLimit}}"}
	wantUpdate := []string{"/usr/bin/docker", "swarm", "update", "--task-history-limit", "2"}
	if !reflect.DeepEqual(inspected, wantInspect) || !reflect.DeepEqual(updated, wantUpdate) {
		t.Fatalf("stack-reclaim task history calls changed: inspect=%v update=%v", inspected, updated)
	}
}
