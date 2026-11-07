//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRootRegistryNeedsMigrationOnlyForAnOwnedRootRegistry(t *testing.T) {
	cases := []struct {
		name  string
		user  string
		owner string
		want  bool
	}{
		{"a registry left running as root is migrated", "", "system", true},
		{"an already converged registry is left alone", "10001:10001", "system", false},
		{"a foreign registry is never replaced", "", "", false},
		{"surrounding whitespace does not hide the identity", " 10001:10001 ", " system ", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := rootRegistryNeedsMigration(testCase.user, testCase.owner); got != testCase.want {
				t.Fatalf("rootRegistryNeedsMigration(%q, %q) = %v, want %v", testCase.user, testCase.owner, got, testCase.want)
			}
		})
	}
}

// The collector and the registry must resolve to the same identity, and the
// recreated container must keep the hardening `setup` installs.
func TestRootRegistryCreateArgsMatchTheCollectorIdentity(t *testing.T) {
	create := strings.Join(rootRegistryCreateArgs(), " ")
	for _, expected := range []string{"--user " + rootRegistryUser, "--cap-drop ALL", "--security-opt no-new-privileges=true", "--label " + rootRegistryOwner, "-p 127.0.0.1:5000:5000", rootRegistryImage} {
		if !strings.Contains(create, expected) {
			t.Fatalf("create args %q lack %q", create, expected)
		}
	}
	if collect := strings.Join(rootRegistryGarbageCollectArgs(), " "); !strings.Contains(collect, "--user "+rootRegistryUser) {
		t.Fatalf("collector %q does not run as %s", collect, rootRegistryUser)
	}
	if chown := strings.Join(rootRegistryChownArgs(), " "); !strings.Contains(chown, "chown -R "+rootRegistryUser+" /var/lib/registry") || !strings.Contains(chown, "--network none") {
		t.Fatalf("chown args %q do not re-own the volume on no network", chown)
	}
}

func TestRootRegistryImageConvergenceIsVersionGuardedAndKeepsItsVolumeAndHardening(t *testing.T) {
	previousImage := rootRegistryImage
	t.Cleanup(func() { rootRegistryImage = previousImage })
	running := "registry:3.1.2@sha256:" + strings.Repeat("a", 64)
	planned := "registry:3.1.3@sha256:" + strings.Repeat("b", 64)
	rootRegistryImage = planned
	commands, err := rootRegistryConvergenceCommands(running, planned, rootRegistryUser, "system")
	if err != nil || len(commands) != 5 {
		t.Fatalf("same-major update commands=%v err=%v", commands, err)
	}
	create := strings.Join(commands[4], " ")
	for _, expected := range []string{"--user " + rootRegistryUser, "--cap-drop ALL", "--security-opt no-new-privileges=true", "--label " + rootRegistryOwner, "-v shuttle-registry:/var/lib/registry", "127.0.0.1:5000:5000", planned} {
		if !strings.Contains(create, expected) {
			t.Errorf("converged registry create command %q lacks %q", create, expected)
		}
	}
	for _, rejected := range []struct{ name, candidate string }{
		{"downgrade", "registry:3.1.1@sha256:" + strings.Repeat("c", 64)},
		{"implicit major change", "registry:4.0.0@sha256:" + strings.Repeat("d", 64)},
	} {
		t.Run(rejected.name, func(t *testing.T) {
			if _, err := rootRegistryConvergenceCommands(running, rejected.candidate, rootRegistryUser, "system"); err == nil {
				t.Fatalf("unsafe planned image %q was accepted", rejected.candidate)
			}
		})
	}
	if commands, err := rootRegistryConvergenceCommands(planned, planned, rootRegistryUser, "system"); err != nil || len(commands) != 0 {
		t.Fatalf("already converged registry commands=%v err=%v", commands, err)
	}
	if _, err := rootRegistryConvergenceCommands(running, planned, rootRegistryUser, "foreign"); err == nil {
		t.Fatal("foreign registry was accepted for replacement")
	}
}

func TestRootRegistryConvergenceRefusesAnUnexpectedDataVolume(t *testing.T) {
	if err := validateRootRegistryVolume([]recoveryRegistryMount{{Type: "volume", Name: "shuttle-registry", Destination: "/var/lib/registry"}}); err != nil {
		t.Fatalf("expected registry volume rejected: %v", err)
	}
	for _, mounts := range [][]recoveryRegistryMount{
		{{Type: "volume", Name: "foreign-registry", Destination: "/var/lib/registry"}},
		{{Type: "bind", Source: "/srv/registry", Destination: "/var/lib/registry"}},
		{},
	} {
		err := validateRootRegistryVolume(mounts)
		if err == nil || !strings.Contains(err.Error(), "expected volume:shuttle-registry") {
			t.Fatalf("unexpected mount %v was not refused with its expected target: %v", mounts, err)
		}
		if len(mounts) > 0 && mounts[0].Type == "bind" && !strings.Contains(err.Error(), "bind:/srv/registry") {
			t.Fatalf("refusal did not name the actual bind source: %v", err)
		}
	}
	if !strings.Contains(setupRegistryNonRootSource, "registry_mount") || !strings.Contains(setupRegistryNonRootSource, "refusing to replace loopback registry") {
		t.Fatal("setup registry convergence does not validate and report its existing data mount")
	}
}

func isolateRootRegistryConvergence(t *testing.T) {
	t.Helper()
	journal := rootRegistryJournal
	value, command, shared, sole, log, image := rootRegistryDockerValue, rootRegistryDockerCommand, rootRetainedStacksShared, rootRegistrySoleOperation, rootRegistryLog, rootRegistryImage
	t.Cleanup(func() {
		rootRegistryDockerValue, rootRegistryDockerCommand, rootRetainedStacksShared, rootRegistrySoleOperation, rootRegistryLog, rootRegistryImage = value, command, shared, sole, log, image
		rootRegistryJournal = journal
	})
	rootRegistrySoleOperation = func(_ string, fn func() error) error { return fn() }
	rootRegistryLog = func(string, ...any) {}
	rootRegistryJournal = func(context.Context, coord.RegistryReplacement) error { return nil }
}

func registryConvergenceInspection(image string) string {
	return `{"HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":{"5000/tcp":[{"HostIp":"127.0.0.1","HostPort":"5000"}]}},"Config":{"Image":"` + image + `","User":"10001:10001","Labels":{"dev.shuttle.owner":"system"}},"Mounts":[{"Type":"volume","Name":"shuttle-registry","Destination":"/var/lib/registry"}]}`
}

func TestRootRegistryConcurrentConvergenceReplacesOnce(t *testing.T) {
	isolateRootRegistryConvergence(t)
	running := "registry:3.1.2@sha256:" + strings.Repeat("a", 64)
	planned := "registry:3.1.3@sha256:" + strings.Repeat("b", 64)
	rootRegistryImage = planned
	var shared, state sync.Mutex
	var lockCalls atomic.Int32
	secondAttempt := make(chan struct{}, 2)
	rootRetainedStacksShared = func(fn func() error) error {
		if lockCalls.Add(1) == 2 {
			secondAttempt <- struct{}{}
		}
		shared.Lock()
		defer shared.Unlock()
		return fn()
	}
	reads := 0
	rootRegistryDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		if args[0] == "volume" {
			return registryRecoveryVolumeJSON, nil
		}
		state.Lock()
		defer state.Unlock()
		reads++
		if reads == 2 {
			secondAttempt <- struct{}{}
		}
		return registryConvergenceInspection(running), nil
	}
	pulled, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var commands []string
	rootRegistryDockerCommand = func(_ string, args ...string) error {
		if args[0] == "pull" {
			once.Do(func() { close(pulled); <-release })
		}
		state.Lock()
		defer state.Unlock()
		commands = append(commands, strings.Join(args, " "))
		if args[0] == "run" && args[1] == "-d" {
			running = planned
		}
		return nil
	}
	results := make(chan error, 2)
	go func() { results <- convergeRootRegistryImage(context.Background(), "first", planned) }()
	<-pulled
	go func() { results <- convergeRootRegistryImage(context.Background(), "second", planned) }()
	<-secondAttempt
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(commands) != 5 || reads != 2 {
		t.Fatalf("want one pull/stop/rm/chown/create and two fresh inspections; reads=%d commands=%v", reads, commands)
	}
}

func TestRootRegistryBusyReplacementKeepsObservedImageAndContinuesDeploy(t *testing.T) {
	isolateRootRegistryConvergence(t)
	isolateRootStackPreflight(t)
	running := "registry:3.1.2@sha256:" + strings.Repeat("a", 64)
	planned := "registry:3.1.3@sha256:" + strings.Repeat("b", 64)
	payload := rootStackPreflightPayload(t, config.ProductionConfig{})
	originalPayload := string(payload)
	plan := rootStackPreflightPlan(t, payload, time.Now())
	plan.Stack.RegistryImage = planned
	rootRetainedStacksShared = func(fn func() error) error { return fn() }
	rootRegistryDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		if args[0] == "volume" {
			return registryRecoveryVolumeJSON, nil
		}
		return registryConvergenceInspection(running), nil
	}
	rootRegistryDockerCommand = func(_ string, args ...string) error {
		t.Errorf("busy registry must not be mutated: %v", args)
		return nil
	}
	rootRegistrySoleOperation = func(id string, _ func() error) error {
		if id != plan.OperationID {
			t.Errorf("sole-operation check used %q, want %q", id, plan.OperationID)
		}
		return coord.ErrOtherOperationsActive
	}
	var logLine string
	rootRegistryLog = func(format string, args ...any) { logLine = fmt.Sprintf(format, args...) }
	inPhase := false
	rootStackPhase = func(_ rootplan.Plan, fn func(context.Context) error) error {
		inPhase = true
		return fn(context.Background())
	}
	continued := errors.New("test stopped after registry convergence")
	preRunFilesystem = func(string) (uint64, uint64, error) {
		if inPhase {
			if rootRegistryImage != running {
				t.Errorf("follow-up commands use %q, want observed %q", rootRegistryImage, running)
			}
			return 0, 0, continued
		}
		return 100, 100, nil
	}
	if err := applyRootStack(plan, payload); !errors.Is(err, continued) {
		t.Fatalf("deploy did not continue after safe registry deferral: %v", err)
	}
	if string(payload) != originalPayload || plan.Stack.RegistryImage != planned {
		t.Fatal("registry deferral changed the signed request or application manifest")
	}
	if !strings.Contains(logLine, running) || !strings.Contains(logLine, planned) || !strings.Contains(logLine, "deferred") {
		t.Fatalf("deferral did not identify requested and observed images: %q", logLine)
	}
}

const registryRecoveryVolumeJSON = `{"Name":"shuttle-registry","Driver":"local","Scope":"local","Mountpoint":"/var/lib/docker/volumes/shuttle-registry/_data","CreatedAt":"2026-10-01T12:00:00Z","Options":null,"Labels":null}`

func TestRecoveryMissingRegistryRequiresMatchingReplacementProof(t *testing.T) {
	for _, scenario := range []string{"matching volume", "changed volume", "legacy journal", "daemon unavailable", "wrong image digest", "volume changes after confirmation"} {
		t.Run(scenario, func(t *testing.T) {
			previous := rootRegistryImage
			t.Cleanup(func() { rootRegistryImage = previous })
			docker := &fakeRecoveryDocker{}
			attachHealthyWeb(docker)
			rt := newTestRecoveryRuntime(t, docker)
			current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
			attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
			record := testRecoveryRecord("deploy", "demo")
			image := "registry:3@sha256:" + strings.Repeat("a", 64)
			if scenario != "legacy journal" {
				// Decode the optional field as a journal reader does. On the base
				// revision it is ignored, leaving the missing registry unresolved.
				body := `{"registry_replacement":{"image":"` + image + `","volume_sha256":"` + rootRecoveryDigest([]byte(registryRecoveryVolumeJSON)) + `"}}`
				if err := json.Unmarshal([]byte(body), &record); err != nil {
					t.Fatal(err)
				}
			}
			now := rt.clock()
			coordinator := newRecoveryCoordinator(t, &now)
			owner := "SHA256:" + strings.Repeat("A", 43)
			handle, err := coordinator.Reserve(context.Background(), coord.Request{ID: testRecoveryOpID, Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost})
			if err != nil {
				t.Fatal(err)
			}
			interrupted := errors.New("simulated interruption after registry removal")
			request := coord.PhaseRequest{ID: handle.ID(), Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost, Name: "stack-apply", Concurrent: true}
			err = coordinator.ExecutePhase(context.Background(), request, func(ctx context.Context, _ coord.Record) error {
				if record.RegistryReplacement != nil {
					if err := coord.JournalRegistryReplacement(ctx, *record.RegistryReplacement); err != nil {
						return err
					}
				}
				return interrupted
			})
			if !errors.Is(err, interrupted) {
				t.Fatalf("interruption fixture: %v", err)
			}
			volume := registryRecoveryVolumeJSON
			if scenario == "changed volume" {
				volume = strings.ReplaceAll(volume, "2026-10-01", "2026-10-02")
			}
			created := false
			var reads []string
			rt.dockerRead = func(ctx context.Context, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				reads = append(reads, joined)
				genericInspect := joined == "inspect --format {{json .}} shuttle-registry"
				containerInspect := joined == "container inspect --format {{json .}} shuttle-registry"
				if (genericInspect || containerInspect) && !created {
					if scenario == "daemon unavailable" {
						return "", errors.New("Cannot connect to the Docker daemon")
					}
					// Real Docker's generic inspect falls back to the same-named
					// volume after rm. Only a container lookup proves absence.
					if genericInspect {
						return volume, nil
					}
					return "", errors.New("Error: No such container: shuttle-registry")
				}
				if joined == "volume inspect shuttle-registry --format {{json .}}" {
					return volume, nil
				}
				if (genericInspect || containerInspect) && created {
					body := healthyRegistryJSON("")
					return strings.TrimSuffix(body, "}") + `,"Mounts":[{"Type":"volume","Name":"shuttle-registry","Destination":"/var/lib/registry"}]}`, nil
				}
				if args[0] == "image" && scenario == "wrong image digest" {
					return `[{"RepoDigests":["registry@sha256:` + strings.Repeat("b", 64) + `"]}]`, nil
				}
				return docker.Read(ctx, args...)
			}
			rt.dockerRun = func(ctx context.Context, args ...string) error {
				if args[0] == "run" && args[1] == "-d" {
					created = true
				}
				return docker.Run(ctx, args...)
			}
			plan, err := coordinator.RecoveryPlan(context.Background(), handle.ID(), rt.observe)
			if err != nil {
				t.Fatal(err)
			}
			observation := plan.Observed
			allowed := scenario == "matching volume" || scenario == "volume changes after confirmation"
			if observation.Safe != allowed {
				t.Fatalf("safe=%v want=%v; unresolved=%v actions=%v", observation.Safe, allowed, observation.Unresolved, observation.Actions)
			}
			if !allowed {
				if len(docker.runs) != 0 {
					t.Fatalf("refused recovery mutated Docker: %v", docker.runs)
				}
				return
			}
			if scenario == "volume changes after confirmation" {
				volume = strings.ReplaceAll(volume, "2026-10-01", "2026-10-02")
			}
			_, err = coordinator.ApplyRecoveryWithProof(context.Background(), handle.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply)
			if scenario == "volume changes after confirmation" {
				if err == nil || len(docker.runs) != 0 {
					t.Fatalf("changed volume was not refused before effects: runs=%v err=%v", docker.runs, err)
				}
				return
			}
			if err != nil || !created {
				t.Fatalf("matching missing registry was not recreated: runs=%v err=%v", docker.runs, err)
			}
			if len(docker.runs) != 2 {
				t.Fatalf("expected only chown and creation: %v", docker.runs)
			}
			healthInspected := false
			for _, read := range reads {
				if strings.HasPrefix(read, "inspect ") && strings.HasSuffix(read, " "+rootRegistryContainer) {
					t.Errorf("registry lookup can resolve its volume instead of its container: %s", read)
				}
				if read == "container inspect --format {{json .State.Health.Status}} shuttle-registry" {
					healthInspected = true
				}
			}
			if !healthInspected {
				t.Fatal("recovery did not verify the recreated container's health with a typed lookup")
			}
			for _, expected := range []string{"--user " + rootRegistryUser, "--cap-drop ALL", "--security-opt no-new-privileges=true", "--restart=always", "-p 127.0.0.1:5000:5000", "-v shuttle-registry:/var/lib/registry", image} {
				if !strings.Contains(docker.runs[1], expected) {
					t.Errorf("recreation lacks %q: %s", expected, docker.runs[1])
				}
			}
		})
	}
}

func TestRootRegistryReplacementPersistsProofBeforeDestruction(t *testing.T) {
	for _, scenario := range []string{"journal persisted", "journal failure", "public binding"} {
		t.Run(scenario, func(t *testing.T) {
			isolateRootRegistryConvergence(t)
			now := time.Now().UTC()
			coordinator := newRecoveryCoordinator(t, &now)
			owner := "SHA256:" + strings.Repeat("A", 43)
			handle, err := coordinator.Reserve(context.Background(), coord.Request{ID: testRecoveryOpID, Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost})
			if err != nil {
				t.Fatal(err)
			}
			running := "registry:3.1.2@sha256:" + strings.Repeat("a", 64)
			planned := "registry:3.1.3@sha256:" + strings.Repeat("b", 64)
			rootRetainedStacksShared = func(fn func() error) error { return fn() }
			rootRegistrySoleOperation = func(id string, fn func() error) error {
				return coordinator.WithSoleOperation(context.Background(), id, fn)
			}
			rootRegistryDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
				if args[0] == "volume" {
					return registryRecoveryVolumeJSON, nil
				}
				body := registryConvergenceInspection(running)
				if scenario == "public binding" {
					body = strings.ReplaceAll(body, "127.0.0.1", "0.0.0.0")
				}
				return body, nil
			}
			var durable *coord.RegistryReplacement
			rootRegistryJournal = func(ctx context.Context, intent coord.RegistryReplacement) error {
				if scenario == "journal failure" {
					return errors.New("injected journal fsync failure")
				}
				if err := coord.JournalRegistryReplacement(ctx, intent); err != nil {
					return err
				}
				stored, err := coordinator.Get(context.Background(), handle.ID())
				durable = stored.RegistryReplacement
				return err
			}
			var commands []string
			rootRegistryDockerCommand = func(_ string, args ...string) error {
				if durable == nil || durable.Image != planned || durable.VolumeSHA256 != rootRecoveryDigest([]byte(registryRecoveryVolumeJSON)) {
					t.Errorf("command before durable signed-image/volume proof: %v", args)
				}
				commands = append(commands, strings.Join(args, " "))
				return nil
			}
			request := coord.PhaseRequest{ID: handle.ID(), Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost, Name: "stack-apply", Concurrent: true}
			err = coordinator.ExecutePhase(context.Background(), request, func(ctx context.Context, _ coord.Record) error {
				return convergeRootRegistryImage(ctx, handle.ID(), planned)
			})
			if scenario == "journal persisted" {
				if err != nil || len(commands) != 5 {
					t.Fatalf("replacement failed: commands=%v err=%v", commands, err)
				}
			} else if err == nil || len(commands) != 0 {
				t.Fatalf("unsafe replacement was not refused before effects: commands=%v err=%v", commands, err)
			}
		})
	}
}
