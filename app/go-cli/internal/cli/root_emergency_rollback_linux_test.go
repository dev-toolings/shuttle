//go:build linux

package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	emergencyRedisOld   = "redis:8.10.1-alpine@sha256:becdda6c" + "00000000000000000000000000000000000000000000000000000000"
	emergencyRedisNew   = "redis:8.10.3-alpine@sha256:47b08295" + "00000000000000000000000000000000000000000000000000000000"
	emergencyRedisNext  = "redis:9.0.0-alpine@sha256:" + "5555555555555555555555555555555555555555555555555555555555555555"
	emergencyRedisOther = "ghcr.io/vendor/redis:8.10.3-alpine@sha256:" + "6666666666666666666666666666666666666666666666666666666666666666"
)

// emergencyDocker answers the two reads the decision makes: the live image of
// a service, and the version an image carries in its configuration.
type emergencyDocker struct {
	live     map[string]string
	versions map[string]string
	errors   map[string]error
	calls    [][]string
}

func (f *emergencyDocker) read(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	last := args[len(args)-1]
	switch {
	case len(args) >= 2 && args[0] == "service" && args[1] == "inspect":
		if err := f.errors[last]; err != nil {
			return "", err
		}
		image, ok := f.live[last]
		if !ok {
			return "", fmt.Errorf("Error: no such service: %s", last)
		}
		return image, nil
	case len(args) >= 2 && args[0] == "image" && args[1] == "inspect":
		for image, version := range f.versions {
			if recoveryInfrastructureInspectReference(image) == last {
				// Each runtime exposes only its own variable: reading
				// RabbitMQ's version through Redis's would find nothing.
				variable := "REDIS_VERSION"
				if strings.HasPrefix(image, "rabbitmq:") {
					variable = "RABBITMQ_VERSION"
				}
				body, err := json.Marshal([]string{"PATH=/bin", variable + "=" + version})
				return string(body), err
			}
		}
		return "", fmt.Errorf("Error: No such image: %s", last)
	}
	return "", errors.New("unexpected docker call")
}

// emergencyFixture writes previous.yml in a fresh state directory, wires the
// seams, and returns what the decision needs.
func emergencyFixture(t *testing.T, retainedRedis string, docker *emergencyDocker) (root, previous string, logs *[]string) {
	t.Helper()
	return emergencyFixtureManifest(t, testRecoveryInfrastructureManifest(map[string]string{
		"web":   "127.0.0.1:5000/demo-web@" + testWebDigest,
		"redis": retainedRedis,
	}), docker)
}

func emergencyFixtureManifest(t *testing.T, manifest string, docker *emergencyDocker) (root, previous string, logs *[]string) {
	t.Helper()
	root = t.TempDir()
	previous = filepath.Join(root, "previous.yml")
	if err := os.WriteFile(previous, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	lines := []string{}
	logs = &lines
	originalRead, originalLog := rootEmergencyDockerRead, rootEmergencyLog
	rootEmergencyDockerRead = docker.read
	rootEmergencyLog = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { rootEmergencyDockerRead, rootEmergencyLog = originalRead, originalLog })
	return root, previous, logs
}

func emergencyRedisImage(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	services, err := rootStackServices("demo", body)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		if service.Name == "redis" {
			return service.Image
		}
	}
	t.Fatal("no redis service in " + path)
	return ""
}

func TestEmergencyRollbackKeepsNewerLiveRedisOfTheSameMajor(t *testing.T) {
	docker := &emergencyDocker{
		live:     map[string]string{"demo_redis": emergencyRedisNew},
		versions: map[string]string{emergencyRedisOld: "8.10.1", emergencyRedisNew: "8.10.3"},
	}
	root, previous, logs := emergencyFixture(t, emergencyRedisOld, docker)
	before, _ := os.ReadFile(previous)
	current := filepath.Join(root, "current.yml")
	if err := os.WriteFile(current, before, 0o600); err != nil {
		t.Fatal(err)
	}

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	if !ok || file == previous {
		t.Fatalf("a newer live Redis must produce an adjusted manifest: file=%s ok=%v", file, ok)
	}
	if after, _ := os.ReadFile(current); string(after) != string(before) {
		t.Fatal("current.yml was rewritten by the decision")
	}
	if got := emergencyRedisImage(t, file); got != emergencyRedisNew {
		t.Fatalf("rollback manifest redis = %s, want the live %s", got, emergencyRedisNew)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 || filepath.Dir(file) != root {
		t.Fatalf("adjusted manifest must be a 0600 file in the state directory: %v %v", info, err)
	}
	if after, _ := os.ReadFile(previous); string(after) != string(before) {
		t.Fatal("previous.yml was rewritten")
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "keeps redis "+emergencyRedisNew) {
		t.Fatalf("the decision was not journaled: %v", *logs)
	}
	cleanup()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("temporary manifest survived its cleanup: %v", err)
	}
}

func TestEmergencyRollbackRefusesAMajorChangeAndKeepsLive(t *testing.T) {
	docker := &emergencyDocker{
		live:     map[string]string{"demo_redis": emergencyRedisNext},
		versions: map[string]string{emergencyRedisOld: "8.10.1", emergencyRedisNext: "9.0.0"},
	}
	root, previous, logs := emergencyFixture(t, emergencyRedisOld, docker)

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	defer cleanup()
	if !ok || file == previous {
		t.Fatalf("a major change must keep the live image in a new manifest: file=%s ok=%v", file, ok)
	}
	if got := emergencyRedisImage(t, file); got != emergencyRedisNext {
		t.Fatalf("rollback manifest redis = %s, want the live %s", got, emergencyRedisNext)
	}
	if joined := strings.Join(*logs, "\n"); !strings.Contains(joined, "refusing to replace running redis") || !strings.Contains(joined, "major change 9.0.0 -> 8.10.1") {
		t.Fatalf("the refusal was not journaled: %v", *logs)
	}
}

func TestEmergencyRollbackAppliesAStrictlyNewerRetainedImage(t *testing.T) {
	docker := &emergencyDocker{
		live:     map[string]string{"demo_redis": emergencyRedisOld},
		versions: map[string]string{emergencyRedisOld: "8.10.1", emergencyRedisNew: "8.10.3"},
	}
	root, previous, _ := emergencyFixture(t, emergencyRedisNew, docker)

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	defer cleanup()
	if !ok || file != previous {
		t.Fatalf("a strictly newer retained image must be applied from previous.yml itself: file=%s ok=%v", file, ok)
	}
	if got := emergencyRedisImage(t, file); got != emergencyRedisNew {
		t.Fatalf("redis = %s, want the retained %s", got, emergencyRedisNew)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 1 {
		t.Fatalf("no temporary manifest should exist: %v", entries)
	}
}

func TestEmergencyRollbackNominalCaseUsesTheSameFileAndWritesNothing(t *testing.T) {
	docker := &emergencyDocker{live: map[string]string{"demo_redis": emergencyRedisOld}}
	root, previous, logs := emergencyFixture(t, emergencyRedisOld, docker)

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	defer cleanup()
	if !ok || file != previous {
		t.Fatalf("equal images must keep the rollback file path: file=%s ok=%v", file, ok)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 1 {
		t.Fatalf("the nominal case wrote a file: %v", entries)
	}
	if len(*logs) != 0 {
		t.Fatalf("the nominal case must stay silent: %v", *logs)
	}

	absent := &emergencyDocker{}
	rootEmergencyDockerRead = absent.read
	if file, _, ok := emergencyRollbackManifest(root, "demo", previous); !ok || file != previous {
		t.Fatalf("a service Docker does not know has nothing to protect: file=%s ok=%v", file, ok)
	}
}

func TestEmergencyRollbackKeepsANonOfficialLiveImage(t *testing.T) {
	docker := &emergencyDocker{live: map[string]string{"demo_redis": emergencyRedisOther}}
	root, previous, logs := emergencyFixture(t, emergencyRedisNew, docker)

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	defer cleanup()
	if !ok || file == previous {
		t.Fatalf("a non-official live image must be kept: file=%s ok=%v", file, ok)
	}
	if got := emergencyRedisImage(t, file); got != emergencyRedisOther {
		t.Fatalf("rollback manifest redis = %s, want the live %s", got, emergencyRedisOther)
	}
	for _, call := range docker.calls {
		if call[0] == "image" {
			t.Fatalf("a non-official image must not be inspected: %v", call)
		}
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "is not an official redis image pinned by digest") {
		t.Fatalf("the reason was not journaled: %v", *logs)
	}
}

func TestEmergencyRollbackSkipsWhenTheLiveImageCannotBeRead(t *testing.T) {
	docker := &emergencyDocker{errors: map[string]error{"demo_redis": errors.New("permission denied")}}
	root, previous, logs := emergencyFixture(t, emergencyRedisOld, docker)

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	defer cleanup()
	if ok || file != "" {
		t.Fatalf("an unreadable stateful service must block the rollback: file=%s ok=%v", file, ok)
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "emergency rollback SKIPPED") {
		t.Fatalf("the skip was not journaled: %v", *logs)
	}
}

func TestEmergencyRollbackSkipsWhenTheManifestCannotBeRead(t *testing.T) {
	docker := &emergencyDocker{live: map[string]string{"demo_redis": emergencyRedisNew}}
	root, _, logs := emergencyFixture(t, emergencyRedisOld, docker)
	missing := filepath.Join(root, "absent.yml")

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", missing)
	defer cleanup()
	if ok || file != "" {
		t.Fatalf("an unreadable manifest must block the rollback: file=%s ok=%v", file, ok)
	}
	if len(docker.calls) != 0 {
		t.Fatalf("docker was read although the manifest was unreadable: %v", docker.calls)
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "emergency rollback SKIPPED") {
		t.Fatalf("the skip was not journaled: %v", *logs)
	}
}

func TestEmergencyRollbackSkipsWhenTheManifestIsNotInTheValidatedShape(t *testing.T) {
	webImage := "127.0.0.1:5000/demo-web@" + testWebDigest
	for name, manifest := range map[string]string{
		"uppercase service name": strings.Replace(testRecoveryInfrastructureManifest(map[string]string{"web": webImage, "redis": emergencyRedisOld}), "  web:", "  Web:", 1),
		"unpinned image":         testRecoveryInfrastructureManifest(map[string]string{"web": "demo-web:latest", "redis": emergencyRedisOld}),
		"not yaml":               "services: [unterminated\n",
	} {
		t.Run(name, func(t *testing.T) {
			docker := &emergencyDocker{live: map[string]string{"demo_redis": emergencyRedisNew}}
			root, previous, logs := emergencyFixtureManifest(t, manifest, docker)

			file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
			defer cleanup()
			if ok || file != "" {
				t.Fatalf("a manifest the helper would not validate must block the rollback: file=%s ok=%v", file, ok)
			}
			if !strings.Contains(strings.Join(*logs, "\n"), "emergency rollback SKIPPED") {
				t.Fatalf("the skip was not journaled: %v", *logs)
			}
		})
	}
}

func TestEmergencyRollbackKeepsNewerLiveRabbitMQ(t *testing.T) {
	retained := "rabbitmq:4.1.0-alpine@sha256:" + strings.Repeat("7", 64)
	live := "rabbitmq:4.1.2-alpine@sha256:" + strings.Repeat("8", 64)
	docker := &emergencyDocker{
		live:     map[string]string{"demo_rabbitmq": live},
		versions: map[string]string{retained: "4.1.0", live: "4.1.2"},
	}
	root, previous, logs := emergencyFixtureManifest(t, testRecoveryInfrastructureManifest(map[string]string{
		"web":      "127.0.0.1:5000/demo-web@" + testWebDigest,
		"rabbitmq": retained,
	}), docker)

	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	defer cleanup()
	if !ok || file == previous {
		t.Fatalf("a newer live RabbitMQ must produce an adjusted manifest: file=%s ok=%v", file, ok)
	}
	body, _ := os.ReadFile(file)
	services, err := rootStackServices("demo", body)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		if service.Name == "rabbitmq" && service.Image != live {
			t.Fatalf("rabbitmq = %s, want the live %s", service.Image, live)
		}
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "keeps rabbitmq "+live) {
		t.Fatalf("the decision was not journaled: %v", *logs)
	}
}

// blockingEmergencyRead answers nothing until its context ends, and records the
// deadline each call carried.
type blockingEmergencyRead struct {
	deadlines []time.Time
	missing   int
}

func (b *blockingEmergencyRead) read(ctx context.Context, _ ...string) (string, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		b.missing++
	}
	b.deadlines = append(b.deadlines, deadline)
	<-ctx.Done()
	return "", ctx.Err()
}

func TestEmergencyRollbackHonorsTheSharedReadDeadline(t *testing.T) {
	docker := &emergencyDocker{}
	manifest := testRecoveryInfrastructureManifest(map[string]string{
		"web":      "127.0.0.1:5000/demo-web@" + testWebDigest,
		"redis":    emergencyRedisOld,
		"rabbitmq": "rabbitmq:4.1.0-alpine@sha256:" + strings.Repeat("7", 64),
	})
	root, previous, logs := emergencyFixtureManifest(t, manifest, docker)
	blocking := &blockingEmergencyRead{}
	rootEmergencyDockerRead = blocking.read
	original := rootEmergencyInfrastructureReadBudget
	rootEmergencyInfrastructureReadBudget = 50 * time.Millisecond
	t.Cleanup(func() { rootEmergencyInfrastructureReadBudget = original })

	started := time.Now()
	file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
	defer cleanup()
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the decision outlived its budget: %s", elapsed)
	}
	if ok || file != "" {
		t.Fatalf("services that could not be read in time must block the rollback: file=%s ok=%v", file, ok)
	}
	if blocking.missing != 0 || len(blocking.deadlines) != 2 || !blocking.deadlines[0].Equal(blocking.deadlines[1]) {
		t.Fatalf("every read must carry the one shared deadline: %+v", blocking)
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "emergency rollback SKIPPED") {
		t.Fatalf("the skip was not journaled: %v", *logs)
	}
}

func TestEmergencyRollbackSkipsAnUnsafeLiveReference(t *testing.T) {
	for name, live := range map[string]string{
		"embedded space":  "redis 8.10.3@sha256:" + strings.Repeat("9", 64),
		"leading dash":    "-redis:8.10.3@sha256:" + strings.Repeat("9", 64),
		"embedded quotes": "redis:8.10.3\"@sha256:" + strings.Repeat("9", 64),
	} {
		t.Run(name, func(t *testing.T) {
			docker := &emergencyDocker{live: map[string]string{"demo_redis": live}}
			root, previous, _ := emergencyFixture(t, emergencyRedisOld, docker)

			file, cleanup, ok := emergencyRollbackManifest(root, "demo", previous)
			defer cleanup()
			if ok || file != "" {
				t.Fatalf("an unsafe live reference must never be written to a manifest: file=%s ok=%v", file, ok)
			}
			if entries, _ := os.ReadDir(root); len(entries) != 1 {
				t.Fatalf("a manifest was written: %v", entries)
			}
		})
	}
}

func TestEmergencyRollbackSkipsWhenTheAdjustedManifestCannotBeWritten(t *testing.T) {
	docker := &emergencyDocker{
		live:     map[string]string{"demo_redis": emergencyRedisNew},
		versions: map[string]string{emergencyRedisOld: "8.10.1", emergencyRedisNew: "8.10.3"},
	}
	root, previous, logs := emergencyFixture(t, emergencyRedisOld, docker)
	// A state directory that does not exist: the write fails whoever runs the test.
	gone := filepath.Join(root, "gone")

	file, cleanup, ok := emergencyRollbackManifest(gone, "demo", previous)
	defer cleanup()
	if ok || file != "" {
		t.Fatalf("a manifest that cannot be written must block the rollback: file=%s ok=%v", file, ok)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 1 {
		t.Fatalf("a temporary file was left behind: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(gone, rootEmergencyRollbackManifestName)); !os.IsNotExist(err) {
		t.Fatalf("the adjusted manifest exists: %v", err)
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "emergency rollback SKIPPED") {
		t.Fatalf("the skip was not journaled: %v", *logs)
	}
}

// Explicit rollback and the rollback requested after an origin-proof failure
// both enter stack-rollback. Assert on the bytes handed to Docker, not merely
// the retained file which deliberately preserves the signed release.
func TestExplicitRollbackProtectsLiveStatefulImages(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(fmt.Sprintf("unreadable=%t", unreadable), func(t *testing.T) {
			isolateRootStackPreflight(t)
			rabbitOld := "rabbitmq:4.1.0@sha256:" + strings.Repeat("a", 64)
			rabbitNew := "rabbitmq:4.1.1@sha256:" + strings.Repeat("b", 64)
			docker := &emergencyDocker{
				live:     map[string]string{"demo_redis": emergencyRedisNew, "demo_rabbitmq": rabbitNew},
				versions: map[string]string{emergencyRedisOld: "8.10.1", emergencyRedisNew: "8.10.3", rabbitOld: "4.1.0", rabbitNew: "4.1.1"},
			}
			if unreadable {
				docker.errors = map[string]error{"demo_redis": errors.New("daemon unavailable")}
			}
			// A retained global volume option is accepted under its original
			// policy, even though a newly submitted stack would be refused.
			manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": emergencyRedisOld, "rabbitmq": rabbitOld}) + "volumes:\n  legacy:\n    driver_opts:\n      type: tmpfs\n"
			root, previous, _ := emergencyFixtureManifest(t, manifest, docker)
			current := filepath.Join(root, "current.yml")
			live := strings.ReplaceAll(strings.ReplaceAll(manifest, emergencyRedisOld, emergencyRedisNew), rabbitOld, rabbitNew)
			live = strings.ReplaceAll(live, testWebDigest, "sha256:"+strings.Repeat("c", 64))
			if err := os.WriteFile(current, []byte(live), 0o600); err != nil {
				t.Fatal(err)
			}
			rootStackPreflightCurrentPath = func(string) string { return current }
			rootStackPhase = func(_ rootplan.Plan, run func(context.Context) error) error { return run(context.Background()) }
			oldDeploy := rootStackDeployOutput
			t.Cleanup(func() { rootStackDeployOutput = oldDeploy })
			calls := 0
			rootStackDeployOutput = func(command *exec.Cmd) ([]byte, error) {
				calls++
				file := command.Args[len(command.Args)-2]
				body, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				services, err := rootStackServices("demo", body)
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]string{"redis": emergencyRedisNew, "rabbitmq": rabbitNew, "web": "127.0.0.1:5000/demo-web@" + testWebDigest}
				for _, service := range services {
					if service.Image != want[service.Name] {
						t.Errorf("deployed rollback image for %s = %s, want %s", service.Name, service.Image, want[service.Name])
					}
				}
				return []byte("test stopped at deploy"), errors.New("test stopped at deploy")
			}
			err := applyRootStack(rootplan.Plan{Action: "stack-rollback", Stack: &rootplan.StackOperation{App: "demo"}}, nil)
			if unreadable {
				if calls != 0 || err == nil || !strings.Contains(err.Error(), "stateful") {
					t.Fatalf("unreadable live image must refuse before deploy: calls=%d err=%v", calls, err)
				}
			} else if calls != 1 || err == nil || !strings.Contains(err.Error(), "test stopped at deploy") {
				t.Fatalf("rollback did not reach the guarded deploy: calls=%d err=%v", calls, err)
			}
			// Both refusal before deploy and failure during deploy must preserve
			// the current release: rollback only wrote its temporary manifest.
			if body, _ := os.ReadFile(current); string(body) != live {
				t.Fatal("failed rollback changed current.yml")
			}
			if body, _ := os.ReadFile(previous); string(body) != manifest {
				t.Fatal("rollback changed retained previous.yml")
			}
		})
	}
}

func TestFailedApplyRestoresExactServingManifest(t *testing.T) {
	for _, identical := range []bool{true, false} {
		for _, failure := range []string{"deploy", "convergence", "convergence-restore-write", "convergence-temp-create", "convergence-temp-write"} {
			t.Run(fmt.Sprintf("identical=%t/%s", identical, failure), func(t *testing.T) {
				isolateRootStackPreflight(t)
				oldTemp := rootStackRollbackTemp
				t.Cleanup(func() { rootStackRollbackTemp = oldTemp })
				rootStackRollbackTemp = func(dir, pattern string) (*os.File, error) {
					if failure == "convergence-temp-create" {
						return nil, os.ErrPermission
					}
					file, err := os.CreateTemp(dir, pattern)
					if err == nil && failure == "convergence-temp-write" {
						if err := file.Close(); err != nil {
							t.Fatal(err)
						}
					}
					return file, err
				}
				oldPreflight, oldPostgres := rootStackApplyPreflight, rootPostgresOwnershipPreflight
				oldDeploy, oldWait, oldHistory := rootStackDeployOutput, rootStackWait, swarmTaskHistoryValue
				oldRegistry, oldRegistryImage := rootStackRegistryImage, rootRegistryImage
				oldCertificates := rootEdgeCertificateReader
				t.Cleanup(func() { rootEdgeCertificateReader = oldCertificates })
				rootEdgeCertificateReader = func() ([]*x509.Certificate, error) { return nil, errors.New("fixture has no certificates") }
				t.Cleanup(func() { rootStackRegistryImage, rootRegistryImage = oldRegistry, oldRegistryImage })
				rootStackRegistryImage = func() (string, error) { return "registry:3@sha256:" + strings.Repeat("d", 64), nil }
				t.Cleanup(func() {
					rootStackApplyPreflight, rootPostgresOwnershipPreflight = oldPreflight, oldPostgres
					rootStackDeployOutput, rootStackWait, swarmTaskHistoryValue = oldDeploy, oldWait, oldHistory
				})
				rootStackApplyPreflight = func(rootplan.Plan, []byte) error { return nil }
				rootPostgresOwnershipPreflight = func(string, []byte) error { return nil }
				swarmTaskHistoryValue = func(time.Duration, string, ...string) (string, error) { return fmt.Sprint(swarmTaskHistoryLimit), nil }
				current := rootStackPreflightCurrentPath("demo")
				if err := os.MkdirAll(filepath.Dir(current), 0o700); err != nil {
					t.Fatal(err)
				}
				previous := filepath.Join(filepath.Dir(current), "previous.yml")
				serving := rootStackPreflightPayload(t, config.ProductionConfig{})
				older := []byte(strings.ReplaceAll(string(serving), strings.Repeat("a", 64), strings.Repeat("b", 64)))
				payload := serving
				if !identical {
					payload = []byte(strings.ReplaceAll(string(serving), strings.Repeat("a", 64), strings.Repeat("c", 64)))
				}
				if err := os.WriteFile(current, serving, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(previous, older, 0o600); err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				c := newRecoveryCoordinator(t, &now)
				_, request := reserveLiveDeploy(t, c, testRecoveryOpID)
				rootStackPhase = func(_ rootplan.Plan, run func(context.Context) error) error {
					return c.ExecutePhase(context.Background(), request, func(ctx context.Context, _ coord.Record) error { return run(ctx) })
				}
				calls := 0
				var rollbackInput string
				rootStackDeployOutput = func(command *exec.Cmd) ([]byte, error) {
					calls++
					if calls == 2 {
						rollbackInput = command.Args[len(command.Args)-2]
						if failure == "convergence-restore-write" && rollbackInput == current {
							t.Error("rollback still depends on current.yml")
						}
						body, err := os.ReadFile(rollbackInput)
						if err != nil || string(body) != string(serving) {
							t.Errorf("emergency rollback selected an older release: %v", err)
						}
					}
					if failure == "deploy" || calls == 2 {
						return []byte("injected deploy failure"), errors.New("injected deploy failure")
					}
					return nil, nil
				}
				rootStackWait = func(string, string, time.Time, time.Duration) error {
					if failure == "convergence-restore-write" {
						// Refuse only restoration of current.yml, while allowing
						// a temporary rollback manifest in the same directory.
						failed := filepath.Join(filepath.Dir(current), "failed-release.yml")
						if err := os.WriteFile(failed, payload, 0o600); err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(current); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(failed, current); err != nil {
							t.Fatal(err)
						}
					}
					return errors.New("injected convergence failure")
				}
				err := applyRootStack(rootplan.Plan{Action: "stack-apply", Stack: &rootplan.StackOperation{App: "demo"}}, payload)
				if err == nil || !strings.Contains(err.Error(), "injected") {
					t.Fatalf("did not reach failure handler: %v", err)
				}
				if failure == "convergence-restore-write" && !strings.Contains(err.Error(), "refusing symlink") {
					t.Errorf("restore error missing from returned failure: %v", err)
				}
				expectedCalls := 2
				if failure == "deploy" || (identical && strings.HasPrefix(failure, "convergence-temp-")) {
					expectedCalls = 1
				}
				if calls != expectedCalls {
					t.Fatalf("unexpected deploy count: %d, want %d", calls, expectedCalls)
				}
				if strings.HasPrefix(failure, "convergence-temp-") && !identical && rollbackInput != previous {
					t.Errorf("rollback did not use verified previous.yml: %s", rollbackInput)
				}
				if strings.HasPrefix(failure, "convergence-temp-") && identical && !strings.Contains(err.Error(), "prepare emergency rollback manifest") {
					t.Errorf("missing refusal for unavailable temporary manifest: %v", err)
				}
				body, readErr := os.ReadFile(current)
				expected := serving
				if failure == "convergence-restore-write" {
					expected = payload
				}
				if readErr != nil || string(body) != string(expected) {
					t.Errorf("unexpected current manifest after failed apply: %v", readErr)
				}
				if failure == "convergence-restore-write" && rollbackInput != "" {
					if _, err := os.Stat(rollbackInput); !os.IsNotExist(err) {
						t.Fatal("temporary rollback manifest was not removed")
					}
				}
				if identical {
					body, err := os.ReadFile(previous)
					if err != nil || string(body) != string(older) {
						t.Fatal("identical redeploy changed rollback history")
					}
				}
			})
		}
	}
}
