//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

const (
	testRecoveryOpID   = "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b10"
	testRecoveryBootID = "75cd8e98-536d-44a2-aed6-1bed269a8027"
	testRecoveryHost   = "SHA256:" + "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	testWebDigest      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func testRecoveryManifest(replicas int) string {
	return "services:\n  web:\n    image: 127.0.0.1:5000/demo-web@" + testWebDigest + "\n    deploy:\n      replicas: " + strconv.Itoa(replicas) + "\n"
}

func testRecoveryRoutedManifest(replicas int) string {
	return testRecoveryManifest(replicas) + "      labels:\n        dev.shuttle.domain: demo.example\n        dev.shuttle.port: \"8080\"\n"
}

func testRecoveryBinding() operationwriters.Binding {
	return operationwriters.Binding{OperationID: testRecoveryOpID, Generation: 7, HostKey: testRecoveryHost, BootID: testRecoveryBootID}
}

func testRecoveryRecord(kind, app string) coord.Record {
	return coord.Record{ID: testRecoveryOpID, Kind: kind, App: app, Host: testRecoveryHost, HostBootID: testRecoveryBootID, State: coord.RecoveryRequired}
}

func testRecoveryBaseline(current string, previousPresent bool, previous string) operationwriters.Baseline {
	baseline := operationwriters.Baseline{
		Current:                   operationwriters.BaselineArtifact{Present: current != "", FullSHA256: current},
		Previous:                  operationwriters.BaselineArtifact{Present: previousPresent, FullSHA256: previous},
		ConfiguredNativePGVersion: "18.6",
		ConfiguredNativePGCluster: "main",
	}
	return baseline
}

func closedWriterState(t *testing.T, binding operationwriters.Binding, baseline operationwriters.Baseline) operationwriters.State {
	t.Helper()
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := operationwriters.OpenStore(operationwriters.StoreOptions{Root: root, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.InitializeLocked(binding, baseline); err != nil {
		t.Fatal(err)
	}
	runner := operationwriters.RemoteRunner{HostKey: binding.HostKey, RunToken: "run-token"}
	if _, err := store.RegisterLocked(binding, operationwriters.Writer{ID: "runner", Kind: operationwriters.WriterKindRemoteRunner, Remote: &runner}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CloseAdmissionsLocked(binding); err != nil {
		t.Fatal(err)
	}
	evidence := "sha256:" + strings.Repeat("a", 64)
	observedAt := now.UTC().Format(time.RFC3339Nano)
	remote := &operationwriters.RemoteRunnerReceipt{
		HostKey: runner.HostKey, RunToken: runner.RunToken, Generation: binding.Generation, ObservedAt: observedAt,
		AdmissionsClosed: true, ResourcesClosed: true, ResourceIDs: []string{"buildkit:runner-1"}, TunnelID: "tunnel-1",
		EvidenceSHA256: evidence, AuthenticatedProof: "SHU1-Fence/v1",
	}
	state, err := store.CommitClosureLocked(binding, []operationwriters.Receipt{{
		WriterID: "runner", Kind: operationwriters.WriterKindRemoteRunner, Generation: binding.Generation, ObservedAt: observedAt,
		AdmissionsClosed: true, ResourcesClosed: true, EvidenceSHA256: evidence, Remote: remote,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

type fakeRecoveryDocker struct {
	version           string
	registry          string
	image             string
	roster            string
	stackServices     string
	networks          string
	containers        string
	secrets           []string
	volumes           []string
	volumeInspections map[string]bool
	tasks             map[string]string
	inspect           map[string]string
	health            string
	reads             []string
	runs              []string
	removedServices   []string
	removedNetworks   []string
}

func (f *fakeRecoveryDocker) Read(_ context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("empty docker")
	}
	f.reads = append(f.reads, strings.Join(args, " "))
	switch args[0] {
	case "version":
		return f.version, nil
	case "image":
		if f.image != "" {
			return f.image, nil
		}
		return `[{"RepoDigests":["registry@sha256:` + strings.Repeat("a", 64) + `"]}]`, nil
	case "container":
		if len(args) < 2 || args[1] != "inspect" {
			return "", errors.New("unsupported container command")
		}
		fallthrough
	case "inspect":
		target := args[len(args)-1]
		if target == rootRegistryContainer {
			if strings.Contains(strings.Join(args, " "), "Health.Status") {
				if f.health == "" {
					f.health = `"healthy"`
				}
				return f.health, nil
			}
			return f.registry, nil
		}
		if body, ok := f.inspect[target]; ok {
			return body, nil
		}
		return "", errors.New("unknown inspect target")
	case "service":
		if len(args) > 1 && args[1] == "ls" {
			if len(args) >= 2 && args[len(args)-2] == "--format" && args[len(args)-1] == "{{.ID}}" {
				return f.stackServices, nil
			}
			return f.roster, nil
		}
		if len(args) > 1 && args[1] == "ps" {
			service := args[len(args)-1]
			body, ok := f.tasks[service]
			if !ok {
				return "", errors.New("unknown service")
			}
			return body, nil
		}
	case "network":
		if len(args) > 1 && args[1] == "ls" {
			return f.networks, nil
		}
	case "volume":
		if len(args) > 1 && args[1] == "ls" {
			return strings.Join(f.volumes, "\n"), nil
		}
		if len(args) > 2 && args[1] == "inspect" {
			name := args[len(args)-1]
			exists := f.volumeInspections[name]
			for _, listed := range f.volumes {
				if listed == name {
					exists = true
				}
			}
			if exists {
				if len(args) > 3 && args[2] == "--format" {
					return `{"com.docker.stack.namespace":"demo"}`, nil
				}
				return "[]", nil
			}
			return "", errors.New("no such volume")
		}
	case "ps":
		if len(args) > 1 && args[1] == "-a" {
			return f.containers, nil
		}
	}
	return "", errors.New("unsupported docker read")
}

func TestDeployRecoveryBeforeHelperMutationUsesOnlyClosedWriterProof(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	c := newRecoveryCoordinator(t, &now)
	owner := "SHA256:" + strings.Repeat("A", 43)
	h, err := c.Reserve(context.Background(), coord.Request{ID: testRecoveryOpID, Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost})
	if err != nil {
		t.Fatal(err)
	}
	request := coord.PhaseRequest{ID: h.ID(), Kind: "deploy", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost, HostIdentity: testRecoveryHost, PlanExpiresAt: now.Add(time.Hour)}
	for _, name := range []string{"writers-initialize", "stack-reclaim"} {
		request.Name = name
		if err := c.ExecutePhase(context.Background(), request, func(context.Context, coord.Record) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	request.Name = "client-promotion"
	if err := c.Control(context.Background(), request, "renew", "not-started"); err != nil {
		t.Fatal(err)
	}
	request.Name = "client-cleanup"
	if err := c.Control(context.Background(), request, "renew", "completed"); err != nil {
		t.Fatal(err)
	}
	if err := c.Control(context.Background(), request, "abort", "client exited before helper mutation"); err != nil {
		t.Fatal(err)
	}

	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(plan.Observed.Actions) != 0 {
		t.Fatalf("no-mutation deploy did not produce a safe empty observation: %+v", plan.Observed)
	}
	if plan.Observed.ManifestProof != rootRecoveryDigest([]byte(`{"manifests":[]}`)) {
		t.Fatalf("empty manifest proof mismatch: %q", plan.Observed.ManifestProof)
	}
	if len(docker.reads) != 1 || docker.reads[0] != "version --format {{.Server.Version}}" {
		t.Fatalf("no-mutation observation called Docker beyond version: %v", docker.reads)
	}

	// A second observation is part of the confirmed apply path. Its only host
	// action remains the closed-writer proof, even when the inherited abort
	// checklist is copied into the displayed plan.
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply)
	if err != nil {
		t.Fatal(err)
	}
	if len(docker.runs) != 0 {
		t.Fatalf("no-mutation recovery ran Docker mutations: %v", docker.runs)
	}
	for _, call := range docker.reads {
		if !strings.HasPrefix(call, "version ") {
			t.Fatalf("no-mutation recovery made unexpected Docker read %q", call)
		}
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	wantActions := []string{"observe actual service state", "verify registry health and retained releases", "confirm all writers stopped"}
	if record.State != "recovered" || record.RecoveryRequired || record.Result != "explicit recovery reconciled observed host state" || !reflect.DeepEqual(record.RecoveryActions, wantActions) {
		t.Fatalf("recovered no-mutation record differs from the accepted inherited result: %+v", record)
	}
}

func (f *fakeRecoveryDocker) Run(_ context.Context, args ...string) error {
	f.runs = append(f.runs, strings.Join(args, " "))
	if len(args) >= 2 && args[0] == "start" {
		f.registry = healthyRegistryJSON("")
		f.health = `"healthy"`
	}
	if len(args) > 2 && args[0] == "service" && args[1] == "rm" {
		f.removedServices = append(f.removedServices, args[2:]...)
		f.roster = ""
		f.stackServices = ""
		f.containers = ""
		f.tasks = map[string]string{}
	}
	if len(args) > 2 && args[0] == "network" && args[1] == "rm" {
		f.removedNetworks = append(f.removedNetworks, args[2:]...)
		f.networks = ""
	}
	if len(args) > 2 && args[0] == "secret" && args[1] == "rm" {
		f.secrets = removeFakeRecoveryValues(f.secrets, args[2:])
	}
	if len(args) > 2 && args[0] == "volume" && args[1] == "rm" {
		f.volumes = removeFakeRecoveryValues(f.volumes, args[2:])
	}
	if len(args) >= 3 && args[0] == "service" && args[1] == "scale" {
		_, count, _ := strings.Cut(args[2], "=")
		if count != "0" {
			attachHealthyWeb(f)
		}
	}
	if len(args) >= 1 && args[0] == "stack" {
		if len(args) >= 2 && args[1] == "rm" {
			f.roster = ""
			f.stackServices = ""
			f.networks = ""
			f.containers = ""
		} else {
			attachHealthyWeb(f)
		}
	}
	return nil
}

func removeFakeRecoveryValues(values, removed []string) []string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		keep := true
		for _, candidate := range removed {
			if value == candidate {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func healthyRegistryJSON(logStart string) string {
	if logStart == "" {
		logStart = "2026-09-13T15:00:00.000000000Z"
	}
	return `{"State":{"Running":true,"Health":{"Status":"healthy","Log":[{"Start":"` + logStart + `","Output":"ok"}]}},"HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":{"5000/tcp":[{"HostIp":"127.0.0.1","HostPort":"5000"}]}},"Config":{"Image":"registry:3@sha256:` + strings.Repeat("a", 64) + `","Labels":{"dev.shuttle.owner":"system"}},"Image":"sha256:` + strings.Repeat("c", 64) + `"}`
}

func publicRegistryJSON() string {
	return `{"State":{"Running":true,"Health":{"Status":"healthy"}},"HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":{"5000/tcp":[{"HostIp":"127.0.0.1","HostPort":"5000"}],"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"80"}]}},"Config":{"Image":"registry:3@sha256:` + strings.Repeat("a", 64) + `","Labels":{"dev.shuttle.owner":"system"}},"Image":"sha256:` + strings.Repeat("c", 64) + `"}`
}

func stoppedRegistryJSON() string {
	return `{"State":{"Running":false,"Health":{"Status":"unhealthy"}},"HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":{"5000/tcp":[{"HostIp":"127.0.0.1","HostPort":"5000"}]}},"Config":{"Image":"registry:3@sha256:` + strings.Repeat("a", 64) + `","Labels":{"dev.shuttle.owner":"system"}},"Image":"sha256:` + strings.Repeat("c", 64) + `"}`
}

func registryJSONWith(image, owner, bindings string) string {
	labels := "{}"
	if owner != "" {
		labels = `{"dev.shuttle.owner":"` + owner + `"}`
	}
	return `{"State":{"Running":true,"Health":{"Status":"healthy"}},"HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":` + bindings + `},"Config":{"Image":"` + image + `","Labels":` + labels + `},"Image":"sha256:` + strings.Repeat("c", 64) + `"}`
}

const loopbackRegistryBindings = `{"5000/tcp":[{"HostIp":"127.0.0.1","HostPort":"5000"}]}`

// The preprod VPS ran the registry 3.1.1 an older Shuttle installed. Recovery
// refused it as "registry image identity is unsafe" once the pin moved to
// 3.1.2, and only a recovery could release the deploy that blocked every
// convergence. An earlier Shuttle pin on a Shuttle-owned container is the
// retained service; anything else is still refused.
func TestRecoveryRegistryAcceptsAnEarlierShuttlePinItOwns(t *testing.T) {
	previous := "registry:3.1.1@sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name       string
		body       string
		state      string
		unresolved bool
	}{
		{"current pin", registryJSONWith(previous, "system", loopbackRegistryBindings), registryStateHealthy, false},
		{"earlier pin owned by shuttle", registryJSONWith(previous, "system", loopbackRegistryBindings), registryStateHealthy, false},
		{"earlier pin without the owner label", registryJSONWith(previous, "", loopbackRegistryBindings), registryStateWrongImage, true},
		{"earlier pin owned by an application", registryJSONWith(previous, "demo", loopbackRegistryBindings), registryStateWrongImage, true},
		{"earlier pin on a public binding", registryJSONWith(previous, "system", `{"5000/tcp":[{"HostIp":"0.0.0.0","HostPort":"5000"}]}`), registryStateUnsafe, true},
		{"unpinned tag owned by shuttle", registryJSONWith("registry:3.1.1", "system", loopbackRegistryBindings), registryStateWrongImage, true},
		{"valid official digest owned by shuttle", registryJSONWith("registry:3.1.1@sha256:"+strings.Repeat("e", 64), "system", loopbackRegistryBindings), registryStateHealthy, false},
		{"config digest is not a manifest identity", registryJSONWith(previous, "system", loopbackRegistryBindings), registryStateWrongImage, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest := strings.Repeat("a", 64)
			switch tc.name {
			case "config digest is not a manifest identity":
				digest = strings.Repeat("b", 64)
			case "valid official digest owned by shuttle":
				digest = strings.Repeat("e", 64)
			case "unpinned tag owned by shuttle":
				digest = ""
			}
			image := `[{"RepoDigests":["registry@sha256:` + digest + `"]}]`
			if digest == "" {
				image = `[{"RepoDigests":[]}]`
			}
			docker := &fakeRecoveryDocker{registry: tc.body, image: image}
			rt := newTestRecoveryRuntime(t, docker)
			_, state, unresolved := rt.observeRegistry(context.Background(), nil)
			if state != tc.state || (len(unresolved) > 0) != tc.unresolved {
				t.Fatalf("state=%q unresolved=%v, want state=%q unresolved=%v", state, unresolved, tc.state, tc.unresolved)
			}
			if !strings.Contains(strings.Join(docker.reads, "\n"), "image inspect sha256:"+strings.Repeat("c", 64)) {
				t.Fatalf("image metadata was not read by the container config ID: %v", docker.reads)
			}
		})
	}
}

func TestRegistryImageMatchesPinUsesRepositoryManifestDigest(t *testing.T) {
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("c", 64)
	image := "registry:3.1.1@" + manifestDigest
	if !registryImageMatchesPin(image, []string{"registry@" + manifestDigest}) {
		t.Fatal("matching official RepoDigest was not accepted")
	}
	if registryImageMatchesPin(image, []string{"registry@" + configDigest}) {
		t.Fatal("Docker config digest was accepted as the registry manifest digest")
	}
	if registryImageMatchesPin(image, nil) {
		t.Fatal("missing RepoDigests were accepted")
	}
}

func healthyWebFixture() (roster, tasks, taskJSON, containerJSON string) {
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	roster = "demo_web\treplicated\t1/1\n"
	tasks = "taskweb1\tRunning\tRunning 3 seconds ago\t" + image + "\t\n"
	taskJSON = `{"Status":{"ContainerStatus":{"ContainerID":"ctrweb1"}}}`
	containerJSON = `{"State":{"Running":true,"Status":"running","Health":{"Status":"healthy","Log":[{"Start":"2026-09-13T15:00:01Z"}]}},"Config":{"Image":"` + image + `"},"Image":"` + testWebDigest + `"}`
	return roster, tasks, taskJSON, containerJSON
}

func newTestRecoveryRuntime(t *testing.T, docker *fakeRecoveryDocker) *rootRecoveryRuntime {
	t.Helper()
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	return newTestRecoveryRuntimeAt(t, docker, &now)
}

func newTestRecoveryRuntimeAt(t *testing.T, docker *fakeRecoveryDocker, clock *time.Time) *rootRecoveryRuntime {
	t.Helper()
	root := t.TempDir()
	appRoot := filepath.Join(root, "apps")
	staging := filepath.Join(root, "backup-staging")
	pg := filepath.Join(root, "postgresql", "18", "main")
	caddy := filepath.Join(root, "caddy")
	for _, dir := range []string{appRoot, staging, pg, caddy} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	boot := filepath.Join(root, "boot_id")
	if err := os.WriteFile(boot, []byte(testRecoveryBootID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if clock == nil {
		now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
		clock = &now
	}
	if docker == nil {
		docker = &fakeRecoveryDocker{version: "27.1.0"}
	}
	if docker.version == "" {
		docker.version = "27.1.0"
	}
	if docker.registry == "" {
		docker.registry = healthyRegistryJSON("")
	}
	if docker.tasks == nil {
		docker.tasks = map[string]string{}
	}
	if docker.inspect == nil {
		docker.inspect = map[string]string{}
	}
	archive := filepath.Join(root, "operations")
	if err := os.MkdirAll(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	rt := &rootRecoveryRuntime{
		now:                   func() time.Time { return clock.UTC() },
		readFile:              os.ReadFile,
		lstat:                 os.Lstat,
		remove:                os.Remove,
		syncDir:               func(string) error { return nil },
		dockerRead:            docker.Read,
		dockerRun:             docker.Run,
		appStateRoot:          appRoot,
		backupStaging:         staging,
		destroyJournalRoot:    filepath.Join(archive, "destroy-cleanup"),
		bootIDPath:            boot,
		postgresRoot:          filepath.Join(root, "postgresql"),
		caddyDir:              caddy,
		helperMigrationIntent: filepath.Join(root, "helper-migration", "intent.json"),
		waitStack:             func(string, string, time.Time, time.Duration) error { return nil },
		applyCaddy:            func(string, []byte, time.Duration) error { return nil },
		reloadEdge:            func() error { return nil },
		verifyCaddy:           func(string, []byte) error { return nil },
		prepareStack:          func(app, path string) (string, error) { return path, nil },
		readBaselineArtifact: func(id, role string, artifact operationwriters.BaselineArtifact) ([]byte, error) {
			return readRootOperationBaselineArtifactAt(archive, id, role, artifact)
		},
		preserveBackupReplicas: func(id, app string, replicas map[string]int) error {
			return preserveRootOperationBackupReplicaProofAt(archive, id, app, replicas)
		},
		readBackupReplicas: func(id string) (map[string]int, error) {
			return readRootOperationBackupReplicaProofAt(archive, id)
		},
		archiveRoot: archive,
	}
	rt.after = func(d time.Duration) <-chan time.Time {
		*clock = clock.Add(d)
		ch := make(chan time.Time, 1)
		ch <- *clock
		return ch
	}
	return rt
}

func newRecoveryCoordinator(t *testing.T, clock *time.Time) *coord.Coordinator {
	t.Helper()
	root := t.TempDir()
	return coord.New(coord.Options{
		Root: root, LockPath: filepath.Join(root, "root.lock"), LockWait: time.Second, Lease: time.Hour,
		Now:    func() time.Time { return clock.UTC() },
		BootID: func() (string, error) { return testRecoveryBootID, nil },
	})
}

func reserveRecovery(t *testing.T, c *coord.Coordinator, kind, app string) *coord.Handle {
	t.Helper()
	h, err := c.Reserve(context.Background(), coord.Request{
		ID: testRecoveryOpID, Kind: kind, App: app, Principal: "operator", Host: testRecoveryHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("interrupted"); err != nil {
		t.Fatal(err)
	}
	return h
}

func writeAppManifest(t *testing.T, rt *rootRecoveryRuntime, app, name, body string) string {
	t.Helper()
	dir := filepath.Join(rt.appStateRoot, app)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return rootRecoveryDigest([]byte(body))
}

func attachClosedReader(rt *rootRecoveryRuntime, state operationwriters.State) {
	rt.reader = func(context.Context, coord.Record) (operationwriters.State, error) {
		return state, nil
	}
}

func TestRecoveryDestroyWithNothingLeftIsReleased(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{version: "27.1.0"}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	completeCalls := 0
	rt.completeDestroy = func(context.Context, string, io.Writer) error {
		completeCalls++
		return nil
	}
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(plan.Observed.Actions) != 0 || plan.Observed.DataState != "not applicable to destroy" {
		t.Fatalf("empty destroy observation = %+v", plan.Observed)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	if completeCalls != 0 {
		t.Fatalf("complete destroy calls = %d, want none", completeCalls)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("empty destroy was not released: %+v", record)
	}
}

func TestRecoveryDestroyCompletesTheRemainder(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{version: "27.1.0", volumes: []string{"demo_results"}}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	stateDir := filepath.Join(rt.appStateRoot, "demo")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	completeCalls := 0
	var destroyOutput bytes.Buffer
	rt.destroyOutput = &destroyOutput
	rt.completeDestroy = func(ctx context.Context, app string, out io.Writer) error {
		completeCalls++
		if app != "demo" {
			t.Errorf("complete destroy app = %q, want demo", app)
		}
		if _, err := out.Write([]byte("captured destroy detail\n")); err != nil {
			return err
		}
		docker.volumes = nil
		if err := os.RemoveAll(stateDir); err != nil {
			return err
		}
		id, _ := ctx.Value(destroyOperationContextKey{}).(string)
		return removeDestroyCleanupJournalAt(rt.destroyJournalRoot, id)
	}
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	if err := writeDestroyCleanupJournalAt(rt.destroyJournalRoot, destroyCleanupJournal{Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo", DrainBoundNanos: int64(30 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionCompleteDestroy || rt.planned[0].App != "demo" {
		t.Fatalf("destroy remainder plan = %+v, actions=%+v", plan.Observed, rt.planned)
	}
	if len(plan.Observed.Actions) != 1 || !strings.Contains(plan.Observed.Actions[0], "volumes") || !strings.Contains(plan.Observed.Actions[0], "state") {
		t.Fatalf("destroy action display does not name remaining resources: %v", plan.Observed.Actions)
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previousStdout := os.Stdout
	os.Stdout = writePipe
	_, applyErr := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply)
	_ = writePipe.Close()
	os.Stdout = previousStdout
	stdout, readErr := io.ReadAll(readPipe)
	_ = readPipe.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	if len(stdout) != 0 {
		t.Fatalf("destroy details leaked to recovery stdout: %q", stdout)
	}
	if destroyOutput.String() != "captured destroy detail\n" {
		t.Fatalf("destroy output was not captured by the recovery writer: %q", destroyOutput.String())
	}
	if completeCalls != 1 {
		t.Fatalf("complete destroy calls = %d, want 1", completeCalls)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("destroy remainder was not completed: %+v", record)
	}
}

func TestRecoveryDestroyJournalKeepsPendingCleanupVisible(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{version: "27.1.0"}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	journal := destroyCleanupJournal{
		Schema: rootDestroyCleanupSchema, OperationID: h.ID(), App: "demo",
		DrainBoundNanos: int64(30 * time.Second),
		Progress:        destroyCleanupProgress{RouteRemoved: true, StateRemoved: true},
	}
	if err := writeDestroyCleanupJournalAt(rt.destroyJournalRoot, journal); err != nil {
		t.Fatal(err)
	}
	completeCalls := 0
	rt.completeDestroy = func(ctx context.Context, app string, _ io.Writer) error {
		completeCalls++
		if app != "demo" {
			t.Fatalf("completed app = %q, want demo", app)
		}
		operationID, _ := ctx.Value(destroyOperationContextKey{}).(string)
		if operationID != h.ID() {
			t.Fatalf("destroy operation id = %q, want %q", operationID, h.ID())
		}
		return removeDestroyCleanupJournalAt(rt.destroyJournalRoot, operationID)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionCompleteDestroy {
		t.Fatalf("pending destroy journal was not planned for completion: %+v actions=%+v", plan.Observed, rt.planned)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	if completeCalls != 1 {
		t.Fatalf("complete destroy calls = %d, want 1", completeCalls)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("journaled destroy cleanup was not completed: %+v", record)
	}
}

func TestRecoveryDestroyRefusesOpenWriters(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{version: "27.1.0", volumes: []string{"demo_results"}}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	state := closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, ""))
	state.Closure = nil
	attachClosedReader(rt, state)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "destroy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Observed.Safe || len(plan.Observed.Actions) != 0 || !recoveryUnresolvedContains(plan.Observed, "closed writer admissions are not proven closed") {
		t.Fatalf("destroy recovery did not refuse open writers: %+v", plan.Observed)
	}
}

func attachHealthyWeb(docker *fakeRecoveryDocker) {
	roster, tasks, taskJSON, containerJSON := healthyWebFixture()
	docker.roster = roster
	if docker.tasks == nil {
		docker.tasks = map[string]string{}
	}
	if docker.inspect == nil {
		docker.inspect = map[string]string{}
	}
	docker.tasks["demo_web"] = tasks
	docker.inspect["taskweb1"] = taskJSON
	docker.inspect["ctrweb1"] = containerJSON
}

func prepareRunRecovery(t *testing.T, runPhase bool, outcome string) (*coord.Coordinator, *coord.Handle, *rootRecoveryRuntime, *fakeRecoveryDocker, func(string), string) {
	t.Helper()
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	target := strings.Repeat("d", 64)
	targetState := outcome
	baseRead := rt.dockerRead
	rt.dockerRead = func(ctx context.Context, args ...string) (string, error) {
		if len(args) >= 2 && args[0] == "inspect" && args[len(args)-1] == target {
			switch targetState {
			case "gone":
				return "", errors.New("No such container: " + target)
			case "inspect-fail":
				return "", errors.New("Docker connection lost")
			case "running", "mismatch", "stopped":
				label := "demo_web"
				if targetState == "mismatch" {
					label = "other_web"
				}
				running, status := "true", "running"
				if targetState == "stopped" {
					running, status = "false", "exited"
				}
				return `{"State":{"Running":` + running + `,"Status":"` + status + `"},"Config":{"Labels":{"com.docker.swarm.service.name":"` + label + `"}}}`, nil
			default:
				return "", errors.New("unsupported run target test state")
			}
		}
		return baseRead(ctx, args...)
	}
	setTargetState := func(state string) { targetState = state }
	c := coord.New(coord.Options{Root: t.TempDir(), LockPath: filepath.Join(t.TempDir(), "root.lock"), LockWait: time.Second, Lease: 500 * time.Millisecond, Now: func() time.Time { return now }, BootID: func() (string, error) { return testRecoveryBootID, nil }})
	owner := "SHA256:" + strings.Repeat("A", 43)
	h, err := c.Reserve(context.Background(), coord.Request{ID: testRecoveryOpID, Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost})
	if err != nil {
		t.Fatal(err)
	}
	if !runPhase {
		if err := h.NeedsRecovery("failed before run phase", "observe run state"); err != nil {
			t.Fatal(err)
		}
		return c, h, rt, docker, setTargetState, target
	}
	request := coord.PhaseRequest{ID: h.ID(), Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: testRecoveryHost, Name: "run"}
	var phaseErr error = errors.New("helper outcome unknown")
	if outcome == "known" {
		phaseErr = coord.KnownOutcome(errors.New("exit status 3"))
	}
	if err := c.ExecutePhase(context.Background(), request, func(phase context.Context, _ coord.Record) error {
		if err := coord.JournalRunTarget(phase, "web", target); err != nil {
			return err
		}
		return phaseErr
	}); err == nil {
		t.Fatal("failed run phase unexpectedly succeeded")
	}
	if outcome == "known" {
		now = now.Add(time.Second)
	}
	return c, h, rt, docker, setTargetState, target
}

func applyRunRecovery(t *testing.T, c *coord.Coordinator, h *coord.Handle, rt *rootRecoveryRuntime) (coord.RecoveryPlan, error) {
	t.Helper()
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		return plan, err
	}
	if !plan.Observed.Safe {
		return plan, errors.New("run recovery observation is unsafe: " + strings.Join(plan.Observed.Unresolved, "; "))
	}
	_, err = c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply)
	return plan, err
}

func TestRunRecoveryIsSupportedAndReleasesWithoutRunPhase(t *testing.T) {
	if supported, reason := recoveryKindSupported("run"); !supported || reason != "" {
		t.Fatalf("run recovery support=%v reason=%q", supported, reason)
	}
	c, h, rt, docker, _, _ := prepareRunRecovery(t, false, "running")
	plan, err := applyRunRecovery(t, c, h, rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Observed.Actions) != 0 || len(plan.Actions) != 0 || len(docker.runs) != 0 {
		t.Fatalf("pre-flight run without a run phase was mutated: plan=%+v actions=%v", plan, docker.runs)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("run without an opened phase was not released: %+v %v", record, err)
	}
}

func TestRunRecoveryReleasesKnownFailureWithoutInspectOrServiceUpdate(t *testing.T) {
	c, h, rt, docker, _, _ := prepareRunRecovery(t, true, "known")
	plan, err := applyRunRecovery(t, c, h, rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Observed.Actions) != 0 || len(plan.Actions) != 0 || len(docker.runs) != 0 {
		t.Fatalf("known command failure attempted service recovery: plan=%+v actions=%v", plan, docker.runs)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" {
		t.Fatalf("known failure was not released: %+v %v", record, err)
	}
}

func TestRunRecoveryLegacyPhaseWithoutTargetStaysUnresolved(t *testing.T) {
	_, _, rt, _, _, _ := prepareRunRecovery(t, false, "gone")
	record := testRecoveryRecord("run", "demo")
	record.Phases = []coord.Phase{{Name: "run", StartedAt: "2026-09-13T15:00:00Z", EndedAt: "2026-09-13T15:00:01Z", Error: "legacy failure"}}
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation, err := rt.observe(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || !recoveryUnresolvedContains(observation, "no journaled container target") {
		t.Fatalf("legacy run without a target was released: %+v", observation)
	}
}

func TestRunRecoveryGoneOrStoppedContainerNeedsNoTaskReplacement(t *testing.T) {
	for _, state := range []string{"gone", "stopped"} {
		t.Run(state, func(t *testing.T) {
			c, h, rt, docker, _, _ := prepareRunRecovery(t, true, state)
			plan, err := applyRunRecovery(t, c, h, rt)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Observed.Actions) != 0 || len(plan.Actions) != 0 || len(docker.runs) != 0 {
				t.Fatalf("%s container caused a replacement: plan=%+v actions=%v", state, plan, docker.runs)
			}
			record, err := c.Get(context.Background(), h.ID())
			if err != nil || record.State != "recovered" {
				t.Fatalf("%s container did not release the operation: %+v %v", state, record, err)
			}
		})
	}
}

func TestRunRecoveryRunningContainerIsReplacedAndVerified(t *testing.T) {
	c, h, rt, docker, setTargetState, _ := prepareRunRecovery(t, true, "running")
	baseRun := rt.dockerRun
	rt.dockerRun = func(ctx context.Context, args ...string) error {
		if strings.Join(args, " ") == "service update --force --detach=false demo_web" {
			setTargetState("stopped")
		}
		return baseRun(ctx, args...)
	}
	plan, err := applyRunRecovery(t, c, h, rt)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"service update --force --detach=false demo_web"}
	if !reflect.DeepEqual(docker.runs, want) || len(plan.Observed.Actions) != 1 {
		t.Fatalf("run recovery did not force-replace exactly the recorded service: plan=%+v commands=%v", plan, docker.runs)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("verified run replacement did not release the operation: %+v %v", record, err)
	}
}

func TestRunRecoveryLabelMismatchAndSharedSafetyFailureStayUnresolved(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		state    string
		registry string
		want     string
	}{
		{name: "service label mismatch", state: "mismatch", want: "does not carry the recorded Swarm service label"},
		{name: "registry unhealthy", state: "running", registry: stoppedRegistryJSON(), want: "registry health is not proven"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			_, _, rt, docker, _, _ := prepareRunRecovery(t, true, scenario.state)
			if scenario.registry != "" {
				docker.registry = scenario.registry
			}
			current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
			attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
			observation, err := rt.observe(context.Background(), testRecoveryRecordWithRunTarget("demo"))
			if err != nil {
				t.Fatal(err)
			}
			if observation.Safe || !recoveryUnresolvedContains(observation, scenario.want) {
				t.Fatalf("unsafe run recovery evidence was accepted: %+v", observation)
			}
			if scenario.name == "registry unhealthy" && (len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionReplaceRunTasks) {
				t.Fatalf("run recovery gained a generic shared action: %+v", rt.planned)
			}
		})
	}
}

func testRecoveryRecordWithRunTarget(app string) coord.Record {
	record := testRecoveryRecord("run", app)
	record.Phases = []coord.Phase{{Name: "run", StartedAt: "2026-09-13T15:00:00Z"}}
	record.RunTarget = &coord.RunTarget{Service: "web", Container: strings.Repeat("d", 64)}
	return record
}

func TestRunRecoveryVerificationFailureRemainsUnresolved(t *testing.T) {
	c, h, rt, _, setTargetState, _ := prepareRunRecovery(t, true, "running")
	baseRun := rt.dockerRun
	rt.dockerRun = func(ctx context.Context, args ...string) error {
		if strings.Join(args, " ") == "service update --force --detach=false demo_web" {
			setTargetState("inspect-fail")
		}
		return baseRun(ctx, args...)
	}
	baseAfter := rt.after
	rt.after = func(time.Duration) <-chan time.Time { return baseAfter(time.Hour) }
	plan, err := applyRunRecovery(t, c, h, rt)
	if err == nil || !strings.Contains(err.Error(), "verify journaled run container") {
		t.Fatalf("failed post-update container proof was accepted: plan=%+v err=%v", plan, err)
	}
	plan, err = c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Observed.Safe || !recoveryUnresolvedContains(plan.Observed, "container inspection is unresolved") {
		t.Fatalf("failed run replacement proof was not retained as unresolved: %+v", plan.Observed)
	}
}

const (
	testRedisRetained  = "redis:7.4.5-alpine@sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	testRedisLive      = "redis:7.4-alpine@sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
	testRedisNewer     = "redis:7.4-alpine@sha256:" + "3333333333333333333333333333333333333333333333333333333333333333"
	testRedisMajor8    = "redis:8-alpine@sha256:" + "4444444444444444444444444444444444444444444444444444444444444444"
	testRabbitRetained = "rabbitmq:3.13-alpine@sha256:" + "5555555555555555555555555555555555555555555555555555555555555555"
	testRabbitLive     = "rabbitmq:3-alpine@sha256:" + "6666666666666666666666666666666666666666666666666666666666666666"
)

type recoveryInfraDocker struct {
	t                    *testing.T
	base                 *fakeRecoveryDocker
	liveImages           map[string]string
	serviceErrors        map[string]error
	imageEnvs            map[string][]string
	imageErrors          map[string]error
	serviceInspectCounts map[string]int
	onServiceInspect     func(service string, count int)
	readCalls            [][]string
	runCalls             [][]string
	afterStackDeploy     func(stackFile string) error
}

func (f *recoveryInfraDocker) Read(ctx context.Context, args ...string) (string, error) {
	for _, arg := range args {
		if strings.Contains(strings.ToLower(arg), "pull") {
			f.t.Fatalf("unexpected pull command in dockerRead: %v", args)
			return "", errors.New("unreachable")
		}
	}
	f.readCalls = append(f.readCalls, append([]string(nil), args...))
	if len(args) >= 2 && args[0] == "service" && args[1] == "inspect" {
		service := args[len(args)-1]
		f.serviceInspectCounts[service]++
		if f.onServiceInspect != nil {
			f.onServiceInspect(service, f.serviceInspectCounts[service])
		}
		if err := f.serviceErrors[service]; err != nil {
			return "", err
		}
		image, ok := f.liveImages[service]
		if !ok {
			return "", fmt.Errorf("Error: no such service: %s", service)
		}
		return image, nil
	}
	// `image inspect <config id>` without --format is the registry identity
	// proof (RepoDigests); the base fake models it.
	if len(args) == 3 && args[0] == "image" && args[1] == "inspect" {
		return f.base.Read(ctx, args...)
	}
	if len(args) >= 3 && args[0] == "image" && args[1] == "inspect" {
		image := args[len(args)-1]
		if err := f.imageErrors[image]; err != nil {
			return "", err
		}
		environment, ok := f.imageEnvs[image]
		if !ok {
			return "", fmt.Errorf("Error: No such image: %s", image)
		}
		body, err := json.Marshal(environment)
		return string(body), err
	}
	return f.base.Read(ctx, args...)
}

func (f *recoveryInfraDocker) Run(ctx context.Context, args ...string) error {
	for _, arg := range args {
		if strings.Contains(strings.ToLower(arg), "pull") {
			f.t.Fatalf("unexpected pull command in dockerRun: %v", args)
			return errors.New("unreachable")
		}
	}
	f.runCalls = append(f.runCalls, append([]string(nil), args...))
	if err := f.base.Run(ctx, args...); err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "stack" && f.afterStackDeploy != nil {
		for index := range args {
			if args[index] == "-c" && index+1 < len(args) {
				return f.afterStackDeploy(args[index+1])
			}
		}
	}
	return nil
}

func newRecoveryInfraDocker(t *testing.T, declared map[string]string, live map[string]string, versions map[string]string) *recoveryInfraDocker {
	t.Helper()
	base := &fakeRecoveryDocker{registry: healthyRegistryJSON(""), tasks: map[string]string{}, inspect: map[string]string{}}
	fake := &recoveryInfraDocker{
		t:                    t,
		base:                 base,
		liveImages:           copyStringMap(live),
		serviceErrors:        map[string]error{},
		imageEnvs:            map[string][]string{},
		imageErrors:          map[string]error{},
		serviceInspectCounts: map[string]int{},
	}
	var roster strings.Builder
	for _, service := range []string{"web", "redis", "rabbitmq"} {
		if _, present := declared[service]; !present {
			continue
		}
		liveImage := live["demo_"+service]
		if liveImage == "" {
			continue
		}
		roster.WriteString("demo_" + service + "\treplicated\t1/1\n")
		taskID := "task_" + service
		containerID := "ctr_" + service
		base.tasks["demo_"+service] = taskID + "\tRunning\tRunning 3 seconds ago\t" + recoveryServiceTaskImage(liveImage) + "\t\n"
		base.inspect[taskID] = `{"Status":{"ContainerStatus":{"ContainerID":"` + containerID + `"}}}`
		base.inspect[containerID] = `{"State":{"Running":true,"Status":"running","Health":{"Status":"healthy"}},"Config":{"Image":"` + liveImage + `"},"Image":"` + liveImage + `"}`
	}
	base.roster = roster.String()
	for image, version := range versions {
		lookup := recoveryInfrastructureInspectReference(image)
		service := "redis"
		if strings.HasPrefix(image, "rabbitmq:") {
			service = "rabbitmq"
		}
		versionEnv := infrastructureRuntimeFor(service).versionEnv
		fake.imageEnvs[lookup] = []string{versionEnv + "=" + version}
	}
	fake.afterStackDeploy = func(stackFile string) error {
		body, err := os.ReadFile(stackFile)
		if err != nil {
			return err
		}
		services, err := rootStackServices("demo", body)
		if err != nil {
			return err
		}
		var nextRoster strings.Builder
		base.tasks = map[string]string{}
		base.inspect = map[string]string{}
		for _, service := range services {
			nextRoster.WriteString(service.Service + "\treplicated\t1/1\n")
			taskID := "task_" + service.Name
			containerID := "ctr_" + service.Name
			base.tasks[service.Service] = taskID + "\tRunning\tRunning 3 seconds ago\t" + recoveryServiceTaskImage(service.Image) + "\t\n"
			base.inspect[taskID] = `{"Status":{"ContainerStatus":{"ContainerID":"` + containerID + `"}}}`
			base.inspect[containerID] = `{"State":{"Running":true,"Status":"running","Health":{"Status":"healthy"}},"Config":{"Image":"` + service.Image + `"},"Image":"` + service.Image + `"}`
		}
		base.roster = nextRoster.String()
		return nil
	}
	return fake
}

func recoveryServiceTaskImage(image string) string {
	repository := rootImageRepository(image)
	if rootImageHasTag(repository) {
		return repository
	}
	return image
}

func testRecoveryInfrastructureManifest(images map[string]string) string {
	var body strings.Builder
	body.WriteString("services:\n")
	for _, service := range []string{"web", "redis", "rabbitmq"} {
		image, present := images[service]
		if !present {
			continue
		}
		body.WriteString("  " + service + ":\n    image: " + image + "\n    read_only: true\n    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL\n    healthcheck:\n      test: [CMD, true]\n    deploy:\n      replicas: 1\n      resources:\n        limits:\n          cpus: \"0.5\"\n          memory: 256M\n")
	}
	return body.String()
}

func keptRedisFormattingFixture() string {
	return "# retained release with operator comments\nservices:\n    redis:  # intentionally unusual indentation\n      image: '" + testRedisRetained + "' # keep this comment\n      read_only: true\n      security_opt:\n        - no-new-privileges:true\n      cap_drop:\n        - ALL\n      healthcheck:\n        test: [CMD, true]\n      deploy:\n        replicas: 1\n        resources:\n          limits:\n            cpus: \"0.5\"\n            memory: 256M\n"
}

func routedRecoveryInfrastructureManifest(images map[string]string) string {
	return testRecoveryInfrastructureManifest(images) + "      labels:\n        dev.shuttle.domain: demo.example\n        dev.shuttle.port: \"8080\"\n"
}

func bindTestRecoveryCaddyRoute(rt *rootRecoveryRuntime, loaded *string) {
	rt.loadedRoute = func(string) (string, error) { return *loaded, nil }
	rt.applyCaddy = func(app string, payload []byte, _ time.Duration) error {
		want, err := caddyRouteFragment(app, payload)
		if err != nil {
			return err
		}
		*loaded = want
		return nil
	}
	rt.verifyCaddy = func(app string, payload []byte) error {
		want, err := caddyRouteFragment(app, payload)
		if err != nil {
			return err
		}
		if !loadedRouteMatches(*loaded, want) {
			return errors.New("test Caddy route did not converge")
		}
		return nil
	}
}

func recoveryInfraFixture(t *testing.T, kind string, manifest string, liveImages map[string]string, versions map[string]string) (*rootRecoveryRuntime, *recoveryInfraDocker, operationwriters.Baseline, string) {
	t.Helper()
	inhibitInfrastructurePull(t)
	declared := map[string]string{}
	if services, err := rootStackServices("demo", []byte(manifest)); err == nil {
		for _, service := range services {
			declared[service.Name] = "declared"
		}
	}
	docker := newRecoveryInfraDocker(t, declared, liveImages, versions)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	rt := newTestRecoveryRuntimeAt(t, docker.base, &now)
	rt.dockerRead = docker.Read
	rt.dockerRun = docker.Run
	digest := writeAppManifest(t, rt, "demo", "current.yml", manifest)
	baseline := operationwriters.Baseline{
		Current:                   operationwriters.BaselineArtifact{Present: true, FullSHA256: digest},
		ConfiguredNativePGVersion: postgresNotConfigured,
		ConfiguredNativePGCluster: postgresNotConfigured,
	}
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), baseline))
	return rt, docker, baseline, digest
}

func inhibitInfrastructurePull(t *testing.T) {
	t.Helper()
	original := infrastructureImageVersion
	infrastructureImageVersion = func(image, versionEnv string) (string, error) {
		t.Fatalf("recovery called pull-based infrastructureImageVersion for %s (%s)", image, versionEnv)
		return "", errors.New("unreachable")
	}
	t.Cleanup(func() { infrastructureImageVersion = original })
}

func recoveryActionKindPresent(actions []recoveryAction, kind recoveryActionKind) bool {
	for _, action := range actions {
		if action.Kind == kind {
			return true
		}
	}
	return false
}

func recoveryDisplayContains(actions []string, text string) bool {
	for _, action := range actions {
		if strings.Contains(action, text) {
			return true
		}
	}
	return false
}

func TestRecoveryWriterReaderMissingFailsClosed(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || observation.ExecutorProof != "" || observation.ExecutorCount != 0 {
		t.Fatalf("missing B hook must not invent a closed executor: %+v", observation)
	}
	found := false
	for _, item := range observation.Unresolved {
		if strings.Contains(item, "rootRecoveryWriterReader") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing B hook did not name the wiring contract: %v", observation.Unresolved)
	}
}

func TestRecoveryWriterReaderBoundToCoordinatedRootWriterState(t *testing.T) {
	if rootRecoveryWriterReader == nil {
		t.Fatal("rootRecoveryWriterReader must remain bound to readCoordinatedRootWriterState")
	}
	want := readCoordinatedRootWriterState
	if fmt.Sprintf("%p", rootRecoveryWriterReader) != fmt.Sprintf("%p", want) {
		t.Fatal("rootRecoveryWriterReader is not bound to readCoordinatedRootWriterState")
	}
}

func TestRecoveryWrongBindingFailsClosed(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	binding := testRecoveryBinding()
	binding.OperationID = "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b11"
	state := closedWriterState(t, binding, testRecoveryBaseline("", false, ""))
	attachClosedReader(rt, state)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || observation.ExecutorProof != "" {
		t.Fatalf("wrong binding must not yield a closed proof: %+v", observation)
	}
}

func TestRecoveryFirstReleaseWithoutPrevious(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	state := closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, ""))
	attachClosedReader(rt, state)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.CurrentDigest != current || observation.PreviousDigest != "" {
		t.Fatalf("first release digests = %q / %q", observation.CurrentDigest, observation.PreviousDigest)
	}
	if observation.ExecutorProof == "" || observation.ExecutorCount != 0 {
		t.Fatalf("valid closed proof was not bound: %+v", observation)
	}
	for _, item := range observation.Unresolved {
		if strings.Contains(item, "previous") {
			t.Fatalf("first release treated missing previous as an error: %v", observation.Unresolved)
		}
	}
}

func TestRecoveryFirstReleaseRefusedAfterSecretsPhaseIsReleased(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	for _, name := range []string{"writers-initialize", "secrets-host"} {
		request.Name = name
		if err := c.ExecutePhase(context.Background(), request, func(context.Context, coord.Record) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.NeedsRecovery("stack preflight refused after secrets preparation"); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(plan.Observed.Actions) != 0 || plan.Observed.ServiceState != serviceStateFirstReleaseNoServices {
		t.Fatalf("empty first-release baseline was not safe without host actions: %+v", plan.Observed)
	}
	if !recoveryFirstRelease(testRecoveryRecord("deploy", "demo"), testRecoveryBaseline("", false, "")) {
		t.Fatal("closed empty deploy baseline was not recognized as a first release")
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	recovered, err := c.Get(context.Background(), h.ID())
	if err != nil || recovered.State != "recovered" || recovered.RecoveryRequired {
		t.Fatalf("first-release refusal was not released: %+v %v", recovered, err)
	}
	if len(docker.runs) != 0 {
		t.Fatalf("empty first-release recovery mutated the host: %v", docker.runs)
	}
}

func TestRecoveryFirstReleaseWithServicesButNoManifestStaysUnresolved(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON(""), stackServices: "service-id\n"}
	rt := newTestRecoveryRuntime(t, docker)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || !recoveryUnresolvedContains(observation, "first-release services exist without a retained manifest") {
		t.Fatalf("services without a manifest were not refused: %+v", observation)
	}
}

func TestRecoveryFirstReleaseThatNeverConvergedIsRemovedNotReplayed(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker := &fakeRecoveryDocker{
		registry:      healthyRegistryJSON(""),
		roster:        "demo_web\treplicated\t0/1\n",
		stackServices: "service-id\n",
		networks:      "network-id\n",
		secrets:       []string{"demo_owned_secret"},
		volumes:       []string{"demo_data"},
		tasks:         map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tfailed\n"},
	}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryRoutedManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	rt.loadedRoute = func(string) (string, error) { return "demo.example {\n  reverse_proxy demo_web:8080\n}\n", nil }
	routePath := filepath.Join(rt.caddyDir, "50-demo.caddy")
	if err := os.WriteFile(routePath, []byte("demo.example {\n  reverse_proxy demo_web:8080\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadCalls := 0
	rt.reloadEdge = func() error { reloadCalls++; return nil }
	syncCalls := 0
	rt.syncDir = func(path string) error {
		if path == filepath.Dir(filepath.Join(rt.appStateRoot, "demo", "current.yml")) {
			syncCalls++
		}
		return nil
	}
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	journalFirstReleaseConvergence(t, c, request, current, coord.FirstReleaseConvergenceFailed)
	if err := h.NeedsRecovery("first release tasks failed to converge"); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("unconverged first release did not plan a single removal: %+v, actions=%+v", plan.Observed, rt.planned)
	}
	action := rt.planned[0]
	if action.App != "demo" || action.ManifestPath != filepath.Join(rt.appStateRoot, "demo", "current.yml") || action.ManifestSHA256 != current {
		t.Fatalf("removal action is not bound to the current release: %+v", action)
	}
	if !recoveryDisplayContains(plan.Observed.Actions, "remove unconverged first-release services") || !recoveryDisplayContains(plan.Observed.Actions, "keep volumes, secrets and databases") {
		t.Fatalf("removal plan does not explain its data boundary: %v", plan.Observed.Actions)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	recovered, err := c.Get(context.Background(), h.ID())
	if err != nil || recovered.State != "recovered" || recovered.RecoveryRequired {
		t.Fatalf("removed first release did not release its record: %+v %v", recovered, err)
	}
	for _, call := range docker.runs {
		if call == "stack rm demo" {
			t.Fatalf("first-release recovery used stack rm, which deletes stack-owned secrets: %v", docker.runs)
		}
		if strings.Contains(call, "volume rm") || strings.Contains(call, "secret rm") {
			t.Fatalf("first-release recovery deleted retained data: %v", docker.runs)
		}
		if strings.HasPrefix(call, "stack deploy") {
			t.Fatalf("first-release recovery replayed the failed release: %v", docker.runs)
		}
	}
	if !reflect.DeepEqual(docker.runs, []string{"service rm service-id", "network rm network-id"}) {
		t.Fatalf("first-release removal did not remove only the stack services and networks: %v", docker.runs)
	}
	if !reflect.DeepEqual(docker.removedServices, []string{"service-id"}) || !reflect.DeepEqual(docker.removedNetworks, []string{"network-id"}) {
		t.Fatalf("fake Docker did not record each explicit removal: services=%v networks=%v", docker.removedServices, docker.removedNetworks)
	}
	if !reflect.DeepEqual(docker.secrets, []string{"demo_owned_secret"}) || !reflect.DeepEqual(docker.volumes, []string{"demo_data"}) {
		t.Fatalf("first-release recovery changed stack-owned retained data: secrets=%v volumes=%v", docker.secrets, docker.volumes)
	}
	if reloadCalls != 1 || syncCalls != 1 {
		t.Fatalf("route reload/current directory sync counts = %d/%d, want 1/1", reloadCalls, syncCalls)
	}
	for _, path := range []string{filepath.Join(rt.appStateRoot, "demo", "current.yml"), routePath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("first-release artifact %s remains, lstat error=%v", path, err)
		}
	}
	if !recoveryFirstRelease(recovered, testRecoveryBaseline("", false, "")) {
		t.Fatal("removed release no longer has the empty baseline for its next deploy")
	}
}

func TestRecoveryFirstReleasePendingAfterDockerRejectionIsRemoved(t *testing.T) {
	recoverPendingFirstRelease(t, false)
}

func TestRecoveryFirstReleasePendingAfterHelperInterruptionIsRemoved(t *testing.T) {
	recoverPendingFirstRelease(t, true)
}

func recoverPendingFirstRelease(t *testing.T, interruptHelper bool) {
	t.Helper()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker := &fakeRecoveryDocker{
		registry:      healthyRegistryJSON(""),
		roster:        "demo_web\treplicated\t0/1\n",
		stackServices: "service-id\n",
		networks:      "network-id\n",
		secrets:       []string{"demo_owned_secret"},
		volumes:       []string{"demo_data"},
		tasks:         map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tfailed\n"},
	}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	phaseErr := c.ExecutePhase(context.Background(), request, func(ctx context.Context, _ coord.Record) error {
		if err := coord.JournalCurrentManifest(ctx, current); err != nil {
			return err
		}
		if err := coord.JournalFirstReleaseConvergence(ctx, coord.FirstReleaseConvergencePending); err != nil {
			return err
		}
		if interruptHelper {
			return c.MarkWatchdogRecoveryForPhase(request, "helper interrupted after pending convergence journal")
		}
		return errors.New("docker stack deploy rejected the first release")
	})
	if phaseErr == nil {
		t.Fatal("simulated first-release failure unexpectedly completed the phase")
	}
	if !interruptHelper {
		if err := h.NeedsRecovery("docker stack deploy rejected the first release"); err != nil {
			t.Fatal(err)
		}
	}
	journal, err := c.Get(context.Background(), h.ID())
	if err != nil || journal.FirstReleaseConvergenceState != coord.FirstReleaseConvergencePending ||
		journal.FirstReleaseConvergenceManifestSHA256 != current {
		t.Fatalf("pending first-release marker was not durable and bound: record=%+v err=%v", journal, err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("pending first release did not plan removal: observation=%+v actions=%+v", plan.Observed, rt.planned)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	for _, call := range docker.runs {
		if strings.HasPrefix(call, "stack deploy") || call == "stack rm demo" || strings.Contains(call, "volume rm") || strings.Contains(call, "secret rm") {
			t.Fatalf("pending first-release recovery replayed the stack or removed retained data: %v", docker.runs)
		}
	}
	if !reflect.DeepEqual(docker.runs, []string{"service rm service-id", "network rm network-id"}) {
		t.Fatalf("pending first-release recovery removed unexpected objects: %v", docker.runs)
	}
	if !reflect.DeepEqual(docker.secrets, []string{"demo_owned_secret"}) || !reflect.DeepEqual(docker.volumes, []string{"demo_data"}) {
		t.Fatalf("pending first-release recovery changed retained data: secrets=%v volumes=%v", docker.secrets, docker.volumes)
	}
}

func TestRecoveryFirstReleaseUnreadableRemovalJournalIsRefused(t *testing.T) {
	docker := &fakeRecoveryDocker{
		registry:      healthyRegistryJSON(""),
		roster:        "demo_web\treplicated\t0/1\n",
		stackServices: "service-id\n",
	}
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	record := testRecoveryRecord("deploy", "demo")
	record.CurrentManifestSHA256 = current
	record.FirstReleaseConvergenceState = coord.FirstReleaseConvergencePending
	record.FirstReleaseConvergenceManifestSHA256 = current
	journalPath, err := rt.firstReleaseRemovalJournalPath(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	observation, err := rt.observe(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || !recoveryUnresolvedContains(observation, "first-release removal journal is unavailable") ||
		recoveryActionKindPresent(rt.planned, recoveryActionRemoveFirstRelease) {
		t.Fatalf("unreadable removal journal did not block recovery: %+v", observation)
	}
	if len(docker.runs) != 0 {
		t.Fatalf("unreadable removal journal allowed Docker mutations: %v", docker.runs)
	}
}

func TestRecoveryFirstReleaseUnreadableOperationJournalIsRefused(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	journalRoot := t.TempDir()
	c := coord.New(coord.Options{
		Root: journalRoot, LockPath: filepath.Join(journalRoot, "root.lock"), LockWait: time.Second, Lease: time.Hour,
		Now: func() time.Time { return now.UTC() }, BootID: func() (string, error) { return testRecoveryBootID, nil },
	})
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	if err := c.ExecutePhase(context.Background(), request, func(ctx context.Context, _ coord.Record) error {
		if err := coord.JournalCurrentManifest(ctx, current); err != nil {
			return err
		}
		return coord.JournalFirstReleaseConvergence(ctx, coord.FirstReleaseConvergencePending)
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("helper stopped after journaling pending convergence"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(journalRoot, h.ID()+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := `"first_release_convergence_state": "pending"`
	if !strings.Contains(string(body), marker) {
		t.Fatalf("operation journal does not contain the expected pending marker: %s", body)
	}
	body = []byte(strings.Replace(string(body), marker, `"first_release_convergence_state": "unknown"`, 1))
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe); err == nil || !strings.Contains(err.Error(), "invalid operation journal record") {
		t.Fatalf("unreadable operation journal did not refuse recovery: %v", err)
	}
	if len(docker.runs) != 0 {
		t.Fatalf("unreadable operation journal allowed Docker mutations: %v", docker.runs)
	}
}

func TestRecoveryFirstReleaseThatConvergedThenDegradedIsReapplied(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker := &fakeRecoveryDocker{
		registry:      healthyRegistryJSON(""),
		roster:        "demo_web\treplicated\t0/1\n",
		stackServices: "service-id\n",
		tasks:         map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tfailed\n"},
	}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	journalFirstReleaseConvergence(t, c, request, current, coord.FirstReleaseConvergenceSucceeded)
	if err := h.NeedsRecovery("Caddy reload failed after stack convergence"); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionReapplyCurrent {
		t.Fatalf("degraded converged first release did not use normal reapply recovery: observation=%+v actions=%+v", plan.Observed, rt.planned)
	}
	if recoveryActionKindPresent(rt.planned, recoveryActionRemoveFirstRelease) {
		t.Fatalf("recovery planned destructive first-release removal after convergence: %+v", rt.planned)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.FirstReleaseConvergenceState != coord.FirstReleaseConvergenceSucceeded ||
		record.FirstReleaseConvergenceManifestSHA256 != current {
		t.Fatalf("successful convergence proof was not durable in the operation journal: %+v %v", record, err)
	}
	unmarked := record
	unmarked.FirstReleaseConvergenceState = ""
	unmarked.FirstReleaseConvergenceManifestSHA256 = ""
	observation, err := rt.observe(context.Background(), unmarked)
	if err != nil || !observation.Safe || recoveryActionKindPresent(rt.planned, recoveryActionRemoveFirstRelease) ||
		!recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) {
		t.Fatalf("missing convergence proof authorized removal instead of reapply: observation=%+v actions=%+v err=%v", observation, rt.planned, err)
	}
}

func TestRecoveryFirstReleaseInternalApplicationDoesNotTouchCaddy(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker := &fakeRecoveryDocker{
		registry:      healthyRegistryJSON(""),
		roster:        "demo_web\treplicated\t0/1\n",
		stackServices: "service-id\n",
		tasks:         map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tfailed\n"},
	}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	reloadCalls := 0
	rt.reloadEdge = func() error {
		reloadCalls++
		return errors.New("shared Caddy is unavailable")
	}
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	journalFirstReleaseConvergence(t, c, request, current, coord.FirstReleaseConvergenceFailed)
	if err := h.NeedsRecovery("internal first release did not converge"); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !plan.Observed.Safe || len(rt.planned) != 1 {
		t.Fatalf("internal first release was not safely planned: plan=%+v actions=%+v err=%v", plan, rt.planned, err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply); err != nil {
		t.Fatalf("internal first release depended on Caddy: %v", err)
	}
	if reloadCalls != 0 {
		t.Fatalf("internal app without a route reloaded Caddy %d times", reloadCalls)
	}
	if _, err := os.Stat(filepath.Join(rt.appStateRoot, "demo", "current.yml")); !os.IsNotExist(err) {
		t.Fatalf("internal first-release manifest remains, stat error=%v", err)
	}
	recovered, err := c.Get(context.Background(), h.ID())
	if err != nil || recovered.State != "recovered" || recovered.RecoveryRequired {
		t.Fatalf("internal first release stayed recovery_required: %+v %v", recovered, err)
	}
}

func TestRecoveryFirstReleaseDirectorySyncFailureIsRetriedAfterRestart(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker := &fakeRecoveryDocker{
		registry:      healthyRegistryJSON(""),
		roster:        "demo_web\treplicated\t0/1\n",
		stackServices: "service-id\n",
		tasks:         map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tfailed\n"},
	}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	journalFirstReleaseConvergence(t, c, request, current, coord.FirstReleaseConvergenceFailed)
	if err := h.NeedsRecovery("internal first release did not converge"); err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("persistent current.yml directory sync failure")
	syncCalls := 0
	rt.syncDir = func(path string) error {
		syncCalls++
		if path != filepath.Dir(filepath.Join(rt.appStateRoot, "demo", "current.yml")) {
			t.Fatalf("synced unexpected directory %q", path)
		}
		return syncFailure
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("initial removal plan is invalid: plan=%+v actions=%+v err=%v", plan, rt.planned, err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply); err == nil || !strings.Contains(err.Error(), syncFailure.Error()) {
		t.Fatalf("directory sync failure did not block recovery: %v", err)
	}
	currentPath := filepath.Join(rt.appStateRoot, "demo", "current.yml")
	if _, err := os.Stat(currentPath); !os.IsNotExist(err) {
		t.Fatalf("current.yml was not unlinked before the sync failure: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != coord.RecoveryRequired {
		t.Fatalf("sync failure released recovery: %+v %v", record, err)
	}
	journalPath, err := rt.firstReleaseRemovalJournalPath(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journalPath); err != nil {
		t.Fatalf("durable removal journal is missing after unlink: %v", err)
	}
	retryPlan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !retryPlan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("persistent sync failure did not retain a retry action: plan=%+v actions=%+v err=%v", retryPlan, rt.planned, err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), retryPlan.PlanDigest, rt.observe, rt.apply); err == nil || !strings.Contains(err.Error(), syncFailure.Error()) {
		t.Fatalf("persistent directory sync failure released recovery: %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("directory sync attempts before restart = %d, want two", syncCalls)
	}
	record, err = c.Get(context.Background(), h.ID())
	if err != nil || record.State != coord.RecoveryRequired {
		t.Fatalf("persistent sync failure released recovery: %+v %v", record, err)
	}

	restarted := *rt
	restarted.planned = nil
	restarted.completed = nil
	restarted.remaining = nil
	restartSyncCalls := 0
	restarted.syncDir = func(path string) error {
		restartSyncCalls++
		if path != filepath.Dir(currentPath) {
			t.Fatalf("restart synced unexpected directory %q", path)
		}
		return nil
	}
	restartPlan, err := c.RecoveryPlan(context.Background(), h.ID(), restarted.observe)
	if err != nil || !restartPlan.Observed.Safe || len(restarted.planned) != 1 || restarted.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("restart did not recover the pending sync action: plan=%+v actions=%+v err=%v", restartPlan, restarted.planned, err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), restartPlan.PlanDigest, restarted.observe, restarted.apply); err != nil {
		t.Fatalf("restart could not sync the unlinked current.yml directory: %v", err)
	}
	if restartSyncCalls != 1 {
		t.Fatalf("restart directory sync calls = %d, want one", restartSyncCalls)
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("completed removal journal remains, stat error=%v", err)
	}
	record, err = c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("recovery was not released after the directory sync: %+v %v", record, err)
	}
}

func TestRecoveryFirstReleaseCaddyDirectorySyncFailureIsRetried(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker := &fakeRecoveryDocker{
		registry:      healthyRegistryJSON(""),
		roster:        "demo_web\treplicated\t0/1\n",
		stackServices: "service-id\n",
		tasks:         map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tfailed\n"},
	}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryRoutedManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	routePath := filepath.Join(rt.caddyDir, "50-demo.caddy")
	routeBody := "demo.example {\n  reverse_proxy demo_web:8080\n}\n"
	if err := os.WriteFile(routePath, []byte(routeBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rt.loadedRoute = func(string) (string, error) { return routeBody, nil }
	reloadCalls := 0
	rt.reloadEdge = func() error { reloadCalls++; return nil }
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	journalFirstReleaseConvergence(t, c, request, current, coord.FirstReleaseConvergenceFailed)
	if err := h.NeedsRecovery("first release tasks failed to converge"); err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("Caddy configuration directory sync failed")
	routeSyncCalls := 0
	currentSyncCalls := 0
	rt.syncDir = func(path string) error {
		switch path {
		case rt.caddyDir:
			routeSyncCalls++
			if routeSyncCalls == 1 {
				return syncFailure
			}
		case filepath.Dir(filepath.Join(rt.appStateRoot, "demo", "current.yml")):
			currentSyncCalls++
		default:
			t.Fatalf("synced unexpected directory %q", path)
		}
		return nil
	}
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("initial first-release removal plan is invalid: plan=%+v actions=%+v err=%v", plan, rt.planned, err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), plan.PlanDigest, rt.observe, rt.apply); err == nil || !strings.Contains(err.Error(), syncFailure.Error()) {
		t.Fatalf("Caddy directory sync failure did not block recovery: %v", err)
	}
	if reloadCalls != 0 || routeSyncCalls != 1 || currentSyncCalls != 0 {
		t.Fatalf("failed route sync did not stop before reload/current removal: route syncs=%d reloads=%d current syncs=%d", routeSyncCalls, reloadCalls, currentSyncCalls)
	}
	if _, err := os.Stat(routePath); !os.IsNotExist(err) {
		t.Fatalf("route was not unlinked before the sync failure: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != coord.RecoveryRequired {
		t.Fatalf("Caddy sync failure released recovery: %+v %v", record, err)
	}
	removalJournal, err := rt.readFirstReleaseRemovalJournal(record)
	if err != nil || removalJournal == nil || !removalJournal.RouteReloadPending || removalJournal.CurrentDirectorySyncPending {
		t.Fatalf("failed Caddy sync did not preserve route retry evidence: journal=%+v err=%v", removalJournal, err)
	}

	retryPlan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !retryPlan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("Caddy sync retry plan is invalid: plan=%+v actions=%+v err=%v", retryPlan, rt.planned, err)
	}
	if _, err := c.ApplyRecoveryWith(context.Background(), h.ID(), retryPlan.PlanDigest, rt.observe, rt.apply); err != nil {
		t.Fatalf("route directory sync retry did not complete recovery: %v", err)
	}
	if routeSyncCalls != 2 || reloadCalls != 1 || currentSyncCalls != 1 {
		t.Fatalf("sync/reload counts after retry = route %d, reload %d, current %d", routeSyncCalls, reloadCalls, currentSyncCalls)
	}
	if _, err := os.Stat(filepath.Join(rt.appStateRoot, "demo", "current.yml")); !os.IsNotExist(err) {
		t.Fatalf("current.yml remains after successful route sync retry: %v", err)
	}
	recovered, err := c.Get(context.Background(), h.ID())
	if err != nil || recovered.State != "recovered" || recovered.RecoveryRequired {
		t.Fatalf("recovery was not released after route directory sync: %+v %v", recovered, err)
	}
}

func TestRecoveryFirstReleaseThatConvergedIsKept(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryRoutedManifest(1))
	rt.loadedRoute = func(string) (string, error) { return "demo.example {\n  reverse_proxy demo_web:8080\n}\n", nil }
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	record := testRecoveryRecord("deploy", "demo")
	record.CurrentManifestSHA256 = current
	observation, err := rt.observe(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || observation.ServiceState != serviceStateMatch || recoveryActionKindPresent(rt.planned, recoveryActionRemoveFirstRelease) {
		t.Fatalf("converged first release was not kept: %+v actions=%+v", observation, rt.planned)
	}
}

func TestRecoveryFirstReleaseRemovalRefusesAChangedCurrent(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker.roster = "demo_web\treplicated\t0/1\n"
	docker.tasks = map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tfailed\n"}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryRoutedManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	record := testRecoveryRecord("deploy", "demo")
	record.CurrentManifestSHA256 = current
	record.FirstReleaseConvergenceState = coord.FirstReleaseConvergenceFailed
	record.FirstReleaseConvergenceManifestSHA256 = current
	observation, err := rt.observe(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRemoveFirstRelease {
		t.Fatalf("first-release removal action missing from dry run: %+v actions=%+v", observation, rt.planned)
	}
	unmarked := record
	unmarked.FirstReleaseConvergenceState = ""
	unmarked.FirstReleaseConvergenceManifestSHA256 = ""
	if err := rt.executeRemoveFirstRelease(context.Background(), unmarked, rt.planned[0]); err == nil ||
		!strings.Contains(err.Error(), "does not prove first-release non-convergence") {
		t.Fatalf("destructive executor accepted missing convergence proof: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"), []byte(testRecoveryRoutedManifest(1)+"# changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = rt.executeRemoveFirstRelease(context.Background(), record, rt.planned[0])
	if err == nil || !strings.Contains(err.Error(), "current manifest changed") {
		t.Fatalf("changed current manifest was not refused: %v", err)
	}
	if len(docker.runs) != 0 {
		t.Fatalf("changed current manifest caused host mutations: %v", docker.runs)
	}
}

func TestRecoveryFirstReleaseIgnoresAnUnknownCurrent(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || !recoveryUnresolvedContains(observation, "unknown retained current artifact is not authorized") || recoveryActionKindPresent(rt.planned, recoveryActionRemoveFirstRelease) {
		t.Fatalf("unknown current artifact was authorized for removal: %+v actions=%+v", observation, rt.planned)
	}
}

func TestRecoveryReapplyDoesNotForceUnconvergedServices(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	record := testRecoveryRecord("deploy", "demo")
	record.CurrentManifestSHA256 = current
	var order []string
	rt.dockerRun = func(_ context.Context, args ...string) error {
		call := strings.Join(args, " ")
		docker.runs = append(docker.runs, call)
		order = append(order, call)
		return nil
	}
	waitFailure := errors.New("service did not converge")
	rt.waitStack = func(string, string, time.Time, time.Duration) error {
		order = append(order, "waitStack")
		return waitFailure
	}
	action := recoveryAction{Kind: recoveryActionReapplyCurrent, App: "demo", ManifestPath: filepath.Join(rt.appStateRoot, "demo", "current.yml"), ManifestSHA256: current}
	if err := rt.executeReapplyCurrent(context.Background(), record, action); !errors.Is(err, waitFailure) {
		t.Fatalf("reapply did not preserve the existing convergence failure: %v", err)
	}
	if len(docker.runs) != 1 || !strings.HasPrefix(docker.runs[0], "stack deploy ") {
		t.Fatalf("reapply issued an unrelated service update: %v", docker.runs)
	}
	if len(order) != 2 || order[0] != docker.runs[0] || order[1] != "waitStack" {
		t.Fatalf("reapply order changed: %v", order)
	}
}

func TestRecoveryManifestChangedAfterDryRun(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	state := closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, ""))
	attachClosedReader(rt, state)
	first, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1)+"    environment:\n      CHANGED: \"1\"\n")
	second, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestProof == second.ManifestProof || first.ResourceVersion == second.ResourceVersion {
		t.Fatal("changed manifest kept the confirmed dry-run identity")
	}
}

func TestRecoverySameMapLengthChangedReplicasInvalidatesConfirmation(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	record := testRecoveryRecord("backup", "demo")
	writeMarker(t, rt, record, map[string]int{"demo_web": 1, "demo_worker": 2}, "")
	_, first, err := rt.readPendingBackupMarker(record)
	if err != nil {
		t.Fatal(err)
	}
	writeMarker(t, rt, record, map[string]int{"demo_web": 2, "demo_worker": 1}, "")
	_, second, err := rt.readPendingBackupMarker(record)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first == second {
		t.Fatalf("changed replica counts kept marker proof %q", first)
	}
}

func TestRecoveryDesiredRunningActualFailed(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker.roster = "demo_web\treplicated\t1/1\n"
	docker.tasks = map[string]string{"demo_web": "taskweb1\tRunning\tFailed 3 seconds ago\t" + image + "\tboom\n"}
	docker.inspect = map[string]string{"taskweb1": `{"Status":{"ContainerStatus":{"ContainerID":"ctrweb1"}}}`}
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.ServiceState == serviceStateMatch {
		t.Fatal("desired running / actual failed was treated as converged")
	}
}

func TestRecoveryUnhealthyContainer(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker.roster = "demo_web\treplicated\t1/1\n"
	docker.tasks = map[string]string{"demo_web": "taskweb1\tRunning\tRunning 3 seconds ago\t" + image + "\t\n"}
	docker.inspect = map[string]string{
		"taskweb1": `{"Status":{"ContainerStatus":{"ContainerID":"ctrweb1"}}}`,
		"ctrweb1":  `{"State":{"Running":true,"Status":"running","Health":{"Status":"unhealthy"}},"Config":{"Image":"` + image + `"},"Image":"` + testWebDigest + `"}`,
	}
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.ServiceState == serviceStateMatch {
		t.Fatal("unhealthy container was treated as converged")
	}
}

func TestRecoveryRouteFailure(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	rt.verifyCaddy = func(string, []byte) error { return errors.New("caddy route was not applied") }
	action := recoveryAction{Kind: recoveryActionApplyCaddyRoute, App: "demo", ManifestPath: filepath.Join(rt.appStateRoot, "demo", "current.yml"), ManifestSHA256: current}
	if err := rt.executeAction(context.Background(), testRecoveryRecord("deploy", "demo"), action); err == nil {
		t.Fatal("route failure was ignored")
	}
}

func TestRecoveryPostgreSQLNotConfigured(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	if err := os.RemoveAll(rt.postgresRoot); err != nil {
		t.Fatal(err)
	}
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.DataState != dataStateMissing || observation.Safe {
		t.Fatalf("missing native cluster was not fail-closed: %+v", observation)
	}
}

func TestRecoveryPostgreSQLSeveralClusters(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	if err := os.MkdirAll(filepath.Join(rt.postgresRoot, "18", "preprod"), 0o755); err != nil {
		t.Fatal(err)
	}
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	baseline := testRecoveryBaseline(current, false, "")
	baseline.ConfiguredNativePGVersion = "18,18"
	baseline.ConfiguredNativePGCluster = "main,preprod"
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), baseline))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.DataState != dataStateMatch {
		t.Fatalf("two present clusters were not recognized: %+v", observation)
	}
	if err := os.RemoveAll(filepath.Join(rt.postgresRoot, "18", "preprod")); err != nil {
		t.Fatal(err)
	}
	observation, err = rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.DataState != dataStateMissing || observation.Safe {
		t.Fatalf("one missing cluster out of two was not fail-closed: %+v", observation)
	}
}

func TestRecoveryPublicAdditionalRegistryBinding(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: publicRegistryJSON()}
	rt := newTestRecoveryRuntime(t, docker)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("registry-gc", ""))
	if err != nil {
		t.Fatal(err)
	}
	if observation.RegistryState != registryStateUnsafe || observation.Safe {
		t.Fatalf("public registry binding was accepted: %+v", observation)
	}
}

func TestRegistryBindingRejectsPublicAdditional(t *testing.T) {
	err := validateLoopbackRegistryBindings(map[string][]recoveryPortBinding{
		"5000/tcp": {{HostIP: "127.0.0.1", HostPort: "5000"}},
		"80/tcp":   {{HostIP: "0.0.0.0", HostPort: "80"}},
	})
	if err == nil {
		t.Fatal("additional public binding was accepted")
	}
}

func TestRecoveryRemovalFsyncFailure(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	record := testRecoveryRecord("backup", "demo")
	writeMarker(t, rt, record, map[string]int{"demo_web": 1}, filepath.Join(rt.backupStaging, "demo-work"))
	if err := os.MkdirAll(filepath.Join(rt.backupStaging, "demo-work"), 0o755); err != nil {
		t.Fatal(err)
	}
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	rt.syncDir = func(string) error { return errors.New("fsync parent failed") }
	marker, path, err := rt.loadPendingBackupMarker(record)
	if err != nil || marker == nil {
		t.Fatalf("marker: %v", err)
	}
	action := recoveryAction{Kind: recoveryActionRestoreBackupReplicas, App: "demo", MarkerPath: path, MarkerProof: canonicalMarkerProof(*marker, path), Replicas: copyReplicaMap(marker.Replicas)}
	if err := rt.executeAction(context.Background(), record, action); err == nil || !strings.Contains(err.Error(), "fsync") {
		t.Fatalf("fsync failure = %v", err)
	}
	if _, err := os.Stat(filepath.Join(rt.backupStaging, "demo-work")); err != nil {
		t.Fatalf("staging data was removed after fsync failure: %v", err)
	}
}

func TestRecoveryPartialJSONBody(t *testing.T) {
	body, err := marshalRecoveryApplyReport(coord.RecoveryPlan{
		ID: testRecoveryOpID, State: coord.RecoveryRequired, Actions: []string{"start the existing loopback registry and verify health", "apply the retained Caddy route and verify the route"},
		PlanDigest: "sha256:" + strings.Repeat("b", 64),
	}, []string{"start the existing loopback registry and verify health"}, []string{"apply the retained Caddy route and verify the route"}, errors.New("caddy route was not applied"))
	if body == nil || err == nil {
		t.Fatal("failed apply must return a JSON body and an error")
	}
	var report recoveryApplyReport
	if decodeErr := json.Unmarshal(body, &report); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if report.Schema != rootRecoveryApplySchema || report.Error == "" || len(report.CompletedSteps) != 1 || len(report.RemainingRecovery) != 1 {
		t.Fatalf("partial report = %+v", report)
	}
}

func TestRecoveryConfirmationStableUnderHealthLogTimestampChange(t *testing.T) {
	firstDocker := &fakeRecoveryDocker{registry: healthyRegistryJSON("2026-09-13T15:00:00Z")}
	attachHealthyWeb(firstDocker)
	rt := newTestRecoveryRuntime(t, firstDocker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	first, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	secondDocker := &fakeRecoveryDocker{version: firstDocker.version, registry: healthyRegistryJSON("2026-09-13T15:04:11Z")}
	attachHealthyWeb(secondDocker)
	rt.dockerRead = secondDocker.Read
	second, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ResourceVersion == "" || first.ResourceVersion != second.ResourceVersion || first.ActionProof != second.ActionProof {
		t.Fatalf("health log timestamp changed confirmation %q vs %q", first.ResourceVersion, second.ResourceVersion)
	}
}

func TestRecoveryUnsupportedRebootKind(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("reboot", ""))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || len(observation.Actions) != 0 {
		t.Fatalf("reboot was treated as this reconciler's work: %+v", observation)
	}
	found := false
	for _, item := range observation.Unresolved {
		if strings.Contains(item, "operations reboot --resume") {
			found = true
		}
	}
	if !found {
		t.Fatalf("reboot refusal did not name the resume command: %v", observation.Unresolved)
	}
}

func TestRecoveryApplyUsesTypedActionsNotSentences(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation := coord.RecoveryObservation{
		Actions:     []string{"start the existing loopback registry and verify health"},
		ActionProof: "not-a-canonical-action-proof",
	}
	if err := rt.apply(context.Background(), testRecoveryRecord("deploy", "demo"), observation); err == nil {
		t.Fatal("sentence matching was used to select an action")
	}
	for _, run := range docker.runs {
		if strings.Contains(run, "start "+rootRegistryContainer) {
			t.Fatalf("registry start ran from a display sentence: %v", docker.runs)
		}
	}
}

func TestRecoveryExecutorCountZeroOnlyOnValidProof(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	missing, err := rt.observe(context.Background(), testRecoveryRecord("registry-gc", ""))
	if err != nil {
		t.Fatal(err)
	}
	if missing.ExecutorProof != "" {
		t.Fatal("missing closure still produced an executor proof")
	}
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt = newTestRecoveryRuntime(t, docker)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	valid, err := rt.observe(context.Background(), testRecoveryRecord("registry-gc", ""))
	if err != nil {
		t.Fatal(err)
	}
	if valid.ExecutorProof == "" || valid.ExecutorCount != 0 {
		t.Fatalf("valid closure was not bound as executor proof: %+v", valid)
	}
	if _, hashErr := (operationwriters.State{}).ClosedProofHash(); hashErr == nil {
		t.Fatal("empty state unexpectedly hashed")
	}
}

func TestPendingBackupMarkerRefusesUnknownJSON(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	record := testRecoveryRecord("backup", "demo")
	path := rt.pendingBackupMarkerPath("demo")
	body := `{"app":"demo","operation_id":"` + record.ID + `","replicas":{"demo_web":1},"work":"","unknown":true}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rt.loadPendingBackupMarker(record); err == nil {
		t.Fatal("unknown marker field was accepted")
	}
}

func TestPendingBackupMarkerRefusesTrailingJSON(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	record := testRecoveryRecord("backup", "demo")
	path := rt.pendingBackupMarkerPath("demo")
	body := `{"app":"demo","operation_id":"` + record.ID + `","replicas":{"demo_web":1},"work":""}` + "\n{}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rt.loadPendingBackupMarker(record); err == nil {
		t.Fatal("trailing marker JSON was accepted")
	}
}

func TestRecoveryStoppedRegistryRestartIsTyped(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: stoppedRegistryJSON()}
	rt := newTestRecoveryRuntime(t, docker)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("registry-gc", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRestartRegistry {
		t.Fatalf("stopped registry did not produce a typed restart: %+v", rt.planned)
	}
	if len(observation.Actions) != 1 || strings.Contains(strings.ToLower(observation.Actions[0]), "garbage") {
		t.Fatalf("registry-gc implied garbage collection: %v", observation.Actions)
	}
}

func writeMarker(t *testing.T, rt *rootRecoveryRuntime, record coord.Record, replicas map[string]int, work string) {
	t.Helper()
	marker := pendingBackupMarker{App: record.App, OperationID: record.ID, Replicas: replicas, Work: work}
	body, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rt.pendingBackupMarkerPath(record.App), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryPostgreSQLExplicitlyNotConfigured(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	baseline := testRecoveryBaseline(current, false, "")
	baseline.ConfiguredNativePGVersion = postgresNotConfigured
	baseline.ConfiguredNativePGCluster = postgresNotConfigured
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), baseline))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.DataState != dataStateNotApplicable || !observation.Safe {
		t.Fatalf("explicit not-configured postgres was not N/A: %+v", observation)
	}
}

func TestRecoveryReplicaMapZeroKeyReplacement(t *testing.T) {
	left := map[string]int{"demo_web": 1, "demo_worker": 0}
	right := map[string]int{"demo_web": 1, "demo_other": 0}
	if replicaMapsEqual(left, right) {
		t.Fatal("zero-value key replacement compared equal")
	}
}

func TestRecoveryTaskAgeDoesNotChangeResourceVersion(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	first, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	image := "127.0.0.1:5000/demo-web@" + testWebDigest
	docker.tasks["demo_web"] = "taskweb1\tRunning\tRunning 9 seconds ago\t" + image + "\t\n"
	second, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ResourceVersion == "" || first.ResourceVersion != second.ResourceVersion {
		t.Fatalf("task age changed resource version %q vs %q", first.ResourceVersion, second.ResourceVersion)
	}
}

func TestRecoveryRotationSelectsAuthorizedHashAndRefusesUnknown(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntime(t, docker)
	c0 := writeAppManifest(t, rt, "demo", "previous.yml", testRecoveryManifest(1))
	c1 := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1)+"    environment:\n      C1: \"1\"\n")
	p0 := "sha256:" + strings.Repeat("f", 64)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(c0, true, p0)))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.CurrentDigest != c1 || observation.PreviousDigest != c0 {
		t.Fatalf("slot digests = %q / %q", observation.CurrentDigest, observation.PreviousDigest)
	}
	found := false
	for _, item := range observation.Unresolved {
		if item == absentBaselineArtifact {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing P0 was not reported as B persistence requirement: %v", observation.Unresolved)
	}
	if observation.Safe {
		t.Fatal("missing P0 bytes were treated as a complete baseline")
	}
	if len(rt.planned) == 0 || rt.planned[0].ManifestSHA256 != c0 || rt.planned[0].ManifestPath != filepath.Join(rt.appStateRoot, "demo", "previous.yml") {
		t.Fatalf("authorized C0 was not selected across rotation: %+v", rt.planned)
	}
	for _, action := range rt.planned {
		if action.ManifestSHA256 == c1 {
			t.Fatal("unknown C1 was authorized")
		}
	}
}

func TestRecoveryAnchoredReadRefusesSymlink(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntime(t, docker)
	dir := filepath.Join(rt.appStateRoot, "demo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.yml")
	if err := os.WriteFile(target, []byte(testRecoveryManifest(1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "current.yml")); err != nil {
		t.Fatal(err)
	}
	current := rootRecoveryDigest([]byte(testRecoveryManifest(1)))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe {
		t.Fatal("symlink manifest was treated as an anchored regular file")
	}
}

func TestRecoveryMalformedExpiryJSON(t *testing.T) {
	body, err := recoveryRootApply(context.Background(), testRecoveryOpID, "sha256:"+strings.Repeat("d", 64), rootplan.Plan{ExpiresAt: "not-a-timestamp"})
	if body == nil || err == nil {
		t.Fatal("invalid expiry must return JSON and an error")
	}
	var report recoveryApplyReport
	if decodeErr := json.Unmarshal(body, &report); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if report.Schema != rootRecoveryApplySchema || report.ID != testRecoveryOpID || report.Error == "" {
		t.Fatalf("invalid expiry report = %+v", report)
	}
}

func TestRecoveryCoordinatorRejectsWriterProofDisappearingBeforeEffects(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: stoppedRegistryJSON()}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	state := closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, ""))
	calls := 0
	rt.reader = func(context.Context, coord.Record) (operationwriters.State, error) {
		calls++
		if calls >= 3 {
			return operationwriters.State{}, errors.New("writer closed proof disappeared")
		}
		return state, nil
	}
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "registry-gc", "")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRestartRegistry {
		t.Fatalf("stopped registry plan = %+v planned=%+v", plan.Observed, rt.planned)
	}
	_, err = c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply)
	if err == nil {
		t.Fatal("apply ran after closed writer proof disappeared")
	}
	for _, run := range docker.runs {
		if strings.HasPrefix(run, "start ") {
			t.Fatalf("registry start ran after missing writer proof: %v", docker.runs)
		}
	}
}

func TestRecoveryCoordinatorRestoresCapturedBackupReplicas(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON(""), roster: "demo_web\treplicated\t0/0\n"}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(2))
	record := testRecoveryRecord("backup", "demo")
	writeMarker(t, rt, record, map[string]int{"demo_web": 1}, "")
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "backup", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || !plan.Observed.PendingBackup || plan.Observed.OriginalReplicas != 1 {
		t.Fatalf("scaled-zero backup was not repairable: %+v", plan.Observed)
	}
	if len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRestoreBackupReplicas || rt.planned[0].Replicas["demo_web"] != 1 {
		t.Fatalf("captured replica action = %+v", rt.planned)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	foundScale := false
	for _, run := range docker.runs {
		if run == "service scale demo_web=1" {
			foundScale = true
		}
	}
	if !foundScale {
		t.Fatalf("captured replica scale was not applied: %v", docker.runs)
	}
	if _, err := os.Stat(rt.pendingBackupMarkerPath("demo")); !os.IsNotExist(err) {
		t.Fatalf("pending marker remained after restore: %v", err)
	}
	durable, err := rt.readBackupReplicas(h.ID())
	if err != nil || durable["demo_web"] != 1 {
		t.Fatalf("durable replica proof missing after marker delete: %v %#v", err, durable)
	}
}

func TestRecoveryCoordinatorRepairsRouteIndependentlyOfTasks(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryRoutedManifest(1))
	loaded := "stale-loaded-config"
	rt.loadedRoute = func(string) (string, error) { return loaded, nil }
	rt.verifyCaddy = rt.verifyRetainedCaddyRoute
	rt.applyCaddy = func(string, []byte, time.Duration) error {
		loaded = "demo.example {\n  reverse_proxy demo_web:8080\n}\n"
		return nil
	}
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Observed.ServiceState != serviceStateMatch {
		t.Fatalf("healthy tasks were not independent of the route: %+v", plan.Observed)
	}
	if len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionApplyCaddyRoute {
		t.Fatalf("route mismatch did not plan an independent caddy action: %+v", rt.planned)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
}

func archiveBaselineBytes(t *testing.T, rt *rootRecoveryRuntime, currentBody, previousBody []byte) {
	t.Helper()
	source := t.TempDir()
	appDir := filepath.Join(source, "demo")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	currentHash, previousHash := "", ""
	if currentBody != nil {
		if err := os.WriteFile(filepath.Join(appDir, "current.yml"), currentBody, 0o600); err != nil {
			t.Fatal(err)
		}
		currentHash = rootRecoveryDigest(currentBody)
	}
	if previousBody != nil {
		if err := os.WriteFile(filepath.Join(appDir, "previous.yml"), previousBody, 0o600); err != nil {
			t.Fatal(err)
		}
		previousHash = rootRecoveryDigest(previousBody)
	}
	baseline := testRecoveryBaseline(currentHash, previousBody != nil, previousHash)
	if err := preserveRootOperationBaselineArtifactsAt(rt.archiveRoot, source, testRecoveryOpID, "demo", baseline); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryUsesArchivedBaselineAfterSlotRotation(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntime(t, docker)
	c0Body := []byte(testRecoveryManifest(1))
	p0Body := []byte(testRecoveryManifest(1) + "    environment:\n      P0: \"1\"\n")
	c1Body := []byte(testRecoveryManifest(1) + "    environment:\n      C1: \"1\"\n")
	c0 := rootRecoveryDigest(c0Body)
	p0 := rootRecoveryDigest(p0Body)
	c1 := writeAppManifest(t, rt, "demo", "current.yml", string(c1Body))
	writeAppManifest(t, rt, "demo", "previous.yml", string(c0Body))
	archiveBaselineBytes(t, rt, c0Body, p0Body)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(c0, true, p0)))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.CurrentDigest != c1 || observation.PreviousDigest != c0 {
		t.Fatalf("slot digests = %q / %q", observation.CurrentDigest, observation.PreviousDigest)
	}
	for _, item := range observation.Unresolved {
		if item == absentBaselineArtifact {
			t.Fatalf("archived P0 was ignored: %v", observation.Unresolved)
		}
	}
	unknown := false
	for _, item := range observation.Unresolved {
		if item == "unknown retained current artifact is not authorized" {
			unknown = true
		}
	}
	if !unknown {
		t.Fatalf("unknown C1 was accepted: %v", observation.Unresolved)
	}
	if len(rt.planned) == 0 || rt.planned[0].ManifestSHA256 != c0 {
		t.Fatalf("archived/slot C0 was not selected: %+v", rt.planned)
	}
}

func TestLoadedRouteMatchesRequiresReverseProxyTarget(t *testing.T) {
	want := "demo.example {\n  reverse_proxy demo_web:8080\n}\n"
	if loadedRouteMatches("demo.example {\n  reverse_proxy other_web:8080\n}\n", want) {
		t.Fatal("host substring accepted the wrong upstream")
	}
	if !loadedRouteMatches("demo.example {\n  reverse_proxy demo_web:8080\n}\n", want) {
		t.Fatal("matching reverse_proxy target was refused")
	}
}

func TestProductionLoadedRouteUsesTheCaddyfileValidator(t *testing.T) {
	var calls [][]string
	rt := &rootRecoveryRuntime{dockerRead: func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) > 0 && args[0] == "ps" {
			return "caddy-container\n", nil
		}
		return "demo.example {\n  reverse_proxy demo_web:8080\n}\n", nil
	}}
	got, err := rt.productionLoadedRoute("demo")
	if err != nil {
		t.Fatal(err)
	}
	if got == "" || len(calls) != 2 {
		t.Fatalf("unexpected route probe calls: got=%q calls=%v", got, calls)
	}
	want := []string{"exec", "caddy-container", "sh", "-ec", "caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null && cat /etc/caddy/Caddyfile /etc/caddy/conf.d/*.caddy"}
	if strings.Join(calls[1], "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("route probe used %v, want %v", calls[1], want)
	}
}

func TestRecoveryFIFOManifestIsNotARegularFile(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	rt := newTestRecoveryRuntime(t, docker)
	dir := filepath.Join(rt.appStateRoot, "demo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "current.yml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	current := rootRecoveryDigest([]byte(testRecoveryManifest(1)))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	done := make(chan struct{})
	go func() {
		defer close(done)
		observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
		if err != nil {
			t.Error(err)
			return
		}
		if observation.Safe {
			t.Error("FIFO manifest was treated as a bounded regular file")
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO manifest blocked the anchored read")
	}
}

func TestRecoveryRestoresFromDurableReplicaProofAfterMarkerDelete(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON(""), roster: "demo_web\treplicated\t0/0\n"}
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(2))
	record := testRecoveryRecord("backup", "demo")
	if err := rt.preserveBackupReplicas(record.ID, "demo", map[string]int{"demo_web": 1}); err != nil {
		t.Fatal(err)
	}
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation, err := rt.observe(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if observation.OriginalReplicas != 1 {
		t.Fatalf("durable replica proof was not observed: %+v", observation)
	}
	if len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRestoreBackupReplicas || rt.planned[0].Replicas["demo_web"] != 1 {
		t.Fatalf("missing marker dropped durable replica restore: %+v", rt.planned)
	}
}

func testHelperUpdateRecord() coord.Record {
	record := testRecoveryRecord("helper-update", "")
	record.RecoveryRequired = true
	record.Phases = []coord.Phase{{
		Name:      "helper-update",
		StartedAt: "2026-09-13T15:00:00.000000000Z",
		EndedAt:   "2026-09-13T15:00:01.000000000Z",
		Result:    "helper-update failed before replacement",
	}}
	return record
}

func attachAbsentWriterReader(rt *rootRecoveryRuntime) {
	rt.reader = func(context.Context, coord.Record) (operationwriters.State, error) {
		return operationwriters.State{}, operationwriters.ErrNotFound
	}
}

func unclosedWriterState(t *testing.T, binding operationwriters.Binding, baseline operationwriters.Baseline) operationwriters.State {
	t.Helper()
	now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := operationwriters.OpenStore(operationwriters.StoreOptions{Root: root, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.InitializeLocked(binding, baseline)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

const testRecoveryHelperDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func writeRecoveryHelperFile(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRecoveryHelperIntent(t *testing.T, rt *rootRecoveryRuntime, phase string) {
	t.Helper()
	writeRecoveryHelperFile(t, rt.helperMigrationIntent, helperMigrationIntent{
		Schema: helperMigrationSchema, ID: "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b99",
		Source: "/usr/local/libexec/shuttle-root#" + testRecoveryHelperDigest, CandidateSHA256: testRecoveryHelperDigest,
		Host: testRecoveryHost, BootID: testRecoveryBootID, Phase: phase,
	})
}

func writeRecoveryOwnReservation(t *testing.T, rt *rootRecoveryRuntime, operationID string) {
	t.Helper()
	writeRecoveryHelperFile(t, helperMigrationOwnReservationPath(helperMigrationPaths{IntentPath: rt.helperMigrationIntent}), helperMigrationOwnReservationProof{
		Schema: helperMigrationOwnReservationSchema, OperationID: operationID, OperationKind: "helper-update",
		OwnerKeyFingerprint: testRecoveryHost, HostFingerprint: testRecoveryHost, BootID: testRecoveryBootID, CandidateSHA256: testRecoveryHelperDigest,
	})
}

func recoveryUnresolvedContains(observation coord.RecoveryObservation, needle string) bool {
	for _, item := range observation.Unresolved {
		if strings.Contains(item, needle) {
			return true
		}
	}
	return false
}

func TestRecoveryFailedHelperUpdateWithoutWriterIsRecoverable(t *testing.T) {
	// A signed helper-update can fail in phase helper-update before
	// replaceRootHelper. That leaves a global recovery_required reservation,
	// no writer file, an unchanged helper, and either no intent or a leftover
	// completed intent from another operation. Journal recovery must unblock
	// later deploys without mutating the helper.
	for _, name := range []string{"absent-intent", "completed-intent-other-operation"} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
			docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
			rt := newTestRecoveryRuntimeAt(t, docker, &now)
			attachAbsentWriterReader(rt)
			if name == "completed-intent-other-operation" {
				writeRecoveryHelperIntent(t, rt, helperMigrationPhaseComplete)
				writeRecoveryOwnReservation(t, rt, "018f3a7e-8e3b-4a8c-9a2d-4f2d1c7e9b11")
			}
			record := testHelperUpdateRecord()
			observation, err := rt.observe(context.Background(), record)
			if err != nil {
				t.Fatal(err)
			}
			if !observation.Safe || observation.ExecutorProof == "" || observation.ExecutorCount != 0 {
				t.Fatalf("failed helper-update before replacement was not recoverable: %+v", observation)
			}
			if observation.DataState != dataStateNotApplicable {
				t.Fatalf("helper-update postgres was treated as configured: %+v", observation)
			}
			if len(rt.planned) != 0 || len(observation.Actions) != 0 {
				t.Fatalf("helper-update planned a host mutation: planned=%+v actions=%v", rt.planned, observation.Actions)
			}
			c := newRecoveryCoordinator(t, &now)
			h := reserveRecovery(t, c, "helper-update", "")
			plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
			if err != nil {
				t.Fatal(err)
			}
			if !plan.Observed.Safe || plan.Observed.ExecutorProof == "" {
				t.Fatalf("helper-update dry-run was unsafe: %+v", plan.Observed)
			}
			if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
				t.Fatal(err)
			}
			if len(docker.runs) != 0 {
				t.Fatalf("helper-update recovery mutated the host: %v", docker.runs)
			}
			got, err := c.Get(context.Background(), h.ID())
			if err != nil {
				t.Fatal(err)
			}
			if got.State != "recovered" || got.RecoveryRequired {
				t.Fatalf("helper-update journal was not recovered: %+v", got)
			}
		})
	}
}

func TestRecoveryHelperUpdateRefusesPendingIntent(t *testing.T) {
	// Prepared intent means probing started; replacement may or may not follow. Journal recovery of the
	// reservation would drop the global fence while the helper is mid-migration.
	for _, phase := range []string{helperMigrationPhaseReady, helperMigrationPhaseReplaced} {
		t.Run(phase, func(t *testing.T) {
			rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
			attachAbsentWriterReader(rt)
			writeRecoveryHelperIntent(t, rt, phase)
			observation, err := rt.observe(context.Background(), testHelperUpdateRecord())
			if err != nil {
				t.Fatal(err)
			}
			if observation.Safe || !recoveryUnresolvedContains(observation, "still pending") {
				t.Fatalf("pending helper-update intent was recovered: %+v", observation)
			}
			if len(rt.planned) != 0 {
				t.Fatalf("pending helper-update planned a host mutation: %+v", rt.planned)
			}
		})
	}
}

func TestRecoveryHelperUpdateRefusesOwnReservationForThisOperation(t *testing.T) {
	// The parent writes the own-reservation proof before probing and renaming
	// the new helper; a failed probe may clear it only without an intent. A proof naming this operation means the swap may have
	// happened, so "failed before replacement" is not proven.
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	attachAbsentWriterReader(rt)
	writeRecoveryOwnReservation(t, rt, testRecoveryOpID)
	observation, err := rt.observe(context.Background(), testHelperUpdateRecord())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || !recoveryUnresolvedContains(observation, "replacement is not excluded") {
		t.Fatalf("admitted helper-update candidate was recovered: %+v", observation)
	}
}

func TestRecoveryHelperUpdateRefusesUnclosedWriterState(t *testing.T) {
	// A present writer file means this is not the no-state failure. Open
	// admissions are still validated as today and must not be skipped.
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	attachClosedReader(rt, unclosedWriterState(t, testRecoveryBinding(), testRecoveryBaseline("", false, "")))
	observation, err := rt.observe(context.Background(), testHelperUpdateRecord())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || observation.ExecutorProof != "" {
		t.Fatalf("unclosed helper-update writer was treated as closed proof: %+v", observation)
	}
	if !recoveryUnresolvedContains(observation, "closed writer admissions are not proven closed") {
		t.Fatalf("unclosed helper-update writer did not fail closed: %v", observation.Unresolved)
	}
}

func TestRecoveryHelperUpdateRefusesActiveRecord(t *testing.T) {
	// A live helper-update lease still owns the global fence. Recovery must
	// not clear it from an observe of an active record.
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	attachAbsentWriterReader(rt)
	record := testHelperUpdateRecord()
	record.State = "active"
	record.RecoveryRequired = false
	record.LeaseUntil = "2026-09-13T16:00:00.000000000Z"
	observation, err := rt.observe(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Safe || observation.ExecutorProof != "" {
		t.Fatalf("active helper-update was recovered: %+v", observation)
	}
	if !recoveryUnresolvedContains(observation, "still recorded as active") {
		t.Fatalf("active helper-update did not fail closed: %v", observation.Unresolved)
	}
}

const testRecoveryOwner = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func reserveLiveDeploy(t *testing.T, c *coord.Coordinator, id string) (*coord.Handle, coord.PhaseRequest) {
	t.Helper()
	h, err := c.Reserve(context.Background(), coord.Request{ID: id, Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: testRecoveryOwner, Host: testRecoveryHost})
	if err != nil {
		t.Fatal(err)
	}
	return h, coord.PhaseRequest{ID: h.ID(), Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: testRecoveryOwner, Host: testRecoveryHost, Name: "stack-apply", Concurrent: true}
}

func journalFirstReleaseConvergence(t *testing.T, c *coord.Coordinator, request coord.PhaseRequest, digest, state string) {
	t.Helper()
	err := c.ExecutePhase(context.Background(), request, func(ctx context.Context, _ coord.Record) error {
		if err := coord.JournalCurrentManifest(ctx, digest); err != nil {
			return err
		}
		if err := coord.JournalFirstReleaseConvergence(ctx, coord.FirstReleaseConvergencePending); err != nil {
			return err
		}
		if state == coord.FirstReleaseConvergencePending {
			return nil
		}
		return coord.JournalFirstReleaseConvergence(ctx, state)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPromotionSweepFailureDefersWithoutBlockingTheNextDeploy(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	shared := func(fn func() error) error { return fn() }
	reset := errors.New("Delete http://127.0.0.1:5000/v2/demo-web/manifests/sha256:2de8: read tcp 127.0.0.1:37150->127.0.0.1:5000: read: connection reset by peer")

	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	err := c.ExecutePhase(context.Background(), request, func(context.Context, coord.Record) error {
		return sweepAfterRootPromotion("demo", shared, func() error { return reset }, func() error { return nil })
	})
	if err != nil {
		t.Fatalf("a failed manifest delete after promotion failed the phase: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "active" || !strings.Contains(record.Phases[0].Warning, "connection reset by peer") {
		t.Fatalf("deferred sweep was not recorded as a warning on an active record: %+v %v", record, err)
	}
	if err := h.Complete("all requested changes verified"); err != nil {
		t.Fatal(err)
	}
	next, err := c.Reserve(context.Background(), coord.Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: testRecoveryOwner, Host: testRecoveryHost})
	if err != nil {
		t.Fatalf("next deploy of the same application was refused: %v", err)
	}
	_ = next.NeedsRecovery("test cleanup")

	// A registry the collector may have left stopped is not a known state.
	c2 := newRecoveryCoordinator(t, &now)
	down, request := reserveLiveDeploy(t, c2, "")
	err = c2.ExecutePhase(context.Background(), request, func(context.Context, coord.Record) error {
		return sweepAfterRootPromotion("demo", shared, func() error {
			return &rootRegistryLeftDownError{err: errors.New("docker start shuttle-registry: exit status 1")}
		}, func() error { return nil })
	})
	if err == nil {
		t.Fatal("a registry left stopped completed the phase")
	}
	if record, _ := c2.Get(context.Background(), down.ID()); record.State != coord.RecoveryRequired {
		t.Fatalf("registry left stopped: state = %s, want %s", record.State, coord.RecoveryRequired)
	}
}

func TestPreDeployReclaimFailureDefersWithoutBlockingTheNextDeploy(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	shared := func(fn func() error) error { return fn() }

	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	request.Name = "stack-reclaim"
	err := c.ExecutePhase(context.Background(), request, func(context.Context, coord.Record) error {
		return reclaimImageStoreBeforeDeploy("demo", shared, func() error {
			return errors.New("remove image demo-web:old: conflict: image is being used by a stopped container")
		})
	})
	if err != nil {
		t.Fatalf("a failed pre-deploy reclaim failed the phase: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "active" || !strings.Contains(record.Phases[0].Warning, "being used") {
		t.Fatalf("deferred reclaim was not recorded as a warning on an active record: %+v %v", record, err)
	}
	if err := h.Complete("all requested changes verified"); err != nil {
		t.Fatal(err)
	}
	next, err := c.Reserve(context.Background(), coord.Request{Kind: "deploy", App: "demo", Principal: "operator", OwnerKeyFingerprint: testRecoveryOwner, Host: testRecoveryHost})
	if err != nil {
		t.Fatalf("next deploy of the same application was refused: %v", err)
	}
	_ = next.NeedsRecovery("test cleanup")
}

// journaledStackApply reproduces 2026-10-08 on web: stack-apply wrote
// and journaled current.yml, then the operation never reached a terminal
// state. journaled is the digest the phase records; "" journals nothing.
func journaledStackApply(t *testing.T, c *coord.Coordinator, journaled string) *coord.Handle {
	t.Helper()
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	if err := c.ExecutePhase(context.Background(), request, func(phase context.Context, _ coord.Record) error {
		if journaled == "" {
			return nil
		}
		return coord.JournalCurrentManifest(phase, journaled)
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.NeedsRecovery("client lost after stack-apply"); err != nil {
		t.Fatal(err)
	}
	return h
}

func ownCurrentRecoveryFixture(t *testing.T, now *time.Time) (*rootRecoveryRuntime, string) {
	t.Helper()
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntimeAt(t, docker, now)
	rt.loadedRoute = func(string) (string, error) { return "demo.example {\n  reverse_proxy demo_web:8080\n}\n", nil }
	// C0 served before the deploy, from another image; C1 is the release this
	// deploy promoted and the one the live task runs.
	c0Body := []byte(strings.ReplaceAll(testRecoveryRoutedManifest(1), testWebDigest, "sha256:"+strings.Repeat("b", 64)))
	p0Body := []byte(string(c0Body) + "    environment:\n      P0: \"1\"\n")
	c1 := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryRoutedManifest(1))
	writeAppManifest(t, rt, "demo", "previous.yml", string(c0Body))
	archiveBaselineBytes(t, rt, c0Body, p0Body)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(rootRecoveryDigest(c0Body), true, rootRecoveryDigest(p0Body))))
	return rt, c1
}

func TestRecoveryAcceptsTheCurrentManifestItsOperationJournaled(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	rt, c1 := ownCurrentRecoveryFixture(t, &now)
	c := newRecoveryCoordinator(t, &now)
	h := journaledStackApply(t, c, c1)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || plan.Observed.ServiceState != serviceStateMatch {
		t.Fatalf("journaled current.yml was not proven against the live tasks: %+v", plan.Observed)
	}
	if len(rt.planned) != 0 {
		t.Fatalf("a healthy promoted release planned repairs (a rollback to C0?): %+v", rt.planned)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	if record, err := c.Get(context.Background(), h.ID()); err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("record after recovery: %+v %v", record, err)
	}
}

func TestRecoveryStillRefusesACurrentManifestTheOperationDidNotJournal(t *testing.T) {
	for name, journaled := range map[string]string{
		"not journaled":  "",
		"another digest": "sha256:" + strings.Repeat("d", 64),
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			rt, c1 := ownCurrentRecoveryFixture(t, &now)
			c := newRecoveryCoordinator(t, &now)
			h := journaledStackApply(t, c, journaled)
			plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Observed.Safe || !recoveryUnresolvedContains(plan.Observed, "unknown retained current artifact is not authorized") {
				t.Fatalf("unjournaled current.yml was accepted: %+v", plan.Observed)
			}
			for _, action := range rt.planned {
				if action.ManifestSHA256 == c1 {
					t.Fatalf("unjournaled C1 was selected: %+v", rt.planned)
				}
			}
			if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err == nil {
				t.Fatal("recovery applied over an unknown current artifact")
			}
		})
	}
}

func TestRecoveryOriginalOwnCurrentStillRequiresBaselineArchive(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	rt, c1 := ownCurrentRecoveryFixture(t, &now)
	c0Body := []byte(strings.ReplaceAll(testRecoveryRoutedManifest(1), testWebDigest, "sha256:"+strings.Repeat("b", 64)))
	p0Body := []byte(string(c0Body) + "    environment:\n      P0: \"1\"\n")
	writeAppManifest(t, rt, "demo", "previous.yml", string(p0Body))
	archiveCurrent := filepath.Join(rt.archiveRoot, rootOperationBaselineDirName, testRecoveryOpID, "current.yml")
	if err := os.Remove(archiveCurrent); err != nil {
		t.Fatal(err)
	}
	c := newRecoveryCoordinator(t, &now)
	h := journaledStackApply(t, c, c1)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Observed.Safe || !recoveryUnresolvedContains(plan.Observed, absentBaselineArtifact) {
		t.Fatalf("original own-current skipped its missing baseline archive: %+v", plan.Observed)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err == nil {
		t.Fatal("recovery proceeded without the authorized baseline archive")
	}
}

// A deploy whose availability probe failed promoted C1, then rolled back to
// C0: current.yml is C0 again and C1, the operation's own journaled manifest,
// now sits in previous.yml (preprod, 2026-10-19).
func TestRecoveryAcceptsItsOwnManifestRotatedIntoPreviousByARollback(t *testing.T) {
	now := time.Date(2026, 10, 19, 17, 0, 0, 0, time.UTC)
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntimeAt(t, docker, &now)
	rt.loadedRoute = func(string) (string, error) { return "demo.example {\n  reverse_proxy demo_web:8080\n}\n", nil }
	c0Body := []byte(testRecoveryRoutedManifest(1))
	p0Body := []byte(string(c0Body) + "    environment:\n      P0: \"1\"\n")
	c1Body := strings.ReplaceAll(testRecoveryRoutedManifest(1), testWebDigest, "sha256:"+strings.Repeat("b", 64))
	writeAppManifest(t, rt, "demo", "current.yml", string(c0Body))
	c1 := writeAppManifest(t, rt, "demo", "previous.yml", c1Body)
	archiveBaselineBytes(t, rt, c0Body, p0Body)
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(rootRecoveryDigest(c0Body), true, rootRecoveryDigest(p0Body))))
	c := newRecoveryCoordinator(t, &now)
	h := journaledStackApply(t, c, c1)
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || plan.Observed.ServiceState != serviceStateMatch {
		t.Fatalf("rolled-back deploy could not be recovered: %+v", plan.Observed)
	}
	for _, action := range rt.planned {
		if action.ManifestSHA256 == c1 {
			t.Fatalf("the rolled-back release was selected again: %+v", rt.planned)
		}
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	if record, err := c.Get(context.Background(), h.ID()); err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("record after recovery: %+v %v", record, err)
	}
}

func TestRecoveryInfraKeptRedisCountsAsWanted(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{
		"demo_web":   "127.0.0.1:5000/demo-web@" + testWebDigest,
		"demo_redis": testRedisLive,
	}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || observation.ServiceState != serviceStateMatch || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRecordKeptInfrastructure {
		t.Fatalf("kept Redis was not treated as the wanted image: observation=%+v actions=%+v", observation, rt.planned)
	}
	_, _, _, _, _, _, _, serviceIdentities, _, _, _, _, _ := rt.observeApplication(context.Background(), testRecoveryRecord("deploy", "demo"), testRecoveryBaseline(observation.CurrentDigest, false, ""), false)
	var redisIdentity *recoveryServiceIdentity
	for index := range serviceIdentities {
		if serviceIdentities[index].Service == "demo_redis" {
			redisIdentity = &serviceIdentities[index]
		}
	}
	if redisIdentity == nil || redisIdentity.WantDigest != rootImageDigest(testRedisLive) || !strings.HasPrefix(redisIdentity.WantDigest, "sha256:") {
		t.Fatalf("kept Redis wanted digest = %+v, want bare %s", redisIdentity, rootImageDigest(testRedisLive))
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraKeptRedisReapplyAndProof(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	oldWeb := "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11", testRedisNewer: "7.4.12"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": oldWeb, "demo_redis": testRedisLive}, versions)
	rt.prepareStack = nil
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || rt.planned[0].Kind != recoveryActionReapplyCurrent {
		t.Fatalf("diverging application task did not retain its reapply action: %+v", rt.planned)
	}
	if len(rt.planned) < 2 || rt.planned[len(rt.planned)-1].Kind != recoveryActionRecordKeptInfrastructure {
		t.Fatalf("kept infrastructure record action was not last: %+v", rt.planned)
	}
	if got := plan.Actions[0]; !strings.Contains(got, "; keep redis 7.4.11 (retained 7.4.5)") || len(got) > coord.MaxReasonBytes {
		t.Fatalf("reapply display = %q", got)
	}
	keptRedis := rt.planned[0].KeepInfrastructureImages["redis"]
	if keptRedis.Live != testRedisLive || keptRedis.Retained != testRedisRetained {
		t.Fatalf("action did not bind both kept references: %+v", rt.planned[0])
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("dry-run called dockerRun: %v", docker.runCalls)
	}
	firstDigest := plan.PlanDigest
	docker.liveImages["demo_redis"] = testRedisNewer
	secondPlan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if secondPlan.PlanDigest == firstDigest {
		t.Fatal("changing the kept image did not change the recovery plan digest")
	}
	docker.liveImages["demo_redis"] = testRedisLive
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), firstDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	var stackPath string
	for _, call := range docker.runCalls {
		if len(call) > 0 && call[0] == "stack" {
			for index := range call {
				if call[index] == "-c" && index+1 < len(call) {
					stackPath = call[index+1]
				}
			}
		}
	}
	if stackPath == "" {
		t.Fatalf("stack deploy was not called: %v", docker.runCalls)
	}
	materialized, err := os.ReadFile(stackPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := strings.Replace(manifest, testRedisRetained, testRedisLive, 1)
	if string(materialized) != expected {
		t.Fatalf("materialized recovery manifest differs beyond the kept Redis image:\n%s\nwant:\n%s", materialized, expected)
	}
	current, err := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
	expectedCurrent, expectedErr := replaceKeptInfrastructureImageSpans([]byte(manifest), map[string]recoveryInfrastructureImageProof{"redis": {Live: testRedisLive, Retained: testRedisRetained}})
	if err != nil || expectedErr != nil || !bytes.Equal(current, expectedCurrent) {
		t.Fatalf("current.yml was not rewritten byte-preservingly: read=%v prepare=%v body=%q", err, expectedErr, current)
	}
	if record, err := c.Get(context.Background(), h.ID()); err != nil || record.RecoveryCurrentManifestSHA256 != rootRecoveryDigest(current) {
		t.Fatalf("recovery manifest binding did not survive: record=%+v err=%v", record, err)
	}
	if record, err := c.Get(context.Background(), h.ID()); err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("reapply recovery did not finish after recording kept images: record=%+v err=%v", record, err)
	}
	if len(docker.runCalls) != 1 || docker.runCalls[0][0] != "stack" {
		t.Fatalf("unexpected recovery mutations: %v", docker.runCalls)
	}
}

func TestRecoveryInfraKeptRedisEndToEndRewritesOnlyCurrentImage(t *testing.T) {
	manifest := keptRedisFormattingFixture()
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, docker, baseline, digest := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	previous := writeAppManifest(t, rt, "demo", "previous.yml", manifest)
	if previous != digest {
		t.Fatalf("identical current and previous manifests have different digests: %s / %s", digest, previous)
	}
	baseline.Previous = operationwriters.BaselineArtifact{Present: true, FullSHA256: previous}
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), baseline))
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || len(plan.Observed.Actions) != 1 || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRecordKeptInfrastructure {
		t.Fatalf("keep-only Redis recovery did not plan just the record action: %+v actions=%+v", plan.Observed, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("dry-run called dockerRun: %v", docker.runCalls)
	}
	currentBefore, err := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
	if err != nil {
		t.Fatal(err)
	}
	previousBefore, err := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "previous.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("record did not recover: %+v %v", record, err)
	}
	post, err := rt.observe(context.Background(), record)
	if err != nil || len(post.Actions) != 0 || !post.Safe {
		t.Fatalf("post-recovery observation still plans work: %+v %v", post, err)
	}
	currentAfter, _ := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
	previousAfter, _ := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "previous.yml"))
	expected, err := replaceKeptInfrastructureImageSpans(currentBefore, map[string]recoveryInfrastructureImageProof{"redis": {Live: testRedisLive, Retained: testRedisRetained}})
	if err != nil || !bytes.Equal(currentAfter, expected) || !bytes.Equal(previousBefore, previousAfter) || bytes.Equal(currentBefore, currentAfter) {
		t.Fatalf("recovery did not rewrite only current.yml's Redis image: prepare=%v", err)
	}
	if record.RecoveryCurrentManifestSHA256 != rootRecoveryDigest(currentAfter) {
		t.Fatalf("recovery current manifest digest = %q, want %q", record.RecoveryCurrentManifestSHA256, rootRecoveryDigest(currentAfter))
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observe-only recovery ran Docker commands: %v", docker.runCalls)
	}
}

func TestReplaceKeptInfrastructureImageSpansPreservesScalarFormsAndUnicodeColumns(t *testing.T) {
	redis := testRedisRetained
	rabbit := testRabbitRetained
	web := "127.0.0.1:5000/demo-web@" + testWebDigest
	manifest := "services:\n" +
		"  redis:\n    image: '" + redis + "' # single quoted\n    read_only: true\n    security_opt: [no-new-privileges:true]\n    cap_drop: [ALL]\n    healthcheck: {test: [CMD, true]}\n    deploy: {replicas: 1, resources: {limits: {cpus: \"0.5\", memory: 256M}}}\n" +
		"  web:\n    image: " + web + " # plain scalar\n    read_only: true\n    security_opt: [no-new-privileges:true]\n    cap_drop: [ALL]\n    healthcheck: {test: [CMD, true]}\n    deploy: {replicas: 1, resources: {limits: {cpus: \"0.5\", memory: 256M}}}\n" +
		"  rabbitmq: {note: \"café\", image: \"" + rabbit + "\", read_only: true, security_opt: [no-new-privileges:true], cap_drop: [ALL], healthcheck: {test: [CMD, true]}, deploy: {replicas: 1, resources: {limits: {cpus: \"0.5\", memory: 256M}}}}\n"
	keep := map[string]recoveryInfrastructureImageProof{
		"redis":    {Live: testRedisLive, Retained: redis},
		"web":      {Live: "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64), Retained: web},
		"rabbitmq": {Live: testRabbitLive, Retained: rabbit},
	}
	got, err := replaceKeptInfrastructureImageSpans([]byte(manifest), keep)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(manifest, redis, testRedisLive, 1)
	want = strings.Replace(want, web, keep["web"].Live, 1)
	want = strings.Replace(want, rabbit, testRabbitLive, 1)
	if string(got) != want {
		t.Fatalf("scalar span replacement changed bytes beyond image values:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestRecoveryInfraJournalBeforeWriteReplaysSameAction(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, oldDigest := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRecordKeptInfrastructure {
		t.Fatalf("initial plan did not contain only the recovery binding: actions=%+v err=%v", rt.planned, err)
	}
	currentPath := filepath.Join(rt.appStateRoot, "demo", "current.yml")
	oldBytes, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := replaceKeptInfrastructureImageSpans(oldBytes, rt.planned[0].KeepInfrastructureImages)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, func(ctx context.Context, _ coord.Record, _ coord.RecoveryObservation) error {
		if err := coord.JournalRecoveryCurrentManifest(ctx, rootRecoveryDigest(prospective)); err != nil {
			return err
		}
		return errors.New("simulated stop after durable journal write")
	}); err == nil {
		t.Fatal("simulated pre-rename stop was not returned")
	}
	current, err := os.ReadFile(currentPath)
	if err != nil || !bytes.Equal(current, oldBytes) || rootRecoveryDigest(current) != oldDigest {
		t.Fatalf("pre-rename crash changed current.yml: digest=%s err=%v", rootRecoveryDigest(current), err)
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State != coord.RecoveryRequired || record.RecoveryCurrentManifestSHA256 != rootRecoveryDigest(prospective) {
		t.Fatalf("journaled prospective digest was lost after failure: record=%+v err=%v", record, err)
	}
	replayed, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !replayed.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRecordKeptInfrastructure {
		t.Fatalf("pre-rename crash did not replay the same action: plan=%+v actions=%+v err=%v", replayed, rt.planned, err)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), replayed.PlanDigest, now.Add(2*time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	current, err = os.ReadFile(currentPath)
	if err != nil || !bytes.Equal(current, prospective) {
		t.Fatalf("replayed rewrite did not converge: err=%v", err)
	}
}

func TestRecoveryInfraPostWriteVerifyFailureKeepsBindingAndNextObservationAccepts(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	observeCount := 0
	postFailure := errors.New("simulated post-action observation failure")
	observer := func(ctx context.Context, record coord.Record) (coord.RecoveryObservation, error) {
		observeCount++
		if observeCount == 2 {
			return coord.RecoveryObservation{}, postFailure
		}
		return rt.observe(ctx, record)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, observer, rt.apply); err == nil || !strings.Contains(err.Error(), postFailure.Error()) {
		t.Fatalf("post-action observation failure was not returned: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	current, readErr := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
	if err != nil || readErr != nil || record.State != coord.RecoveryRequired || record.RecoveryCurrentManifestSHA256 == "" || record.RecoveryCurrentManifestSHA256 != rootRecoveryDigest(current) {
		t.Fatalf("verification failure erased the durable binding or rewrite: record=%+v get=%v read=%v", record, err, readErr)
	}
	next, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !next.Observed.Safe || len(next.Observed.Actions) != 0 || recoveryActionKindPresent(rt.planned, recoveryActionRecordKeptInfrastructure) {
		t.Fatalf("next observation did not accept the rewritten own-current manifest: observation=%+v actions=%+v err=%v", next.Observed, rt.planned, err)
	}
}

func TestRecoveryInfraExistingDifferentRecoveryBindingIsUnresolved(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	record := testRecoveryRecord("deploy", "demo")
	record.RecoveryCurrentManifestSHA256 = "sha256:" + strings.Repeat("f", 64)
	observation, err := rt.observe(context.Background(), record)
	if err != nil || !recoveryUnresolvedContains(observation, "current.yml already rebound by this recovery; recover by hand") || recoveryActionKindPresent(rt.planned, recoveryActionRecordKeptInfrastructure) {
		t.Fatalf("different recovery binding was not refused: observation=%+v actions=%+v err=%v", observation, rt.planned, err)
	}
}

func TestRecoveryInfraBindingMatchingDiskCannotAuthorizeDifferentProspectiveRewrite(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, diskDigest := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	record := testRecoveryRecord("deploy", "demo")
	record.RecoveryCurrentManifestSHA256 = diskDigest
	observation, err := rt.observe(context.Background(), record)
	if err != nil || !recoveryUnresolvedContains(observation, "current.yml recovery binding matches the on-disk bytes") || recoveryActionKindPresent(rt.planned, recoveryActionRecordKeptInfrastructure) {
		t.Fatalf("on-disk binding authorized a different prospective rewrite: observation=%+v actions=%+v err=%v", observation, rt.planned, err)
	}
}

func TestRecoveryInfraChangedDecisionAbortsBeforeCurrentWrite(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11", testRedisNewer: "7.4.12"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(rt.appStateRoot, "demo", "current.yml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	docker.onServiceInspect = func(service string, count int) {
		if service == "demo_redis" && count == 4 {
			docker.liveImages[service] = testRedisNewer
		}
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err == nil || !strings.Contains(err.Error(), "kept infrastructure image references changed before current.yml rewrite") {
		t.Fatalf("changed keep decision did not abort the record action: %v", err)
	}
	after, readErr := os.ReadFile(path)
	record, recordErr := c.Get(context.Background(), h.ID())
	if readErr != nil || recordErr != nil || !bytes.Equal(before, after) || record.RecoveryCurrentManifestSHA256 != "" {
		t.Fatalf("changed keep decision wrote or journaled current.yml: record=%+v read=%v get=%v", record, readErr, recordErr)
	}
}

func TestRecoveryInfraRewriteValidationFailsClosedButArchiveSelectionDoesNotRewrite(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	invalidRoot := strings.Replace(manifest, "    read_only: true\n", "", 1)
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	t.Run("invalid prospective root stack", func(t *testing.T) {
		rt, _, _, digest := recoveryInfraFixture(t, "deploy", invalidRoot, map[string]string{"demo_redis": testRedisLive}, versions)
		observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
		if err != nil || !recoveryUnresolvedContains(observation, "rewritten current.yml is not a valid root stack") || recoveryActionKindPresent(rt.planned, recoveryActionRecordKeptInfrastructure) {
			t.Fatalf("invalid prospective stack was planned: observation=%+v actions=%+v err=%v", observation, rt.planned, err)
		}
		path := filepath.Join(rt.appStateRoot, "demo", "current.yml")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		action := recoveryAction{Kind: recoveryActionRecordKeptInfrastructure, App: "demo", ManifestPath: path, ManifestSHA256: digest, KeepInfrastructureImages: map[string]recoveryInfrastructureImageProof{"redis": {Live: testRedisLive, Retained: testRedisRetained}}}
		if err := rt.executeRecordKeptInfrastructure(context.Background(), testRecoveryRecord("deploy", "demo"), action); err == nil || !strings.Contains(err.Error(), "rewritten current.yml is not a valid root stack") {
			t.Fatalf("executor did not stop on structural validation before journaling: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("structurally invalid rewrite changed current.yml: %v", err)
		}
	})
	t.Run("selected baseline archive", func(t *testing.T) {
		rt, _, baseline, _ := recoveryInfraFixture(t, "deploy", invalidRoot, map[string]string{"demo_redis": testRedisLive}, versions)
		currentPath := filepath.Join(rt.appStateRoot, "demo", "current.yml")
		if err := os.Remove(currentPath); err != nil {
			t.Fatal(err)
		}
		rt.readBaselineArtifact = func(_ string, role string, _ operationwriters.BaselineArtifact) ([]byte, error) {
			if role == "current" {
				return []byte(invalidRoot), nil
			}
			return nil, os.ErrNotExist
		}
		attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), baseline))
		observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
		if err != nil || !observation.Safe || len(observation.Actions) != 0 || len(rt.planned) != 0 {
			t.Fatalf("archive-selected manifest no longer resolves without a rewrite: observation=%+v actions=%+v err=%v", observation, rt.planned, err)
		}
	})
}

func TestRecoveryInfraMultipleKeptImagesUseOneRecordAction(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained, "rabbitmq": testRabbitRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11", testRabbitRetained: "3.13.0", testRabbitLive: "3.13.2"}
	rt, _, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive, "demo_rabbitmq": testRabbitLive}, versions)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRecordKeptInfrastructure || len(rt.planned[0].KeepInfrastructureImages) != 2 {
		t.Fatalf("multiple keeps did not produce one bound action: actions=%+v err=%v", rt.planned, err)
	}
	old, err := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := replaceKeptInfrastructureImageSpans(old, rt.planned[0].KeepInfrastructureImages)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("two kept image spans were not written exactly: err=%v", err)
	}
}

func TestRecoveryInfraCaddyActionPrecedesRecordAction(t *testing.T) {
	t.Run("caddy only", func(t *testing.T) {
		manifest := routedRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
		versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
		rt, _, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
		loaded := "stale route"
		bindTestRecoveryCaddyRoute(rt, &loaded)
		now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
		c := newRecoveryCoordinator(t, &now)
		h := reserveRecovery(t, c, "deploy", "demo")
		plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
		if err != nil || !plan.Observed.Safe || len(rt.planned) != 2 || rt.planned[0].Kind != recoveryActionApplyCaddyRoute || rt.planned[1].Kind != recoveryActionRecordKeptInfrastructure {
			t.Fatalf("Caddy-only repair was not followed by the record action: plan=%+v actions=%+v err=%v", plan, rt.planned, err)
		}
		if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
			t.Fatal(err)
		}
		if record, err := c.Get(context.Background(), h.ID()); err != nil || record.State != "recovered" {
			t.Fatalf("Caddy-only recovery did not resolve: record=%+v err=%v", record, err)
		}
	})
	t.Run("reapply and caddy", func(t *testing.T) {
		oldWeb := "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)
		manifest := routedRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
		versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
		rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": oldWeb, "demo_redis": testRedisLive}, versions)
		loaded := "stale route"
		bindTestRecoveryCaddyRoute(rt, &loaded)
		now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
		c := newRecoveryCoordinator(t, &now)
		h := reserveRecovery(t, c, "deploy", "demo")
		plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
		if err != nil || len(rt.planned) != 3 || rt.planned[0].Kind != recoveryActionReapplyCurrent || rt.planned[1].Kind != recoveryActionApplyCaddyRoute || rt.planned[2].Kind != recoveryActionRecordKeptInfrastructure {
			t.Fatalf("repair actions are not ordered before the record action: actions=%+v err=%v", rt.planned, err)
		}
		if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err != nil {
			t.Fatal(err)
		}
		if record, err := c.Get(context.Background(), h.ID()); err != nil || record.State != "recovered" {
			t.Fatalf("ordered recovery did not resolve: record=%+v err=%v", record, err)
		}
		if len(docker.runCalls) != 1 || docker.runCalls[0][0] != "stack" {
			t.Fatalf("unexpected stack mutations: %v", docker.runCalls)
		}
	})
}

func TestRecoveryInfraDirectorySyncFollowsRenameAndFailureIsReported(t *testing.T) {
	for _, failSync := range []bool{false, true} {
		name := "sync succeeds"
		if failSync {
			name = "sync failure"
		}
		t.Run(name, func(t *testing.T) {
			manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
			versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
			rt, _, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
			now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
			c := newRecoveryCoordinator(t, &now)
			h := reserveRecovery(t, c, "deploy", "demo")
			plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
			if err != nil {
				t.Fatal(err)
			}
			prospective, err := replaceKeptInfrastructureImageSpans(original, rt.planned[0].KeepInfrastructureImages)
			if err != nil {
				t.Fatal(err)
			}
			syncCalls := 0
			syncFailure := errors.New("test directory sync failure")
			syncFails := failSync
			rt.syncDir = func(path string) error {
				syncCalls++
				if path != filepath.Dir(filepath.Join(rt.appStateRoot, "demo", "current.yml")) {
					t.Fatalf("synced directory %q", path)
				}
				published, readErr := os.ReadFile(filepath.Join(rt.appStateRoot, "demo", "current.yml"))
				if readErr != nil || !bytes.Equal(published, prospective) {
					t.Fatalf("directory sync ran before the rename: read=%v", readErr)
				}
				if syncFails {
					return syncFailure
				}
				return nil
			}
			_, applyErr := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply)
			if syncCalls != 1 {
				t.Fatalf("directory sync calls = %d, want one", syncCalls)
			}
			if failSync {
				if applyErr == nil || !strings.Contains(applyErr.Error(), syncFailure.Error()) {
					t.Fatalf("directory sync failure did not fail recovery: %v", applyErr)
				}
				record, err := c.Get(context.Background(), h.ID())
				if err != nil || record.State != coord.RecoveryRequired || record.RecoveryCurrentManifestSHA256 != rootRecoveryDigest(prospective) {
					t.Fatalf("sync failure lost the durable recovery binding: %+v %v", record, err)
				}
				retryPlan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
				if err != nil || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionSyncCurrentDirectory {
					t.Fatalf("retry did not plan the outstanding directory sync: plan=%+v actions=%+v err=%v", retryPlan, rt.planned, err)
				}
				if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), retryPlan.PlanDigest, now.Add(2*time.Minute), "", nil, rt.observe, rt.apply); err == nil || !strings.Contains(err.Error(), syncFailure.Error()) {
					t.Fatalf("persistent directory sync failure did not keep recovery required: %v", err)
				}
				if syncCalls != 2 {
					t.Fatalf("directory sync calls after retry = %d, want two", syncCalls)
				}
				record, err = c.Get(context.Background(), h.ID())
				if err != nil || record.State != coord.RecoveryRequired {
					t.Fatalf("persistent sync failure released recovery: %+v %v", record, err)
				}
				syncFails = false
				finalPlan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
				if err != nil || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionSyncCurrentDirectory {
					t.Fatalf("final retry did not plan the outstanding directory sync: plan=%+v actions=%+v err=%v", finalPlan, rt.planned, err)
				}
				if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), finalPlan.PlanDigest, now.Add(3*time.Minute), "", nil, rt.observe, rt.apply); err != nil {
					t.Fatalf("recovery did not complete after directory sync succeeded: %v", err)
				}
				if syncCalls != 3 {
					t.Fatalf("directory sync calls after success = %d, want three", syncCalls)
				}
				record, err = c.Get(context.Background(), h.ID())
				if err != nil || record.State != "recovered" || record.RecoveryRequired {
					t.Fatalf("successful directory sync did not release recovery: %+v %v", record, err)
				}
			} else if applyErr != nil {
				t.Fatal(applyErr)
			}
		})
	}
}

func TestRecoveryInfraCrashAfterRenameRetriesDirectorySync(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionRecordKeptInfrastructure {
		t.Fatalf("initial plan did not contain the manifest rewrite: actions=%+v err=%v", rt.planned, err)
	}
	currentPath := filepath.Join(rt.appStateRoot, "demo", "current.yml")
	original, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := replaceKeptInfrastructureImageSpans(original, rt.planned[0].KeepInfrastructureImages)
	if err != nil {
		t.Fatal(err)
	}
	crash := errors.New("simulated crash after rename before directory sync")
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, func(ctx context.Context, _ coord.Record, _ coord.RecoveryObservation) error {
		if err := coord.JournalRecoveryCurrentManifest(ctx, rootRecoveryDigest(prospective)); err != nil {
			return err
		}
		if err := writeRootFile(currentPath, prospective, 0o600); err != nil {
			return err
		}
		return crash
	}); err == nil || !strings.Contains(err.Error(), crash.Error()) {
		t.Fatalf("simulated crash boundary was not returned: %v", err)
	}
	record, err := c.Get(context.Background(), h.ID())
	current, readErr := os.ReadFile(currentPath)
	if err != nil || readErr != nil || record.State != coord.RecoveryRequired || record.RecoveryCurrentManifestSHA256 != rootRecoveryDigest(prospective) || !bytes.Equal(current, prospective) {
		t.Fatalf("rename-before-sync state was not preserved: record=%+v get=%v read=%v", record, err, readErr)
	}
	syncCalls := 0
	rt.syncDir = func(path string) error {
		syncCalls++
		if path != filepath.Dir(currentPath) {
			t.Fatalf("synced directory %q", path)
		}
		published, readErr := os.ReadFile(currentPath)
		if readErr != nil || !bytes.Equal(published, prospective) {
			t.Fatalf("directory sync ran before the recovery manifest was on disk: read=%v", readErr)
		}
		return nil
	}
	retryPlan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil || !retryPlan.Observed.Safe || len(rt.planned) != 1 || rt.planned[0].Kind != recoveryActionSyncCurrentDirectory {
		t.Fatalf("post-crash recovery did not plan the directory sync: plan=%+v actions=%+v err=%v", retryPlan, rt.planned, err)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), retryPlan.PlanDigest, now.Add(2*time.Minute), "", nil, rt.observe, rt.apply); err != nil {
		t.Fatalf("post-crash recovery did not sync before completing: %v", err)
	}
	if syncCalls != 1 {
		t.Fatalf("post-crash directory sync calls = %d, want one", syncCalls)
	}
	record, err = c.Get(context.Background(), h.ID())
	if err != nil || record.State != "recovered" || record.RecoveryRequired {
		t.Fatalf("post-crash recovery did not complete after syncing: %+v %v", record, err)
	}
}

func TestRecoveryInfraUnknownCurrentDigestRemainsRefused(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, baselineDigest := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	path := filepath.Join(rt.appStateRoot, "demo", "current.yml")
	changed := []byte(manifest + "# unjournaled byte change\n")
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	record := testRecoveryRecord("deploy", "demo")
	record.CurrentManifestSHA256 = "sha256:" + strings.Repeat("b", 64)
	record.RecoveryCurrentManifestSHA256 = "sha256:" + strings.Repeat("c", 64)
	observation, err := rt.observe(context.Background(), record)
	if err != nil || !recoveryUnresolvedContains(observation, "unknown retained current artifact is not authorized") || recoveryActionKindPresent(rt.planned, recoveryActionRecordKeptInfrastructure) {
		t.Fatalf("unknown current digest was authorized: baseline=%s observation=%+v actions=%+v err=%v", baselineDigest, observation, rt.planned, err)
	}
}

func TestRecoveryCurrentBindingDoesNotAuthorizePreviousSlot(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	previous := manifest + "# different previous bytes\n"
	previousDigest := writeAppManifest(t, rt, "demo", "previous.yml", previous)
	record := testRecoveryRecord("deploy", "demo")
	record.RecoveryCurrentManifestSHA256 = previousDigest
	observation, err := rt.observe(context.Background(), record)
	if err != nil || !recoveryUnresolvedContains(observation, "unknown retained previous artifact is not authorized") {
		t.Fatalf("recovery current binding authorized previous.yml: observation=%+v err=%v", observation, err)
	}
}

func TestRollbackRecoveryNeverPlansKeptInfrastructureRecordAction(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11"}
	rt, _, _, _ := recoveryInfraFixture(t, "rollback", manifest, map[string]string{"demo_redis": testRedisLive}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("rollback", "demo"))
	if err != nil || recoveryActionKindPresent(rt.planned, recoveryActionRecordKeptInfrastructure) {
		t.Fatalf("rollback recovery planned the deploy-only record action: observation=%+v actions=%+v err=%v", observation, rt.planned, err)
	}
}

func TestRecoveryInfraNewerMajorRefusesReapply(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisMajor8: "8.0.0"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64), "demo_redis": testRedisMajor8}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	want := "refusing to replace running redis " + testRedisMajor8 + " with retained " + testRedisRetained + ": major change 8.0.0 -> 7.4.5"
	if !recoveryUnresolvedContains(observation, want) || recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || recoveryDisplayContains(observation.Actions, "reapply the retained current manifest") {
		t.Fatalf("major downgrade was not refused without a reapply action: unresolved=%v actions=%+v", observation.Unresolved, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraOlderMajorRefusesReapply(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	olderMajor := "redis:6-alpine@sha256:" + strings.Repeat("7", 64)
	versions := map[string]string{testRedisRetained: "7.4.5", olderMajor: "6.2.0"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64), "demo_redis": olderMajor}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !recoveryUnresolvedContains(observation, "major change 6.2.0 -> 7.4.5") || recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || recoveryDisplayContains(observation.Actions, "reapply the retained current manifest") {
		t.Fatalf("older major was not refused without a reapply action: unresolved=%v actions=%+v", observation.Unresolved, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraEqualImageKeepsExistingPlan(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@" + testWebDigest, "demo_redis": testRedisRetained}, map[string]string{})
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || len(rt.planned) != 0 || len(observation.Actions) != 0 {
		t.Fatalf("equal live and retained images changed the plan: %+v actions=%+v", observation, rt.planned)
	}
	for _, call := range docker.readCalls {
		if len(call) > 3 && call[0] == "image" && call[1] == "inspect" { // version inspection only; "image inspect <id>" is the registry identity proof
			t.Fatalf("equal images triggered version inspection: %v", call)
		}
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraChangedKeptReferenceAbortsBeforeDeploy(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	oldWeb := "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11", testRedisNewer: "7.4.12"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": oldWeb, "demo_redis": testRedisLive}, versions)
	docker.onServiceInspect = func(service string, count int) {
		if service == "demo_redis" && count == 4 {
			docker.liveImages[service] = testRedisNewer
		}
	}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("dry-run called dockerRun: %v", docker.runCalls)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err == nil || !strings.Contains(err.Error(), "kept infrastructure image references changed") {
		t.Fatalf("changed kept reference did not abort execution: %v", err)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("stack deploy ran after the kept reference changed: %v", docker.runCalls)
	}
}

func TestRecoveryInfraNewCaseCOnNonKeptServiceAbortsBeforeDeploy(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained, "rabbitmq": testRabbitRetained})
	oldWeb := "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)
	newRabbit := "rabbitmq:4-alpine@sha256:" + strings.Repeat("8", 64)
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11", testRabbitRetained: "3.13.0", newRabbit: "4.0.0"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": oldWeb, "demo_redis": testRedisLive, "demo_rabbitmq": testRabbitRetained}, versions)
	docker.onServiceInspect = func(service string, count int) {
		if service == "demo_rabbitmq" && count == 4 {
			docker.liveImages[service] = newRabbit
		}
	}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("dry-run called dockerRun: %v", docker.runCalls)
	}
	if _, err := c.ApplyRecoveryWithProof(context.Background(), h.ID(), plan.PlanDigest, now.Add(time.Minute), "", nil, rt.observe, rt.apply); err == nil || !strings.Contains(err.Error(), "refusing to replace running rabbitmq") {
		t.Fatalf("new refusal on the non-kept service did not abort execution: %v", err)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("stack deploy ran after the non-kept service became unsafe: %v", docker.runCalls)
	}
}

func TestRecoveryInfraOlderSameMajorStillReapplies(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	older := "redis:7.4-alpine@sha256:" + strings.Repeat("9", 64)
	versions := map[string]string{testRedisRetained: "7.4.5", older: "7.4.3"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@" + testWebDigest, "demo_redis": older}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || !recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || len(rt.planned[0].KeepInfrastructureImages) != 0 {
		t.Fatalf("older same-major official Redis did not retain normal reapply: observation=%+v actions=%+v", observation, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraUnofficialOrUnpinnedLiveImageRefusesReapply(t *testing.T) {
	for name, live := range map[string]string{
		"unofficial pinned": "ghcr.io/vendor/redis:7.4-alpine@sha256:" + strings.Repeat("a", 64),
		"official unpinned": "redis:7.4-alpine",
	} {
		t.Run(name, func(t *testing.T) {
			manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
			rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64), "demo_redis": live}, map[string]string{})
			observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
			if err != nil {
				t.Fatal(err)
			}
			if !recoveryUnresolvedContains(observation, "refusing to replace running redis") || recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || recoveryDisplayContains(observation.Actions, "reapply the retained current manifest") {
				t.Fatalf("unsafe live image did not refuse reapply: unresolved=%v actions=%+v", observation.Unresolved, rt.planned)
			}
			for _, call := range docker.readCalls {
				if len(call) > 3 && call[0] == "image" && call[1] == "inspect" { // version inspection only; "image inspect <id>" is the registry identity proof
					t.Fatalf("unsafe live image was passed to image inspect: %v", call)
				}
			}
			if len(docker.runCalls) != 0 {
				t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
			}
		})
	}
}

func TestRecoveryInfraRetainedImageAbsentBlocksWithPullMessage(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	versions := map[string]string{testRedisLive: "7.4.11"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64), "demo_redis": testRedisLive}, versions)
	docker.imageErrors[recoveryInfrastructureInspectReference(testRedisRetained)] = errors.New("Error: No such image")
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	want := "cannot read the version of retained redis " + testRedisRetained + ": image absent from the host; pull it as the administrator, then run recover again"
	if !recoveryUnresolvedContains(observation, want) || recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || recoveryDisplayContains(observation.Actions, "reapply the retained current manifest") {
		t.Fatalf("missing retained image did not block reapply: unresolved=%v actions=%+v", observation.Unresolved, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraInspectErrorIsUnresolved(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)}, map[string]string{})
	docker.serviceErrors["demo_redis"] = errors.New("permission denied while inspecting service")
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !recoveryUnresolvedContains(observation, "cannot inspect running redis service demo_redis") || recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || recoveryDisplayContains(observation.Actions, "reapply the retained current manifest") {
		t.Fatalf("non-absence inspect error did not block reapply: unresolved=%v actions=%+v", observation.Unresolved, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraRollbackKeepsCurrentBehavior(t *testing.T) {
	current := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": "redis:7.4.9-alpine@sha256:" + strings.Repeat("a", 64)})
	previous := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	live := "redis:7.4-alpine@sha256:" + strings.Repeat("b", 64)
	rt, docker, baseline, _ := recoveryInfraFixture(t, "rollback", current, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("c", 64), "demo_redis": live}, map[string]string{})
	previousDigest := writeAppManifest(t, rt, "demo", "previous.yml", previous)
	baseline.Previous = operationwriters.BaselineArtifact{Present: true, FullSHA256: previousDigest}
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), baseline))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("rollback", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || !recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || len(rt.planned[0].KeepInfrastructureImages) != 0 || rt.planned[0].ManifestSHA256 != previousDigest {
		t.Fatalf("rollback behavior changed: observation=%+v actions=%+v", observation, rt.planned)
	}
	for _, call := range docker.readCalls {
		if len(call) > 1 && call[0] == "service" && call[1] == "inspect" {
			t.Fatalf("rollback inspected infrastructure image runtime: %v", call)
		}
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraRedisAndRabbitmqKeepsFitCoordinatorActionLimit(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained, "rabbitmq": testRabbitRetained})
	oldWeb := "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)
	versions := map[string]string{testRedisRetained: "7.4.5", testRedisLive: "7.4.11", testRabbitRetained: "3.13.0", testRabbitLive: "3.13.2"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": oldWeb, "demo_redis": testRedisLive, "demo_rabbitmq": testRabbitLive}, versions)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h := reserveRecovery(t, c, "deploy", "demo")
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Observed.Safe || !recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || len(plan.Actions) < 1 {
		t.Fatalf("coordinator rejected the kept infrastructure action: %+v actions=%v", plan.Observed, plan.Actions)
	}
	var reapplyDisplay string
	for _, action := range plan.Actions {
		if len(action) > coord.MaxReasonBytes {
			t.Fatalf("recovery action exceeds %d bytes: %q", coord.MaxReasonBytes, action)
		}
		if strings.HasPrefix(action, "reapply the retained current manifest") {
			reapplyDisplay = action
		}
	}
	if reapplyDisplay == "" || strings.Index(reapplyDisplay, "keep redis") > strings.Index(reapplyDisplay, "keep rabbitmq") || !strings.Contains(reapplyDisplay, "keep rabbitmq 3.13.2 (retained 3.13.0)") {
		t.Fatalf("kept infrastructure action is invalid or out of order: %q", reapplyDisplay)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraUsesImageConfigInsteadOfLiveTag(t *testing.T) {
	live := "redis:7.4.11-alpine@sha256:" + strings.Repeat("2", 64)
	retained := "redis:7.4.9-alpine@sha256:" + strings.Repeat("3", 64)
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": retained})
	versions := map[string]string{retained: "7.4.9", live: "7.4.5"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@" + testWebDigest, "demo_redis": live}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || !recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || len(rt.planned[0].KeepInfrastructureImages) != 0 {
		t.Fatalf("tag overrode the older Config.Env version: observation=%+v actions=%+v", observation, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraImageConfigMajorOverridesLiveTag(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	live := "redis:7.4-alpine@sha256:" + strings.Repeat("a", 64)
	versions := map[string]string{testRedisRetained: "7.4.5", live: "8.0.0"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@" + testWebDigest, "demo_redis": live}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !recoveryUnresolvedContains(observation, "major change 8.0.0 -> 7.4.5") || recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) {
		t.Fatalf("Config.Env major was ignored in favor of the live tag: unresolved=%v actions=%+v", observation.Unresolved, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraRetainedImageConfigOverridesRetainedTag(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	live := "redis:7.4.11-alpine@sha256:" + strings.Repeat("d", 64)
	versions := map[string]string{testRedisRetained: "7.4.12", live: "7.4.11"}
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": "127.0.0.1:5000/demo-web@" + testWebDigest, "demo_redis": live}, versions)
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || !recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || len(rt.planned[0].KeepInfrastructureImages) != 0 {
		t.Fatalf("retained image tag overrode its Config.Env version: observation=%+v actions=%+v", observation, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

func TestRecoveryInfraAbsentServiceKeepsExistingBehavior(t *testing.T) {
	manifest := testRecoveryInfrastructureManifest(map[string]string{"web": "127.0.0.1:5000/demo-web@" + testWebDigest, "redis": testRedisRetained})
	oldWeb := "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("b", 64)
	rt, docker, _, _ := recoveryInfraFixture(t, "deploy", manifest, map[string]string{"demo_web": oldWeb}, map[string]string{})
	docker.serviceErrors["demo_redis"] = errors.New("Error: no such service: demo_redis")
	observation, err := rt.observe(context.Background(), testRecoveryRecord("deploy", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Safe || !recoveryActionKindPresent(rt.planned, recoveryActionReapplyCurrent) || recoveryUnresolvedContains(observation, "cannot inspect running redis") {
		t.Fatalf("absent infrastructure service did not preserve existing reapply behavior: observation=%+v actions=%+v", observation, rt.planned)
	}
	if len(docker.runCalls) != 0 {
		t.Fatalf("observation ran Docker commands: %v", docker.runCalls)
	}
}

// A sync interrupted by the watchdog leaves a recovery_required record. The
// reconciler must own it, observe, and plan no repair: a sync never changes
// the stack, the registry or the edge.
func TestRecoveryOwnsAnInterruptedSecretsSync(t *testing.T) {
	docker := &fakeRecoveryDocker{registry: healthyRegistryJSON("")}
	attachHealthyWeb(docker)
	rt := newTestRecoveryRuntime(t, docker)
	current := writeAppManifest(t, rt, "demo", "current.yml", testRecoveryManifest(1))
	attachClosedReader(rt, closedWriterState(t, testRecoveryBinding(), testRecoveryBaseline(current, false, "")))
	observation, err := rt.observe(context.Background(), testRecoveryRecord("secrets-sync", "demo"))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range observation.Unresolved {
		if strings.Contains(item, "not owned") {
			t.Fatalf("secrets-sync is not owned by the reconciler: %v", observation.Unresolved)
		}
	}
	if len(observation.Actions) != 0 {
		t.Fatalf("a sync recovery planned repairs: %+v", observation.Actions)
	}
	if !observation.Safe {
		t.Fatalf("a healthy host after an interrupted sync is not releasable: %v", observation.Unresolved)
	}
}

// TestRunRecoveryGoneContainerStillNeedsHealthyService pins the second attempt
// after a failed replacement: the forced update stopped the journaled container
// but the new tasks never became healthy. The container is gone now, and that
// alone must not release the operation while the service is not whole.
func TestRunRecoveryGoneContainerStillNeedsHealthyService(t *testing.T) {
	c, h, rt, docker, _, _ := prepareRunRecovery(t, true, "gone")
	docker.tasks["demo_web"] = ""
	plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Observed.Safe || !recoveryUnresolvedContains(plan.Observed, "run service tasks are not proven healthy") {
		t.Fatalf("gone container released a run whose service is not whole: %+v", plan.Observed)
	}
	if _, err := applyRunRecovery(t, c, h, rt); err == nil {
		t.Fatal("recovery released a run without a healthy service")
	}
	record, err := c.Get(context.Background(), h.ID())
	if err != nil || record.State == "recovered" || !record.RecoveryRequired {
		t.Fatalf("unhealthy service was released: %+v %v", record, err)
	}
}

// TestRunRecoveryAcceptsLongValidNames covers an application and a service
// whose names are each valid but whose Swarm name is longer than one
// component may be. Deploy derives that name from the two validated parts;
// recovery must do the same instead of refusing the run forever.
func TestRunRecoveryAcceptsLongValidNames(t *testing.T) {
	app := "a" + strings.Repeat("p", 39)
	service := "s" + strings.Repeat("v", 39)
	container := strings.Repeat("e", 64)
	if !rootAppName.MatchString(app) || !rootServiceName.MatchString(service) || rootServiceName.MatchString(app+"_"+service) {
		t.Fatal("fixture must be two valid components with an over-long combined name")
	}
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	rt.dockerRead = func(_ context.Context, args ...string) (string, error) {
		if len(args) >= 2 && args[0] == "inspect" && args[len(args)-1] == container {
			return "", errors.New("No such container: " + container)
		}
		return "", errors.New("unexpected docker read")
	}
	record := coord.Record{Kind: "run", App: app, Phases: []coord.Phase{{Name: "run", StartedAt: "2026-10-26T12:00:00Z", EndedAt: "2026-10-26T12:00:01Z", Error: "helper outcome unknown"}}, RunTarget: &coord.RunTarget{Service: service, Container: container}}
	state, unresolved := rt.observeRunTarget(context.Background(), record)
	if state != "gone" || len(unresolved) != 0 {
		t.Fatalf("long valid names were refused: state=%s unresolved=%v", state, unresolved)
	}
}

// TestRunRecoveryRetryAfterFailedReplacementWaitsForHealthyService runs the
// whole sequence: the forced update stops or removes the journaled container,
// the replacement tasks are not healthy, so the first recovery fails; the next
// recovery sees the container ended and must stay blocked until the service is
// whole again, then release.
func TestRunRecoveryRetryAfterFailedReplacementWaitsForHealthyService(t *testing.T) {
	for _, ended := range []string{"gone", "stopped"} {
		t.Run(ended, func(t *testing.T) {
			c, h, rt, docker, setTargetState, _ := prepareRunRecovery(t, true, "running")
			baseRun := rt.dockerRun
			rt.dockerRun = func(ctx context.Context, args ...string) error {
				if strings.Join(args, " ") == "service update --force --detach=false demo_web" {
					setTargetState(ended)
					docker.tasks["demo_web"] = ""
				}
				return baseRun(ctx, args...)
			}
			if _, err := applyRunRecovery(t, c, h, rt); err == nil {
				t.Fatal("replacement with unhealthy tasks was accepted")
			}
			plan, err := c.RecoveryPlan(context.Background(), h.ID(), rt.observe)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Observed.Safe || !recoveryUnresolvedContains(plan.Observed, "run service tasks are not proven healthy") {
				t.Fatalf("retry released a %s container with an unhealthy service: %+v", ended, plan.Observed)
			}
			attachHealthyWeb(docker)
			if _, err := applyRunRecovery(t, c, h, rt); err != nil {
				t.Fatalf("retry did not release once the service was healthy: %v", err)
			}
			record, err := c.Get(context.Background(), h.ID())
			if err != nil || record.State != "recovered" || record.RecoveryRequired {
				t.Fatalf("healthy service did not release the run: %+v %v", record, err)
			}
		})
	}
}

// TestRunRecoveryServiceNameAcceptsLongValidComponents pins the one derivation
// both observation and the replacement action use.
func TestRunRecoveryServiceNameAcceptsLongValidComponents(t *testing.T) {
	app := "a" + strings.Repeat("p", 39)
	service := "s" + strings.Repeat("v", 39)
	got, err := runRecoveryServiceName(app, service)
	if err != nil || got != app+"_"+service {
		t.Fatalf("long valid components refused: %q %v", got, err)
	}
	for _, bad := range [][2]string{{"Demo", "web"}, {"demo", "-web"}, {"demo", ""}, {"", "web"}} {
		if _, err := runRecoveryServiceName(bad[0], bad[1]); err == nil {
			t.Fatalf("invalid components accepted: %v", bad)
		}
	}
}

// TestRunRecoveryActionAcceptsLongValidNames drives the replacement action
// itself with a long application name: it must get past identity validation
// (and fail later, on the manifest this test does not provide), so a combined
// name check reinstated in the action alone is caught.
func TestRunRecoveryActionAcceptsLongValidNames(t *testing.T) {
	rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
	app := "a" + strings.Repeat("p", 59)
	record := coord.Record{Kind: "run", App: app}
	action := recoveryAction{Kind: recoveryActionReplaceRunTasks, App: app, Service: "web", Container: strings.Repeat("e", 64), ManifestPath: "missing.yml", ManifestSHA256: "sha256:" + strings.Repeat("0", 64)}
	err := rt.executeReplaceRunTasks(context.Background(), record, action)
	if err == nil {
		t.Fatal("action without a manifest unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "identity is invalid") {
		t.Fatalf("long valid names were refused by the action: %v", err)
	}
}

func TestRecoveryHelperUpdateAfterFailedProbe(t *testing.T) {
	for _, state := range []string{"absent", "completed", "prepared", "unreadable", "unconfirmed", "foreign"} {
		t.Run(state, func(t *testing.T) {
			rt := newTestRecoveryRuntime(t, &fakeRecoveryDocker{registry: healthyRegistryJSON("")})
			attachAbsentWriterReader(rt)
			paths := helperMigrationPaths{IntentPath: rt.helperMigrationIntent}
			fs := testHelperMigrationFS()
			writeRecoveryOwnReservation(t, rt, testRecoveryOpID)
			proof, err := readHelperMigrationOwnReservationProof(fs, paths)
			if err != nil || proof == nil {
				t.Fatalf("read admission: %v", err)
			}
			cause := error(context.DeadlineExceeded)
			if state == "prepared" {
				writeRecoveryHelperIntent(t, rt, helperMigrationPhaseReady)
			}
			if state == "completed" {
				writeRecoveryHelperIntent(t, rt, helperMigrationPhaseComplete)
			}
			if state == "unreadable" {
				if err := os.WriteFile(paths.IntentPath, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if state == "unconfirmed" {
				cause = errors.Join(cause, errHelperProbeUnconfirmed)
			}
			if state == "foreign" {
				proof.OperationID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			intentBefore, _ := os.ReadFile(paths.IntentPath)
			before, err := rt.observe(context.Background(), testHelperUpdateRecord())
			if err != nil || before.Safe {
				t.Fatalf("admitted probe unexpectedly recoverable: %+v %v", before, err)
			}
			if err := helperProbeFailureBeforeReplacement(*proof, cause, fs, paths); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lost probe failure: %v", err)
			}
			after, err := rt.observe(context.Background(), testHelperUpdateRecord())
			if err != nil {
				t.Fatal(err)
			}
			if after.Safe != (state == "absent" || state == "completed") {
				t.Fatalf("failed probe recovery state: %+v", after)
			}
			intentAfter, _ := os.ReadFile(paths.IntentPath)
			if string(intentAfter) != string(intentBefore) {
				t.Fatal("failed probe changed migration evidence")
			}
			stored, err := readHelperMigrationOwnReservationProof(fs, paths)
			if err != nil || (stored == nil) != (state == "absent" || state == "completed") {
				t.Fatalf("wrong admission cleanup: %+v %v", stored, err)
			}
		})
	}
}
