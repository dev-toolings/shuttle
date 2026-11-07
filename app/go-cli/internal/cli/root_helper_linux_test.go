//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestInternalReadinessRejectsDeployedPublicationMismatch(t *testing.T) {
	noLabel := func(string) (string, error) {
		return `[{"ID":"service-id-full","Spec":{"Name":"demo_web","Labels":{"com.docker.stack.namespace":"demo"}}}]`, nil
	}
	if err := validateReadinessPublication("demo", "", []string{"service-id"}, noLabel); err != nil {
		t.Fatalf("internal stack without publication label was refused: %v", err)
	}
	labelled := func(string) (string, error) {
		return `[{"ID":"service-id-full","Spec":{"Name":"demo_web","Labels":{"dev.shuttle.domain":"web.example.com"}}}]`, nil
	}
	if err := validateReadinessPublication("demo", "", []string{"service-id"}, labelled); err == nil || err.Error() != "app demo publishes demo_web on web.example.com, but the readiness audit has no domain: the config and the deployed stack disagree" {
		t.Fatalf("publication mismatch refusal = %v", err)
	}
	if err := validateReadinessPublication("demo", "", []string{"service-id"}, func(string) (string, error) {
		return "", errors.New("docker inspect failed")
	}); err == nil || !strings.Contains(err.Error(), "inspect service service-id") {
		t.Fatalf("service inspect failure was not refused: %v", err)
	}
	// Malformed or empty inspections must never read as "no label".
	for _, payload := range []string{`[{}]`, `[null]`, `[{"ID":"service-id-full","Spec":null}]`, `[{"ID":"service-id-full","Spec":{"Name":""}}]`, `[{"ID":"other-id","Spec":{"Name":"demo_web"}}]`, `[]`} {
		if err := validateReadinessPublication("demo", "", []string{"service-id"}, func(string) (string, error) { return payload, nil }); err == nil {
			t.Errorf("malformed inspection %s was accepted", payload)
		}
	}
	// A service without any label map is a legitimate internal service.
	if err := validateReadinessPublication("demo", "", []string{"service-id"}, func(string) (string, error) {
		return `[{"ID":"service-id-full","Spec":{"Name":"demo_worker"}}]`, nil
	}); err != nil {
		t.Fatalf("service without labels was refused: %v", err)
	}
}

func TestRootImageStoreSweepPlansStoppedTaskContainers(t *testing.T) {
	superseded := map[string]bool{"sha256:image": true}
	for name, test := range map[string]struct {
		containers []rootContainerEntry
		want       []string
	}{
		"exited superseded Swarm task": {
			containers: []rootContainerEntry{{ID: "exited", State: "exited", ImageID: "sha256:image", TaskID: "task-1"}},
			want:       []string{"exited"},
		},
		"dead included and created excluded": {
			containers: []rootContainerEntry{
				{ID: "dead", State: "dead", ImageID: "sha256:image", TaskID: "task-2"},
				{ID: "created", State: "created", ImageID: "sha256:image", TaskID: "task-3"},
			},
			want: []string{"dead"},
		},
		"active states excluded": {
			containers: []rootContainerEntry{
				{ID: "running", State: "running", ImageID: "sha256:image", TaskID: "task-4"},
				{ID: "paused", State: "paused", ImageID: "sha256:image", TaskID: "task-5"},
				{ID: "restarting", State: "restarting", ImageID: "sha256:image", TaskID: "task-6"},
			},
		},
		"hand started container excluded": {
			containers: []rootContainerEntry{{ID: "manual", State: "exited", ImageID: "sha256:image"}},
		},
		"retained or foreign image excluded": {
			containers: []rootContainerEntry{{ID: "other-image", State: "exited", ImageID: "sha256:retained", TaskID: "task-7"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := planRootStoppedTaskContainers(superseded, test.containers); !slices.Equal(got, test.want) {
				t.Fatalf("planned containers = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRootImageStoreSweepParsesContainerInspectRows(t *testing.T) {
	got := parseRootContainers("valid\texited\tsha256:image\ttask-1\nmalformed\tonly-two\nmanual\texited\tsha256:image\t<no value>\n\tdead\tsha256:image\ttask-2\n")
	want := []rootContainerEntry{
		{ID: "valid", State: "exited", ImageID: "sha256:image", TaskID: "task-1"},
		{ID: "manual", State: "exited", ImageID: "sha256:image"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("parsed containers = %#v, want %#v", got, want)
	}
}

func TestRootImageStoreSweepUsesConfiguredDiskRefusalThreshold(t *testing.T) {
	if got, want := rootDiskSpaceRefusal().Error(), "deployment refused: less than 20 percent disk space remains"; got != want {
		t.Fatalf("disk refusal = %q, want %q", got, want)
	}
	if got, want := fmt.Sprintf("minimum is %d%%", rootMinFreeDiskPercent), "minimum is 20%"; got != want {
		t.Fatalf("disk log threshold = %q, want %q", got, want)
	}
}

func setRootInfraSweepSeams(t *testing.T) {
	t.Helper()
	originalKeep, originalValue, originalCommand := rootInfrastructureKeep, rootImageStoreDockerValue, rootImageStoreDockerCommand
	originalSole, originalNow := rootInfraSoleOperation, rootImageStoreNow
	t.Cleanup(func() {
		rootInfrastructureKeep, rootImageStoreDockerValue, rootImageStoreDockerCommand = originalKeep, originalValue, originalCommand
		rootInfraSoleOperation, rootImageStoreNow = originalSole, originalNow
	})
	rootInfraSoleOperation = func(_ string, fn func() error) error { return fn() }
	rootImageStoreNow = time.Now
}

func TestRootInfraSweepPlansAndRemovesStoppedRabbitTask(t *testing.T) {
	setRootInfraSweepSeams(t)
	imageID := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	var removedContainer, removedImage bool
	rootInfrastructureKeep = func(string, string, string, string) (rootInfraKeepSet, error) {
		return rootInfraKeepSet{digests: map[string]bool{"sha256:" + strings.Repeat("c", 64): true}, appNamespaces: map[string]bool{"demo": true}}, nil
	}
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:2], " ") {
		case "service ls":
			// Pinned argv: `service ls` rejects --no-trunc on a real daemon.
			if got := strings.Join(args, " "); got != "service ls --format {{.ID}}" {
				t.Fatalf("service listing argv = %q", got)
			}
			return "svc\n", nil
		case "service inspect":
			return `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"rabbitmq:4.1@sha256:` + strings.Repeat("d", 64) + `"}}},"PreviousSpec":null}]`, nil
		case "image ls":
			return "rabbitmq\t" + digest + "\t" + imageID + "\n", nil
		case "container ls":
			if removedContainer {
				return "", nil
			}
			return "old-task\n", nil
		case "container inspect":
			return "old-task\texited\t" + imageID + "\ttask-old\tdemo_rabbitmq\tdemo", nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		if strings.Join(args, " ") == "container rm old-task" {
			removedContainer = true
			return nil
		}
		if strings.Join(args, " ") == "image rm "+imageID {
			if !removedContainer {
				t.Fatal("image removed before task container")
			}
			removedImage = true
			return nil
		}
		t.Fatalf("unexpected command (force is forbidden): %v", args)
		return nil
	}
	if err := pruneRootInfrastructureImages("current", "previous", "op", false); err != nil {
		t.Fatal(err)
	}
	if !removedContainer || !removedImage {
		t.Fatalf("removed container=%v image=%v", removedContainer, removedImage)
	}
}

func TestRootInfraSweepPreviousSpecAndRetainedDigestKeepTask(t *testing.T) {
	setRootInfraSweepSeams(t)
	imageID := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	rootInfrastructureKeep = func(string, string, string, string) (rootInfraKeepSet, error) {
		return rootInfraKeepSet{digests: map[string]bool{}, appNamespaces: map[string]bool{"demo": true}}, nil
	}
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:2], " ") {
		case "service ls":
			return "s\n", nil
		case "service inspect":
			return `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"rabbitmq:4.1@sha256:` + strings.Repeat("d", 64) + `"}}},"PreviousSpec":{"TaskTemplate":{"ContainerSpec":{"Image":"rabbitmq:4.0@sha256:` + strings.Repeat("b", 64) + `"}}}}]`, nil
		case "image ls":
			return "docker.io/library/rabbitmq\t" + digest + "\t" + imageID + "\n", nil
		case "container ls":
			return "old-task\n", nil
		case "container inspect":
			return "old-task\texited\t" + imageID + "\ttask\tdemo_rabbitmq\tdemo", nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		t.Fatalf("rollback image/container removed: %v", args)
		return nil
	}
	if err := pruneRootInfrastructureImages("current", "previous", "op", false); err != nil {
		t.Fatal(err)
	}
}

func TestRootInfraSweepPlannerStateAndOwnershipRules(t *testing.T) {
	inScope := func(service, namespace string) bool {
		return namespace == "demo" && service == "demo_redis" || namespace == "shuttle-edge" && service == "shuttle-edge_caddy"
	}
	containers := []rootInfraContainerEntry{
		{ID: "stopped", State: "exited", ImageID: "old", TaskID: "task", Service: "demo_redis", Namespace: "demo"},
		{ID: "dead", State: "dead", ImageID: "old", TaskID: "task", Service: "demo_redis", Namespace: "demo"},
		{ID: "running", State: "running", ImageID: "live", TaskID: "task", Service: "demo_redis", Namespace: "demo"},
		{ID: "paused", State: "paused", ImageID: "paused", TaskID: "task", Service: "demo_redis", Namespace: "demo"},
		{ID: "restarting", State: "restarting", ImageID: "restart", TaskID: "task", Service: "demo_redis", Namespace: "demo"},
		{ID: "created", State: "created", ImageID: "created", TaskID: "task", Service: "demo_redis", Namespace: "demo"},
		{ID: "operator", State: "exited", ImageID: "operator", TaskID: "task", Service: "shared_uptime-kuma", Namespace: "shared_uptime-kuma"},
		{ID: "mercure", State: "exited", ImageID: "mercure", TaskID: "task", Service: "mercure-hub_mercure", Namespace: "mercure-hub"},
		{ID: "registry", State: "exited", ImageID: "registry", TaskID: "task", Service: "", Namespace: ""},
		{ID: "manual", State: "exited", ImageID: "manual", Service: "demo_redis", Namespace: "demo"},
	}
	got := planRootInfrastructureContainers(inScope, map[string]bool{"live": true, "paused": true, "restart": true, "created": true}, containers)
	if !slices.Equal(got, []string{"dead", "stopped"}) {
		t.Fatalf("container plan=%v", got)
	}
	oldDigest, newDigest, keptDigest := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("3", 64)
	entries := []rootImageStoreEntry{{Repository: "redis", Digest: oldDigest, ID: "old"}, {Repository: "docker.io/library/rabbitmq", Digest: newDigest, ID: "new"}, {Repository: "other", Digest: "sha256:" + strings.Repeat("4", 64), ID: "other"}, {Repository: "caddy", Digest: "", ID: "unknown"}, {Repository: "rabbitmq", Digest: oldDigest, ID: "shared"}, {Repository: "redis", Digest: keptDigest, ID: "shared"}}
	images := planRootInfrastructureImages(map[string]bool{"redis": true, "rabbitmq": true, "caddy": true}, map[string]bool{keptDigest: true}, nil, nil, entries)
	if !slices.Equal(images, []string{"new", "old"}) {
		t.Fatalf("image plan=%v", images)
	}
	liveAndOld := []rootImageStoreEntry{{Repository: "redis", Digest: oldDigest, ID: "old"}, {Repository: "redis", Digest: newDigest, ID: "new"}}
	if got := planRootInfrastructureImages(map[string]bool{"redis": true}, nil, map[string]bool{"new": true}, nil, liveAndOld); !slices.Equal(got, []string{"old"}) {
		t.Fatalf("newer live image should protect only itself: %v", got)
	}
	if got := planRootInfrastructureImages(map[string]bool{"redis": true}, nil, nil, map[string]bool{"old": true}, liveAndOld); !slices.Equal(got, []string{"new"}) {
		t.Fatalf("container-held image should be excluded: %v", got)
	}
}

func TestRootInfraSweepCaddyStackDigestIsRetained(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	digest := "sha256:" + strings.Repeat("e", 64)
	path := filepath.Join(root, "caddy-stack.yml")
	if err := os.WriteFile(path, []byte("services:\n  caddy:\n    image: caddy:2@"+digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep, err := readRootInfrastructureKeep(filepath.Join(root, "missing-current.yml"), filepath.Join(root, "missing-previous.yml"), state, path)
	if err != nil {
		t.Fatal(err)
	}
	if !keep.digests[digest] {
		t.Fatalf("Caddy stack digest %s was not retained: %v", digest, keep.digests)
	}
}

func TestRootInfraSweepPreviousAppFileDigestIsRetained(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "apps")
	if err := os.MkdirAll(filepath.Join(state, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("7", 64)
	if err := os.WriteFile(filepath.Join(state, "demo", "previous.yml"), []byte("services:\n  redis:\n    image: redis:8.10.3-alpine@"+digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep, err := readRootInfrastructureKeep(filepath.Join(root, "current-missing.yml"), filepath.Join(root, "previous-missing.yml"), state, filepath.Join(root, "caddy-missing.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !keep.digests[digest] || !keep.appNamespaces["demo"] {
		t.Fatalf("previous app reference/scope missing: %#v", keep)
	}
}

func TestRootInfraSweepRechecksKeepInsideSoleOperation(t *testing.T) {
	setRootInfraSweepSeams(t)
	target := "sha256:" + strings.Repeat("f", 64)
	imageID := "sha256:" + strings.Repeat("a", 64)
	inside, soleCalls := false, 0
	rootInfrastructureKeep = func(string, string, string, string) (rootInfraKeepSet, error) {
		keep := map[string]bool{"sha256:" + strings.Repeat("c", 64): true}
		if inside {
			keep[target] = true
		}
		return rootInfraKeepSet{digests: keep}, nil
	}
	rootInfraSoleOperation = func(_ string, fn func() error) error {
		soleCalls++
		inside = true
		defer func() { inside = false }()
		return fn()
	}
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:2], " ") {
		case "service ls":
			return "", nil
		case "image ls":
			return "redis\t" + target + "\t" + imageID + "\n", nil
		case "container ls":
			return "", nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
	rootImageStoreDockerCommand = func(_ string, args ...string) error { t.Fatalf("freshly retained image removed: %v", args); return nil }
	if err := pruneRootInfrastructureImages("c", "p", "op", true); err != nil {
		t.Fatal(err)
	}
	if soleCalls != 1 {
		t.Fatalf("sole-operation calls=%d, want 1", soleCalls)
	}
}

func TestRootInfraSweepActiveOperationDefersImagePass(t *testing.T) {
	setRootInfraSweepSeams(t)
	target := "sha256:" + strings.Repeat("f", 64)
	imageID := "sha256:" + strings.Repeat("a", 64)
	rootInfrastructureKeep = func(string, string, string, string) (rootInfraKeepSet, error) {
		return rootInfraKeepSet{digests: map[string]bool{"sha256:" + strings.Repeat("c", 64): true}}, nil
	}
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:2], " ") {
		case "service ls":
			return "", nil
		case "image ls":
			return "redis\t" + target + "\t" + imageID + "\n", nil
		case "container ls":
			return "", nil
		default:
			t.Fatalf("unexpected read: %v", args)
			return "", nil
		}
	}
	soleCalls := 0
	rootInfraSoleOperation = func(string, func() error) error { soleCalls++; return errors.New("foreign operation active") }
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		t.Fatalf("image removed during active operation: %v", args)
		return nil
	}
	if err := pruneRootInfrastructureImages("c", "p", "op", true); err != nil {
		t.Fatalf("deferral should be nonfatal: %v", err)
	}
	if soleCalls != 1 {
		t.Fatalf("sole-operation calls=%d", soleCalls)
	}
}

func TestRootInfraSweepDirectImagePassSkipsSoleOperationFence(t *testing.T) {
	setRootInfraSweepSeams(t)
	rootInfrastructureKeep = func(string, string, string, string) (rootInfraKeepSet, error) {
		return rootInfraKeepSet{digests: map[string]bool{"sha256:x": true}}, nil
	}
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:2], " ") {
		case "service ls":
			return "", nil
		case "image ls":
			return "", nil
		case "container ls":
			return "", nil
		default:
			t.Fatalf("unexpected read: %v", args)
			return "", nil
		}
	}
	rootInfraSoleOperation = func(string, func() error) error {
		t.Fatal("sole-operation fence called for nonconcurrent operation")
		return nil
	}
	if err := pruneRootInfrastructureImages("c", "p", "op", false); err != nil {
		t.Fatal(err)
	}
}

func TestRootInfraSweepFailsClosedOnKeepAndDaemonReadErrors(t *testing.T) {
	for _, mode := range []string{"keep-error", "empty-keep", "container-list", "service-list", "service-inspect", "image-list", "digestless-spec", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			setRootInfraSweepSeams(t)
			rootImageStoreNow = time.Now
			rootInfrastructureKeep = func(string, string, string, string) (rootInfraKeepSet, error) {
				switch mode {
				case "keep-error":
					return rootInfraKeepSet{}, errors.New("read failed")
				case "empty-keep":
					return rootInfraKeepSet{digests: map[string]bool{}}, nil
				}
				return rootInfraKeepSet{digests: map[string]bool{"sha256:retained": true}}, nil
			}
			rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
				switch strings.Join(args[:2], " ") {
				case "service ls":
					if mode == "service-list" {
						return "", errors.New("service list failed")
					}
					if mode == "empty-keep" {
						// No retained digest and no service image: the union is
						// empty, which must abort rather than mean "keep nothing".
						return "", nil
					}
					return "svc\n", nil
				case "service inspect":
					if mode == "service-inspect" {
						return "", errors.New("inspect failed")
					}
					if mode == "digestless-spec" {
						return `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"redis:8"}}},"PreviousSpec":null}]`, nil
					}
					return `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"rabbitmq:4@sha256:` + strings.Repeat("d", 64) + `"}}},"PreviousSpec":null}]`, nil
				case "image ls":
					if mode == "image-list" {
						return "", errors.New("image list failed")
					}
					return "redis\tsha256:unused\tsha256:" + strings.Repeat("a", 64) + "\n", nil
				case "container ls":
					if mode == "container-list" {
						return "", errors.New("container list failed")
					}
					return "", nil
				default:
					t.Fatalf("unexpected read: %v", args)
					return "", nil
				}
			}
			rootImageStoreDockerCommand = func(_ string, args ...string) error {
				t.Fatalf("removal after failed read %s: %v", mode, args)
				return nil
			}
			if mode == "deadline" {
				calls := 0
				start := time.Now()
				rootImageStoreNow = func() time.Time {
					calls++
					if calls >= 2 {
						return start.Add(rootImageStoreInspectBudget + time.Second)
					}
					return start
				}
			}
			err := pruneRootInfrastructureImages("c", "p", "op", false)
			want := map[string]string{
				"keep-error":      "read failed",
				"empty-keep":      "no retained infrastructure image digest",
				"container-list":  "container list failed",
				"service-list":    "service list failed",
				"service-inspect": "inspect failed",
				"image-list":      "image list failed",
				"digestless-spec": "no digest",
				"deadline":        "deadline",
			}[mode]
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s: the injected failure must abort the pass with its own error (want %q), got %v", mode, want, err)
			}
		})
	}
}

func TestRootInfraSweepRetainedFileParseErrorAborts(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	bad := filepath.Join(root, "bad.yml")
	if err := os.WriteFile(bad, []byte("services: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootInfrastructureKeep(bad, filepath.Join(root, "missing.yml"), state, filepath.Join(root, "missing-caddy.yml")); err == nil {
		t.Fatal("malformed retained file did not fail closed")
	}
}

func TestRootInfraSweepRetainedFileReadErrorAborts(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "not-a-file.yml")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootInfrastructureKeep(directory, filepath.Join(root, "missing.yml"), filepath.Join(root, "missing-apps"), filepath.Join(root, "missing-caddy.yml")); err == nil {
		t.Fatal("retained file read error did not fail closed")
	}
}

func TestRootInfraSweepRejectsRemovalFlagsAndResourceCommands(t *testing.T) {
	if got := planRootInfrastructureContainers(func(string, string) bool { return true }, nil, []rootInfraContainerEntry{{ID: "x", State: "exited", ImageID: "i", TaskID: "t", Service: "s", Namespace: "n"}}); !slices.Equal(got, []string{"x"}) {
		t.Fatalf("unexpected plan: %v", got)
	}
	command := func(args ...string) {
		if slices.Contains(args, "--force") || args[0] == "volume" || args[0] == "network" || strings.Contains(strings.Join(args, " "), "system prune") {
			t.Fatalf("forbidden cleanup command: %v", args)
		}
	}
	command("container", "rm", "x")
	command("image", "rm", "i")
}

func setRootImageStoreSweepSeams(t *testing.T) {
	t.Helper()
	originalKeep := rootImageStoreKeepDigests
	originalValue := rootImageStoreDockerValue
	originalCommand := rootImageStoreDockerCommand
	originalShared := rootRetainedStacksShared
	originalNow := rootImageStoreNow
	t.Cleanup(func() {
		rootImageStoreNow = originalNow
		rootImageStoreKeepDigests = originalKeep
		rootImageStoreDockerValue = originalValue
		rootImageStoreDockerCommand = originalCommand
		rootRetainedStacksShared = originalShared
	})
	rootRetainedStacksShared = func(fn func() error) error { return fn() }
}

func TestRootImageStoreSweepRemovesStoppedContainersBeforeTheirImages(t *testing.T) {
	for _, sameIDAsDigest := range []bool{false, true} {
		t.Run(fmt.Sprintf("containerd-store-%v", sameIDAsDigest), func(t *testing.T) {
			setRootImageStoreSweepSeams(t)
			retained := "sha256:" + strings.Repeat("a", 64)
			superseded := "sha256:" + strings.Repeat("b", 64)
			imageID := "sha256:" + strings.Repeat("c", 64)
			if sameIDAsDigest {
				imageID = superseded
			}
			rootImageStoreKeepDigests = func(string, string) (map[string]bool, error) { return map[string]bool{retained: true}, nil }
			listing := rootRegistryImagePrefix + "demo-web\t" + superseded + "\t" + imageID + "\n"
			containerRemoved := false
			var order []string
			rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
				switch strings.Join(args[:3], " ") {
				case "image ls --all":
					return listing, nil
				case "container ls --all":
					return "container-1\n", nil
				case "container inspect --format":
					return "container-1\texited\t" + imageID + "\ttask-1", nil
				default:
					t.Fatalf("unexpected docker value args: %v", args)
					return "", nil
				}
			}
			rootImageStoreDockerCommand = func(_ string, args ...string) error {
				if len(args) == 3 && args[0] == "container" && args[1] == "rm" && args[2] == "container-1" {
					order = append(order, "container")
					containerRemoved = true
					return nil
				}
				if len(args) == 3 && args[0] == "image" && args[1] == "rm" && args[2] == imageID {
					if !containerRemoved {
						t.Fatal("image removal ran before its only holding container was removed")
					}
					order = append(order, "image")
					return nil
				}
				t.Fatalf("unexpected docker command (force is forbidden): %v", args)
				return nil
			}
			if err := rootRetainedStacksShared(func() error { return pruneRootImageStore("current", "previous") }); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(order, []string{"container", "image"}) {
				t.Fatalf("removal order = %v, want [container image]", order)
			}
		})
	}
}

func TestRootImageStoreSweepFreshKeepIntersectionProtectsSharedImage(t *testing.T) {
	setRootImageStoreSweepSeams(t)
	retainedA, retainedB := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	imageID := "sha256:" + strings.Repeat("c", 64)
	reads := 0
	rootImageStoreKeepDigests = func(string, string) (map[string]bool, error) {
		reads++
		if reads == 1 {
			return map[string]bool{"sha256:" + strings.Repeat("d", 64): true}, nil
		}
		return map[string]bool{retainedA: true}, nil
	}
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:3], " ") {
		case "image ls --all":
			return rootRegistryImagePrefix + "demo-web\t" + retainedA + "\t" + imageID + "\n" + rootRegistryImagePrefix + "demo-web\t" + retainedB + "\t" + imageID + "\n", nil
		case "container ls --all":
			return "container-1\n", nil
		case "container inspect --format":
			return "container-1\texited\t" + imageID + "\ttask-1", nil
		default:
			t.Fatalf("unexpected docker value args: %v", args)
			return "", nil
		}
	}
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		t.Fatalf("freshly retained shared image or its container was removed: %v", args)
		return nil
	}
	if err := rootRetainedStacksShared(func() error { return pruneRootImageStore("current", "previous") }); err != nil {
		t.Fatal(err)
	}
	if reads != 3 {
		t.Fatalf("keep-set reads = %d, want initial, container-pass, and image-pass reads", reads)
	}
}

func TestRootImageStoreSweepRollbackSwapAndSweepShareLock(t *testing.T) {
	setRootImageStoreSweepSeams(t)
	current, previous := writeSwapFixture(t)
	if err := os.WriteFile(current, stackWithDigest("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, stackWithDigest("2"), 0o600); err != nil {
		t.Fatal(err)
	}
	var lock sync.Mutex
	rootRetainedStacksShared = func(fn func() error) error {
		lock.Lock()
		defer lock.Unlock()
		return fn()
	}
	firstSync, continueSwap := make(chan struct{}), make(chan struct{})
	originalSync := syncRootFileDirectory
	t.Cleanup(func() { syncRootFileDirectory = originalSync })
	syncCalls := 0
	syncRootFileDirectory = func(string) error {
		syncCalls++
		if syncCalls == 1 {
			close(firstSync)
			<-continueSwap
		}
		return nil
	}
	readCompleted := make(chan map[string]bool, 2)
	rootImageStoreKeepDigests = func(currentPath, previousPath string) (map[string]bool, error) {
		keep := map[string]bool{}
		for _, path := range []string{currentPath, previousPath} {
			body, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			for _, digest := range rootStackRegistryDigests(body) {
				keep[digest] = true
			}
		}
		readCompleted <- keep
		return keep, nil
	}
	imageID := "sha256:" + strings.Repeat("f", 64)
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:3], " ") {
		case "image ls --all":
			return rootRegistryImagePrefix + "demo-web\tsha256:" + strings.Repeat("1", 64) + "\t" + imageID + "\n", nil
		case "container ls --all":
			return "undone-task-container\n", nil
		case "container inspect --format":
			return "undone-task-container\texited\t" + imageID + "\ttask-1", nil
		default:
			t.Fatalf("unexpected docker value args: %v", args)
			return "", nil
		}
	}
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		t.Fatalf("rollback target or undone release was removed during stack rotation: %v", args)
		return nil
	}
	rotateResult := make(chan error, 1)
	go func() { _, err := rotateRetainedStacksAfterRollback(current, previous); rotateResult <- err }()
	<-firstSync
	sweepResult := make(chan error, 1)
	go func() {
		sweepResult <- rootRetainedStacksShared(func() error { return pruneRootImageStore(current, previous) })
	}()
	select {
	case keep := <-readCompleted:
		t.Fatalf("sweep completed keep-set read during the half-written swap: %v", keep)
	default:
	}
	close(continueSwap)
	if err := <-rotateResult; err != nil {
		t.Fatal(err)
	}
	if err := <-sweepResult; err != nil {
		t.Fatal(err)
	}
	keep := <-readCompleted
	if !keep["sha256:"+strings.Repeat("1", 64)] || !keep["sha256:"+strings.Repeat("2", 64)] {
		t.Fatalf("post-swap keep set lost a retained release: %v", keep)
	}
}

// infrastructureServicePayload writes a generated service the way secureStack
// does, so a drift between the two sides fails here rather than on the host.
func infrastructureServicePayload(runtime infrastructureRuntime, app, user string) string {
	body := "  " + runtime.service + ":\n    image: " + runtime.image + "\n"
	if user != "" {
		body += "    user: \"" + user + "\"\n"
	}
	return body + "    volumes: [" + app + "_" + runtime.service + "_data:" + runtime.target + "]\n"
}

func TestInfrastructureVolumesUsePinnedRuntimeOwnership(t *testing.T) {
	redis, rabbit := infrastructureRuntimeFor("redis"), infrastructureRuntimeFor("rabbitmq")
	payload := []byte("services:\n" + infrastructureServicePayload(redis, "demo", redis.user()) + infrastructureServicePayload(rabbit, "demo", rabbit.user()))
	volumes, err := infrastructureVolumes("demo", payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 2 || volumes[0] != (infrastructureVolume{name: "demo_redis_data", uid: 999, gid: 1000}) || volumes[1] != (infrastructureVolume{name: "demo_rabbitmq_data", uid: 100, gid: 101}) {
		t.Fatalf("unexpected infrastructure ownership: %#v", volumes)
	}
}

func TestInfrastructureVolumesRejectImageAndPathDrift(t *testing.T) {
	redis := infrastructureRuntimeFor("redis")
	valid := "services:\n" + infrastructureServicePayload(redis, "demo", redis.user())
	for _, payload := range []string{
		strings.Replace(valid, redisImage, "registry.invalid/redis@sha256:"+strings.Repeat("a", 64), 1),
		strings.Replace(valid, "demo_redis_data:/data", "other:/data", 1),
	} {
		if _, err := infrastructureVolumes("demo", []byte(payload)); err == nil {
			t.Fatalf("unsafe infrastructure volume accepted:\n%s", payload)
		}
	}
}

func TestInfrastructureVolumesAllowThePreviouslyRetainedImage(t *testing.T) {
	legacy := infrastructureRuntimeFor("redis")
	legacy.image = "redis:7.4.5-alpine@sha256:" + strings.Repeat("b", 64)
	payload := []byte("services:\n" + infrastructureServicePayload(legacy, "demo", legacy.user()))
	if _, err := infrastructureVolumes("demo", payload); err != nil {
		t.Fatalf("an official signed Redis digest must be accepted on a fresh host: %v", err)
	}
	if _, err := infrastructureVolumes("demo", payload, payload); err != nil {
		t.Fatalf("the exact retained Redis image was refused: %v", err)
	}
	stubInfrastructureVersions(t, map[string]string{legacy.image: "7.4.5"})
	drift := strings.Replace(string(payload), legacy.image, "registry.invalid/redis:7.4.5-alpine@sha256:"+strings.Repeat("c", 64), 1)
	if _, err := infrastructureVolumes("demo", []byte(drift), payload); err == nil {
		t.Fatal("an image outside the official repository was accepted")
	}
}

// stubInfrastructureVersions answers the helper's image version lookup from a
// table, so no test pulls an image. An image missing from the table fails the
// lookup the way an unreachable or unknown digest does on a host.
func stubInfrastructureVersions(t *testing.T, versions map[string]string) *[]string {
	t.Helper()
	asked := []string{}
	original := infrastructureImageVersion
	infrastructureImageVersion = func(image, versionEnv string) (string, error) {
		asked = append(asked, image)
		if versionEnv != "REDIS_VERSION" && versionEnv != "RABBITMQ_VERSION" {
			t.Fatalf("unexpected version variable %q", versionEnv)
		}
		if version, ok := versions[image]; ok {
			return version, nil
		}
		return "", errors.New("manifest unknown")
	}
	t.Cleanup(func() { infrastructureImageVersion = original })
	return &asked
}

// The case that blocked a production deploy: an application kept on redis
// 7.4.5 by production.redis_image could not take 7.4.11, because the helper
// accepted only the release pin (redis 8) or the exact retained image.
func TestInfrastructureVolumesAcceptANewerPatchOfTheRetainedMajor(t *testing.T) {
	retained := infrastructureRuntimeFor("redis")
	retained.image = "redis:7.4.5-alpine@sha256:" + strings.Repeat("b", 64)
	retainedStack := []byte("services:\n" + infrastructureServicePayload(retained, "demo", retained.user()))
	newer := "redis:7.4-alpine@sha256:" + strings.Repeat("d", 64)
	stubInfrastructureVersions(t, map[string]string{retained.image: "7.4.5", newer: "7.4.11"})

	candidate := strings.Replace(string(retainedStack), retained.image, newer, 1)
	volumes, err := infrastructureVolumes("demo", []byte(candidate), retainedStack)
	if err != nil {
		t.Fatalf("a newer 7.4 patch of the retained redis was refused: %v", err)
	}
	if len(volumes) != 1 || volumes[0] != (infrastructureVolume{name: "demo_redis_data", uid: 999, gid: 1000}) {
		t.Fatalf("unexpected infrastructure ownership: %#v", volumes)
	}
}

func TestInfrastructureVolumesRefuseUnsafeRuntimeChanges(t *testing.T) {
	retained := infrastructureRuntimeFor("redis")
	retained.image = "redis:7.4.5-alpine@sha256:" + strings.Repeat("b", 64)
	retainedStack := []byte("services:\n" + infrastructureServicePayload(retained, "demo", retained.user()))
	digest := func(c string) string { return "@sha256:" + strings.Repeat(c, 64) }
	versions := map[string]string{
		retained.image:                     "7.4.5",
		"redis:7.4-alpine" + digest("1"):   "8.0.2", // the tag lies; the image is redis 8
		"redis:7.4.2-alpine" + digest("2"): "7.4.2",
		"redis:7.2-alpine" + digest("3"):   "7.2.9",
		"redis:7.4-alpine" + digest("4"):   "7.4.11-rc1",
	}
	asked := stubInfrastructureVersions(t, versions)
	for name, image := range map[string]string{
		"a major step hidden behind a 7.4 tag": "redis:7.4-alpine" + digest("1"),
		"a downgrade":                          "redis:7.4.2-alpine" + digest("2"),
		"an older minor":                       "redis:7.2-alpine" + digest("3"),
		"a pre-release":                        "redis:7.4-alpine" + digest("4"),
		"an unknown digest":                    "redis:7.4-alpine" + digest("5"),
		"another registry":                     "registry.invalid/redis:7.4.11" + digest("6"),
		"another repository":                   "valkey:8.1" + digest("7"),
		"a mutable tag":                        "redis:7.4.11-alpine",
	} {
		candidate := strings.Replace(string(retainedStack), retained.image, image, 1)
		if _, err := infrastructureVolumes("demo", []byte(candidate), retainedStack); err == nil {
			t.Fatalf("%s was accepted: %s", name, image)
		}
	}
	for _, image := range *asked {
		if strings.Contains(image, "registry.invalid") || strings.HasPrefix(image, "valkey") || !strings.Contains(image, "@sha256:") {
			t.Fatalf("an image the reference check refuses was pulled: %s", image)
		}
	}

	// A first deployment accepts its signed official digest without a baked floor.
	candidate := strings.Replace(string(retainedStack), retained.image, "redis:7.4.5-alpine"+digest("2"), 1)
	if _, err := infrastructureVolumes("demo", []byte(candidate)); err != nil {
		t.Fatalf("a signed official digest was refused without a retained runtime: %v", err)
	}
}

func TestParseInfrastructureVersion(t *testing.T) {
	for value, want := range map[string][]int{"7.4.11": {7, 4, 11}, "8.0": {8, 0, 0}, "4.3.5": {4, 3, 5}} {
		got, ok := parseInfrastructureVersion(value)
		if !ok || !slices.Equal(got, want) {
			t.Fatalf("%s parsed as %v, %v", value, got, ok)
		}
	}
	for _, value := range []string{"", "7", "7.4.11.1", "7.4.11-rc1", "7.04.1", "v7.4.1", "7..1"} {
		if _, ok := parseInfrastructureVersion(value); ok {
			t.Fatalf("%q parsed as a release version", value)
		}
	}
}

// The helper chowns the named volume to one fixed account, which is only the
// right owner for the account the container assumes. A payload declaring
// another one — or none, as every stack signed before this — must be refused
// rather than handed a directory its service cannot open.
func TestInfrastructureVolumesRefuseAMismatchedUser(t *testing.T) {
	redis := infrastructureRuntimeFor("redis")
	for name, user := range map[string]string{"no user": "", "root": "0:0", "another account": "1000:1000"} {
		payload := "services:\n" + infrastructureServicePayload(redis, "demo", user)
		if _, err := infrastructureVolumes("demo", []byte(payload)); err == nil {
			t.Fatalf("redis running as %q must be refused", name)
		}
	}
}

func TestSSHDDropInIncludeWins(t *testing.T) {
	for name, config := range map[string]string{
		"debian default":  "Include /etc/ssh/sshd_config.d/*.conf\n\nPermitRootLogin prohibit-password\n",
		"relative path":   "Include sshd_config.d/*.conf\nPasswordAuthentication yes\n",
		"quoted glob":     "Include \"/etc/ssh/sshd_config.d/*.conf\"\nPermitRootLogin yes\n",
		"comments first":  "# vendor header\n\n#PermitRootLogin no\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
		"unowned keyword": "Port 22\nUsePAM yes\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
	} {
		if !sshdDropInIncludeWins([]byte(config)) {
			t.Fatalf("%s: the Shuttle drop-in should take precedence:\n%s", name, config)
		}
	}
}

func TestSSHDDropInIncludeLosesOrIsMissing(t *testing.T) {
	for name, config := range map[string]string{
		// The state a Hostinger "reset SSH" leaves behind.
		"no include":        "PermitRootLogin yes\nPasswordAuthentication yes\n",
		"include too late":  "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n",
		"allowusers first":  "AllowUsers admin\nInclude /etc/ssh/sshd_config.d/*.conf\n",
		"unrelated include": "Include /etc/ssh/other.d/*.conf\nPermitRootLogin yes\n",
		"commented include": "#Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n",
	} {
		if sshdDropInIncludeWins([]byte(config)) {
			t.Fatalf("%s: the Shuttle drop-in must not be trusted to win:\n%s", name, config)
		}
	}
}

// The stack-convergence wait used to be a 25 s constant compiled into the root
// helper, with no link to the budget the client measured against. It now comes
// from the signed plan, so a framework given a longer budget gets a longer
// convergence wait — and a plan carrying no budget still falls back to a bounded
// default instead of the constant.
func TestRootStackWaitsComeFromTheSignedPlan(t *testing.T) {
	php := rootplan.Plan{Stack: &rootplan.StackOperation{App: "demo", PromotionSLOSeconds: 45}}
	if got := rootStackWaits(php, config.PromotionModeLegacy); got != config.DeployWaits(45) {
		t.Errorf("a plan carrying a 45 s budget must size the privileged waits from it, got %+v", got)
	}
	if got := rootStackWaits(php, config.PromotionModeCapped); got != config.SwarmWaits(45, config.PromotionModeCapped) {
		t.Errorf("the capped mode must size the privileged waits from the same budget, got %+v", got)
	}
	legacy := rootplan.Plan{Stack: &rootplan.StackOperation{App: "demo"}}
	if got := rootStackWaits(legacy, config.PromotionModeLegacy); got != config.DeployWaits(config.DefaultDeploySLOSeconds("")) {
		t.Errorf("a plan without a budget must fall back to the shipped default, got %+v", got)
	}
}

func TestFirstReleaseGetsConvergenceFloorOnly(t *testing.T) {
	planned := config.DeployWaits(30).StackConvergence
	if planned != 16500*time.Millisecond {
		t.Fatalf("planned stack wait = %s, want 16.5s", planned)
	}
	if got := rootPromotionConvergenceWait(config.DeployWaits(30), true); got != config.FirstReleaseStackConvergenceFloor {
		t.Errorf("first release convergence wait = %s, want 120s", got)
	}
	if got := rootPromotionConvergenceWait(config.DeployWaits(30), false); got != planned {
		t.Errorf("later release convergence wait = %s, want planned %s", got, planned)
	}
}

func TestRegistryRestartWaitsForHealthAndV2(t *testing.T) {
	started, inspections, probes := false, 0, 0
	err := restartRootRegistryWithTimeout(time.Second, func() error {
		started = true
		return nil
	}, func(time.Duration) (string, error) {
		inspections++
		if inspections == 1 {
			return "starting", nil
		}
		return "healthy", nil
	}, func(time.Duration) error {
		probes++
		if probes == 1 {
			return errors.New("connection refused")
		}
		return nil
	}, func(time.Duration) { time.Sleep(time.Millisecond) })
	if err != nil {
		t.Fatalf("registry readiness wait failed: %v", err)
	}
	if !started || inspections < 3 || probes != 2 {
		t.Fatalf("restart evidence: started=%v inspections=%d probes=%d", started, inspections, probes)
	}
}

func TestRegistryRestartNeverHealthyReturnsLeftDownError(t *testing.T) {
	started := false
	err := restartRootRegistryWithTimeout(10*time.Millisecond, func() error {
		started = true
		return nil
	}, func(time.Duration) (string, error) { return "starting", nil }, func(time.Duration) error {
		t.Fatal("/v2/ must not be probed before Docker reports healthy")
		return nil
	}, time.Sleep)
	var leftDown *rootRegistryLeftDownError
	if !started || !errors.As(err, &leftDown) {
		t.Fatalf("unhealthy restart must fail through rootRegistryLeftDownError, started=%v err=%v", started, err)
	}
	if !strings.Contains(err.Error(), "did not become healthy") {
		t.Fatalf("readiness failure is not reported: %v", err)
	}
}

// Whatever a signed plan claims, the privileged waits it produces must stay far
// below the root-operation lock budget: a helper that blocks past it leaves the
// host unusable until the provider console is opened.
func TestRootStackWaitsStayBelowTheRootOperationBudget(t *testing.T) {
	for _, seconds := range []int{0, -1, rootplan.MinPromotionSLOSeconds, 45, rootplan.MaxPromotionSLOSeconds, 1 << 20} {
		for _, mode := range []config.PromotionMode{config.PromotionModeLegacy, config.PromotionModeCapped} {
			waits := rootStackWaits(rootplan.Plan{Stack: &rootplan.StackOperation{App: "demo", PromotionSLOSeconds: seconds}}, mode)
			// Only these two run under the root-operation lock; the origin proof and
			// the availability wait belong to the unprivileged client.
			privileged := waits.StackConvergence + waits.CaddyReload
			if privileged >= rootOperationBudget {
				t.Errorf("a plan claiming %d s produced %s of privileged waiting in the %s mode", seconds, privileged, mode)
			}
		}
	}
}

// A reload outside a budgeted promotion (stack removal) still has to be bounded,
// and by the same share the promotion allocates to it.
func TestDefaultCaddyReloadTimeoutMatchesTheShippedShare(t *testing.T) {
	want := config.DeployWaits(config.DefaultDeploySLOSeconds("")).CaddyReload
	if defaultCaddyReloadTimeout != want || defaultCaddyReloadTimeout <= 0 || defaultCaddyReloadTimeout > 30*time.Second {
		t.Errorf("default Caddy reload timeout is %s, want %s", defaultCaddyReloadTimeout, want)
	}
}

// The registry maintenance contract, in one place: the cache manifest the
// :buildcache tag currently points at survives, everything the retained stacks
// no longer reference goes, and the collector always runs.
func TestRegistryMaintenancePreservesTheCurrentBuildCache(t *testing.T) {
	current := "sha256:" + strings.Repeat("1", 64)
	previous := "sha256:" + strings.Repeat("2", 64)
	cache := "sha256:" + strings.Repeat("3", 64)
	stale := "sha256:" + strings.Repeat("4", 64)
	index := registryTagIndex{
		"demo-web": {
			"release-3":          current,
			"release-2":          previous,
			"release-1":          stale,
			rootRegistryCacheTag: cache,
		},
	}
	plan := planRootRegistryMaintenance(map[string]bool{current: true, previous: true}, index)
	for _, reference := range plan.DeleteManifests {
		if strings.HasSuffix(reference, cache) {
			t.Fatalf("the current build cache manifest must never be deleted: %s", reference)
		}
		if strings.HasSuffix(reference, current) || strings.HasSuffix(reference, previous) {
			t.Fatalf("a retained release manifest must never be deleted: %s", reference)
		}
	}
	if len(plan.DeleteManifests) != 1 || plan.DeleteManifests[0] != "demo-web@"+stale {
		t.Fatalf("the superseded release manifest must be deleted, got %v", plan.DeleteManifests)
	}
}

// The leak this fixes: every deploy rewrites :buildcache, so the manifest it
// used to point at becomes untagged. A tag walk cannot see it, so nothing was
// deleted and the collector was never even started — while a mode=max cache
// export costs 1 to 2 GB per PHP application per release. Maintenance must run
// the collector on every promotion, whether or not a tagged manifest was
// superseded, because only the collector can reclaim orphaned manifests.
func TestRegistryMaintenanceAlwaysCollectsOrphanedCacheManifests(t *testing.T) {
	cache := "sha256:" + strings.Repeat("3", 64)
	release := "sha256:" + strings.Repeat("1", 64)
	index := registryTagIndex{"demo-web": {"release-1": release, rootRegistryCacheTag: cache}}
	plan := planRootRegistryMaintenance(map[string]bool{release: true}, index)
	if len(plan.DeleteManifests) != 0 {
		t.Fatalf("nothing tagged is superseded here, got %v", plan.DeleteManifests)
	}
	if !plan.CollectGarbage {
		t.Fatal("the collector must run even when no tagged manifest was superseded, or orphaned cache manifests are never reclaimed")
	}
	args := rootRegistryGarbageCollectArgs()
	if !slices.Contains(args, "--delete-untagged") {
		t.Fatalf("without --delete-untagged the collector marks every manifest live and reclaims nothing: %v", args)
	}
	// The current cache is protected by being tagged, which is precisely why
	// the maintenance above may never delete that tag.
	if !slices.Contains(args, "garbage-collect") || args[len(args)-1] != "/etc/distribution/config.yml" {
		t.Fatalf("unexpected collector invocation: %v", args)
	}
}

// retention.registry_cache, applied. Under budget nothing is evicted, so a warm
// cache stays warm; over budget the build cache is the only thing dropped,
// because the retained release manifests are what `shuttle rollback` needs.
func TestRegistryCacheEvictionAppliesTheRetentionBudget(t *testing.T) {
	cache := "sha256:" + strings.Repeat("3", 64)
	release := "sha256:" + strings.Repeat("1", 64)
	index := registryTagIndex{"demo-web": {"release-1": release, rootRegistryCacheTag: cache}}
	if evicted := planRegistryCacheEviction(4<<30, 5<<30, index); len(evicted) != 0 {
		t.Fatalf("a registry under its budget must keep its cache, got %v", evicted)
	}
	if evicted := planRegistryCacheEviction(9<<30, 0, index); len(evicted) != 0 {
		t.Fatalf("no stated budget means no eviction, got %v", evicted)
	}
	evicted := planRegistryCacheEviction(9<<30, 5<<30, index)
	if len(evicted) != 1 || evicted[0] != "demo-web@"+cache {
		t.Fatalf("an over-budget registry must drop its build cache and only that, got %v", evicted)
	}
}

func TestDirectoryBytesMeasuresTheRegistryVolume(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docker/registry/v2/blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docker/registry/v2/blobs/data"), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "marker"), make([]byte, 96), 0o600); err != nil {
		t.Fatal(err)
	}
	size, err := directoryBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	if size != 4096+96 {
		t.Fatalf("measured %d bytes, want %d", size, 4096+96)
	}
}

// The address went to the published service alone, so a service holding a
// database password had no way to learn where to use it and fell back to the
// hostname baked into its image — a Compose service name that does not exist on
// a managed host:
//
//	psycopg.OperationalError: failed to resolve host 'agents-postgres'
func TestManagedDatabaseHostReachesEveryServiceHoldingAPassword(t *testing.T) {
	payload := []byte(`services:
  web:
    image: demo
    deploy:
      labels:
        dev.shuttle.postgres: "true"
  api:
    image: demo
    secrets:
      - source: demo_db_demo_agents_password_v1
        target: POSTGRES_PASSWORD_DEMO_AGENTS
  worker:
    image: demo
    secrets:
      - source: demo_postgres_password_v1
        target: POSTGRES_PASSWORD
  static:
    image: demo
`)
	out, changed, err := injectManagedDatabaseHost(payload, "172.17.0.1")
	if err != nil || !changed {
		t.Fatalf("injection must happen: changed=%v err=%v", changed, err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(out, &document); err != nil {
		t.Fatal(err)
	}
	services, _ := document["services"].(map[string]any)
	for _, name := range []string{"web", "api", "worker"} {
		service, _ := services[name].(map[string]any)
		environment, _ := service["environment"].(map[string]any)
		if environment["POSTGRES_HOST"] != "172.17.0.1" {
			t.Fatalf("%s must learn the managed database address, got %v", name, environment)
		}
	}
	// A service that holds no credential is not a service that connects.
	static, _ := services["static"].(map[string]any)
	if _, exists := static["environment"]; exists {
		t.Fatalf("a service without a database password must be untouched, got %v", static["environment"])
	}
}

// stackWithDigest is the shape a signed stack actually has: images pinned by
// digest, never by tag, because resolveRemoteRegistryDigests resolves them
// before the payload is signed.
func stackWithDigest(digest string) []byte {
	return []byte("services:\n  web:\n    image: " + rootRegistryImagePrefix + "demo-web@sha256:" + strings.Repeat(digest, 64) + "\n")
}

// A rebuild that resolves to the same digests produces a byte-identical stack.
// Rotating for such a promotion replaces the only rollback target with a copy of
// the release already serving, and `shuttle rollback` then redeploys the very
// release it was asked to undo. It also halves the digest set the registry
// maintenance protects, because rootRegistryKeepDigests reads both files.
func TestRedeployingAnIdenticalStackKeepsTheRollbackTarget(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current.yml")
	previous := filepath.Join(root, "previous.yml")
	older, release := stackWithDigest("a"), stackWithDigest("b")

	if err := writeRootFile(current, older, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{release, release} {
		if _, err := retainRollbackTarget(current, previous, payload); err != nil {
			t.Fatal(err)
		}
		if err := writeRootFile(current, payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	retained, err := os.ReadFile(previous)
	if err != nil {
		t.Fatal(err)
	}
	if string(retained) != string(older) {
		t.Fatalf("redeploying an unchanged stack destroyed the rollback target:\n%s", retained)
	}
	keep, err := rootRegistryKeepDigests(filepath.Join(root, "absent"), current, previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(keep) != 2 {
		t.Fatalf("both retained releases must protect their digests, got %d: %v", len(keep), keep)
	}
}

// The guard must not be mistaken for "never rotate": a genuinely changed stack
// rotates exactly as it did before, and a first promotion onto a host with no
// current.yml is not an error.
func TestRetainRollbackTargetRotatesOnAChangedStack(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current.yml")
	previous := filepath.Join(root, "previous.yml")

	if rotated, err := retainRollbackTarget(current, previous, stackWithDigest("b")); err != nil || rotated {
		t.Fatalf("a first promotion has nothing to retain: rotated=%v %v", rotated, err)
	}
	if _, err := os.Stat(previous); !os.IsNotExist(err) {
		t.Fatal("a first promotion must not invent a rollback target")
	}
	older := stackWithDigest("a")
	if err := writeRootFile(current, older, 0o600); err != nil {
		t.Fatal(err)
	}
	if rotated, err := retainRollbackTarget(current, previous, stackWithDigest("b")); err != nil || !rotated {
		t.Fatalf("a changed stack must report that it rotated: rotated=%v %v", rotated, err)
	}
	retained, err := os.ReadFile(previous)
	if err != nil || string(retained) != string(older) {
		t.Fatalf("a changed stack must rotate: %v %s", err, retained)
	}
}

// The node's image store is what actually holds the layers: deleting a registry
// manifest reclaims nothing, and Swarm never drops an image because the last
// task using it went away. The sweep must reclaim the releases this host has
// moved past and touch nothing else on the node.
func TestPruningTheImageStoreSparesRetainedAndForeignImages(t *testing.T) {
	keep := map[string]bool{"sha256:" + strings.Repeat("a", 64): true}
	entries := parseRootImageStore(strings.Join([]string{
		rootRegistryImagePrefix + "demo-web\tsha256:" + strings.Repeat("a", 64) + "\tsha256:1111",
		rootRegistryImagePrefix + "demo-api\tsha256:" + strings.Repeat("b", 64) + "\tsha256:2222",
		rootRegistryImagePrefix + "demo-api\tsha256:" + strings.Repeat("b", 64) + "\tsha256:2222",
		rootRegistryImagePrefix + "demo-web\t<none>\tsha256:3333",
		"postgres\tsha256:" + strings.Repeat("c", 64) + "\tsha256:4444",
		"127.0.0.1:5080/legacy-web\tsha256:" + strings.Repeat("d", 64) + "\tsha256:5555",
		"docker.umami.is/umami-software/umami\tsha256:" + strings.Repeat("e", 64) + "\tsha256:6666",
	}, "\n"))

	got := planRootImageStorePrune(keep, entries)
	if !slices.Equal(got, []string{"sha256:2222"}) {
		t.Fatalf("the sweep must reclaim only the superseded loopback image, got %v", got)
	}
}

// Anything the helper did not publish is out of its mandate, and an image the
// daemon reports without a digest cannot be matched against a retained stack —
// an image that cannot be proven unused is kept.
func TestImageStorePruneKeepsWhatItCannotProveUnused(t *testing.T) {
	entries := parseRootImageStore(strings.Join([]string{
		rootRegistryImagePrefix + "demo-web\t<none>\tsha256:1111",
		"redis\t<none>\tsha256:2222",
		"\tsha256:" + strings.Repeat("f", 64) + "\tsha256:3333",
	}, "\n"))
	if got := planRootImageStorePrune(map[string]bool{}, entries); len(got) != 0 {
		t.Fatalf("nothing here is provably unused, got %v", got)
	}
}

// The store lists one row per repository digest, so a local image can appear
// several times — pulled again under a new digest, or shared with a repository
// the helper has no mandate over. The daemon deletes by id and takes every row
// with it, so one row proving the image is still needed protects all of them.
func TestImageStorePruneProtectsAnIdentityAnyRowStillNeeds(t *testing.T) {
	retained := "sha256:" + strings.Repeat("a", 64)
	superseded := "sha256:" + strings.Repeat("b", 64)
	keep := map[string]bool{retained: true}
	entries := parseRootImageStore(strings.Join([]string{
		// One image, two repository digests, one of them still retained.
		rootRegistryImagePrefix + "demo-web\t" + retained + "\tsha256:1111",
		rootRegistryImagePrefix + "demo-web\t" + superseded + "\tsha256:1111",
		// One image the operator also tagged by hand: not the helper's to delete.
		rootRegistryImagePrefix + "demo-api\t" + superseded + "\tsha256:2222",
		"local/demo-api\t<none>\tsha256:2222",
		// Nothing vouches for this one.
		rootRegistryImagePrefix + "demo-worker\t" + superseded + "\tsha256:3333",
	}, "\n"))

	if got := planRootImageStorePrune(keep, entries); !slices.Equal(got, []string{"sha256:3333"}) {
		t.Fatalf("a shared image id must survive any row that still needs it, got %v", got)
	}
}

// An empty keep set is a host that could not read its own retained stacks, not
// a host with nothing to retain: rootStackRegistryDigests answers a malformed
// stack with no digests and no error. Sweeping on it would delete the serving
// release. Not knowing must stop the sweep.
func TestImageStorePruneRefusesToSweepOnAnEmptyKeepSet(t *testing.T) {
	entries := parseRootImageStore(strings.Join([]string{
		rootRegistryImagePrefix + "demo-web\tsha256:" + strings.Repeat("a", 64) + "\tsha256:1111",
		rootRegistryImagePrefix + "demo-api\tsha256:" + strings.Repeat("b", 64) + "\tsha256:2222",
	}, "\n"))
	if got := planRootImageStorePrune(map[string]bool{}, entries); len(got) != 0 {
		t.Fatalf("a host that cannot say what it retains must delete nothing, got %v", got)
	}
	if got := planRootImageStorePrune(nil, entries); len(got) != 0 {
		t.Fatalf("a nil keep set must delete nothing, got %v", got)
	}
}

// A repository that merely starts with the loopback host is not the loopback
// registry: 127.0.0.1:50001 is a different port and a different registry, and
// nothing there is the helper's to delete.
func TestImageStorePruneDoesNotMistakeANeighbouringPortForTheRegistry(t *testing.T) {
	keep := map[string]bool{"sha256:" + strings.Repeat("a", 64): true}
	entries := parseRootImageStore(strings.Join([]string{
		rootRegistryImagePrefix + "demo-web\tsha256:" + strings.Repeat("a", 64) + "\tsha256:1111",
		"127.0.0.1:50001/other-web\tsha256:" + strings.Repeat("b", 64) + "\tsha256:2222",
		"127.0.0.1:5080/legacy-web\tsha256:" + strings.Repeat("c", 64) + "\tsha256:3333",
	}, "\n"))
	if got := planRootImageStorePrune(keep, entries); len(got) != 0 {
		t.Fatalf("only the loopback registry is in scope, got %v", got)
	}
}

// Swarm's default task history keeps five finished tasks per service slot, and
// each one pins the image its task ran: a sweep that honours the daemon's
// refusal reclaims nothing for five releases. The limit is rewritten only when
// it differs, because every rewrite bumps the cluster spec version, and a value
// that cannot be read is corrected rather than trusted.
func TestSwarmTaskHistoryIsCorrectedOnlyWhenItDiffers(t *testing.T) {
	for reported, want := range map[string]bool{
		"2":          false,
		"2\n":        false,
		"5":          true,
		"0":          true,
		"":           true,
		"<no value>": true,
	} {
		if got := swarmTaskHistoryNeedsUpdate(reported); got != want {
			t.Errorf("reported %q: update=%v, want %v", reported, got, want)
		}
	}
}

// A stack the helper cannot read, or one naming a service it will not put on a
// docker command line, has to fail the wait immediately and say why. Waiting
// out the budget first would delay the emergency rollback for no information.
func TestWaitRootStackRefusesAStackItCannotVerify(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yml")
	err := waitRootStack("demo", missing, time.Now(), time.Second)
	if err == nil || !strings.Contains(err.Error(), "cannot be verified") {
		t.Fatalf("an unreadable stack must fail the wait with its reason, got %v", err)
	}
	invalid := filepath.Join(t.TempDir(), "stack.yml")
	if err := os.WriteFile(invalid, []byte("services:\n  web:\n    image: 127.0.0.1:5000/demo-web:latest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = waitRootStack("demo", invalid, time.Now(), time.Second)
	if err == nil || !strings.Contains(err.Error(), "not pinned by digest") {
		t.Fatalf("an image the wait cannot compare must be refused, got %v", err)
	}
}

// The budget is the only thing standing between a stack that will never
// converge and a helper that holds the root-operation lock until its watchdog
// fires. The wait must return inside it, and the message must name the service
// rather than just the stack — that message is all an operator gets back.
//
// No docker state is required: whatever this host answers (not a swarm manager,
// no such service, no docker at all), every answer is a legitimate "not
// converged yet" and the wait must still expire on time and say which service
// it was waiting for.
func TestWaitRootStackRespectsItsBudgetAndNamesTheService(t *testing.T) {
	stack := filepath.Join(t.TempDir(), "stack.yml")
	payload := "services:\n  web:\n    image: 127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("c", 64) + "\n    deploy:\n      replicas: 1\n"
	if err := os.WriteFile(stack, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	budget := 300 * time.Millisecond
	started := time.Now()
	err := waitRootStack("shuttletest", stack, started, budget)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("a service that is not running the applied release must fail the wait")
	}
	if !strings.Contains(err.Error(), "did not converge within") || !strings.Contains(err.Error(), "shuttletest_web") {
		t.Errorf("the message must name the stack and the service that did not converge, got %v", err)
	}
	// The budget plus the bounded diagnostic pass that follows it. Generous
	// because a cold docker CLI is slow, tight enough to catch a wait that has
	// stopped honouring its deadline at all.
	if ceiling := budget + rootConvergenceDiagnosticBudget + 10*time.Second; elapsed > ceiling {
		t.Errorf("the wait took %s for a %s budget; it must never outlive it by more than the diagnostic tail", elapsed, ceiling)
	}
}

// The wait is now the only one that covers real work, and it runs inside a
// single SSH session whose transport deadline was a flat two minutes. That
// deadline has to cover both privileged waits, and still land inside the
// helper's own watchdog so a genuinely stuck host answers with the helper's
// message — which names the service — instead of an opaque SSH timeout.
func TestSignedStackSessionOutlivesThePrivilegedWaits(t *testing.T) {
	for _, seconds := range []int{config.MinDeploySLOSeconds, 30, 45, 120, 200, config.MaxDeploySLOSeconds} {
		waits := config.DeployWaits(seconds)
		session := rootHelperOperationTimeout(seconds)
		if session <= waits.StackConvergence+waits.CaddyReload {
			t.Errorf("a %d s budget authorises %s of privileged waiting inside a %s session", seconds, waits.StackConvergence+waits.CaddyReload, session)
		}
		if session >= rootOperationBudget {
			t.Errorf("a %d s budget produced a %s session, past the helper's own %s watchdog", seconds, session, rootOperationBudget)
		}
	}
}

func TestFirstReleaseSSHCeilingCoversConvergenceFloor(t *testing.T) {
	waits := config.DeployWaits(30)
	want := config.FirstReleaseStackConvergenceFloor + waits.CaddyReload + hashvaultPromotionConfirmBudget + rootHelperOperationMargin
	if got := rootHelperOperationTimeout(30); got != want {
		t.Fatalf("SSH ceiling = %s, want %s to cover first-release convergence and remaining waits", got, want)
	}
}

// writeRootFile must sync the parent directory after the rename: the journal
// already names the new current.yml, so a power cut must not bring the old
// directory entry back.
func TestWriteRootFileSyncsParentDirectoryAfterRename(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "current.yml")
	if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := syncRootFileDirectory
	t.Cleanup(func() { syncRootFileDirectory = original })
	var synced []string
	var bodyAtSync string
	syncRootFileDirectory = func(path string) error {
		synced = append(synced, path)
		body, err := os.ReadFile(target)
		if err != nil {
			return err
		}
		bodyAtSync = string(body)
		return nil
	}
	if err := writeRootFile(target, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != directory {
		t.Fatalf("directory syncs = %v, want exactly [%s]", synced, directory)
	}
	if bodyAtSync != "new\n" {
		t.Fatalf("target held %q when the directory was synced, want the renamed body", bodyAtSync)
	}
}

func TestWriteRootFileReturnsDirectorySyncFailure(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "previous.yml")
	original := syncRootFileDirectory
	t.Cleanup(func() { syncRootFileDirectory = original })
	failure := errors.New("injected sync failure")
	syncRootFileDirectory = func(string) error { return failure }
	err := writeRootFile(target, []byte("new\n"), 0o600)
	if !errors.Is(err, failure) {
		t.Fatalf("writeRootFile error = %v, want the injected sync failure", err)
	}
	if !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("error %q does not say the file was already replaced", err)
	}
	if !errors.Is(err, errRootFileNotDurable) {
		t.Fatalf("error %v does not carry errRootFileNotDurable", err)
	}
	if body, readErr := os.ReadFile(target); readErr != nil || string(body) != "new\n" {
		t.Fatalf("target = %q, %v after the sync error, want the renamed new body", body, readErr)
	}
}

func writeSwapFixture(t *testing.T) (current, previous string) {
	t.Helper()
	directory := t.TempDir()
	current = filepath.Join(directory, "current.yml")
	previous = filepath.Join(directory, "previous.yml")
	if err := os.WriteFile(current, []byte("undone-release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, []byte("rollback-target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return current, previous
}

func assertSwapped(t *testing.T, current, previous string) {
	t.Helper()
	// Before the swap current.yml holds the release being undone and previous.yml
	// the rollback target that was just deployed; after it the rollback target
	// must sit in current.yml and the undone release in previous.yml.
	for path, want := range map[string]string{current: "rollback-target\n", previous: "undone-release\n"} {
		if body, err := os.ReadFile(path); err != nil || string(body) != want {
			t.Fatalf("%s = %q, %v, want %q", path, body, err, want)
		}
	}
}

func TestSwapRetainedStacksSwapsBothFiles(t *testing.T) {
	current, previous := writeSwapFixture(t)
	original := syncRootFileDirectory
	t.Cleanup(func() { syncRootFileDirectory = original })
	syncRootFileDirectory = func(string) error { return nil }
	identical, err := swapRetainedStacks(current, previous)
	if err != nil {
		t.Fatal(err)
	}
	if identical {
		t.Fatal("distinct bodies were reported identical")
	}
	assertSwapped(t, current, previous)
}

// A directory sync that fails after the first rename must not skip the second
// write: both slots would hold the rollback target and the undone release
// would be lost.
func TestSwapRetainedStacksFinishesAfterFirstSyncFailure(t *testing.T) {
	current, previous := writeSwapFixture(t)
	original := syncRootFileDirectory
	t.Cleanup(func() { syncRootFileDirectory = original })
	failure := errors.New("injected sync failure")
	calls := 0
	syncRootFileDirectory = func(string) error {
		calls++
		if calls == 1 {
			return failure
		}
		return nil
	}
	_, err := swapRetainedStacks(current, previous)
	if !errors.Is(err, errRootFileNotDurable) || !errors.Is(err, failure) {
		t.Fatalf("swap error = %v, want errRootFileNotDurable wrapping the injected failure", err)
	}
	if calls != 2 {
		t.Fatalf("directory syncs = %d, want 2 (the second write must still happen)", calls)
	}
	assertSwapped(t, current, previous)
}

// The listing asks the daemon for stopped Swarm task containers only, and the
// inspect pass stops at its budget: containers left uninspected are kept.
func TestRootImageStoreSweepFiltersListingAndBoundsInspectPass(t *testing.T) {
	setRootImageStoreSweepSeams(t)
	retained := "sha256:" + strings.Repeat("a", 64)
	superseded := "sha256:" + strings.Repeat("c", 64)
	rootImageStoreKeepDigests = func(string, string) (map[string]bool, error) {
		return map[string]bool{retained: true}, nil
	}
	start := time.Date(2026, 10, 27, 20, 0, 0, 0, time.UTC)
	clock := start
	rootImageStoreNow = func() time.Time { return clock }
	inspected := 0
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:3], " ") {
		case "image ls --all":
			return rootRegistryImagePrefix + "demo-web\t" + superseded + "\t" + superseded + "\n", nil
		case "container ls --all":
			joined := strings.Join(args, " ")
			for _, filter := range []string{"status=exited", "status=dead", "label=com.docker.swarm.task.id"} {
				if !strings.Contains(joined, filter) {
					t.Fatalf("container listing lacks filter %s: %v", filter, args)
				}
			}
			return "container-1\ncontainer-2\n", nil
		case "container inspect --format":
			inspected++
			// The first inspect consumes the whole budget.
			clock = start.Add(rootImageStoreInspectBudget)
			return args[len(args)-1] + "\texited\t" + superseded + "\ttask-1", nil
		case "ps --all --quiet":
			return "", nil
		default:
			t.Fatalf("unexpected docker value args: %v", args)
			return "", nil
		}
	}
	var removed []string
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		removed = append(removed, strings.Join(args, " "))
		return nil
	}
	if err := pruneRootImageStore("current", "previous"); err != nil {
		t.Fatal(err)
	}
	if inspected != 1 {
		t.Fatalf("inspected %d containers, want 1 (budget exhausted after the first)", inspected)
	}
	if len(removed) == 0 || removed[0] != "container rm container-1" {
		t.Fatalf("removals = %v, want container-1 removed first and container-2 kept", removed)
	}
	for _, r := range removed {
		if strings.Contains(r, "container-2") {
			t.Fatalf("uninspected container was removed: %v", removed)
		}
	}
}

// The production template's separators are real tab characters, which is what
// parseRootContainers splits on: docker prints the template's bytes verbatim.
func TestRootImageStoreSweepInspectTemplateMatchesParser(t *testing.T) {
	if strings.Count(rootStoppedContainerInspectFormat, "\t") != 3 {
		t.Fatalf("inspect template has %d tab separators, want 3: %q", strings.Count(rootStoppedContainerInspectFormat, "\t"), rootStoppedContainerInspectFormat)
	}
	rendered := strings.NewReplacer(
		"{{.Id}}", "c1",
		"{{.State.Status}}", "exited",
		"{{.Image}}", "sha256:"+strings.Repeat("c", 64),
		`{{index .Config.Labels "com.docker.swarm.task.id"}}`, "task-1",
	).Replace(rootStoppedContainerInspectFormat)
	got := parseRootContainers(rendered)
	if len(got) != 1 || got[0].ID != "c1" || got[0].State != "exited" || got[0].TaskID != "task-1" {
		t.Fatalf("parsed %+v from rendered template %q", got, rendered)
	}
}

// An inspect starting just before the budget ends gets only the time left.
func TestRootImageStoreSweepInspectTimeoutNeverExceedsBudget(t *testing.T) {
	setRootImageStoreSweepSeams(t)
	retained := "sha256:" + strings.Repeat("a", 64)
	superseded := "sha256:" + strings.Repeat("c", 64)
	rootImageStoreKeepDigests = func(string, string) (map[string]bool, error) {
		return map[string]bool{retained: true}, nil
	}
	start := time.Date(2026, 10, 27, 20, 0, 0, 0, time.UTC)
	calls := 0
	rootImageStoreNow = func() time.Time {
		calls++
		if calls == 1 {
			return start
		}
		return start.Add(rootImageStoreInspectBudget - 2*time.Second)
	}
	var inspectTimeout time.Duration
	rootImageStoreDockerValue = func(timeout time.Duration, _ string, args ...string) (string, error) {
		switch strings.Join(args[:3], " ") {
		case "image ls --all":
			return rootRegistryImagePrefix + "demo-web\t" + superseded + "\t" + superseded + "\n", nil
		case "container ls --all":
			return "container-1\n", nil
		case "container inspect --format":
			inspectTimeout = timeout
			return "container-1\texited\t" + superseded + "\ttask-1", nil
		default:
			return "", nil
		}
	}
	rootImageStoreDockerCommand = func(string, ...string) error { return nil }
	if err := pruneRootImageStore("current", "previous"); err != nil {
		t.Fatal(err)
	}
	if inspectTimeout != 2*time.Second {
		t.Fatalf("inspect timeout = %s, want the 2s left in the budget", inspectTimeout)
	}
}

// Review finding: a raw-string template sent Docker a literal backslash-t,
// so no inspected row ever split into fields.
func TestRootInfraSweepContainerTemplateUsesRealTabs(t *testing.T) {
	if strings.Contains(rootInfraContainerInspectFormat, `\t`) || strings.Count(rootInfraContainerInspectFormat, "\t") != 10 {
		t.Fatalf("inspect template must separate its eleven fields with real tabs: %q", rootInfraContainerInspectFormat)
	}
}

func TestRootInfraSweepServiceWithoutImageAbortsTheKeepRead(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "app", "current.yml")
	caddy := filepath.Join(root, "caddy-stack.yml")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := "redis:8.10.3-alpine@sha256:" + strings.Repeat("a", 64)
	write(current, "services:\n  redis:\n    image: "+good+"\n  worker:\n    environment: {}\n")
	if _, err := readRootInfrastructureKeep(current, filepath.Join(root, "app", "previous.yml"), root, caddy); err == nil {
		t.Fatal("a retained service without an image must abort the keep read")
	}
	write(current, "services:\n  redis:\n    image: "+good+"\n")
	write(caddy, "services:\n  caddy:\n    deploy: {}\n")
	if _, err := readRootInfrastructureKeep(current, filepath.Join(root, "app", "previous.yml"), root, caddy); err == nil {
		t.Fatal("a Caddy stack service without an image must abort the keep read")
	}
}

func TestRootInfraSweepServiceInspectWithoutSpecImageAborts(t *testing.T) {
	previousValue := rootImageStoreDockerValue
	t.Cleanup(func() { rootImageStoreDockerValue = previousValue })
	for name, payload := range map[string]string{
		"empty Spec image":                   `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":""}}},"PreviousSpec":null}]`,
		"PreviousSpec present without image": `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"caddy:2@sha256:` + strings.Repeat("b", 64) + `"}}},"PreviousSpec":{"TaskTemplate":{"ContainerSpec":{}}}}]`,
	} {
		rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
			if len(args) > 1 && args[0] == "service" && args[1] == "ls" {
				return "svc1\n", nil
			}
			return payload, nil
		}
		if _, err := rootInfraServiceImages(); err == nil {
			t.Fatalf("%s: incomplete service inspection must abort", name)
		}
	}
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		if len(args) > 1 && args[0] == "service" && args[1] == "ls" {
			return "svc1\n", nil
		}
		return `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"caddy:2@sha256:` + strings.Repeat("b", 64) + `"}}},"PreviousSpec":null}]`, nil
	}
	if _, err := rootInfraServiceImages(); err != nil {
		t.Fatalf("a null PreviousSpec is absent, not an error: %v", err)
	}
}

func TestRootInfraSweepMalformedImageListingIsAnError(t *testing.T) {
	good := "redis\tsha256:" + strings.Repeat("a", 64) + "\tsha256:" + strings.Repeat("a", 64) + "\n<none>\t<none>\tsha256:" + strings.Repeat("c", 64) + "\n"
	entries, err := parseRootInfraImageStore(good)
	if err != nil || len(entries) != 2 || entries[1].Digest != "" {
		t.Fatalf("well-formed listing: entries=%+v err=%v", entries, err)
	}
	for _, bad := range []string{good + "rabbitmq\tsha256:x\n", good + "caddy\t\tsha256:" + strings.Repeat("d", 64) + "\n"} {
		if _, err := parseRootInfraImageStore(bad); err == nil {
			t.Fatalf("a malformed row must be an error: %q", bad)
		}
	}
}

// Review finding: Shuttle's standalone registry has no Swarm labels, so its
// inspect row ends with empty label fields; trimming the row ate the tabs and
// deferred every sweep. Such a row parses, and an eligible stopped infra task
// container next to it is still planned.
func TestRootInfraSweepParsesContainersWithoutSwarmLabels(t *testing.T) {
	for _, label := range []string{"", "<no value>"} {
		t.Run(fmt.Sprintf("label=%q", label), func(t *testing.T) { checkRootInfraUnlabelledContainer(t, label) })
	}
}

func checkRootInfraUnlabelledContainer(t *testing.T, label string) {
	setRootInfraSweepSeams(t)
	registryID, stoppedID := strings.Repeat("1", 64), strings.Repeat("2", 64)
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		if args[0] == "container" && args[1] == "ls" {
			return registryID + "\n" + stoppedID + "\n", nil
		}
		if args[0] == "container" && args[1] == "inspect" {
			switch args[len(args)-1] {
			case registryID:
				return registryID + "\trunning\tsha256:" + strings.Repeat("r", 64) + "\t" + label + "\t" + label + "\t" + label + "\n", nil
			case stoppedID:
				return stoppedID + "\texited\tsha256:" + strings.Repeat("q", 64) + "\ttask1\tshared_rabbitmq\tshared\n", nil
			}
		}
		t.Fatalf("unexpected read: %v", args)
		return "", nil
	}
	containers, err := rootInfraListContainers()
	if err != nil {
		t.Fatalf("a container without Swarm labels must parse: %v", err)
	}
	if len(containers) != 2 || containers[0].TaskID != "" || containers[0].Service != "" || containers[0].Namespace != "" || containers[1].Service != "shared_rabbitmq" {
		t.Fatalf("parsed containers = %+v", containers)
	}
	planned := planRootInfrastructureContainers(func(service, namespace string) bool { return service == "shared_rabbitmq" && namespace == "shared" }, map[string]bool{}, containers)
	if len(planned) != 1 || planned[0] != stoppedID {
		t.Fatalf("the eligible stopped infra container must still be planned: %v", planned)
	}
}

// A host's first deploy has no retained stack anywhere: the pre-deploy sweep
// has nothing to free and must not report a deferral (VM e2e, 2026-10-28).
// Retained files that exist but yield no digest still stop the sweep.
func TestPruneRootImageStoreFirstReleaseIsNothingToSweep(t *testing.T) {
	originalKeep, originalExist, originalValue := rootImageStoreKeepDigests, rootImageStoreRetainedStacksExist, rootImageStoreDockerValue
	t.Cleanup(func() {
		rootImageStoreKeepDigests, rootImageStoreRetainedStacksExist, rootImageStoreDockerValue = originalKeep, originalExist, originalValue
	})
	rootImageStoreKeepDigests = func(string, string) (map[string]bool, error) { return map[string]bool{}, nil }
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		t.Fatalf("no docker call expected, got %v", args)
		return "", nil
	}
	rootImageStoreRetainedStacksExist = func(string, string) (bool, error) { return false, nil }
	if err := pruneRootImageStore("/missing/current.yml", "/missing/previous.yml"); err != nil {
		t.Fatalf("first release sweep = %v, want nil", err)
	}
	rootImageStoreRetainedStacksExist = func(string, string) (bool, error) { return true, nil }
	if err := pruneRootImageStore("/x/current.yml", "/x/previous.yml"); err == nil {
		t.Fatal("retained files without a digest must still stop the sweep")
	}
	dir := t.TempDir()
	if found, err := rootRetainedStackFilesExist(dir, filepath.Join(dir, "a", "current.yml"), filepath.Join(dir, "a", "previous.yml")); err != nil || found {
		t.Fatalf("empty state root = %v, %v", found, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other", "previous.yml"), []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := rootRetainedStackFilesExist(dir, filepath.Join(dir, "a", "current.yml"), filepath.Join(dir, "a", "previous.yml")); err != nil || !found {
		t.Fatalf("another app's retained file = %v, %v", found, err)
	}
}
