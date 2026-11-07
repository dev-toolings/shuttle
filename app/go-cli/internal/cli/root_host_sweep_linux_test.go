//go:build linux

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
)

func TestParseRootHostImageStore(t *testing.T) {
	listing := "<none>\t<none>\t<none>\tsha256:one\tunreadable\t12MB\n" +
		"docker.io/library/app\tv1\tsha256:two\tsha256:two\t2026-10-28 12:00:00 +0000 UTC\t1.2GB\n"
	entries, err := parseRootHostImageStore(listing)
	if err != nil || len(entries) != 2 {
		t.Fatalf("parsed entries=%+v err=%v", entries, err)
	}
	if entries[0].Repository != "" || entries[0].Tag != "" || entries[0].Digest != "" || !entries[0].Created.IsZero() {
		t.Fatalf("<none> or unparseable fields were not normalized safely: %+v", entries[0])
	}
	if entries[1].Repository != "docker.io/library/app" || entries[1].Tag != "v1" || entries[1].Created.IsZero() {
		t.Fatalf("valid image row parsed incorrectly: %+v", entries[1])
	}
	for _, malformed := range []string{"repo\ttag\tdigest\tid\ttime\n", "repo\ttag\tdigest\t\ttime\t1GB\n", "repo\ttag\tdigest\t<none>\ttime\t1GB\n", "repo\ttag\tdigest\tid\ttime\t"} {
		if _, err := parseRootHostImageStore(malformed); err == nil {
			t.Errorf("malformed row accepted: %q", malformed)
		}
	}
	unknownTimeProtection := rootHostProtection{
		HeldIDs:      map[string]bool{},
		Digests:      map[string]bool{},
		TagRefs:      map[string]bool{},
		ServiceRepos: map[string]bool{"repo": true},
	}
	if got := planRootHostImages(entries[:1], unknownTimeProtection, time.Now()); len(got) != 0 {
		t.Fatalf("an unparseable creation time was treated as old: %+v", got)
	}
}

func TestRootHostRepository(t *testing.T) {
	for ref, want := range map[string]string{
		"docker.io/library/uptime-kuma:2.5.7":        "uptime-kuma",
		"docker.io/mercure/mercure:latest@sha256:ab": "mercure/mercure",
		"ghcr.io/acme/tool:v3":                       "ghcr.io/acme/tool",
		"127.0.0.1:5000/demo-web:old":                "127.0.0.1:5000/demo-web",
	} {
		if got := rootHostRepository(ref); got != want {
			t.Errorf("rootHostRepository(%q)=%q, want %q", ref, got, want)
		}
	}
	if got := rootHostTagRef("docker.io/library/app:stable"); got != "app:stable" {
		t.Fatalf("normalized tag ref=%q", got)
	}
	if got := rootHostTagRef("app"); got != "app:latest" {
		t.Fatalf("implicit Docker tag ref=%q, want app:latest", got)
	}
	if got := rootHostTagRef("app:"); got != "" {
		t.Fatalf("invalid empty tag was normalized as %q", got)
	}
}

func TestRootHostTaskSlotFromLabels(t *testing.T) {
	tests := []struct {
		name, service, taskName, taskID, nodeID, taskSlot, want string
	}{
		{name: "replicated slot from task name", service: "app.web", taskName: "app.web.2.task-id", taskID: "task-id", nodeID: "node-a", want: "replica:2"},
		{name: "replicated slot from task slot", service: "app.web", taskName: "app.web.2", nodeID: "node-a", taskSlot: "2", want: "replica:2"},
		{name: "replicated task slot without task name", service: "app.web", taskID: "task-id", taskSlot: "2", want: "replica:2"},
		{name: "global task on this node", service: "app.web", taskName: "app.web.node-a.task-id", taskID: "task-id", nodeID: "node-a", taskSlot: "0", want: "node:node-a"},
		{name: "global slot without task name", service: "app.web", taskID: "task-id", nodeID: "node-a", taskSlot: "0", want: "node:node-a"},
		{name: "missing task name", service: "app.web", taskID: "task-id", nodeID: "node-a", want: ""},
		{name: "wrong task id", service: "app.web", taskName: "app.web.2.other-task", taskID: "task-id", nodeID: "node-a", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rootHostTaskSlot(test.service, test.taskName, test.taskID, test.nodeID, test.taskSlot); got != test.want {
				t.Fatalf("slot identity=%q, want %q", got, test.want)
			}
		})
	}
}

func TestRootSwarmServiceImageRefsIncludesBothSpecs(t *testing.T) {
	original := rootImageStoreDockerValue
	t.Cleanup(func() { rootImageStoreDockerValue = original })
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		if slices.Equal(args, []string{"service", "ls", "--format", "{{.ID}}"}) {
			return "service-id\n", nil
		}
		if slices.Equal(args, []string{"service", "inspect", "service-id"}) {
			return `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"app:current"}}},"PreviousSpec":{"TaskTemplate":{"ContainerSpec":{"Image":"app:previous@sha256:abc"}}}}]`, nil
		}
		t.Fatalf("unexpected docker read: %v", args)
		return "", nil
	}
	refs, err := rootSwarmServiceImageRefs()
	if err != nil || !slices.Equal(refs, []string{"app:current", "app:previous@sha256:abc"}) {
		t.Fatalf("service refs=%v err=%v", refs, err)
	}
}

func TestRootHostRepositorySwitchKeepsOldRepositoryTags(t *testing.T) {
	originalValue := rootImageStoreDockerValue
	originalNow := rootImageStoreNow
	t.Cleanup(func() {
		rootImageStoreDockerValue = originalValue
		rootImageStoreNow = originalNow
	})
	rootImageStoreNow = time.Now
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch {
		case slices.Equal(args, []string{"service", "ls", "--format", "{{.ID}}"}):
			return "service-id\n", nil
		case slices.Equal(args, []string{"service", "inspect", "service-id"}):
			return `[ {"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"repo-b:current"}}},"PreviousSpec":{"TaskTemplate":{"ContainerSpec":{"Image":"repo-a:rollback"}}}} ]`, nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
	pairs, err := rootSwarmServiceImageRefPairs()
	if err != nil || len(pairs) != 1 || pairs[0].current != "repo-b:current" || pairs[0].previous != "repo-a:rollback" {
		t.Fatalf("service ref pairs=%+v err=%v", pairs, err)
	}
	protect := rootHostProtection{
		HeldIDs:      map[string]bool{},
		Digests:      map[string]bool{},
		TagRefs:      map[string]bool{},
		ServiceRepos: map[string]bool{},
	}
	if err := addRootHostServiceProtection(&protect, []string{pairs[0].current}, []string{pairs[0].previous}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	entries := []rootHostImageEntry{
		{Repository: "repo-a", Tag: "unrelated", ID: "repo-a-unrelated", Created: old},
		{Repository: "repo-a", Tag: "rollback", ID: "repo-a-rollback", Created: old},
		{Repository: "repo-b", Tag: "old", ID: "repo-b-old", Created: old},
	}
	got := planRootHostImages(entries, protect, now)
	if len(got) != 1 || got[0].ID != "repo-b-old" {
		t.Fatalf("planned images after repository switch=%+v, want only repo-b-old", got)
	}
}

func TestPlanRootHostImagesKeepsUnusedDigestOnlyRepository(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	protect := rootHostProtection{
		HeldIDs:      map[string]bool{},
		Digests:      map[string]bool{},
		TagRefs:      map[string]bool{},
		ServiceRepos: map[string]bool{"current/repo": true},
	}
	entry := rootHostImageEntry{
		Repository: "unused/repo",
		Digest:     "sha256:unused",
		ID:         "digest-only-unused",
		Created:    now.Add(-48 * time.Hour),
	}
	if got := planRootHostImages([]rootHostImageEntry{entry}, protect, now); len(got) != 0 {
		t.Fatalf("unused digest-only image was planned for removal: %+v", got)
	}
}

func TestPlanRootHostImagesIncidentFixture(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	image := func(repository, tag, id string, created time.Time) rootHostImageEntry {
		return rootHostImageEntry{Repository: repository, Tag: tag, ID: id, Size: "900MB", Created: created}
	}
	entries := []rootHostImageEntry{
		image("uptime-kuma", "2.5.3", "id-uptime-253", old),
		image("uptime-kuma", "2.5.6", "id-uptime-256", old),
		image("uptime-kuma", "2.5.7", "id-uptime-257", old),
		image("mercure-hub", "v1", "id-mercure-1", old),
		image("mercure-hub", "v2", "id-mercure-2", old),
		image("mercure-hub", "v3", "id-mercure-3", old),
		image("mercure-hub", "v4", "id-mercure-4", old),
		image("mercure-hub", "v5", "id-mercure-5", old),
		image("rabbitmq", "4.3.7-management-alpine", "id-rabbit-old", old),
		image("rabbitmq", "4-management-alpine", "id-rabbit-current", old),
		image("caddy", "2.8.4-alpine", "id-caddy-old", old),
		image("127.0.0.1:5000/demo/web", "release-old", "id-loopback", old),
		image("uptime-kuma", "2.5.8", "id-uptime-recent", now.Add(-6*time.Hour)),
		image("cron-tool", "1.0", "id-inactive-repository", old),
	}
	protect := rootHostProtection{
		HeldIDs:      map[string]bool{},
		Digests:      map[string]bool{},
		TagRefs:      map[string]bool{"uptime-kuma:2.5.7": true, "mercure-hub:v5": true, "rabbitmq:4-management-alpine": true},
		ServiceRepos: map[string]bool{"uptime-kuma": true, "mercure-hub": true, "rabbitmq": true, "caddy": true},
	}
	var refs []string
	for _, removal := range planRootHostImages(entries, protect, now) {
		refs = append(refs, removal.Refs...)
	}
	slices.Sort(refs)
	want := []string{
		"caddy:2.8.4-alpine",
		"mercure-hub:v1",
		"mercure-hub:v2",
		"mercure-hub:v3",
		"mercure-hub:v4",
		"rabbitmq:4.3.7-management-alpine",
		"uptime-kuma:2.5.3",
		"uptime-kuma:2.5.6",
	}
	if !slices.Equal(refs, want) {
		t.Fatalf("planned refs=%v, want %v", refs, want)
	}
}

func TestPlanRootHostImagesNeverRemovesProtected(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	entry := func(tag, id, digest string) rootHostImageEntry {
		return rootHostImageEntry{Repository: "example.test/app", Tag: tag, ID: id, Digest: digest, Size: "1GB", Created: old}
	}
	entries := []rootHostImageEntry{
		entry("running", "held-running", "sha256:1"),
		entry("created", "held-created", "sha256:2"),
		entry("exited", "held-exited", "sha256:3"),
		entry("release", "held-release", "sha256:retained"),
		entry("infra", "held-infra", "sha256:infra"),
		entry("previous", "held-previous", "sha256:previous"),
		entry("service-tag", "held-tag", "sha256:tag"),
		entry("service-tag", "held-multitag", "sha256:multi"),
		entry("old-alias", "held-multitag", "sha256:other"),
		entry("known-age", "held-unknown-age", "sha256:age-known"),
		{Repository: "example.test/app", Tag: "unknown-age", ID: "held-unknown-age", Size: "1GB"},
		entry("unused", "eligible", "sha256:eligible"),
	}
	protect := rootHostProtection{
		HeldIDs:      map[string]bool{"held-running": true, "held-created": true, "held-exited": true},
		Digests:      map[string]bool{"sha256:retained": true, "sha256:infra": true, "sha256:previous": true},
		TagRefs:      map[string]bool{"example.test/app:service-tag": true},
		ServiceRepos: map[string]bool{"example.test/app": true},
	}
	got := planRootHostImages(entries, protect, now)
	if len(got) != 1 || got[0].ID != "eligible" || !slices.Equal(got[0].Refs, []string{"example.test/app:unused"}) {
		t.Fatalf("protected rows were planned: %+v", got)
	}
}

func TestPlanRootHostTaskContainers(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	containers := []rootInfraContainerEntry{
		{ID: "live", State: "running", ImageID: "sha256:current", TaskID: "task-live", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: now.Add(-time.Hour)},
		{ID: "old-task", State: "exited", ImageID: "sha256:old", TaskID: "task-old", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: now.Add(-2 * time.Hour)},
		{ID: "crash-loop", State: "exited", ImageID: "sha256:crash", TaskID: "task-crash", Service: "app_crash", ServiceID: "service-crash", Slot: "replica:1", Created: now.Add(-2 * time.Hour)},
		{ID: "same-live-image", State: "exited", ImageID: "sha256:shared", TaskID: "task-old-shared", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: now.Add(-2 * time.Hour)},
		{ID: "created-live-image", State: "created", ImageID: "sha256:shared"},
		{ID: "manual", State: "exited", ImageID: "sha256:manual", Service: "app_web"},
	}
	got := planRootHostTaskContainers(map[string]bool{}, containers)
	if !slices.Equal(got, []string{"old-task"}) {
		t.Fatalf("planned task containers=%v, want [old-task]", got)
	}
}

func TestPlanRootHostTaskContainersRequiresNewerTaskInSameSlot(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Hour)
	newer := now.Add(-time.Hour)
	tests := []struct {
		name       string
		stopped    rootInfraContainerEntry
		running    rootInfraContainerEntry
		wantRemove bool
	}{
		{
			name:       "same slot with newer running replacement",
			stopped:    rootInfraContainerEntry{ID: "old-slot-1", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: old},
			running:    rootInfraContainerEntry{ID: "running-slot-1", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: newer},
			wantRemove: true,
		},
		{
			name:    "different slot does not authorize removal",
			stopped: rootInfraContainerEntry{ID: "old-slot-2", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:2", Created: old},
			running: rootInfraContainerEntry{ID: "running-slot-1", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: newer},
		},
		{
			name:    "same service name with different service identity is kept",
			stopped: rootInfraContainerEntry{ID: "old-service", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_web", ServiceID: "old-service-id", Slot: "replica:1", Created: old},
			running: rootInfraContainerEntry{ID: "running-service", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_web", ServiceID: "new-service-id", Slot: "replica:1", Created: newer},
		},
		{
			name:    "missing slot is kept",
			stopped: rootInfraContainerEntry{ID: "unknown-slot", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_web", ServiceID: "service-web", Created: old},
			running: rootInfraContainerEntry{ID: "running-slot-1", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: newer},
		},
		{
			name:    "older running task does not authorize removal",
			stopped: rootInfraContainerEntry{ID: "newer-stopped", State: "exited", ImageID: "sha256:old", TaskID: "new-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: newer},
			running: rootInfraContainerEntry{ID: "older-running", State: "running", ImageID: "sha256:new", TaskID: "old-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: old},
		},
		{
			name:       "newer global task on same node",
			stopped:    rootInfraContainerEntry{ID: "old-global", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_global", ServiceID: "service-global", Slot: "node:node-a", Created: old},
			running:    rootInfraContainerEntry{ID: "running-global", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_global", ServiceID: "service-global", Slot: "node:node-a", Created: newer},
			wantRemove: true,
		},
		{
			name:    "global task on another node does not authorize removal",
			stopped: rootInfraContainerEntry{ID: "old-global", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_global", ServiceID: "service-global", Slot: "node:node-a", Created: old},
			running: rootInfraContainerEntry{ID: "running-global", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_global", ServiceID: "service-global", Slot: "node:node-b", Created: newer},
		},
		{
			name:    "unknown creation time is kept",
			stopped: rootInfraContainerEntry{ID: "unknown-created", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1"},
			running: rootInfraContainerEntry{ID: "running-slot-1", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: newer},
		},
		{
			name:    "missing service identity is kept",
			stopped: rootInfraContainerEntry{ID: "unknown-service", State: "exited", ImageID: "sha256:old", TaskID: "old-task", Service: "app_web", Slot: "replica:1", Created: old},
			running: rootInfraContainerEntry{ID: "running-slot-1", State: "running", ImageID: "sha256:new", TaskID: "new-task", Service: "app_web", ServiceID: "service-web", Slot: "replica:1", Created: newer},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := planRootHostTaskContainers(map[string]bool{}, []rootInfraContainerEntry{test.stopped, test.running})
			if test.wantRemove && !slices.Equal(got, []string{test.stopped.ID}) {
				t.Fatalf("planned containers=%v, want [%s]", got, test.stopped.ID)
			}
			if !test.wantRemove && len(got) != 0 {
				t.Fatalf("planned containers=%v, want none", got)
			}
		})
	}
}

func TestPruneRootHostImagesRemovesStoppedTaskContainersAndReportsServices(t *testing.T) {
	setRootHostSweepSeams(t)
	removedTask := false
	var containerListings int
	imageListing := rootHostListing("app", "old", "", "sha256:old", "2026-10-28 00:00:00 +0000 UTC", "1GB")
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch {
		case slices.Equal(args, []string{"service", "ls", "--format", "{{.ID}}"}):
			return "service-id\n", nil
		case slices.Equal(args, []string{"service", "inspect", "service-id"}):
			return rootHostServiceInspect("app:current@sha256:" + strings.Repeat("a", 64)), nil
		case len(args) >= 2 && args[0] == "container" && args[1] == "ls":
			containerListings++
			if removedTask {
				return "live\n", nil
			}
			return "old-task\nlive\n", nil
		case len(args) >= 2 && args[0] == "container" && args[1] == "inspect":
			id := args[len(args)-1]
			if id == "old-task" {
				return "old-task\texited\tsha256:old\ttask-old\tapp_web\tapp\tapp_web.1.task-old\tnode-a\t1\tservice-id\t2026-10-28T00:00:00Z", nil
			}
			return "live\trunning\tsha256:current\ttask-live\tapp_web\tapp\tapp_web.1.task-live\tnode-a\t1\tservice-id\t2026-10-29T00:00:00Z", nil
		case len(args) >= 2 && args[0] == "image" && args[1] == "ls":
			return imageListing, nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
	var removed []string
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		removed = append(removed, strings.Join(args, " "))
		if slices.Equal(args, []string{"container", "rm", "old-task"}) {
			removedTask = true
			return nil
		}
		if slices.Equal(args, []string{"image", "rm", "app:old"}) {
			return nil
		}
		t.Fatalf("unexpected docker removal: %v", args)
		return nil
	}
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	callErr := pruneRootHostImages("current", "previous", "operation", false)
	_ = writer.Close()
	os.Stderr = originalStderr
	reclaimed, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if callErr != nil || readErr != nil {
		t.Fatalf("prune err=%v stderr read err=%v", callErr, readErr)
	}
	wantCommands := []string{"container rm old-task", "image rm app:old"}
	if !slices.Equal(removed, wantCommands) {
		t.Fatalf("removal order=%v, want %v", removed, wantCommands)
	}
	if containerListings != 4 || !strings.Contains(string(reclaimed), "shuttle-root reclaimed: 1 stopped task containers (app_web)") {
		t.Fatalf("container listings=%d reclaimed=%q", containerListings, reclaimed)
	}
}

func TestPruneRootHostImagesUsesRealReaderForEmptyRetainedSetWithSwarmRefs(t *testing.T) {
	setRootHostSweepSeams(t)
	root := t.TempDir()
	stateRoot := filepath.Join(root, "apps")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(root, "current.yml")
	previousPath := filepath.Join(root, "previous.yml")
	caddyPath := filepath.Join(root, "missing-caddy.yml")
	keep, err := readRootInfrastructureKeep(currentPath, previousPath, stateRoot, caddyPath)
	if err != nil || keep.digests == nil || len(keep.digests) != 0 {
		t.Fatalf("real retained reader empty result=%+v err=%v", keep, err)
	}
	rootInfrastructureKeep = func(current, previous, _, _ string) (rootInfraKeepSet, error) {
		return readRootInfrastructureKeep(current, previous, stateRoot, caddyPath)
	}
	listing := rootHostListing("app", "old", "sha256:old", "sha256:old", "2026-10-28 00:00:00 +0000 UTC", "1GB")
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch {
		case slices.Equal(args, []string{"service", "ls", "--format", "{{.ID}}"}):
			return "service-id\n", nil
		case slices.Equal(args, []string{"service", "inspect", "service-id"}):
			return rootHostServiceInspect("app:current@sha256:" + strings.Repeat("a", 64)), nil
		case len(args) >= 2 && args[0] == "container" && args[1] == "ls":
			return "", nil
		case len(args) >= 2 && args[0] == "image" && args[1] == "ls":
			return listing, nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
	var removed []string
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		removed = append(removed, strings.Join(args, " "))
		return nil
	}
	if err := pruneRootHostImages(currentPath, previousPath, "operation", false); err != nil {
		t.Fatalf("host pass with empty retained set failed: %v", err)
	}
	if !slices.Equal(removed, []string{"image rm app:old"}) {
		t.Fatalf("removals=%v, want image rm app:old", removed)
	}
}

func TestPruneRootHostImagesRechecksBeforeRemoval(t *testing.T) {
	setRootHostSweepSeams(t)
	containerReads := 0
	imageListing := rootHostListing("docker.io/library/app", "old", "sha256:old", "sha256:old", "2026-10-28 00:00:00 +0000 UTC", "1GB")
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		switch {
		case slices.Equal(args, []string{"service", "ls", "--format", "{{.ID}}"}):
			return "service-id\n", nil
		case slices.Equal(args, []string{"service", "inspect", "service-id"}):
			return rootHostServiceInspect("docker.io/library/app:current@sha256:" + strings.Repeat("a", 64)), nil
		case len(args) >= 2 && args[0] == "container" && args[1] == "ls":
			containerReads++
			if containerReads == 2 {
				return "appeared\n", nil
			}
			return "", nil
		case len(args) >= 2 && args[0] == "image" && args[1] == "ls":
			return imageListing, nil
		case len(args) >= 2 && args[0] == "container" && args[1] == "inspect":
			return "appeared\trunning\tsha256:old\ttask-appeared\tapp_web\tapp\tapp_web.1.task-appeared\tnode-a\t1\tservice-id\t2026-10-29T00:00:00Z", nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		if slices.Contains(args, "--force") || slices.Contains(args, "-f") || slices.Contains(args, "prune") || strings.Contains(strings.Join(args, " "), "127.0.0.1:5000/") || strings.Contains(strings.Join(args, " "), "localhost:5000/") {
			t.Fatalf("forbidden docker command: %v", args)
		}
		t.Fatalf("unexpected removal despite fresh container hold: %v", args)
		return nil
	}
	if err := pruneRootHostImages("current", "previous", "operation", false); err != nil {
		t.Fatal(err)
	}
	if containerReads != 2 {
		t.Fatalf("container listings=%d, want initial and fresh reads", containerReads)
	}
}

func TestPruneRootHostImagesRemovesEveryTagRefWithoutForce(t *testing.T) {
	setRootHostSweepSeams(t)
	listing := strings.Join([]string{
		rootHostListing("docker.io/library/app", "old-a", "", "sha256:multi", "2026-10-28 00:00:00 +0000 UTC", "900MB"),
		rootHostListing("docker.io/library/app", "old-b", "", "sha256:multi", "2026-10-28 00:00:00 +0000 UTC", "900MB"),
	}, "")
	rootImageStoreDockerValue = hostSweepDockerReads(t, listing, func() string { return "" })
	var removed []string
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		if len(args) != 3 || args[0] != "image" || args[1] != "rm" || slices.Contains(args, "--force") || slices.Contains(args, "-f") || slices.Contains(args, "prune") {
			t.Fatalf("unexpected or unsafe removal: %v", args)
		}
		removed = append(removed, args[2])
		return nil
	}
	if err := pruneRootHostImages("current", "previous", "operation", false); err != nil {
		t.Fatal(err)
	}
	want := []string{"docker.io/library/app:old-a", "docker.io/library/app:old-b"}
	if !slices.Equal(removed, want) {
		t.Fatalf("image rm refs=%v, want %v", removed, want)
	}
}

func TestPruneRootHostImagesDefersWhileAnotherOperationRuns(t *testing.T) {
	setRootHostSweepSeams(t)
	rootImageStoreDockerValue = hostSweepDockerReads(t, rootHostListing("docker.io/library/app", "old", "", "sha256:old", "2026-10-28 00:00:00 +0000 UTC", "1GB"), func() string { return "" })
	rootInfraSoleOperation = func(string, func() error) error { return errors.New("another operation is active") }
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		t.Fatalf("image removed while another operation runs: %v", args)
		return nil
	}
	if err := pruneRootHostImages("current", "previous", "operation", true); err != nil {
		t.Fatalf("a held shared-operation fence is a deferral, got %v", err)
	}
}

func TestPruneRootHostImagesFailureIsAWarning(t *testing.T) {
	setRootHostSweepSeams(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	c := newRecoveryCoordinator(t, &now)
	h, request := reserveLiveDeploy(t, c, testRecoveryOpID)
	request.Name = "stack-reclaim"
	rootImageStoreDockerValue = func(_ time.Duration, _ string, args ...string) (string, error) {
		if len(args) >= 2 && args[0] == "service" && args[1] == "ls" {
			return "", errors.New("daemon unavailable")
		}
		t.Fatalf("unexpected docker read after failing service listing: %v", args)
		return "", nil
	}
	err := c.ExecutePhase(t.Context(), request, func(_ context.Context, _ coord.Record) error {
		return reclaimImageStoreBeforeDeploy("demo", func(run func() error) error { return run() }, func() error {
			return pruneRootHostImages("current", "previous", "operation", false)
		})
	})
	if err != nil {
		t.Fatalf("deferred host sweep blocked the deploy phase: %v", err)
	}
	record, err := c.Get(t.Context(), h.ID())
	if err != nil || record.State != "active" || !strings.Contains(record.Phases[0].Warning, "daemon unavailable") {
		t.Fatalf("host sweep failure was not recorded as a warning: record=%+v err=%v", record, err)
	}
	if err := h.Complete("test finished"); err != nil {
		t.Fatal(err)
	}
}

func TestReportRootHelperReclaims(t *testing.T) {
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	count := reportRootHelperReclaims("ordinary stderr\nshuttle-root reclaimed: image app:old (1GB)\nshuttle-root warning: deferred\nshuttle-root reclaimed: 2 stopped task containers (app_web, app_api)\n")
	_ = writer.Close()
	os.Stdout = original
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if count != 2 || strings.Count(string(output), "Image store: removed ") != 2 || strings.Contains(string(output), "ordinary stderr") || strings.Contains(string(output), "deferred") {
		t.Fatalf("reclaims=%d output=%q", count, output)
	}
}

func setRootHostSweepSeams(t *testing.T) {
	t.Helper()
	originalKeep := rootImageStoreKeepDigests
	originalRetained := rootImageStoreRetainedStacksExist
	originalNow := rootImageStoreNow
	originalValue := rootImageStoreDockerValue
	originalCommand := rootImageStoreDockerCommand
	originalShared := rootRetainedStacksShared
	originalSole := rootInfraSoleOperation
	originalInfrastructureKeep := rootInfrastructureKeep
	t.Cleanup(func() {
		rootImageStoreKeepDigests = originalKeep
		rootImageStoreRetainedStacksExist = originalRetained
		rootImageStoreNow = originalNow
		rootImageStoreDockerValue = originalValue
		rootImageStoreDockerCommand = originalCommand
		rootRetainedStacksShared = originalShared
		rootInfraSoleOperation = originalSole
		rootInfrastructureKeep = originalInfrastructureKeep
	})
	rootImageStoreKeepDigests = func(string, string) (map[string]bool, error) { return map[string]bool{}, nil }
	rootImageStoreRetainedStacksExist = func(string, string) (bool, error) { return false, nil }
	rootImageStoreNow = func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) }
	rootRetainedStacksShared = func(run func() error) error { return run() }
	rootInfraSoleOperation = func(_ string, run func() error) error { return run() }
	rootInfrastructureKeep = func(string, string, string, string) (rootInfraKeepSet, error) {
		return rootInfraKeepSet{digests: map[string]bool{}, appNamespaces: map[string]bool{}}, nil
	}
}

func hostSweepDockerReads(t *testing.T, images string, containerListing func() string) func(time.Duration, string, ...string) (string, error) {
	t.Helper()
	return func(_ time.Duration, _ string, args ...string) (string, error) {
		switch {
		case slices.Equal(args, []string{"service", "ls", "--format", "{{.ID}}"}):
			return "service-id\n", nil
		case slices.Equal(args, []string{"service", "inspect", "service-id"}):
			return rootHostServiceInspect("docker.io/library/app:current@sha256:" + strings.Repeat("a", 64)), nil
		case len(args) >= 2 && args[0] == "container" && args[1] == "ls":
			return containerListing(), nil
		case len(args) >= 2 && args[0] == "container" && args[1] == "inspect":
			t.Fatalf("unexpected container inspection: %v", args)
			return "", nil
		case len(args) >= 2 && args[0] == "image" && args[1] == "ls":
			if !slices.Equal(args, []string{"image", "ls", "--digests", "--no-trunc", "--format", rootHostImageListFormat}) {
				t.Fatalf("host image listing must omit intermediate layers: %v", args)
			}
			return images, nil
		default:
			t.Fatalf("unexpected docker read: %v", args)
			return "", nil
		}
	}
}

func rootHostListing(repository, tag, digest, id, created, size string) string {
	return strings.Join([]string{repository, tag, digest, id, created, size}, "\t") + "\n"
}

func rootHostServiceInspect(image string) string {
	return `[{"Spec":{"TaskTemplate":{"ContainerSpec":{"Image":"` + image + `"}}},"PreviousSpec":null}]`
}

// Docker 29 with the containerd image store names a Swarm-pulled image
// `busybox:1.36@sha256:...`; `docker image rm busybox:1.36` answers "No such
// image" (e2e, 30-10-2026). The pinned name is tried; an in-use refusal is not.
func TestRemoveRootHostImageRefFallsBackToPinnedDigestName(t *testing.T) {
	original := rootImageStoreDockerCommand
	t.Cleanup(func() { rootImageStoreDockerCommand = original })
	digest := "sha256:" + strings.Repeat("a", 64)
	var calls []string
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		ref := args[len(args)-1]
		calls = append(calls, ref)
		if ref == "busybox:1.36" {
			return errors.New("Error response from daemon: No such image: busybox:1.36")
		}
		return nil
	}
	if err := removeRootHostImageRef("busybox:1.36", []string{"busybox:1.36@" + digest, "busybox@" + digest}); err != nil {
		t.Fatalf("pinned fallback failed: %v", err)
	}
	if len(calls) != 2 || calls[1] != "busybox:1.36@"+digest {
		t.Fatalf("calls = %v", calls)
	}

	calls = nil
	rootImageStoreDockerCommand = func(_ string, args ...string) error {
		calls = append(calls, args[len(args)-1])
		return errors.New("Error response from daemon: conflict: unable to remove repository reference (must force) - container abc is using its referenced image")
	}
	if err := removeRootHostImageRef("busybox:1.36", []string{"busybox:1.36@" + digest}); err == nil || len(calls) != 1 {
		t.Fatalf("an in-use refusal must not try alternates: err=%v calls=%v", err, calls)
	}
}
