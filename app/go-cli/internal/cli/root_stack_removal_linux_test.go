//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestStackRemovalDrainsOnlyOwnedServicesBeforeNetworks(t *testing.T) {
	calls := [][]string{}
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		switch len(calls) {
		case 1:
			return []byte("owned-a\nowned-b\n"), nil
		case 2:
			return []byte("0\n0\n"), nil
		case 3:
			return nil, nil
		case 4, 5:
			return nil, nil
		}
		t.Fatal("unexpected command")
		return nil, nil
	}
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	if _, err := drainRootStackBeforeRemoval("recipe-node-api", run, func() time.Time { return current }, func(time.Duration) {}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"service", "ls", "--filter", "label=com.docker.stack.namespace=recipe-node-api", "--format", "{{.ID}}"},
		{"service", "inspect", "--format", "{{json .Spec.TaskTemplate.ContainerSpec.StopGracePeriod}}", "owned-a", "owned-b"},
		{"service", "rm", "owned-a", "owned-b"},
		{"ps", "-q", "--filter", "label=com.docker.stack.namespace=recipe-node-api"},
		{"ps", "-a", "-q", "--no-trunc", "--filter", "label=com.docker.stack.namespace=recipe-node-api"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unsafe drain sequence: %v", calls)
	}
}

func TestStackRemovalRefusesNetworksWhenDrainIsUnproven(t *testing.T) {
	for _, failure := range []string{"list", "grace", "stop", "inspect", "still-running"} {
		t.Run(failure, func(t *testing.T) {
			current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
			run := func(args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				if strings.HasPrefix(command, "service ls") && failure == "list" {
					return nil, errors.New("Docker unavailable")
				}
				if strings.HasPrefix(command, "service ls") && (failure == "grace" || failure == "stop") {
					return []byte("owned"), nil
				}
				if strings.HasPrefix(command, "service inspect") && failure == "grace" {
					return []byte("Docker unavailable"), errors.New("inspect failed")
				}
				if strings.HasPrefix(command, "service inspect") {
					return []byte("0"), nil
				}
				if strings.HasPrefix(command, "service rm") && failure == "stop" {
					return []byte("Docker unavailable"), errors.New("remove failed")
				}
				if strings.HasPrefix(command, "ps -q") && failure == "inspect" {
					return []byte("Docker unavailable"), errors.New("list containers failed")
				}
				if strings.HasPrefix(command, "ps -q") && failure == "still-running" {
					return []byte("task-not-stopped"), nil
				}
				return nil, nil
			}
			sleep := func(time.Duration) { current = current.Add(30 * time.Second) }
			_, err := drainRootStackBeforeRemoval("recipe-node-api", run, func() time.Time { return current }, sleep)
			if err == nil {
				t.Fatal("unproven drain must block network deletion")
			}
			if failure == "still-running" && err.Error() != "application recipe-node-api still has running containers; refusing to remove its networks" {
				t.Fatal(err)
			}
		})
	}
}

func TestStackRemovalWaitsForExitedTaskContainers(t *testing.T) {
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	allCalls := [][]string{}
	allPolls := 0
	run := func(args ...string) ([]byte, error) {
		allCalls = append(allCalls, append([]string(nil), args...))
		switch strings.Join(args, " ") {
		case "service ls --filter label=com.docker.stack.namespace=demo --format {{.ID}}":
			return []byte("demo_web\n"), nil
		case "service inspect --format {{json .Spec.TaskTemplate.ContainerSpec.StopGracePeriod}} demo_web":
			return []byte("20000000000\n"), nil
		case "service rm demo_web", "container rm task-container":
			return nil, nil
		case "ps -q --filter label=com.docker.stack.namespace=demo":
			return nil, nil
		case "ps -a -q --no-trunc --filter label=com.docker.stack.namespace=demo":
			allPolls++
			if allPolls == 1 {
				return []byte("task-container\n"), nil
			}
			return nil, nil
		case "container inspect --format {{.State.Status}}\t{{index .Config.Labels \"com.docker.swarm.task.id\"}} task-container":
			return []byte("exited\ttask-id\n"), nil
		default:
			t.Fatalf("unexpected command: %q", args)
			return nil, nil
		}
	}
	deadline, err := drainRootStackBeforeRemoval("demo", run, func() time.Time { return current }, func(time.Duration) {})
	if err != nil {
		t.Fatal(err)
	}
	if want := current.Add(50 * time.Second); !deadline.Equal(want) {
		t.Fatalf("drain deadline = %s, want %s", deadline, want)
	}
	for _, call := range allCalls {
		if len(call) >= 3 && call[0] == "container" && call[1] == "rm" && strings.Contains(strings.Join(call, " "), "--force") {
			t.Fatalf("container removal used force: %v", call)
		}
	}
	if allPolls != 2 {
		t.Fatalf("all-container polls = %d, want 2", allPolls)
	}
}

func TestStackRemovalNeverRemovesAContainerWithoutTaskLabelOrRunning(t *testing.T) {
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	removals := 0
	run := func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "service ls --filter label=com.docker.stack.namespace=demo --format {{.ID}}", "ps -q --filter label=com.docker.stack.namespace=demo":
			return nil, nil
		case "ps -a -q --no-trunc --filter label=com.docker.stack.namespace=demo":
			return []byte("created-container exited-container\n"), nil
		case "container inspect --format {{.State.Status}}\t{{index .Config.Labels \"com.docker.swarm.task.id\"}} created-container":
			return []byte("created\tcreated-task\n"), nil
		case "container inspect --format {{.State.Status}}\t{{index .Config.Labels \"com.docker.swarm.task.id\"}} exited-container":
			return []byte("exited\t\n"), nil
		case "container rm created-container", "container rm exited-container":
			removals++
			return nil, nil
		default:
			t.Fatalf("unexpected command: %q", args)
			return nil, nil
		}
	}
	sleep := func(time.Duration) { current = current.Add(30 * time.Second) }
	_, err := drainRootStackBeforeRemoval("demo", run, func() time.Time { return current }, sleep)
	want := "application demo still has containers after 30s; refusing to remove its volumes"
	if err == nil || err.Error() != want {
		t.Fatalf("drain error = %v, want %q", err, want)
	}
	if removals != 0 {
		t.Fatalf("removed %d containers without an exited task label", removals)
	}
}

func TestStackRemovalDrainBoundFollowsStopGracePeriod(t *testing.T) {
	grace, err := parseStopGracePeriods([]byte("20000000000\n<nil>\n"))
	if err != nil || grace != 20*time.Second {
		t.Fatalf("parsed grace = %s, %v, want 20s", grace, err)
	}
	if got := destroyDrainBound(grace); got != 50*time.Second {
		t.Fatalf("20s grace bound = %s, want 50s", got)
	}
	if got := destroyDrainBound(0); got != 30*time.Second {
		t.Fatalf("zero grace bound = %s, want 30s", got)
	}
	if got := destroyDrainBound(10 * time.Minute); got != 5*time.Minute {
		t.Fatalf("large grace bound = %s, want 5m", got)
	}
	defaultGrace, err := parseStopGracePeriods([]byte("\n<nil>\n0\n"))
	if err != nil || defaultGrace != 10*time.Second {
		t.Fatalf("empty service grace = %s, %v, want Docker default 10s", defaultGrace, err)
	}
	if _, err := parseStopGracePeriods([]byte("twenty seconds\n")); err == nil {
		t.Fatal("malformed grace period must fail")
	}
	if _, err := parseStopGracePeriods([]byte("10s\n")); err == nil {
		t.Fatal("duration tokens must fail: the caller asks Docker for the json nanosecond form")
	}
	if grace, err := parseStopGracePeriods([]byte("null\n20000000000\n")); err != nil || grace != 20*time.Second {
		t.Fatalf("json null is an unset grace period, got %s, %v", grace, err)
	}
	if grace, err := parseStopGracePeriods([]byte("null\n")); err != nil || grace != 10*time.Second {
		t.Fatalf("unset grace period defaults to 10s, got %s, %v", grace, err)
	}
	if _, err := parseStopGracePeriods([]byte("nil\n")); err == nil {
		t.Fatal("unexpected grace token must fail")
	}
}

func TestStackRemovalReusesPersistedDrainBudgetAfterServicesDisappear(t *testing.T) {
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	run := func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "service ls --filter label=com.docker.stack.namespace=demo --format {{.ID}}",
			"ps -q --filter label=com.docker.stack.namespace=demo",
			"ps -a -q --no-trunc --filter label=com.docker.stack.namespace=demo":
			return nil, nil
		default:
			t.Fatalf("unexpected command: %q", args)
			return nil, nil
		}
	}
	var persistedBound time.Duration
	var persistedDeadline time.Time
	deadline, err := drainRootStackBeforeRemovalWithBudget(
		"demo", run, func() time.Time { return current }, func(time.Duration) {}, 50*time.Second,
		func(bound time.Duration, deadline time.Time) error {
			persistedBound = bound
			persistedDeadline = deadline
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := current.Add(50 * time.Second)
	if persistedBound != 50*time.Second || !persistedDeadline.Equal(want) || !deadline.Equal(want) {
		t.Fatalf("persisted drain budget/deadline = %s / %s, returned %s, want 50s / %s", persistedBound, persistedDeadline, deadline, want)
	}
	deadline, err = drainRootStackBeforeRemovalWithBudget(
		"demo", run, func() time.Time { return current }, func(time.Duration) {}, 50*time.Second,
		func(bound time.Duration, persisted time.Time) error {
			persistedBound = bound
			persistedDeadline = persisted
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.Equal(want) || !persistedDeadline.Equal(want) {
		t.Fatalf("resumed drain budget = %s, returned=%s want=%s", persistedDeadline, deadline, want)
	}
}

func TestDestroyRouteRemovalSyncsItsDirectoryBeforeCompletion(t *testing.T) {
	directory := t.TempDir()
	route := filepath.Join(directory, "50-demo.caddy")
	if err := os.WriteFile(route, []byte("route\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalSync := syncRootFileDirectory
	t.Cleanup(func() { syncRootFileDirectory = originalSync })
	syncFailure := errors.New("injected directory sync failure")
	syncCalls := 0
	failSync := true
	syncRootFileDirectory = func(path string) error {
		syncCalls++
		if path != directory {
			t.Fatalf("synced directory = %q, want %q", path, directory)
		}
		if _, err := os.Lstat(route); !os.IsNotExist(err) {
			t.Fatalf("route still exists while syncing: %v", err)
		}
		if failSync {
			return syncFailure
		}
		return nil
	}
	journal := &destroyCleanupJournal{App: "demo", PendingRoutes: []string{"50-demo.caddy"}}
	persistCalls := 0
	persist := func() error {
		persistCalls++
		return nil
	}
	if err := completeDestroyRouteRemoval(journal, "50-demo.caddy", route, persist); !errors.Is(err, syncFailure) {
		t.Fatalf("route removal error = %v, want sync failure", err)
	}
	if syncCalls != 1 || persistCalls != 0 || !reflect.DeepEqual(journal.PendingRoutes, []string{"50-demo.caddy"}) || journal.Progress.RouteDirectorySynced {
		t.Fatalf("failed sync advanced route progress: calls=%d persist=%d journal=%+v", syncCalls, persistCalls, journal)
	}
	if _, err := os.Lstat(route); !os.IsNotExist(err) {
		t.Fatalf("route was not unlinked before sync: %v", err)
	}
	failSync = false
	if err := completeDestroyRouteRemoval(journal, "50-demo.caddy", route, persist); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 2 || persistCalls != 1 || len(journal.PendingRoutes) != 0 || !journal.Progress.RouteDirectorySynced {
		t.Fatalf("successful sync did not complete route progress: calls=%d persist=%d journal=%+v", syncCalls, persistCalls, journal)
	}
}

func TestStackRemovalPersistsDiscoveryDeadlineBeforeFirstCommand(t *testing.T) {
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	firstCommandSawDeadline := false
	persisted := false
	run := func(args ...string) ([]byte, error) {
		if !persisted {
			t.Fatal("Docker command ran before its discovery deadline was persisted")
		}
		firstCommandSawDeadline = true
		if strings.HasPrefix(strings.Join(args, " "), "service ls ") {
			return nil, nil
		}
		if strings.HasPrefix(strings.Join(args, " "), "ps ") {
			return nil, nil
		}
		t.Fatalf("unexpected command: %q", args)
		return nil, nil
	}
	var deadline time.Time
	_, err := drainRootStackBeforeRemovalWithBudget(
		"demo", run, func() time.Time { return current }, func(time.Duration) {}, 30*time.Second,
		func(bound time.Duration, persistedDeadline time.Time) error {
			if !persisted {
				if bound != 30*time.Second || !persistedDeadline.Equal(current.Add(rootHelperOperationMargin)) {
					t.Fatalf("initial discovery bound/deadline = %s / %s", bound, persistedDeadline)
				}
				persisted = true
			} else {
				deadline = persistedDeadline
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !firstCommandSawDeadline || !deadline.Equal(current.Add(30*time.Second)) {
		t.Fatalf("discovery ran=%v, final deadline=%s", firstCommandSawDeadline, deadline)
	}
}

func TestDestroyRecoveryUsesOnlyPendingPostgresObjects(t *testing.T) {
	journal := &destroyCleanupJournal{
		Removal: postgresRemoval{
			Databases: []string{"demo_db_done", "demo_db_pending"},
			Roles:     []string{"demo_role_done", "demo_role_pending"},
		},
		PendingDatabases: []string{"demo_db_done", "demo_db_pending"},
		PendingRoles:     []string{"demo_role_done", "demo_role_pending"},
	}
	persistCalls := 0
	persist := func() error {
		persistCalls++
		return nil
	}
	if err := recordCompletedDestroyPostgresDrop(journal, "database", "demo_db_done", persist); err != nil {
		t.Fatal(err)
	}
	if err := recordCompletedDestroyPostgresDrop(journal, "role", "demo_role_done", persist); err != nil {
		t.Fatal(err)
	}
	work := destroyPendingPostgresRemoval(journal)
	if !reflect.DeepEqual(work.Databases, []string{"demo_db_pending"}) || !reflect.DeepEqual(work.Roles, []string{"demo_role_pending"}) {
		t.Fatalf("recovery would repeat completed PostgreSQL drops: %+v", work)
	}
	if !reflect.DeepEqual(journal.Removal.Databases, []string{"demo_db_done", "demo_db_pending"}) || persistCalls != 2 {
		t.Fatalf("original snapshot or per-object persistence changed: journal=%+v persists=%d", journal, persistCalls)
	}
	journal.Progress.PostgresDropsComplete = true
	work = destroyPendingPostgresRemoval(journal)
	if len(work.Databases)+len(work.Roles) != 0 {
		t.Fatalf("completed PostgreSQL phase still has drop work: %+v", work)
	}
}

func TestStackRemovalDeadlineBoundsABlockedDockerCall(t *testing.T) {
	deadline := time.Now().Add(20 * time.Millisecond)
	runner := destroyDeadlineRunner(context.Background(), func() time.Time { return deadline }, func(ctx context.Context, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	started := time.Now()
	_, err := runner("blocked-command")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked command error = %v, want deadline exceeded", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("blocked command exceeded the bounded wait: %s", time.Since(started))
	}
}

func TestStackRemovalRetriesAVolumeInUseUntilTheDeadline(t *testing.T) {
	t.Run("transient", func(t *testing.T) {
		current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
		removals := 0
		run := func(args ...string) ([]byte, error) {
			switch strings.Join(args, " ") {
			case "volume ls --filter label=com.docker.stack.namespace=demo --format {{.Name}}":
				return []byte("demo_results\n"), nil
			case "volume inspect --format {{json .Labels}} demo_results":
				return []byte(`{"com.docker.stack.namespace":"demo"}`), nil
			case "volume rm demo_results":
				removals++
				if removals == 1 {
					return []byte("Error: volume is in use"), errors.New("docker failed")
				}
				return nil, nil
			case "volume inspect --format {{json .Labels}} demo_redis_data", "volume inspect --format {{json .Labels}} demo_rabbitmq_data":
				return nil, errors.New("no such volume")
			default:
				t.Fatalf("unexpected command: %q", args)
				return nil, nil
			}
		}
		if err := removeOwnedVolumes("demo", run, current.Add(time.Second), func() time.Time { return current }, func(d time.Duration) { current = current.Add(d) }); err != nil {
			t.Fatal(err)
		}
		if removals != 2 {
			t.Fatalf("volume rm attempts = %d, want 2", removals)
		}
	})

	t.Run("until-deadline", func(t *testing.T) {
		current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
		deadline := current.Add(time.Second)
		removals := 0
		run := func(args ...string) ([]byte, error) {
			switch strings.Join(args, " ") {
			case "volume ls --filter label=com.docker.stack.namespace=demo --format {{.Name}}":
				return []byte("demo_results\n"), nil
			case "volume inspect --format {{json .Labels}} demo_results":
				return []byte(`{"com.docker.stack.namespace":"demo"}`), nil
			case "volume inspect --format {{json .Labels}} demo_redis_data", "volume inspect --format {{json .Labels}} demo_rabbitmq_data":
				return nil, errors.New("no such volume")
			case "volume rm demo_results":
				removals++
				return []byte("volume is in use"), errors.New("docker failed")
			default:
				t.Fatalf("unexpected command: %q", args)
				return nil, nil
			}
		}
		err := removeOwnedVolumes("demo", run, deadline, func() time.Time { return current }, func(d time.Duration) { current = current.Add(d) })
		if err == nil || !strings.Contains(err.Error(), "remove owned volume demo_results: volume is in use") {
			t.Fatalf("volume retry error = %v", err)
		}
		if removals != 2 || current.Before(deadline) {
			t.Fatalf("attempts = %d, clock = %s", removals, current)
		}
	})

	t.Run("other-error", func(t *testing.T) {
		var calls []string
		run := func(args ...string) ([]byte, error) {
			command := strings.Join(args, " ")
			calls = append(calls, command)
			switch command {
			case "volume ls --filter label=com.docker.stack.namespace=demo --format {{.Name}}":
				return []byte("demo_results\n"), nil
			case "volume inspect --format {{json .Labels}} demo_results":
				return []byte(`{"com.docker.stack.namespace":"demo"}`), nil
			case "volume inspect --format {{json .Labels}} demo_redis_data", "volume inspect --format {{json .Labels}} demo_rabbitmq_data":
				return nil, errors.New("no such volume")
			case "volume rm demo_results":
				return []byte("permission denied"), errors.New("docker failed")
			default:
				t.Fatalf("unexpected command: %q", args)
				return nil, nil
			}
		}
		now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
		if err := removeOwnedVolumes("demo", run, now.Add(time.Minute), func() time.Time { return now }, func(time.Duration) { t.Fatal("unexpected retry") }); err == nil {
			t.Fatal("non-transient volume error must fail immediately")
		}
		if got := calls[len(calls)-1]; got != "volume rm demo_results" {
			t.Fatalf("final Docker call = %q, calls=%v", got, calls)
		}
	})
}

func TestStackRemovalTouchesOnlyOwnedVolumes(t *testing.T) {
	filter := "label=com.docker.stack.namespace=demo"
	var removals []string
	var calls [][]string
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		switch strings.Join(args, " ") {
		case "volume ls --filter " + filter + " --format {{.Name}}":
			return []byte("demo_data\ndemo_conflict\n"), nil
		case "volume inspect --format {{json .Labels}} demo_data":
			return []byte(`{"com.docker.stack.namespace":"demo"}`), nil
		case "volume inspect --format {{json .Labels}} demo_conflict":
			return []byte(`{"com.docker.stack.namespace":"demo","dev.shuttle.owner":"otherapp"}`), nil
		case "volume inspect --format {{json .Labels}} demo_redis_data":
			return []byte(`{"dev.shuttle.owner":"demo"}`), nil
		case "volume inspect --format {{json .Labels}} demo_rabbitmq_data":
			return []byte(`{"com.docker.stack.namespace":"otherapp"}`), nil
		case "volume inspect --format {{json .Labels}} otherapp_redis_data":
			t.Fatalf("inspected another app's volume: %v", args)
			return nil, nil
		case "volume inspect --format {{json .Labels}} otherapp_rabbitmq_data":
			t.Fatalf("inspected another app's volume: %v", args)
			return nil, nil
		case "volume inspect --format {{json .Labels}} demo_missing":
			return nil, errors.New("no such volume")
		default:
			if len(args) == 3 && args[0] == "volume" && args[1] == "rm" {
				removals = append(removals, args[2])
				return nil, nil
			}
			if args[0] == "volume" && args[1] == "inspect" && strings.Contains(strings.Join(args, " "), "otherapp") {
				t.Fatalf("inspected another app's volume: %v", args)
			}
			t.Fatalf("unexpected command: %q", args)
			return nil, nil
		}
	}
	now := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	if err := removeOwnedVolumes("demo", run, now.Add(time.Minute), func() time.Time { return now }, func(time.Duration) { t.Fatal("unexpected retry") }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removals, []string{"demo_data", "demo_redis_data"}) {
		t.Fatalf("removed volumes = %v", removals)
	}
	if !reflect.DeepEqual(calls[0], []string{"volume", "ls", "--filter", filter, "--format", "{{.Name}}"}) {
		t.Fatalf("volume ownership filter = %v", calls[0])
	}
}

func TestStackRemovalRecoveryUsesOnlyPreparedPendingVolumes(t *testing.T) {
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	journal := &destroyCleanupJournal{
		Progress:       destroyCleanupProgress{VolumesPrepared: true},
		PendingVolumes: []string{"demo_results"},
	}
	var removed []string
	persistCalls := 0
	run := func(args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch command {
		case "volume inspect --format {{json .Labels}} demo_results":
			return []byte(`{"com.docker.stack.namespace":"demo"}`), nil
		case "volume rm demo_results":
			removed = append(removed, "demo_results")
			return nil, nil
		case "volume ls --filter label=com.docker.stack.namespace=demo --format {{.Name}}", "volume rm demo_recreated":
			t.Fatalf("recovery rediscovered or removed a volume created after preparation: %q", command)
			return nil, nil
		default:
			t.Fatalf("unexpected command: %q", command)
			return nil, nil
		}
	}
	err := removePreparedDestroyVolumes("demo", journal, run, current.Add(time.Minute), func() time.Time { return current }, func(time.Duration) { t.Fatal("unexpected retry") }, func() error {
		persistCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{"demo_results"}) || len(journal.PendingVolumes) != 0 || persistCalls != 1 {
		t.Fatalf("prepared volume recovery removed=%v pending=%v persists=%d", removed, journal.PendingVolumes, persistCalls)
	}
}

// Docker deleted demo_results, then the helper died before the journal recorded
// it; demo_shared was relabeled by another app. Recovery must settle both names
// instead of leaving a pending list that blocks the journal forever.
func TestStackRemovalRecoverySettlesAbsentAndKeptPreparedVolumes(t *testing.T) {
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	journal := &destroyCleanupJournal{
		Progress:       destroyCleanupProgress{VolumesPrepared: true},
		PendingVolumes: []string{"demo_results", "demo_shared"},
	}
	persistCalls := 0
	run := func(args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch command {
		case "volume inspect --format {{json .Labels}} demo_results":
			return []byte("Error: No such volume: demo_results"), errors.New("exit status 1")
		case "volume inspect --format {{json .Labels}} demo_shared":
			return []byte(`{"com.docker.stack.namespace":"other"}`), nil
		default:
			t.Fatalf("unexpected command: %q", command)
			return nil, nil
		}
	}
	err := removePreparedDestroyVolumes("demo", journal, run, current.Add(time.Minute), func() time.Time { return current }, func(time.Duration) { t.Fatal("unexpected retry") }, func() error {
		persistCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.PendingVolumes) != 0 || persistCalls != 1 {
		t.Fatalf("settled recovery pending=%v persists=%d", journal.PendingVolumes, persistCalls)
	}
}

// An absent journaled volume followed by a removal failure must not be
// settled: settlement happens only after the whole loop succeeds.
func TestStackRemovalRecoveryKeepsPendingVolumesOnFailure(t *testing.T) {
	current := time.Date(2026, 10, 30, 0, 7, 0, 0, time.UTC)
	journal := &destroyCleanupJournal{
		Progress:       destroyCleanupProgress{VolumesPrepared: true},
		PendingVolumes: []string{"demo_gone", "demo_results"},
	}
	run := func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "volume inspect --format {{json .Labels}} demo_gone":
			return []byte("Error: No such volume: demo_gone"), errors.New("exit status 1")
		case "volume inspect --format {{json .Labels}} demo_results":
			return []byte(`{"com.docker.stack.namespace":"demo"}`), nil
		case "volume rm demo_results":
			return []byte("Error: permission denied"), errors.New("exit status 1")
		default:
			t.Fatalf("unexpected command: %q", strings.Join(args, " "))
			return nil, nil
		}
	}
	err := removePreparedDestroyVolumes("demo", journal, run, current.Add(time.Minute), func() time.Time { return current }, func(time.Duration) { t.Fatal("unexpected retry") }, func() error { return nil })
	if err == nil {
		t.Fatal("a removal failure must be reported")
	}
	if !reflect.DeepEqual(journal.PendingVolumes, []string{"demo_gone", "demo_results"}) {
		t.Fatalf("failed recovery settled volumes: %v", journal.PendingVolumes)
	}
}

// A role whose drop fails while a kept database depends on it is kept on
// purpose: recovery settles it, keeps its credentials and can finish.
func TestDestroySettlesWithheldPostgresRole(t *testing.T) {
	journal := &destroyCleanupJournal{
		PendingRoles:       []string{"demo"},
		PostgresDropIntent: &postgresDropIntent{Kind: "role", Name: "demo", OID: "16384"},
		Removal: postgresRemoval{
			Roles: []string{"demo"},
			Kept:  []keptPostgresObject{{Kind: "database", Name: "demo_keep", Reason: "not recorded as created by Shuttle"}},
		},
		Progress: destroyCleanupProgress{PostgresDropsPrepared: true, PostgresDropIntentsPrepared: true},
	}
	persists := 0
	var settledLedger postgresLedger
	lines, err := applyPostgresRemovalSteps("demo", destroyPendingPostgresRemoval(journal), postgresRemovalSteps{
		drop: func(kind, name string) error {
			return errors.New("role \"demo\" cannot be dropped because some objects depend on it")
		},
		settleWithheld: func(withheld []string) error {
			return settleWithheldDestroyPostgresRoles(journal, withheld, func() error { persists++; return nil })
		},
		writeOrClearLedger: func(remainder postgresLedger) error { settledLedger = remainder; return nil },
		removeState:        func(bool) error { return nil },
		removeCredentials:  func(postgresRemoval, []string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.PendingRoles) != 0 || journal.PostgresDropIntent != nil || persists != 1 {
		t.Fatalf("withheld role not settled: pending=%v intent=%v persists=%d", journal.PendingRoles, journal.PostgresDropIntent, persists)
	}
	if !destroyPostgresDropsComplete(journal, settledLedger) {
		t.Fatalf("drops must be complete once the kept role is settled; ledger=%+v", settledLedger)
	}
	keep := postgresCredentialsToKeep("demo", journal.Removal, nil, postgresLedger{})
	if !slices.Contains(keep.DockerSecrets, "demo_postgres_password_v1") {
		t.Fatalf("kept role credentials must survive later passes: %+v (lines %v)", keep, lines)
	}
}

func TestDestroyCleanupJournalCannotBeRemovedWithPendingWork(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := &destroyCleanupJournal{
		Schema: rootDestroyCleanupSchema, OperationID: "destroy-op", App: "demo",
		DrainBoundNanos:  int64(30 * time.Second),
		PendingDatabases: []string{"demo_db"},
		Progress: destroyCleanupProgress{
			ServicesRemoved: true, ContainersGone: true, StackRemoved: true, NetworksGone: true,
			SecretsPrepared: true, SecretsRemoved: true, VolumesPrepared: true, VolumesRemoved: true,
			RouteRemoved: true, RouteDirectorySynced: true, PostgresDropsPrepared: true,
			PostgresDropsComplete: true, PostgresDropIntentsPrepared: true, LedgerUpdated: true, StateRemoved: true,
			CredentialsPrepared: true, CredentialsRemoved: true, CaddyReloaded: true,
		},
	}
	if err := writeDestroyCleanupJournalAt(root, *journal); err != nil {
		t.Fatal(err)
	}
	if err := removeCompletedDestroyCleanupJournalAt(root, journal.OperationID, journal); err == nil {
		t.Fatal("pending PostgreSQL work must prevent destroy journal removal")
	}
	path, err := destroyCleanupJournalPath(root, journal.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pending destroy journal was not preserved: %v", err)
	}
	journal.PendingDatabases = nil
	if err := removeCompletedDestroyCleanupJournalAt(root, journal.OperationID, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("settled destroy journal still exists: %v", err)
	}
}

func TestDestroyPostgresDropsRemainIncompleteWhileAnObjectIsPending(t *testing.T) {
	journal := &destroyCleanupJournal{PendingRoles: []string{"demo_role"}}
	if destroyPostgresDropsComplete(journal, postgresLedger{Version: postgresLedgerVersion}) {
		t.Fatal("a withheld PostgreSQL role must remain retryable in the destroy journal")
	}
	journal.PendingRoles = nil
	if !destroyPostgresDropsComplete(journal, postgresLedger{Version: postgresLedgerVersion}) {
		t.Fatal("an empty pending set and ledger remainder must complete the drop phase")
	}
}

func TestDestroyPostgresDropTrackingRefusesAmbiguousLegacyJournal(t *testing.T) {
	journal := &destroyCleanupJournal{
		Progress:         destroyCleanupProgress{PostgresDropsPrepared: true, RouteRemoved: true},
		PendingDatabases: []string{"demo_db"},
	}
	persistCalls := 0
	err := prepareDestroyPostgresDropTracking(journal, func() error {
		persistCalls++
		return nil
	})
	if err == nil || persistCalls != 0 || journal.Progress.PostgresDropIntentsPrepared {
		t.Fatalf("ambiguous legacy journal was adopted: err=%v persists=%d progress=%+v", err, persistCalls, journal.Progress)
	}
	journal.Progress.RouteRemoved = false
	if err := prepareDestroyPostgresDropTracking(journal, func() error {
		persistCalls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if persistCalls != 1 || !journal.Progress.PostgresDropIntentsPrepared {
		t.Fatalf("safe journal did not persist the identity protocol: persists=%d progress=%+v", persistCalls, journal.Progress)
	}
}
