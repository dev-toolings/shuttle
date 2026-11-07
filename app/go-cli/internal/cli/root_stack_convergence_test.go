package cli

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The convergence check had zero tests, which is why it shipped a wait that
// could not fail. Everything below is a table over parsed command output, so
// each trap is a value rather than a live host.

var (
	appliedRelease  = "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("c", 64)
	previousRelease = "127.0.0.1:5000/demo-web@sha256:" + strings.Repeat("a", 64)
	// A generated infrastructure service: NamedTagged plus a digest, which is
	// the shape the docker formatter strips the digest off.
	taggedRelease = "redis:7.4.5-alpine@sha256:" + strings.Repeat("b", 64)
)

func webService(replicas int) rootStackService {
	return rootStackService{
		Name:     "web",
		Service:  "demo_web",
		Image:    appliedRelease,
		Digest:   rootImageDigest(appliedRelease),
		Replicas: replicas,
		Primary:  true,
	}
}

func countedRoster(name string, running, desired int) rootServiceRoster {
	return rootServiceRoster{Name: name, Mode: "replicated", Running: running, Desired: desired, Counted: true}
}

// The whole bug in one assertion: the running task's image is the verdict.
func TestStackConvergenceRequiresTheTasksToCarryTheAppliedImage(t *testing.T) {
	stale := []rootServiceTask{{ID: "t1", DesiredState: "Running", CurrentState: "Running", Since: "4 minutes ago", Image: previousRelease}}
	verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 1, 1), true, stale)
	if verdict.Converged {
		t.Fatal("a task on the previous release must never count as converged; that is the promotion this check exists to fail")
	}
	if !strings.Contains(verdict.Reason, rootReleaseMarker(previousRelease)) || !strings.Contains(verdict.Reason, rootReleaseMarker(appliedRelease)) {
		t.Errorf("the reason must name both the running and the wanted release, got %q", verdict.Reason)
	}

	fresh := []rootServiceTask{{ID: "t2", DesiredState: "Running", CurrentState: "Running", Since: "2 seconds ago", Image: appliedRelease}}
	if verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 1, 1), true, fresh); !verdict.Converged {
		t.Errorf("the same service on the applied release must converge, got %q", verdict.Reason)
	}
}

// THE hang trap. Swarm does not update a service whose spec did not change, so
// its UpdateStatus keeps whatever an older run left on it and would never reach
// "completed". Phrasing the pass condition over the image is what makes such a
// service converge on the first evaluation instead of burning the whole budget
// and then emergency-rolling-back a healthy release.
func TestStackConvergenceIgnoresAServiceWhoseImageDidNotChange(t *testing.T) {
	unchanged := rootStackService{Name: "cache", Service: "demo_cache", Image: taggedRelease, Digest: rootImageDigest(taggedRelease), Replicas: 1}
	tasks := []rootServiceTask{{ID: "t1", DesiredState: "Running", CurrentState: "Running", Since: "3 weeks ago", Image: taggedRelease}}
	if verdict := evaluateRootServiceConvergence(unchanged, countedRoster("demo_cache", 1, 1), true, tasks); !verdict.Converged {
		t.Fatalf("a service Swarm never touched is already running the applied image, got %q", verdict.Reason)
	}
	// The same service carrying a stale rollback_completed from an older
	// failure. UpdateStatus is never a pass condition, so it cannot hang this,
	// and the freshness test disarms it as a fast fail too.
	stale, ok := parseRootServiceUpdate(`{"State":"rollback_completed","StartedAt":"2026-06-01T10:39:04.773Z","CompletedAt":"2026-06-01T10:39:09.773Z"}`)
	if !ok {
		t.Fatal("the incident's own UpdateStatus JSON must parse")
	}
	if rootUpdateGaveUp(stale, time.Date(2026, 9, 3, 10, 38, 58, 0, time.UTC)) {
		t.Error("a rollback_completed left by an older run must not abort a deploy that has not started it")
	}
}

// The failure that shipped: Swarm rolled the primary service back, restored the
// previous spec, and the promotion reported success.
func TestStackConvergenceRefusesAServiceSwarmRolledBack(t *testing.T) {
	deployedAt := time.Date(2026, 9, 3, 10, 38, 58, 949000000, time.UTC)
	tasks := []rootServiceTask{{ID: "nk3ug", DesiredState: "Running", CurrentState: "Running", Since: "9 minutes ago", Image: previousRelease}}
	verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 1, 1), true, tasks)
	if verdict.Converged {
		t.Fatal("a rolled-back service must fail the wait")
	}
	update, ok := parseRootServiceUpdate(`{"State":"rollback_completed","StartedAt":"2026-09-03T10:38:58.949Z","CompletedAt":"2026-09-03T10:39:04.773Z"}`)
	if !ok {
		t.Fatal("the incident's UpdateStatus must parse")
	}
	if !rootUpdateGaveUp(update, deployedAt) {
		t.Error("a rollback that started at or after this deploy is terminal and must abort the wait early")
	}
}

// The task that explains it is demoted to DesiredState=Shutdown, so it is
// invisible behind --filter desired-state=running. Reading every task and
// filtering in Go is what keeps the cause attached to the verdict.
func TestStackConvergenceSurfacesTheRejectedTaskThatExplainsIt(t *testing.T) {
	registryReset := `starting container failed: failed to copy: httpReadSeeker: failed open: failed to do request: Get "https://127.0.0.1:5000/v2/demo-web/blobs/sha256:cc5377f6": read tcp 127.0.0.1:40814->127.0.0.1:5000: read: connection reset by peer`
	tasks := []rootServiceTask{
		{ID: "rejected1", DesiredState: "Shutdown", CurrentState: "Rejected", Since: "3 seconds ago", Image: appliedRelease, Error: registryReset},
		{ID: "old1", DesiredState: "Running", CurrentState: "Running", Since: "9 minutes ago", Image: previousRelease},
	}
	verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 1, 1), true, tasks)
	if verdict.Converged {
		t.Fatal("the service is still on the previous release")
	}
	if verdict.Failed == nil {
		t.Fatal("the Rejected task carrying the applied image is the only thing that says why, and it must reach the verdict")
	}
	if verdict.Failed.ID != "rejected1" || verdict.Failed.Error != registryReset {
		t.Errorf("the full error must be carried whole, got %+v", verdict.Failed)
	}
	// It must also survive into the operator-facing message, with the service
	// named — that message is all a root helper gets to say.
	err := rootStackConvergenceError("stack demo did not converge within 16s",
		[]rootStackService{webService(1)},
		map[string]rootServiceVerdict{"demo_web": verdict},
		map[string]rootServiceUpdate{})
	if !strings.Contains(err.Error(), "demo_web") || !strings.Contains(err.Error(), "connection reset by peer") {
		t.Errorf("the message must name the service and quote the reason, got %q", err)
	}
}

// restart_policy is on-failure with max_attempts 3, so the registry-reset
// rejection that caused this incident is exactly the kind Swarm recovers from.
// Failing fast on it would turn a recoverable hiccup into an emergency rollback
// of a healthy release.
func TestStackConvergenceDoesNotFailFastOnARejectedTask(t *testing.T) {
	tasks := []rootServiceTask{
		{ID: "rejected1", DesiredState: "Shutdown", CurrentState: "Rejected", Since: "1 second ago", Image: appliedRelease, Error: "no such image"},
		{ID: "new1", DesiredState: "Running", CurrentState: "Preparing", Since: "1 second ago", Image: appliedRelease},
	}
	verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 0, 1), true, tasks)
	if verdict.Converged {
		t.Fatal("a task still preparing is not converged")
	}
	if verdict.Failed == nil {
		t.Error("the rejection is still worth reporting even though it is not terminal")
	}
	// Nothing about a Rejected task may be terminal on its own: only a fresh
	// UpdateStatus is, and there is none here.
	if rootUpdateGaveUp(rootServiceUpdate{State: "updating"}, time.Time{}) {
		t.Error("an update in flight is never terminal")
	}
}

func TestStackConvergenceTreatsAStaleUpdateStatusAsNoEvidence(t *testing.T) {
	deployedAt := time.Date(2026, 9, 3, 10, 38, 58, 0, time.UTC)
	before := deployedAt.Add(-time.Hour)
	after := deployedAt.Add(time.Millisecond)
	for _, state := range []string{"rollback_completed", "rollback_paused", "paused"} {
		if rootUpdateGaveUp(rootServiceUpdate{State: state, StartedAt: &before}, deployedAt) {
			t.Errorf("%s from before this deploy is not evidence about this deploy", state)
		}
		if !rootUpdateGaveUp(rootServiceUpdate{State: state, StartedAt: &after}, deployedAt) {
			t.Errorf("%s started by this deploy is terminal", state)
		}
		if rootUpdateGaveUp(rootServiceUpdate{State: state}, deployedAt) {
			t.Errorf("%s with no StartedAt cannot be dated and must not abort anything", state)
		}
	}
	for _, state := range []string{"updating", "rollback_started", "completed"} {
		if rootUpdateGaveUp(rootServiceUpdate{State: state, StartedAt: &after}, deployedAt) {
			t.Errorf("%s is not a state Swarm has given up in", state)
		}
	}
	if _, ok := parseRootServiceUpdate("null"); ok {
		t.Error("a service that was never updated prints null and must read as no evidence")
	}
	if _, ok := parseRootServiceUpdate("  "); ok {
		t.Error("empty output must read as no evidence")
	}
	if _, ok := parseRootServiceUpdate("{oops"); ok {
		t.Error("undecodable output must read as no evidence, never as a state")
	}
}

func TestRootUpdateUndoesRelease(t *testing.T) {
	deployedAt := time.Date(2026, 10, 23, 15, 51, 45, 0, time.UTC)
	before := deployedAt.Add(-time.Second)
	after := deployedAt.Add(time.Second)
	tests := []struct {
		name   string
		update rootServiceUpdate
		want   bool
	}{
		{name: "rollback started after deploy", update: rootServiceUpdate{State: "rollback_started", StartedAt: &after}, want: true},
		{name: "rollback completed after deploy", update: rootServiceUpdate{State: "rollback_completed", StartedAt: &after}, want: true},
		{name: "rollback paused after deploy", update: rootServiceUpdate{State: "rollback_paused", StartedAt: &after}, want: true},
		{name: "paused after deploy", update: rootServiceUpdate{State: "paused", StartedAt: &after}, want: true},
		{name: "state is trimmed and case insensitive", update: rootServiceUpdate{State: " ROLLBACK_STARTED ", StartedAt: &after}, want: true},
		{name: "rollback started before deploy", update: rootServiceUpdate{State: "rollback_started", StartedAt: &before}},
		{name: "rollback completed before deploy", update: rootServiceUpdate{State: "rollback_completed", StartedAt: &before}},
		{name: "rollback paused before deploy", update: rootServiceUpdate{State: "rollback_paused", StartedAt: &before}},
		{name: "paused before deploy", update: rootServiceUpdate{State: "paused", StartedAt: &before}},
		{name: "empty state", update: rootServiceUpdate{StartedAt: &after}},
		{name: "updating after deploy", update: rootServiceUpdate{State: "updating", StartedAt: &after}},
		{name: "completed after deploy", update: rootServiceUpdate{State: "completed", StartedAt: &after}},
		{name: "nil started at", update: rootServiceUpdate{State: "rollback_started"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rootUpdateUndoesRelease(test.update, deployedAt); got != test.want {
				t.Errorf("rootUpdateUndoesRelease(%+v) = %t, want %t", test.update, got, test.want)
			}
		})
	}

	incident, ok := parseRootServiceUpdate(`{"State":"rollback_completed","StartedAt":"2026-10-23T15:51:59.037313922Z","CompletedAt":"2026-10-23T15:52:19.599215182Z","Message":"rollback completed"}`)
	if !ok {
		t.Fatal("the measured UpdateStatus JSON must parse")
	}
	if !rootUpdateUndoesRelease(incident, deployedAt) {
		t.Error("the measured rollback status must identify a rollback of this deploy")
	}
}

// The previous implementation treated "0/0" as permanently unconverged, so a
// worker parked at replicas: 0 — the standard way to keep a service defined but
// off — made every deploy burn the budget and fire an emergency rollback.
func TestStackConvergenceAcceptsAServiceScaledToZero(t *testing.T) {
	parked := rootStackService{Name: "worker", Service: "demo_worker", Image: appliedRelease, Digest: rootImageDigest(appliedRelease), Replicas: 0}
	if verdict := evaluateRootServiceConvergence(parked, countedRoster("demo_worker", 0, 0), true, nil); !verdict.Converged {
		t.Fatalf("replicas: 0 with no task is exactly what was asked for, got %q", verdict.Reason)
	}
	leftover := []rootServiceTask{{ID: "t1", DesiredState: "Running", CurrentState: "Running", Image: appliedRelease}}
	if verdict := evaluateRootServiceConvergence(parked, countedRoster("demo_worker", 1, 0), true, leftover); verdict.Converged {
		t.Error("a service scaled to zero that still has a task wanted running has not converged")
	}
}

func TestStackConvergenceAcceptsAGlobalServiceOnTheAppliedImage(t *testing.T) {
	agent := rootStackService{Name: "agent", Service: "demo_agent", Image: appliedRelease, Digest: rootImageDigest(appliedRelease), Replicas: -1, Global: true}
	tasks := []rootServiceTask{{ID: "t1", DesiredState: "Running", CurrentState: "Running", Image: appliedRelease}}
	scheduled := rootServiceRoster{Name: "demo_agent", Mode: "global", Running: 1, Desired: 1, Counted: true}
	if verdict := evaluateRootServiceConvergence(agent, scheduled, true, tasks); !verdict.Converged {
		t.Fatalf("a global service running the applied image has converged, got %q", verdict.Reason)
	}
	unscheduled := rootServiceRoster{Name: "demo_agent", Mode: "global", Running: 0, Desired: 0, Counted: true}
	if verdict := evaluateRootServiceConvergence(agent, unscheduled, true, nil); !verdict.Converged {
		t.Errorf("a global service Swarm wants on no node here has converged, got %q", verdict.Reason)
	}
}

// The exact state the old check read as "1/1, converged": update_config is
// order: start-first, so the old task is still wanted running and still healthy
// while the new one is being pulled.
func TestStackConvergenceWaitsWhileAStartFirstUpdateHasTwoTasks(t *testing.T) {
	tasks := []rootServiceTask{
		{ID: "new1", DesiredState: "Running", CurrentState: "Preparing", Since: "1 second ago", Image: appliedRelease},
		{ID: "old1", DesiredState: "Running", CurrentState: "Running", Since: "9 minutes ago", Image: previousRelease},
	}
	// Swarm reports the transient 2/1 the incident observed on another service;
	// the count alone would have to get lucky to catch it, the image never does.
	verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 2, 1), true, tasks)
	if verdict.Converged {
		t.Fatal("a start-first window is not a converged stack")
	}
	// Same window, seen through the count the old check actually read.
	verdict = evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 1, 1), true, tasks)
	if verdict.Converged {
		t.Fatal(`"1/1" during a start-first update means the update has not begun, not that it finished`)
	}
}

func TestStackConvergenceWaitsForAServiceWithNoTasksYet(t *testing.T) {
	verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 0, 1), true, nil)
	if verdict.Converged {
		t.Fatal("a service with no task has not converged")
	}
	if !strings.Contains(verdict.Reason, "0 of 1") {
		t.Errorf("the reason must say how far off it is, got %q", verdict.Reason)
	}
}

// A first-ever deploy, and a service added by this release, are the same shape:
// no old task, and the count gates honestly on its own because Swarm reports
// 0/1 until the container is running and healthy.
func TestStackConvergenceAcceptsAFirstEverDeployOnceItIsRunning(t *testing.T) {
	starting := []rootServiceTask{{ID: "t1", DesiredState: "Running", CurrentState: "Starting", Since: "1 second ago", Image: appliedRelease}}
	if verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 0, 1), true, starting); verdict.Converged {
		t.Fatal("a container that has not reported healthy yet is not converged")
	}
	running := []rootServiceTask{{ID: "t1", DesiredState: "Running", CurrentState: "Running", Since: "1 second ago", Image: appliedRelease}}
	if verdict := evaluateRootServiceConvergence(webService(1), countedRoster("demo_web", 1, 1), true, running); !verdict.Converged {
		t.Fatalf("a brand new service running the applied image has converged, got %q", verdict.Reason)
	}
}

// Iteration is over the stack file, so a service --prune is removing is
// invisible by construction. Waiting for it to reach an image the stack no
// longer declares would never terminate.
func TestStackConvergenceIgnoresAServiceThePruneRemoved(t *testing.T) {
	applied := []rootStackService{webService(1)}
	roster := map[string]rootServiceRoster{
		"demo_web":     countedRoster("demo_web", 1, 1),
		"demo_dropped": countedRoster("demo_dropped", 1, 1),
	}
	converged := true
	for _, want := range applied {
		entry, listed := roster[want.Service]
		tasks := []rootServiceTask{{ID: "t1", DesiredState: "Running", CurrentState: "Running", Image: appliedRelease}}
		converged = converged && evaluateRootServiceConvergence(want, entry, listed, tasks).Converged
	}
	if !converged {
		t.Fatal("a service the applied stack no longer declares must not be waited on")
	}
}

func TestStackConvergenceRefusesAServiceTheStackDeclaresAndSwarmDoesNotHave(t *testing.T) {
	verdict := evaluateRootServiceConvergence(webService(1), rootServiceRoster{}, false, nil)
	if verdict.Converged {
		t.Fatal("a declared service Swarm has never heard of has not converged")
	}
	if !strings.Contains(verdict.Reason, "demo_web") {
		t.Errorf("the reason must name the missing service, got %q", verdict.Reason)
	}
}

func TestStackConvergenceRefusesAReplicaCountSwarmDisagreesWith(t *testing.T) {
	verdict := evaluateRootServiceConvergence(webService(2), countedRoster("demo_web", 1, 1), true, nil)
	if verdict.Converged {
		t.Fatal("Swarm wanting a different number of replicas than the applied stack is itself non-convergence")
	}
	if !strings.Contains(verdict.Reason, "1") || !strings.Contains(verdict.Reason, "2") {
		t.Errorf("the reason must state both figures, got %q", verdict.Reason)
	}
}

func TestParseRootServiceTasksReadsTheFieldsDockerPrints(t *testing.T) {
	registryReset := `starting container failed: failed to copy: httpReadSeeker: failed open: failed to do request: Get "https://127.0.0.1:5000/v2/demo-web/blobs/sha256:cc53": read tcp 127.0.0.1:40814->127.0.0.1:5000: read: connection reset by peer`
	output := strings.Join([]string{
		"nk3ug7ffcv0h\tRunning\tRunning 3 seconds ago\t" + appliedRelease + "\t",
		"a malformed line with no tabs at all",
		"q1w2e3r4t5y6\tShutdown\tRejected 1 second ago\t" + appliedRelease + "\t" + registryReset,
		"",
	}, "\n")
	tasks := parseRootServiceTasks(output)
	if len(tasks) != 2 {
		t.Fatalf("a malformed line must be dropped without affecting the others, got %d tasks", len(tasks))
	}
	if tasks[0].ID != "nk3ug7ffcv0h" || tasks[0].CurrentState != "Running" || tasks[0].Since != "3 seconds ago" {
		t.Errorf("the state column is a first word plus a human suffix, got %+v", tasks[0])
	}
	if tasks[0].Image != appliedRelease {
		t.Errorf("the image must survive whole, got %q", tasks[0].Image)
	}
	if tasks[1].CurrentState != "Rejected" || tasks[1].Error != registryReset {
		t.Errorf("an error containing quotes, a URL and an IPv4:port pair must survive whole, got %+v", tasks[1])
	}
	// Order is preserved because docker lists a slot newest-first, which is what
	// makes "the first matching failure" the most recent one.
	if tasks[0].ID != "nk3ug7ffcv0h" {
		t.Error("input order must be preserved")
	}
}

func TestParseRootServiceRosterReadsModeAndReplicas(t *testing.T) {
	output := strings.Join([]string{
		"demo_web\treplicated\t1/1",
		"demo_api\treplicated\t2/1",
		"demo_worker\treplicated\t0/0",
		"demo_queue\treplicated\t0/1",
		"demo_capped\treplicated\t1/1 (max 2 per node)",
		"demo_job\treplicated job\t0/0 (3/3 completed)",
		"demo_agent\tglobal\t1/1",
	}, "\n")
	roster := parseRootServiceRoster(output)
	if len(roster) != 7 {
		t.Fatalf("every row must be read, got %d", len(roster))
	}
	for name, want := range map[string][2]int{
		"demo_web":    {1, 1},
		"demo_api":    {2, 1},
		"demo_worker": {0, 0},
		"demo_queue":  {0, 1},
		// The placement suffix used to shred the whole check: strings.Fields
		// over the raw output produced tokens like "(max" that failed the
		// running/desired parse, so a stack using max_replicas_per_node could
		// never converge at all.
		"demo_capped": {1, 1},
		"demo_agent":  {1, 1},
	} {
		entry := roster[name]
		if !entry.Counted || entry.Running != want[0] || entry.Desired != want[1] {
			t.Errorf("%s parsed as %+v, want %d/%d counted", name, entry, want[0], want[1])
		}
	}
	if roster["demo_job"].Counted {
		t.Error("a job's Replicas column counts completions, not steady-state tasks, and must not be used as a replica count")
	}
	if roster["demo_job"].Name != "demo_job" {
		t.Error("an uncountable row must still be listed, or its service reads as missing from the roster")
	}
}

func TestRootStackServicesReadsTheAppliedStackNotTheLiveSpec(t *testing.T) {
	payload := `services:
  worker:
    image: ` + previousRelease + `
    deploy:
      replicas: 0
  web:
    image: ` + appliedRelease + `
    deploy:
      replicas: 2
      labels:
        dev.shuttle.domain: example.test
  agent:
    image: ` + taggedRelease + `
    deploy:
      mode: global
`
	services, err := rootStackServices("demo", []byte(payload))
	if err != nil {
		t.Fatalf("a valid stack must extract: %v", err)
	}
	if len(services) != 3 {
		t.Fatalf("every service must be extracted, got %d", len(services))
	}
	// Sorted by name, or Go's map iteration would reorder both the poll and the
	// lines of the failure message between two runs of the same failure.
	if services[0].Name != "agent" || services[1].Name != "web" || services[2].Name != "worker" {
		t.Fatalf("services must come out sorted by name, got %+v", services)
	}
	web := services[1]
	if web.Service != "demo_web" || web.Image != appliedRelease || web.Digest != rootImageDigest(appliedRelease) {
		t.Errorf("the web service must carry the applied image, got %+v", web)
	}
	if web.Replicas != 2 || !web.Primary || web.Global {
		t.Errorf("replicas, primary and global must come out of the file, got %+v", web)
	}
	if services[0].Global != true || services[0].Replicas != -1 {
		t.Errorf("a global service states no replica count of its own, got %+v", services[0])
	}
	if services[2].Replicas != 0 {
		t.Errorf("replicas: 0 must survive as 0, not collapse into unset, got %+v", services[2])
	}

	if _, err := rootStackServices("demo", []byte("services:\n  ../evil:\n    image: "+appliedRelease+"\n")); err == nil {
		t.Error("a service key outside the Compose charset must be refused before it reaches a docker argument list")
	}
	if _, err := rootStackServices("demo", []byte("services:\n  web:\n    image: 127.0.0.1:5000/demo-web:latest\n")); err == nil {
		t.Error("an image with no digest gives the wait nothing to compare and must be refused")
	}
	if _, err := rootStackServices("Demo Corp", []byte(payload)); err == nil {
		t.Error("the application name is re-validated here too")
	}
	if _, err := rootStackServices("demo", []byte("services: {}\n")); err == nil {
		t.Error("a stack with no service must be refused rather than converge vacuously")
	}
}

func TestRootImageMatchesComparesDigestsAndFallsBackOnlyForATaggedReference(t *testing.T) {
	// Digest against digest, whatever the daemon did to the repository half.
	if !rootImageMatches(appliedRelease, "demo-web:release-7@"+rootImageDigest(appliedRelease)) {
		t.Error("the digest is the identity; a normalised repository must not read as a different release")
	}
	if rootImageMatches(appliedRelease, previousRelease) {
		t.Error("two different digests are two different releases")
	}
	// The formatter strips the digest off a NamedTagged reference, so the
	// generated redis and rabbitmq services would otherwise never match and
	// every stack using them would hang until its budget expired.
	matched, fallback := rootImageMatch(taggedRelease, "redis:7.4.5-alpine")
	if !matched || !fallback {
		t.Errorf("a tagged reference reported without its digest must match, and must record that it did: matched=%v fallback=%v", matched, fallback)
	}
	if rootImageMatches(taggedRelease, "redis:7.4.4-alpine") {
		t.Error("the fallback still compares the tag")
	}
	// A digest-only reference reported without its digest matches nothing.
	// Shuttle's own release images are exactly that shape, and they are the only
	// images that change between two releases, so a lenient fallback here would
	// silently re-open the bug.
	if rootImageMatches(appliedRelease, "127.0.0.1:5000/demo-web") {
		t.Error("a digest-only reference reported without a digest proves nothing")
	}
	if rootImageHasTag("127.0.0.1:5000/demo-web") {
		t.Error("the registry port is not a tag")
	}
	if !rootImageHasTag("redis:7.4.5-alpine") {
		t.Error("redis:7.4.5-alpine is tagged")
	}
}

func TestStackConvergenceErrorNamesEveryServiceThatDidNotConverge(t *testing.T) {
	order := []rootStackService{
		{Name: "web", Service: "demo_web", Image: appliedRelease, Primary: true},
		{Name: "worker", Service: "demo_worker", Image: appliedRelease},
		{Name: "cache", Service: "demo_cache", Image: taggedRelease},
	}
	failed := rootServiceTask{ID: "nk3ug", CurrentState: "Rejected", Error: "read: connection reset by peer"}
	started := time.Date(2026, 9, 3, 10, 38, 58, 949000000, time.UTC)
	err := rootStackConvergenceError("stack demo did not converge within 16s", order,
		map[string]rootServiceVerdict{
			"demo_web":    {Reason: "task old1 still runs " + rootReleaseMarker(previousRelease) + ", the applied stack asks for " + rootReleaseMarker(appliedRelease), Failed: &failed},
			"demo_worker": {Reason: "0 of 1 task wanted running"},
			"demo_cache":  {Converged: true},
		},
		map[string]rootServiceUpdate{"demo_web": {State: "rollback_completed", StartedAt: &started}})
	message := err.Error()
	for _, expected := range []string{
		"stack demo did not converge within 16s",
		"demo_web (published service)",
		rootReleaseMarker(previousRelease),
		rootReleaseMarker(appliedRelease),
		"swarm update state rollback_completed",
		`task nk3ug is Rejected: "read: connection reset by peer"`,
		"demo_worker: 0 of 1 task wanted running",
	} {
		if !strings.Contains(message, expected) {
			t.Errorf("the message must contain %q, got:\n%s", expected, message)
		}
	}
	if strings.Contains(message, "demo_cache") {
		t.Errorf("a converged service must not be listed as a failure, got:\n%s", message)
	}
}

func TestStackConvergenceErrorCapsTheServiceList(t *testing.T) {
	order := []rootStackService{}
	verdicts := map[string]rootServiceVerdict{}
	for i := 0; i < rootStackConvergenceErrorServices+3; i++ {
		name := "demo_s" + string(rune('a'+i))
		order = append(order, rootStackService{Name: name, Service: name, Image: appliedRelease})
		verdicts[name] = rootServiceVerdict{Reason: "0 of 1 task wanted running"}
	}
	message := rootStackConvergenceError("stack demo did not converge within 16s", order, verdicts, nil).Error()
	if !strings.Contains(message, "and 3 more service(s)") {
		t.Errorf("past the cap the list must say how many it hid, got:\n%s", message)
	}
	if lines := strings.Count(message, "\n"); lines != rootStackConvergenceErrorServices+1 {
		t.Errorf("the message must be capped at %d services plus the tail, got %d lines", rootStackConvergenceErrorServices, lines)
	}
}

// deploy.promotion_slo_seconds may legally be 600, which gives convergence a
// 330 s share. At a flat 500 ms with four services that is roughly 3300 docker
// subprocesses spawned as root during a single promotion.
func TestStackConvergencePollingBacksOffOnALongBudget(t *testing.T) {
	if got := rootStackPollInterval(0); got != 500*time.Millisecond {
		t.Errorf("the first polls stay tight, got %s", got)
	}
	if got := rootStackPollInterval(14 * time.Second); got != 500*time.Millisecond {
		t.Errorf("a normal rolling update finishes inside the tight window, got %s", got)
	}
	if got := rootStackPollInterval(15 * time.Second); got != 2*time.Second {
		t.Errorf("past the tight window the poll must back off, got %s", got)
	}
	budget := 330 * time.Second
	polls := 0
	for elapsed := time.Duration(0); elapsed < budget; elapsed += rootStackPollInterval(elapsed) {
		polls++
	}
	if polls > 200 {
		t.Errorf("a %s budget must not spawn thousands of root subprocesses: %d polls", budget, polls)
	}
}

// Blocking on Preparing alone is deliberate: an unschedulable Pending task would
// otherwise pin the host "busy" forever, the sweep would never run again, and
// the registry volume would grow until the free-disk guard refused every deploy.
func TestRegistrySweepDefersWhileATaskIsStillPulling(t *testing.T) {
	if !rootRegistryPullInFlight("Running 3 minutes ago\nPreparing 2 seconds ago\n") {
		t.Error("a task in Preparing is pulling; the registry must not be stopped under it")
	}
	for _, quiet := range []string{
		"Running 3 minutes ago\n",
		"Pending 4 hours ago\n",
		"Assigned 1 second ago\n",
		"Ready 1 second ago\n",
		"Starting 1 second ago\n",
		"Shutdown 2 days ago\n",
		"",
	} {
		if rootRegistryPullInFlight(quiet) {
			t.Errorf("%q must not block the sweep: a task that never leaves that state would stop the host cleaning itself for good", strings.TrimSpace(quiet))
		}
	}
}

// The residual window between waitRootStack returning and docker stop
// shuttle-registry. A failed `docker node ps` used to be treated as permission
// to stop the registry — the original incident with the lights off. "We could
// not look" is not proof the node is quiet; the sweep must defer.
func TestRegistrySweepDoesNotStopWhenNodeTasksCannotBeRead(t *testing.T) {
	if rootRegistryQuietEnough("", errors.New("docker node ps: signal: killed")) {
		t.Fatal("a failed read must not authorise stopping the registry")
	}
	if !rootRegistryQuietEnough("Running 3 minutes ago\n", nil) {
		t.Fatal("a quiet node with a successful read may be swept")
	}
	if !rootRegistryQuietEnough("Pending 4 hours ago\n", nil) {
		t.Fatal("Pending is not a pull; blocking on it would pin the host busy forever")
	}
	if rootRegistryQuietEnough("Preparing 1 second ago\n", nil) {
		t.Fatal("a Preparing task is a pull in flight")
	}
	if rootRegistryQuietEnough("Preparing 1 second ago\n", errors.New("ignored")) {
		t.Fatal("a failed read wins over whatever body came back with it")
	}
}

// These --format strings are load-bearing. Swapping Image and Replicas on the
// status audit would make verifyPromotedRelease treat "1/1" as an image, and
// unifying the wait's roster format with the status format would drop Mode,
// so a global service and a job could no longer be told apart.
func TestDockerFormatStringsKeepTheirColumns(t *testing.T) {
	if rootStackStatusFormat != "{{.Name}}\t{{.Image}}\t{{.Replicas}}" {
		t.Fatalf("status --format must stay Name, Image, Replicas, got %q", rootStackStatusFormat)
	}
	if rootServiceRosterFormat != "{{.Name}}\t{{.Mode}}\t{{.Replicas}}" {
		t.Fatalf("wait roster --format must stay Name, Mode, Replicas, got %q", rootServiceRosterFormat)
	}
	if rootServiceTaskFormat != "{{.ID}}\t{{.DesiredState}}\t{{.CurrentState}}\t{{.Image}}\t{{.Error}}" {
		t.Fatalf("task --format must keep Image and put Error last, got %q", rootServiceTaskFormat)
	}
	if rootServiceUpdateFormat != "{{json .UpdateStatus}}" {
		t.Fatalf("update --format must be JSON so a nil UpdateStatus does not panic, got %q", rootServiceUpdateFormat)
	}
	if rootNodeTaskStateFormat != "{{.CurrentState}}" {
		t.Fatalf("node-ps --format must be CurrentState, got %q", rootNodeTaskStateFormat)
	}
	if strings.Contains(rootStackStatusFormat, "{{.Mode}}") {
		t.Fatal("status is shuttle status + release identity; Mode does not belong there")
	}
	if strings.Contains(rootServiceRosterFormat, "{{.Image}}") {
		t.Fatal("the wait roster is not the release check; Image is read from service ps")
	}
}

// The client-side half: nothing ever read back which release is running, so a
// promotion in which zero services updated looked exactly like a complete one.
func TestPromotedReleaseComparisonNamesTheServiceStillOnThePreviousRelease(t *testing.T) {
	wanted := []rootStackService{
		{Name: "web", Service: "demo_web", Image: appliedRelease, Primary: true},
		{Name: "cache", Service: "demo_cache", Image: taggedRelease},
	}
	// The shape `docker stack services` actually prints: the digest survives on
	// a digest-only reference and is stripped off a NamedTagged one.
	audit := "demo_web\t" + previousRelease + "\t1/1\n" +
		"demo_cache\tredis:7.4.5-alpine\t1/1\n" +
		"operation=audit digest=" + strings.Repeat("f", 64) + "\n"
	reported := parseStackServiceImages(audit)
	complaints := compareAppliedReleaseImages(wanted, reported)
	if len(complaints) != 1 {
		t.Fatalf("only the service on the previous release must be reported, got %v", complaints)
	}
	if !strings.Contains(complaints[0], "demo_web (published service)") || !strings.Contains(complaints[0], rootReleaseMarker(appliedRelease)) {
		t.Errorf("the complaint must name the service and the release it should be on, got %q", complaints[0])
	}
	// The same audit once the promotion actually took.
	good := parseStackServiceImages("demo_web\t" + appliedRelease + "\t1/1\ndemo_cache\tredis:7.4.5-alpine\t1/1\n")
	if complaints := compareAppliedReleaseImages(wanted, good); complaints != nil {
		t.Errorf("a complete promotion must have nothing to complain about, got %v", complaints)
	}
	// A service the host does not report at all is not silently accepted.
	if complaints := compareAppliedReleaseImages(wanted, map[string]string{"demo_cache": "redis:7.4.5-alpine"}); len(complaints) != 1 {
		t.Errorf("a missing service must be reported, got %v", complaints)
	}
	// And a service the host still lists but the applied stack dropped is not
	// waited on, because iteration is over the applied stack.
	extra := parseStackServiceImages("demo_web\t" + appliedRelease + "\t1/1\ndemo_cache\tredis:7.4.5-alpine\t1/1\ndemo_dropped\t" + previousRelease + "\t1/1\n")
	if complaints := compareAppliedReleaseImages(wanted, extra); complaints != nil {
		t.Errorf("a service the applied stack no longer declares must be ignored, got %v", complaints)
	}
}
