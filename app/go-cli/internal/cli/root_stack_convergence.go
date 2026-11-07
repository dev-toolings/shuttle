package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// This file holds the whole convergence decision as pure functions, with no
// exec, no clock and no filesystem, so it compiles and is tested on every
// platform. The privileged half — which docker commands are run, under which
// deadline — lives in waitRootStack in root_helper_linux.go and does nothing
// but feed these functions.
//
// THE TRAP THIS FILE EXISTS TO CLOSE. The wait used to be
// `docker service ls --format {{.Replicas}}` compared as running == desired.
// Every Shuttle service is generated with update_config order: start-first, so
// during a rolling update the OLD task is still running and still healthy while
// the new one is being pulled. Swarm therefore reports "1/1" for a service
// whose update has not begun, and the old check declared the stack converged in
// milliseconds. A promotion whose primary service Swarm later rolled back
// reported "Promotion SLO met" and exited 0 while production served the
// previous release, and the registry garbage collector then stopped the
// registry out from under the pulls that were still in flight — which is what
// caused the rollback in the first place.
//
// The pass condition here is therefore a statement about the images the tasks
// carry, never about an update lifecycle:
//
//	every task Swarm currently WANTS RUNNING for a service declared by the
//	applied stack file is in state Running and carries the image that stack
//	file declares for it, and their number is the desired count.
//
// Phrasing it over images rather than over UpdateStatus.State == "completed" is
// what keeps a service whose image did not change from hanging the wait: Swarm
// does not update such a service at all, so its UpdateStatus keeps whatever an
// older run left behind (possibly a "rollback_completed" from a failure months
// ago, possibly nothing at all) and would never reach "completed". Its already
// running task already carries the applied image, so it converges on the first
// evaluation with no special case at all.
// An unchanged image does not mean an unchanged spec: a rollback of an env-only
// or secret-only change keeps the image, so convergence also refuses a service
// whose UpdateStatus shows this deploy being undone.
//
// Comparing against the applied stack file rather than against the live
// Spec.TaskTemplate.ContainerSpec.Image is the second half of the same
// argument. When swarmkit completes a rollback it restores PreviousSpec into
// Spec, so tasks and Spec agree perfectly on the OLD image: a check against the
// live spec passes on precisely the failure it was built to catch.
//
// One limitation, stated here so nobody reads "converged" as "answering": the
// health gate is free only because swarmkit reports a task as RUNNING once its
// container is healthy, and validateRootStack requires every service to define
// a healthcheck. A stack that declares `healthcheck: {disable: true}` satisfies
// that check with a map of length one and gets no health gate, so its tasks are
// Running as soon as the process is spawned. Convergence then proves the
// release was placed and started, not that it answers.

// rootStackService is one service of the stack that was just handed to
// `docker stack deploy`, reduced to what the convergence decision needs.
type rootStackService struct {
	// Name is the compose key, Service the Swarm service name it produces.
	Name    string
	Service string
	// Image is the reference the applied stack declares, verbatim, and Digest
	// the sha256 it is pinned by. Both are kept: the digest decides identity,
	// the full reference is what a fallback comparison needs when the docker
	// formatter strips the digest off a name:tag@sha256 reference.
	Image  string
	Digest string
	// Replicas is deploy.replicas when the stack states one, -1 otherwise. It
	// is not defaulted to 1: a stack that says nothing must take Swarm's own
	// desired count, which is the only figure that is correct for a global
	// service as well.
	Replicas int
	Global   bool
	// Primary marks the service carrying dev.shuttle.domain, so the error
	// message can say which failure took the site down rather than just naming
	// a service.
	Primary bool
}

// rootStackServices reads the services out of the stack file the helper just
// applied.
//
// The applied file is the right source and the only correct one. It is the
// signed payload byte for byte, or the effective.yml derived from it when a
// managed database address is injected — and injectManagedDatabaseHost only
// ever rewrites `environment`, never `image`, so the images in either file are
// the signed ones. Reading them here means the helper grows no dependency on
// unsigned host state to decide what "the applied release" is.
//
// Everything is re-checked even though validateRootStack has already checked
// it. The helper is a trust boundary, not a second opinion, and a service name
// or an image that reached a `docker service ps` argument list unchecked could
// start with a dash and turn into a flag.
func rootStackServices(app string, payload []byte) ([]rootStackService, error) {
	if !rootAppName.MatchString(app) {
		return nil, fmt.Errorf("application name %q is invalid", app)
	}
	var document map[string]any
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("applied stack is not valid YAML: %w", err)
	}
	services, _ := document["services"].(map[string]any)
	if len(services) == 0 {
		return nil, fmt.Errorf("applied stack for %s declares no service", app)
	}
	// A stack that declares the domain label twice is refused by
	// caddyRouteFragment anyway; here the marker is cosmetic, so an ambiguous
	// answer degrades to "no service is marked primary" instead of failing a
	// promotion over the wording of an error message.
	primary, _, _ := serviceWithLabel(document, "dev.shuttle.domain")
	extracted := make([]rootStackService, 0, len(services))
	for name, raw := range services {
		if !rootServiceName.MatchString(name) {
			return nil, fmt.Errorf("applied stack declares an invalid service name %q", name)
		}
		service, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("service %s is invalid", name)
		}
		image, _ := service["image"].(string)
		digest := rootImageDigest(image)
		if digest == "" {
			return nil, fmt.Errorf("service %s image is not pinned by digest", name)
		}
		deploy, _ := service["deploy"].(map[string]any)
		extracted = append(extracted, rootStackService{
			Name:     name,
			Service:  app + "_" + name,
			Image:    image,
			Digest:   digest,
			Replicas: rootDeclaredReplicas(deploy),
			Global:   strings.EqualFold(strings.TrimSpace(fmt.Sprint(deploy["mode"])), "global"),
			Primary:  name == primary,
		})
	}
	// Sorted by name because Go randomises map iteration: without this the poll
	// order, and worse the order of the lines in the failure message, would
	// differ between two runs of the same failure.
	sort.Slice(extracted, func(i, j int) bool { return extracted[i].Name < extracted[j].Name })
	return extracted, nil
}

// rootDeclaredReplicas reads deploy.replicas, returning -1 when the stack does
// not state one. A YAML string is accepted because a compose file written by
// hand may quote the number, and refusing that would fail a promotion over
// punctuation.
func rootDeclaredReplicas(deploy map[string]any) int {
	raw, present := deploy["replicas"]
	if !present {
		return -1
	}
	switch value := raw.(type) {
	case int:
		if value < 0 {
			return -1
		}
		return value
	case string:
		count, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || count < 0 {
			return -1
		}
		return count
	default:
		count, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(raw)))
		if err != nil || count < 0 {
			return -1
		}
		return count
	}
}

// rootImageDigest returns the sha256 an image reference is pinned by, or "".
func rootImageDigest(image string) string {
	at := strings.LastIndex(image, "@")
	if at < 0 {
		return ""
	}
	digest := strings.TrimSpace(image[at+1:])
	if !strings.HasPrefix(digest, "sha256:") {
		return ""
	}
	return digest
}

// rootImageRepository is everything before the digest.
func rootImageRepository(image string) string {
	repository, _, _ := strings.Cut(strings.TrimSpace(image), "@")
	return repository
}

// rootImageHasTag reports whether a repository reference carries a tag. The
// colon has to be looked for after the last slash, or the port in
// 127.0.0.1:5000/demo-web reads as a tag.
func rootImageHasTag(repository string) bool {
	slash := strings.LastIndex(repository, "/")
	return strings.Contains(repository[slash+1:], ":")
}

// rootImageMatch reports whether a reference docker printed is the applied
// image, and whether that verdict rested on the tag fallback rather than on a
// digest.
//
// Digest against digest is the identity that matters, and it is the only one
// that survives whatever normalisation the daemon applies to a reference: a
// stack declaring 127.0.0.1:5000/demo-web@sha256:… can be stored in the spec as
// repo:tag@sha256:…, so comparing whole strings reports a false mismatch and
// hangs the wait on a release that is perfectly correct.
//
// The fallback exists because `docker service ps` strips the digest off any
// reference that is NamedTagged — redis:7.4.5-alpine@sha256:… is printed as
// redis:7.4.5-alpine even with --no-trunc — and without it every stack
// declaring production.redis or production.rabbitmq would burn its whole
// convergence budget and then emergency-roll-back a healthy release. It is
// deliberately refused for a digest-only reference: Shuttle's own release
// images are always 127.0.0.1:5000/<repo>@sha256:… with no tag at all, so
// letting a digest-less report satisfy them would re-open this bug for exactly
// the images that change between two releases.
func rootImageMatch(want, got string) (bool, bool) {
	wantDigest, gotDigest := rootImageDigest(want), rootImageDigest(got)
	if wantDigest != "" && gotDigest != "" {
		return wantDigest == gotDigest, false
	}
	if wantDigest != "" {
		repository := rootImageRepository(want)
		if !rootImageHasTag(repository) {
			return false, false
		}
		return repository == strings.TrimSpace(got), true
	}
	// Unreachable through rootStackServices, which refuses an image with no
	// digest. Kept honest rather than optimistic: two references that carry no
	// digest can only be compared as strings.
	return strings.TrimSpace(want) == strings.TrimSpace(got), false
}

func rootImageMatches(want, got string) bool {
	matched, _ := rootImageMatch(want, got)
	return matched
}

// rootReleaseMarker names an image the way an operator can compare two of them
// on one line.
func rootReleaseMarker(image string) string {
	if digest := rootImageDigest(image); digest != "" {
		hex := strings.TrimPrefix(digest, "sha256:")
		if len(hex) > 12 {
			return "sha256:" + hex[:12] + "…"
		}
		return digest
	}
	return strings.TrimSpace(image)
}

// rootServiceTask is one row of `docker service ps`.
type rootServiceTask struct {
	ID           string
	DesiredState string
	// CurrentState is the first word of the column ("Running 3 seconds ago" ->
	// "Running"); Since is the remainder, kept only for the message.
	CurrentState string
	Since        string
	Image        string
	Error        string
}

// Docker --format strings. A column swap here is a silent logic bug, not a
// compile error, so they are named constants the tests pin.
//
// rootStackStatusFormat is `shuttle status` AND verifyPromotedRelease's only
// view of what the host is running. Column 2 MUST stay {{.Image}}: Replicas
// there is display. The wait does not use this string; it has its own roster
// format with Mode instead of Image, because a global service and a job are
// distinguished by mode, not by the image the spec currently claims.
const (
	rootStackStatusFormat   = "{{.Name}}\t{{.Image}}\t{{.Replicas}}"
	rootServiceRosterFormat = "{{.Name}}\t{{.Mode}}\t{{.Replicas}}"
	rootServiceTaskFormat   = "{{.ID}}\t{{.DesiredState}}\t{{.CurrentState}}\t{{.Image}}\t{{.Error}}"
	rootServiceUpdateFormat = "{{json .UpdateStatus}}"
	rootNodeTaskStateFormat = "{{.CurrentState}}"
)

// parseRootServiceTasks reads the five columns the task command prints.
//
// A line that does not yield five fields is dropped rather than fatal: a task
// error containing a newline would otherwise panic an index or, worse, be
// mistaken for a task. The error column is last, so the SplitN keeps an error
// containing tabs whole.
//
// The input order is preserved. Docker lists a slot's history newest-first,
// which is what makes "the first matching failure" the most recent one.
func parseRootServiceTasks(output string) []rootServiceTask {
	tasks := []rootServiceTask{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) != 5 {
			continue
		}
		state, since := rootFirstWord(fields[2])
		tasks = append(tasks, rootServiceTask{
			ID:           strings.TrimSpace(fields[0]),
			DesiredState: strings.TrimSpace(fields[1]),
			CurrentState: state,
			Since:        since,
			Image:        strings.TrimSpace(fields[3]),
			Error:        strings.TrimSpace(fields[4]),
		})
	}
	return tasks
}

func rootFirstWord(value string) (string, string) {
	trimmed := strings.TrimSpace(value)
	first, rest, found := strings.Cut(trimmed, " ")
	if !found {
		return first, ""
	}
	return first, strings.TrimSpace(rest)
}

// rootTaskStateIs compares a task state case-insensitively. Docker PrettyPrints
// them capitalised; that is a display decision and the helper must not depend
// on it.
func rootTaskStateIs(state string, expected ...string) bool {
	for _, candidate := range expected {
		if strings.EqualFold(strings.TrimSpace(state), candidate) {
			return true
		}
	}
	return false
}

// rootServiceRoster is one row of `docker service ls` for the stack namespace.
type rootServiceRoster struct {
	Name    string
	Mode    string
	Running int
	Desired int
	// Counted is false when the Replicas column could not be read as a plain
	// running/desired pair. The image check then decides on its own and the
	// count check is skipped, which is what keeps an exotic mode from hanging a
	// promotion.
	Counted bool
}

// parseRootServiceRoster reads the live service list.
//
// The Replicas column is a human column, not a machine field, and the docker
// CLI renders several shapes into it: "1/1", "1/1 (max 2 per node)" when
// deploy.placement.max_replicas_per_node is set, and "0/0 (3/3 completed)" for
// a job. Taking the first whitespace-separated token is what makes the
// placement suffix harmless — the previous implementation ran strings.Fields
// over the whole output and every token but the first failed its own
// running/desired parse, so a stack using max_replicas_per_node could never
// converge at all.
//
// Desired == 0 is a legitimate answer, never an error: a service parked at
// deploy.replicas: 0, or a global service Swarm wants on no node here, has zero
// tasks forever. The clause that treated "0" as unconverged made such an
// application undeployable — it burned the whole budget, fired the emergency
// rollback and failed, on a stack that was exactly what the operator asked for.
func parseRootServiceRoster(output string) map[string]rootServiceRoster {
	roster := map[string]rootServiceRoster{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" {
			continue
		}
		entry := rootServiceRoster{Name: name, Mode: strings.TrimSpace(fields[1])}
		if tokens := strings.Fields(fields[2]); len(tokens) > 0 {
			running, desired, split := strings.Cut(tokens[0], "/")
			runningCount, runningErr := strconv.Atoi(running)
			desiredCount, desiredErr := strconv.Atoi(desired)
			// A job's Replicas column counts completions rather than the tasks
			// the service steadily wants, so its figures are not comparable to
			// a replica count and are refused as a source.
			isJob := strings.Contains(strings.ToLower(entry.Mode), "job")
			if split && runningErr == nil && desiredErr == nil && runningCount >= 0 && desiredCount >= 0 && !isJob {
				entry.Running, entry.Desired, entry.Counted = runningCount, desiredCount, true
			}
		}
		roster[name] = entry
	}
	return roster
}

// rootServiceVerdict is the answer for one service in one poll.
type rootServiceVerdict struct {
	Converged bool
	Reason    string
	// Failed is the task that explains the failure, when there is one. It is
	// filled whatever the verdict, because a service that has since recovered
	// still owes the operator the reason it took an extra thirty seconds.
	Failed *rootServiceTask
	// TagFallback records that at least one task was accepted on a repository
	// comparison because docker printed its image without a digest. The caller
	// logs it once per service: it is the one place this check is deliberately
	// weaker than digest identity, and it must not be silent.
	TagFallback bool
}

// evaluateRootServiceConvergence is the whole decision for one service: pure, no
// exec, no clock, so every trap below is a table test rather than a live host.
//
// The order of the clauses is chosen for message quality, not for speed. A
// service that is both on the wrong image and short of a task should say "wrong
// image", because that is the sentence that names the failure.
func evaluateRootServiceConvergence(want rootStackService, roster rootServiceRoster, listed bool, tasks []rootServiceTask) rootServiceVerdict {
	verdict := rootServiceVerdict{}
	// Independent of everything else: the task that carries the reason. It is
	// found over ALL tasks, at any desired state, because once the orchestrator
	// demotes a Rejected task to DesiredState=Shutdown it leaves the
	// desired-state=running view entirely — and that demoted task is the only
	// one holding the message that says why (a registry reset mid-pull, a
	// missing mount, an unsatisfiable constraint). Filtering in Go over the full
	// list is what lets one command serve both the decision and the diagnosis.
	for i := range tasks {
		if !rootTaskStateIs(tasks[i].CurrentState, "rejected", "failed", "orphaned") {
			continue
		}
		if tasks[i].Error == "" || !rootImageMatches(want.Image, tasks[i].Image) {
			continue
		}
		verdict.Failed = &tasks[i]
		break
	}

	if !listed {
		verdict.Reason = "swarm has no service " + want.Service
		return verdict
	}

	desired, known := roster.Desired, roster.Counted
	switch {
	case want.Global:
		// A global service has no replica count of its own: Swarm's desired
		// figure is the node count, which the helper cannot derive.
	case want.Replicas >= 0:
		if roster.Counted && roster.Desired != want.Replicas {
			verdict.Reason = fmt.Sprintf("swarm wants %d replica(s), the applied stack asks for %d", roster.Desired, want.Replicas)
			return verdict
		}
		desired, known = want.Replicas, true
	}

	running := make([]rootServiceTask, 0, len(tasks))
	for _, task := range tasks {
		if rootTaskStateIs(task.DesiredState, "running") {
			running = append(running, task)
		}
	}

	if known && desired == 0 {
		if len(running) == 0 {
			verdict.Converged = true
			return verdict
		}
		verdict.Reason = fmt.Sprintf("scaled to zero but %d task(s) are still wanted running", len(running))
		return verdict
	}

	// The start-first window lands here. While the new task is pulling, the old
	// one is still DesiredState=Running on the OLD image and still healthy, so
	// the replica count reads 1/1 and the previous implementation returned
	// "converged" before the update had begun. Reading the image instead, that
	// same window reads "not converged", correctly.
	for _, task := range running {
		matched, fallback := rootImageMatch(want.Image, task.Image)
		verdict.TagFallback = verdict.TagFallback || (matched && fallback)
		if matched {
			continue
		}
		verdict.Reason = fmt.Sprintf("task %s still runs %s, the applied stack asks for %s", task.ID, rootReleaseMarker(task.Image), rootReleaseMarker(want.Image))
		return verdict
	}

	for _, task := range running {
		if rootTaskStateIs(task.CurrentState, "running") {
			continue
		}
		verdict.Reason = strings.TrimSpace(fmt.Sprintf("task %s is %s %s", task.ID, task.CurrentState, task.Since))
		return verdict
	}

	switch {
	case known && len(running) != desired:
		verdict.Reason = fmt.Sprintf("%d of %d %s wanted running", len(running), desired, rootTaskNoun(desired))
	case !known && len(running) == 0:
		verdict.Reason = "no task is running the applied release yet"
	default:
		verdict.Converged = true
	}
	return verdict
}

func rootTaskNoun(count int) string {
	if count == 1 {
		return "task"
	}
	return "tasks"
}

// rootServiceUpdate is `docker service inspect --format {{json .UpdateStatus}}`.
//
// The JSON form is deliberate. UpdateStatus is a *UpdateStatus and StartedAt a
// *time.Time, so a dotted template panics on a service that was never updated,
// and Go renders a time.Time as "2026-09-03 10:38:58.949 +0000 UTC" rather than
// anything a parser wants. encoding/json handles the nil and the timestamps for
// free.
type rootServiceUpdate struct {
	State       string     `json:"State"`
	StartedAt   *time.Time `json:"StartedAt"`
	CompletedAt *time.Time `json:"CompletedAt"`
	Message     string     `json:"Message"`
}

func parseRootServiceUpdate(output string) (rootServiceUpdate, bool) {
	body := strings.TrimSpace(output)
	if body == "" || body == "null" {
		return rootServiceUpdate{}, false
	}
	var update rootServiceUpdate
	if err := json.Unmarshal([]byte(body), &update); err != nil {
		return rootServiceUpdate{}, false
	}
	if strings.TrimSpace(update.State) == "" {
		return rootServiceUpdate{}, false
	}
	return update, true
}

// rootUpdateGaveUp reports the one signal that is terminal: Swarm has restored
// the previous spec and no amount of further waiting can change the answer.
//
// It is diagnosis and early abort ONLY. It is never consulted to declare a
// service converged, because a service whose image did not change is never
// updated and keeps whatever UpdateStatus an older run left on it.
//
// That is exactly why the freshness test is not optional. A stale
// "rollback_completed" from a failure weeks ago would otherwise abort every
// subsequent deploy the instant it started — the same trap as gating on
// "completed", wearing fast-fail clothing. deployedAt must be captured before
// `docker stack deploy` is launched: Swarm stamps StartedAt while that call is
// still running, so a timestamp taken afterwards sits after StartedAt and turns
// this whole branch into dead code.
//
// updating, rollback_started and completed are never terminal: the first two
// are still in motion, and "completed" is a success this function has no
// business overriding.
func rootUpdateGaveUp(update rootServiceUpdate, deployedAt time.Time) bool {
	switch strings.ToLower(strings.TrimSpace(update.State)) {
	case "rollback_completed", "rollback_paused", "paused":
	default:
		return false
	}
	if update.StartedAt == nil {
		return false
	}
	return !update.StartedAt.Before(deployedAt)
}

// rootUpdateUndoesRelease recognizes the measured env-only rollback sequence:
// Swarm enters rollback_started while the old task is still desired-running,
// then reaches rollback_completed with the same image as the applied stack.
// updating and completed are deliberately not gated: waiting for completed
// would add Swarm's 10 s monitor to every promotion and fail small SLOs.
func rootUpdateUndoesRelease(update rootServiceUpdate, deployedAt time.Time) bool {
	switch strings.ToLower(strings.TrimSpace(update.State)) {
	case "rollback_started", "rollback_completed", "rollback_paused", "paused":
	default:
		return false
	}
	if update.StartedAt == nil {
		return false
	}
	return !update.StartedAt.Before(deployedAt)
}

// rootStackConvergenceErrorServices caps how many services the failure message
// names. Past this the list stops being read.
const rootStackConvergenceErrorServices = 8

// rootStackConvergenceError renders the message an operator gets from a root
// helper — which is all they get, since the helper's stderr is the protocol's
// return channel and the CLI prints it verbatim. Multi-line is correct here.
//
// Only the services that did not converge are named, in stack-file order, each
// with the reason, the update state when one was read and the full text of the
// task error that explains it.
func rootStackConvergenceError(headline string, order []rootStackService, verdicts map[string]rootServiceVerdict, updates map[string]rootServiceUpdate) error {
	lines := []string{}
	hidden := 0
	for _, want := range order {
		verdict, evaluated := verdicts[want.Service]
		if evaluated && verdict.Converged {
			continue
		}
		if len(lines) >= rootStackConvergenceErrorServices {
			hidden++
			continue
		}
		line := "  " + want.Service
		if want.Primary {
			line += " (published service)"
		}
		reason := strings.TrimSpace(verdict.Reason)
		if reason == "" {
			reason = "did not converge"
		}
		line += ": " + reason
		if update, ok := updates[want.Service]; ok && strings.TrimSpace(update.State) != "" {
			line += "; swarm update state " + strings.TrimSpace(update.State)
			if message := strings.TrimSpace(update.Message); message != "" {
				line += " (" + message + ")"
			}
		}
		if verdict.Failed != nil {
			line += fmt.Sprintf("; task %s is %s: %q", verdict.Failed.ID, verdict.Failed.CurrentState, verdict.Failed.Error)
		}
		lines = append(lines, line)
	}
	if hidden > 0 {
		lines = append(lines, fmt.Sprintf("  and %d more service(s)", hidden))
	}
	if len(lines) == 0 {
		return fmt.Errorf("%s", headline)
	}
	return fmt.Errorf("%s:\n%s", headline, strings.Join(lines, "\n"))
}

// rootStackPollInterval backs the poll off once the interesting part is over.
//
// deploy.promotion_slo_seconds may legally be 600, which gives convergence a
// 330 s share. At a flat 500 ms with four services that is roughly 3300 docker
// subprocesses spawned as root during a single promotion, for a stack that is
// simply slow. The first fifteen seconds stay tight because that is where a
// normal rolling update finishes and where the operator is waiting.
func rootStackPollInterval(elapsed time.Duration) time.Duration {
	if elapsed < 15*time.Second {
		return 500 * time.Millisecond
	}
	return 2 * time.Second
}

// rootRegistryPullInFlight reads `docker node ps --format {{.CurrentState}}` and
// reports whether a task on this node is still pulling an image.
//
// Preparing is the state in which swarmkit's Prepare runs pullImage, and it is
// the ONLY state this blocks on. Pending, Assigned, Accepted, Ready and
// Starting are deliberately excluded: a task that can never be scheduled — an
// unsatisfiable placement constraint, a missing secret — sits in Pending
// forever, and blocking on it would pin the host permanently "busy". The sweep
// that exists to keep the registry volume from filling the disk would then
// never run again, and the 20 % free-disk guard would eventually refuse every
// deploy. That is the exact failure collectRootRegistryGarbage exists to
// prevent, so the guard must not be able to cause it.
func rootRegistryPullInFlight(nodeTasks string) bool {
	for _, line := range strings.Split(nodeTasks, "\n") {
		state, _ := rootFirstWord(line)
		if strings.EqualFold(state, "preparing") {
			return true
		}
	}
	return false
}

// rootRegistryQuietEnough reports whether one `docker node ps` observation is
// enough evidence to stop the registry.
//
// A failed read is not: the original incident was docker stop shuttle-registry
// resetting an in-flight pull, and "we could not look" is not proof that
// nothing is pulling. The sweep is deferred and retries on the next promotion;
// a disk that grows by one more release is cheaper than killing a fetch that
// is still running. Pending is still ignored — that decision lives in
// rootRegistryPullInFlight, not here.
func rootRegistryQuietEnough(nodeTasks string, readErr error) bool {
	if readErr != nil {
		return false
	}
	return !rootRegistryPullInFlight(nodeTasks)
}
