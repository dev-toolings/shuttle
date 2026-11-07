package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// overlapTrace is the ordered record of what the steps of an overlapped build
// did. The steps run on several goroutines, so it is guarded.
type overlapTrace struct {
	mu     sync.Mutex
	events []string
}

func (trace *overlapTrace) add(event string) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.events = append(trace.events, event)
}

func (trace *overlapTrace) log() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return slices.Clone(trace.events)
}

// recordedOverlapSteps is a set of steps that only write to the trace. The
// reclaim waits for reclaimGate when there is one (a nil gate lets it finish at
// once) and then returns reclaimErr.
func recordedOverlapSteps(trace *overlapTrace, reclaimGate <-chan struct{}, reclaimErr error) swarmOverlappedBuild {
	return swarmOverlappedBuild{
		StartReclaim: func() *imageStoreReclaim {
			trace.add("reclaim-start")
			return startImageStoreReclaim(func() error {
				if reclaimGate != nil {
					<-reclaimGate
				}
				trace.add("reclaim-end")
				return reclaimErr
			})
		},
		Build:             func() error { trace.add("build"); return nil },
		StartLeaseRenewal: func() { trace.add("renewal-start") },
		DiskGuard:         func() error { trace.add("disk-guard"); return nil },
		Preserve:          func(image string) error { trace.add("preserve:" + image); return nil },
		Publish:           func() error { trace.add("publish"); return nil },
	}
}

func overlapTestPlan(images ...string) buildPlan {
	var plan buildPlan
	for _, image := range images {
		plan.Builds = append(plan.Builds, plannedBuild{
			Service:    "api",
			Services:   []string{"api"},
			Image:      image,
			CacheImage: "127.0.0.1:5000/app-api:buildcache",
			Spec:       &buildSpec{Context: ".", Dockerfile: "Dockerfile"},
		})
	}
	return plan
}

func TestOverlappedBuildRunsGuardPreserveAndPushOnlyAfterTheReclaimEnded(t *testing.T) {
	trace := &overlapTrace{}
	gate := make(chan struct{})
	steps := recordedOverlapSteps(trace, gate, nil)
	// The reclaim ends after the build has: the order below is then the order of
	// the contract, not a race.
	steps.Build = func() error {
		trace.add("build")
		close(gate)
		return nil
	}
	pushStartedAt, err := runSwarmOverlappedBuildAndPush(overlapTestPlan("registry/app-api:abc", "registry/app-web:abc"), steps)
	if err != nil {
		t.Fatalf("overlapped build failed: %v", err)
	}
	if pushStartedAt.IsZero() {
		t.Fatal("a completed push reported no start time")
	}
	want := []string{
		"reclaim-start", "build", "reclaim-end", "renewal-start", "disk-guard",
		"preserve:registry/app-api:abc", "preserve:registry/app-web:abc", "publish",
	}
	if got := trace.log(); !slices.Equal(got, want) {
		t.Fatalf("overlap order:\n got: %v\nwant: %v", got, want)
	}
}

// The first build must not push, whatever the cache policy says, and the push
// must not start before the reclaim has joined and the disk guard has measured
// the cleaned host: a push that started earlier could fill a disk nobody has
// measured and replace manifests preserve has not kept.
func TestOverlappedBuildPushesOnlyAfterTheReclaimJoinAndTheDiskGuard(t *testing.T) {
	trace := &overlapTrace{}
	base := swarmCachePolicyFor("shuttle-demo", "").Build
	base.SkipRegistryCache = true
	cacheOnly, publish := swarmOverlapBuildOptions(base)
	plan := overlapTestPlan("127.0.0.1:5000/app-api:abc123")
	cf := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}

	previousRunner := dockerBuildRunner
	dockerBuildRunner = func(args []string) error {
		trace.add(fmt.Sprintf("docker-build push=%t", slices.Contains(args, "--push")))
		return nil
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	gate := make(chan struct{})
	steps := recordedOverlapSteps(trace, gate, nil)
	steps.Build = func() error {
		err := buildPlannedImagesWithOptions(cf, plan, false, cacheOnly)
		close(gate)
		return err
	}
	// The real second build pushes through BuildKit and checks the registry, so
	// the test records what it would be asked to do instead.
	steps.Publish = func() error {
		trace.add(fmt.Sprintf("publish push=%t cache-export=%t", publish.Push, publish.RegistryCacheExport))
		return nil
	}
	if _, err := runSwarmOverlappedBuildAndPush(plan, steps); err != nil {
		t.Fatalf("overlapped build failed: %v", err)
	}
	events := trace.log()
	pushing := slices.Index(events, "publish push=true cache-export=true")
	for _, before := range []string{"reclaim-end", "disk-guard", "preserve:127.0.0.1:5000/app-api:abc123"} {
		at := slices.Index(events, before)
		if at < 0 || pushing < 0 || at > pushing {
			t.Fatalf("push must come after %q: %v", before, events)
		}
	}
	if slices.Contains(events, "docker-build push=true") || !slices.Contains(events, "docker-build push=false") {
		t.Fatalf("the build that runs beside the reclaim must not push: %v", events)
	}
}

func TestOverlappedBuildOptionsSplitTheCacheOnlyBuildFromTheCachedPublish(t *testing.T) {
	base := swarmCachePolicyFor("shuttle-demo", "min").Build
	base.ProgressResults = &buildProgressResults{}
	base.PushedDigests = newPushedDigestSet()
	cacheOnly, publish := swarmOverlapBuildOptions(base)

	if cacheOnly.Push || cacheOnly.RegistryCacheExport || !cacheOnly.CacheOnly || cacheOnly.CachedPublish {
		t.Fatalf("the first build must only fill the cache: %+v", cacheOnly)
	}
	if cacheOnly.ProgressResults != base.ProgressResults || cacheOnly.Builder != "shuttle-demo" {
		t.Fatalf("the first build keeps the builder and the transcript capture: %+v", cacheOnly)
	}
	if !publish.Push || !publish.RegistryCacheExport || publish.CacheOnly || !publish.CachedPublish {
		t.Fatalf("the second build must push with the registry cache export: %+v", publish)
	}
	if publish.ProgressResults != nil || publish.RegistryCacheMode != "min" || publish.PushedDigests != base.PushedDigests {
		t.Fatalf("the second build keeps the cache mode and digest set, and drops the capture: %+v", publish)
	}
	if !base.Push || !base.RegistryCacheExport || base.CacheOnly {
		t.Fatalf("deriving the two builds must not change the policy: %+v", base)
	}
}

func TestCacheOnlyBuildCommandHasNoOutputAndNoRegistryCacheExport(t *testing.T) {
	base := swarmCachePolicyFor("shuttle-demo", "").Build
	// The registry cache lookup is a network call; the export is what is under
	// test, and it needs a cache reference to show up.
	base.SkipRegistryCache = true
	cacheOnly, _ := swarmOverlapBuildOptions(base)
	plan := overlapTestPlan("127.0.0.1:5000/app-api:abc123")
	cf := &composeFile{Services: map[string]composeService{"api": {Build: "."}}}

	var invocations [][]string
	previousRunner := dockerBuildRunner
	dockerBuildRunner = func(args []string) error {
		invocations = append(invocations, slices.Clone(args))
		return nil
	}
	t.Cleanup(func() { dockerBuildRunner = previousRunner })

	if err := buildPlannedImagesWithOptions(cf, plan, false, cacheOnly); err != nil {
		t.Fatal(err)
	}
	if len(invocations) != 1 {
		t.Fatalf("expected one cache-only build, got %#v", invocations)
	}
	args := invocations[0]
	for _, arg := range args {
		for _, forbidden := range []string{"--push", "--load", "--output", "--cache-to", "--metadata-file"} {
			if strings.HasPrefix(arg, forbidden) {
				t.Fatalf("cache-only build carries %q: %#v", forbidden, args)
			}
		}
		if strings.Contains(arg, "type=registry") && strings.Contains(arg, "mode=") {
			t.Fatalf("cache-only build exports to the registry cache: %#v", args)
		}
	}
	for _, required := range []string{"buildx", "build", "--builder", "shuttle-demo", "--pull", "--provenance=false", "-t", "127.0.0.1:5000/app-api:abc123"} {
		if !slices.Contains(args, required) {
			t.Fatalf("cache-only build lost %q: %#v", required, args)
		}
	}
}

func TestCacheOnlyBuildxCommandImportsTheRegistryCacheWithoutExportingIt(t *testing.T) {
	args := dockerBuildxCacheOnlyCommandArgs("shuttle-demo", "127.0.0.1:5000/app-api:abc123", "Dockerfile",
		"127.0.0.1:5000/app-api:buildcache", []string{"--target", "prod"}, ".")
	want := []string{
		"buildx", "build", "--builder", "shuttle-demo", "--pull", "--provenance=false",
		"-t", "127.0.0.1:5000/app-api:abc123", "-f", "Dockerfile",
		"--cache-from", "type=registry,ref=127.0.0.1:5000/app-api:buildcache",
		"--target", "prod", ".",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("cache-only buildx arguments:\n got: %#v\nwant: %#v", args, want)
	}
	if cold := dockerBuildxCacheOnlyCommandArgs("shuttle-demo", "app:abc", "Dockerfile", "", nil, "."); slices.Contains(cold, "--cache-from") {
		t.Fatalf("a cold build must not import an absent cache: %#v", cold)
	}
}

func TestOverlappedBuildStopsBeforeTheGuardWhenTheDiskGuardRefuses(t *testing.T) {
	trace := &overlapTrace{}
	refusal := errors.New("not enough free disk")
	steps := recordedOverlapSteps(trace, nil, nil)
	steps.DiskGuard = func() error { trace.add("disk-guard"); return refusal }
	pushStartedAt, err := runSwarmOverlappedBuildAndPush(overlapTestPlan("registry/app-api:abc"), steps)
	if !errors.Is(err, refusal) || !pushStartedAt.IsZero() {
		t.Fatalf("a refused disk guard must end the deploy, got %v at %v", err, pushStartedAt)
	}
	for _, event := range trace.log() {
		if event == "publish" || strings.HasPrefix(event, "preserve:") {
			t.Fatalf("%s ran after the disk guard refused: %v", event, trace.log())
		}
	}
}

// The reclaim is a signed root operation on the deploy's own record. Returning
// while it is in flight, or without having let the renewal start, leaves the
// helper working under an operation the client has moved on from.
func TestOverlappedBuildJoinsTheReclaimWhicheverSideFails(t *testing.T) {
	buildFailure := errors.New("build failed")
	reclaimFailure := errors.New("reclaim failed")
	for name, test := range map[string]struct{ buildErr, reclaimErr error }{
		"the build fails":   {buildErr: buildFailure},
		"the reclaim fails": {reclaimErr: reclaimFailure},
		"both fail":         {buildErr: buildFailure, reclaimErr: reclaimFailure},
	} {
		t.Run(name, func(t *testing.T) {
			trace := &overlapTrace{}
			var renewals atomic.Int32
			gate := make(chan struct{})
			steps := recordedOverlapSteps(trace, gate, test.reclaimErr)
			steps.Build = func() error {
				trace.add("build")
				// The build is over long before the reclaim: the runner has to wait.
				time.AfterFunc(30*time.Millisecond, func() { close(gate) })
				return test.buildErr
			}
			steps.StartLeaseRenewal = func() { trace.add("renewal-start"); renewals.Add(1) }

			pushStartedAt, err := runSwarmOverlappedBuildAndPush(overlapTestPlan("registry/app-api:abc"), steps)

			if !pushStartedAt.IsZero() {
				t.Fatalf("a failed overlap reported a push start: %v", pushStartedAt)
			}
			if errors.Is(err, buildFailure) != (test.buildErr != nil) || errors.Is(err, reclaimFailure) != (test.reclaimErr != nil) {
				t.Fatalf("error %v does not carry exactly the failures %v / %v", err, test.buildErr, test.reclaimErr)
			}
			events := trace.log()
			if !slices.Contains(events, "reclaim-end") {
				t.Fatalf("the runner returned before the reclaim ended: %v", events)
			}
			// The renewal the deploy stops on its way out has been started, once,
			// and by now no goroutine of the runner is still starting it.
			if renewals.Load() != 1 {
				t.Fatalf("the renewal started %d times, want once: %v", renewals.Load(), events)
			}
			for _, event := range events {
				if event == "disk-guard" || event == "publish" || strings.HasPrefix(event, "preserve:") {
					t.Fatalf("%s ran after a failed overlap: %v", event, events)
				}
			}
			time.Sleep(20 * time.Millisecond)
			if after := trace.log(); !slices.Equal(after, events) {
				t.Fatalf("a step kept running after the runner returned:\n at return: %v\n later:     %v", events, after)
			}
		})
	}
}

// The reclaim stops renewing the reservation when it ends, and the lease is 15
// minutes: a build that outlives the reclaim must not be left with nothing
// renewing. The build below only returns once it has seen the renewal start, so
// a runner that waited for the build first would fail it.
func TestOverlappedBuildStartsLeaseRenewalWhenTheReclaimEndsNotTheBuild(t *testing.T) {
	trace := &overlapTrace{}
	renewalStarted := make(chan struct{})
	steps := recordedOverlapSteps(trace, nil, nil)
	steps.StartLeaseRenewal = func() { trace.add("renewal-start"); close(renewalStarted) }
	steps.Build = func() error {
		trace.add("build-start")
		select {
		case <-renewalStarted:
			trace.add("build-saw-renewal")
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("the renewal did not start while the build was still running")
		}
	}
	if _, err := runSwarmOverlappedBuildAndPush(overlapTestPlan("registry/app-api:abc"), steps); err != nil {
		t.Fatalf("overlapped build failed: %v", err)
	}
	events := trace.log()
	if slices.Index(events, "build-saw-renewal") < 0 || slices.Index(events, "build-saw-renewal") > slices.Index(events, "disk-guard") {
		t.Fatalf("the renewal must be running before the build ends: %v", events)
	}
}

func TestOverlappedBuildStartsLeaseRenewalWhenTheReclaimFailsWhileTheBuildGoesOn(t *testing.T) {
	trace := &overlapTrace{}
	reclaimFailure := errors.New("reclaim failed")
	renewalStarted := make(chan struct{})
	steps := recordedOverlapSteps(trace, nil, reclaimFailure)
	steps.StartLeaseRenewal = func() { trace.add("renewal-start"); close(renewalStarted) }
	steps.Build = func() error {
		select {
		case <-renewalStarted:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("the renewal did not start while the build was still running")
		}
	}
	_, err := runSwarmOverlappedBuildAndPush(overlapTestPlan("registry/app-api:abc"), steps)
	if !errors.Is(err, reclaimFailure) || strings.Contains(fmt.Sprint(err), "did not start") {
		t.Fatalf("want only the reclaim failure after the renewal restarted, got %v", err)
	}
}

// The reclaim renews its own lease under the executor flock, so a second renewal
// beside it would be a second control call on the same operation.
func TestOverlappedBuildKeepsLeaseRenewalOffWhileTheReclaimRuns(t *testing.T) {
	trace := &overlapTrace{}
	gate := make(chan struct{})
	steps := recordedOverlapSteps(trace, gate, nil)
	steps.Build = func() error {
		trace.add("build")
		// Long enough for an eager renewal goroutine to show itself.
		time.Sleep(30 * time.Millisecond)
		if slices.Contains(trace.log(), "renewal-start") {
			close(gate)
			return errors.New("the renewal started while the reclaim was running")
		}
		close(gate)
		return nil
	}
	if _, err := runSwarmOverlappedBuildAndPush(overlapTestPlan("registry/app-api:abc"), steps); err != nil {
		t.Fatalf("overlapped build failed: %v", err)
	}
}

// End to end through the real keep-alive: the reservation is renewed over SSH
// while the build is still running, after the reclaim has ended and not before.
func TestOverlappedBuildRenewsTheReservationWhileTheBuildOutlivesTheReclaim(t *testing.T) {
	oldInterval := operationKeepAliveInterval
	t.Cleanup(func() { operationKeepAliveInterval = oldInterval })
	operationKeepAliveInterval = 10 * time.Millisecond

	const operationID = "12345678-1234-1234-1234-123456789abc"
	var renewals atomic.Int32
	fixture, pin := administratorSSHFixture(t, func(_, _ string, input []byte) shuttlessh.Result {
		plan, _, err := decodeRootHelperEnvelope(bytes.NewReader(input))
		if err != nil {
			return shuttlessh.Result{Code: 1, Stderr: err.Error()}
		}
		if plan.Action != "operation-renew" {
			return shuttlessh.Result{Code: 1, Stderr: "unexpected action " + plan.Action}
		}
		renewals.Add(1)
		body, _ := json.Marshal(coord.Record{ID: operationID, Kind: "deploy", State: "active"})
		return shuttlessh.Result{Stdout: string(body)}
	})
	client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, fixture.user, fixture.port, pin)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := &remoteOperation{id: operationID, kind: "deploy", client: client, key: key, identity: trustedHostIdentity{HostKeyFingerprint: pin, OperatorKeyFingerprint: fixture.operatorKeyFingerprint}}

	var stopRenewal func() error
	var whileReclaiming, whileBuilding int32
	gate := make(chan struct{})
	steps := recordedOverlapSteps(&overlapTrace{}, gate, nil)
	steps.StartLeaseRenewal = func() { stopRenewal = operation.keepAlive(func() error { return nil }) }
	steps.Build = func() error {
		time.Sleep(50 * time.Millisecond)
		whileReclaiming = renewals.Load()
		close(gate)
		deadline := time.After(10 * time.Second)
		for renewals.Load() < whileReclaiming+2 {
			select {
			case <-deadline:
				return errors.New("the reservation was not renewed while the build outlived the reclaim")
			case <-time.After(5 * time.Millisecond):
			}
		}
		whileBuilding = renewals.Load() - whileReclaiming
		return nil
	}
	if _, err := runSwarmOverlappedBuildAndPush(overlapTestPlan("registry/app-api:abc"), steps); err != nil {
		t.Fatalf("overlapped build failed: %v", err)
	}
	if whileReclaiming != 0 {
		t.Fatalf("the reservation was renewed %d times while the reclaim ran", whileReclaiming)
	}
	if whileBuilding < 2 {
		t.Fatalf("the reservation was renewed %d times while the build outlived the reclaim, want at least 2", whileBuilding)
	}
	if stopRenewal == nil {
		t.Fatal("the renewal was never started")
	}
	if err := stopRenewal(); err != nil {
		t.Fatalf("stopping the renewal failed: %v", err)
	}
}
