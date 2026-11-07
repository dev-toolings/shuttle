package cli

import (
	"errors"
	"fmt"
	"time"
)

// imageStoreReclaim is a stack-reclaim running beside the local build.
type imageStoreReclaim struct {
	done chan struct{}
	err  error
}

// startImageStoreReclaim runs the reclaim in its own goroutine. Join must be
// called on every path out of the function that started it: the reclaim is a
// signed root operation on the deploy's own operation record, and returning
// while it is still in flight would leave the helper working under an operation
// the client has already moved on from.
func startImageStoreReclaim(run func() error) *imageStoreReclaim {
	reclaim := &imageStoreReclaim{done: make(chan struct{})}
	go func() {
		defer close(reclaim.done)
		reclaim.err = run()
	}()
	return reclaim
}

// Join waits for the reclaim and returns its outcome. It may be called any
// number of times, and on a nil reclaim.
func (reclaim *imageStoreReclaim) Join() error {
	if reclaim == nil {
		return nil
	}
	<-reclaim.done
	return reclaim.err
}

// Done is closed once the reclaim has finished, with or without an error. On a
// nil reclaim it is already closed, so a caller that waits on it never blocks on
// work that does not exist.
func (reclaim *imageStoreReclaim) Done() <-chan struct{} {
	if reclaim == nil {
		finished := make(chan struct{})
		close(finished)
		return finished
	}
	return reclaim.done
}

// swarmOverlapBuildOptions derives the two builds of an overlapped deploy from
// the Swarm cache policy's build options. The first fills the builder's cache and
// leaves everything else off: no push, no registry cache export. The second is
// the cached publish: the same options with the transcript capture dropped, so
// its Push, --metadata-file and registry cache export are the ones a serial
// deploy would have used.
func swarmOverlapBuildOptions(options buildExecutionOptions) (cacheOnly, publish buildExecutionOptions) {
	cacheOnly = options
	cacheOnly.Push, cacheOnly.RegistryCacheExport, cacheOnly.CacheOnly = false, false, true
	publish = options
	publish.CachedPublish, publish.ProgressResults = true, nil
	return cacheOnly, publish
}

// swarmOverlappedBuild is the set of steps of a local Swarm build that overlaps
// the VPS image-store reclaim (DEV-DEPL-85). Each field is one step, so the
// order they run in is the whole contract of runSwarmOverlappedBuildAndPush.
type swarmOverlappedBuild struct {
	// StartReclaim launches stack-reclaim and returns at once.
	StartReclaim func() *imageStoreReclaim
	// Build is the cache-only build: no output flag, no registry cache export.
	Build func() error
	// StartLeaseRenewal starts the operation keep-alive. It stays stopped while
	// the reclaim runs, which renews its own lease as a root phase, and is
	// started the moment the reclaim has finished, while the build goes on.
	StartLeaseRenewal func()
	// DiskGuard is the free-disk check, which has to measure the host after the
	// reclaim, not before it.
	DiskGuard func() error
	// Preserve keeps the previous registry manifest of one image before the
	// push replaces it.
	Preserve func(image string) error
	// Publish is the second build: cached, with --push, --metadata-file and the
	// registry cache export.
	Publish func() error
}

// runSwarmOverlappedBuildAndPush runs the build while the reclaim finishes, and
// publishes only after both have. The order is:
//
//  1. launch the reclaim, then build into the builder's cache (nothing is
//     pushed, nothing is exported to the registry cache);
//  2. the moment the reclaim finishes, success or error, start the lease
//     renewal, without waiting for the build;
//  3. join the reclaim once the build has returned, whether the build succeeded
//     or not;
//  4. run the disk guard, run preserve for every image;
//  5. only then the cached push.
//
// The renewal cannot wait for the build. The reclaim stops renewing the
// reservation when it ends, and the lease is 15 minutes: a build that outlives
// the reclaim by more than that, with nothing renewing, would let the
// reservation expire under a deploy that is still working. The renewal still
// stays off while the reclaim runs, because a renewal racing a root phase is a
// second control call on the same operation.
//
// Pushing last is not cosmetic. Before DEV-DEPL-85 the reclaim ran strictly
// before the build, so a host short of disk was refused (or cleaned) before a
// single layer reached it; a push that started during the reclaim could fill the
// disk the guard has not measured yet, and would replace the registry manifests
// before preserve could keep the previous ones.
//
// It returns when the push has finished, with the time the push began, which is
// what the deploy reports as its push timing. On every path out, the reclaim has
// been joined and StartLeaseRenewal has returned, so the caller can stop the
// renewal it started without racing the goroutine that started it.
func runSwarmOverlappedBuildAndPush(plan buildPlan, steps swarmOverlappedBuild) (time.Time, error) {
	reclaim := steps.StartReclaim()
	renewalStarted := make(chan struct{})
	go func() {
		defer close(renewalStarted)
		<-reclaim.Done()
		steps.StartLeaseRenewal()
	}()
	buildErr := steps.Build()
	// Joined unconditionally, before anything is decided from the build result.
	reclaimErr := reclaim.Join()
	<-renewalStarted
	if buildErr != nil || reclaimErr != nil {
		return time.Time{}, errors.Join(buildErr, reclaimErr)
	}
	if err := steps.DiskGuard(); err != nil {
		return time.Time{}, err
	}
	for _, build := range plan.Builds {
		if err := steps.Preserve(build.Image); err != nil {
			return time.Time{}, fmt.Errorf("preserve previous %s before BuildKit push: %w", build.Image, err)
		}
	}
	pushStartedAt := time.Now()
	if err := steps.Publish(); err != nil {
		return time.Time{}, err
	}
	return pushStartedAt, nil
}
