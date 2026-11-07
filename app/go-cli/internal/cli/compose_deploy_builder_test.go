package cli

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// A prune that fails on the operator's laptop must leave the verified deploy
// alone: the helper has no error to return, so it cannot abort the operation.
func TestPruneLocalBuildCacheAfterPromotionSwallowsFailure(t *testing.T) {
	previous := localBuildCachePruner
	var got []string
	localBuildCachePruner = func(args ...string) error {
		got = args
		return errors.New("daemon not running")
	}
	t.Cleanup(func() { localBuildCachePruner = previous })

	cfg := &config.Config{App: "web"}
	cfg.Deploy.PruneBuildCache = "all"
	pruneLocalBuildCacheAfterPromotion(cfg)

	if !slices.Contains(got, "shuttle-web") {
		t.Fatalf("prune was not attempted on the app builder: %v", got)
	}
}

// fakeBuilderDocker records every docker invocation and replays canned answers
// keyed by the joined arguments, so the builder lifecycle can be asserted
// without a Docker daemon.
type fakeBuilderDocker struct {
	calls     [][]string
	responses map[string]struct {
		out []byte
		err error
	}
}

func (f *fakeBuilderDocker) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if response, ok := f.responses[strings.Join(args, " ")]; ok {
		return response.out, response.err
	}
	return nil, nil
}

func (f *fakeBuilderDocker) commands() []string {
	joined := make([]string, 0, len(f.calls))
	for _, call := range f.calls {
		joined = append(joined, strings.Join(call, " "))
	}
	return joined
}

func installFakeBuilderDocker(t *testing.T, fake *fakeBuilderDocker) {
	t.Helper()
	previousRunner := dockerBuilderRunner
	dockerBuilderRunner = fake.run
	t.Cleanup(func() { dockerBuilderRunner = previousRunner })
}

func TestEnsurePersistentBuilderCreatesBuilderOnHostNetwork(t *testing.T) {
	fake := &fakeBuilderDocker{responses: map[string]struct {
		out []byte
		err error
	}{
		"buildx inspect shuttle-app": {err: errors.New("no builder")},
	}}
	installFakeBuilderDocker(t, fake)

	if err := ensurePersistentBuilder("app"); err != nil {
		t.Fatalf("ensurePersistentBuilder returned %v", err)
	}

	want := []string{"buildx", "create", "--name", "shuttle-app", "--driver", "docker-container", "--driver-opt", "network=host"}
	index := slices.IndexFunc(fake.calls, func(call []string) bool { return slices.Equal(call, want) })
	if index < 0 {
		// Without network=host the BuildKit container gets its own loopback and
		// can never reach the SSH-tunnelled registry on the host loopback.
		t.Fatalf("builder was not created on the host network, calls: %#v", fake.commands())
	}
	if !slices.Contains(fake.commands(), "buildx inspect --bootstrap shuttle-app") {
		t.Fatalf("builder was not bootstrapped, calls: %#v", fake.commands())
	}
}

func TestEnsurePersistentBuilderRecreatesBridgedLegacyBuilder(t *testing.T) {
	fake := &fakeBuilderDocker{responses: map[string]struct {
		out []byte
		err error
	}{
		// A builder created before the fix: it answers inspect, but its stored
		// driver options carry no network option at all.
		"buildx inspect shuttle-app": {out: []byte("Name:          shuttle-app\nDriver:        docker-container\n\nNodes:\nName:      shuttle-app0\nStatus:    running\n")},
		"inspect buildx_buildkit_shuttle-app0 --format {{.HostConfig.NetworkMode}}": {out: []byte("bridge\n")},
	}}
	installFakeBuilderDocker(t, fake)

	if err := ensurePersistentBuilder("app"); err != nil {
		t.Fatalf("ensurePersistentBuilder returned %v", err)
	}

	commands := fake.commands()
	removed := slices.Index(commands, "buildx rm shuttle-app")
	if removed < 0 {
		t.Fatalf("legacy bridged builder was not removed, calls: %#v", commands)
	}
	created := slices.Index(commands, "buildx create --name shuttle-app --driver docker-container --driver-opt network=host")
	if created < 0 {
		t.Fatalf("builder was not recreated on the host network, calls: %#v", commands)
	}
	if created < removed {
		t.Fatalf("builder was recreated before being removed, calls: %#v", commands)
	}
}

func TestEnsurePersistentBuilderRecreatesBuilderWhoseContainerStayedBridged(t *testing.T) {
	fake := &fakeBuilderDocker{responses: map[string]struct {
		out []byte
		err error
	}{
		"buildx inspect shuttle-app": {out: []byte("Nodes:\nName:             shuttle-app0\nDriver Options:   network=\"host\"\nStatus:           running\n")},
		// Stored options already say host, but the live BuildKit container was
		// started before that and still sits in the bridge namespace.
		"inspect buildx_buildkit_shuttle-app0 --format {{.HostConfig.NetworkMode}}": {out: []byte("bridge\n")},
	}}
	installFakeBuilderDocker(t, fake)

	if err := ensurePersistentBuilder("app"); err != nil {
		t.Fatalf("ensurePersistentBuilder returned %v", err)
	}

	if !slices.Contains(fake.commands(), "buildx rm shuttle-app") {
		t.Fatalf("stale bridged BuildKit container was not recreated, calls: %#v", fake.commands())
	}
}

func TestEnsurePersistentBuilderRestartsHealthyHostNetworkBuilder(t *testing.T) {
	fake := &fakeBuilderDocker{responses: map[string]struct {
		out []byte
		err error
	}{
		"buildx inspect shuttle-app": {out: []byte("Nodes:\nName:             shuttle-app0\nDriver Options:   network=\"host\"\nStatus:           running\n")},
		"inspect buildx_buildkit_shuttle-app0 --format {{.HostConfig.NetworkMode}}": {out: []byte("host\n")},
	}}
	installFakeBuilderDocker(t, fake)

	if err := ensurePersistentBuilder("app"); err != nil {
		t.Fatalf("ensurePersistentBuilder returned %v", err)
	}

	commands := fake.commands()
	for _, command := range commands {
		if strings.HasPrefix(command, "buildx rm") || strings.HasPrefix(command, "buildx create") {
			t.Fatalf("healthy builder metadata must not be recreated, calls: %#v", commands)
		}
	}
	stopped := slices.Index(commands, "buildx stop shuttle-app")
	bootstrapped := slices.Index(commands, "buildx inspect --bootstrap shuttle-app")
	if stopped < 0 || bootstrapped < 0 || stopped > bootstrapped {
		t.Fatalf("healthy builder must be stopped then bootstrapped for this run, calls: %#v", commands)
	}
}

func TestEnsurePersistentBuilderReportsUnbootstrappedBuilderAsHostNetworked(t *testing.T) {
	fake := &fakeBuilderDocker{responses: map[string]struct {
		out []byte
		err error
	}{
		"buildx inspect shuttle-app": {out: []byte("Nodes:\nDriver Options:   network=\"host\"\nStatus:           inactive\n")},
		// No container yet: the stored driver option decides what bootstrap gets.
		"inspect buildx_buildkit_shuttle-app0 --format {{.HostConfig.NetworkMode}}": {err: errors.New("no such object")},
	}}
	installFakeBuilderDocker(t, fake)

	if err := ensurePersistentBuilder("app"); err != nil {
		t.Fatalf("ensurePersistentBuilder returned %v", err)
	}

	if slices.Contains(fake.commands(), "buildx rm shuttle-app") {
		t.Fatalf("builder awaiting bootstrap must not be recreated, calls: %#v", fake.commands())
	}
	if !slices.Contains(fake.commands(), "buildx stop shuttle-app") {
		t.Fatalf("an existing builder must be stopped before bootstrap, calls: %#v", fake.commands())
	}
}

func TestStopPersistentBuilderStopsDaemonButKeepsBuilder(t *testing.T) {
	fake := &fakeBuilderDocker{responses: map[string]struct {
		out []byte
		err error
	}{}}
	installFakeBuilderDocker(t, fake)

	if err := stopPersistentBuilder("app"); err != nil {
		t.Fatalf("stopPersistentBuilder returned %v", err)
	}

	commands := fake.commands()
	if !slices.Contains(commands, "buildx stop shuttle-app") {
		t.Fatalf("BuildKit daemon was not stopped, calls: %#v", commands)
	}
	if slices.Contains(commands, "buildx rm shuttle-app") {
		t.Fatalf("shutdown must preserve builder metadata and cache, calls: %#v", commands)
	}
}

func TestStopPersistentBuilderIgnoresMissingBuilder(t *testing.T) {
	fake := &fakeBuilderDocker{responses: map[string]struct {
		out []byte
		err error
	}{
		"buildx inspect shuttle-app": {err: errors.New("no builder")},
	}}
	installFakeBuilderDocker(t, fake)

	if err := stopPersistentBuilder("app"); err != nil {
		t.Fatalf("missing builder cleanup returned %v", err)
	}
	if slices.Contains(fake.commands(), "buildx stop shuttle-app") {
		t.Fatalf("missing builder must be a no-op, calls: %#v", fake.commands())
	}
}
