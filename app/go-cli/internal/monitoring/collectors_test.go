package monitoring

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/readiness"
)

const collectorStack = `services:
  web:
    image: demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    deploy:
      replicas: 1
    healthcheck:
      test: ["CMD", "true"]
`

func collectorConfig() config.MonitoringConfig {
	value := config.MonitoringConfig{Enabled: true}
	value.NormalizeMonitoring()
	value.Disk.Data.Path = "/data"
	value.Disk.ImagesRegistry.Path = "/images"
	value.Disk.Cache.Path = "/cache"
	value.Disk.Backups.Path = "/backups"
	value.Security.CheckSSH = false
	value.Security.CheckUFW = false
	value.Security.CheckDockerUser = false
	value.Security.CheckFail2ban = false
	value.Security.RequireSSHKeyOnly = false
	value.Security.RequireUFW = false
	value.Security.RequireDockerUser = false
	value.Security.RequireFail2ban = false
	return value
}

func collectorRunner(stack, image, health string) CommandRunner {
	return func(_ context.Context, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "stack services"):
			return []byte(stack), nil
		case strings.Contains(joined, "service inspect demo_web"):
			return []byte(image + "\t1"), nil
		case strings.Contains(joined, "service ps demo_web"):
			return []byte("taskweb1\tRunning 5 seconds ago\tRunning\t\n"), nil
		case strings.Contains(joined, "docker inspect taskweb1") && strings.Contains(joined, "ContainerSpec.Image"):
			return []byte(`"` + image + `"`), nil
		case strings.Contains(joined, "docker ps"):
			return []byte("abc123\n"), nil
		case strings.Contains(joined, "docker inspect abc123"):
			return []byte(`{"Status":"` + health + `"}`), nil
		default:
			return nil, errors.New("unexpected collector command: " + joined)
		}
	}
}

func collectorEngine(stack, image, health string) Engine {
	return New("demo", collectorConfig(), Adapters{
		Run:  collectorRunner(stack, image, health),
		Read: func(string) ([]byte, error) { return []byte(collectorStack), nil },
	})
}

func TestApplicationUsesRetainedExpectedInventoryAndContainerHealth(t *testing.T) {
	engine := collectorEngine("demo_web\t1/1\n", "demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "healthy")
	state, _, evidence := engine.application(context.Background())
	if state != StateHealthy || evidence["expected_services"] != 1 {
		t.Fatalf("expected healthy inventory result, state=%s evidence=%#v", state, evidence)
	}
}

func TestApplicationCounterexamplesDoNotPass(t *testing.T) {
	tests := map[string]struct {
		stack  string
		image  string
		health string
		want   string
	}{
		"expected service missing": {stack: "demo_other\t1/1\n", image: "demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", health: "healthy", want: StateUnavailable},
		"explicit zero replicas":   {stack: "demo_web\t0/0\n", image: "", health: "", want: StateDegraded},
		"running but unhealthy":    {stack: "demo_web\t1/1\n", image: "demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", health: "unhealthy", want: StateDegraded},
		"wrong image":              {stack: "demo_web\t1/1\n", image: "other@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", health: "healthy", want: StateDegraded},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			engine := collectorEngine(test.stack, test.image, test.health)
			state, _, _ := engine.application(context.Background())
			if state != test.want {
				t.Fatalf("state=%s want=%s", state, test.want)
			}
		})
	}
}

func TestExplicitZeroReplicasCanBeHealthyOnlyWhenRetained(t *testing.T) {
	engine := collectorEngine("demo_web\t0/0\n", "", "")
	engine.Adapters.Read = func(string) ([]byte, error) {
		return []byte(`services:
  web:
    image: demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    deploy:
      replicas: 0
`), nil
	}
	state, _, _ := engine.application(context.Background())
	if state != StateHealthy {
		t.Fatalf("explicit zero replica inventory should be healthy, got %s", state)
	}
}

func TestConfiguredOptionalServiceMissingFromInventoryIsUnavailable(t *testing.T) {
	engine := collectorEngine("demo_web\t1/1\n", "", "")
	state, _, _ := engine.optionalService(context.Background(), "redis", true)
	if state != StateUnavailable {
		t.Fatalf("configured but absent optional service should be unavailable, got %s", state)
	}
	state, _, _ = engine.optionalService(context.Background(), "redis", false)
	if state != StateNotApplicable {
		t.Fatalf("unconfigured optional service should be not applicable, got %s", state)
	}
}

func securityConfig() config.MonitoringConfig {
	value := collectorConfig()
	value.Security.ExpectedSSHPort = 2222
	value.Security.ExpectedSSHUsers = []string{"deploy", "ops"}
	return value
}

func TestSecurityCollectorsRejectSSHContextDriftAndFail2banWrongPort(t *testing.T) {
	unsafeSSH := "permitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 2222\nallowusers deploy ops\n"
	safeSSH := "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 2222\nallowusers deploy ops\n"
	runner := func(_ context.Context, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "systemctl is-active fail2ban"):
			return []byte("active\n"), nil
		case strings.Contains(joined, "sshd -T -C user=ops"):
			return []byte(unsafeSSH), nil
		case strings.Contains(joined, "sshd -T -C user=deploy"):
			return []byte(safeSSH), nil
		case strings.Contains(joined, "sshd -T"):
			return []byte(safeSSH), nil
		case strings.Contains(joined, "fail2ban-client"):
			return []byte("Status for the jail: sshd\n"), nil
		case strings.Contains(joined, "jail.d/shuttle-sshd.local"):
			return []byte("port=22\n"), nil
		default:
			return nil, errors.New("unexpected security command: " + joined)
		}
	}
	configValue := securityConfig()
	configValue.Security.CheckSSH = true
	configValue.Security.CheckFail2ban = true
	configValue.Security.RequireSSHKeyOnly = true
	configValue.Security.RequireFail2ban = true
	engine := New("demo", configValue, Adapters{Run: runner})
	checks := engine.securityChecks(context.Background())
	if len(checks) != 2 || checks[0].State != StateDegraded || checks[1].State != StateDegraded {
		t.Fatalf("security counterexamples were not degraded: %#v", checks)
	}
}

func TestUFWAllowAllIsDegraded(t *testing.T) {
	configValue := securityConfig()
	configValue.Security.CheckUFW = true
	configValue.Security.RequireUFW = true
	engine := New("demo", configValue, Adapters{Run: func(_ context.Context, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "ufw status verbose") {
			return []byte("Status: active\nDefault: allow (incoming), deny (outgoing), disabled (routed)\n"), nil
		}
		return nil, errors.New("unexpected command")
	}})
	checks := engine.securityChecks(context.Background())
	if len(checks) != 1 || checks[0].State != StateDegraded {
		t.Fatalf("allow-all UFW policy was not degraded: %#v", checks)
	}
}

func TestSSHDArgvIsOneCommaSeparatedContextAndDoesNotInventPeer(t *testing.T) {
	safeSSH := "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 22\nallowusers deploy ops\n"
	loopbackMatch := "permitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 22\nallowusers deploy ops\n"
	var seen [][]string
	runner := func(_ context.Context, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "sshd -T") {
			if len(args) > 0 && args[0] == "sshd" {
				seen = append(seen, append([]string(nil), args...))
				if len(args) != 4 || args[1] != "-T" || args[2] != "-C" {
					t.Fatalf("sshd argv was not one -C context: %#v", args)
				}
				if strings.Contains(args[3], "addr=127.0.0.1") || strings.Contains(args[3], "host=localhost") {
					t.Fatalf("loopback peer context was invented: %#v", args)
				}
			}
			return []byte(safeSSH), nil
		}
		if strings.Contains(joined, "sshd") {
			return []byte(loopbackMatch), nil
		}
		return nil, errors.New("unexpected command: " + joined)
	}
	configValue := securityConfig()
	configValue.Security.CheckSSH = true
	configValue.Security.RequireSSHKeyOnly = true
	configValue.Security.ExpectedSSHPort = 22
	configValue.Security.SSHListenAddress = "203.0.113.10"
	engine := New("demo", configValue, Adapters{Run: runner})
	checks := engine.securityChecks(context.Background())
	if len(checks) != 1 || checks[0].State != StateHealthy {
		t.Fatalf("public SSH operator context was not healthy: %#v", checks)
	}
	if len(seen) != 2 {
		t.Fatalf("expected one sshd -T per account, got %#v", seen)
	}
	want := []string{
		"user=deploy,laddr=203.0.113.10,lport=22",
		"user=ops,laddr=203.0.113.10,lport=22",
	}
	got := []string{seen[0][3], seen[1][3]}
	if strings.Join(got, " ") != strings.Join(want, " ") && strings.Join(got, " ") != strings.Join([]string{want[1], want[0]}, " ") {
		t.Fatalf("unexpected sshd contexts: %#v", got)
	}
	if checks[0].Evidence["peer_context"] != "not_observed" {
		t.Fatalf("missing peer context was not reported: %#v", checks[0].Evidence)
	}
}

func TestSSHDMatchLoopbackFixtureIsDetectedWithoutInventingPeer(t *testing.T) {
	loopback := "permitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\nport 22\nallowusers deploy ops\n"
	args := sshdEffectiveArgs("ops", 22, "203.0.113.10", "", "")
	if len(args) != 4 || args[1] != "-T" || args[2] != "-C" || args[3] != "user=ops,laddr=203.0.113.10,lport=22" {
		t.Fatalf("unexpected sshd argv shape: %#v", args)
	}
	for _, part := range strings.Split(args[3], ",") {
		name, _, found := strings.Cut(part, "=")
		if found && name == "addr" {
			t.Fatal("peer addr was invented")
		}
	}
	if readiness.MonitoringSSHMatches(loopback, []string{"deploy", "ops"}, 22) {
		t.Fatal("Match-applied unsafe loopback fixture was accepted")
	}
}

func TestUFWExpectedHTTPSAndSSHAllowUnexpectedPublicPort(t *testing.T) {
	configValue := securityConfig()
	configValue.Security.CheckUFW = true
	configValue.Security.RequireUFW = true
	configValue.Security.ExpectedSSHPort = 22
	configValue.Security.AllowedTCPPorts = []string{"22", "80", "443"}
	configValue.Security.PrivateInterface = ""
	verbose := "Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n22/tcp ALLOW IN Anywhere\n80/tcp ALLOW IN Anywhere\n443/tcp ALLOW IN Anywhere\n"
	engine := New("demo", configValue, Adapters{Run: func(_ context.Context, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "ufw status verbose" {
			return []byte(verbose), nil
		}
		return nil, errors.New("unexpected command: " + strings.Join(args, " "))
	}})
	checks := engine.securityChecks(context.Background())
	if len(checks) != 1 || checks[0].State != StateHealthy {
		t.Fatalf("expected HTTPS and SSH UFW policy was not healthy: %#v", checks)
	}
	engine = New("demo", configValue, Adapters{Run: func(_ context.Context, args ...string) ([]byte, error) {
		return []byte(verbose + "8080/tcp ALLOW IN Anywhere\n"), nil
	}})
	checks = engine.securityChecks(context.Background())
	if len(checks) != 1 || checks[0].State != StateDegraded {
		t.Fatalf("unexpected public port was accepted: %#v", checks)
	}
}

// The recette VPS has no private interface and allows only 80/443 publicly;
// its SSH rule was reported as unexpected on every cycle.
func TestUFWPublicSSHIsExpectedWithoutPrivateInterface(t *testing.T) {
	configValue := securityConfig()
	configValue.Security.CheckUFW = true
	configValue.Security.RequireUFW = true
	configValue.Security.ExpectedSSHPort = 22
	configValue.Security.AllowedTCPPorts = []string{"80", "443"}
	configValue.Security.PrivateInterface = ""
	verbose := "Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n22/tcp ALLOW IN Anywhere\n80/tcp ALLOW IN Anywhere\n443/tcp ALLOW IN Anywhere\n443/udp ALLOW IN Anywhere\n"
	engine := New("demo", configValue, Adapters{Run: func(_ context.Context, args ...string) ([]byte, error) {
		return []byte(verbose), nil
	}})
	if checks := engine.securityChecks(context.Background()); len(checks) != 1 || checks[0].State != StateHealthy {
		t.Fatalf("public SSH without a private interface was reported: %#v", checks)
	}
	engine = New("demo", configValue, Adapters{Run: func(_ context.Context, args ...string) ([]byte, error) {
		return []byte(verbose + "2222/tcp ALLOW IN Anywhere\n"), nil
	}})
	if checks := engine.securityChecks(context.Background()); len(checks) != 1 || checks[0].State != StateDegraded {
		t.Fatalf("a public port other than SSH was accepted: %#v", checks)
	}
}

func TestRunningTaskOldDigestIsDegradedWhenSpecMatchesManifest(t *testing.T) {
	const (
		newDigest = "demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		oldDigest = "demo-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	engine := collectorEngine("demo_web\t1/1\n", newDigest, "healthy")
	engine.Adapters.Run = func(_ context.Context, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "stack services"):
			return []byte("demo_web\t1/1\n"), nil
		case strings.Contains(joined, "service inspect demo_web"):
			return []byte(newDigest + "\t1"), nil
		case strings.Contains(joined, "service ps demo_web"):
			return []byte("taskold1\tRunning 5 seconds ago\tRunning\t\n"), nil
		case strings.Contains(joined, "docker inspect taskold1") && strings.Contains(joined, "ContainerSpec.Image"):
			return []byte(`"` + oldDigest + `"`), nil
		default:
			return nil, errors.New("unexpected collector command: " + joined)
		}
	}
	state, _, evidence := engine.application(context.Background())
	if state != StateDegraded {
		t.Fatalf("old running task digest was not degraded: state=%s evidence=%#v", state, evidence)
	}
	if evidence["actual_image"] != oldDigest || evidence["expected_image"] != newDigest {
		t.Fatalf("counterexample evidence missing image identities: %#v", evidence)
	}
}

func TestPostgresSeparateMountLowSpaceIsDegraded(t *testing.T) {
	cfg := collectorConfig()
	engine := New("demo", cfg, Adapters{
		Run: func(_ context.Context, args ...string) ([]byte, error) {
			if strings.Contains(strings.Join(args, " "), "pg_lsclusters") {
				return []byte("18 main 5432 online postgres /var/lib/postgresql/18/main /var/log/postgresql/postgresql-18-main.log\n"), nil
			}
			return nil, errors.New("unexpected command: " + strings.Join(args, " "))
		},
		Statfs: func(path string) (DiskStats, error) {
			if path == "/var/lib/postgresql/18/main" {
				return DiskStats{Blocks: 100, Bavail: 5, Files: 100, Ffree: 40}, nil
			}
			return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
		},
	})
	engine.PostgresVersion = 18
	engine.PostgresCluster = "main"
	checks := engine.diskChecks(context.Background())
	var data, pg Result
	for _, check := range checks {
		switch check.ID {
		case "disk.data":
			data = check
		case "disk.data.postgresql":
			pg = check
		}
	}
	if data.State != StateHealthy {
		t.Fatalf("application data filesystem should stay healthy: %#v", data)
	}
	if pg.State != StateDegraded || pg.Evidence["path"] != "/var/lib/postgresql/18/main" {
		t.Fatalf("separate PostgreSQL mount was not degraded: %#v", pg)
	}
}

func TestBuildKitRemoteCacheIsNotApplicableOnVPS(t *testing.T) {
	cfg := collectorConfig()
	cfg.Disk.Cache.Path = "/var/cache"
	engine := New("demo", cfg, Adapters{Statfs: func(string) (DiskStats, error) {
		return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
	}})
	checks := engine.diskChecks(context.Background())
	var cache Result
	for _, check := range checks {
		if check.ID == "disk.cache" {
			cache = check
		}
	}
	if cache.State != StateNotApplicable {
		t.Fatalf("unrelated /var/cache was treated as BuildKit: %#v", cache)
	}
	if cache.Evidence["observed"] != "not_observed" || cache.Evidence["reason"] != "buildkit_remote_cache_not_in_vps_scope" {
		t.Fatalf("cache scope evidence was not truthful: %#v", cache.Evidence)
	}
}

func TestComposeApplicationIsExplicitlyUnmanaged(t *testing.T) {
	engine := collectorEngine("demo_web\t1/1\n", "demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "healthy")
	engine.DeployStrategy = config.StrategyCompose
	state, summary, evidence := engine.application(context.Background())
	if state != StateNotApplicable || evidence["reason"] != "unmanaged" {
		t.Fatalf("compose application was not reported unmanaged: state=%s summary=%s evidence=%#v", state, summary, evidence)
	}
	redisState, _, redisEvidence := engine.optionalService(context.Background(), "redis", true)
	if redisState != StateNotApplicable || redisEvidence["reason"] != "unmanaged" {
		t.Fatalf("compose redis was treated as a Swarm service: state=%s evidence=%#v", redisState, redisEvidence)
	}
}

func TestRegistryMountUsesDestinationAndUnavailableWhenUnknown(t *testing.T) {
	cfg := collectorConfig()
	cfg.Disk.ImagesRegistry.Path = config.DefaultMonitoringImagesPath
	reordered := `[{"Type":"bind","Source":"/etc/docker/registry","Destination":"/etc/docker/registry"},{"Type":"volume","Source":"/var/lib/registry-data","Destination":"/var/lib/registry"}]`
	engine := New("demo", cfg, Adapters{
		Run: func(_ context.Context, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "DockerRootDir"):
				return []byte("/var/lib/docker"), nil
			case strings.Contains(joined, "inspect shuttle-registry") && strings.Contains(joined, "Mounts"):
				return []byte(reordered), nil
			default:
				return nil, errors.New("unexpected command: " + joined)
			}
		},
		Statfs: func(path string) (DiskStats, error) {
			if path == "/var/lib/registry-data" {
				return DiskStats{Blocks: 100, Bavail: 5, Files: 100, Ffree: 40}, nil
			}
			return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
		},
	})
	checks := engine.diskChecks(context.Background())
	var volume Result
	for _, check := range checks {
		if check.ID == "disk.images_registry.volume" {
			volume = check
		}
	}
	if volume.State != StateDegraded || volume.Evidence["path"] != "/var/lib/registry-data" {
		t.Fatalf("registry destination mount was not selected: %#v", volume)
	}

	engine.Adapters.Run = func(_ context.Context, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "DockerRootDir") {
			return []byte("/var/lib/docker"), nil
		}
		if strings.Contains(joined, "Mounts") {
			return nil, errors.New("inspect failed")
		}
		return nil, errors.New("unexpected command: " + joined)
	}
	missing := engine.diskChecks(context.Background())
	var unknown Result
	for _, check := range missing {
		if check.ID == "disk.images_registry.volume" {
			unknown = check
		}
	}
	if unknown.State != StateUnavailable || unknown.Evidence["reason"] != "registry_mounts_unobserved" {
		t.Fatalf("failed registry mount inspection was omitted: %#v", unknown)
	}
}

func TestDiskInventoryCommandsHonorCheckTimeout(t *testing.T) {
	cfg := collectorConfig()
	cfg.TimeoutSeconds = 1
	started := make(chan struct{})
	engine := New("demo", cfg, Adapters{
		Run: func(ctx context.Context, args ...string) ([]byte, error) {
			if strings.Contains(strings.Join(args, " "), "pg_lsclusters") {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, errors.New("unexpected command: " + strings.Join(args, " "))
		},
		Statfs: func(string) (DiskStats, error) {
			return DiskStats{Blocks: 100, Bavail: 40, Files: 100, Ffree: 40}, nil
		},
	})
	engine.PostgresVersion = 18
	engine.PostgresCluster = "main"
	done := make(chan []Result, 1)
	go func() {
		done <- engine.diskChecks(context.Background())
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("pg_lsclusters was not started under the check")
	}
	select {
	case checks := <-done:
		var pg Result
		for _, check := range checks {
			if check.ID == "disk.data.postgresql" {
				pg = check
			}
		}
		if pg.State != StateUnavailable {
			t.Fatalf("inventory timeout was not unavailable: %#v", pg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("disk inventory ignored the check timeout")
	}
}

// A start-first rollout shows the old task running and the new one still
// starting (demo prod, 2026-10-28 10:41:52, api_worker-high). That is
// convergence, not a failure; a task that failed is still unhealthy.
func TestServiceHealthTreatsAStartingTaskAsConvergingNotUnhealthy(t *testing.T) {
	tasks := "a1b2c3d4e5f6\tRunning 2 hours ago\tRunning\t\nb1c2d3e4f5a6\tStarting 3 seconds ago\tRunning\t\n"
	engine := Engine{Adapters: Adapters{Run: func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 2 && args[1] == "service" && args[2] == "ps" {
			return []byte(tasks), nil
		}
		return nil, fmt.Errorf("unexpected command %v", args)
	}}}
	if state, summary, evidence := engine.serviceHealth(context.Background(), "demo_worker", stackService{}); state != StateHealthy {
		t.Fatalf("rollout with a starting task = %s (%s, %v), want healthy", state, summary, evidence)
	}
	tasks = "a1b2c3d4e5f6\tRunning 2 hours ago\tRunning\t\nb1c2d3e4f5a6\tFailed 3 seconds ago\tRunning\ttask: non-zero exit (1)\n"
	if state, _, _ := engine.serviceHealth(context.Background(), "demo_worker", stackService{}); state != StateDegraded {
		t.Fatalf("a failed task must stay degraded, got %s", state)
	}
	tasks = "b1c2d3e4f5a6\tStarting 3 seconds ago\tRunning\t\n"
	if state, summary, _ := engine.serviceHealth(context.Background(), "demo_worker", stackService{}); state != StateDegraded || summary != "Service tasks are still starting" {
		t.Fatalf("no running task yet = %s (%s), want degraded with the starting summary", state, summary)
	}
}
