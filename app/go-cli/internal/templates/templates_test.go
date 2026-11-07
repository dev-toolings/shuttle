package templates

import (
	"strings"
	"testing"
)

func TestIsReadinessPreset(t *testing.T) {
	for _, p := range ReadinessPresets {
		if !IsReadinessPreset(p) {
			t.Fatalf("%s should be a valid preset", p)
		}
	}
	if IsReadinessPreset("rails") {
		t.Fatal("rails should not be a valid preset")
	}
}

func TestPHPDockerfilesUseOfficialLatestRuntime(t *testing.T) {
	for name, body := range map[string]string{
		"laravel": DockerfileLaravel(ModeAPI),
		"symfony": DockerfileSymfony(ModeAPI, false),
	} {
		if !strings.Contains(body, "ARG SHUTTLE_PHP_RUNTIME="+phpRuntimeImage) {
			t.Fatalf("%s Dockerfile must use the Shuttle PHP runtime", name)
		}
		if strings.Contains(phpRuntimeImage, "@sha256:") {
			t.Fatalf("%s Dockerfile must follow the mutable official PHP 8.4 release line", name)
		}
		prod := body[strings.LastIndex(body, " AS prod"):]
		if strings.Contains(prod, "RUN install-php-extensions") || strings.Contains(prod, "apt-get install") {
			t.Fatalf("%s production stage must not compile or install PHP extensions", name)
		}
		if !strings.Contains(body, "USER www-data") {
			t.Fatalf("%s Dockerfile must retain an unprivileged runtime", name)
		}
	}
}

func TestSymfonyMonolithOnlyAddsAssetStageWhenPackageJSONExists(t *testing.T) {
	assetMapper := DockerfileSymfony(ModeMonolith, false)
	if strings.Contains(assetMapper, " AS assets") {
		t.Fatal("AssetMapper project without package.json must not generate an asset stage")
	}

	nodeAssets := DockerfileSymfony(ModeMonolith, true)
	if !strings.Contains(nodeAssets, "FROM "+bunAssetImage+" AS assets") {
		t.Fatal("Symfony monolith with package.json must generate the pinned Bun asset stage")
	}
	if !strings.Contains(nodeAssets, "COPY --link package.json bun.lock ./") || !strings.Contains(nodeAssets, "bun install --frozen-lockfile") {
		t.Fatal("Symfony monolith asset stage must require a committed Bun lockfile")
	}
}

func TestComposePHPReadinessProbesApplication(t *testing.T) {
	laravel := ComposeTemplate("laravel-app", "laravel", "8000")
	if !strings.Contains(laravel, "http://127.0.0.1:8000/up") {
		t.Fatal("laravel compose healthcheck must probe the framework readiness endpoint")
	}
	if !strings.Contains(laravel, "interval: 5s") {
		t.Fatal("laravel compose healthcheck must use the PHP readiness interval")
	}

	symfony := ComposeTemplate("symfony-app", "symfony", "8080")
	if !strings.Contains(symfony, "get_headers") || !strings.Contains(symfony, "[1-4][0-9]{2}") {
		t.Fatal("symfony compose healthcheck must accept an application response below 500")
	}
	if !strings.Contains(symfony, "/__shuttle_health") {
		t.Fatal("symfony compose healthcheck must use a guaranteed non-static path")
	}
	if !strings.Contains(symfony, "$$h=@get_headers") {
		t.Fatal("symfony compose healthcheck must preserve PHP variables through compose interpolation")
	}
	if strings.Contains(symfony, ":2019/metrics") {
		t.Fatal("symfony compose healthcheck must not accept a Caddy-only metrics response")
	}
}

// A FrankenPHP task needs seconds to boot Caddy, provision its PKI, start the
// PHP kernel and warm the framework cache under a 1.0 CPU limit. With the
// default 2s grace it is marked unhealthy mid-boot and the stack never
// converges, so the PHP presets must get a long start_period while every other
// preset keeps the fast budget.
func TestComposeHealthTimingIsPerPreset(t *testing.T) {
	for _, preset := range []string{"laravel", "symfony"} {
		body := ComposeTemplate("demo", preset, "8080")
		if !strings.Contains(body, "start_period: 30s") {
			t.Fatalf("%s compose healthcheck must tolerate a slow PHP cold start:\n%s", preset, body)
		}
		if !strings.Contains(body, "interval: 5s") {
			t.Fatalf("%s compose healthcheck must use the PHP readiness interval:\n%s", preset, body)
		}
		if !strings.Contains(body, "timeout: 3s") || !strings.Contains(body, "retries: 3") {
			t.Fatalf("%s compose healthcheck must keep the shared timeout and retries:\n%s", preset, body)
		}
	}

	for _, preset := range []string{"hono", "nextjs", "fastapi"} {
		body := ComposeTemplate("demo", preset, "")
		if !strings.Contains(body, "start_period: 2s") || !strings.Contains(body, "interval: 2s") {
			t.Fatalf("%s compose healthcheck must keep the fast readiness budget:\n%s", preset, body)
		}
	}

	// start_interval support by `docker stack deploy` is unverified on the
	// targeted engine, and an unsupported key rejects the deployment.
	if strings.Contains(ComposeTemplate("demo", "laravel", "8080"), "start_interval") {
		t.Fatal("compose healthcheck must not emit start_interval")
	}
}

// TestPresetTmpfsDoesNotMaskCachesBuiltIntoTheImage is the compose half of the
// cold-start fix. A tmpfs hides whatever the image built underneath it, so the
// mounts must cover exactly what the framework writes while serving and nothing
// more. Mounting /app/var or /app/bootstrap/cache wholesale threw away the
// warmed Symfony cache and Laravel's package manifest on every task.
func TestPresetTmpfsDoesNotMaskCachesBuiltIntoTheImage(t *testing.T) {
	symfony := ComposeTemplate("demo", "symfony", "8080")
	for _, required := range []string{"- /app/var/cache:rw,", "- /app/var/log:rw,"} {
		if !strings.Contains(symfony, required) {
			t.Errorf("symfony compose must keep %q writable under read_only: true:\n%s", required, symfony)
		}
	}
	// /app/var as a whole would also swallow var/shuttle-warm-cache, the copy
	// the Dockerfile parks outside the mount for the boot wrapper to seed.
	if strings.Contains(symfony, "- /app/var:") {
		t.Error("mounting /app/var hides the warm cache the builder parked under it")
	}

	laravel := ComposeTemplate("demo", "laravel", "8000")
	if !strings.Contains(laravel, "- /app/storage:rw,") {
		t.Errorf("laravel still compiles Blade views into storage at runtime:\n%s", laravel)
	}
	// packages.php, services.php and routes-v7.php are built into the image;
	// a mount here made Laravel redo package discovery in every task.
	if strings.Contains(laravel, "/app/bootstrap/cache") {
		t.Error("mounting /app/bootstrap/cache hides the build-time Laravel caches")
	}

	if presetTmpfs("nextjs") != "" {
		t.Error("only the PHP presets need a writable tree")
	}
}

func TestFastAPIComposeProbeUsesItsRuntime(t *testing.T) {
	body := ComposeTemplate("recipe", "fastapi", "8000")
	if !strings.Contains(body, "python -c") || !strings.Contains(body, "urllib.request") || strings.Contains(body, "curl -fsS") {
		t.Fatalf("Python slim has neither curl nor wget; generated probe must use Python: %s", body)
	}
}

func TestPHPComposeTmpfsIsWritableAfterDroppingPrivileges(t *testing.T) {
	for _, preset := range []string{"laravel", "symfony"} {
		if !strings.Contains(presetTmpfs(preset), "mode=1777") {
			t.Fatalf("%s tmpfs must remain writable to the non-root runtime, matching the prepared image mountpoints", preset)
		}
	}
}
