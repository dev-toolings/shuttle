package templates

import "fmt"

// ComposeTemplate returns a production docker-compose.yml for the given app
// and preset. port defaults to "8080" for laravel/symfony and "3000" for
// nextjs when left empty.
func ComposeTemplate(app, preset, port string) string {
	if port == "" {
		switch preset {
		case "nextjs":
			port = "3000"
		default:
			port = "8080"
		}
	}

	healthPath := "/"
	healthProbe := "curl -fsS http://127.0.0.1:%s%s >/dev/null 2>&1 || wget -qO /dev/null http://127.0.0.1:%s%s"
	healthProbeArgs := []any{port, healthPath, port, healthPath}
	switch preset {
	case "fastapi":
		healthProbe = `python -c 'from urllib.request import urlopen; urlopen("http://127.0.0.1:%s%s", timeout=2).close()'`
		healthProbeArgs = []any{port, healthPath}
	case "laravel":
		healthPath = "/up"
		healthProbeArgs = []any{port, healthPath, port, healthPath}
	case "symfony":
		// This path is deliberately absent from public/, so Caddy must rewrite it
		// through index.php. A stock skeleton correctly returns 404 after the
		// Symfony kernel boots; a broken kernel returns 5xx and remains unhealthy.
		healthPath = "/__shuttle_health"
		// Compose consumes '$' during interpolation. Doubling it preserves the
		// PHP variable in the command that reaches the container.
		healthProbe = `php -r '$$h=@get_headers("http://127.0.0.1:%s%s"); exit($$h && preg_match("/ ([1-4][0-9]{2}) /", $$h[0]) ? 0 : 1);'`
		healthProbeArgs = []any{port, healthPath}
	}

	return fmt.Sprintf(`services:
  web:
    build:
      context: .
      dockerfile: Dockerfile
    expose:
      - "%s"
    restart: unless-stopped%s
    healthcheck:
      # Portable probe: Debian-based images (FrankenPHP) ship curl but not
      # wget, Alpine-based ones ship wget but not curl. Probing with the wrong
      # binary fails every time, and the orchestrator kills a healthy app.
      test: ["CMD-SHELL", %q]
%s
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "1.0"
`, port, presetTmpfs(preset), fmt.Sprintf(healthProbe, healthProbeArgs...), presetHealthTiming(preset))
}

// presetHealthTiming returns the healthcheck timing block for a preset.
//
// The timing is not one-size-fits-all because cold-start cost is not. The
// default budget marks a task unhealthy at roughly start_period + retries *
// interval = 2 + 3*2 = 8s, which suits a runtime that serves its first request
// in milliseconds. A FrankenPHP task needs 4-12s before it answers: it boots
// Caddy, provisions its internal PKI, starts the PHP kernel and warms the
// framework cache, all under a 1.0 CPU limit. Under the default budget the
// orchestrator kills it mid-boot, the replica never converges, and the
// promotion fails on timeout rather than on a real defect.
//
// PHP presets therefore get start_period: 30s (silence during boot, failures
// there are not counted) and interval: 5s (3 failed probes after the grace
// period still detect a genuinely dead task within ~15s). start_interval is
// deliberately not used: its support by `docker stack deploy` on the targeted
// engine is unverified, and an unsupported key rejects the whole deployment.
func presetHealthTiming(preset string) string {
	interval, startPeriod := "2s", "2s"
	switch preset {
	case "laravel", "symfony":
		interval, startPeriod = "5s", "30s"
	}
	return "      interval: " + interval + "\n" +
		"      timeout: 3s\n" +
		"      start_period: " + startPeriod + "\n" +
		"      retries: 3"
}

// presetTmpfs declares the writable paths a preset needs at runtime.
//
// Shuttle deploys every service with read_only: true, so a path the image
// writes to at boot must be an explicit tmpfs or the container crash-loops.
// Caddy's own state is handled in the Dockerfile with XDG_DATA_HOME and
// XDG_CONFIG_HOME, because it is written after the drop to www-data and a
// root-owned tmpfs would deny it.
//
// Every mount here also *hides* whatever the image built at that path, so the
// list is kept to what the framework provably writes while serving, and no
// wider. Anything the Dockerfile precomputes has to sit outside these paths or
// it is dead weight.
//
//   - symfony: var/log and var/cache, not var/. Symfony writes into
//     var/cache/prod at runtime — url_matching_routes.php, twig/,
//     translations/ and pools/ all come from optional cache warmers that
//     cannot run at build time without the app's runtime environment — so the
//     cache directory genuinely has to be writable and the mount stays. Naming
//     the two subdirectories instead of their parent is what makes the fix
//     work: it leaves var/shuttle-warm-cache/, where the builder parks the
//     compiled container, visible from the image so shuttle-symfony-boot can
//     copy it into the empty tmpfs at startup.
//   - laravel: storage/ only. bootstrap/cache/ is dropped because nothing
//     writes there at runtime — packages.php, services.php and routes-v7.php
//     are all produced during the build (verified: a stock app serves / and
//     /up with bootstrap/cache made read-only), while mounting over them made
//     Laravel redo package discovery in every task. storage/ has to stay: the
//     framework's own /up route renders View::file() on a path outside the
//     view finder, so Blade compiles it into storage/framework/views on the
//     fly and no build-time view:cache can cover it.
//
// These trees are caches and logs, so losing them when a task is replaced is
// correct. Durable user data belongs in a named volume or object storage.
func presetTmpfs(preset string) string {
	var paths []string
	switch preset {
	case "symfony":
		paths = []string{"/app/var/cache", "/app/var/log"}
	case "laravel":
		paths = []string{"/app/storage"}
	default:
		return ""
	}
	block := "\n    tmpfs:"
	for _, path := range paths {
		block += "\n      - " + path + ":rw,noexec,nosuid,size=64m,mode=1777"
	}
	return block
}
