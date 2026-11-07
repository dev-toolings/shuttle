package templates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretsEntrypointExportsOnlyAllowlistedMountedSecret(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "entrypoint.sh")
	if err := os.WriteFile(script, []byte(SecretsEntrypoint()), 0o755); err != nil {
		t.Fatal(err)
	}
	secretDir := filepath.Join(dir, "secrets")
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "DB_PASSWORD"), []byte("correct horse"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "APP_KEY"), []byte("must stay file-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.ReplaceAll(string(body), "/run/secrets/$key", secretDir+"/$key")
	if err := os.WriteFile(script, []byte(patched), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script, "sh", "-c", `printf '%s|%s' "$DB_PASSWORD" "${APP_KEY-unset}"`)
	cmd.Env = append(os.Environ(), "SHUTTLE_ENV_SECRETS=DB_PASSWORD")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("entrypoint failed: %v: %s", err, output)
	}
	if string(output) != "correct horse|unset" {
		t.Fatalf("secret value was not exported: %q", output)
	}
}

func TestPHPDockerfilesUseFrankenPHPPHP2ShellRelease(t *testing.T) {

	for name, body := range map[string]string{
		"laravel": DockerfileLaravel(ModeAPI),
		"symfony": DockerfileSymfony(ModeAPI, false),
	} {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(body, "serversideup/") {
				t.Fatal("production Dockerfile must not use the former serversideup runtime")
			}
			for _, required := range []string{
				"FROM composer/composer:2-bin AS composer",
				"FROM base AS extensions",
				"COPY --from=composer /composer /usr/local/bin/composer",
				"COPY --from=extensions /usr/local/lib/php/extensions",
				`php.ini-production`,
				"setcap -r /usr/local/bin/frankenphp",
				"apt-get purge -y --auto-remove $PHPIZE_DEPS",
				"/usr/local/bin/install-php-extensions",
				"USER www-data",
			} {
				if !strings.Contains(body, required) {
					t.Errorf("production Dockerfile missing %q", required)
				}
			}
			if !strings.Contains(body, "FROM base AS prod") && !strings.Contains(body, "FROM app-base AS prod") {
				t.Fatal("production Dockerfile must use a final runtime stage")
			}
			for _, forbidden := range []string{"COPY --link docker/", "docker/docker-secrets-entrypoint.sh"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("production Dockerfile must be standalone, found %q", forbidden)
				}
			}
			for _, required := range []string{"SHUTTLE_ENV_SECRETS", "/run/secrets/$key", "export \"$key=$(cat \"$secret_file\")\"", `ENTRYPOINT ["/usr/local/bin/shuttle-secrets-entrypoint"]`} {
				if !strings.Contains(body, required) {
					t.Errorf("production Dockerfile must load Docker Secrets, missing %q", required)
				}
			}
		})
	}
}

func TestStockPHPProductionDockerfilesUseOfficialCaddyRuntime(t *testing.T) {
	laravel := DockerfileLaravel(ModeAPI)
	if strings.Contains(laravel, "octane:") || strings.Contains(laravel, "laravel/octane") {
		t.Fatal("stock Laravel Dockerfile must not require optional Octane")
	}
	// Laravel's CMD goes through shuttle-laravel-boot, which recreates the
	// storage skeleton inside the tmpfs and then execs the same server command.
	for _, required := range []string{"ENV SERVER_NAME=:8000", "ENV SERVER_ROOT=/app/public", `CMD ["/usr/local/bin/shuttle-laravel-boot", "frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"]`, "http://localhost:8000/up"} {
		if !strings.Contains(laravel, required) {
			t.Errorf("Laravel runtime missing %q", required)
		}
	}

	symfony := DockerfileSymfony(ModeAPI, false)
	// Symfony's CMD goes through shuttle-symfony-boot, which seeds the warm
	// cache into the tmpfs and then execs the very same server command.
	for _, required := range []string{"ENV SERVER_NAME=:8080", "ENV SERVER_ROOT=/app/public", "ENV DEFAULT_URI=http://localhost", `CMD ["/usr/local/bin/shuttle-symfony-boot", "frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"]`, "http://localhost:8080/__shuttle_health"} {
		if !strings.Contains(symfony, required) {
			t.Errorf("Symfony runtime missing %q", required)
		}
	}
}

func TestPHPDevelopmentDockerfilesAreSourceMountFriendly(t *testing.T) {
	for name, testCase := range map[string]struct {
		body string
		port string
	}{
		"laravel": {DockerfileLaravelDev(), "8000"},
		"symfony": {DockerfileSymfonyDev(), "8080"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.HasPrefix(testCase.body, "FROM "+phpRuntimeImage+"\n") {
				t.Fatal("development Dockerfile must start from the official FrankenPHP runtime")
			}
			for _, required := range []string{
				"WORKDIR /app",
				"Mount the application source with ./:/app.",
				"ENV SERVER_ROOT=/app/public",
				"ENV SERVER_NAME=:" + testCase.port,
				"setcap -r /usr/local/bin/frankenphp",
				"setpriv --reuid=www-data --regid=www-data --clear-groups",
				"EXPOSE " + testCase.port,
			} {
				if !strings.Contains(testCase.body, required) {
					t.Errorf("development Dockerfile missing %q", required)
				}
			}
			if name == "laravel" {
				for _, required := range []string{"ENV SESSION_DRIVER=file", "ENV CACHE_STORE=file", "ENV QUEUE_CONNECTION=sync"} {
					if !strings.Contains(testCase.body, required) {
						t.Errorf("Laravel development Dockerfile missing %q", required)
					}
				}
			}
			if strings.Contains(testCase.body, "COPY .") {
				t.Fatal("development Dockerfile must leave source code to the host mount")
			}
			if strings.Contains(testCase.body, "chown -R www-data:www-data /app") {
				t.Fatal("runtime must not recursively rewrite ownership of the mounted source tree")
			}
		})
	}
}

// TestPHPProductionStageRunsRuntimeWorkBeforeTheApplicationCopy locks the layer
// ordering of the final stage. `COPY --from=app-tree /app /app` carries the
// commit, so it is a cache miss on every deploy: any instruction placed after it
// is re-executed every time. Only instructions that actually read or write /app
// have a reason to be there. Everything else — the dpkg purge and its trigger
// chain, the apt cleanup, setcap, the /data and /config chown, the generated
// entrypoint — must sit above the copy so it stays cached across deploys.
func TestPHPProductionStageRunsRuntimeWorkBeforeTheApplicationCopy(t *testing.T) {
	const appCopy = "--from=app-tree /app /app"

	cases := map[string]struct {
		body string
		// afterCopy are the markers that legitimately depend on /app.
		afterCopy []string
	}{
		"laravel-api":      {DockerfileLaravel(ModeAPI), []string{"mkdir -p \\\n    storage/app/public", "chown -R www-data:www-data storage bootstrap/cache database"}},
		"laravel-monolith": {DockerfileLaravel(ModeMonolith), []string{"mkdir -p \\\n    storage/app/public", "chown -R www-data:www-data storage bootstrap/cache database"}},
		"symfony-api":      {DockerfileSymfony(ModeAPI, false), []string{"chown -R www-data:www-data var"}},
		"symfony-monolith": {DockerfileSymfony(ModeMonolith, true), []string{"chown -R www-data:www-data var"}},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			start := strings.Index(testCase.body, "AS prod\n")
			if start < 0 {
				t.Fatal("no production stage found")
			}
			stage := testCase.body[start:]

			// The copy must be --link so the hardening layers above it can change
			// without forcing the whole application tree to be re-copied.
			if !strings.Contains(stage, "COPY --link "+appCopy) {
				t.Error("application copy must use COPY --link")
			}

			copyAt := strings.Index(stage, appCopy)
			if copyAt < 0 {
				t.Fatal("production stage does not copy the application tree")
			}

			// Cacheable runtime work: never touches /app, must precede the copy.
			for _, marker := range []string{
				"apt-get purge -y --auto-remove $PHPIZE_DEPS",
				"cat > /usr/local/bin/shuttle-secrets-entrypoint",
				"setcap -r /usr/local/bin/frankenphp",
				"chown -R www-data:www-data /data /config",
				"apt-get clean",
				"rm -rf /var/lib/apt/lists/*",
				"rm -f /usr/local/bin/docker-php-ext-*",
			} {
				at := strings.Index(stage, marker)
				if at < 0 {
					t.Errorf("production stage lost %q", marker)
					continue
				}
				if at > copyAt {
					t.Errorf("%q runs after the application copy, so it is re-executed on every deploy", marker)
				}
			}

			// /app-dependent work has to stay after the copy to be effective.
			for _, marker := range testCase.afterCopy {
				at := strings.Index(stage, marker)
				if at < 0 {
					t.Errorf("production stage lost %q", marker)
					continue
				}
				if at < copyAt {
					t.Errorf("%q runs before the application copy, so the copy overwrites it", marker)
				}
			}

			// The privilege drop closes the stage; reordering must not lift it
			// above the copy, which would run the remaining steps as www-data.
			userAt := strings.Index(stage, "\nUSER www-data\n")
			if userAt < copyAt {
				t.Error("USER www-data must remain after the application copy")
			}
			if strings.Contains(stage, "setcap -r") && strings.Contains(stage[copyAt:], "setcap ") {
				t.Error("no capability work may remain after the application copy")
			}
		})
	}
}

// TestPHPBuildersWarmTheFrameworkCacheBeforeTheProductionCopy locks the fix for
// the dominant promotion cost: a PHP image that ships no framework cache pays
// for building it on the first request of every task, under cpus: "1.0", and
// pays again for the next task. The warmup therefore has to happen in the
// builder stage, above `COPY --from=app-tree /app /app`, not at runtime.
func TestPHPBuildersWarmTheFrameworkCacheBeforeTheProductionCopy(t *testing.T) {
	cases := map[string]struct {
		body   string
		warmup []string
	}{
		"laravel-api":      {DockerfileLaravel(ModeAPI), []string{"php artisan route:cache"}},
		"laravel-monolith": {DockerfileLaravel(ModeMonolith), []string{"php artisan route:cache"}},
		"symfony-api":      {DockerfileSymfony(ModeAPI, false), []string{"bin/console cache:warmup --no-optional-warmers"}},
		"symfony-monolith": {DockerfileSymfony(ModeMonolith, true), []string{"bin/console cache:warmup --no-optional-warmers"}},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			builderAt := strings.Index(testCase.body, "AS builder\n")
			if builderAt < 0 {
				t.Fatal("no builder stage found")
			}
			copyAt := strings.Index(testCase.body, "--from=app-tree /app /app")
			if copyAt < 0 {
				t.Fatal("production stage does not copy the application tree")
			}
			for _, marker := range testCase.warmup {
				at := strings.Index(testCase.body, marker)
				if at < 0 {
					t.Fatalf("framework cache is never warmed at build time: missing %q", marker)
				}
				if at < builderAt {
					t.Errorf("%q runs before the builder stage starts", marker)
				}
				if at > copyAt {
					t.Errorf("%q runs after the production copy, so its output never reaches the image", marker)
				}
			}
			// The heredoc is handed to a plain /bin/sh: without `set -e` a failed
			// warmup or dump-autoload would silently produce a broken image.
			if !strings.Contains(testCase.body[builderAt:copyAt], "\nset -e\n") {
				t.Error("builder heredoc must abort on the first failure")
			}
		})
	}
}

// TestLaravelBuildNeverFreezesRuntimeSecretsOrMaskedCaches guards the two
// artisan caches that were deliberately left out.
func TestLaravelBuildNeverFreezesRuntimeSecrets(t *testing.T) {
	for name, body := range map[string]string{
		"api":      DockerfileLaravel(ModeAPI),
		"monolith": DockerfileLaravel(ModeMonolith),
	} {
		t.Run(name, func(t *testing.T) {
			// config:cache resolves every env() call at build time. Shuttle
			// delivers secrets through shuttle-secrets-entrypoint at container
			// start, so a cached config pins APP_KEY and DB_PASSWORD to empty
			// and silently ignores the injected values.
			if strings.Contains(body, "artisan config:cache") {
				t.Error("config:cache freezes build-time env() values and breaks Docker Secret injection")
			}
			// view:cache writes into storage/framework/views, which presetTmpfs
			// must keep as a tmpfs, so its output would be masked at runtime.
			if strings.Contains(body, "artisan view:cache") {
				t.Error("view:cache output is masked by the storage tmpfs")
			}
			// A route table that cannot be serialized is a valid application,
			// not a broken build, so that one command opts out explicitly.
			if !strings.Contains(body, "php artisan route:cache || {") {
				t.Error("route:cache must fail non-fatally, and only route:cache")
			}
			if strings.Contains(body, "|| true") {
				t.Error("no blanket failure suppression in the generated Dockerfile")
			}
		})
	}
}

// TestSymfonyWarmCacheSurvivesTheRuntimeTmpfs checks the other half of the fix.
// Symfony writes into var/cache while serving, so that path has to stay a
// tmpfs; the warmed cache is therefore parked outside the mount and copied in
// at boot. Building it straight into var/cache would be invisible at runtime.
func TestSymfonyWarmCacheSurvivesTheRuntimeTmpfs(t *testing.T) {
	for name, body := range map[string]string{
		"api":      DockerfileSymfony(ModeAPI, false),
		"monolith": DockerfileSymfony(ModeMonolith, true),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(body, "mv var/cache/prod var/shuttle-warm-cache/prod") {
				t.Fatal("the warmed cache must be parked outside the runtime tmpfs")
			}
			if !strings.Contains(body, "cat > /usr/local/bin/shuttle-symfony-boot") {
				t.Fatal("no boot wrapper to seed the tmpfs from the image")
			}
			for _, required := range []string{
				"warm=/app/var/shuttle-warm-cache/prod",
				"live=/app/var/cache/prod",
				`cp -a "$warm/." "$live/"`,
				`exec "$@"`,
			} {
				if !strings.Contains(body, required) {
					t.Errorf("boot wrapper missing %q", required)
				}
			}
			if !strings.Contains(body, `CMD ["/usr/local/bin/shuttle-symfony-boot", "frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"]`) {
				t.Fatal("the boot wrapper must be wired into CMD, behind the secrets entrypoint")
			}
			// The wrapper is a generator constant, so it must stay above the
			// per-commit application copy to remain cached.
			stage := body[strings.Index(body, "AS prod\n"):]
			if strings.Index(stage, "cat > /usr/local/bin/shuttle-symfony-boot") > strings.Index(stage, "--from=app-tree /app /app") {
				t.Error("the boot wrapper is rebuilt on every deploy; move it above the application copy")
			}
		})
	}
}

// TestLaravelBootRestoresTheStorageSkeletonInsideTheTmpfs covers the failure
// that kept Laravel from ever converging: /app/storage must stay a tmpfs, but
// the mount hides the tree the image created there and Laravel dies on the
// first request with "Please provide a valid cache path". The wrapper recreates
// it before the server starts.
func TestLaravelBootRestoresTheStorageSkeletonInsideTheTmpfs(t *testing.T) {
	for name, body := range map[string]string{
		"api":      DockerfileLaravel(ModeAPI),
		"monolith": DockerfileLaravel(ModeMonolith),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(body, "cat > /usr/local/bin/shuttle-laravel-boot") {
				t.Fatal("no boot wrapper to repopulate the storage tmpfs")
			}
			for _, required := range []string{
				"mkdir -p /app/storage/app/public \\",
				"/app/storage/framework/cache/data \\",
				"/app/storage/framework/sessions \\",
				"/app/storage/framework/views \\",
				"/app/storage/logs",
				`exec "$@"`,
			} {
				if !strings.Contains(body, required) {
					t.Errorf("boot wrapper missing %q", required)
				}
			}
			// bootstrap/cache is image content now; recreating it at boot would
			// mean the build-time caches were expected to be missing.
			if strings.Contains(body, "mkdir -p /app/bootstrap/cache") {
				t.Error("bootstrap/cache is built into the image and must not be recreated at boot")
			}
			stage := body[strings.Index(body, "AS prod\n"):]
			if strings.Index(stage, "cat > /usr/local/bin/shuttle-laravel-boot") > strings.Index(stage, "--from=app-tree /app /app") {
				t.Error("the boot wrapper is rebuilt on every deploy; move it above the application copy")
			}
		})
	}
}

func TestPHPImagesPrepareWritableSwarmTmpfsMountpoints(t *testing.T) {
	if !strings.Contains(DockerfileLaravel(ModeAPI), "chmod 1777 storage") {
		t.Fatal("Laravel storage tmpfs must inherit a writable image mode")
	}
	if !strings.Contains(DockerfileSymfony(ModeAPI, false), "chmod 1777 var/cache var/log") {
		t.Fatal("Symfony cache and log tmpfs must inherit writable image modes")
	}
}

// phpDockerfileCase describes one generated production Dockerfile that carries
// a composer install: both frameworks, with and without the asset stage.
type phpDockerfileCase struct {
	body string
	// depsFrom is the FROM line of the deps stage: the very stage the builder
	// started from before vendor/ got a layer of its own.
	depsFrom string
	// install is the composer install line, exactly as the builder had it.
	install string
	// locks is the COPY of the manifests and lock files.
	locks string
	// before are prerequisites of the install that are not COPYs of the
	// extensions or the composer binary (environment, php.ini).
	before []string
}

func phpDockerfileCases() map[string]phpDockerfileCase {
	const laravelInstall = "RUN composer install --prefer-dist --no-dev --no-autoloader --no-scripts --no-progress"
	const symfonyInstall = "RUN composer install --no-cache --prefer-dist --no-dev --no-autoloader --no-scripts --no-progress"
	laravelLocks := "COPY --link composer.json composer.lock ./"
	symfonyLocks := "COPY --link composer.json composer.lock symfony.lock ./"
	symfonyBefore := []string{"ENV APP_ENV=prod", `RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"`}
	return map[string]phpDockerfileCase{
		"laravel-api":      {DockerfileLaravel(ModeAPI), "FROM base AS deps\n", laravelInstall, laravelLocks, nil},
		"laravel-monolith": {DockerfileLaravel(ModeMonolith), "FROM base AS deps\n", laravelInstall, laravelLocks, nil},
		"symfony-api":      {DockerfileSymfony(ModeAPI, false), "FROM app-base AS deps\n", symfonyInstall, symfonyLocks, symfonyBefore},
		"symfony-monolith": {DockerfileSymfony(ModeMonolith, true), "FROM app-base AS deps\n", symfonyInstall, symfonyLocks, symfonyBefore},
	}
}

// phpStageBody returns the text of one Dockerfile stage, from its FROM line up
// to the next stage header or the end of the file.
func phpStageBody(t *testing.T, dockerfile, fromLine string) string {
	t.Helper()
	start := strings.Index(dockerfile, fromLine)
	if start < 0 {
		t.Fatalf("stage %q not found", fromLine)
	}
	rest := dockerfile[start+len(fromLine):]
	end := len(rest)
	for _, marker := range []string{"\nFROM ", "\n# ── "} {
		if at := strings.Index(rest, marker); at >= 0 && at < end {
			end = at
		}
	}
	return rest[:end]
}

// TestPHPDepsStageCarriesEverythingComposerInstallNeedsInOrder pins the layer
// that makes a code-only release cheap: vendor/ is produced by a stage whose
// inputs are the extensions, the environment, the php.ini and the lock files,
// and nothing from the sources. If any of them moved after the install, or the
// sources were copied before it, vendor/ would be rebuilt (and re-pushed) by
// every commit. DEV-DEPL-83.
func TestPHPDepsStageCarriesEverythingComposerInstallNeedsInOrder(t *testing.T) {
	for name, testCase := range phpDockerfileCases() {
		t.Run(name, func(t *testing.T) {
			deps := phpStageBody(t, testCase.body, testCase.depsFrom)

			// Every prerequisite must precede the lock files, which must
			// precede the install.
			prerequisites := []string{
				"COPY --from=composer /composer /usr/local/bin/composer",
				"COPY --from=extensions /usr/local/lib/php/extensions /usr/local/lib/php/extensions",
				"COPY --from=extensions /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d",
				"COPY --from=extensions /tmp/php-extension-libs /usr/lib/",
				"ENV COMPOSER_ALLOW_SUPERUSER=1",
			}
			prerequisites = append(prerequisites, testCase.before...)
			lockAt := strings.Index(deps, testCase.locks)
			installAt := strings.Index(deps, testCase.install)
			if lockAt < 0 || installAt < 0 {
				t.Fatalf("deps stage must contain %q and %q:\n%s", testCase.locks, testCase.install, deps)
			}
			if lockAt > installAt {
				t.Error("the lock files must be copied before composer install")
			}
			for _, marker := range prerequisites {
				at := strings.Index(deps, marker)
				if at < 0 {
					t.Errorf("deps stage is missing %q", marker)
					continue
				}
				if at > lockAt {
					t.Errorf("deps stage runs %q after the lock files, so composer install would not see it", marker)
				}
			}
			if strings.Count(deps, "composer install") != 1 {
				t.Errorf("deps stage must run composer install exactly once:\n%s", deps)
			}
			// The sources never enter this stage, otherwise every commit would
			// invalidate vendor/.
			if strings.Contains(deps, "COPY --link . .") {
				t.Error("deps stage must not copy the application sources")
			}

			builder := phpStageBody(t, testCase.body, "FROM deps AS builder\n")
			if strings.Index(testCase.body, testCase.depsFrom) > strings.Index(testCase.body, "FROM deps AS builder\n") {
				t.Error("deps must be declared before builder")
			}
			if strings.Contains(builder, "composer install") {
				t.Error("builder inherits vendor/ from deps and must not install it again")
			}
			for _, marker := range []string{"COPY --link . .", "composer dump-autoload --classmap-authoritative --no-dev", "composer check-platform-reqs --no-dev"} {
				if !strings.Contains(builder, marker) {
					t.Errorf("builder lost %q", marker)
				}
			}
		})
	}
}

// TestPHPAppTreeStageKeepsOnlyWhatChangesWithTheCode runs the generated clean-up
// command against a fake vendor/: packages are removed, while vendor/composer/
// and vendor/autoload*.php (rewritten by dump-autoload on every code change)
// are kept.
func TestPHPAppTreeStageKeepsOnlyWhatChangesWithTheCode(t *testing.T) {
	for name, testCase := range phpDockerfileCases() {
		t.Run(name, func(t *testing.T) {
			appTree := phpStageBody(t, testCase.body, "FROM builder AS app-tree\n")
			var command string
			for _, line := range strings.Split(appTree, "\n") {
				if !strings.HasPrefix(line, "RUN ") {
					continue
				}
				if command != "" {
					t.Fatalf("app-tree must have a single RUN, got a second: %q", line)
				}
				command = strings.TrimPrefix(line, "RUN ")
			}
			if command == "" {
				t.Fatal("app-tree has no RUN")
			}

			root := t.TempDir()
			vendor := filepath.Join(root, "vendor")
			kept := []string{"composer/installed.json", "composer/autoload_classmap.php", "autoload.php", "autoload_runtime.php"}
			removed := []string{"laravel/framework/src/Foo.php", "symfony/console/Bar.php", "bin/phpunit", "notes.txt", "composer-plugin/x.php"}
			for _, rel := range append(append([]string{}, kept...), removed...) {
				path := filepath.Join(vendor, rel)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// Application files outside vendor/ are untouched.
			if err := os.WriteFile(filepath.Join(root, "composer.json"), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("sh", "-c", command)
			cmd.Dir = root
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("app-tree command failed: %v: %s", err, output)
			}
			for _, rel := range kept {
				if _, err := os.Stat(filepath.Join(vendor, rel)); err != nil {
					t.Errorf("app-tree removed %s, which changes with every code change", rel)
				}
			}
			for _, rel := range removed {
				if _, err := os.Stat(filepath.Join(vendor, rel)); err == nil {
					t.Errorf("app-tree kept %s, which belongs to the deps layer", rel)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "composer.json")); err != nil {
				t.Error("app-tree must not touch files outside vendor/")
			}
		})
	}
}

// TestPHPProductionStageCopiesVendorBeforeTheApplicationTree pins the two
// COPY --link lines: vendor/ first, from deps, as a layer of its own; then the
// application tree, which carries vendor/composer and vendor/autoload*.php.
func TestPHPProductionStageCopiesVendorBeforeTheApplicationTree(t *testing.T) {
	const vendorCopy = "COPY --link --from=deps /app/vendor /app/vendor\n"
	const treeCopy = "COPY --link --from=app-tree /app /app\n"
	for name, testCase := range phpDockerfileCases() {
		t.Run(name, func(t *testing.T) {
			prod := testCase.body[strings.LastIndex(testCase.body, " AS prod\n"):]
			vendorAt := strings.Index(prod, vendorCopy)
			treeAt := strings.Index(prod, treeCopy)
			if vendorAt < 0 || treeAt < 0 {
				t.Fatalf("prod must contain both %q and %q", vendorCopy, treeCopy)
			}
			if vendorAt > treeAt {
				t.Error("vendor/ must be copied before the application tree")
			}
			if strings.Contains(prod, "--from=builder") {
				t.Error("prod must no longer copy the whole builder tree")
			}
			// Capabilities are cleared before the copies; ownership of /app is
			// settled after them.
			if setcapAt := strings.Index(prod, "setcap -r /usr/local/bin/frankenphp"); setcapAt < 0 || setcapAt > vendorAt {
				t.Error("setcap must stay before the vendor copy")
			}
			if strings.LastIndex(prod, "chown -R www-data:www-data ") < treeAt {
				t.Error("the ownership step must stay after the application copy")
			}
			if strings.Contains(testCase.body, " AS assets\n") {
				if !strings.Contains(prod[treeAt:], "COPY --from=assets /app/public/build /app/public/build") {
					t.Error("the asset copy must stay unchanged, after the application tree")
				}
			}
		})
	}
}
