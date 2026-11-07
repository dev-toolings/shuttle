package templates

// ModeAPI builds a headless service: no frontend toolchain, no compiled
// assets, smallest runtime closure.
const ModeAPI = "api"

// ModeMonolith builds an app that also serves its own frontend, so the image
// needs the Vite/asset output. The Bun toolchain stays in a separate stage
// and never reaches the runtime image.
const ModeMonolith = "monolith"

// The generator replaces these placeholders with registry-resolved identities.
const phpRuntimeImage = "__SHUTTLE_FRANKENPHP_IMAGE__"

// composerImage supplies Composer only to build stages; generated production
// images never retain it.
const composerImage = "composer/composer:2-bin"

const bunAssetImage = "__SHUTTLE_BUN_IMAGE__"

// IsMode reports whether the given value is a supported build mode.
func IsMode(mode string) bool {
	return mode == ModeAPI || mode == ModeMonolith
}

// DockerfileLaravelDev returns the official FrankenPHP development image. The
// project source is intentionally not copied: mount ./:/app to iterate on the
// host files without rebuilding the image.
func DockerfileLaravelDev() string {
	return `FROM ` + phpRuntimeImage + `

WORKDIR /app

# Mount the application source with ./:/app.
ENV SERVER_NAME=:8000
ENV SERVER_ROOT=/app/public
# FrankenPHP embeds Caddy, which provisions a local CA and autosaves its config
# before serving a single request. It writes those under XDG_DATA_HOME and
# XDG_CONFIG_HOME, defaulting to /data and /config. Shuttle runs every service
# with read_only: true and the server drops to www-data before Caddy starts, so
# both defaults fail: first "read-only file system", then "permission denied" on
# a root-owned mount. Pointing them at /tmp, which is always a writable tmpfs,
# keeps the boot path working without widening the container's write surface.
ENV XDG_DATA_HOME=/tmp/caddy-data
ENV XDG_CONFIG_HOME=/tmp/caddy-config
# Stock Laravel scaffolds use SQLite-backed cache, queue and sessions. Keep
# development state inside the writable framework directories rather than
# requiring a root-owned bind-mounted database file to be writable.
ENV SESSION_DRIVER=file
ENV CACHE_STORE=file
ENV QUEUE_CONNECTION=sync

RUN setcap -r /usr/local/bin/frankenphp && \
    chown -R www-data:www-data /data /config

EXPOSE 8000

# A bind mount replaces /app and its ownership. Prepare only Laravel's writable
# directories as root, then drop all supplementary groups and privileges before
# FrankenPHP starts; application code never runs as root.
CMD ["sh", "-c", "mkdir -p storage/app/public storage/framework/cache storage/framework/sessions storage/framework/views storage/logs bootstrap/cache && chown -R www-data:www-data storage bootstrap/cache && exec setpriv --reuid=www-data --regid=www-data --clear-groups frankenphp run --config /etc/frankenphp/Caddyfile"]
`
}

// DockerfileSymfonyDev returns the official FrankenPHP development image. The
// project source is intentionally not copied: mount ./:/app to iterate on the
// host files without rebuilding the image.
func DockerfileSymfonyDev() string {
	return `FROM ` + phpRuntimeImage + `

WORKDIR /app

# Mount the application source with ./:/app.
ENV SERVER_NAME=:8080
ENV SERVER_ROOT=/app/public
# FrankenPHP embeds Caddy, which provisions a local CA and autosaves its config
# before serving a single request. It writes those under XDG_DATA_HOME and
# XDG_CONFIG_HOME, defaulting to /data and /config. Shuttle runs every service
# with read_only: true and the server drops to www-data before Caddy starts, so
# both defaults fail: first "read-only file system", then "permission denied" on
# a root-owned mount. Pointing them at /tmp, which is always a writable tmpfs,
# keeps the boot path working without widening the container's write surface.
ENV XDG_DATA_HOME=/tmp/caddy-data
ENV XDG_CONFIG_HOME=/tmp/caddy-config

RUN setcap -r /usr/local/bin/frankenphp && \
    chown -R www-data:www-data /data /config

EXPOSE 8080

# A bind mount replaces /app and its ownership. Prepare only Symfony's writable
# var directory, then drop all privileges before application code executes.
CMD ["sh", "-c", "mkdir -p var/cache var/log && chown -R www-data:www-data var && exec setpriv --reuid=www-data --regid=www-data --clear-groups frankenphp run --config /etc/frankenphp/Caddyfile"]
`
}

// laravelAssetParts returns the optional Vite build stage and the copy that
// pulls its output into the runtime image. API mode returns empty strings, so
// the generated Dockerfile carries no Node toolchain at all.
func laravelAssetParts(mode string) (stage string, copyStep string) {
	if mode != ModeMonolith {
		return "", ""
	}
	stage = `
# ── Asset stage ───────────────────────────────────────────────
# Monolith only. Bun lives here and never reaches the runtime image.
FROM ` + bunAssetImage + ` AS assets

WORKDIR /app

# A committed Bun text lockfile is the reproducibility contract.
COPY --link package.json bun.lock ./
RUN bun install --frozen-lockfile

# Whole context rather than an enumerated list: COPY fails outright on a
# missing source, and not every project has tailwind.config.js or postcss.
# .dockerignore already keeps vendor/ and node_modules/ out, so this stays
# small (measured at 644 kB on a stock Laravel app).
COPY --link . .
RUN bun run build
`
	copyStep = `
# Compiled Vite output. Kept out of the builder stage so a CSS change does not
# invalidate the composer layers.
COPY --from=assets /app/public/build /app/public/build
`
	return stage, copyStep
}

// DockerfileLaravel returns a production-ready Dockerfile for Laravel
// using the stock FrankenPHP Caddy configuration.
// It intentionally works with a stock Laravel installation (no Octane needed).
// Uses Debian (not Alpine) to avoid musl libc issues.
func DockerfileLaravel(mode string) string {
	assetStage, assetCopy := laravelAssetParts(mode)
	return `#syntax=docker/dockerfile:1
ARG SHUTTLE_PHP_RUNTIME=` + phpRuntimeImage + `
FROM ${SHUTTLE_PHP_RUNTIME} AS base

USER root
WORKDIR /app

FROM ` + composerImage + ` AS composer

# ── PHP extension stage ───────────────────────────────────────
# Compilers and extension installers remain here, never in production.
FROM base AS extensions

RUN install-php-extensions \
    bcmath \
    gd \
    intl \
    opcache \
    pcntl \
    pdo_mysql \
    pdo_pgsql \
    redis \
    zip

# Copy the shared-library closure required by the installed extensions. This
# follows the official FrankenPHP hardening guidance while retaining Debian.
RUN <<EOF
apt-get update
apt-get install -y --no-install-recommends libtree
EXT_DIR="$(php -r 'echo ini_get("extension_dir");')"
mkdir -p /tmp/php-extension-libs
for target in $(find "$EXT_DIR" -type f -name '*.so'); do
    libtree -pv "$target" | sed 's/.*── \(.*\) \[.*/\1/' | while IFS= read -r lib; do
        [ -f "$lib" ] || continue
        cp -n "$lib" /tmp/php-extension-libs/
    done
done
EOF

# ── Dependency stage ──────────────────────────────────────────
# vendor/ lives in its own stage so that it is also its own image layer in the
# production stage. Its inputs are composer.json, composer.lock and the PHP
# extensions: a code-only release leaves all three untouched, so this stage and
# the layer copied from it keep the same digest and the registry does not
# receive vendor/ again (DEV-DEPL-83).
FROM base AS deps

COPY --from=composer /composer /usr/local/bin/composer
COPY --from=extensions /usr/local/lib/php/extensions /usr/local/lib/php/extensions
COPY --from=extensions /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d
COPY --from=extensions /tmp/php-extension-libs /usr/lib/

ENV COMPOSER_ALLOW_SUPERUSER=1

COPY --link composer.json composer.lock ./
RUN composer install --prefer-dist --no-dev --no-autoloader --no-scripts --no-progress

# ── Build stage ───────────────────────────────────────────────
FROM deps AS builder

COPY --link . .

RUN <<EOF
# A Dockerfile heredoc is fed to a plain /bin/sh, which does not stop on the
# first failure: without this, a broken dump-autoload would silently ship an
# image whose package manifest is missing. Failures below are fatal unless a
# step explicitly opts out.
set -e
# post-autoload-dump runs artisan package:discover, which writes
# bootstrap/cache/packages.php and services.php. That is the whole reason
# bootstrap/cache is no longer a tmpfs at runtime (see presetTmpfs): with the
# mount in place the manifest was hidden and Laravel re-scanned every installed
# package on the first request of every task.
composer dump-autoload --classmap-authoritative --no-dev
composer check-platform-reqs --no-dev
chmod +x artisan
# Serialize the route table into bootstrap/cache. FrankenPHP serves in
# request-per-boot mode, so without this every single request re-parses
# routes/*.php and re-registers every route.
#
# Targeted opt-out: route caching legitimately fails on projects whose routes
# bind closures that cannot be serialized. That is a valid application, not a
# broken build, so drop the partial artifact and let Laravel register routes at
# runtime as before. Only this command is tolerated; everything else stays fatal.
php artisan route:cache || {
    echo "shuttle: route:cache skipped, this project's routes are not cacheable" >&2
    rm -f bootstrap/cache/routes-v*.php
}
# Deliberately NOT run here:
#
#   * config:cache — it freezes the value of every env() call into
#     bootstrap/cache/config.php. Shuttle delivers APP_KEY, DB_PASSWORD and
#     friends as Docker Secrets that shuttle-secrets-entrypoint exports at
#     container start, so at build time they do not exist: a cached config
#     would pin them to empty and the runtime values would be ignored
#     (verified: config("database.connections.pgsql.password") reads back empty
#     even with DB_PASSWORD set in the container). Building with a .env present
#     would be worse still, baking the secrets into a distributable image layer.
#
#   * view:cache — its output lands in storage/framework/views, which must stay
#     a tmpfs: Laravel's own /up route renders View::file() on a path outside
#     the view finder, so it is never precompiled and Blade has to compile it at
#     runtime. Precompiling here would be masked by the mount and buy nothing.
EOF

# ── Application tree ──────────────────────────────────────────
# The builder tree minus the installed packages, which the production stage
# takes from the deps stage instead. Two things in vendor/ are NOT packages and
# change with every code change, so they stay here: vendor/composer/ and
# vendor/autoload*.php. dump-autoload --classmap-authoritative rewrites them
# from the application classes, and composer plugins rewrite them with it.
FROM builder AS app-tree

RUN find vendor -mindepth 1 -maxdepth 1 ! -name composer ! -name 'autoload*.php' -exec rm -rf -- {} +

` + assetStage + `
# ── Production ────────────────────────────────────────────────
FROM base AS prod

ENV SERVER_NAME=:8000
ENV SERVER_ROOT=/app/public
# FrankenPHP embeds Caddy, which provisions a local CA and autosaves its config
# before serving a single request. It writes those under XDG_DATA_HOME and
# XDG_CONFIG_HOME, defaulting to /data and /config. Shuttle runs every service
# with read_only: true and the server drops to www-data before Caddy starts, so
# both defaults fail: first "read-only file system", then "permission denied" on
# a root-owned mount. Pointing them at /tmp, which is always a writable tmpfs,
# keeps the boot path working without widening the container's write surface.
ENV XDG_DATA_HOME=/tmp/caddy-data
ENV XDG_CONFIG_HOME=/tmp/caddy-config

RUN <<EOF
cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
printf '%s\n' \
    'opcache.enable=1' \
    'opcache.memory_consumption=256' \
    'opcache.max_accelerated_files=32531' \
    'opcache.interned_strings_buffer=16' \
    'opcache.validate_timestamps=0' \
    'opcache.enable_file_override=1' \
    'realpath_cache_size=4096K' \
    'realpath_cache_ttl=600' \
    'expose_php=0' \
    > "$PHP_INI_DIR/conf.d/99-shuttle-production.ini"
EOF

COPY --from=extensions /usr/local/lib/php/extensions /usr/local/lib/php/extensions
COPY --from=extensions /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d
COPY --from=extensions /tmp/php-extension-libs /usr/lib/

# Ordering rule for this stage: anything that does not read or write /app runs
# BEFORE the application copy. That copy carries the commit and is invalidated
# by every code change, so a hardening step placed after it is re-executed on
# every deploy — a dpkg purge with its trigger chain, an apt cleanup and a
# setcap, for a tree none of them ever look at.
#
# Use a non-privileged port, remove the image's build tooling and clear the
# bind-to-80/443 capability. Caddy's state directories stay writable.
RUN apt-get purge -y --auto-remove $PHPIZE_DEPS && \
    rm -f /usr/local/bin/docker-php-ext-* \
        /usr/local/bin/docker-php-source \
        /usr/local/bin/install-php-extensions \
        /usr/local/bin/pear \
        /usr/local/bin/peardev \
        /usr/local/bin/pecl \
        /usr/local/bin/phpize && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    setcap -r /usr/local/bin/frankenphp && \
    chown -R www-data:www-data /data /config

# The entrypoint is a build-time constant of the generator, never derived from
# the project, so it is cached once instead of being rewritten per commit.
RUN <<'EOF'
cat > /usr/local/bin/shuttle-secrets-entrypoint <<'SCRIPT'
` + SecretsEntrypoint() + `
SCRIPT
chmod 0755 /usr/local/bin/shuttle-secrets-entrypoint
EOF

# Also a generator constant, so it stays above the application copy and cached.
RUN <<'EOF'
cat > /usr/local/bin/shuttle-laravel-boot <<'SCRIPT'
#!/bin/sh
set -eu
# /app/storage is a tmpfs and has to stay one: read_only: true plus Laravel's
# runtime writes leave no alternative. Blade in particular compiles on demand —
# the framework's own /up route renders View::file() on a path outside the view
# finder, so no build-time view:cache can cover it.
#
# But the mount also hides the directory tree the image created underneath, and
# Laravel refuses to boot without it: the first request dies on
# "Please provide a valid cache path". Recreate the skeleton in the empty mount
# before handing over to the server. The directories below the mount points
# (bootstrap/cache) are image content now and are deliberately untouched.
mkdir -p /app/storage/app/public \
    /app/storage/framework/cache/data \
    /app/storage/framework/sessions \
    /app/storage/framework/views \
    /app/storage/frankenphp \
    /app/storage/logs
exec "$@"
SCRIPT
chmod 0755 /usr/local/bin/shuttle-laravel-boot
EOF

# --link makes each layer independent of the chain above it, so editing the
# hardening steps no longer forces the application tree to be re-copied.
#
# vendor/ goes first and alone: its content depends only on composer.lock and
# the PHP extensions, so a code-only release reuses the very same layer. The
# application tree follows and overlays vendor/composer/ and vendor/autoload*.php
# with the autoloader generated for this commit. Operator decision of
# 01-11-2026: no build-time diff of vendor/ is run, the default Laravel plugins
# do not write into vendor/ during dump-autoload.
COPY --link --from=deps /app/vendor /app/vendor
COPY --link --from=app-tree /app /app
` + assetCopy + `

# Stays after the copy: these are the only instructions in the stage that touch
# /app. Laravel needs the writable trees to exist and to be owned by www-data
# before the runtime drops privileges.
RUN <<EOF
mkdir -p \
    storage/app/public \
    storage/framework/cache \
    storage/framework/sessions \
    storage/framework/views \
    storage/logs \
    bootstrap/cache \
    database
mkdir -p storage/frankenphp
chown -R www-data:www-data storage bootstrap/cache database
chmod -R ug+rwx storage bootstrap/cache
# Swarm's legacy Compose converter drops tmpfs.mode. Docker inherits the
# mountpoint mode instead; prepare this writable cache before dropping root.
chmod 1777 storage
EOF

USER www-data

EXPOSE 8000

HEALTHCHECK --start-period=2s --interval=2s --timeout=2s --retries=5 \
    CMD php -r 'exit(false === @file_get_contents("http://localhost:8000/up", context: stream_context_create(["http" => ["timeout" => 3]])) ? 1 : 0);'

# The secrets bridge stays the entrypoint and execs this wrapper, which restores
# the writable storage skeleton inside the tmpfs before starting the server.
ENTRYPOINT ["/usr/local/bin/shuttle-secrets-entrypoint"]
CMD ["/usr/local/bin/shuttle-laravel-boot", "frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"]
`
}

// LaravelOpcacheIni returns the optimized OPcache config for Laravel production.
func LaravelOpcacheIni() string {
	return `; OPcache: production tuning for Laravel + FrankenPHP
opcache.enable = 1
opcache.memory_consumption = 256
opcache.max_accelerated_files = 32531
opcache.interned_strings_buffer = 16
opcache.validate_timestamps = 0
opcache.enable_file_override = 1

; Realpath cache
realpath_cache_size = 4096K
realpath_cache_ttl = 600

; Security
expose_php = 0
`
}

// symfonyAssetParts mirrors laravelAssetParts. Symfony's builder already runs
// asset-map:compile when importmap.php exists, which covers AssetMapper. This
// stage covers the Encore/Vite case, where a Node build is required.
func symfonyAssetParts(mode string, hasPackageJSON bool) (stage string, copyStep string) {
	if mode != ModeMonolith || !hasPackageJSON {
		return "", ""
	}
	stage = `
# ── Asset stage ───────────────────────────────────────────────
# Monolith only. Bun lives here and never reaches the runtime image.
# Skipped entirely when the project has no package.json (AssetMapper setups),
# so the stage is safe to keep in both cases.
FROM ` + bunAssetImage + ` AS assets

WORKDIR /app

COPY --link package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY --link . .
RUN bun run build
`
	copyStep = `
# Encore and Vite both emit into public/build.
COPY --from=assets /app/public/build /app/public/build
`
	return stage, copyStep
}

// DockerfileSymfony returns a production-ready Dockerfile for Symfony
// using the stock FrankenPHP Caddy configuration.
// It intentionally works with a stock Symfony installation and no docker/ tree.
func DockerfileSymfony(mode string, hasPackageJSON bool) string {
	assetStage, assetCopy := symfonyAssetParts(mode, hasPackageJSON)
	return `#syntax=docker/dockerfile:1
ARG SHUTTLE_PHP_RUNTIME=` + phpRuntimeImage + `
FROM ${SHUTTLE_PHP_RUNTIME} AS base

USER root
WORKDIR /app

FROM ` + composerImage + ` AS composer

# ── PHP extension stage ───────────────────────────────────────
# Compilers and extension installers remain here, never in production.
FROM base AS extensions

RUN install-php-extensions \
    apcu \
    intl \
    opcache \
    pdo_mysql \
    pdo_pgsql \
    redis \
    zip

# Copy the shared-library closure required by the installed extensions. This
# follows the official FrankenPHP hardening guidance while retaining Debian.
RUN <<EOF
apt-get update
apt-get install -y --no-install-recommends libtree
EXT_DIR="$(php -r 'echo ini_get("extension_dir");')"
mkdir -p /tmp/php-extension-libs
for target in $(find "$EXT_DIR" -type f -name '*.so'); do
    libtree -pv "$target" | sed 's/.*── \(.*\) \[.*/\1/' | while IFS= read -r lib; do
        [ -f "$lib" ] || continue
        cp -n "$lib" /tmp/php-extension-libs/
    done
done
EOF

FROM base AS app-base

ENV PHP_INI_SCAN_DIR=":$PHP_INI_DIR/app.conf.d"
# The prebuilt runtime defaults CADDY_ADMIN to the literal string "off" for
# its own generated config. Shuttle's Symfony healthcheck intentionally probes
# the local admin metrics endpoint, so give Caddy a valid loopback address.
ENV CADDY_ADMIN=127.0.0.1:2019
ENV APP_BASE_DIR=/app
ENV SERVER_ROOT=/app/public
# FrankenPHP embeds Caddy, which provisions a local CA and autosaves its config
# before serving a single request. It writes those under XDG_DATA_HOME and
# XDG_CONFIG_HOME, defaulting to /data and /config. Shuttle runs every service
# with read_only: true and the server drops to www-data before Caddy starts, so
# both defaults fail: first "read-only file system", then "permission denied" on
# a root-owned mount. Pointing them at /tmp, which is always a writable tmpfs,
# keeps the boot path working without widening the container's write surface.
ENV XDG_DATA_HOME=/tmp/caddy-data
ENV XDG_CONFIG_HOME=/tmp/caddy-config
ENV SERVER_NAME=:8080
ENV DEFAULT_URI=http://localhost
ENV APP_RUNTIME_OPTIONS='{"disable_dotenv":true}'

# ── Dependency stage ──────────────────────────────────────────
# vendor/ lives in its own stage so that it is also its own image layer in the
# production stage. Its inputs are composer.json, composer.lock, symfony.lock
# and the PHP extensions: a code-only release leaves all of them untouched, so
# this stage and the layer copied from it keep the same digest and the registry
# does not receive vendor/ again (DEV-DEPL-83).
FROM app-base AS deps

ENV APP_ENV=prod

COPY --from=composer /composer /usr/local/bin/composer
COPY --from=extensions /usr/local/lib/php/extensions /usr/local/lib/php/extensions
COPY --from=extensions /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d
COPY --from=extensions /tmp/php-extension-libs /usr/lib/

ENV COMPOSER_ALLOW_SUPERUSER=1

RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY --link composer.json composer.lock symfony.lock ./
RUN composer install --no-cache --prefer-dist --no-dev --no-autoloader --no-scripts --no-progress

# ── Build stage ───────────────────────────────────────────────
FROM deps AS builder

COPY --link . .

RUN <<EOF
# A Dockerfile heredoc is fed to a plain /bin/sh, which does not stop on the
# first failure. Make every step below fatal so a half-built image cannot ship;
# the one command allowed to fail says so explicitly.
set -e
composer dump-autoload --classmap-authoritative --no-dev
composer check-platform-reqs --no-dev
chmod +x bin/console
mkdir -p var/cache var/log
# Compile the production kernel here instead of on the first request of every
# task. APP_ENV=prod is set on this stage and APP_RUNTIME_OPTIONS disables
# dotenv on app-base, so the kernel boots from real environment variables only
# and never looks for the .env that .dockerignore keeps out of the context.
#
# --no-optional-warmers is load-bearing, not cosmetic. The optional warmers
# instantiate services, and Doctrine's resolve the DATABASE_URL environment
# variable; Shuttle only injects that from a Docker Secret at container start,
# so a plain cache:warmup aborts here with EnvNotFoundException on a stock
# webapp skeleton (verified). The mandatory warmers compile the dependency
# injection container — roughly 400 files, and the dominant share of a cold
# boot. The router matcher, Twig templates and translation catalogues come from
# optional warmers and stay lazily built at runtime, which is why var/cache has
# to remain writable there.
bin/console cache:warmup --no-optional-warmers
# Park the warmed cache outside var/cache. That directory is a tmpfs at runtime
# (see presetTmpfs: Symfony provably writes url_matching_routes.php, twig/,
# translations/ and pools/ into it while serving), and the mount would hide
# everything built above. shuttle-symfony-boot copies this tree back into the
# empty tmpfs once per container, which is a couple of megabytes instead of a
# full container compilation under the 1.0 CPU limit.
mkdir -p var/shuttle-warm-cache
mv var/cache/prod var/shuttle-warm-cache/prod
chmod -R g=u var
sync
EOF

# ── Application tree ──────────────────────────────────────────
# The builder tree minus the installed packages, which the production stage
# takes from the deps stage instead. Two things in vendor/ are NOT packages and
# change with every code change, so they stay here: vendor/composer/ and
# vendor/autoload*.php. dump-autoload --classmap-authoritative rewrites them
# from the application classes, and composer plugins rewrite them with it.
FROM builder AS app-tree

RUN find vendor -mindepth 1 -maxdepth 1 ! -name composer ! -name 'autoload*.php' -exec rm -rf -- {} +

` + assetStage + `
# ── Production ────────────────────────────────────────────────
FROM app-base AS prod

ENV APP_ENV=prod

RUN <<EOF
cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
printf '%s\n' \
    'expose_php=0' \
    'apc.enable_cli=1' \
    'session.use_strict_mode=1' \
    'realpath_cache_size=4096K' \
    'realpath_cache_ttl=600' \
    'opcache.interned_strings_buffer=16' \
    'opcache.max_accelerated_files=32531' \
    'opcache.memory_consumption=256' \
    'opcache.enable_file_override=1' \
    'opcache.validate_timestamps=0' \
    > "$PHP_INI_DIR/conf.d/99-shuttle-production.ini"
EOF

COPY --from=extensions /usr/local/lib/php/extensions /usr/local/lib/php/extensions
COPY --from=extensions /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d
COPY --from=extensions /tmp/php-extension-libs /usr/lib/

# Ordering rule for this stage: anything that does not read or write /app runs
# BEFORE the application copy. That copy carries the commit and is invalidated
# by every code change, so a hardening step placed after it is re-executed on
# every deploy — a dpkg purge with its trigger chain, an apt cleanup and a
# setcap, for a tree none of them ever look at.
#
# Remove the image's build tooling and clear the bind-to-80/443 capability.
# Caddy's own state directories stay writable.
RUN <<EOF
apt-get purge -y --auto-remove $PHPIZE_DEPS
rm -f /usr/local/bin/docker-php-ext-* \
    /usr/local/bin/docker-php-source \
    /usr/local/bin/install-php-extensions \
    /usr/local/bin/pear \
    /usr/local/bin/peardev \
    /usr/local/bin/pecl \
    /usr/local/bin/phpize
apt-get clean
rm -rf /var/lib/apt/lists/*
setcap -r /usr/local/bin/frankenphp
chown -R www-data:www-data /data /config
EOF

# The entrypoint is a build-time constant of the generator, never derived from
# the project, so it is cached once instead of being rewritten per commit.
RUN <<'EOF'
cat > /usr/local/bin/shuttle-secrets-entrypoint <<'SCRIPT'
` + SecretsEntrypoint() + `
SCRIPT
chmod 0755 /usr/local/bin/shuttle-secrets-entrypoint
EOF

# Also a generator constant, so it stays above the application copy and cached.
RUN <<'EOF'
cat > /usr/local/bin/shuttle-symfony-boot <<'SCRIPT'
#!/bin/sh
set -eu
# /app/var/cache is a tmpfs because read_only: true plus Symfony's runtime
# writes (router matcher, compiled Twig templates, translation catalogues,
# cache pools) leave no alternative. An empty tmpfs means the kernel recompiles
# its whole dependency injection container on the first request of every task,
# which is what dominated promotion time. Seed the mount from the copy the
# builder parked outside it, once per container.
warm=/app/var/shuttle-warm-cache/prod
live=/app/var/cache/prod
if [ -d "$warm" ] && [ -z "$(ls -A "$live" 2>/dev/null || true)" ]; then
    # Degrade rather than refuse to boot: without the seed Symfony rebuilds the
    # cache itself, which is exactly the behaviour this wrapper optimises away.
    { mkdir -p "$live" && cp -a "$warm/." "$live/"; } ||
        echo "shuttle: could not seed the Symfony cache, the kernel will rebuild it" >&2
fi
exec "$@"
SCRIPT
chmod 0755 /usr/local/bin/shuttle-symfony-boot
EOF

# --link makes each layer independent of the chain above it, so editing the
# hardening steps no longer forces the application tree to be re-copied.
#
# vendor/ goes first and alone: its content depends only on the lock files and
# the PHP extensions, so a code-only release reuses the very same layer. The
# application tree follows and overlays vendor/composer/ and vendor/autoload*.php
# with the autoloader generated for this commit. Operator decision of
# 01-11-2026: no build-time diff of vendor/ is run, the default Symfony plugins
# do not write into vendor/ during dump-autoload.
COPY --link --from=deps /app/vendor /app/vendor
COPY --link --from=app-tree /app /app
` + assetCopy + `

# Stays after the copy: var/ is the only /app path Symfony writes at runtime and
# it must be owned by www-data. The builder already ran chmod -R g=u on it and
# COPY preserves modes, so that part is not repeated here.
RUN chown -R www-data:www-data var && chmod 1777 var/cache var/log

USER www-data

EXPOSE 8080

# The default Caddy configuration forwards this non-static path to Symfony;
# any non-5xx application response proves the web runtime is available.
HEALTHCHECK --start-period=2s --interval=2s --timeout=2s --retries=5 \
    CMD php -r '$h=@get_headers("http://localhost:8080/__shuttle_health"); exit($h && preg_match("/ ([1-4][0-9]{2}) /", $h[0]) ? 0 : 1);'

# The secrets bridge stays the entrypoint and execs this wrapper, which seeds
# the warm cache into the tmpfs before handing over to the server.
ENTRYPOINT ["/usr/local/bin/shuttle-secrets-entrypoint"]
CMD ["/usr/local/bin/shuttle-symfony-boot", "frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"]
`
}

// SymfonyCaddyfile returns the production Caddyfile for generic Symfony apps.
func SymfonyCaddyfile() string {
	return `{
    {$CADDY_GLOBAL_OPTIONS}

    frankenphp {
        {$FRANKENPHP_CONFIG}
    }
}

{$SERVER_NAME:localhost} {
    root /app/public
    encode zstd br gzip

    header {
        X-Content-Type-Options    nosniff
        X-Frame-Options           DENY
        Referrer-Policy            strict-origin-when-cross-origin
        ?Permissions-Policy       "browsing-topics=()"
        -Server
        -X-Powered-By
    }

    @phpRoute {
        not file {path}
    }
    rewrite @phpRoute index.php

	@frontController path index.php
	# Generic Symfony projects do not necessarily require the optional
	# runtime/frankenphp-symfony package. Serve regular PHP requests here;
	# projects that deliberately install and lock that runtime may opt into
	# worker mode in their own Caddyfile.
	php @frontController

    file_server {
        hide *.php
        hide .env*
        hide .git*
    }
}
`
}

// SymfonyBaseIni returns the shared PHP config (dev + prod).
func SymfonyBaseIni() string {
	return `; Security
expose_php = 0

; Timezone
date.timezone = UTC

; APCu
apc.enable_cli = 1

; Session
session.use_strict_mode = 1

; Performance
zend.detect_unicode = 0
realpath_cache_size = 4096K
realpath_cache_ttl = 600

; OPcache
opcache.interned_strings_buffer = 16
opcache.max_accelerated_files = 32531
opcache.memory_consumption = 256
opcache.enable_file_override = 1
`
}

// SymfonyProdIni returns the production-only PHP config.
func SymfonyProdIni() string {
	return `; OPcache: production only
opcache.preload_user = www-data
opcache.preload = /app/config/preload.php
opcache.validate_timestamps = 0
`
}
