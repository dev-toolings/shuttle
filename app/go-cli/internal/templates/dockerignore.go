package templates

// Dockerignore returns a .dockerignore tailored to the given preset.
// It combines a shared base with preset-specific additions.
func Dockerignore(preset string) string {
	base := `.git
.gitignore
docker-compose*.yml
shuttle.yml
config.json
.shuttle/
README.md
.env
.env.*
`

	switch preset {
	case "laravel":
		// bootstrap/cache holds the package-discovery and config caches built
		// on the developer machine, where dev dependencies are present. The
		// image installs --no-dev, so shipping that cache makes the container
		// boot into "Class Laravel\Pail\PailServiceProvider not found".
		return base + `vendor/
node_modules/
tests/
phpunit.xml
bootstrap/cache/*
storage/logs/*
storage/framework/cache/*
storage/framework/sessions/*
storage/framework/views/*
`
	case "symfony":
		return base + `vendor/
node_modules/
tests/
phpunit.xml.dist
var/cache/*
var/log/*
`
	case "nextjs":
		return base + `node_modules/
.next/
out/
`
	case "hono", "fastify", "fastapi", "tanstack-start":
		if ignore, ok := FrameworkDockerignore(preset); ok {
			return ignore
		}
		return base
	default:
		return base
	}
}
