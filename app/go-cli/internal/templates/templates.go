package templates

// ReadinessPresets enumerates the application presets accepted by `init`.
// Every preset is rendered through the same single-node Swarm configuration.
var ReadinessPresets = []string{"nextjs", "laravel", "symfony", "node-api", "hono", "fastify", "fastapi", "tanstack-start", "docker-swarm"}

// IsReadinessPreset reports whether name is a supported preset.
func IsReadinessPreset(name string) bool {
	for _, preset := range ReadinessPresets {
		if preset == name {
			return true
		}
	}
	return false
}
