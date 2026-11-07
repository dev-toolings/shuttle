package cli

import (
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

const caddyImageDefault = "caddy:2"

func caddyImage(value config.Caddy) string {
	if configured := strings.TrimSpace(value.Image); configured != "" {
		if strings.Contains(configured, "@sha256:") && !strings.Contains(strings.SplitN(configured, "@", 2)[0], ":") {
			return caddyImageDefault
		}
		return configured
	}
	return caddyImageDefault
}
