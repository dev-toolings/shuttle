package cli

import "github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"

func validateDeployEnvironment(cfg *config.Config) error {
	if len(cfg.Deploy.EnvSchema) == 0 {
		return nil
	}
	return cfg.Deploy.EnvSchema.ValidateEnv()
}
