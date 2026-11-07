package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func rollbackStack(cfg *config.Config, dryRun bool) error {
	return rollbackStackWithinOperation(cfg, dryRun, nil)
}

func rollbackStackWithinOperation(cfg *config.Config, dryRun bool, parent *remoteOperation) (operationErr error) {
	if dryRun {
		fmt.Printf("[dry-run] Would apply the retained previous stack for %s through the signed root helper.\n", cfg.App)
		return nil
	}
	group, host, err := singleVPS(cfg)
	if err != nil {
		return err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return err
	}
	// Deploy already refuses a helper without coordinated operations; a
	// rollback skipped that negotiation and would reach an old helper that
	// mutates outside the operation journal.
	if err := ensureRequiredRootHelperCapabilities(cfg, group, host, client); err != nil {
		return err
	}
	// A rollback goes through the same signed action and therefore through the
	// same convergence wait, which now waits for the retained release to be
	// running rather than for a replica count. It needs the same session
	// deadline as a promotion for the same reason.
	client.SetOperationTimeout(rootHelperOperationTimeout(cfg.Deploy.PromotionSLOSeconds))
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return err
	}
	privateKey, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return err
	}
	operation := parent
	if operation == nil {
		operation, err = beginRemoteOperation(client, identity, privateKey, "rollback", cfg.App)
		if err != nil {
			return err
		}
		defer operation.finish(&operationErr)
	}
	operationID := operation.id
	// A rollback carries no registry budget: it re-promotes a retained stack
	// whose images must stay in the registry, so it has nothing to reclaim.
	plan, err := rootplan.NewStackAction("stack-rollback", cfg.App, "", cfg.Deploy.PromotionSLOSeconds, 0, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 2*time.Minute)
	if err == nil {
		plan, err = bindOperationPlan(plan, operationID, operation.kind, cfg.App)
	}
	if err == nil {
		plan, err = rootplan.Sign(plan, privateKey)
	}
	if err != nil {
		return err
	}
	envelope, err := encodeRootHelperEnvelope(plan, nil)
	if err != nil {
		return err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		return fmt.Errorf("signed rollback failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}
