package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func signedHelperMigrationFinalizer(client *shuttlessh.Client, identity trustedHostIdentity, request helperMigrationFinalizeRequest) error {
	return sendSignedHelperMigration(client, identity, request, "helper-migration-finalize")
}

func sendSignedHelperMigration(client *shuttlessh.Client, identity trustedHostIdentity, request helperMigrationFinalizeRequest, action string) error {
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return err
	}
	key, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return err
	}
	plan, err := rootplan.NewHelperMigrationAction(action, request.CandidateSHA256, request.IntentID, identity.OperatorKeyFingerprint, identity.HostKeyFingerprint, time.Now(), 5*time.Minute)
	if err == nil {
		plan, err = rootplan.Sign(plan, key)
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
		return fmt.Errorf("signed helper migration failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

func applySignedHelperMigration(ctx context.Context, plan rootplan.Plan) error {
	if plan.HelperMigration == nil {
		return errors.New("helper migration candidate is missing")
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		return err
	}
	validate := func() error {
		key, err := rootplan.ReadTrustedKey(rootHelperTrustedKey)
		if err != nil {
			return err
		}
		if err := rootplan.Verify(plan, key, time.Now()); err != nil {
			return err
		}
		return verifyRootOperationIdentity(plan)
	}
	if err := validate(); err != nil {
		return err
	}
	request := helperMigrationFinalizeRequest{CandidateSHA256: plan.HelperMigration.CandidateSHA256, IntentID: plan.HelperMigration.IntentID, Host: plan.RequiredHostFingerprint, PlanExpiresAt: expires, Validate: validate}
	if plan.Action == "helper-migration-reconcile" {
		return reconcileRootHelperMigration(ctx, helperMigrationReconcileRequest(request))
	}
	if plan.Action != "helper-migration-finalize" {
		return errors.New("unsupported helper migration action")
	}
	return finalizeRootHelperMigration(ctx, request)
}
