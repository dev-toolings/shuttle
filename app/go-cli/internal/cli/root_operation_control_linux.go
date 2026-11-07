//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func controlRootOperation(ctx context.Context, plan rootplan.Plan) ([]byte, error) {
	if err := verifyRootOperationIdentity(plan); err != nil {
		return nil, err
	}
	return controlRootOperationWith(ctx, coord.NewDefault(), plan)
}

func controlRootOperationWith(ctx context.Context, c *coord.Coordinator, plan rootplan.Plan) ([]byte, error) {
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil || !time.Now().Before(expires) {
		return nil, errors.New("operation control plan expired")
	}
	phase := plan.Control.Phase
	if phase == "" {
		phase = "client-renew"
	}
	action := ""
	switch plan.Action {
	case "operation-renew":
		action = "renew"
	case "operation-finish":
		action = "finish"
	case "operation-abort":
		action = "abort"
	case "operation-refuse":
		action = "refuse"
	default:
		return nil, errors.New("unsupported operation control")
	}
	err = c.Control(ctx, coord.PhaseRequest{ID: plan.OperationID, Kind: plan.OperationKind, App: plan.OperationApp, Principal: plan.OperatorKeyFingerprint, OwnerKeyFingerprint: plan.OperatorKeyFingerprint, Host: plan.RequiredHostFingerprint, Name: phase, PlanExpiresAt: expires, HostIdentity: plan.RequiredHostFingerprint, Validate: func(record coord.Record) error {
		if err := rootCoordinatedMutationGuard(plan.Action); err != nil {
			return err
		}
		// Helper-update does not initialize writers: a phase-less reservation
		// is the proof that neither staging nor candidate execution started.
		if action == "finish" || (action == "refuse" && !(record.Kind == "helper-update" && len(record.Phases) == 0)) {
			if err := requireRootWritersClosed(c, record); err != nil {
				return err
			}
		}
		return rootCoordinatedIdentityVerifier(plan)
	}}, action, plan.Control.Result)
	if err != nil {
		return nil, err
	}
	record, err := c.Get(ctx, plan.OperationID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(operationResponseRecord(record))
}

// operationResponseRecord keeps the established wire shape while the private
// journal retains recovery evidence. Exposing registry_replacement made older
// strict clients reject even a successful operation-finish response. Project a
// value copy so status and control never erase the proof needed by recovery.
func operationResponseRecord(record coord.Record) coord.Record {
	record.RegistryReplacement = nil
	return record
}

func refuseGenericRebootRecovery(ctx context.Context, id string) error {
	record, err := coord.NewDefault().Get(ctx, id)
	if err != nil {
		return err
	}
	if record.Kind == "reboot" {
		return errors.New("planned reboot requires operations reboot --resume " + id + " --yes to verify the changed boot and public HTTPS before completion")
	}
	return nil
}
