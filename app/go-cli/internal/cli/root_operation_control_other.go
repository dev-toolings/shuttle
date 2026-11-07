//go:build !linux

package cli

import (
	"context"
	"errors"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func controlRootOperation(context.Context, rootplan.Plan) ([]byte, error) {
	return nil, errors.New("operation control requires Linux")
}

func refuseGenericRebootRecovery(context.Context, string) error {
	return errors.New("reboot recovery requires Linux")
}
