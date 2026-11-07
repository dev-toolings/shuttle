//go:build !linux

package cli

import (
	"context"
	"errors"
)

func finalizeRootHelperMigration(context.Context, helperMigrationFinalizeRequest) error {
	return errors.New("helper migration is supported only on Linux")
}

func reconcileRootHelperMigration(context.Context, helperMigrationReconcileRequest) error {
	return errors.New("helper migration reconciliation is supported only on Linux")
}

func refuseRootHelperMutationDuringMigration(string) error {
	return errors.New("helper migration is supported only on Linux")
}

func rootHelperMigrationCapabilitiesReady() error {
	return errors.New("helper migration is supported only on Linux")
}
