//go:build !linux

package cli

import (
	"context"
	"errors"
	"io"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func rootHelperSupported() bool { return false }
func rootLog(string, ...any)    {}
func runningAsRoot() bool       { return false }
func verifyRootOperationIdentity(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func applyRootBaseline(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func rollbackRootBaseline(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func commitRootBaseline(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func auditRootOperation(rootplan.Plan) (string, error) {
	return "", errors.New("shuttle-root is supported only on Linux")
}
func applyRootStack(rootplan.Plan, []byte) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func reclaimRootStack(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func applyRootSecrets(rootplan.Plan, []byte) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func applyRootHostSecrets(rootplan.Plan, io.Writer) error {
	return errors.New("shuttle-root is supported only on Linux")
}

func applyRootHashvault(rootplan.Plan, []byte, io.Writer) error {
	return errors.New("shuttle-root is supported only on Linux")
}

func syncRootHashvault(rootplan.Plan, io.Writer) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func applyRootHelperUpdate(rootplan.Plan, []byte) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func reserveRootOperation(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}

func operationsRootStatus(context.Context) ([]byte, error) {
	return nil, errors.New("shuttle-root is supported only on Linux")
}
func recoveryRootPlan(context.Context, string) ([]byte, error) {
	return nil, errors.New("shuttle-root is supported only on Linux")
}
func recoveryRootApply(context.Context, string, string, rootplan.Plan) ([]byte, error) {
	return nil, errors.New("shuttle-root is supported only on Linux")
}

func runDeclaredOperationForPlan(rootplan.Plan, io.Writer) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func installRootMonitoring(rootplan.Plan, []byte) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func removeRootMonitoring(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func runSignedRootMonitoring(rootplan.Plan, io.Writer) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func runSignedRootMonitoringStatus(rootplan.Plan, io.Writer) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func runDirectRootMonitoring(string, io.Writer) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func setRootMonitoringMaintenance(rootplan.Plan) error {
	return errors.New("shuttle-root is supported only on Linux")
}
func publishRootBackupStatus(rootplan.Plan, []byte) error {
	return errors.New("shuttle-root is supported only on Linux")
}
