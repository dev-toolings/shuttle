package rootplan

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// MonitoringOperation carries only coordinates and a digest. The monitoring
// document itself travels as the signed envelope payload, while remove, run
// and maintenance carry no arbitrary bytes to the privileged helper.
type MonitoringOperation struct {
	App           string `json:"app"`
	OperationID   string `json:"operation_id"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
	Until         string `json:"until,omitempty"`
}

type BackupStatusOperation struct {
	App           string `json:"app"`
	OperationID   string `json:"operation_id"`
	PayloadSHA256 string `json:"payload_sha256"`
}

var monitoringApp = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func NewMonitoringInstall(app, payloadDigest, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newMonitoringPlan("monitor-install", app, payloadDigest, "", operatorKeyFingerprint, hostFingerprint, now, validity)
}

func NewMonitoringRemove(app, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newMonitoringPlan("monitor-remove", app, "", "", operatorKeyFingerprint, hostFingerprint, now, validity)
}

func NewMonitoringRun(app, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newMonitoringPlan("monitor-run", app, "", "", operatorKeyFingerprint, hostFingerprint, now, validity)
}

func NewMonitoringStatus(app, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newMonitoringPlan("monitor-status", app, "", "", operatorKeyFingerprint, hostFingerprint, now, validity)
}

func NewBackupStatus(app, operationID, payloadDigest, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	plan := Plan{Schema: Schema, Action: "backup-status", GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, BackupStatus: &BackupStatusOperation{App: app, OperationID: operationID, PayloadSHA256: payloadDigest}}
	return seal(plan)
}

func NewMonitoringMaintenance(app string, until time.Time, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	return newMonitoringPlan("monitor-maintenance", app, "", until.UTC().Format(time.RFC3339Nano), operatorKeyFingerprint, hostFingerprint, now, validity)
}

func newMonitoringPlan(action, app, payloadDigest, until, operatorKeyFingerprint, hostFingerprint string, now time.Time, validity time.Duration) (Plan, error) {
	operationID := fmt.Sprintf("%s-%d", action, now.UTC().UnixNano())
	plan := Plan{Schema: Schema, Action: action, GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKeyFingerprint, RequiredHostFingerprint: hostFingerprint, Monitoring: &MonitoringOperation{App: app, OperationID: operationID, PayloadSHA256: payloadDigest, Until: until}}
	return seal(plan)
}

func validateMonitoringOperation(operation *MonitoringOperation, action string) error {
	if operation == nil || !monitoringApp.MatchString(operation.App) || !operationName.MatchString(operation.OperationID) {
		return errors.New("invalid monitoring operation")
	}
	switch action {
	case "monitor-install":
		if !contentDigest.MatchString(operation.PayloadSHA256) || operation.Until != "" {
			return errors.New("monitor-install requires a configuration payload digest")
		}
	case "monitor-remove", "monitor-run", "monitor-status":
		if operation.PayloadSHA256 != "" || operation.Until != "" {
			return errors.New("monitoring action does not accept a payload or maintenance deadline")
		}
	case "monitor-maintenance":
		if operation.PayloadSHA256 != "" || operation.Until == "" {
			return errors.New("monitor-maintenance requires a deadline")
		}
		until, err := time.Parse(time.RFC3339Nano, operation.Until)
		if err != nil || until.Sub(time.Now().UTC()) > 7*24*time.Hour {
			return errors.New("monitor-maintenance deadline must be a valid bounded timestamp")
		}
	default:
		return fmt.Errorf("unsupported monitoring action %q", action)
	}
	return nil
}

func monitoringFieldsOnly(plan Plan) bool {
	return plan.Stack == nil && plan.Secrets == nil && plan.HostSecrets == nil && plan.Audit == nil && plan.Run == nil && plan.Baseline == nil && plan.Helper == nil && plan.BackupStatus == nil && plan.Control == nil && plan.Writers == nil && plan.HelperMigration == nil && plan.Operations == nil && plan.Recovery == nil
}
