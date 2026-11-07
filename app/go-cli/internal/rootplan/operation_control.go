package rootplan

import (
	"errors"
	"time"
)

// OperationControl describes the outcome of the whole client operation after
// its remote phase, image publication and writer cleanup have all returned.
type OperationControl struct {
	Phase  string `json:"phase,omitempty"`
	Result string `json:"result,omitempty"`
}

func NewOperationControl(action, id, kind, app, result, operatorKey, host string, now time.Time, validity time.Duration) (Plan, error) {
	if action != "operation-renew" && action != "operation-finish" && action != "operation-abort" && action != "operation-refuse" {
		return Plan{}, errors.New("unsupported operation control action")
	}
	return seal(Plan{Schema: Schema, Action: action, GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKey, RequiredHostFingerprint: host, OperationID: id, OperationKind: kind, OperationApp: app, Control: &OperationControl{Result: result}})
}

func NewOperationProgress(id, kind, app, phase, result, operatorKey, host string, now time.Time, validity time.Duration) (Plan, error) {
	p, err := NewOperationControl("operation-renew", id, kind, app, result, operatorKey, host, now, validity)
	if err != nil {
		return Plan{}, err
	}
	p.Digest = ""
	p.Control.Phase = phase
	return seal(p)
}
