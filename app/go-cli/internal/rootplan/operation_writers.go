package rootplan

import (
	"errors"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
)

// OperationWriters carries one explicit writer inventory transition. The
// signed operation identity and generation prevent cross-operation receipts.
type OperationWriters struct {
	Generation uint64                     `json:"generation"`
	Writer     *operationwriters.Writer   `json:"writer,omitempty"`
	Receipts   []operationwriters.Receipt `json:"receipts,omitempty"`
}

func NewOperationWriters(action, id, kind, app, operatorKey, host string, payload OperationWriters, now time.Time, validity time.Duration) (Plan, error) {
	if action != "operation-writer-register" && action != "operation-writers-close" && action != "operation-writers-commit" {
		return Plan{}, errors.New("unsupported writer inventory action")
	}
	return seal(Plan{Schema: Schema, Action: action, GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKey, RequiredHostFingerprint: host, OperationID: id, OperationKind: kind, OperationApp: app, Writers: &payload})
}

func validateWriterOperation(plan Plan) error {
	w := plan.Writers
	if w == nil || w.Generation != 1 || plan.OperationID == "" || plan.Stack != nil || plan.Secrets != nil || plan.HostSecrets != nil || plan.Audit != nil || plan.Run != nil || plan.Baseline != nil || plan.Helper != nil || plan.Recovery != nil || plan.Operations != nil || plan.Control != nil || plan.HelperMigration != nil {
		return errors.New("writer operation requires only the reserved identity and inventory")
	}
	switch plan.Action {
	case "operation-writer-register":
		if w.Writer == nil || len(w.Receipts) != 0 {
			return errors.New("writer registration requires exactly one writer")
		}
		return w.Writer.Validate()
	case "operation-writers-close":
		if w.Writer != nil || len(w.Receipts) != 0 {
			return errors.New("closing admissions does not accept an inventory mutation")
		}
	case "operation-writers-commit":
		if w.Writer != nil || len(w.Receipts) > 64 {
			return errors.New("writer closure inventory is invalid")
		}
	default:
		return errors.New("unsupported writer inventory action")
	}
	return nil
}
