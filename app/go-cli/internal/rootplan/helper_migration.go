package rootplan

import (
	"errors"
	"time"
)

// HelperMigrationOperation binds finalization to the exact installed candidate.
// It deliberately carries no ordinary reservation, which a legacy helper
// cannot decode during the first signed update exchange.
type HelperMigrationOperation struct {
	CandidateSHA256 string `json:"candidate_sha256"`
	IntentID        string `json:"intent_id,omitempty"`
}

func NewHelperMigrationFinalize(candidateDigest, operatorKey, host string, now time.Time, validity time.Duration) (Plan, error) {
	return NewHelperMigrationAction("helper-migration-finalize", candidateDigest, "", operatorKey, host, now, validity)
}

func NewHelperMigrationAction(action, candidateDigest, intentID, operatorKey, host string, now time.Time, validity time.Duration) (Plan, error) {
	if action != "helper-migration-finalize" && action != "helper-migration-reconcile" {
		return Plan{}, errors.New("unsupported helper migration action")
	}
	return seal(Plan{Schema: Schema, Action: action, GeneratedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(validity).UTC().Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operatorKey, RequiredHostFingerprint: host, HelperMigration: &HelperMigrationOperation{CandidateSHA256: candidateDigest, IntentID: intentID}})
}
