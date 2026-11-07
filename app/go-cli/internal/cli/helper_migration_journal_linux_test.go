//go:build linux

package cli

import (
	"strings"
	"testing"
)

// Shape of the recovered deploy journal observed on the recette VPS. The
// previous narrow decoder stopped at "revision" and blocked helper updates.
const recetteRecoveredDeployJournal = `{"schema":"shuttle.operation/v1","id":"f32567fa-5241-580c-2204-b37f009ea1e7","revision":9,"kind":"deploy","scope":"global","app":"shuttle-build-recette","principal":"SHA256:bewDJMyAPCoglP4E0mq9TROXdM2O4pQ1GFYpoSsD2n4","owner_key_fingerprint":"SHA256:bewDJMyAPCoglP4E0mq9TROXdM2O4pQ1GFYpoSsD2n4","host":"SHA256:NBk61Hrcei2Eck1o651VSGc8puZJ2rE9NO9K54OWUAw","host_boot_id":"00ca92ea-383f-49fa-b3cc-d582134571fb","started_at":"2026-09-13T16:12:36.931941466Z","updated_at":"2026-09-13T18:17:34.032623593Z","lease_until":"","state":"recovered","recovery_required":false,"result":"explicit recovery reconciled observed host state","phases":[{"name":"writers-initialize","started_at":"2026-09-13T16:12:36.936494944Z","ended_at":"2026-09-13T16:12:37.049104991Z","result":"phase completed"}],"events":[{"at":"2026-09-13T18:17:34.032623593Z","kind":"recovered","state":"recovered"}]}`

func TestDecodeMigrationJournalRecordAcceptsModernCoordinatorRecord(t *testing.T) {
	record, err := decodeMigrationJournalRecord([]byte(recetteRecoveredDeployJournal))
	if err != nil {
		t.Fatalf("modern journal refused: %v", err)
	}
	if record.ID != "f32567fa-5241-580c-2204-b37f009ea1e7" || record.State != "recovered" || record.RecoveryRequired || record.HostBootID != "00ca92ea-383f-49fa-b3cc-d582134571fb" {
		t.Fatalf("journal identity lost in decoding: %+v", record)
	}
	annotated := strings.Replace(recetteRecoveredDeployJournal, `"state":"recovered"}]`, `"state":"recovered","note":"operator: promotion not-started, no ohb-console stack"}]`, 1)
	if annotated == recetteRecoveredDeployJournal {
		t.Fatal("fixture no longer carries the event the operator annotated")
	}
	if _, err := decodeMigrationJournalRecord([]byte(annotated)); err != nil {
		t.Fatalf("operator event note refused: %v", err)
	}
	tampered := recetteRecoveredDeployJournal[:len(recetteRecoveredDeployJournal)-1] + `,"surprise":true}`
	if _, err := decodeMigrationJournalRecord([]byte(tampered)); err == nil {
		t.Fatal("unknown journal field accepted")
	}
}
