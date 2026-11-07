package cli

import (
	"strings"
	"testing"
)

func TestAdoptionDoesNotInferHBAFromFiles(t *testing.T) {
	s := adoptionPrerequisiteFixture(t)
	if strings.Contains(adoptionSurveySource, "pg_hba_file_rules") || strings.Contains(adoptionSurveySource, "pg_conf_load_time") || strings.Contains(adoptionSurveySource, "postgres-hba-included") {
		t.Fatal("adoption must not guess loaded HBA rules from configuration files")
	}
	if err := adoptionPrerequisiteError(s); err != nil {
		t.Fatalf("valid listener refused: %v", err)
	}
}
