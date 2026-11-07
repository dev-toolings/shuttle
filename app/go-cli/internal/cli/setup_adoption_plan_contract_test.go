package cli

import (
	"strings"
	"testing"
)

func TestAdoptionSatisfiedStagesDoNotGenerateTheirBodies(t *testing.T) {
	survey := adoptionSurvey{Satisfied: []string{"20-docker", "30-postgres"}}
	plan := strings.Join(adoptionAppliedStages(survey, adoptionEdgePlan{}), "\n")
	stages := adoptionSetupStages(adoptionApplyConfig(t), 22, survey)
	for _, stage := range stages {
		if strings.Contains(stage.command, "apt-get install -y docker-ce") && strings.Contains(plan, "adoption skips its body") {
			t.Fatal("plan says Docker is skipped but the generated command contains its stage body")
		}
		if strings.Contains(stage.command, "listen_addresses = '127.0.0.1,$gateway'") && strings.Contains(plan, "adoption skips its body") {
			t.Fatal("plan says PostgreSQL is skipped but the generated command contains its stage body")
		}
	}
}
