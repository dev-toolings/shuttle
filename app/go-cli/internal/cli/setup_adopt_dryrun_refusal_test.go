package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestAdoptionDryRunReturnsEdgeRefusal(t *testing.T) {
	for _, field := range []string{"cutover", "reconverge"} {
		t.Run(field, func(t *testing.T) {
			refusal := errors.New("foreign Swarm incumbent")
			edge := adoptionEdgePlan{}
			if field == "cutover" {
				edge.Refusal = refusal
			} else {
				edge.ReconvergeRefusal = refusal
			}
			var out bytes.Buffer
			err := completeAdoptionPreflight(&out, adoptionSurvey{}, edge, true)
			if !errors.Is(err, refusal) || strings.Contains(out.String(), "preflight verified") {
				t.Fatalf("got error %v and output %q", err, out.String())
			}
		})
	}
	var out bytes.Buffer
	if err := completeAdoptionPreflight(&out, adoptionSurvey{}, adoptionEdgePlan{}, true); err != nil || !strings.Contains(out.String(), "preflight verified") {
		t.Fatalf("valid preflight: %v %q", err, out.String())
	}
}
