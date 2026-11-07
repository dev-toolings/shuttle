package cli

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestSwarmIncumbentCutoverRefusedBeforeCommands(t *testing.T) {
	if !strings.Contains(adoptionSurveySource, `incumbent-service=%s %s`) || !strings.Contains(adoptionSurveySource, `"$name" "$service"`) {
		t.Fatal("survey must report the container service label")
	}
	survey, err := parseAdoptionSurvey("port-held=80 by published container foreign_proxy.1.abc\nforeign-container=foreign_proxy.1.abc\nswarm-service=foreign_proxy\nincumbent-service=foreign_proxy.1.abc foreign_proxy\n")
	if err != nil {
		t.Fatal(err)
	}
	options := adoptionOptions()
	options.cutoverEdge = true
	for _, dryRun := range []bool{true, false} {
		options.dryRun = dryRun
		edge := resolveAdoptionEdgePlan(setupIdentity{}, survey, options, nil, !dryRun)
		if edge.Refusal == nil || edge.applies() {
			t.Fatalf("dryRun=%v: Swarm incumbent must be refused: %+v", dryRun, edge)
		}
		for _, part := range []string{"foreign_proxy", "Remove or scale", "re-run"} {
			if !strings.Contains(describeAdoptionEdgePlan(edge), part) {
				t.Fatalf("dryRun=%v: refusal missing %q: %v", dryRun, part, edge.Refusal)
			}
		}
		if !dryRun {
			// A nil client would panic if any remote command were attempted.
			if err := applyAdoption(io.Discard, nil, setupIdentity{}, options, survey, edge, nil, time.Time{}); err == nil {
				t.Fatal("apply must refuse before running a command")
			}
		}
	}
}

func TestPlainIncumbentCutoverStillPlanned(t *testing.T) {
	survey, err := parseAdoptionSurvey("port-held=80 by published container web\nincumbent-restart=web always\n")
	if err != nil {
		t.Fatal(err)
	}
	options := adoptionOptions()
	options.cutoverEdge = true
	edge := resolveAdoptionEdgePlan(setupIdentity{}, survey, options, nil, false)
	if !edge.applies() || edge.Incumbent != "web" || edge.IncumbentRestart != "always" {
		t.Fatalf("unexpected plan: %+v", edge)
	}
}

func TestSwarmIncumbentWithoutCutoverIsUnchanged(t *testing.T) {
	survey, err := parseAdoptionSurvey("port-held=80 by published container foreign_proxy.1.abc\nincumbent-service=foreign_proxy.1.abc foreign_proxy\n")
	if err != nil {
		t.Fatal(err)
	}
	edge := resolveAdoptionEdgePlan(setupIdentity{}, survey, adoptionOptions(), nil, false)
	if edge.applies() || edge.Refusal != nil || edge.Incumbent != "" {
		t.Fatalf("unexpected plan: %+v", edge)
	}
}

func TestSwarmPublishedPortSurveyRefusesNamedService(t *testing.T) {
	for _, port := range []string{"80", "443"} {
		t.Run(port, func(t *testing.T) {
			survey, err := parseAdoptionSurvey("service-port=" + port + " demo-service\nport-held=" + port + "/tcp by process docker-proxy\n")
			if err != nil {
				t.Fatal(err)
			}
			opts := adoptionOptions()
			opts.cutoverEdge = true
			edge := resolveAdoptionEdgePlan(setupIdentity{}, survey, opts, nil, false)
			if edge.Refusal == nil || !strings.Contains(edge.Refusal.Error(), "demo-service") {
				t.Fatalf("missing named service refusal: %+v", edge)
			}
		})
	}
	if !strings.Contains(adoptionSurveySource, ".Endpoint.Ports") {
		t.Fatal("survey does not inspect published service ports")
	}
}

func TestAdoptionPlanNamesOnlyActualStages(t *testing.T) {
	survey := adoptionSurvey{LegacyMarker: "present", Pending: []string{"50-caddy-direct"}, PortsHeld: []string{"80 by published container web"}}
	opts := adoptionOptions()
	opts.cutoverEdge = true
	opts.operator = &setupOperatorAccess{user: "admin"}
	identity := setupIdentity{user: "ops", host: "203.0.113.7", port: 22}
	edge := resolveAdoptionEdgePlan(identity, survey, opts, nil, false)
	plan := adoptionPlan(identity, "demo", "SHA256:fixture", survey, opts, edge, []int{80, 443}, false)
	start := strings.Index(plan, "stages this run applies, in order:")
	end := strings.Index(plan[start:], "  on a host in service")
	if start < 0 || end < 0 {
		t.Fatal("stage list absent")
	}
	applied := plan[start : start+end]
	for _, name := range []string{"helper-safety", "operator", "50-caddy-direct"} {
		if !strings.Contains(applied, name) {
			t.Fatalf("applied stages omit %s:\n%s", name, applied)
		}
	}
	if strings.Contains(strings.Join(adoptionDeferredWork(edge, true), "\n"), "50-caddy-direct") {
		t.Fatal("scheduled cutover also listed as not attempted")
	}
}
