package cli

import (
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

func TestParseObservedEdgeSpecLegacyRootEdge(t *testing.T) {
	image := "caddy@sha256:" + strings.Repeat("a", 64)
	raw := `{"Image":"` + image + `","Privileges":{"NoNewPrivileges":false},"Env":["TOKEN=never-store-this","MODE=production"],"Secrets":[{"File":{"Name":"edge_secret"}}],"Mounts":[{"Type":"volume","Source":"edge-data","Target":"/data"},{"Type":"volume","Source":"edge-config","Target":"/config"},{"Type":"bind","Source":"/srv","Target":"/srv"}]}`
	observed, err := parseObservedEdgeSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Image != image || observed.User != "" || observed.ReadOnly || len(observed.CapabilityAdd) != 0 || len(observed.CapabilityDrop) != 0 {
		t.Fatalf("legacy edge spec parsed unexpectedly: %+v", observed)
	}
	if !reflect.DeepEqual(observed.EnvNames, []string{"MODE", "TOKEN"}) || !reflect.DeepEqual(observed.SecretTargets, []string{"edge_secret"}) || !reflect.DeepEqual(observed.MountTargets, []string{"/config", "/data", "/srv"}) {
		t.Fatalf("edge resources were not extracted deterministically: %+v", observed)
	}
	if !reflect.DeepEqual(observed.Mounts, []observedEdgeMount{
		{Type: "volume", Source: "edge-config", Target: "/config"},
		{Type: "volume", Source: "edge-data", Target: "/data"},
		{Type: "bind", Source: "/srv", Target: "/srv"},
	}) {
		t.Fatalf("edge mount sources were not retained: %+v", observed.Mounts)
	}
	if strings.Contains(strings.Join(observed.EnvNames, " "), "never-store-this") {
		t.Fatal("environment values must not be retained in the observed spec")
	}
}

func TestParseObservedEdgeSpecRejectsInvalidJSON(t *testing.T) {
	if _, err := parseObservedEdgeSpec(`{"Image":`); err == nil {
		t.Fatal("malformed edge JSON was accepted")
	}
	if _, err := parseAdoptionSurvey("edge-container-spec={\n"); err == nil {
		t.Fatal("malformed edge JSON in the survey was accepted")
	}
	if _, err := parseAdoptionSurvey("edge-container-spec={}\nedge-container-spec={}\n"); err == nil {
		t.Fatal("a duplicate edge container spec was accepted")
	}
	adapted := base64.StdEncoding.EncodeToString([]byte(`{"apps":{}}`))
	if _, err := parseAdoptionSurvey("edge-effective-config=" + adapted + "\nedge-effective-config=" + adapted + "\n"); err == nil {
		t.Fatal("a duplicate adapted Caddy configuration was accepted")
	}
}

func TestAdoptionSurveySourceParses(t *testing.T) {
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(adoptionSurveySource)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("adoption survey source is invalid shell: %v\n%s", err, output)
	}
}

func TestEdgeSpecDriftLegacyEdge(t *testing.T) {
	image := "caddy@sha256:" + strings.Repeat("a", 64)
	got := edgeSpecDrift(observedEdgeSpec{Image: image}, "")
	want := []string{
		`runs as root (user "", want 10001:10001)`,
		"root filesystem is writable (want read_only)",
		"capabilities are not dropped (want cap_drop ALL, cap_add NET_BIND_SERVICE)",
		"image " + image + " is the legacy digest-only form",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("drift = %#v, want %#v", got, want)
	}
}

func TestEdgeSpecDriftIgnoresNoNewPrivileges(t *testing.T) {
	image := "caddy:2.10.0@sha256:" + strings.Repeat("b", 64)
	observed, err := parseObservedEdgeSpec(`{"Image":"` + image + `","User":"10001:10001","ReadOnly":true,"Privileges":{"NoNewPrivileges":false},"CapabilityDrop":["ALL"],"CapabilityAdd":["NET_BIND_SERVICE"]}`)
	if err != nil {
		t.Fatal(err)
	}
	got := edgeSpecDrift(observed, observed.Image)
	if len(got) != 0 {
		t.Fatalf("NoNewPrivileges is not represented by the Swarm stack service spec: %v", got)
	}
}

func TestEdgeSpecDriftRenderedSpecIsClean(t *testing.T) {
	image := "caddy:2.10.0@sha256:" + strings.Repeat("b", 64)
	var stack map[string]any
	if err := yaml.Unmarshal([]byte(setupCaddyStack(image, config.Caddy{})), &stack); err != nil {
		t.Fatal(err)
	}
	service := stack["services"].(map[string]any)["caddy"].(map[string]any)
	observed := observedEdgeSpec{
		Image:          service["image"].(string),
		User:           service["user"].(string),
		ReadOnly:       service["read_only"].(bool),
		CapabilityAdd:  stringsFromYAML(t, service["cap_add"]),
		CapabilityDrop: stringsFromYAML(t, service["cap_drop"]),
	}
	if got := edgeSpecDrift(observed, image); len(got) != 0 {
		t.Fatalf("rendered edge spec reported drift: %v", got)
	}
}

func stringsFromYAML(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("YAML value is %T, want []any", value)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.(string))
	}
	return result
}

func TestEdgeSpecDriftImageOnlyWhenResolved(t *testing.T) {
	observed := observedEdgeSpec{
		Image:          "caddy:2.10.0@sha256:" + strings.Repeat("b", 64),
		User:           "10001:10001",
		ReadOnly:       true,
		CapabilityDrop: []string{"ALL"},
		CapabilityAdd:  []string{"NET_BIND_SERVICE"},
	}
	if got := edgeSpecDrift(observed, ""); len(got) != 0 {
		t.Fatalf("dry-run image comparison should be deferred: %v", got)
	}
	got := edgeSpecDrift(observed, "caddy:2.10.1@sha256:"+strings.Repeat("c", 64))
	if len(got) != 1 || !strings.HasPrefix(got[0], "image "+observed.Image+" differs from caddy:2.10.1") {
		t.Fatalf("resolved image change = %v", got)
	}
}

func TestEdgeReconvergeRefusalUndeclaredState(t *testing.T) {
	observed := observedEdgeSpec{
		EnvNames:      []string{"UNDECLARED_ENV"},
		SecretTargets: []string{"undeclared_secret"},
		MountTargets:  []string{"/config", "/data", "/undeclared"},
		Mounts: []observedEdgeMount{
			{Type: "volume", Source: "shuttle-edge_shuttle_caddy_data", Target: "/data"},
			{Type: "volume", Source: "shuttle-edge_shuttle_caddy_config", Target: "/config"},
			{Type: "bind", Source: "/srv/custom", Target: "/undeclared"},
		},
	}
	for _, reason := range []string{"environment variables UNDECLARED_ENV", "secret targets undeclared_secret", "mount targets /undeclared"} {
		err := edgeReconvergeRefusal(observed, config.Caddy{})
		if err == nil || !strings.Contains(err.Error(), reason) || !strings.Contains(err.Error(), "re-run setup --adopt from the configuration that declares them") {
			t.Fatalf("refusal does not name %q: %v", reason, err)
		}
	}
	declared := config.Caddy{
		Env:       map[string]string{"UNDECLARED_ENV": "value"},
		SecretEnv: map[string]string{"TOKEN": "undeclared_secret"},
		Mounts:    []config.CaddyMount{{Source: "/data/custom", Target: "/undeclared"}},
	}
	if err := edgeReconvergeRefusal(observed, declared); err != nil {
		t.Fatalf("declared edge state was refused: %v", err)
	}
	observed.MountTargets = []string{"/data", "/config", "/etc/caddy/conf.d"}
	observed.Mounts = []observedEdgeMount{
		{Type: "volume", Source: "shuttle-edge_shuttle_caddy_data", Target: "/data"},
		{Type: "volume", Source: "shuttle-edge_shuttle_caddy_config", Target: "/config"},
		{Type: "bind", Source: "/opt/shuttle/caddy/conf.d", Target: "/etc/caddy/conf.d"},
	}
	if err := edgeReconvergeRefusal(observed, declared); err != nil {
		t.Fatalf("standard mounts were refused: %v", err)
	}
}

func TestEdgeReconvergeRefusalForNondefaultCertificateVolume(t *testing.T) {
	observed, err := parseObservedEdgeSpec(`{"Mounts":[{"Type":"volume","Source":"legacy_caddy_certs","Target":"/data"},{"Type":"volume","Source":"shuttle-edge_shuttle_caddy_config","Target":"/config"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	err = edgeReconvergeRefusal(observed, config.Caddy{})
	if err == nil || !strings.Contains(err.Error(), "/data=volume:legacy_caddy_certs") {
		t.Fatalf("nondefault certificate volume was not refused: %v", err)
	}
	if edge := (adoptionEdgePlan{AlreadyServing: true, Reconverge: []string{"root filesystem is writable"}, ReconvergeRefusal: err}); edge.reconverges() {
		t.Fatal("an edge with a certificate volume mismatch was scheduled for deployment")
	}
	if err := edgeReconvergeRefusal(observed, config.Caddy{DataVolume: "legacy_caddy_certs"}); err != nil {
		t.Fatalf("configured legacy certificate volume was refused: %v", err)
	}
}

func TestEdgeHTTPSProbeHostsNormalizeDefaultPortsAndRejectGaps(t *testing.T) {
	got, err := edgeHTTPSProbeHosts([]string{"example.com", "https://www.example.com:443", "api.example.com:443", "http://only-http.example.com", "only-http.example.com:80"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("probe hosts = %v, want %v", got, want)
	}
	for _, unsupported := range [][]string{{"*.example.com"}, {"example.com:8443"}, {"192.0.2.10"}} {
		if _, err := edgeHTTPSProbeHosts(unsupported); err == nil {
			t.Fatalf("unsupported probe addresses were silently skipped: %v", unsupported)
		}
	}
	if got, err := edgeHTTPSProbeHosts([]string{":80", "http://only-http.example.com"}); err != nil || len(got) != 0 {
		t.Fatalf("HTTP-only sites produced HTTPS probes: %v, %v", got, err)
	}
}

func TestCaddyEffectiveSiteHostsReadsAdaptedImports(t *testing.T) {
	adapted := []byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":["example.com","api.example.com"]}]}]}}}}}`)
	hosts, err := caddyEffectiveSiteHosts(adapted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hosts, []string{"api.example.com", "example.com"}) {
		t.Fatalf("effective site hosts = %v", hosts)
	}
	if _, err := caddyEffectiveSiteHosts([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":"unexpected"}]}]}}}}}`)); err == nil {
		t.Fatal("invalid adapted host matcher was accepted")
	}
}

func TestAdoptionSurveyUsesEffectiveCaddyConfig(t *testing.T) {
	if !strings.Contains(adoptionSurveySource, "caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile") || !strings.Contains(adoptionSurveySource, "base64 -w0") {
		t.Fatal("adoption survey does not report the expanded effective Caddy configuration")
	}
	if strings.Contains(adoptionSurveySource, "for site in /opt/shuttle/caddy/conf.d") {
		t.Fatal("adoption survey still guesses site addresses from one host directory")
	}
}

func TestAdoptionPlanAnnouncesEdgeReconvergence(t *testing.T) {
	image := "caddy@sha256:" + strings.Repeat("a", 64)
	effectiveConfig := base64.StdEncoding.EncodeToString([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}}}}`))
	body := "swarm-service=shuttle-edge_caddy\n" +
		"port-held=80 by published container shuttle-edge_caddy.1.old\n" +
		"port-held=443 by published container shuttle-edge_caddy.1.old\n" +
		"satisfied=10-base\nsatisfied=20-docker\nsatisfied=30-postgres\nsatisfied=40-runtime\nsatisfied=50-caddy-direct\n" +
		"edge-container-spec={\"Image\":\"" + image + "\",\"Mounts\":[{\"Type\":\"volume\",\"Source\":\"shuttle-edge_shuttle_caddy_data\",\"Target\":\"/data\"},{\"Type\":\"volume\",\"Source\":\"shuttle-edge_shuttle_caddy_config\",\"Target\":\"/config\"}]}\n" +
		"edge-effective-config=" + effectiveConfig + "\n"
	survey, err := parseAdoptionSurvey(body)
	if err != nil {
		t.Fatal(err)
	}
	identity := setupIdentity{user: "ops", host: "203.0.113.8", port: 22}
	cfg := &config.Config{}
	edge := resolveAdoptionEdgePlan(identity, survey, adoptionOptions(), cfg, false)
	plan := adoptionPlan(identity, "example", "SHA256:"+strings.Repeat("A", 43), survey, adoptionOptions(), edge, []int{80, 443}, false)
	for _, part := range []string{
		"edge spec         re-converged: runs as root (user \"\", want 10001:10001)",
		"root filesystem is writable (want read_only)",
		"capabilities are not dropped (want cap_drop ALL, cap_add NET_BIND_SERVICE)",
		"image " + image + " is the legacy digest-only form",
		"a brief 80/443 outage (stop-first update), certificates kept, rolled back if a site that answers HTTPS now stops answering",
		"50-caddy-direct (re-converge the shared edge to this release's spec)",
	} {
		if !strings.Contains(plan, part) {
			t.Fatalf("adoption plan omitted %q:\n%s", part, plan)
		}
	}
	if strings.Contains(plan, "host is already converged") {
		t.Fatalf("drifting edge was called converged:\n%s", plan)
	}

	survey.Edge.EnvNames = []string{"UNDECLARED_ENV"}
	edge = resolveAdoptionEdgePlan(identity, survey, adoptionOptions(), cfg, false)
	plan = adoptionPlan(identity, "example", "SHA256:"+strings.Repeat("A", 43), survey, adoptionOptions(), edge, []int{80, 443}, false)
	if !strings.Contains(plan, "not attempted by this run") || !strings.Contains(plan, "environment variables UNDECLARED_ENV") {
		t.Fatalf("undeclared state refusal was not deferred in the plan:\n%s", plan)
	}
}

func TestAdoptionDoesNotReConvergeNoNewPrivilegesOnly(t *testing.T) {
	survey, err := parseAdoptionSurvey("swarm-service=shuttle-edge_caddy\n" +
		"port-held=80 by published container shuttle-edge_caddy.1.old\n" +
		"port-held=443 by published container shuttle-edge_caddy.1.old\n")
	if err != nil {
		t.Fatal(err)
	}
	survey.Edge = &observedEdgeSpec{
		Image:          "caddy:2.10.1@sha256:" + strings.Repeat("d", 64),
		User:           "10001:10001",
		ReadOnly:       true,
		CapabilityDrop: []string{"ALL"},
		CapabilityAdd:  []string{"NET_BIND_SERVICE"},
		Mounts: []observedEdgeMount{
			{Type: "volume", Source: "shuttle-edge_shuttle_caddy_data", Target: "/data"},
			{Type: "volume", Source: "shuttle-edge_shuttle_caddy_config", Target: "/config"},
		},
	}
	survey.Edge.MountTargets = []string{"/data", "/config"}
	identity := setupIdentity{user: "ops", host: "203.0.113.8", port: 22}
	edge := resolveAdoptionEdgePlan(identity, survey, adoptionOptions(), &config.Config{}, false)
	if edge.reconverges() || len(edge.Reconverge) != 0 {
		t.Fatalf("NoNewPrivileges-only edge drift must be ignored because Swarm drops that field: %+v", edge)
	}
}

func TestAdoptionReconvergesCapabilityOnlyDrift(t *testing.T) {
	survey := adoptionSurvey{
		SwarmServices: []string{"shuttle-edge_caddy"},
		PortsHeld: []string{
			"80 by published container shuttle-edge_caddy.1.old",
			"443 by published container shuttle-edge_caddy.1.old",
		},
		EdgeSiteHosts: []string{"example.com"},
		Edge: &observedEdgeSpec{
			Image:        "caddy:2.10.1@sha256:" + strings.Repeat("d", 64),
			User:         "10001:10001",
			ReadOnly:     true,
			Mounts:       []observedEdgeMount{{Type: "volume", Source: "shuttle-edge_shuttle_caddy_data", Target: "/data"}, {Type: "volume", Source: "shuttle-edge_shuttle_caddy_config", Target: "/config"}},
			MountTargets: []string{"/data", "/config"},
		},
	}
	edge := resolveAdoptionEdgePlan(setupIdentity{}, survey, adoptionOptions(), &config.Config{}, false)
	want := []string{"capabilities are not dropped (want cap_drop ALL, cap_add NET_BIND_SERVICE)"}
	if !edge.reconverges() || !reflect.DeepEqual(edge.Reconverge, want) {
		t.Fatalf("capability-only privilege drift was not scheduled for re-convergence: %+v", edge)
	}
}

func TestAdoptionRefusesReconvergenceWithoutVerifiableDomains(t *testing.T) {
	image := "caddy:2.10.1@sha256:" + strings.Repeat("d", 64)
	adapted := base64.StdEncoding.EncodeToString([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"path":["/*"]}]}]}}}}}`))
	body := "swarm-service=shuttle-edge_caddy\n" +
		"port-held=80 by published container shuttle-edge_caddy.1.old\n" +
		"port-held=443 by published container shuttle-edge_caddy.1.old\n" +
		"edge-container-spec={\"Image\":\"" + image + "\",\"User\":\"root\",\"Mounts\":[{\"Type\":\"volume\",\"Source\":\"shuttle-edge_shuttle_caddy_data\",\"Target\":\"/data\"},{\"Type\":\"volume\",\"Source\":\"shuttle-edge_shuttle_caddy_config\",\"Target\":\"/config\"}]}\n" +
		"edge-effective-config=" + adapted + "\n"
	survey, err := parseAdoptionSurvey(body)
	if err != nil {
		t.Fatal(err)
	}
	edge := resolveAdoptionEdgePlan(setupIdentity{}, survey, adoptionOptions(), &config.Config{}, false)
	if edge.ReconvergeRefusal == nil || !strings.Contains(edge.ReconvergeRefusal.Error(), "no verifiable HTTPS domain") {
		t.Fatalf("edge without a verifiable domain was not refused: %+v", edge)
	}
}

func TestEdgeReconvergeProgramParses(t *testing.T) {
	program := setupCaddyReconvergeCommand("caddy:2.10@sha256:"+strings.Repeat("a", 64), []string{"example.com"})
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(program)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated reconvergence program is invalid: %v\n%s", err, output)
	}
	preparation := caddyVolumePreparationWithOwnerSnapshot(config.Caddy{})
	command = exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(preparation)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated owner snapshot program is invalid: %v\n%s", err, output)
	}
	for _, required := range []string{"find /volume -xdev -exec stat -c", "invalid Caddy volume owner manifest", "SHUTTLE_CADDY_OWNER_FILE", "chown -R 10001:10001 /volume"} {
		if !strings.Contains(preparation, required) {
			t.Fatalf("owner snapshot preparation omits %q:\n%s", required, preparation)
		}
	}
	lastSnapshot := strings.LastIndex(preparation, "find /volume -xdev -exec stat -c")
	firstChown := strings.Index(preparation, "chown -R 10001:10001 /volume")
	if lastSnapshot < 0 || firstChown < 0 || lastSnapshot >= firstChown {
		t.Fatalf("all managed volume owners must be recorded before any chown:\n%s", preparation)
	}
	for _, required := range []string{"mktemp -d /tmp/shuttle-caddy-owners.XXXXXX", "trap finish_caddy_owner_record EXIT", `rm -rf "$owner_dir"`} {
		if !strings.Contains(program, required) {
			t.Fatalf("re-convergence program omits private owner record cleanup %q:\n%s", required, program)
		}
	}
}

func TestEdgeDomainPrecheckRefusesWithoutChangingHost(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	curl := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_CURL_LOG\"\nexit 22\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "curl"), []byte(curl), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "host-mutated")
	program := setupCaddyDomainPrecheckCommand([]string{"example.com", "www.example.com"}) + `touch "$FAKE_MUTATION_MARKER"
`
	command := exec.Command("sh", "-s")
	command.Stdin = strings.NewReader(program)
	command.Env = append(os.Environ(),
		"PATH="+fakeBin+":"+os.Getenv("PATH"),
		"FAKE_CURL_LOG="+filepath.Join(dir, "curl.log"),
		"FAKE_MUTATION_MARKER="+marker,
	)
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("precheck accepted domains that did not answer HTTPS")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("host mutation marker exists after precheck refusal: %v", err)
	}
	if !strings.Contains(stderr.String(), "no host changes were made") {
		t.Fatalf("precheck refusal did not explain that no host changes were made: %s", stderr.String())
	}
	log, err := os.ReadFile(filepath.Join(dir, "curl.log"))
	if err != nil || !strings.Contains(string(log), "--max-time 10 --resolve example.com:443:127.0.0.1") || !strings.Contains(string(log), "--max-time 10 --resolve www.example.com:443:127.0.0.1") {
		t.Fatalf("precheck did not make bounded per-domain probes: %v, %s", err, log)
	}
}

func TestAdoptionRetainsPrecheckDomainsBeforeEdgeReplacement(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	curl := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
if [ "$FAKE_CURL_MODE" = after-host-stages ]; then
  case "$*" in *"--resolve www.example.com:443:127.0.0.1"*) exit 22 ;; esac
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(fakeBin, "curl"), []byte(curl), 0o700); err != nil {
		t.Fatal(err)
	}
	docker := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$*" in
  *Version.Index*) echo 1 ;;
  *"json .Spec.TaskTemplate.ContainerSpec}}"*) echo old-container-spec ;;
  *"json .Spec}}"*) echo old-service-spec ;;
  *"ContainerSpec.User}}|{{.Spec.TaskTemplate.ContainerSpec.Image}}"*) echo '10001:10001|caddy:1' ;;
  *"stack deploy"*) exit 99 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(fakeBin, "docker"), []byte(docker), 0o700); err != nil {
		t.Fatal(err)
	}
	curlLog := filepath.Join(dir, "curl.log")
	dockerLog := filepath.Join(dir, "docker.log")
	run := func(program, mode string) (string, string, error) {
		t.Helper()
		command := exec.Command("sh", "-s")
		command.Stdin = strings.NewReader(program)
		command.Env = append(os.Environ(),
			"PATH="+fakeBin+":"+os.Getenv("PATH"),
			"FAKE_CURL_MODE="+mode,
			"FAKE_CURL_LOG="+curlLog,
			"FAKE_DOCKER_LOG="+dockerLog,
		)
		var stdout, stderr strings.Builder
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		return stdout.String(), stderr.String(), err
	}
	allHosts := []string{"example.com", "www.example.com"}
	precheckOutput, precheckError, err := run(setupCaddyDomainPrecheckCommand(allHosts), "healthy")
	if err != nil {
		t.Fatalf("two answering domains did not pass the early precheck: %v, %s", err, precheckError)
	}
	servingHosts, err := parseCaddyDomainPrecheckOutput(precheckOutput, allHosts)
	if err != nil || !reflect.DeepEqual(servingHosts, allHosts) {
		t.Fatalf("early precheck domain set = %v, %v; want %v", servingHosts, err, allHosts)
	}
	_, stderr, err := run(setupCaddyReconvergeCommand("caddy:2", servingHosts), "after-host-stages")
	if err == nil || !strings.Contains(stderr, "previously serving HTTPS domain www.example.com stopped answering; no edge update was attempted") {
		t.Fatalf("edge replacement did not refuse the domain lost during host stages: %v, %s", err, stderr)
	}
	log, readErr := os.ReadFile(dockerLog)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(log), "stack deploy") {
		t.Fatalf("edge replacement ran after an early serving domain stopped answering:\n%s", log)
	}
}

func TestAdoptionDomainPrecheckPrecedesHostMutation(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "setup_adopt.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var apply *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "applyAdoption" {
			apply = function
			break
		}
	}
	if apply == nil {
		t.Fatal("applyAdoption was not found")
	}
	positions := map[string]token.Pos{}
	ast.Inspect(apply.Body, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
			selector, selectorOK := assignment.Lhs[0].(*ast.SelectorExpr)
			base, baseOK := (*ast.Ident)(nil), false
			if selectorOK {
				base, baseOK = selector.X.(*ast.Ident)
			}
			rhs, rhsOK := assignment.Rhs[0].(*ast.Ident)
			if selectorOK && baseOK && rhsOK && base.Name == "edge" && selector.Sel.Name == "ProbeHosts" && rhs.Name == "servingHosts" {
				positions["retain-baseline"] = assignment.Pos()
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch function := call.Fun.(type) {
		case *ast.Ident:
			name = function.Name
		case *ast.SelectorExpr:
			name = function.Sel.Name
		}
		if name == "parseCaddyDomainPrecheckOutput" {
			positions["parse-precheck"] = call.Pos()
		}
		if name == "setupCaddyReconvergeCommand" && len(call.Args) == 2 {
			selector, ok := call.Args[1].(*ast.SelectorExpr)
			base, baseOK := (*ast.Ident)(nil), false
			if ok {
				base, baseOK = selector.X.(*ast.Ident)
			}
			if ok && baseOK && base.Name == "edge" && selector.Sel.Name == "ProbeHosts" {
				positions["edge-command"] = call.Pos()
			}
		}
		if name == "run" && len(call.Args) == 1 {
			switch source := call.Args[0].(type) {
			case *ast.Ident:
				if source.Name == "adoptionClaimSource" {
					positions["claim"] = call.Pos()
				}
			case *ast.CallExpr:
				if function, ok := source.Fun.(*ast.Ident); ok {
					if function.Name == "setupCaddyDomainPrecheckCommand" {
						positions["domain-precheck"] = call.Pos()
					}
				}
			}
		}
		switch name {
		case "UploadContent":
			positions["upload"] = call.Pos()
		case "runSetupStages":
			positions["stages"] = call.Pos()
		case "saveTrustedHostIdentity":
			positions["identity"] = call.Pos()
		}
		return true
	})
	precheck := positions["domain-precheck"]
	if precheck == token.NoPos {
		t.Fatal("applyAdoption does not run a live domain precheck")
	}
	for _, step := range []string{"parse-precheck", "retain-baseline", "stages", "edge-command"} {
		if positions[step] == token.NoPos {
			t.Fatalf("applyAdoption does not preserve and pass the early domain set: %v", positions)
		}
	}
	if !(precheck < positions["parse-precheck"] && positions["parse-precheck"] < positions["retain-baseline"] && positions["retain-baseline"] < positions["stages"] && positions["stages"] < positions["edge-command"]) {
		t.Fatalf("the early successful domain set must be parsed, retained, and passed to the edge after host stages: %v", positions)
	}
	for _, mutation := range []string{"claim", "upload", "stages", "identity"} {
		if positions[mutation] == token.NoPos || precheck >= positions[mutation] {
			t.Fatalf("live domain precheck must run before %s: positions=%v", mutation, positions)
		}
	}
}

func TestEdgeReconvergeProgramOrder(t *testing.T) {
	program := setupCaddyReconvergeCommand("caddy:2.10@sha256:"+strings.Repeat("a", 64), []string{"example.com"})
	ordered := []string{
		"command -v curl",
		"curl -sS -o /dev/null --max-time 10 --resolve",
		"previously serving HTTPS domain $probe_host stopped answering; no edge update was attempted",
		"if ! verify_before_hosts; then exit 1; fi",
		"cp /tmp/shuttle-caddy-stack.yml",
		"sh /tmp/shuttle-caddy-volumes.sh",
		"docker image inspect",
		"if ! verify_before_hosts; then exit 1; fi",
		"failed_step=''",
		"if docker stack deploy --detach --prune",
		"the service spec is unchanged, so rollback was not needed",
		".UpdateStatus.State",
		".Spec.TaskTemplate.ContainerSpec.CapabilityDrop",
		".HostConfig.CapDrop",
		".HostConfig.CapAdd",
		"curl -sS -o /dev/null --max-time \"$curl_timeout\" --resolve",
		"touch /etc/shuttle/setup.d/50-caddy-direct",
	}
	previous := -1
	for _, text := range ordered {
		start := previous + 1
		offset := strings.Index(program[start:], text)
		current := -1
		if offset >= 0 {
			current = start + offset
		}
		if current <= previous {
			t.Fatalf("program step %q is missing or out of order:\n%s", text, program)
		}
		previous = current
	}
	if strings.Contains(program, "docker service update --force") || strings.Contains(program, "docker stack rm shuttle-edge") {
		t.Fatal("reconvergence must use the declared stack update and service rollback")
	}
	postUpdate := strings.Index(program, `if [ -z "$failed_step" ] && [ -n "$before_hosts" ]; then`)
	if postUpdate < 0 {
		t.Fatalf("post-update serving checks are missing:\n%s", program)
	}
	httpsProbe := strings.Index(program[postUpdate:], `--resolve "$probe_host:443:127.0.0.1"`)
	httpProbe := strings.Index(program[postUpdate:], `http://127.0.0.1/`)
	if httpsProbe < 0 || httpProbe < 0 || httpsProbe >= httpProbe {
		t.Fatalf("success must verify every previously serving HTTPS domain and then bounded HTTP 80:\n%s", program)
	}
	if !strings.Contains(program, `--max-time "$curl_timeout" http://127.0.0.1/`) {
		t.Fatalf("HTTP 80 probe does not share the bounded post-update deadline:\n%s", program)
	}
	if strings.Contains(program, "NoNewPrivileges") || strings.Contains(program, "SecurityOpt") || strings.Contains(program, "https://127.0.0.1/") {
		t.Fatal("reconvergence must not require Swarm-dropped security options or direct-IP TLS")
	}
	for _, property := range []string{
		".Spec.TaskTemplate.ContainerSpec.User",
		".Spec.TaskTemplate.ContainerSpec.Image",
		".Spec.TaskTemplate.ContainerSpec.ReadOnly",
		".Spec.TaskTemplate.ContainerSpec.CapabilityDrop",
		".Spec.TaskTemplate.ContainerSpec.CapabilityAdd",
		".Config.User",
		".Config.Image",
		".HostConfig.ReadonlyRootfs",
		".HostConfig.CapDrop",
		".HostConfig.CapAdd",
	} {
		if !strings.Contains(program, property) {
			t.Fatalf("post-update verification omits %s", property)
		}
	}
}

func TestEdgeReconvergeProgramRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		updateState                string
		recoveryStatus             string
		serviceSpec                string
		containerHardening         string
		restoredTaskIdentity       string
		curlMode                   string
		ownerConfig                string
		ownerData                  string
		wantRestoredOwners         []string
		checkOwnership             bool
		restoreOnly                bool
		deployFails                bool
		deploySpecChanged          bool
		rollbackFails              bool
		wantExit                   bool
		wantRollback               bool
		wantCheckpoint             bool
		wantFailureReport          bool
		wantRecoveryReport         bool
		wantRecoveryFailure        bool
		wantCritical               bool
		wantUnchangedDeployFailure bool
	}{
		{name: "swarm rollback completes and recovers traffic", updateState: "rollback_completed", recoveryStatus: "rollback_completed", ownerConfig: "0:0", ownerData: "1234:5678", wantRestoredOwners: []string{"0:0", "1234:5678"}, checkOwnership: true, wantExit: true, wantFailureReport: true, wantRecoveryReport: true},
		// Review of DEV-DEPL-81 round 3: a 10001-owned volume root can hold root-owned 0600 files; those come back to root.
		{name: "rollback restores nested root files under a 10001 root", updateState: "rollback_completed", recoveryStatus: "rollback_completed", ownerConfig: "10001:10001", ownerData: "0:0", wantRestoredOwners: []string{"10001:10001", "0:0"}, checkOwnership: true, wantExit: true, wantRecoveryReport: true},
		{name: "wait for swarm rollback completion", updateState: "rollback_started", recoveryStatus: "rollback_completed", wantExit: true, wantFailureReport: true, wantRecoveryReport: true},
		{name: "wrong service hardening", updateState: "completed", serviceSpec: "invalid", wantExit: true, wantRollback: true, wantFailureReport: true, wantRecoveryReport: true},
		{name: "task does not expose no-new-privileges from stack deploy", updateState: "completed", wantCheckpoint: true},
		{name: "restored task has wrong image", updateState: "completed", serviceSpec: "invalid", restoredTaskIdentity: "restored-task|10001:10001|caddy:2", wantExit: true, wantRollback: true, wantRecoveryFailure: true},
		{name: "rollback has no restored task", updateState: "completed", serviceSpec: "invalid", restoredTaskIdentity: "", wantExit: true, wantRollback: true, wantRecoveryFailure: true},
		{name: "swarm rollback never completes", updateState: "rollback_started", recoveryStatus: "rollback_started", wantExit: true, wantRecoveryFailure: true},
		{name: "rollback listener check fails", updateState: "completed", serviceSpec: "invalid", curlMode: "recovery-listener-fails", wantExit: true, wantRollback: true, wantRecoveryFailure: true},
		{name: "rollback domain check fails", updateState: "completed", serviceSpec: "invalid", curlMode: "recovery-domain-fails", wantExit: true, wantRollback: true, wantRecoveryFailure: true},
		{name: "rollback command fails", updateState: "completed", serviceSpec: "invalid", rollbackFails: true, wantExit: true, wantRollback: true, wantCritical: true},
		{name: "previously answering host stops", updateState: "completed", curlMode: "fail-after", wantExit: true, wantRollback: true, wantFailureReport: true, wantRecoveryReport: true},
		{name: "replacement serves HTTPS but not HTTP 80", updateState: "completed", curlMode: "http-fails-after", wantExit: true, wantRollback: true, wantFailureReport: true, wantRecoveryReport: true},
		{name: "deploy exits after changing the service spec", updateState: "completed", deployFails: true, deploySpecChanged: true, wantExit: true, wantRollback: true, wantFailureReport: true, wantRecoveryReport: true},
		{name: "deploy failure leaves the service spec unchanged", updateState: "completed", deployFails: true, wantExit: true, wantUnchangedDeployFailure: true},
		// Review of DEV-DEPL-81: an exit before any rollback (deploy failed, spec unchanged) must still give the incumbent its files back.
		{name: "unchanged-spec deploy failure restores owners", updateState: "completed", deployFails: true, ownerConfig: "0:0", ownerData: "0:0", wantRestoredOwners: []string{"0:0", "0:0"}, checkOwnership: true, restoreOnly: true, wantExit: true, wantUnchangedDeployFailure: true},
		// Review of DEV-DEPL-81 round 2: an explicit rollback waits for a task that needs its files back, so owners are restored before it is requested.
		{name: "explicit rollback restores owners before it is requested", updateState: "completed", serviceSpec: "invalid", ownerConfig: "0:0", ownerData: "0:0", wantRestoredOwners: []string{"0:0", "0:0"}, checkOwnership: true, restoreOnly: true, wantExit: true, wantRollback: true, wantFailureReport: true, wantRecoveryReport: true},
		// Review of DEV-DEPL-81: a root edge with cap_drop ALL cannot start until it owns its files again, so restoration must not wait for rollback_completed.
		{name: "rollback stuck in rollback_started still restores owners", updateState: "rollback_started", recoveryStatus: "rollback_started", ownerConfig: "0:0", ownerData: "0:0", wantRestoredOwners: []string{"0:0", "0:0"}, checkOwnership: true, restoreOnly: true, wantExit: true, wantRecoveryFailure: true},
		{name: "no domain answers before mutation", updateState: "completed", curlMode: "fail-before", wantExit: true},
		{name: "direct-IP TLS fails while restored domain HTTPS works", updateState: "completed", serviceSpec: "invalid", curlMode: "direct-ip-tls-fails", wantExit: true, wantRollback: true, wantFailureReport: true, wantRecoveryReport: true},
		{name: "healthy update", updateState: "completed", ownerConfig: "0:0", ownerData: "1234:5678", checkOwnership: true, wantCheckpoint: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			program := setupCaddyReconvergeCommand("caddy:2", []string{"example.com"})
			program = strings.ReplaceAll(program, "/tmp/", filepath.Join(dir, "tmp")+"/")
			program = strings.ReplaceAll(program, "/etc/shuttle", filepath.Join(dir, "etc", "shuttle"))
			program = strings.ReplaceAll(program, "/opt/shuttle", filepath.Join(dir, "opt", "shuttle"))
			program = strings.ReplaceAll(program, "install -o root -g root -m", "install -m")
			assetDir := filepath.Join(dir, "tmp")
			if err := os.MkdirAll(assetDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "etc", "shuttle"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"shuttle-caddy-stack.yml", "shuttle-Caddyfile"} {
				if err := os.WriteFile(filepath.Join(assetDir, path), []byte("test\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(assetDir, "shuttle-caddy-volumes.sh"), []byte(caddyVolumePreparationWithOwnerSnapshot(config.Caddy{})), 0o700); err != nil {
				t.Fatal(err)
			}
			fakeBin := filepath.Join(dir, "bin")
			if err := os.MkdirAll(fakeBin, 0o700); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "docker.log")
			docker := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
printf 'docker %s\n' "$*" >> "$FAKE_EVENT_LOG"
case " $* " in
  *" image inspect "*) exit 0 ;;
  *" volume inspect "*) exit 0 ;;
  *" run "*)
    case "$*" in
      *"find /volume -xdev"*)
        case "$*" in
          *"shuttle-edge_shuttle_caddy_config:/volume:nocopy"*) printf '%s /volume\n0:0 /volume/nested root.key\n' "$FAKE_OWNER_CONFIG" ;;
          *"shuttle-edge_shuttle_caddy_data:/volume:nocopy"*) printf '%s /volume\n0:0 /volume/nested root.key\n' "$FAKE_OWNER_DATA" ;;
          *) exit 2 ;;
        esac
        exit 0
        ;;
      *"test -r /data"*) exit 0 ;;
      *" restore "*)
        for last in "$@"; do :; done
        printf 'chown -R %s /volume\n' "$last" >> "$FAKE_EVENT_LOG"
        while read -r owner path; do printf 'chown -h %s %s\n' "$owner" "$path" >> "$FAKE_EVENT_LOG"; done
        exit 0
        ;;
      *"chown -R "*) exit 0 ;;
    esac
    exit 0
    ;;
  *" stack deploy "*)
    if [ "$FAKE_DEPLOY_FAIL" = true ]; then
      if [ "$FAKE_DEPLOY_SPEC_CHANGED" = true ]; then touch "$FAKE_DEPLOY_MARKER"; fi
      exit 23
    fi
    touch "$FAKE_DEPLOY_MARKER"
    exit 0
    ;;
  *" service rollback --detach shuttle-edge_caddy "*)
    if [ "$FAKE_ROLLBACK_FAIL" = true ]; then exit 1; fi
    touch "$FAKE_ROLLBACK_MARKER"
    rm -f "$FAKE_DATE_COUNT"
    exit 0
    ;;
  *UpdateStatus.State*)
    count=0
    [ ! -f "$FAKE_UPDATE_COUNT" ] || count=$(cat "$FAKE_UPDATE_COUNT")
    count=$((count + 1))
    printf '%s' "$count" > "$FAKE_UPDATE_COUNT"
    if [ -f "$FAKE_ROLLBACK_MARKER" ]; then printf '%s\n' completed
    elif [ "$count" -eq 1 ]; then
      case "$FAKE_UPDATE_STATE" in
        rollback_started|rollback_completed|rollback_paused) printf 'rollback-detected=%s\n' "$FAKE_UPDATE_STATE" >> "$FAKE_EVENT_LOG" ;;
      esac
      printf '%s\n' "$FAKE_UPDATE_STATE"
    else printf '%s\n' "${FAKE_RECOVERY_STATUS:-$FAKE_UPDATE_STATE}"
    fi
    exit 0
    ;;
  *"Version.Index"*)
    if [ -f "$FAKE_ROLLBACK_MARKER" ]; then echo 4
    elif [ -f "$FAKE_DEPLOY_MARKER" ]; then echo 2
    else echo 1
    fi
    exit 0
    ;;
		*ContainerSpec\}\}*) printf '%s\n' '{"Image":"caddy:1","User":"10001:10001"}'; exit 0 ;;
  *"json .Spec}}"*)
    if [ -f "$FAKE_DEPLOY_MARKER" ] && [ "$FAKE_DEPLOY_SPEC_CHANGED" = true ]; then echo changed-service-spec; else echo old-service-spec; fi
    exit 0
    ;;
			*CapabilityDrop*CapabilityAdd*) printf '%s\n' "$FAKE_SERVICE_SPEC"; exit 0 ;;
		*"ContainerSpec.User}}|{{.Spec.TaskTemplate.ContainerSpec.Image}}"*) printf '%s\n' '10001:10001|caddy:1'; exit 0 ;;
		*"HostConfig.ReadonlyRootfs"*) printf '%s\n' "$FAKE_CONTAINER_HARDENING"; exit 0 ;;
			*"index .Config.Labels"*) printf '%s\n' "$FAKE_RESTORED_TASK_IDENTITY"; exit 0 ;;
  *Replicas*) echo 1/1; exit 0 ;;
  *" ps -q "*) printf '%s\n' "${FAKE_CONTAINER:-new-task}"; exit 0 ;;
  *" exec "*) exit 0 ;;
esac
exit 3
`
			if err := os.WriteFile(filepath.Join(fakeBin, "docker"), []byte(docker), 0o700); err != nil {
				t.Fatal(err)
			}
			curl := `#!/bin/sh
printf 'curl %s\n' "$*" >> "$FAKE_EVENT_LOG"
count=0
[ ! -f "$FAKE_CURL_COUNT" ] || count=$(cat "$FAKE_CURL_COUNT")
count=$((count + 1))
printf '%s' "$count" > "$FAKE_CURL_COUNT"
case "$FAKE_CURL_MODE" in
  fail-before) case "$*" in *"--resolve"*) exit 22 ;; esac ;;
  fail-after)
    case "$*" in
      *"--resolve"*)
        resolve_count=0
        [ ! -f "$FAKE_RESOLVE_COUNT" ] || resolve_count=$(cat "$FAKE_RESOLVE_COUNT")
        resolve_count=$((resolve_count + 1))
        printf '%s' "$resolve_count" > "$FAKE_RESOLVE_COUNT"
        if [ ! -f "$FAKE_ROLLBACK_MARKER" ] && [ "$resolve_count" -eq 3 ]; then exit 22; fi
        ;;
    esac
    ;;
  recovery-listener-fails)
    if [ -f "$FAKE_ROLLBACK_MARKER" ]; then
      case "$*" in *"--resolve"*) ;; *) exit 22 ;; esac
    fi
    ;;
  recovery-domain-fails)
    case "$*" in *"--resolve"*) if [ -f "$FAKE_ROLLBACK_MARKER" ]; then exit 22; fi ;; esac
    ;;
  direct-ip-tls-fails)
    case "$*" in *"https://127.0.0.1/"*) exit 35 ;; esac
    ;;
  http-fails-after)
    case "$*" in
      *"http://127.0.0.1/"*) if [ ! -f "$FAKE_ROLLBACK_MARKER" ]; then exit 22; fi ;;
    esac
    ;;
esac
exit 0
`
			if err := os.WriteFile(filepath.Join(fakeBin, "curl"), []byte(curl), 0o700); err != nil {
				t.Fatal(err)
			}
			date := `#!/bin/sh
count=0
[ ! -f "$FAKE_DATE_COUNT" ] || count=$(cat "$FAKE_DATE_COUNT")
count=$((count + 1))
printf '%s' "$count" > "$FAKE_DATE_COUNT"
if { [ "$FAKE_CURL_MODE" = fail-after ] || [ "$FAKE_CURL_MODE" = http-fails-after ]; } && [ ! -f "$FAKE_ROLLBACK_MARKER" ] && [ "$count" -gt 1 ]; then echo 161; else echo $((100 + count / 2)); fi
`
			if err := os.WriteFile(filepath.Join(fakeBin, "date"), []byte(date), 0o700); err != nil {
				t.Fatal(err)
			}
			sleep := "#!/bin/sh\nexit 0\n"
			if err := os.WriteFile(filepath.Join(fakeBin, "sleep"), []byte(sleep), 0o700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("sh", "-s")
			command.Stdin = strings.NewReader(program)
			serviceSpec := tc.serviceSpec
			if serviceSpec == "" {
				serviceSpec = `10001:10001|caddy:2|true|["ALL"]|["NET_BIND_SERVICE"]`
			}
			containerHardening := tc.containerHardening
			if containerHardening == "" {
				containerHardening = `10001:10001|caddy:2|true|["ALL"]|["NET_BIND_SERVICE"]`
			}
			restoredTaskIdentity := tc.restoredTaskIdentity
			if tc.name != "rollback has no restored task" && restoredTaskIdentity == "" {
				restoredTaskIdentity = "restored-task|10001:10001|caddy:1"
			}
			command.Env = append(os.Environ(),
				"PATH="+fakeBin+":"+os.Getenv("PATH"),
				"FAKE_DOCKER_LOG="+logPath,
				"FAKE_EVENT_LOG="+filepath.Join(dir, "events.log"),
				"FAKE_DEPLOY_MARKER="+filepath.Join(dir, "deployed"),
				"FAKE_DEPLOY_FAIL="+map[bool]string{true: "true", false: "false"}[tc.deployFails],
				"FAKE_DEPLOY_SPEC_CHANGED="+map[bool]string{true: "true", false: "false"}[tc.deploySpecChanged],
				"FAKE_ROLLBACK_MARKER="+filepath.Join(dir, "rollback"),
				"FAKE_UPDATE_COUNT="+filepath.Join(dir, "update.count"),
				"FAKE_UPDATE_STATE="+tc.updateState,
				"FAKE_RECOVERY_STATUS="+tc.recoveryStatus,
				"FAKE_SERVICE_SPEC="+serviceSpec,
				"FAKE_CONTAINER_HARDENING="+containerHardening,
				"FAKE_RESTORED_TASK_IDENTITY="+restoredTaskIdentity,
				"FAKE_ROLLBACK_FAIL="+map[bool]string{true: "true", false: "false"}[tc.rollbackFails],
				"FAKE_CURL_MODE="+tc.curlMode,
				"FAKE_OWNER_CONFIG="+map[bool]string{true: tc.ownerConfig, false: "0:0"}[tc.ownerConfig != ""],
				"FAKE_OWNER_DATA="+map[bool]string{true: tc.ownerData, false: "1234:5678"}[tc.ownerData != ""],
				"FAKE_CURL_COUNT="+filepath.Join(dir, "curl.count"),
				"FAKE_RESOLVE_COUNT="+filepath.Join(dir, "resolve.count"),
				"FAKE_DATE_COUNT="+filepath.Join(dir, "date.count"),
			)
			var stdout, stderr strings.Builder
			command.Stdout = &stdout
			command.Stderr = &stderr
			err := command.Run()
			if (err != nil) != tc.wantExit {
				t.Fatalf("exit error = %v, want failure %v; stdout=%s stderr=%s", err, tc.wantExit, stdout.String(), stderr.String())
			}
			if tc.wantUnchangedDeployFailure {
				exitErr, ok := err.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != 23 {
					t.Fatalf("unchanged deploy failure exit = %v, want 23", err)
				}
			}
			log, readErr := os.ReadFile(logPath)
			if readErr != nil {
				if tc.wantRollback {
					t.Fatal(readErr)
				}
				log = nil
			}
			rolledBack := strings.Contains(string(log), "service rollback --detach shuttle-edge_caddy")
			if rolledBack != tc.wantRollback {
				t.Fatalf("rollback called = %v, want %v; docker log:\n%s", rolledBack, tc.wantRollback, log)
			}
			if tc.checkOwnership {
				events, eventErr := os.ReadFile(filepath.Join(dir, "events.log"))
				if eventErr != nil {
					t.Fatal(eventErr)
				}
				eventText := string(events)
				if len(tc.wantRestoredOwners) == 0 {
					for _, owner := range []string{tc.ownerConfig, tc.ownerData} {
						if owner != "" && strings.Contains(eventText, "chown -R "+owner+" /volume") {
							t.Fatalf("successful update restored old owner %s:\n%s", owner, eventText)
						}
					}
				} else if tc.restoreOnly {
					rollbackRequest := strings.Index(eventText, "service rollback --detach shuttle-edge_caddy")
					for _, owner := range tc.wantRestoredOwners {
						restored := strings.Index(eventText, "chown -R "+owner+" /volume")
						if restored < 0 {
							t.Fatalf("owner %s was not restored:\n%s", owner, eventText)
						}
						if tc.wantRollback && (rollbackRequest < 0 || restored > rollbackRequest) {
							t.Fatalf("owner %s restore at %d must precede the explicit rollback request at %d:\n%s", owner, restored, rollbackRequest, eventText)
						}
					}
				} else {
					detected := strings.Index(eventText, "rollback-detected=")
					httpProbe := strings.Index(eventText, "curl -sS -o /dev/null --max-time 10 http://127.0.0.1/")
					if detected < 0 || httpProbe < 0 || detected >= httpProbe {
						t.Fatalf("rollback detection or recovery HTTP probe is missing:\n%s", eventText)
					}
					for _, owner := range tc.wantRestoredOwners {
						restored := strings.Index(eventText[detected:], "chown -R "+owner+" /volume")
						if restored >= 0 {
							restored += detected
						}
						if restored <= detected || restored >= httpProbe {
							t.Fatalf("owner %s restore at %d must follow rollback detection at %d and precede HTTP probe at %d:\n%s", owner, restored, detected, httpProbe, eventText)
						}
					}
					if nested := strings.Index(eventText[detected:], "chown -h 0:0 /volume/nested root.key"); nested < 0 {
						t.Fatalf("a recorded root-owned file under the volume was not restored path by path:\n%s", eventText)
					}
				}
			}
			if tc.wantFailureReport && !strings.Contains(stderr.String(), "the shared edge did not converge (") {
				t.Fatalf("missing rollback report: %s", stderr.String())
			}
			if tc.wantRecoveryReport && (!strings.Contains(stderr.String(), "rollback restored task restored-task") || !strings.Contains(stderr.String(), "recovered HTTP 80 and previously answering HTTPS domains on 443")) {
				t.Fatalf("rollback recovery was not proved before reporting success: %s", stderr.String())
			}
			if tc.wantRecoveryFailure && (!strings.Contains(stderr.String(), "CRITICAL: the shared edge rollback recovery failed (") || strings.Contains(stderr.String(), "rollback restored task")) {
				t.Fatalf("rollback recovery failure was not reported explicitly: %s", stderr.String())
			}
			if tc.wantCritical && !strings.Contains(stderr.String(), "CRITICAL: the shared edge rollback failed; inspect docker service ps shuttle-edge_caddy") {
				t.Fatalf("missing critical rollback failure report: %s", stderr.String())
			}
			if tc.wantUnchangedDeployFailure && !strings.Contains(stderr.String(), "the service spec is unchanged, so rollback was not needed") {
				t.Fatalf("nonzero deploy with unchanged service spec was not reported without rollback: %s", stderr.String())
			}
			if tc.curlMode == "fail-before" {
				if !strings.Contains(stderr.String(), "previously serving HTTPS domain example.com stopped answering; no edge update was attempted") {
					t.Fatalf("missing pre-mutation refusal: %s", stderr.String())
				}
				if strings.Contains(string(log), "stack deploy") || strings.Contains(string(log), "service rollback") {
					t.Fatalf("host changed despite having no verifiable HTTPS domain:\n%s", log)
				}
			}
			checkpoint := filepath.Join(dir, "etc", "shuttle", "setup.d", "50-caddy-direct")
			_, statErr := os.Stat(checkpoint)
			if (statErr == nil) != tc.wantCheckpoint {
				t.Fatalf("checkpoint exists = %v, want %v (stat err %v)", statErr == nil, tc.wantCheckpoint, statErr)
			}
		})
	}
}

// docker stack deploy stores NET_BIND_SERVICE as CAP_NET_BIND_SERVICE (seen on
// Docker 29.9.2); a correctly hardened edge must not be reported as drifted.
func TestEdgeSpecDriftAcceptsDockerCapabilitySpelling(t *testing.T) {
	observed, err := parseObservedEdgeSpec(`{"Image":"caddy:2","User":"10001:10001","ReadOnly":true,"CapabilityDrop":["ALL"],"CapabilityAdd":["CAP_NET_BIND_SERVICE"]}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, drift := range edgeSpecDrift(observed, "") {
		if strings.Contains(drift, "capabilities") {
			t.Fatalf("CAP_NET_BIND_SERVICE reported as drift: %v", drift)
		}
	}
}

// Review of DEV-DEPL-81, round 4: the in-container restore loop must keep a
// trailing space in a file name and must not stop at a recorded path that
// disappeared, or later certificates keep the edge user's ownership.
func TestCaddyOwnerRestoreLoopIsExactAndSkipsVanishedPaths(t *testing.T) {
	program := setupCaddyReconvergeCommand("caddy:2@sha256:"+strings.Repeat("a", 64), []string{"example.com"})
	start := strings.Index(program, `-ec 'chown -R "$1" /volume;`)
	end := strings.Index(program, `' restore "$root_owner"`)
	if start < 0 || end < start {
		t.Fatalf("restore loop not found in the re-convergence program:\n%s", program)
	}
	loop := program[start+len(`-ec '`) : end]
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" >> \"$CHOWN_LOG\"\n"
	if err := os.WriteFile(filepath.Join(bin, "chown"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	volume := filepath.Join(dir, "volume")
	if err := os.MkdirAll(volume, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"key ", "key", "z.crt"} {
		if err := os.WriteFile(filepath.Join(volume, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	loop = strings.ReplaceAll(loop, "/volume", volume)
	manifest := "0:0 " + volume + "/key \n" + "0:0 " + volume + "/gone.tmp\n" + "1234:5678 " + volume + "/z.crt\n"
	logPath := filepath.Join(dir, "chown.log")
	command := exec.Command("sh", "-ec", loop, "restore", "10001:10001")
	command.Stdin = strings.NewReader(manifest)
	command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "CHOWN_LOG="+logPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("restore loop failed: %v\n%s", err, output)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(log)
	for _, want := range []string{"-h|0:0|" + volume + "/key \n", "-h|1234:5678|" + volume + "/z.crt\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("restore loop missed %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "-h|0:0|"+volume+"/key\n") || strings.Contains(got, "gone.tmp") {
		t.Fatalf("restore loop touched the wrong file or a vanished path:\n%s", got)
	}
}

// The e2e of 30-10-2026 saw Swarm start the rollback task 60 s after creating
// it; the recovery budget must outlast that allocator retry.
func TestEdgeRecoveryBudgetOutlastsSwarmAllocatorRetry(t *testing.T) {
	program := setupCaddyReconvergeCommand("caddy:2@sha256:"+strings.Repeat("a", 64), []string{"example.com"})
	if !strings.Contains(program, "recovery_deadline=$(($(date +%s) + 150))") {
		t.Fatalf("rollback recovery budget must be 150 s:\n%s", program)
	}
}

// Review of DEV-DEPL-81, round 5: the SSH deadline of the re-convergence must
// outlast the program's own waits, or a slow rollback is cut before it reports.
func TestEdgeReconvergeSSHTimeoutCoversProgramBudgets(t *testing.T) {
	program := setupCaddyReconvergeCommand("caddy:2@sha256:"+strings.Repeat("a", 64), []string{"example.com"})
	if !strings.Contains(program, `[ "$attempt" -lt 120 ]`) || !strings.Contains(program, "recovery_deadline=$(($(date +%s) + 150))") {
		t.Fatalf("program budgets changed; update edgeReconvergeSSHTimeout and this test:\n%s", program)
	}
	if edgeReconvergeSSHTimeout < (120+150)*time.Second+3*time.Minute {
		t.Fatalf("edgeReconvergeSSHTimeout %s does not cover 120 s update + 150 s recovery + 3 min margin", edgeReconvergeSSHTimeout)
	}
}
