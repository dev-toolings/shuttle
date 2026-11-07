package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// Adoption converges a host that is already in service instead of refusing it.
//
// `shuttle setup` is written for a fresh VPS: it demands root at first contact
// and exits as soon as it finds Docker or PostgreSQL resources it did not
// declare. That is the right default — a setup run that silently rearranges a
// live host is a much worse failure than one that stops — but it leaves every
// host installed by a previous generation of Shuttle with no supported path
// forward, whatever the project.
//
// --adopt is the explicit, opt-in answer. It relaxes *who connects*, never
// *which host answers*: the out-of-band host fingerprint stays mandatory, and
// the adoption user must prove non-interactive root before anything is read.
// It also refuses to adopt a machine it cannot recognise: the previous
// generation's marker for the configured application must exist.
//
// --adopt --yes converges the host. It runs the four checkpointed stages
// 10-base through 40-runtime, in the same order and against the same
// /etc/shuttle/setup.d markers as a fresh setup, so an interrupted adoption
// resumes instead of restarting, and it then finishes the two steps that make
// the host deployable and hardened.
//
// Those last two used to be deferred, and deferring them was not a boundary but
// a hole. /etc/sudoers.d/90-shuttle-root — the one rule that lets deploy invoke
// the signed root helper — is written by applyRootBaseline, which the SSH
// hardening transaction is the only caller of: an adoption that stopped after
// 40-runtime produced a deploy user with no privilege at all, so every later
// `shuttle deploy` on that host failed at its first signed operation. The
// hardening therefore runs, and it signs the first-contact account into
// AllowUsers so the operator does not lose the session they are converging
// from — nor the account a previous generation's deployments still use.
// --lock-out-first-contact-user removes it only with a verified replacement
// administrator. Adoption from root also requires a separate administrator.
//
// The 80/443 cutover is different in kind: Docker cannot bind a host-mode port
// twice, so handing those ports to the shared edge means stopping whatever
// answers on them, and that is an outage. It happens only when the operator
// asks for it with --cutover-edge, only against the container the plan named,
// and it restores that container if the edge does not come up. Both the
// hardening and the cutover are described in the plan the dry run prints, so
// what a run will do to a live host is visible before it is applied.
//
// The same reasoning governs the two adaptations inside the stages: on a host
// in service `apt-get dist-upgrade` is an unrequested change to software
// Shuttle was not asked to touch, and a pending reboot belongs to the
// operator's maintenance window, not to whenever a convergence run reaches it.

// adoptionExitLegacyMarkerMissing and its siblings are the survey's typed
// failures. They are exit codes rather than parsed text so that a truncated or
// noisy stdout can never be mistaken for a passing check.
const (
	adoptionExitUnsupportedOS      = 42
	adoptionExitLegacyMarkerAbsent = 44
	adoptionExitKeyNotAuthorized   = 45
	adoptionExitNoPasswordlessSudo = 46
)

// adoptionAppNamePattern re-validates the application name in the CLI before it
// is embedded in the marker path, even though config.Load already refused
// anything else. The helper boundary re-validates what the CLI validated; the
// same rule applies to a value the CLI is about to turn into a remote path.
var adoptionAppNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// adoptionUserPattern is the login accepted at first contact under --adopt. The
// value checked here is the exact value handed to the SSH client and to the
// remote survey; nothing is trimmed or rewritten in between.
var adoptionUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// adoptionSurveyValuePattern bounds what the survey may report. The host is,
// by definition, not yet trusted: its container names and directory names are
// attacker-influenced input to a report a human reads. A value outside this
// character set is refused instead of being printed.
var adoptionSurveyValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/@-]*$`)

// adoptionSteps is the fixed, ordered convergence vocabulary. Iterating a slice
// rather than a map keeps the printed plan identical between runs. AlwaysApplied
// says whether `--adopt --yes` converges the step unconditionally; the one that
// does not is the cutover, which is applied only when the operator asked for it,
// and it is listed here so the plan can name what it is leaving alone instead of
// omitting it.
var adoptionSteps = []struct {
	ID, Label     string
	AlwaysApplied bool
}{
	{"10-base", "security baseline, unattended upgrades, swap", true},
	{"20-docker", "Docker CE and one-node Swarm", true},
	// No version is named here on purpose: this table is a package-level
	// constant, it does not see the configuration, and on an adopted host the
	// major is resolved on the host itself (see setupPostgresCommand). Naming
	// one would be naming the wrong one half the time.
	{"30-postgres", "PostgreSQL on loopback and the Docker gateway", true},
	{"40-runtime", "deploy user, signed root helper, UFW and Docker forwarding policy", true},
	{"50-caddy-direct", "shared Caddy edge on 80/443", false},
}

// adoptionDeferredWork is what an applied adoption deliberately leaves undone.
// The plan prints it before anything is applied and the completion report
// prints it again afterwards, from this one function, so the two can never
// describe different boundaries.
//
// The database line is only true of a host the previous generation installed:
// it is that generation's PostgreSQL the migration would move. On a host
// Shuttle never set up there is no adopted database, and a report naming one
// sends the operator looking for it.
func adoptionDeferredWork(edge adoptionEdgePlan, legacy bool) []string {
	work := make([]string, 0, 2)
	if edge.ReconvergeRefusal != nil {
		work = append(work, edge.ReconvergeRefusal.Error())
	}
	if !edge.applies() && !edge.AlreadyServing {
		work = append(work, "50-caddy-direct: taking 80/443 from the incumbent listener and deploying the shared edge (--cutover-edge schedules it in the run itself)")
	}
	if legacy {
		work = append(work, "migrating the adopted application's PostgreSQL database")
	}
	return work
}

// errAdoptionNeedsConfirmation refuses an adoption that would mutate without
// being asked to. It is the same contract as `setup --yes`, worded for a host
// that is already carrying production.
var errAdoptionNeedsConfirmation = errors.New("adopting a host in service requires explicit --yes confirmation (run --adopt --dry-run first)")

// adoptionClaimSource is the first mutation of an applied adoption, and it is
// two lines for two reasons.
//
// /etc/shuttle/setup-state is written before the first stage rather than by
// 40-runtime alone. The exit-43 foreign-resource guard in the first-contact
// preflight fires only when neither that file nor the 10-base checkpoint
// exists; it exists to protect a machine nobody has claimed. Once an operator
// has explicitly adopted this host, an interruption between two stages must not
// leave a half-converged machine that the next `shuttle setup` refuses as
// foreign. The content is the same `version=2` 40-runtime writes, so nothing
// downstream can tell the two apart.
//
// The staging paths are removed because the uploads below are written by the
// adoption user, and /tmp is sticky: a file left there by an earlier run as
// root cannot be replaced by ops, and the upload would fail at the rename.
// The 30-10-2026 e2e hit exactly that with /tmp/shuttle-caddy-volumes.sh, which
// was missing from this list: TestAdoptionClaimRemovesEveryStagedUpload now
// fails when a new fixed /tmp/shuttle-* upload is added without its cleanup.
// edgeReconvergeSSHTimeout bounds the whole shared edge re-convergence over
// SSH: update wait (120 s) + rollback recovery (150 s) + pull, snapshot,
// restore and probes, with room to spare.
const edgeReconvergeSSHTimeout = 10 * time.Minute

const adoptionClaimSource = `set -eu
install -d -m 0755 /etc/shuttle
printf 'version=2\n' >/etc/shuttle/setup-state
rm -f /tmp/shuttle-operator.pub /tmp/shuttle-emergency-operator.pub /tmp/shuttle-root-trust.pem /tmp/shuttle-root /tmp/shuttle-Caddyfile /tmp/shuttle-caddy-stack.yml /tmp/shuttle-edge-entrypoint /tmp/shuttle-caddy-volumes.sh
`

// adoptionSurvey is the parsed inventory of a host being considered for
// adoption. Every slice is sorted and de-duplicated so the same host produces
// the same plan.
type adoptionSurvey struct {
	OS        string
	OSVersion string
	// RebootRequired is the host's own pending-reboot marker. It is surveyed
	// rather than discovered mid-run because it decides whether an adoption is
	// allowed to start at all.
	RebootRequired bool
	SetupState     string
	// LegacyMarker is "present" when /opt/shuttle/<app>/state.json exists —
	// the previous generation installed this application here — and "absent"
	// otherwise. The plan reads it to say whether this run converges a Shuttle
	// host or claims one that never was; it is surveyed rather than inferred
	// from --unmanaged so the plan describes the host, not the flag.
	LegacyMarker string
	// LiveRestore is dockerd's own answer ("true" or "false"), or "unknown"
	// when Docker is not running. A satisfied Docker stage is never changed.
	LiveRestore        string
	Gateway            string
	GatewaySubnet      string
	GatewayMTU         string
	DockerCheckpoint   string
	EdgeNetwork        string
	PostgresListen     string
	PostgresRetention  string
	PostgresCluster    string
	RegistryState      string
	PrerequisiteIssues []string
	// PublishedPorts are the host ports containers publish today. 40-runtime
	// closes every one not declared public, and the plan names them.
	PublishedPorts []int
	// ContainerRestart maps each container publishing 80 or 443 to its
	// restart policy, which the cutover has to neutralise and restore.
	ContainerRestart  map[string]string
	ContainerService  map[string]string
	Edge              *observedEdgeSpec
	EdgeSiteHosts     []string
	LegacyApps        []string
	ForeignContainers []string
	ShuttleContainers []string
	SwarmServices     []string
	ServicePorts      []string
	PortsHeld         []string
	Satisfied         []string
	Pending           []string
}

// adoptionSudoProofSource proves the adoption user can become root without a
// password before anything else is attempted. A sudo that would prompt hangs an
// SSH session with no TTY instead of failing, so it is tested with -n and
// reported as its own exit code.
const adoptionSudoProofSource = `set -eu
if ! sudo -n true >/dev/null 2>&1; then
  exit 46
fi
test "$(sudo -n id -u)" = 0
`

// adoptionRootProofSource is the same proof for a host whose root login is
// still open. It does not invoke sudo, which a minimal image may not install.
const adoptionRootProofSource = `set -eu
test "$(id -u)" = 0
`

// adoptionSurveySource reads the host and reports it. An edge service name
// alone used to make a legacy root task look satisfied, so the survey now
// records its container spec and effective Caddy host matchers needed to prove
// HTTPS survives a replacement. It is strictly read-only:
// no file is created, nothing is installed, no service is touched. It runs as
// root (through sudo for a non-root adoption user) because the inventory needs
// the listening-socket owners and the adoption user's authorized_keys.
//
// Every enumeration is sorted at the source, and the step probes are walked in
// a fixed order, so two runs against an unchanged host print the same plan.
const adoptionSurveySource = adoptionContainerClassificationSource + `set -eu
user=$1
fingerprint=$2
app=$3
unmanaged=$4
. /etc/os-release
printf 'os=%s\n' "$ID"
printf 'os-version=%s\n' "$VERSION_ID"
case "$ID:$VERSION_ID" in ubuntu:24.04|debian:13) ;; *) exit 42;; esac
test "$(id -u)" = 0
home=$(getent passwd "$user" | cut -d: -f6)
test -n "$home"
if ! ssh-keygen -lf "$home/.ssh/authorized_keys" -E sha256 2>/dev/null | awk '{print $2}' | grep -Fx "$fingerprint" >/dev/null; then
  exit 45
fi
if [ -f "/opt/shuttle/$app/state.json" ]; then
  printf 'legacy-marker=present\n'
else
  printf 'legacy-marker=absent\n'
fi
if [ -f /etc/shuttle/setup-state ]; then
  printf 'setup-state=present\n'
else
  printf 'setup-state=absent\n'
fi
if [ ! -f "/opt/shuttle/$app/state.json" ] && [ ! -f /etc/shuttle/setup-state ] && [ "$unmanaged" != 1 ]; then
  exit 44
fi
if [ -e /var/run/reboot-required ]; then
  printf 'reboot-required=present\n'
else
  printf 'reboot-required=absent\n'
fi
docker_ok=no
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker_ok=yes
fi
if [ "$docker_ok" = yes ]; then
  printf 'live-restore=%s\n' "$(docker info --format '{{.LiveRestoreEnabled}}')"
else
  printf 'live-restore=unknown\n'
fi
if [ "$docker_ok" = yes ]; then
  docker ps -a --format '{{.Names}}|{{.Label "dev.shuttle.owner"}}|{{.Label "com.docker.swarm.service.name"}}|{{.Label "com.docker.stack.namespace"}}' | sort | while IFS='|' read -r name owner service namespace; do
    classify_adoption_container "$name" "$owner" "$service" "$namespace" /var/lib/shuttle/apps
    if [ -n "$service" ]; then
      printf 'incumbent-service=%s %s\n' "$name" "$service"
    fi
  done
  if docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -qx active; then
    services=$(docker service ls --format '{{.Name}}') || { echo 'cannot inspect service inventory during adoption survey' >&2; exit 1; }
    printf '%s\n' "$services" | sort | while read -r service; do
      [ -n "$service" ] || continue
      printf 'swarm-service=%s\n' "$service"
      ports=$(docker service inspect "$service" --format '{{range .Endpoint.Ports}}{{printf "%d " .PublishedPort}}{{end}}') || exit 1
      for port in $ports; do case "$port" in 80|443) printf 'service-port=%s %s\n' "$port" "$service" ;; esac; done
    done
  fi
fi
for state in /opt/shuttle/*/state.json; do
  [ -f "$state" ] || continue
  directory=${state%/state.json}
  printf 'legacy-app=%s\n' "${directory##*/}"
done
for spec in 80/tcp 443/tcp 443/udp; do
  port=${spec%/*}
  case "${spec#*/}" in
    tcp) flag=-t ;;
    *) flag=-u ;;
  esac
  listeners=$(ss -H -ln "$flag" -p "sport = :$port" 2>/dev/null || true)
  if [ -n "$listeners" ]; then
    holders=$(printf '%s\n' "$listeners" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' ')
    if [ -z "$holders" ]; then
      holders='an unidentified process'
    fi
    printf 'port-held=%s by process %s\n' "$spec" "$holders"
  fi
done
if [ "$docker_ok" = yes ]; then
  for port in 80 443; do
    docker ps --format '{{.Names}}' --filter "publish=$port" | sort | sed "s|^|port-held=$port by published container |"
    docker ps --format '{{.Names}}' --filter "publish=$port" | sort | while read -r name; do
      printf 'incumbent-restart=%s %s\n' "$name" "$(docker container inspect "$name" --format '{{.HostConfig.RestartPolicy.Name}}')"
    done
  done
  docker ps --format '{{.Ports}}' | awk -F, '
    {
      for (i = 1; i <= NF; i++) {
        bind = $i
        sub(/^[ \t]*/, "", bind)
        if (index(bind, "->") == 0) continue
        sub(/->.*/, "", bind)
        if (bind ~ /^:::[0-9][0-9]*$/) sub(/^:::/, "[::]:", bind)
        print "published-bind=" bind
      }
    }
  ' | sort -u
  if docker service ls --format '{{.Name}}' 2>/dev/null | grep -qx shuttle-edge_caddy; then
    printf 'edge-container-spec=%s\n' "$(docker service inspect shuttle-edge_caddy --format '{{json .Spec.TaskTemplate.ContainerSpec}}')"
    edge_container=$(docker ps -q --filter label=com.docker.swarm.service.name=shuttle-edge_caddy | head -n 1)
    [ -n "$edge_container" ]
    effective_caddy_config=$(docker exec "$edge_container" caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile)
    printf 'edge-effective-config=%s\n' "$(printf '%s' "$effective_caddy_config" | base64 -w0)"
  fi
fi
have_base() { [ -f /etc/shuttle/setup.d/10-base ]; }
have_docker() { [ "$docker_ok" = yes ] && docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -qx active; }
have_postgres() { command -v psql >/dev/null 2>&1 && systemctl is-active --quiet postgresql; }
have_runtime() { id deploy >/dev/null 2>&1 && [ -x /usr/local/libexec/shuttle-root ] && [ -f /etc/shuttle/trusted-root-operations.pem ]; }
have_edge() { [ "$docker_ok" = yes ] && docker service ls --format '{{.Name}}' 2>/dev/null | grep -qx shuttle-edge_caddy; }
for probe in 10-base:have_base 20-docker:have_docker 30-postgres:have_postgres 40-runtime:have_runtime 50-caddy-direct:have_edge; do
  step=${probe%%:*}
  check=${probe#*:}
  if "$check"; then
    printf 'satisfied=%s\n' "$step"
  else
    printf 'pending=%s\n' "$step"
  fi
done
` + adoptionPrerequisiteSurveySource

// Swarm task containers do not carry the standalone owner label. Their stack
// namespace is Shuttle-owned when its current application state directory
// exists; an unrelated namespace stays visible as foreign.
const adoptionContainerClassificationSource = `classify_adoption_container() {
  name=$1
  owner=$2
  service=$3
  namespace=$4
  state_root=$5
  case "$owner:$service:$namespace" in
    system:*:*|*:shuttle-edge_*:*|*:*:shuttle-edge) printf 'shuttle-container=%s\n' "$name"; return ;;
  esac
  case "$namespace" in
    ''|*[!a-z0-9-]*) printf 'foreign-container=%s\n' "$name" ;;
    *)
      if [ -d "$state_root/$namespace" ]; then
        printf 'shuttle-container=%s\n' "$name"
      else
        printf 'foreign-container=%s\n' "$name"
      fi
      ;;
  esac
}
`

// runSetupAdoption is the whole --adopt path: verify the host, prove the
// privilege, survey, print the plan, and — only when the operator asked for it
// and the host is in a state where converging is not a surprise — apply.
func runSetupAdoption(out io.Writer, cfg *config.Config, identity setupIdentity, options setupOptions, started time.Time) error {
	if err := requireSetupAdministrator(identity, options); err != nil {
		return err
	}
	app := cfg.App
	if !adoptionAppNamePattern.MatchString(app) {
		return fmt.Errorf("--adopt needs the application name from config.json; %q is not one", app)
	}
	if !options.dryRun && !options.yes {
		return errAdoptionNeedsConfirmation
	}
	client, err := shuttlessh.NewClientExactWithFingerprint(identity.host, identity.user, identity.port, options.expectedHostKey)
	if err != nil {
		return err
	}
	if err := proveAdoptionPrivilege(client, identity); err != nil {
		return err
	}
	if err := preflightSetupOperator(setupRunner{client: client, sudo: identity.user != "root"}, options.operator); err != nil {
		return err
	}
	if err := preflightSetupRetainedUsers(setupRunner{client: client, sudo: identity.user != "root"}, options.retained); err != nil {
		return err
	}
	survey, err := adoptionPreflight(client, adoptionSurveyIdentity(identity, options), app, options.unmanaged, cfg.Retention.Backups)
	if err != nil {
		return err
	}
	// Resolved before the plan is printed, so a dry run shows the refusal an
	// applying run would hit instead of promising a cutover it cannot perform.
	edge := resolveAdoptionEdgePlan(identity, survey, options, cfg, !options.dryRun)
	fmt.Fprint(out, adoptionPlan(identity, app, options.expectedHostKey, survey, options, edge, cfg.AllowedPublicTCPPorts(), !options.dryRun, cfg.Retention.Backups))
	if options.operator != nil {
		fmt.Fprintf(out, "Administrator: configure %s with distinct key %s and NOPASSWD root access; prove before and after SSH hardening.\n", options.operator.user, options.operator.fingerprint)
	}
	fmt.Fprint(out, setupAccessSummary(identity, adoptionPreservedSSHUsers(identity, options)))
	fmt.Fprint(out, setupRetainedUsersSummary(identity, options.retained))
	if err := completeAdoptionPreflight(out, survey, edge, options.dryRun); err != nil {
		return err
	}
	if options.dryRun {
		return nil
	}
	warnAdoptionOnPendingReboot(out, identity, survey, options)
	if err := infrastructureSecurityCheck(cfg, true); err != nil {
		return err
	}
	return applyAdoption(out, cfg, identity, options, survey, edge, client, started)
}

// A dry run is a preflight too: a refused edge must not be reported as
// verified merely because no mutation was requested.
func completeAdoptionPreflight(out io.Writer, survey adoptionSurvey, edge adoptionEdgePlan, dryRun bool) error {
	if err := adoptionPrerequisiteError(survey); err != nil {
		return err
	}
	if edge.ReconvergeRefusal != nil {
		return edge.ReconvergeRefusal
	}
	if edge.Refusal != nil {
		return edge.Refusal
	}
	if dryRun {
		fmt.Fprintln(out, "Adoption preflight verified; no remote state was changed.")
	}
	return nil
}

// When the declared administrator is also the first-contact user, attest that
// user's own key in the survey. --public-key still identifies the separate
// deploy key installed and used in signed plans; conflating the two made a
// correctly separated ops/deploy configuration impossible to adopt through ops.
func adoptionSurveyIdentity(identity setupIdentity, options setupOptions) setupIdentity {
	if options.operator != nil && options.operator.user == identity.user {
		identity.operatorKeyFingerprint = options.operator.fingerprint
	}
	return identity
}

// warnAdoptionOnPendingReboot reports a reboot the host's own packages are
// waiting for, without stopping the adoption.
//
// The marker used to refuse the run. On the production host it had been
// present for weeks (a kernel update from unattended-upgrades), and the refusal
// blocked an unrelated edge change the operator needed that night: the guard
// protected nothing, since an adoption never reboots unless --allow-reboot is
// given, and every stage is checkpointed. The operator decided on 2026-10-12
// that a pending reboot is an alert, not a gate. The run goes on without
// rebooting, and the warning names the flag that would take the reboot.
func warnAdoptionOnPendingReboot(out io.Writer, identity setupIdentity, survey adoptionSurvey, options setupOptions) {
	if !survey.RebootRequired || options.allowReboot {
		return
	}
	fmt.Fprintf(out, "WARNING: %s has /var/run/reboot-required: its packages (often a kernel) wait for a reboot. This run does not reboot it; reboot in a maintenance window or pass --allow-reboot to let a run take it.\n", adoptionEndpoint(identity))
}

// applyAdoption converges the host.
//
// Every stage is the one a fresh setup runs, guarded by the same checkpoint, so
// a run interrupted anywhere resumes from where it stopped. The order of what
// follows them is not incidental:
//
//   - when an existing shared edge will be re-converged, a live HTTPS probe
//     comes before any host write. An edge already down is a refusal, not a
//     reason to claim the host, install stages or persist its trusted identity;
//   - the adoption proof and the trusted identity file come next, so a host
//     that failed to converge is never recorded as one Shuttle set up, and a
//     hardening that fails still leaves the operator with a usable identity;
//   - the 80/443 cutover comes next, while the first-contact account still has
//     a privileged channel. It uploads the edge's assets and runs Docker as
//     root; under --lock-out-first-contact-user the hardening below is exactly
//     what takes that channel away, so doing it afterwards could not work;
//   - the SSH hardening comes last, because it is the step that closes doors,
//     and because a cutover that failed has already handed the ports back and
//     wants the run to stop rather than continue locking the host down.
func applyAdoption(out io.Writer, cfg *config.Config, identity setupIdentity, options setupOptions, survey adoptionSurvey, edge adoptionEdgePlan, client *shuttlessh.Client, started time.Time) error {
	if edge.Refusal != nil {
		return edge.Refusal
	}
	runner := setupRunner{client: client, sudo: identity.user != "root"}
	// Claiming the host is already a mutation, so safety must precede it too.
	stages := adoptionSetupStages(cfg, identity.port, survey)
	if err := runSetupStages(runner, out, stages[:1]); err != nil {
		return err
	}
	if edge.reconverges() {
		result := runner.run(setupCaddyDomainPrecheckCommand(edge.ProbeHosts))
		if result.Code != 0 {
			return fmt.Errorf("refusing edge re-convergence before applying adoption host stages: %s", strings.TrimSpace(result.Stderr))
		}
		servingHosts, err := parseCaddyDomainPrecheckOutput(result.Stdout, edge.ProbeHosts)
		if err != nil {
			return fmt.Errorf("refusing edge re-convergence before applying adoption host stages: %w", err)
		}
		// Keep the early successful set as the baseline. Rebuilding it after
		// host stages could silently drop a site that stopped answering there.
		edge.ProbeHosts = servingHosts
	}
	helperPath, err := resolveLinuxHelper(options.helperBinary)
	if err != nil {
		return err
	}
	privateKeyPath, publicTrustPath, err := ensureRootOperationKeyPair()
	if err != nil {
		return err
	}
	publicTrust, err := os.ReadFile(publicTrustPath)
	if err != nil {
		return err
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		return err
	}
	if result := runner.run(adoptionClaimSource); result.Code != 0 {
		return fmt.Errorf("claim %s for Shuttle before converging it: %s", adoptionEndpoint(identity), strings.TrimSpace(result.Stderr))
	}
	for _, upload := range []struct {
		body string
		path string
		mode os.FileMode
	}{
		{identity.operatorKey + "\n", "/tmp/shuttle-operator.pub", 0o600},
		{string(publicTrust), "/tmp/shuttle-root-trust.pem", 0o600},
		{string(helper), "/tmp/shuttle-root", 0o700},
	} {
		if result := client.UploadContent(upload.body, upload.path, upload.mode); result.Code != 0 {
			return fmt.Errorf("upload %s: %s", upload.path, strings.TrimSpace(result.Stderr))
		}
	}
	if options.operator != nil {
		if result := client.UploadContent(options.operator.publicKey+"\n", "/tmp/shuttle-emergency-operator.pub", 0o600); result.Code != 0 {
			return fmt.Errorf("upload administrator key: %s", result.Stderr)
		}
	}
	if err := runSetupStages(runner, out, stages[1:]); err != nil {
		return err
	}
	if options.allowReboot {
		if err := completePendingSetupReboot(runner, out, cfg.App, identity.operatorKeyFingerprint, options.expectedHostKey); err != nil {
			return err
		}
	}
	if result := runner.run(setupAdoptionProofCommand(identity.port, cfg.AllowedPublicTCPPorts())); result.Code != 0 {
		return fmt.Errorf("adopted host proof failed: %s", strings.TrimSpace(result.Stderr))
	}
	// Persisted only once the host has proven it carries the deploy user, the
	// signed root helper and its trust root: this file is what every later
	// command treats as "Shuttle set this machine up".
	allowedSSHUsers := sortedUnique(append([]string{"deploy"}, adoptionSignedSSHUsers(identity, options)...))
	if err := saveTrustedHostIdentity(trustedHostIdentity{Version: 2, Host: identity.host, Port: identity.port, HostKeyFingerprint: options.expectedHostKey, OperatorKeyFingerprint: identity.operatorKeyFingerprint, AllowedSSHUsers: allowedSSHUsers}); err != nil {
		return fmt.Errorf("persist verified VPS identity after adoption: %w", err)
	}
	if edge.applies() {
		if err := cutoverAdoptedHostEdge(out, cfg, edge, runner); err != nil {
			return err
		}
	}
	if edge.reconverges() {
		fmt.Fprintf(out, "  -> 50-caddy-direct (re-converging the shared edge: %s)\n", strings.Join(edge.Reconverge, "; "))
		// The program alone may wait 120 s for the Swarm update and 150 s for a
		// rollback recovery, on top of the image pull, the ownership snapshot
		// and the probes; the default 2 minute SSH deadline would cut a slow
		// rollback and lose its verified result (DEV-DEPL-81 review, round 5).
		runner.client.SetOperationTimeout(edgeReconvergeSSHTimeout)
		if err := deploySharedCaddyWithVolumePreparation(runner, cfg, setupCaddyReconvergeCommand(caddyImage(cfg.Caddy), edge.ProbeHosts), caddyVolumePreparationWithOwnerSnapshot(cfg.Caddy)); err != nil {
			return fmt.Errorf("re-converge the shared edge: %w", err)
		}
	}
	if err := hardenAdoptedHostSSH(out, identity, options, runner, privateKeyPath); err != nil {
		return err
	}
	fmt.Fprint(out, setupAccessSummary(identity, adoptionPreservedSSHUsers(identity, options)))
	fmt.Fprint(out, setupRetainedUsersSummary(identity, options.retained))
	fmt.Fprintf(out, "Adopted %s in %s.\n", adoptionEndpoint(identity), time.Since(started).Round(time.Second))
	fmt.Fprint(out, adoptionRemainingWork(runner, edge, survey.LegacyMarker == "present"))
	reportSetupSLO(measureSetupSLO(cfg.Setup.SLOSeconds, time.Since(started)))
	return nil
}

// cutoverAdoptedHostEdge hands 80/443 to the shared edge.
//
// The assets and the checkpoint are the fresh path's; only the program differs,
// because on this host the ports are taken. Everything that makes the switch
// survivable lives in that program — pre-pulling before stopping, stopping only
// the container named here, restoring it when the edge does not come up — so
// that the decisions run on the host, where a dropped SSH session cannot leave
// them half-made.
func cutoverAdoptedHostEdge(out io.Writer, cfg *config.Config, edge adoptionEdgePlan, runner setupRunner) error {
	if edge.Incumbent == "" {
		fmt.Fprintln(out, "  -> 50-caddy-direct (nothing holds 80/443)")
	} else {
		fmt.Fprintf(out, "  -> 50-caddy-direct (stopping %s, then taking 80/443)\n", edge.Incumbent)
	}
	if err := deploySharedCaddy(runner, cfg, caddyCheckpointReconcile(cfg.Caddy.Email)+setupCaddyCutoverCommand(edge.Incumbent, caddyImage(cfg.Caddy))); err != nil {
		if edge.Incumbent == "" {
			return err
		}
		return fmt.Errorf("%w; %s was restarted so it holds 80/443 again — re-run with --cutover-edge once the cause is fixed", err, edge.Incumbent)
	}
	return nil
}

// deployLeastPrivilegeProofSource is the gate both a fresh setup and an
// adoption put in front of the SSH hardening: deploy can log in, is not root,
// and is in neither sudo nor docker. One string, so the two paths cannot come
// to hold each other to different standards.
const deployLeastPrivilegeProofSource = `test "$(id -u)" -ne 0 && test "$(id -un)" = deploy && ! id -nG | tr ' ' '\n' | grep -Eq '^(sudo|docker)$'`

// hardenAdoptedHostSSH runs the signed SSH hardening transaction on a host that
// is already carrying production.
//
// It is what makes an adopted host deployable: applyRootBaseline is the only
// writer of /etc/sudoers.d/90-shuttle-root, the rule that lets deploy invoke the
// signed root helper, and the baseline operation is its only caller.
//
// Where the pre-signed rollback travels, and why it is not deploy from the
// start. A fresh setup sends it through deploy, which is correct there: by the
// time it hardens, root SSH is the thing being closed and deploy is the account
// that remains. That channel does not exist yet on an adopted host — the
// sudoers rule deploy would need is created by the very operation that may
// fail, so `sudo -n` would be refused by sudo itself and the rollback would
// report a failure that never reached the helper. The first-contact account is
// privileged and proven: adoptionSudoProofSource established non-interactive
// root before anything was read, let alone mutated. Recovery therefore starts
// there and moves to deploy the instant the baseline has applied — which is
// both when deploy becomes privileged and, under
// --lock-out-first-contact-user, when the first-contact account stops being
// able to open a new session at all.
func hardenAdoptedHostSSH(out io.Writer, identity setupIdentity, options setupOptions, runner setupRunner, privateKeyPath string) error {
	if err := requireSetupAdministrator(identity, options); err != nil {
		return err
	}
	if err := proveAdoptionAdministrators(identity, options); err != nil {
		return fmt.Errorf("refusing SSH hardening: %w", err)
	}
	privateKey, err := rootplan.ReadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	envelopes, err := prepareBaselineEnvelopes(identity, options.expectedHostKey, privateKey, time.Now(), adoptionSignedSSHUsers(identity, options))
	if err != nil {
		return err
	}
	// Nothing is closed before the account that must survive is proven to work.
	deployClient, err := shuttlessh.NewClientExactWithFingerprint(identity.host, "deploy", identity.port, options.expectedHostKey)
	if err != nil {
		return fmt.Errorf("refusing to harden SSH on %s: deploy SSH proof failed: %w", adoptionEndpoint(identity), err)
	}
	if proof := deployClient.Run(deployLeastPrivilegeProofSource); proof.Code != 0 {
		return fmt.Errorf("refusing to harden SSH on %s: deploy least-privilege proof failed: %s", adoptionEndpoint(identity), strings.TrimSpace(proof.Stderr))
	}
	fmt.Fprintln(out, "  -> ssh baseline (signed, "+describeAdoptionAllowUsers(identity, options)+")")

	recovery := runner
	rollback := func(cause error) error {
		result := recovery.applySigned(envelopes.rollback)
		if result.Code != 0 {
			return fmt.Errorf("%w; CRITICAL: automatic SSH rollback failed: %s", cause, strings.TrimSpace(result.Stderr))
		}
		return fmt.Errorf("%w; the previous SSH configuration was restored automatically", cause)
	}
	if result := runner.applySigned(envelopes.baseline); result.Code != 0 {
		return rollback(fmt.Errorf("signed SSH hardening failed: %s", strings.TrimSpace(result.Stderr)))
	}
	// Same race as the proof below: this is the first connection after the
	// reload, and a socket-activated sshd has a moment with no listener. A
	// single refused dial here would roll back a hardening that applied
	// correctly.
	deployClient, err = dialAfterSSHDReload(identity, options, "deploy")
	if err != nil {
		return rollback(fmt.Errorf("post-hardening deploy SSH proof failed: %w", err))
	}
	recovery = setupRunner{client: deployClient, sudo: true}
	if err := proveAdoptionUserSurvivedHardening(identity, options); err != nil {
		return rollback(err)
	}
	if result := recovery.applySigned(envelopes.audit); result.Code != 0 {
		return rollback(fmt.Errorf("post-hardening signed audit failed: %s", strings.TrimSpace(result.Stderr)))
	}
	if result := recovery.applySigned(envelopes.commit); result.Code != 0 {
		return rollback(fmt.Errorf("commit signed SSH hardening failed: %s", strings.TrimSpace(result.Stderr)))
	}
	return nil
}

// proveAdoptionUserSurvivedHardening opens a new session as each administrator
// the baseline promised to keep, including a newly configured replacement.
//
// A new one, not the session already open: sshd's reload never drops
// established connections, so the channel this run is holding would keep
// working for an AllowUsers list that excludes it, and the operator would only
// discover the lockout after hanging up. Retry across sshd's reload window;
// every retained administrator must still have non-interactive root sudo.
func proveAdoptionUserSurvivedHardening(identity setupIdentity, options setupOptions) error {
	for _, user := range adoptionPreservedSSHUsers(identity, options) {
		administrator := identity
		administrator.user = user
		deadline := time.Now().Add(adoptionLoginProofBudget)
		for {
			err := attemptAdoptionUserLogin(administrator, options)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("post-hardening administrator %s SSH/sudo proof failed: %w", user, err)
			}
			time.Sleep(adoptionLoginProofPoll)
		}
	}
	return nil
}

func proveAdoptionAdministrators(identity setupIdentity, options setupOptions) error {
	for _, user := range adoptionPreservedSSHUsers(identity, options) {
		administrator := identity
		administrator.user = user
		if err := attemptAdoptionUserLogin(administrator, options); err != nil {
			return fmt.Errorf("administrator %s SSH/sudo proof failed: %w", user, err)
		}
	}
	return nil
}

// adoptionLoginProofBudget bounds the retry. Past it the account really cannot
// log in, and that is the lockout this proof exists to catch.
const adoptionLoginProofBudget = 30 * time.Second

const adoptionLoginProofPoll = time.Second

// dialAfterSSHDReload connects to an account, tolerating the window in which
// the reloaded sshd is not yet listening. It is not a retry on failure in
// general: past the budget the account genuinely cannot log in.
func dialAfterSSHDReload(identity setupIdentity, options setupOptions, user string) (*shuttlessh.Client, error) {
	deadline := time.Now().Add(adoptionLoginProofBudget)
	for {
		client, err := shuttlessh.NewClientExactWithFingerprint(identity.host, user, identity.port, options.expectedHostKey)
		if err == nil {
			return client, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(adoptionLoginProofPoll)
	}
}

func attemptAdoptionUserLogin(identity setupIdentity, options setupOptions) error {
	client, err := dialAfterSSHDReload(identity, options, identity.user)
	if err != nil {
		return err
	}
	if result := client.Run("test \"$(id -un)\" = " + shell.Escape(identity.user) + " && test \"$(sudo -n id -u)\" = 0"); result.Code != 0 {
		return errors.New(strings.TrimSpace(result.Stderr))
	}
	return nil
}

// adoptionPreservedSSHUsers lists the administrators the signed AllowUsers
// list keeps beyond deploy, combining the retained login and the declared one.
//
// root is never added: PermitRootLogin no is part of the same baseline and wins
// regardless, so signing it in would describe an access the host does not
// grant. deploy is never added either — it is in the list by construction, and
// naming it twice is a duplicate the plan validator rightly refuses.
func adoptionPreservedSSHUsers(identity setupIdentity, options setupOptions) []string {
	users := []string{}
	if !options.lockOutFirstContactUser && identity.user != "root" && identity.user != "deploy" {
		users = append(users, identity.user)
	}
	if options.operator != nil {
		users = append(users, options.operator.user)
	}
	return sortedUnique(users)
}

// describeAdoptionAllowUsers spells the list that will be signed, derived the
// same way the plan derives it, so the sentence an operator reads and the
// directive the host receives cannot say different things.
func describeAdoptionAllowUsers(identity setupIdentity, options setupOptions) string {
	users := sortedUnique(append([]string{"deploy"}, adoptionSignedSSHUsers(identity, options)...))
	return "AllowUsers " + strings.Join(users, " ")
}

// describeAdoptionSSHBaseline is the plan's one line about what hardening does
// to the account the operator is connected as.
func describeAdoptionSSHBaseline(identity setupIdentity, options setupOptions) string {
	directive := describeAdoptionAllowUsers(identity, options)
	switch {
	case identity.user == "root":
		return "root, password and keyboard-interactive logins are closed; signs " + directive + ", and root — the account this run arrived on — is closed with them"
	case options.lockOutFirstContactUser && options.operator != nil:
		return "root, password and keyboard-interactive logins are closed; signs " + directive + ", so " + identity.user + " loses SSH access and " + options.operator.user + " retains administration"
	case options.lockOutFirstContactUser:
		return "root, password and keyboard-interactive logins are closed; signs " + directive + " alone, so " + identity.user + " loses SSH access to this host (--lock-out-first-contact-user)"
	default:
		return "root, password and keyboard-interactive logins are closed; signs " + directive + ", so " + identity.user + " keeps the access this run is using (--lock-out-first-contact-user drops it)"
	}
}

// adoptionRemainingWork restates the boundary after the fact, and adds the one
// thing only the finished host can report: whether the packages this run
// installed have themselves asked for a reboot. Saying so is the point — the
// alternative is a host that quietly needs one and an operator who is not told.
func adoptionRemainingWork(runner setupRunner, edge adoptionEdgePlan, legacy bool) string {
	return describeAdoptionRemainingWork(edge, legacy, runner.run("test -e /var/run/reboot-required").Code == 0)
}

// describeAdoptionRemainingWork is the text of that report, with the one fact
// only the host can supply passed in. It is separate so the report is testable
// as text, which is what it is.
func describeAdoptionRemainingWork(edge adoptionEdgePlan, legacy bool, rebootPending bool) string {
	var b strings.Builder
	if edge.applies() && edge.Incumbent != "" {
		fmt.Fprintf(&b, "80/443 now belong to the shared edge; %s is stopped, not removed, and set to restart: no — reverting means stopping shuttle-edge first, then `docker update --restart %s %s` and `docker start %s`\n", edge.Incumbent, edge.IncumbentRestart, edge.Incumbent, edge.Incumbent)
	}
	remaining := adoptionDeferredWork(edge, legacy)
	if len(remaining) == 0 && !rebootPending {
		b.WriteString("Host is already converged.\n")
		return b.String()
	}
	b.WriteString("still to do, deliberately not part of this run\n")
	for _, item := range remaining {
		fmt.Fprintf(&b, "    - %s\n", item)
	}
	if rebootPending {
		b.WriteString("    - a reboot is pending on this host and was not taken; schedule it, then reboot out of band or re-run with --allow-reboot\n")
	}
	return b.String()
}

// proveAdoptionPrivilege refuses to continue unless the adoption user is
// already root or can become root with no password and no TTY.
func proveAdoptionPrivilege(client *shuttlessh.Client, identity setupIdentity) error {
	if identity.user == "root" {
		if result := client.Run(adoptionRootProofSource); result.Code != 0 {
			return fmt.Errorf("--adopt could not confirm root on %s: %s", adoptionEndpoint(identity), strings.TrimSpace(result.Stderr))
		}
		return nil
	}
	return interpretAdoptionSudoProof(client.Run(adoptionSudoProofSource), identity)
}

// interpretAdoptionSudoProof turns the sudo proof's exit code into the error an
// operator reads. On a host Shuttle never installed this is the first thing
// they meet, so the refusal carries the one line that resolves it rather than
// the name of a concept.
func interpretAdoptionSudoProof(result shuttlessh.Result, identity setupIdentity) error {
	if result.Code == adoptionExitNoPasswordlessSudo {
		return fmt.Errorf("--adopt requires non-interactive sudo for %s: `sudo -n true` failed. Grant %s a NOPASSWD sudoers rule first — as root on the host: printf '%%s\\n' %s >/etc/sudoers.d/90-%s && chmod 0440 /etc/sudoers.d/90-%s — or adopt with a user that already has one", adoptionEndpoint(identity), identity.user, shell.Escape(identity.user+" ALL=(ALL:ALL) NOPASSWD: ALL"), identity.user, identity.user)
	}
	if result.Code != 0 {
		return fmt.Errorf("--adopt could not prove non-interactive root for %s: %s", adoptionEndpoint(identity), strings.TrimSpace(result.Stderr))
	}
	return nil
}

// adoptionPreflight runs the read-only survey and turns its typed exit codes
// into errors that name exactly what is missing.
func adoptionPreflight(client *shuttlessh.Client, identity setupIdentity, app string, unmanaged bool, backups int) (adoptionSurvey, error) {
	command := adoptionSurveyCommand(identity.user, identity.operatorKeyFingerprint, app, unmanaged)
	result := client.RunWithStdin(command, []byte(adoptionSurveySource+adoptionOwnedFilesSurvey(backups)))
	return interpretAdoptionSurvey(result, identity, app)
}

// adoptionSurveyCommand builds the remote command line. The script itself
// travels on standard input and is never concatenated with its arguments. The
// last argument is whether --unmanaged was given, as a literal 0 or 1: the
// survey reads it to decide whether a host with no marker is refused.
func adoptionSurveyCommand(user string, fingerprint string, app string, unmanaged bool) string {
	claim := "0"
	if unmanaged {
		claim = "1"
	}
	arguments := "sh -s -- " + shell.Escape(user) + " " + shell.Escape(fingerprint) + " " + shell.Escape(app) + " " + claim
	if user == "root" {
		return arguments
	}
	return "sudo -n " + arguments
}

func interpretAdoptionSurvey(result shuttlessh.Result, identity setupIdentity, app string) (adoptionSurvey, error) {
	switch result.Code {
	case adoptionExitUnsupportedOS:
		return adoptionSurvey{}, fmt.Errorf("unsupported VPS OS: %s", strings.Join(strings.Fields(result.Stdout), " "))
	case adoptionExitLegacyMarkerAbsent:
		return adoptionSurvey{}, fmt.Errorf("refusing to adopt %s: /opt/shuttle/%s/state.json is absent, so this host holds no previous-generation Shuttle deployment of %q. Adoption converges a host Shuttle already installed; it never claims an unrelated machine", adoptionEndpoint(identity), app, app)
	case adoptionExitKeyNotAuthorized:
		return adoptionSurvey{}, fmt.Errorf("refusing to adopt %s: the declared first-contact key fingerprint %s is not authorized for %s (checked that user's ~/.ssh/authorized_keys on the host)", adoptionEndpoint(identity), identity.operatorKeyFingerprint, identity.user)
	case 0:
		return parseAdoptionSurvey(result.Stdout)
	default:
		return adoptionSurvey{}, fmt.Errorf("verified adoption survey failed on %s: %s", adoptionEndpoint(identity), strings.TrimSpace(result.Stderr))
	}
}

// parseAdoptionSurvey reads the key=value report. An unknown key or an
// out-of-charset value is an error: the CLI and the survey disagreeing about
// the protocol must stop the run, not produce a plan that omits a line.
func parseAdoptionSurvey(body string) (adoptionSurvey, error) {
	survey := adoptionSurvey{}
	effectiveConfigSeen := false
	for _, line := range strings.Split(body, "\n") {
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		value = strings.TrimRight(value, " ")
		if !found || (key != "postgres-listen" && key != "published-bind" && key != "edge-container-spec" && key != "edge-effective-config" && !adoptionSurveyValuePattern.MatchString(value)) {
			return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable line %q", line)
		}
		switch key {
		case "os":
			survey.OS = value
		case "os-version":
			survey.OSVersion = value
		case "setup-state":
			survey.SetupState = value
		case "legacy-marker":
			switch value {
			case "present", "absent":
				survey.LegacyMarker = value
			default:
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable legacy marker state %q", value)
			}
		case "live-restore":
			switch value {
			case "true", "false", "unknown":
				survey.LiveRestore = value
			default:
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable live-restore state %q", value)
			}
		case "published-port":
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable published port %q", value)
			}
			survey.PublishedPorts = append(survey.PublishedPorts, port)
		case "published-bind":
			// The bind is strictly parsed below, so it skips the generic value
			// pattern, which has no room for "[::]:80".
			host, portText, err := net.SplitHostPort(value)
			address := net.ParseIP(host)
			if err != nil || address == nil {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable published bind %q", value)
			}
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable published port %q", portText)
			}
			// On 2026-10-28 the production-host dry run listed Shuttle's registry,
			// bound to 127.0.0.1:5000, as a port 40-runtime would close, and
			// advised declaring it public: following that would have opened
			// the registry in UFW. A loopback bind is not reachable from
			// outside, so it is not a published port.
			if address.IsLoopback() {
				continue
			}
			survey.PublishedPorts = append(survey.PublishedPorts, port)
		case "incumbent-restart":
			// "<container> <policy>"; a container with no policy set reports
			// an empty name, which the trailing-space trim above reduces to
			// the container alone, and Docker's own default for it is "no".
			name, policy, _ := strings.Cut(value, " ")
			if policy == "" {
				policy = "no"
			}
			if survey.ContainerRestart == nil {
				survey.ContainerRestart = map[string]string{}
			}
			survey.ContainerRestart[name] = policy
		case "incumbent-service":
			name, service, found := strings.Cut(value, " ")
			if !found || name == "" || service == "" || strings.Contains(service, " ") {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable container service %q", value)
			}
			if survey.ContainerService == nil {
				survey.ContainerService = map[string]string{}
			}
			survey.ContainerService[name] = service
		case "reboot-required":
			// Only the survey's own two words are accepted: a value this build
			// does not understand must not be read as "no reboot pending".
			switch value {
			case "present":
				survey.RebootRequired = true
			case "absent":
				survey.RebootRequired = false
			default:
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable reboot state %q", value)
			}
		case "legacy-app":
			survey.LegacyApps = append(survey.LegacyApps, value)
		case "foreign-container":
			survey.ForeignContainers = append(survey.ForeignContainers, value)
		case "shuttle-container":
			survey.ShuttleContainers = append(survey.ShuttleContainers, value)
		case "swarm-service":
			survey.SwarmServices = append(survey.SwarmServices, value)
		case "service-port":
			parts := strings.Fields(value)
			if len(parts) != 2 || (parts[0] != "80" && parts[0] != "443") {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unusable service port %q", value)
			}
			survey.ServicePorts = append(survey.ServicePorts, parts[1])
		case "port-held":
			survey.PortsHeld = append(survey.PortsHeld, value)
		case "edge-container-spec":
			if survey.Edge != nil {
				return adoptionSurvey{}, errors.New("adoption survey reported edge-container-spec more than once")
			}
			edge, err := parseObservedEdgeSpec(value)
			if err != nil {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported an invalid edge container spec: %w", err)
			}
			survey.Edge = &edge
		case "edge-effective-config":
			if effectiveConfigSeen {
				return adoptionSurvey{}, errors.New("adoption survey reported edge-effective-config more than once")
			}
			effectiveConfigSeen = true
			adapted, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported invalid adapted Caddy configuration: %w", err)
			}
			hosts, err := caddyEffectiveSiteHosts(adapted)
			if err != nil {
				return adoptionSurvey{}, fmt.Errorf("adoption survey reported invalid adapted Caddy configuration: %w", err)
			}
			survey.EdgeSiteHosts = append(survey.EdgeSiteHosts, hosts...)
		case "gateway":
			survey.Gateway = value
		case "gateway-subnet":
			survey.GatewaySubnet = value
		case "gateway-mtu":
			survey.GatewayMTU = value
		case "docker-checkpoint":
			survey.DockerCheckpoint = value
		case "edge-network":
			survey.EdgeNetwork = value
		case "postgres-listen":
			survey.PostgresListen = value
		case "postgres-retention":
			survey.PostgresRetention = value
		case "postgres-cluster":
			survey.PostgresCluster = value
		case "registry":
			switch value {
			case "present", "absent":
				survey.RegistryState = value
			default:
				return adoptionSurvey{}, fmt.Errorf("invalid registry survey state %q", value)
			}
		case "prerequisite-issue":
			survey.PrerequisiteIssues = append(survey.PrerequisiteIssues, value)
		case "satisfied":
			survey.Satisfied = append(survey.Satisfied, value)
		case "pending":
			survey.Pending = append(survey.Pending, value)
		default:
			return adoptionSurvey{}, fmt.Errorf("adoption survey reported an unrecognised key %q", key)
		}
	}
	for _, list := range []*[]string{
		&survey.EdgeSiteHosts, &survey.LegacyApps, &survey.ForeignContainers, &survey.ShuttleContainers,
		&survey.SwarmServices, &survey.ServicePorts, &survey.PortsHeld, &survey.Satisfied, &survey.Pending,
	} {
		*list = sortedUnique(*list)
	}
	slices.Sort(survey.PublishedPorts)
	survey.PublishedPorts = slices.Compact(survey.PublishedPorts)
	return survey, nil
}

// observedEdgeSpec is the part of a running Swarm task spec adoption needs to
// compare and protect before it replaces the shared edge.
type observedEdgeSpec struct {
	Image          string
	User           string
	ReadOnly       bool
	CapabilityAdd  []string
	CapabilityDrop []string
	EnvNames       []string
	SecretTargets  []string
	MountTargets   []string
	Mounts         []observedEdgeMount
}

type observedEdgeMount struct {
	Type   string
	Source string
	Target string
}

func parseObservedEdgeSpec(raw string) (observedEdgeSpec, error) {
	var decoded struct {
		Image          string   `json:"Image"`
		User           string   `json:"User"`
		ReadOnly       bool     `json:"ReadOnly"`
		CapabilityAdd  []string `json:"CapabilityAdd"`
		CapabilityDrop []string `json:"CapabilityDrop"`
		Env            []string `json:"Env"`
		Secrets        []struct {
			File struct {
				Name string `json:"Name"`
			} `json:"File"`
		} `json:"Secrets"`
		Mounts []struct {
			Type   string `json:"Type"`
			Source string `json:"Source"`
			Target string `json:"Target"`
		} `json:"Mounts"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return observedEdgeSpec{}, err
	}
	observed := observedEdgeSpec{
		Image:          decoded.Image,
		User:           decoded.User,
		ReadOnly:       decoded.ReadOnly,
		CapabilityAdd:  sortedUnique(decoded.CapabilityAdd),
		CapabilityDrop: sortedUnique(decoded.CapabilityDrop),
	}
	for _, env := range decoded.Env {
		name, _, _ := strings.Cut(env, "=")
		observed.EnvNames = append(observed.EnvNames, name)
	}
	for _, secret := range decoded.Secrets {
		observed.SecretTargets = append(observed.SecretTargets, secret.File.Name)
	}
	for _, mount := range decoded.Mounts {
		observed.MountTargets = append(observed.MountTargets, mount.Target)
		observed.Mounts = append(observed.Mounts, observedEdgeMount{Type: mount.Type, Source: mount.Source, Target: mount.Target})
	}
	observed.EnvNames = sortedUnique(observed.EnvNames)
	observed.SecretTargets = sortedUnique(observed.SecretTargets)
	observed.MountTargets = sortedUnique(observed.MountTargets)
	sort.Slice(observed.Mounts, func(i, j int) bool {
		if observed.Mounts[i].Target != observed.Mounts[j].Target {
			return observed.Mounts[i].Target < observed.Mounts[j].Target
		}
		if observed.Mounts[i].Type != observed.Mounts[j].Type {
			return observed.Mounts[i].Type < observed.Mounts[j].Type
		}
		return observed.Mounts[i].Source < observed.Mounts[j].Source
	})
	return observed, nil
}

func edgeSpecDrift(observed observedEdgeSpec, wantImage string) []string {
	var drift []string
	if observed.User != "10001:10001" {
		drift = append(drift, fmt.Sprintf("runs as root (user %q, want 10001:10001)", observed.User))
	}
	if !observed.ReadOnly {
		drift = append(drift, "root filesystem is writable (want read_only)")
	}
	if len(observed.CapabilityDrop) != 1 || observed.CapabilityDrop[0] != "ALL" || len(observed.CapabilityAdd) != 1 || !sameLinuxCapability(observed.CapabilityAdd[0], "NET_BIND_SERVICE") {
		drift = append(drift, "capabilities are not dropped (want cap_drop ALL, cap_add NET_BIND_SERVICE)")
	}
	if legacyDigestOnlyCaddy(observed.Image) {
		drift = append(drift, fmt.Sprintf("image %s is the legacy digest-only form", printableEdgeValue(observed.Image)))
	}
	if wantImage != "" && observed.Image != wantImage {
		drift = append(drift, fmt.Sprintf("image %s differs from %s", printableEdgeValue(observed.Image), printableEdgeValue(wantImage)))
	}
	return drift
}

func edgeReconvergeRefusal(observed observedEdgeSpec, caddy config.Caddy) error {
	declaredEnv := make(map[string]bool, len(caddy.Env))
	for name := range caddy.Env {
		declaredEnv[name] = true
	}
	declaredSecrets := make(map[string]bool, len(caddy.SecretEnv))
	for _, target := range caddy.SecretEnv {
		declaredSecrets[target] = true
	}
	declaredMounts := map[string]bool{
		"/etc/caddy/conf.d": true,
		"/data":             true,
		"/config":           true,
	}
	for _, mount := range caddy.Mounts {
		declaredMounts[mount.Target] = true
	}
	var undeclared []string
	for _, name := range observed.EnvNames {
		if !declaredEnv[name] {
			undeclared = append(undeclared, "environment variables "+printableEdgeValue(name))
		}
	}
	for _, target := range observed.SecretTargets {
		if !declaredSecrets[target] {
			undeclared = append(undeclared, "secret targets "+printableEdgeValue(target))
		}
	}
	for _, target := range observed.MountTargets {
		if !declaredMounts[target] {
			undeclared = append(undeclared, "mount targets "+printableEdgeValue(target))
		}
	}
	dataVolume, externalData := caddyDataVolume(caddy)
	if !externalData {
		dataVolume = "shuttle-edge_" + dataVolume
	}
	for _, target := range []struct {
		path string
		want string
	}{
		{path: "/data", want: dataVolume},
		{path: "/config", want: "shuttle-edge_shuttle_caddy_config"},
	} {
		var matches []observedEdgeMount
		for _, mount := range observed.Mounts {
			if mount.Target == target.path {
				matches = append(matches, mount)
			}
		}
		if len(matches) != 1 || matches[0].Type != "volume" || matches[0].Source != target.want {
			actual := "missing or ambiguous"
			if len(matches) == 1 {
				actual = matches[0].Type + ":" + matches[0].Source
			}
			undeclared = append(undeclared, fmt.Sprintf("mount sources %s=%s (want volume %s)", target.path, printableEdgeValue(actual), printableEdgeValue(target.want)))
		}
	}
	if len(undeclared) == 0 {
		return nil
	}
	return fmt.Errorf("not re-converged: the running edge carries %s that this configuration does not declare; re-run setup --adopt from the configuration that declares them", strings.Join(undeclared, "; "))
}

func printableEdgeValue(value string) string {
	var b strings.Builder
	for _, character := range value {
		if unicode.IsControl(character) {
			fmt.Fprintf(&b, "\\u%04x", character)
			continue
		}
		b.WriteRune(character)
	}
	return b.String()
}

var edgeHTTPSProbeHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func edgeHTTPSProbeHosts(siteHosts []string) ([]string, error) {
	var hosts []string
	for _, address := range siteHosts {
		address = strings.ToLower(strings.TrimSpace(address))
		if address == "" || strings.HasPrefix(address, "http://") {
			continue
		}
		if strings.HasPrefix(address, "https://") {
			parsed, err := url.Parse(address)
			if err != nil || parsed.Hostname() == "" || (parsed.Port() != "" && parsed.Port() != "443") || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
				return nil, fmt.Errorf("cannot verify HTTPS coverage for Caddy site address %q", printableEdgeValue(address))
			}
			address = parsed.Hostname()
		} else if strings.Contains(address, ":") {
			host, port, err := net.SplitHostPort(address)
			if err == nil {
				if port == "80" {
					continue
				}
				if port != "443" {
					return nil, fmt.Errorf("cannot verify HTTPS coverage for Caddy site address %q on port %s", printableEdgeValue(address), port)
				}
				address = host
			} else if strings.HasPrefix(address, ":") {
				continue
			}
		}
		address = strings.TrimSuffix(address, ".")
		if net.ParseIP(address) != nil || strings.Contains(address, "*") || !edgeHTTPSProbeHostPattern.MatchString(address) {
			return nil, fmt.Errorf("cannot verify HTTPS coverage for Caddy site host %q", printableEdgeValue(address))
		}
		hosts = append(hosts, address)
	}
	return sortedUnique(hosts), nil
}

func parseCaddyDomainPrecheckOutput(output string, probeHosts []string) ([]string, error) {
	expected := make(map[string]struct{}, len(probeHosts))
	for _, host := range sortedUnique(probeHosts) {
		expected[host] = struct{}{}
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, errors.New("live HTTPS precheck returned no serving domains")
	}
	seen := make(map[string]struct{}, len(expected))
	var hosts []string
	for _, line := range strings.Split(output, "\n") {
		key, host, ok := strings.Cut(line, "=")
		if !ok || key != "serving-host" || host == "" {
			return nil, errors.New("live HTTPS precheck returned an invalid serving-domain set")
		}
		if _, ok := expected[host]; !ok {
			return nil, errors.New("live HTTPS precheck returned an unexpected serving domain")
		}
		if _, ok := seen[host]; ok {
			return nil, errors.New("live HTTPS precheck returned a duplicate serving domain")
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return nil, errors.New("live HTTPS precheck returned no serving domains")
	}
	return sortedUnique(hosts), nil
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	unique := values[:1]
	for _, value := range values[1:] {
		if value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	return unique
}

// adoptionPortHolderPattern reads one `port-held=` value back into its two
// parts. The survey only ever reports 80 and 443, and the pattern says so: a
// line about any other port means this build and the survey disagree about the
// protocol, which must stop a cutover rather than narrow it.
var adoptionPortHolderPattern = regexp.MustCompile(`^(80|443)(?:/(?:tcp|udp))? by (published container|process) (.+)$`)

// adoptionEdgePlan is the decision about 80 and 443: whether this run takes
// them, from what, and why it must not.
type adoptionEdgePlan struct {
	// Requested is --cutover-edge. Without it nothing about the incumbent is
	// touched, which is the default because the switch is an outage.
	Requested bool
	// Incumbent is the single container that holds 80/443 today, or "" when
	// nothing does. It is the only container this run may stop.
	Incumbent string
	// IncumbentRestart is that container's restart policy as surveyed. The
	// cutover sets it to `no` after the stop and puts this value back if the
	// edge fails; the plan names it so "stopped" is not read as "gone".
	IncumbentRestart string
	// AlreadyServing means Shuttle's Caddy task is already holding both public
	// ports. There is no incumbent to take over, even if --cutover-edge was set.
	AlreadyServing bool
	// Refusal is why the requested cutover must not happen. It is carried
	// rather than returned so a dry run prints it too.
	Refusal           error
	Reconverge        []string
	ReconvergeRefusal error
	ProbeHosts        []string
}

func (p adoptionEdgePlan) applies() bool {
	return p.Requested && !p.AlreadyServing && p.Refusal == nil
}

func (p adoptionEdgePlan) reconverges() bool {
	return p.AlreadyServing && len(p.Reconverge) > 0 && p.ReconvergeRefusal == nil
}

// resolveAdoptionEdgePlan decides the cutover from the survey the host already
// produced, and refuses every case where a failed switch could not hand the
// ports back.
//
// Refusals protect against choosing or failing to restore the incumbent.
// More than one container holding those ports means Shuttle would have to pick which service stops, and picking is
// precisely what it must not do. A holder that is a process rather than a
// container means there is no `docker start` to restore it with, so the outage
// would not be reversible — and a listener this run cannot name is a listener
// it must not stop.
func resolveAdoptionEdgePlan(identity setupIdentity, survey adoptionSurvey, options setupOptions, cfg *config.Config, apply bool) adoptionEdgePlan {
	plan := adoptionEdgePlan{Requested: options.cutoverEdge}
	if options.cutoverEdge {
		for _, service := range survey.ServicePorts {
			if service != "shuttle-edge_caddy" {
				plan.Refusal = fmt.Errorf("refusing to hand 80/443 to the shared edge on %s: Swarm service %s publishes an edge port. Remove or scale that service yourself, then re-run with --cutover-edge", adoptionEndpoint(identity), service)
				return plan
			}
		}
	}
	if adoptionSharedEdgeAlreadyServing(survey) {
		plan.AlreadyServing = true
		if survey.Edge != nil {
			wantImage := ""
			var caddy config.Caddy
			if cfg != nil {
				caddy = cfg.Caddy
				if apply {
					wantImage = caddyImage(cfg.Caddy)
				}
			}
			plan.Reconverge = edgeSpecDrift(*survey.Edge, wantImage)
			probeHosts, probeErr := edgeHTTPSProbeHosts(survey.EdgeSiteHosts)
			plan.ProbeHosts = probeHosts
			if len(plan.Reconverge) > 0 {
				switch {
				case probeErr != nil:
					plan.ReconvergeRefusal = fmt.Errorf("refusing edge re-convergence: %w", probeErr)
				case len(probeHosts) == 0:
					plan.ReconvergeRefusal = errors.New("refusing edge re-convergence: the effective Caddy configuration has no verifiable HTTPS domain")
				default:
					plan.ReconvergeRefusal = edgeReconvergeRefusal(*survey.Edge, caddy)
				}
			}
		}
		return plan
	}
	if !options.cutoverEdge {
		return plan
	}
	containers, processes, err := adoptionPublicPortHolders(survey)
	if err != nil {
		plan.Refusal = err
		return plan
	}
	// Swarm replaces a stopped task, so the old container cannot retain the
	// ports or restore service after a failed edge deployment.
	for _, container := range containers {
		if service := survey.ContainerService[container]; service != "" && service != "shuttle-edge_caddy" {
			plan.Refusal = fmt.Errorf("refusing to hand 80/443 to the shared edge on %s: container %s belongs to Swarm service %s. Remove or scale that service yourself, then re-run with --cutover-edge", adoptionEndpoint(identity), container, service)
			return plan
		}
	}
	switch {
	case len(containers) > 1:
		plan.Refusal = fmt.Errorf("refusing to hand 80/443 to the shared edge on %s: they are held by more than one container (%s), and choosing which one stops serving is not Shuttle's decision. Stop the ones that must not hold those ports, then re-run with --cutover-edge", adoptionEndpoint(identity), strings.Join(containers, ", "))
	case len(containers) == 1:
		plan.Incumbent = containers[0]
		plan.IncumbentRestart = survey.ContainerRestart[plan.Incumbent]
		if plan.IncumbentRestart == "" {
			plan.IncumbentRestart = "no"
		}
	case len(processes) > 0:
		plan.Refusal = fmt.Errorf("refusing to hand 80/443 to the shared edge on %s: they are held by %s, which is not a container this run can stop and start again, so a cutover that failed could not give the ports back. Stop that listener yourself and re-run with --cutover-edge", adoptionEndpoint(identity), strings.Join(processes, ", "))
	}
	return plan
}

// A running service alone is not proof that the shared edge owns the ports.
// Require its task containers to hold both ports and reject any second holder,
// so the plan never hides an actual incumbent behind a healthy service name.
func adoptionSharedEdgeAlreadyServing(survey adoptionSurvey) bool {
	if !slices.Contains(survey.SwarmServices, "shuttle-edge_caddy") {
		return false
	}
	edgePorts := map[string]bool{}
	publishedPorts := map[string]bool{}
	var proxyPorts []string
	for _, held := range survey.PortsHeld {
		match := adoptionPortHolderPattern.FindStringSubmatch(held)
		if match == nil {
			return false
		}
		port, kind, name := match[1], match[2], match[3]
		if kind == "published container" {
			publishedPorts[port] = true
			if strings.HasPrefix(name, "shuttle-edge_caddy.") {
				edgePorts[port] = true
				continue
			}
			return false
		}
		if name != "docker-proxy" {
			return false
		}
		proxyPorts = append(proxyPorts, port)
	}
	for _, port := range proxyPorts {
		if !publishedPorts[port] {
			return false
		}
	}
	return edgePorts["80"] && edgePorts["443"]
}

// adoptionPublicPortHolders splits what the survey saw on 80/443 into the
// containers this run could stop and restore, and everything else.
//
// A value this build cannot parse is an error, not an empty result: reading a
// line the survey meant as "nginx is listening" as "nothing is listening" is
// how a cutover walks into an outage it was told about. shuttle-edge_caddy
// tasks are skipped because they are this stack's own, and re-deploying the stack over
// them is the ordinary idempotent path rather than a cutover.
//
// A `docker-proxy` process on a port that a published container also holds is
// that container's own port publication, not a second listener. Reading it as a
// foreign process refused, on 2026-10-12, to update a host whose only holder
// was this stack's shuttle-edge_caddy: the survey reported "443 by published
// container shuttle-edge_caddy.1..." next to "443/tcp by process
// docker-proxy", and the cutover stopped on the proxy.
func adoptionPublicPortHolders(survey adoptionSurvey) (containers []string, processes []string, err error) {
	type holder struct{ port, kind, name string }
	var holders []holder
	published := map[string]bool{}
	for _, held := range survey.PortsHeld {
		match := adoptionPortHolderPattern.FindStringSubmatch(held)
		if match == nil {
			return nil, nil, fmt.Errorf("refusing to hand 80/443 to the shared edge: the adoption survey reported a holder this build cannot read (%q)", held)
		}
		holders = append(holders, holder{match[1], match[2], match[3]})
		if match[2] == "published container" {
			published[match[1]] = true
		}
	}
	for _, h := range holders {
		if h.kind != "published container" {
			if h.name == "docker-proxy" && published[h.port] {
				continue
			}
			processes = append(processes, h.name)
			continue
		}
		if strings.HasPrefix(h.name, "shuttle-edge_caddy.") {
			continue
		}
		containers = append(containers, h.name)
	}
	return sortedUnique(containers), sortedUnique(processes), nil
}

// describeAdoptionEdgePlan is the plan's one line about the ports, including
// the refusal, so `--dry-run --cutover-edge` reports what an applying run would
// refuse instead of leaving it to be discovered.
func describeAdoptionEdgePlan(plan adoptionEdgePlan) string {
	switch {
	case plan.AlreadyServing:
		return "already served by Shuttle's Caddy on 80/443; no takeover is needed"
	case plan.Refusal != nil:
		return "refused — " + plan.Refusal.Error()
	case !plan.Requested:
		return "not scheduled; whatever holds 80/443 keeps them (--cutover-edge hands them to the shared edge, which is a brief outage)"
	case plan.Incumbent == "":
		return "requested; nothing holds 80/443, so the shared edge is deployed without stopping anything"
	default:
		return fmt.Sprintf("requested; the edge image is pulled first, %s (restart policy %s) is stopped and set to restart: no so a later dockerd restart cannot hand it 80/443 back, and %s is started again with its policy restored if the edge does not reach 1/1 and validate its configuration; until the first `shuttle deploy`, the edge serves no site on those ports", plan.Incumbent, plan.IncumbentRestart, plan.Incumbent)
	}
}

func describeAdoptionEdgeSpec(plan adoptionEdgePlan) string {
	switch {
	case plan.ReconvergeRefusal != nil:
		return plan.ReconvergeRefusal.Error()
	case len(plan.Reconverge) > 0:
		return "re-converged: " + strings.Join(plan.Reconverge, "; ") + "; a brief 80/443 outage (stop-first update), certificates kept, rolled back if a site that answers HTTPS now stops answering"
	case plan.AlreadyServing:
		return "matches this release (image re-checked against the latest Caddy 2 when applied)"
	default:
		return "not checked (the shared edge is not already serving 80/443)"
	}
}

// adoptionClosedPorts are the host ports containers publish today that
// 40-runtime will stop answering: `ufw --force reset` keeps only the SSH port
// and access.allowed_public_tcp_ports. Named in the plan so an operator
// declares the ones the host still needs instead of discovering them closed.
func adoptionClosedPorts(survey adoptionSurvey, sshPort int, publicPorts []int) []string {
	kept := map[int]bool{sshPort: true}
	for _, port := range publicPorts {
		kept[port] = true
	}
	closed := make([]string, 0, len(survey.PublishedPorts))
	for _, port := range survey.PublishedPorts {
		if !kept[port] {
			closed = append(closed, strconv.Itoa(port))
		}
	}
	return closed
}

// describeAdoptionApplication is the plan's verdict on what this run is: a
// convergence of a host a previous generation installed, a resumption of a
// claim this generation already started, or a claim of a host Shuttle never
// touched. It is read from the survey, never from the flag.
func describeAdoptionApplication(app string, survey adoptionSurvey) string {
	switch {
	case survey.LegacyMarker == "present":
		return fmt.Sprintf("%s (marker /opt/shuttle/%s/state.json found)", app, app)
	case survey.LegacyMarker == "":
		// Not defaulted to either verdict: a survey that said nothing about
		// the marker is not a survey that found it absent.
		return fmt.Sprintf("%s (legacy marker state not reported by the survey)", app)
	case survey.SetupState == "present":
		return fmt.Sprintf("%s (no /opt/shuttle/%s/state.json; this generation already claimed the host, resuming)", app, app)
	default:
		return fmt.Sprintf("%s (never set up by Shuttle: no /opt/shuttle/%s/state.json; --unmanaged claims it)", app, app)
	}
}

// describeAdoptionLiveRestore is the plan's line about dockerd's live-restore,
// including the one consequence an operator must hear before --yes: nothing
// restarts during this run, and everything restarts on the next dockerd
// restart or reboot once the setting is off.
func describeAdoptionLiveRestore(survey adoptionSurvey) string {
	switch survey.LiveRestore {
	case "true":
		if slices.Contains(survey.Satisfied, "20-docker") {
			return "enabled; adoption refuses because existing Docker configuration is preserved"
		}
		return "enabled; 20-docker turns it off in /etc/docker/daemon.json (other keys kept, previous file saved beside it) and reloads dockerd — no container restarts now; afterwards a dockerd restart or the deferred reboot restarts every container per its restart policy"
	case "false":
		return "off, as Swarm requires"
	default:
		return "unknown (Docker is not running or not installed)"
	}
}

// adoptionPlan is the operator-facing product of this command: what is on the
// host, what adoption would skip, what it would still have to do, and what it
// will not do at all.
func adoptionPlan(identity setupIdentity, app string, hostFingerprint string, survey adoptionSurvey, options setupOptions, edge adoptionEdgePlan, publicPorts []int, apply bool, retentionValues ...int) string {
	privilege := "already root"
	if identity.user != "root" {
		privilege = "non-interactive sudo proven"
	}
	reboot := "none"
	if survey.RebootRequired {
		reboot = "yes, /var/run/reboot-required is present; warning only, adoption does not reboot without --allow-reboot"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Shuttle adoption plan for %s\n", adoptionEndpoint(identity))
	fmt.Fprintf(&b, "  application       %s\n", describeAdoptionApplication(app, survey))
	fmt.Fprintf(&b, "  host              %s %s, attested by %s\n", survey.OS, survey.OSVersion, hostFingerprint)
	fmt.Fprintf(&b, "  first contact     %s, %s\n", identity.user, privilege)
	fmt.Fprintf(&b, "  pending reboot    %s\n", reboot)
	fmt.Fprintf(&b, "  ssh baseline      %s\n", describeAdoptionSSHBaseline(identity, options))
	fmt.Fprintf(&b, "  edge cutover      %s\n", describeAdoptionEdgePlan(edge))
	fmt.Fprintf(&b, "  edge spec         %s\n", describeAdoptionEdgeSpec(edge))
	fmt.Fprintf(&b, "  live-restore      %s\n", describeAdoptionLiveRestore(survey))
	fmt.Fprintf(&b, "  current-generation setup state: %s\n", survey.SetupState)
	retention := 7
	if len(retentionValues) > 0 && retentionValues[0] != 0 {
		retention = retentionValues[0]
	}
	currentRetention := survey.PostgresRetention
	if currentRetention == "" {
		currentRetention = "not reported"
	}
	fmt.Fprintf(&b, "  PostgreSQL backup retention: %s -> %d backups\n", currentRetention, retention)
	b.WriteString("  PostgreSQL access from the Docker gateway subnet is not proven by adoption; the first deploy can prove it only when the application healthcheck tests PostgreSQL\n")
	b.WriteString("  The healthcheck must test PostgreSQL; otherwise database access remains unproven even if deployment succeeds\n")
	if _, _, err := net.ParseCIDR(survey.GatewaySubnet); err == nil {
		fmt.Fprintf(&b, "  PostgreSQL HBA example: host all all %s scram-sha-256 (check rule order and reload PostgreSQL if changed)\n", survey.GatewaySubnet)
	} else {
		b.WriteString("  PostgreSQL HBA example: host all all <Docker gateway subnet> scram-sha-256 (determine the subnet, check rule order and reload PostgreSQL if changed)\n")
	}
	b.WriteString("found on the host\n")
	writeAdoptionList(&b, "previous-generation Shuttle applications", survey.LegacyApps)
	writeAdoptionList(&b, "foreign containers", survey.ForeignContainers)
	writeAdoptionList(&b, "Shuttle-owned containers", survey.ShuttleContainers)
	writeAdoptionList(&b, "Swarm services", survey.SwarmServices)
	writeAdoptionList(&b, "public ports already held", survey.PortsHeld)
	writeAdoptionList(&b, "ports published today that 40-runtime closes (declare them in access.allowed_public_tcp_ports to keep them)", adoptionClosedPorts(survey, identity.port, publicPorts))
	b.WriteString("convergence\n")
	writeAdoptionList(&b, "steps observed satisfied by the survey", describeAdoptionSteps(survey.Satisfied))
	pending := survey.Pending
	if edge.applies() || edge.reconverges() {
		pending = slices.DeleteFunc(slices.Clone(pending), func(id string) bool { return id == "50-caddy-direct" })
	}
	writeAdoptionList(&b, "steps this host still needs", describeAdoptionSteps(pending))
	writeAdoptionList(&b, "stages this run applies, in order", adoptionAppliedStages(survey, edge, options.operator != nil))
	deferred := adoptionDeferredWork(edge, survey.LegacyMarker == "present")
	b.WriteString("  on a host in service, 10-base installs the baseline packages only: apt-get dist-upgrade is not run\n")
	if slices.Contains(survey.Pending, "30-postgres") {
		b.WriteString("  30-postgres installs a PostgreSQL server on this host whether or not the application uses one; there is no opt-out yet\n")
	}
	b.WriteString("  after the stages, the signed SSH hardening transaction runs: it is what grants deploy the sudoers rule for the root helper\n")
	if len(deferred) > 0 {
		b.WriteString("not attempted by this run\n")
		for _, item := range deferred {
			fmt.Fprintf(&b, "    - %s\n", item)
		}
	}
	if !apply {
		b.WriteString("  dry run: the adoption survey is read-only; no remote change is attempted\n")
	}
	return b.String()
}

// adoptionAppliedStages names the stages in execution order. Satisfaction of
// Docker and PostgreSQL skips their bodies; the other probes do not establish
// checkpoint state. The independently converged registry and PostgreSQL files
// remain visible even when those bodies are skipped.
func adoptionAppliedStages(survey adoptionSurvey, edge adoptionEdgePlan, operators ...bool) []string {
	satisfied := make(map[string]bool, len(survey.Satisfied))
	for _, id := range survey.Satisfied {
		satisfied[id] = true
	}
	stages := []string{"helper-safety (verify safe root helper replacement)"}
	for _, step := range adoptionSteps {
		if !step.AlwaysApplied && !(step.ID == "50-caddy-direct" && (edge.applies() || edge.reconverges())) {
			continue
		}
		if step.ID == "50-caddy-direct" && edge.reconverges() {
			stages = append(stages, "50-caddy-direct (re-converge the shared edge to this release's spec)")
			continue
		}
		note := ""
		if satisfied[step.ID] {
			if step.ID == "20-docker" || step.ID == "30-postgres" {
				note = ", already satisfied so adoption skips its body"
			} else if step.ID == "10-base" {
				note = ", already satisfied so its checkpoint skips it"
			} else {
				note = ", observed present; its checkpoint determines whether it runs"
			}
		}
		stages = append(stages, fmt.Sprintf("%s (%s)%s", step.ID, step.Label, note))
		if step.ID == "40-runtime" && len(operators) > 0 && operators[0] {
			stages = append(stages, "operator (configure the administrator account)")
		}
		if step.ID == "20-docker" {
			if adoptionNeedsCaddyNetwork(survey) {
				stages = append(stages, "20-caddy-network (create the missing overlay for an interrupted Shuttle setup)")
			}
			registry := "21-registry-nonroot (converge the loopback registry)"
			if survey.RegistryState == "absent" {
				if satisfied["20-docker"] {
					registry += ", absent in the survey; create it"
				} else {
					registry += ", absent in the survey; 20-docker creates it first"
				}
			}
			stages = append(stages, registry)
		}
		if step.ID == "30-postgres" && satisfied[step.ID] {
			stages = append(stages, "31-postgres-backup-script (install Shuttle backup script and retention)", "31-postgres-backup-timer (install and enable Shuttle backup service and timer)", "32-postgres-boot-order (install Docker ordering drop-in; takes effect at the next PostgreSQL or host restart, without restarting PostgreSQL now)")
		} else if step.ID == "30-postgres" {
			stages = append(stages, "31-postgres-backup (converge backup policy and retention)", "32-postgres-boot-order (install Docker ordering drop-in)")
		}
	}
	return stages
}

func writeAdoptionList(b *strings.Builder, title string, values []string) {
	fmt.Fprintf(b, "  %s:\n", title)
	if len(values) == 0 {
		b.WriteString("    - none\n")
		return
	}
	for _, value := range values {
		fmt.Fprintf(b, "    - %s\n", value)
	}
}

// describeAdoptionSteps annotates the checkpoint identifiers the survey
// reported. An identifier this build does not know is printed as-is rather than
// dropped: an unexplained line is recoverable, a silently omitted one is not.
func describeAdoptionSteps(ids []string) []string {
	described := make([]string, 0, len(ids))
	for _, id := range ids {
		label := ""
		for _, step := range adoptionSteps {
			if step.ID == id {
				label = step.Label
				break
			}
		}
		if label == "" {
			described = append(described, id)
			continue
		}
		described = append(described, fmt.Sprintf("%s (%s)", id, label))
	}
	return described
}

func adoptionEndpoint(identity setupIdentity) string {
	return fmt.Sprintf("%s@%s:%d", identity.user, identity.host, identity.port)
}

// Docker stores capabilities with the CAP_ prefix (docker stack deploy turns
// NET_BIND_SERVICE into CAP_NET_BIND_SERVICE), so both spellings are the same.
func sameLinuxCapability(observed, want string) bool {
	normalize := func(value string) string {
		return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(value)), "CAP_")
	}
	return normalize(observed) == normalize(want)
}
