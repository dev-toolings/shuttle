//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	"gopkg.in/yaml.v3"
)

const (
	rootBackupStaging                = "/var/lib/shuttle/backup-staging"
	rootRecoveryMaxMarkerBytes       = 128 << 10
	rootRecoveryApplySchema          = "shuttle.recovery-apply/v1"
	rootRecoveryFirstRemovalSchema   = "shuttle.first-release-removal/v1"
	rootRecoveryFirstRemovalMaxBytes = 8 << 10
	rootRecoveryBootIDPath           = "/proc/sys/kernel/random/boot_id"
	rootRecoveryPostgresRoot         = "/etc/postgresql"
	rootRecoveryCaddyDir             = "/opt/shuttle/caddy/conf.d"

	serviceStateFirstReleaseNoServices = "no application services exist, as in the closed first-release baseline"

	registryStateHealthy     = "existing registry is healthy on loopback"
	registryStateStopped     = "existing loopback registry is stopped"
	registryStateMissing     = "registry does not exist"
	registryStateRecreatable = "missing registry has a journaled replacement and matching volume"
	registryStateUnsafe      = "registry identity is not the retained loopback service"
	registryStateUnhealthy   = "existing loopback registry is not healthy"
	registryStateWrongImage  = "registry image is not the retained pinned image"
	registryStateUnreadable  = "registry configuration is unreadable"
	serviceStateMatch        = "configured application tasks match retained current digests and container health"
	serviceStateMismatch     = "configured application tasks do not match retained current digests"
	serviceStateNotObserved  = "not observed"
	routeStateMatch          = "loaded Caddy route matches the selected retained manifest"
	routeStateMismatch       = "loaded Caddy route does not match the selected retained manifest"
	routeStateNotRequired    = "no Caddy route is required"
	routeStateNotObserved    = "not observed"
	dataStateMatch           = "configured native PostgreSQL version and cluster match the closed baseline"
	dataStateMissing         = "configured native PostgreSQL version and cluster are not present on the host"
	dataStateUnconfigured    = "native PostgreSQL is not configured in the closed baseline"
	dataStateNotApplicable   = "native PostgreSQL is not applicable"
	dataStateNotObserved     = "not observed"
	postgresNotConfigured    = "not-configured"
	absentBaselineArtifact   = "authorized baseline artifact is absent after rotation; ROOT B must persist baseline bytes before slot replacement"
)

// rootRecoveryWriterReadFunc is the ROOT B wiring contract. Production recovery
// reads closed writer state only through this function. A nil value is an
// explicit missing proof, never a license to assume generation, revision, or
// closure from the operation record.
type rootRecoveryWriterReadFunc func(context.Context, coord.Record) (operationwriters.State, error)

// rootRecoveryWriterReader is bound by ROOT B at integration. This reconciler
// never installs a default that fabricates closed proof.
var rootRecoveryWriterReader rootRecoveryWriterReadFunc = readCoordinatedRootWriterState

type pendingBackupMarker struct {
	App         string         `json:"app"`
	OperationID string         `json:"operation_id"`
	Replicas    map[string]int `json:"replicas"`
	Work        string         `json:"work"`
}

type firstReleaseRemovalJournal struct {
	Schema                      string `json:"schema"`
	OperationID                 string `json:"operation_id"`
	App                         string `json:"app"`
	ManifestSHA256              string `json:"manifest_sha256"`
	RouteReloadPending          bool   `json:"route_reload_pending"`
	CurrentDirectorySyncPending bool   `json:"current_directory_sync_pending"`
}

type recoveryActionKind string

const (
	recoveryActionRestoreBackupReplicas    recoveryActionKind = "restore-backup-replicas"
	recoveryActionRestartRegistry          recoveryActionKind = "restart-loopback-registry"
	recoveryActionRecreateRegistry         recoveryActionKind = "recreate-loopback-registry"
	recoveryActionReapplyCurrent           recoveryActionKind = "reapply-retained-current"
	recoveryActionRemoveFirstRelease       recoveryActionKind = "remove-unconverged-first-release"
	recoveryActionApplyCaddyRoute          recoveryActionKind = "apply-caddy-route"
	recoveryActionRecordKeptInfrastructure recoveryActionKind = "record-kept-infrastructure"
	recoveryActionSyncCurrentDirectory     recoveryActionKind = "sync-current-directory"
	recoveryActionReplaceRunTasks          recoveryActionKind = "replace-run-tasks"
	recoveryActionCompleteDestroy          recoveryActionKind = "complete-destroy"
)

type recoveryAction struct {
	DestroyPostgres *postgresRemoval   `json:"destroy_postgres,omitempty"`
	DestroyBackups  map[string]string  `json:"destroy_backups,omitempty"`
	Kind            recoveryActionKind `json:"kind"`
	App             string             `json:"app,omitempty"`
	ManifestPath    string             `json:"manifest_path,omitempty"`
	ManifestSHA256  string             `json:"manifest_sha256,omitempty"`
	MarkerPath      string             `json:"marker_path,omitempty"`
	MarkerProof     string             `json:"marker_proof,omitempty"`
	Replicas        map[string]int     `json:"replicas,omitempty"`
	Service         string             `json:"service,omitempty"`
	Container       string             `json:"container,omitempty"`
	// KeepInfrastructureImages binds deploy-only substitutions into ActionProof.
	KeepInfrastructureImages map[string]recoveryInfrastructureImageProof `json:"keep_infrastructure_images,omitempty"`
}

type destroyRemainder struct {
	Services             []string
	Networks             []string
	Containers           []string
	Volumes              []string
	StateDir             bool
	Route                bool
	CleanupJournalSHA256 string
}

type recoveryInfrastructureKeepVersions struct {
	Live     string
	Retained string
}

type recoveryInfrastructureImageProof struct {
	Live     string `json:"live"`
	Retained string `json:"retained"`
}

type recoveryManifestBinding struct {
	Role       string `json:"role"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256,omitempty"`
	Present    bool   `json:"present"`
	Authorized bool   `json:"authorized,omitempty"`
	Selected   bool   `json:"selected,omitempty"`
}

type recoveryApplyReport struct {
	Details           []string                  `json:"details,omitempty"`
	Schema            string                    `json:"schema"`
	ID                string                    `json:"id"`
	State             string                    `json:"state"`
	Observed          coord.RecoveryObservation `json:"observed"`
	Actions           []string                  `json:"actions"`
	PlanDigest        string                    `json:"plan_digest"`
	CompletedSteps    []string                  `json:"completed_steps"`
	Error             string                    `json:"error,omitempty"`
	RemainingRecovery []string                  `json:"remaining_recovery"`
}

type recoveryPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type recoveryRegistryInspect struct {
	State struct {
		Running bool `json:"Running"`
		Health  struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		PortBindings map[string][]recoveryPortBinding `json:"PortBindings"`
	} `json:"HostConfig"`
	Config struct {
		Image  string            `json:"Image"`
		User   string            `json:"User"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Image  string                  `json:"Image"`
	Mounts []recoveryRegistryMount `json:"Mounts"`
}

type recoveryRegistryMount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

type recoveryImageInspect struct {
	RepoDigests []string `json:"RepoDigests"`
}

type recoveryRegistryIdentity struct {
	VolumeSHA256  string
	Image         string
	ImageID       string
	Running       bool
	HealthStatus  string
	RestartPolicy string
	Bindings      []string
}

type recoveryContainerInspect struct {
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
		Health  struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Image string `json:"Image"`
}

type recoveryTaskInspect struct {
	Status struct {
		ContainerStatus struct {
			ContainerID string `json:"ContainerID"`
		} `json:"ContainerStatus"`
	} `json:"Status"`
}

type recoveryTaskIdentity struct {
	ID          string `json:"id"`
	Digest      string `json:"digest"`
	State       string `json:"state"`
	ContainerID string `json:"container_id,omitempty"`
	Health      string `json:"health,omitempty"`
}

type recoveryServiceIdentity struct {
	Service    string                 `json:"service"`
	WantDigest string                 `json:"want_digest"`
	Converged  bool                   `json:"converged"`
	Tasks      []recoveryTaskIdentity `json:"tasks"`
}

var recoveryFirstReleaseRemovalBudget = 2 * time.Minute

// rootRecoveryRuntime is constructed per recovery call so tests inject
// reader, filesystem, docker, clock and executors without racing globals.
type rootRecoveryRuntime struct {
	destroyDetails         bytes.Buffer
	destroyFailure         error
	now                    func() time.Time
	after                  func(time.Duration) <-chan time.Time
	reader                 rootRecoveryWriterReadFunc
	readFile               func(string) ([]byte, error)
	lstat                  func(string) (os.FileInfo, error)
	remove                 func(string) error
	syncDir                func(string) error
	dockerRead             func(context.Context, ...string) (string, error)
	dockerRun              func(context.Context, ...string) error
	waitStack              func(app, stackFile string, deployedAt time.Time, timeout time.Duration) error
	applyCaddy             func(app string, payload []byte, timeout time.Duration) error
	reloadEdge             func() error
	verifyCaddy            func(app string, payload []byte) error
	loadedRoute            func(app string) (string, error)
	readAnchored           func(root, path string, maxBytes int64) ([]byte, error)
	readBaselineArtifact   func(operationID, role string, artifact operationwriters.BaselineArtifact) ([]byte, error)
	preserveBackupReplicas func(operationID, app string, replicas map[string]int) error
	readBackupReplicas     func(operationID string) (map[string]int, error)
	completeDestroy        func(context.Context, string, io.Writer) error
	destroyOutput          io.Writer
	destroyJournalRoot     string
	prepareStack           func(app, path string) (string, error)
	appStateRoot           string
	backupStaging          string
	archiveRoot            string
	bootIDPath             string
	postgresRoot           string
	caddyDir               string
	helperMigrationIntent  string

	planned                             []recoveryAction
	completed                           []string
	remaining                           []string
	keepInfrastructureVersions          map[string]recoveryInfrastructureKeepVersions
	syncedRecoveryCurrentManifestSHA256 string
}

func productionRootRecoveryRuntime() *rootRecoveryRuntime {
	rt := &rootRecoveryRuntime{
		now:                    func() time.Time { return time.Now().UTC() },
		after:                  time.After,
		reader:                 rootRecoveryWriterReader,
		readFile:               os.ReadFile,
		lstat:                  os.Lstat,
		remove:                 os.Remove,
		syncDir:                syncRootRecoveryDir,
		dockerRead:             rootDockerRead,
		dockerRun:              rootRecoveryDockerRun,
		readAnchored:           readAnchoredBoundedFile,
		readBaselineArtifact:   readRootOperationBaselineArtifact,
		preserveBackupReplicas: preserveRootOperationBackupReplicaProof,
		readBackupReplicas:     readRootOperationBackupReplicaProof,
		appStateRoot:           rootAppStateRoot,
		backupStaging:          rootBackupStaging,
		bootIDPath:             rootRecoveryBootIDPath,
		postgresRoot:           rootRecoveryPostgresRoot,
		caddyDir:               rootRecoveryCaddyDir,
		helperMigrationIntent:  helperMigrationIntentPath,
		destroyOutput:          rootLogOnlyWriter{},
		destroyJournalRoot:     filepath.Join(coord.DefaultRoot, "destroy-cleanup"),
		completeDestroy: func(ctx context.Context, app string, out io.Writer) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			operationID, _ := ctx.Value(destroyOperationContextKey{}).(string)
			if operationID == "" {
				return errors.New("destroy recovery operation identity is unavailable")
			}
			return removeRootStack(app, operationID, out)
		},
	}
	rt.waitStack = waitRootStack
	rt.applyCaddy = applyRootCaddyRoute
	rt.reloadEdge = func() error {
		return withRootSharedResources(func() error {
			return reloadSharedCaddy(defaultCaddyReloadTimeout)
		})
	}
	rt.verifyCaddy = rt.verifyRetainedCaddyRoute
	rt.loadedRoute = rt.productionLoadedRoute
	rt.prepareStack = func(app, path string) (string, error) {
		return stackFileWithManagedDatabaseHost(filepath.Join(rt.appStateRoot, app), path)
	}
	return rt
}

func (rt *rootRecoveryRuntime) productionLoadedRoute(app string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listed, err := rt.dockerRead(ctx, "ps", "-q", "--filter", "label=com.docker.swarm.service.name=shuttle-edge_caddy")
	if err != nil {
		return "", err
	}
	id, _, _ := strings.Cut(strings.TrimSpace(listed), "\n")
	if id == "" {
		return "", errors.New("shared Caddy container is not running")
	}
	// Caddy has no `config` CLI subcommand. Validate the active Caddyfile and
	// read its imported route fragments instead. The route applier already
	// reloads Caddy before this proof runs, so a failed reload still fails here.
	body, err := rt.dockerRead(ctx, "exec", id, "sh", "-ec", "caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null && cat /etc/caddy/Caddyfile /etc/caddy/conf.d/*.caddy")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(body), nil
}

func rootRecoveryDockerRun(_ context.Context, args ...string) error {
	return runFixed("/usr/bin/docker", args...)
}

func syncRootRecoveryDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func recoveryRootPlan(ctx context.Context, id string) ([]byte, error) {
	rt := productionRootRecoveryRuntime()
	plan, err := coord.NewDefault().RecoveryPlan(ctx, id, rt.observe)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func recoveryRootApply(ctx context.Context, id, digest string, signedPlan rootplan.Plan) ([]byte, error) {
	rt := productionRootRecoveryRuntime()
	planExpiresAt, err := time.Parse(time.RFC3339, signedPlan.ExpiresAt)
	if err != nil {
		return marshalRecoveryApplyReport(coord.RecoveryPlan{ID: id}, rt.completed, rt.remaining, fmt.Errorf("parse signed recovery expiry: %w", err))
	}
	var plan coord.RecoveryPlan
	var applyErr error
	watchdogErr := withRootOperationWatchdog(func() error {
		plan, applyErr = coord.NewDefault().ApplyRecoveryWithProof(ctx, id, digest, planExpiresAt, signedPlan.RequiredHostFingerprint, func() error {
			return verifyRootOperationIdentity(signedPlan)
		}, rt.observe, rt.apply)
		return applyErr
	})
	if watchdogErr != nil {
		applyErr = watchdogErr
	}
	if applyErr == nil {
		applyErr = rt.destroyFailure
	}
	return marshalRecoveryApplyReport(plan, rt.completed, rt.remaining, applyErr, rt.destroyDetails.String())
}

func rootRecoveryObserver(ctx context.Context, record coord.Record) (coord.RecoveryObservation, error) {
	return productionRootRecoveryRuntime().observe(ctx, record)
}

func rootRecoveryApplier(ctx context.Context, record coord.Record, observation coord.RecoveryObservation) error {
	return productionRootRecoveryRuntime().apply(ctx, record, observation)
}

func marshalRecoveryApplyReport(plan coord.RecoveryPlan, completed, remaining []string, applyErr error, details ...string) ([]byte, error) {
	if completed == nil {
		completed = []string{}
	}
	if remaining == nil {
		if applyErr != nil {
			remaining = append([]string(nil), plan.Actions...)
		} else {
			remaining = []string{}
		}
	}
	report := recoveryApplyReport{
		Schema:            rootRecoveryApplySchema,
		ID:                plan.ID,
		State:             plan.State,
		Observed:          plan.Observed,
		Actions:           append([]string(nil), plan.Actions...),
		PlanDigest:        plan.PlanDigest,
		CompletedSteps:    append([]string(nil), completed...),
		RemainingRecovery: append([]string(nil), remaining...),
	}
	for _, detail := range details {
		for _, line := range strings.Split(strings.TrimSpace(detail), "\n") {
			if line != "" {
				report.Details = append(report.Details, line)
			}
		}
	}
	if applyErr != nil {
		report.Error = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(applyErr.Error(), "\r", " "), "\n", " "))
	}
	if report.Actions == nil {
		report.Actions = []string{}
	}
	body, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), applyErr
}

func (rt *rootRecoveryRuntime) observe(ctx context.Context, record coord.Record) (coord.RecoveryObservation, error) {
	now := rt.clock().UTC()
	observation := coord.RecoveryObservation{
		ObservedAt:    now.Format(time.RFC3339Nano),
		Freshness:     now.Format(time.RFC3339Nano),
		ServiceState:  serviceStateNotObserved,
		RegistryState: "not observed",
		DataState:     dataStateNotObserved,
	}
	rt.planned = nil
	var unresolved []string
	noMutationDeploy := coord.DeployRefusalPhasesValid(record)

	if supported, reason := recoveryKindSupported(record.Kind); !supported {
		unresolved = append(unresolved, reason)
	}

	boot, bootErr := rt.readTrimmed(rt.bootIDPath)
	if bootErr != nil || boot == "" {
		unresolved = append(unresolved, "host boot version unavailable")
	} else {
		observation.BootVersion = boot
	}

	process, processErr := rt.dockerRead(ctx, "version", "--format", "{{.Server.Version}}")
	if processErr != nil || strings.TrimSpace(process) == "" {
		unresolved = append(unresolved, "Docker process version unavailable")
	} else {
		observation.ProcessVersion = strings.TrimSpace(process)
	}

	if len(record.Phases) == 0 {
		observation.PhaseVersion = "none"
	} else {
		phaseBody, _ := json.Marshal(record.Phases)
		observation.PhaseVersion = rootRecoveryDigest(phaseBody)
	}

	state, closedProof, writerUnresolved := rt.readClosedWriterState(ctx, record)
	unresolved = append(unresolved, writerUnresolved...)
	if closedProof != "" {
		observation.ExecutorProof = closedProof
		observation.ExecutorCount = 0
	} else if record.Kind == "helper-update" && len(writerUnresolved) == 0 && helperUpdateRecordIdle(record) {
		// Helper-update never initializes writers. A failed phase before
		// replacement leaves only the journal lease as executor evidence.
		observation.ExecutorProof = helperUpdateRecordExecutorProof(record)
		observation.ExecutorCount = 0
	}

	if record.Kind == "helper-update" {
		if !helperUpdateRecordIdle(record) {
			unresolved = append(unresolved, "helper-update executor is still recorded as active")
		}
		unresolved = append(unresolved, rt.observeHelperMigrationIntent(record)...)
	}
	if record.Kind == "destroy" {
		observation.DataState = "not applicable to destroy"
		var remainder destroyRemainder
		journalRoot := rt.destroyJournalRoot
		if journalRoot == "" {
			journalRoot = coord.DefaultRoot
		}
		journal, journalBody, journalErr := readDestroyCleanupJournalAt(journalRoot, record.ID, record.App)
		if journalErr != nil {
			unresolved = append(unresolved, "destroy cleanup progress cannot be read: "+boundedRecoveryText(journalErr.Error()))
		} else if journal != nil {
			var remainderUnresolved []string
			remainder, remainderUnresolved = rt.observeDestroyRemainder(ctx, record.App)
			unresolved = append(unresolved, remainderUnresolved...)
			remainder.CleanupJournalSHA256 = rootRecoveryDigest(journalBody)
		}
		// The journal is written before the first destroy mutation. A missing
		// journal means no cleanup remains authorized, even if the app is live:
		// reservation alone must never turn recovery into a new destroy.
		proofBody, _ := json.Marshal(remainder)
		observation.ManifestProof = rootRecoveryDigest(proofBody)
		actions := []recoveryAction{}
		if len(unresolved) == 0 && remainder.hasResources() {
			work := postgresRemovalWithConsent(destroyPendingPostgresRemoval(journal), journal.DropDatabases && journal.PostgresBackupFailure == "" && (len(journal.BackupPaths) == 0 || journal.PostgresBackupsComplete))
			paths := planDestroyBackupPaths(journal)

			actions = append(actions, recoveryAction{Kind: recoveryActionCompleteDestroy, App: record.App, DestroyPostgres: &work, DestroyBackups: paths})
			for _, database := range work.Databases {
				observation.Details = append(observation.Details, "drop PostgreSQL database "+database+" after its final dump")
			}
			for _, role := range work.Roles {
				observation.Details = append(observation.Details, "drop PostgreSQL role "+role+" only if no database is kept")
			}
			for _, kept := range work.Kept {
				observation.Details = append(observation.Details, "keep PostgreSQL "+kept.Kind+" "+kept.Name)
			}
			keys := make([]string, 0, len(paths))
			for name := range paths {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			for _, name := range keys {
				observation.Details = append(observation.Details, "PostgreSQL database "+name+" dump target "+paths[name])
			}

		}
		rt.planned = actions
		observation.Actions = recoveryActionDisplays(actions, nil)
		actionProof, proofErr := canonicalActionProof(actions)
		if proofErr != nil {
			unresolved = append(unresolved, "recovery action proof is unavailable")
		} else {
			observation.ActionProof = actionProof
		}
		observation.Unresolved = uniqueNonEmpty(unresolved)
		observation.MissingProof = append([]string(nil), observation.Unresolved...)
		baseline := operationwriters.Baseline{}
		if closedProof != "" {
			baseline = state.Baseline
		}
		observation.ResourceVersion = rootRecoveryDigest(recoveryResourceProof(closedProof, observation, baseline, recoveryRegistryIdentity{}, nil, nil, nil, actionProof, routeStateNotRequired, nil))
		observation.ResourceProof = observation.ResourceVersion
		observation.Safe = len(observation.Unresolved) == 0 && observation.ExecutorCount == 0 && observation.ExecutorProof != ""
		return observation, nil
	}
	runTargetState, runTargetUnresolved := rt.observeRunTarget(ctx, record)
	unresolved = append(unresolved, runTargetUnresolved...)

	baseline := operationwriters.Baseline{}
	firstRelease := false
	if closedProof != "" {
		baseline = state.Baseline
		firstRelease = recoveryFirstRelease(record, baseline)
	}

	marker, markerProof, markerUnresolved := rt.readPendingBackupMarker(record)
	unresolved = append(unresolved, markerUnresolved...)
	observation.MarkerProof = markerProof
	durableReplicas, durableErr := rt.loadDurableBackupReplicas(record.ID)
	if durableErr != nil {
		unresolved = append(unresolved, durableErr.Error())
	}
	if marker != nil {
		observation.PendingBackup = true
		observation.OriginalReplicas = replicaTotal(marker.Replicas)
	} else if len(durableReplicas) > 0 {
		observation.OriginalReplicas = replicaTotal(durableReplicas)
	}

	var registryIdentity recoveryRegistryIdentity
	registryState := "not observed"
	if !noMutationDeploy {
		var registryUnresolved []string
		registryIdentity, registryState, registryUnresolved = rt.observeRegistry(ctx, record.RegistryReplacement)
		if registryState == registryStateMissing && record.RegistryReplacement != nil {
			registryIdentity, registryState, registryUnresolved = rt.observeMissingRegistry(ctx, record)
		}
		unresolved = append(unresolved, registryUnresolved...)
	}
	observation.RegistryState = registryState
	if record.Kind == "run" && registryState != registryStateHealthy {
		unresolved = append(unresolved, "registry health is not proven for run recovery")
	}

	if noMutationDeploy {
		observation.DataState = dataStateNotObserved
	} else if record.Kind == "helper-update" {
		observation.DataState = dataStateNotApplicable
	} else {
		pgState, pgUnresolved := rt.observePostgres(baseline)
		unresolved = append(unresolved, pgUnresolved...)
		observation.DataState = pgState
	}

	var manifestBindings []recoveryManifestBinding
	var serviceIdentities []recoveryServiceIdentity
	var selected recoveryManifestBinding
	var selectedPayload []byte
	var keepInfrastructureImages map[string]recoveryInfrastructureImageProof
	var keepInfrastructureVersions map[string]recoveryInfrastructureKeepVersions
	infrastructureReapplyAllowed := true
	recordKeptInfrastructure := false
	keptInfrastructureRewriteComplete := false
	syncRecoveryCurrentDirectory := false
	routeState := routeStateNotObserved
	if noMutationDeploy {
		observation.ManifestProof = rootRecoveryDigest([]byte(`{"manifests":[]}`))
		routeState = routeStateNotRequired
	} else if record.Kind != "helper-update" && record.App != "" {
		bindings, chosen, payload, currentDigest, previousDigest, manifestProof, serviceState, identities, route, keepImages, keepVersions, reapplyAllowed, manifestUnresolved := rt.observeApplication(ctx, record, baseline, firstRelease)
		manifestBindings = bindings
		selected = chosen
		selectedPayload = payload
		keepInfrastructureImages = keepImages
		keepInfrastructureVersions = keepVersions
		infrastructureReapplyAllowed = reapplyAllowed
		keptInfrastructureRewriteComplete = len(keepInfrastructureImages) == 0
		serviceIdentities = identities
		observation.CurrentDigest = currentDigest
		observation.PreviousDigest = previousDigest
		observation.ManifestProof = manifestProof
		observation.ServiceState = serviceState
		routeState = route
		unresolved = append(unresolved, manifestUnresolved...)
		if record.Kind == "deploy" && len(keepInfrastructureImages) > 0 {
			var rewriteUnresolved []string
			recordKeptInfrastructure, rewriteUnresolved = rt.observeKeptInfrastructureRewrite(record, selected, currentDigest, keepInfrastructureImages)
			unresolved = append(unresolved, rewriteUnresolved...)
			keptInfrastructureRewriteComplete = !recordKeptInfrastructure && len(rewriteUnresolved) == 0
		}
		syncRecoveryCurrentDirectory = record.Kind == "deploy" &&
			record.State == coord.RecoveryRequired && record.RecoveryRequired &&
			record.RecoveryCurrentManifestSHA256 != "" && sameDigest(currentDigest, record.RecoveryCurrentManifestSHA256) &&
			selected.Selected && selected.Path != "" && sameDigest(selected.SHA256, currentDigest) &&
			keptInfrastructureRewriteComplete && infrastructureReapplyAllowed &&
			!sameDigest(rt.syncedRecoveryCurrentManifestSHA256, record.RecoveryCurrentManifestSHA256)
		if record.Kind == "run" && runTargetState == "running" && (!selected.Selected || selected.SHA256 == "") {
			unresolved = append(unresolved, "run recovery cannot bind the selected retained service manifest")
		}
		// A run released because its journaled container ended must still
		// prove the service is whole. A forced task replacement can stop the
		// container and then fail its own verification; the next recovery
		// sees the container gone and, without this, released the operation
		// with missing or unhealthy replicas. The proof is the same converged
		// service identity the other kinds require.
		if record.Kind == "run" && (runTargetState == "gone" || runTargetState == "stopped") && serviceState != serviceStateMatch {
			unresolved = append(unresolved, "run service tasks are not proven healthy after the journaled container ended")
		}
	} else {
		observation.ManifestProof = rootRecoveryDigest([]byte(`{"manifests":[]}`))
		routeState = routeStateNotRequired
	}

	var firstRemovalJournal *firstReleaseRemovalJournal
	firstRemovalJournalReadable := true
	if firstRelease {
		journal, journalErr := rt.readFirstReleaseRemovalJournal(record)
		if journalErr != nil {
			firstRemovalJournalReadable = false
			unresolved = append(unresolved, "first-release removal journal is unavailable: "+boundedRecoveryText(journalErr.Error()))
		} else if journal != nil {
			firstRemovalJournal = journal
			currentPresent := len(manifestBindings) > 0 && manifestBindings[0].Present
			if !currentPresent && (!journal.CurrentDirectorySyncPending || journal.RouteReloadPending) {
				unresolved = append(unresolved, "first-release removal journal does not prove current.yml directory sync is pending")
			} else if !currentPresent {
				currentPath, pathErr := rt.allowlistedManifestPath(record.App, "current.yml")
				if pathErr != nil {
					unresolved = append(unresolved, pathErr.Error())
				} else {
					selected = recoveryManifestBinding{
						Role: "current", Path: currentPath, SHA256: journal.ManifestSHA256,
						Authorized: true, Selected: true,
					}
				}
			}
		}
	}
	firstReleaseProvenNonConverged := false
	if firstRelease {
		convergenceBound := record.FirstReleaseConvergenceManifestSHA256 != "" &&
			sameDigest(record.FirstReleaseConvergenceManifestSHA256, record.CurrentManifestSHA256)
		switch record.FirstReleaseConvergenceState {
		case coord.FirstReleaseConvergencePending, coord.FirstReleaseConvergenceFailed:
			if convergenceBound {
				firstReleaseProvenNonConverged = true
			} else {
				unresolved = append(unresolved, "first-release non-convergence journal is not bound to the deploy manifest")
			}
		case coord.FirstReleaseConvergenceSucceeded:
			if !convergenceBound {
				unresolved = append(unresolved, "first-release convergence journal is not bound to the deploy manifest")
			}
			if firstRemovalJournal != nil {
				unresolved = append(unresolved, "first-release removal journal conflicts with proven convergence")
			}
		case "":
			// Legacy records without a convergence marker retain reapply recovery.
		default:
			unresolved = append(unresolved, "first-release convergence journal has an unknown state")
		}
	}

	kindSupported, _ := recoveryKindSupported(record.Kind)
	rt.keepInfrastructureVersions = copyRecoveryInfrastructureKeepVersions(keepInfrastructureVersions)
	removalJournalCanContinue := firstRemovalJournalReadable && firstRemovalJournal != nil && firstReleaseProvenNonConverged
	removeFirstRelease := firstRemovalJournalReadable && (removalJournalCanContinue || firstReleaseProvenNonConverged && len(manifestBindings) > 0 && manifestBindings[0].Present &&
		selected.Selected && selected.Path == manifestBindings[0].Path && selected.Role == "current" &&
		record.CurrentManifestSHA256 != "" && sameDigest(selected.SHA256, record.CurrentManifestSHA256) &&
		observation.ServiceState == serviceStateMismatch)
	actions := rt.deriveActions(record, kindSupported, marker, markerProof, durableReplicas, registryState, observation.ServiceState, routeState, selected, serviceIdentities, runTargetState, infrastructureReapplyAllowed, keepInfrastructureImages, recordKeptInfrastructure, syncRecoveryCurrentDirectory, removeFirstRelease)
	rt.planned = actions
	observation.Actions = recoveryActionDisplays(actions, rt.keepInfrastructureVersions)
	actionProof, err := canonicalActionProof(actions)
	if err != nil {
		unresolved = append(unresolved, "recovery action proof is unavailable")
	} else {
		observation.ActionProof = actionProof
	}

	observation.Unresolved = uniqueNonEmpty(unresolved)
	observation.MissingProof = append([]string(nil), observation.Unresolved...)
	observation.ResourceVersion = rootRecoveryDigest(recoveryResourceProof(closedProof, observation, baseline, registryIdentity, manifestBindings, marker, serviceIdentities, actionProof, routeState, selectedPayload))
	observation.ResourceProof = observation.ResourceVersion
	observation.Safe = len(observation.Unresolved) == 0 && observation.ExecutorCount == 0 && observation.ExecutorProof != ""
	return observation, nil
}

func recoveryFirstRelease(record coord.Record, baseline operationwriters.Baseline) bool {
	// observe calls this only after readClosedWriterState accepted the closed
	// proof and supplied its baseline. An all-zero fallback baseline is not proof.
	return record.Kind == "deploy" && !baseline.Current.Present && !baseline.Previous.Present
}

func (rt *rootRecoveryRuntime) observeRunTarget(ctx context.Context, record coord.Record) (string, []string) {
	if record.Kind != "run" {
		return "not-run", nil
	}
	if len(record.Phases) > 0 {
		last := record.Phases[len(record.Phases)-1]
		if last.Name == "run" && last.EndedAt != "" && last.Error != "" && last.Known {
			return "known-outcome", nil
		}
	}
	runPhase := false
	for _, phase := range record.Phases {
		if phase.Name == "run" {
			runPhase = true
			break
		}
	}
	if !runPhase {
		return "not-started", nil
	}
	if record.RunTarget == nil {
		return "legacy", []string{"run phase has no journaled container target; executor outcome is unresolved"}
	}
	if !rootServiceName.MatchString(record.RunTarget.Service) || !rootContainerIDPattern.MatchString(record.RunTarget.Container) || !rootAppName.MatchString(record.App) {
		return "invalid", []string{"journaled run target identity is invalid"}
	}
	service, err := runRecoveryServiceName(record.App, record.RunTarget.Service)
	if err != nil {
		return "invalid", []string{"journaled run service identity is invalid"}
	}
	inspected, err := rt.inspectContainer(ctx, record.RunTarget.Container)
	if err != nil {
		if dockerObjectNotFound(err.Error()) {
			return "gone", nil
		}
		return "unknown", []string{"journaled run container inspection is unresolved: " + boundedRecoveryText(err.Error())}
	}
	if inspected.Config.Labels["com.docker.swarm.service.name"] != service {
		return "label-mismatch", []string{"journaled run container does not carry the recorded Swarm service label"}
	}
	if inspected.State.Running {
		return "running", nil
	}
	return "stopped", nil
}

func (rt *rootRecoveryRuntime) apply(ctx context.Context, record coord.Record, observation coord.RecoveryObservation) error {
	rt.completed = nil
	rt.remaining = nil
	live, err := rt.observe(ctx, record)
	if err != nil {
		rt.remaining = append([]string(nil), observation.Actions...)
		return err
	}
	if err := confirmFreshRecoveryObservation(live, observation); err != nil {
		rt.remaining = recoveryActionDisplays(rt.planned, rt.keepInfrastructureVersions)
		return err
	}
	actions := append([]recoveryAction(nil), rt.planned...)
	proof, err := canonicalActionProof(actions)
	if err != nil || proof != observation.ActionProof {
		rt.remaining = recoveryActionDisplays(actions, rt.keepInfrastructureVersions)
		return errors.New("recovery action proof does not match the confirmed plan")
	}
	for i, action := range actions {
		if err := rt.executeAction(ctx, record, action); err != nil {
			rt.remaining = recoveryActionDisplays(actions[i:], rt.keepInfrastructureVersions)
			return err
		}
		if action.Kind == recoveryActionCompleteDestroy && rt.destroyFailure != nil {
			rt.completed = append(rt.completed, "complete destroy cleanup for "+action.App+"; PostgreSQL objects kept after failed removal")
		} else {
			rt.completed = append(rt.completed, recoveryActionDisplays([]recoveryAction{action}, rt.keepInfrastructureVersions)...)
		}
	}
	rt.remaining = []string{}
	return nil
}

func (rt *rootRecoveryRuntime) executeAction(ctx context.Context, record coord.Record, action recoveryAction) error {
	switch action.Kind {
	case recoveryActionRestoreBackupReplicas:
		return rt.executeRestoreBackup(ctx, record, action)
	case recoveryActionRestartRegistry:
		return rt.executeRestartRegistry(ctx)
	case recoveryActionRecreateRegistry:
		return rt.executeRecreateRegistry(ctx, record)
	case recoveryActionReapplyCurrent:
		return rt.executeReapplyCurrent(ctx, record, action)
	case recoveryActionRemoveFirstRelease:
		return rt.executeRemoveFirstRelease(ctx, record, action)
	case recoveryActionApplyCaddyRoute:
		return rt.executeApplyCaddy(record, action)
	case recoveryActionRecordKeptInfrastructure:
		return rt.executeRecordKeptInfrastructure(ctx, record, action)
	case recoveryActionSyncCurrentDirectory:
		return rt.executeSyncCurrentDirectory(record, action)
	case recoveryActionReplaceRunTasks:
		return rt.executeReplaceRunTasks(ctx, record, action)
	case recoveryActionCompleteDestroy:
		if rt.completeDestroy == nil {
			return errors.New("destroy recovery executor is not configured")
		}
		out := rt.destroyOutput
		if out == nil {
			out = rootLogOnlyWriter{}
		}
		ctx = context.WithValue(ctx, destroyOperationContextKey{}, record.ID)
		err := rt.completeDestroy(ctx, action.App, io.MultiWriter(out, &rt.destroyDetails))
		if known, ok := err.(*coord.KnownOutcomeError); ok {
			// Cleanup is settled and data kept; release recovery, but preserve the
			// failure in the response instead of stranding the host reservation.
			rt.destroyFailure = known
			return nil
		}
		return err
	default:
		return fmt.Errorf("unsupported recovery action %q", action.Kind)
	}
}

func (r destroyRemainder) hasResources() bool {
	return len(r.Services)+len(r.Networks)+len(r.Containers)+len(r.Volumes) > 0 || r.StateDir || r.Route || r.CleanupJournalSHA256 != ""
}

func (rt *rootRecoveryRuntime) observeDestroyRemainder(ctx context.Context, app string) (destroyRemainder, []string) {
	var remainder destroyRemainder
	var unresolved []string
	if app == "" || !rootAppName.MatchString(app) {
		return remainder, []string{"destroy app name is invalid"}
	}
	filter := "label=com.docker.stack.namespace=" + app
	reads := []struct {
		args []string
		dst  *[]string
		what string
	}{
		{[]string{"service", "ls", "--filter", filter, "--format", "{{.ID}}"}, &remainder.Services, "owned services"},
		{[]string{"network", "ls", "--filter", filter, "--format", "{{.ID}}"}, &remainder.Networks, "owned networks"},
		{[]string{"ps", "-a", "-q", "--filter", filter}, &remainder.Containers, "owned containers"},
	}
	for _, read := range reads {
		body, err := rt.dockerRead(ctx, read.args...)
		if err != nil {
			unresolved = append(unresolved, "destroy remainder "+read.what+" cannot be read: "+boundedRecoveryText(err.Error()))
			continue
		}
		*read.dst = destroySortedUnique(strings.Fields(body))
	}
	volumeNames, volumeErr := rt.dockerRead(ctx, "volume", "ls", "--filter", filter, "--format", "{{.Name}}")
	if volumeErr != nil {
		unresolved = append(unresolved, "destroy remainder owned volumes cannot be read: "+boundedRecoveryText(volumeErr.Error()))
	} else {
		for _, name := range strings.Fields(volumeNames) {
			if rt.observeOwnedDestroyVolume(ctx, app, name, "volume", &unresolved) {
				remainder.Volumes = append(remainder.Volumes, name)
			}
		}
	}
	for _, name := range []string{app + "_redis_data", app + "_rabbitmq_data"} {
		if rt.observeOwnedDestroyVolume(ctx, app, name, "infrastructure volume", &unresolved) {
			remainder.Volumes = append(remainder.Volumes, name)
		}
	}
	remainder.Volumes = destroySortedUnique(remainder.Volumes)
	stateDir := filepath.Join(rt.appStateRoot, app)
	if _, err := rt.lstat(stateDir); err == nil {
		remainder.StateDir = true
		entries, readErr := os.ReadDir(stateDir)
		if readErr != nil {
			unresolved = append(unresolved, "destroy remainder application state cannot be listed: "+boundedRecoveryText(readErr.Error()))
		} else if len(entries) == 1 && entries[0].Name() == "postgres.json" && entries[0].Type().IsRegular() {
			// Default destroy retains ownership proof, not unfinished cleanup.
			// Treating this ledger as a remainder scheduled destroy forever.
			if _, err := readPostgresLedger(rt.appStateRoot, app); err != nil {
				unresolved = append(unresolved, "kept PostgreSQL ledger is invalid: "+boundedRecoveryText(err.Error()))
			} else {
				remainder.StateDir = false
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		unresolved = append(unresolved, "destroy remainder application state cannot be read: "+boundedRecoveryText(err.Error()))
	}
	routePath := filepath.Join(rt.caddyDir, "50-"+app+".caddy")
	if _, err := rt.lstat(routePath); err == nil {
		remainder.Route = true
	} else if !errors.Is(err, os.ErrNotExist) {
		unresolved = append(unresolved, "destroy remainder Caddy route cannot be read: "+boundedRecoveryText(err.Error()))
	}
	return remainder, unresolved
}

func (rt *rootRecoveryRuntime) observeOwnedDestroyVolume(ctx context.Context, app, name, description string, unresolved *[]string) bool {
	labelsBody, err := rt.dockerRead(ctx, "volume", "inspect", "--format", "{{json .Labels}}", name)
	if err != nil {
		if !dockerObjectAbsent("volume", name, err.Error()) {
			*unresolved = append(*unresolved, "destroy remainder "+description+" "+name+" ownership cannot be read: "+boundedRecoveryText(err.Error()))
		}
		return false
	}
	labels, err := parseRootVolumeLabels([]byte(labelsBody))
	if err != nil {
		*unresolved = append(*unresolved, "destroy remainder "+description+" "+name+" ownership labels are invalid")
		return false
	}
	owned, _ := rootVolumeOwnedByApp(labels, app)
	return owned
}

func destroySortedUnique(values []string) []string {
	sort.Strings(values)
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

type rootLogOnlyWriter struct{}

func (rootLogOnlyWriter) Write(body []byte) (int, error) {
	text := strings.TrimSuffix(string(body), "\n")
	for _, line := range strings.Split(text, "\n") {
		if line != "" {
			rootLog("%s", line)
		}
	}
	return len(body), nil
}

func (rt *rootRecoveryRuntime) observeKeptInfrastructureRewrite(record coord.Record, selected recoveryManifestBinding, observedCurrentDigest string, keepImages map[string]recoveryInfrastructureImageProof) (bool, []string) {
	currentPath, err := rt.allowlistedManifestPath(record.App, "current.yml")
	if err != nil {
		return false, []string{err.Error()}
	}
	if !selected.Selected || selected.Path != currentPath || selected.SHA256 == "" || !sameDigest(observedCurrentDigest, selected.SHA256) {
		// The baseline archive can supply the selected artifact after slot
		// rotation. Recovery keeps that behavior and does not publish archive
		// bytes into current.yml as a side effect.
		return false, nil
	}
	if err := rt.requireAllowlistedManifestPath(record.App, currentPath); err != nil {
		return false, []string{err.Error()}
	}
	original, err := rt.readBoundedRegular(currentPath, rootplan.MaxSize)
	if err != nil {
		return false, []string{"retained current manifest changed while observing kept infrastructure images"}
	}
	currentDigest := rootRecoveryDigest(original)
	if !sameDigest(currentDigest, selected.SHA256) {
		return false, []string{"retained current manifest changed while observing kept infrastructure images"}
	}
	prospective, err := replaceKeptInfrastructureImageSpans(original, keepImages)
	if err != nil {
		return false, []string{"kept infrastructure image rewrite cannot be built exactly: " + boundedRecoveryText(err.Error())}
	}
	prospectiveDigest := rootRecoveryDigest(prospective)
	switch record.RecoveryCurrentManifestSHA256 {
	case "":
		return true, nil
	case prospectiveDigest:
		// A crash after journaling but before rename replays this same action.
		return true, nil
	case currentDigest:
		if prospectiveDigest != currentDigest {
			return false, []string{"current.yml recovery binding matches the on-disk bytes but a different kept image rewrite is now required; recover by hand"}
		}
		return false, nil
	default:
		return false, []string{"current.yml already rebound by this recovery; recover by hand"}
	}
}

func (rt *rootRecoveryRuntime) executeRecordKeptInfrastructure(ctx context.Context, record coord.Record, action recoveryAction) error {
	if record.Kind != "deploy" || len(action.KeepInfrastructureImages) == 0 {
		return errors.New("kept infrastructure manifest action is valid only for deploy recovery")
	}
	currentPath, err := rt.allowlistedManifestPath(record.App, "current.yml")
	if err != nil {
		return err
	}
	if action.ManifestPath != currentPath || action.ManifestSHA256 == "" {
		return errors.New("kept infrastructure manifest action is not bound to current.yml")
	}
	if err := rt.requireAllowlistedManifestPath(record.App, action.ManifestPath); err != nil {
		return err
	}
	original, err := rt.readBoundedRegular(currentPath, rootplan.MaxSize)
	if err != nil {
		return fmt.Errorf("read retained current manifest before kept infrastructure rewrite: %w", err)
	}
	if rootRecoveryDigest(original) != action.ManifestSHA256 {
		return errors.New("retained current manifest changed before kept infrastructure rewrite")
	}
	services, err := rootStackServices(record.App, original)
	if err != nil {
		return err
	}
	keepImages, _, allowed, unresolved := rt.assessInfrastructureImages(ctx, record.App, services)
	if len(unresolved) > 0 || !allowed {
		return fmt.Errorf("infrastructure recovery decision changed before recording kept images: %s", strings.Join(unresolved, "; "))
	}
	if !recoveryInfrastructureMapsEqual(keepImages, action.KeepInfrastructureImages) {
		return errors.New("kept infrastructure image references changed before current.yml rewrite")
	}
	prospective, err := replaceKeptInfrastructureImageSpans(original, keepImages)
	if err != nil {
		return fmt.Errorf("prepare exact current.yml kept infrastructure rewrite: %w", err)
	}
	// The 2026-10-26 incident left current.yml naming Redis 7.4.5 after
	// recovery kept 7.4.11 only in its temporary copy. Bind the exact new bytes
	// first so a crash before rename can replay this action safely.
	if err := coord.JournalRecoveryCurrentManifest(ctx, rootRecoveryDigest(prospective)); err != nil {
		return err
	}
	if err := writeRootFile(currentPath, prospective, 0o600); err != nil {
		return fmt.Errorf("publish kept infrastructure images in current.yml: %w", err)
	}
	if rt.syncDir == nil {
		return errors.New("current.yml parent cannot be synced after kept infrastructure rewrite")
	}
	// The journal is already durable, so recovery cannot report success until
	// the parent also makes the rename durable after a power loss.
	if err := rt.syncDir(filepath.Dir(currentPath)); err != nil {
		return fmt.Errorf("sync current.yml parent after kept infrastructure rewrite: %w", err)
	}
	rt.syncedRecoveryCurrentManifestSHA256 = rootRecoveryDigest(prospective)
	return nil
}

func (rt *rootRecoveryRuntime) executeSyncCurrentDirectory(record coord.Record, action recoveryAction) error {
	if record.Kind != "deploy" || !record.RecoveryRequired || record.State != coord.RecoveryRequired || record.RecoveryCurrentManifestSHA256 == "" {
		return errors.New("current.yml directory sync action is valid only during a bound deploy recovery")
	}
	currentPath, err := rt.allowlistedManifestPath(record.App, "current.yml")
	if err != nil {
		return err
	}
	if action.App != record.App || action.ManifestPath != currentPath || !sameDigest(action.ManifestSHA256, record.RecoveryCurrentManifestSHA256) {
		return errors.New("current.yml directory sync action is not bound to the recovery manifest")
	}
	if err := rt.requireAllowlistedManifestPath(record.App, action.ManifestPath); err != nil {
		return err
	}
	current, err := rt.readBoundedRegular(currentPath, rootplan.MaxSize)
	if err != nil {
		return fmt.Errorf("read retained current manifest before directory sync: %w", err)
	}
	if !sameDigest(rootRecoveryDigest(current), action.ManifestSHA256) {
		return errors.New("retained current manifest changed before its parent directory sync")
	}
	if rt.syncDir == nil {
		return errors.New("current.yml parent cannot be synced after kept infrastructure rewrite")
	}
	if err := rt.syncDir(filepath.Dir(currentPath)); err != nil {
		return fmt.Errorf("sync current.yml parent after kept infrastructure rewrite: %w", err)
	}
	rt.syncedRecoveryCurrentManifestSHA256 = normalizeDigest(action.ManifestSHA256)
	return nil
}

// runRecoveryServiceName derives the Swarm service of a journaled run from its
// two validated components, exactly as deploy derives it. Observation and the
// replacement action both go through it: matching the combined string against
// the per-component pattern refused long but valid names, and a check present
// in one place only would let observation accept a recovery the action then
// refuses forever.
func runRecoveryServiceName(app, service string) (string, error) {
	if !rootAppName.MatchString(app) || !rootServiceName.MatchString(service) {
		return "", errors.New("run recovery service identity is invalid")
	}
	return app + "_" + service, nil
}

func (rt *rootRecoveryRuntime) executeReplaceRunTasks(ctx context.Context, record coord.Record, action recoveryAction) error {
	if action.Service == "" || !rootServiceName.MatchString(action.Service) || !rootContainerIDPattern.MatchString(action.Container) {
		return errors.New("run recovery action has an invalid journaled target")
	}
	service, err := runRecoveryServiceName(record.App, action.Service)
	if err != nil {
		return err
	}
	manifest, err := rt.loadAuthorizedManifestBytes(record, action.ManifestPath, action.ManifestSHA256)
	if err != nil {
		return err
	}
	services, err := rootStackServices(record.App, manifest)
	if err != nil {
		return err
	}
	var target *rootStackService
	for i := range services {
		if services[i].Service == service {
			target = &services[i]
			break
		}
	}
	if target == nil {
		return errors.New("journaled run service is absent from the selected retained manifest")
	}
	inspected, err := rt.inspectContainer(ctx, action.Container)
	if err != nil {
		if dockerObjectNotFound(err.Error()) {
			return nil
		}
		return fmt.Errorf("reinspect journaled run container: %w", err)
	}
	if inspected.Config.Labels["com.docker.swarm.service.name"] != service {
		return errors.New("journaled run container no longer belongs to the recorded service")
	}
	if !inspected.State.Running {
		return nil
	}
	if err := rt.dockerRun(ctx, "service", "update", "--force", "--detach=false", service); err != nil {
		return fmt.Errorf("replace tasks for %s: %w", service, err)
	}
	return rt.waitRunTargetReplacement(ctx, record.App, action.Container, service, *target)
}

func (rt *rootRecoveryRuntime) waitRunTargetReplacement(ctx context.Context, app, containerID, service string, target rootStackService) error {
	// Recovery does not know which promotion mode the interrupted deploy ran in,
	// so every wait here is the longer of the two modes' (config.SwarmWorstCaseWaits).
	timeout := config.SwarmWorstCaseWaits(config.DefaultDeploySLOSeconds("")).StackConvergence
	deadline := rt.clock().Add(timeout)
	var last error
	for {
		inspected, err := rt.inspectContainer(ctx, containerID)
		if err != nil {
			if dockerObjectNotFound(err.Error()) {
				return rt.inspectApplicationContainers(ctx, app, []rootStackService{target})
			}
			last = fmt.Errorf("verify journaled run container: %w", err)
		} else if inspected.Config.Labels["com.docker.swarm.service.name"] != service {
			return errors.New("journaled run container service label changed during recovery")
		} else if !inspected.State.Running {
			return rt.inspectApplicationContainers(ctx, app, []rootStackService{target})
		} else {
			last = errors.New("journaled run container is still running after service replacement")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !rt.clock().Before(deadline) {
			return last
		}
		after := rt.after
		if after == nil {
			after = time.After
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-after(500 * time.Millisecond):
		}
	}
}

func (rt *rootRecoveryRuntime) executeRestoreBackup(ctx context.Context, record coord.Record, action recoveryAction) error {
	marker, _, err := rt.loadPendingBackupMarker(record)
	if err != nil {
		return fmt.Errorf("pending backup marker cannot be safely applied: %v", err)
	}
	replicas := copyReplicaMap(action.Replicas)
	if marker != nil {
		if canonicalMarkerProof(*marker, action.MarkerPath) != action.MarkerProof || !replicaMapsEqual(marker.Replicas, action.Replicas) {
			return errors.New("pending backup marker identity changed before apply")
		}
		replicas = copyReplicaMap(marker.Replicas)
	} else {
		durable, durableErr := rt.loadDurableBackupReplicas(record.ID)
		if durableErr != nil || len(durable) == 0 || !replicaMapsEqual(durable, action.Replicas) {
			return errors.New("durable backup replica proof is missing or changed before apply")
		}
		replicas = durable
	}
	if err := rt.storeDurableBackupReplicas(record.ID, record.App, replicas); err != nil {
		return err
	}
	payload, err := rt.loadAuthorizedManifestBytes(record, action.ManifestPath, action.ManifestSHA256)
	if err != nil {
		return err
	}
	services, err := rootStackServices(record.App, payload)
	if err != nil {
		return err
	}
	if err := replicaMembershipMatches(services, replicas); err != nil {
		return err
	}
	for _, service := range sortedReplicaServices(replicas) {
		if err := rt.dockerRun(ctx, "service", "scale", service+"="+strconv.Itoa(replicas[service])); err != nil {
			return fmt.Errorf("restore original replicas for %s: %w", service, err)
		}
	}
	if err := rt.waitCapturedReplicas(ctx, record.App, services, replicas); err != nil {
		return err
	}
	if marker != nil {
		return rt.removeVerifiedPendingBackupMarker(record, marker)
	}
	return nil
}

func (rt *rootRecoveryRuntime) executeRestartRegistry(ctx context.Context) error {
	if err := rt.dockerRun(ctx, "start", rootRegistryContainer); err != nil {
		return err
	}
	return rt.waitRegistryHealthy(ctx)
}

func (rt *rootRecoveryRuntime) executeReapplyCurrent(ctx context.Context, record coord.Record, action recoveryAction) error {
	payload, err := rt.loadAuthorizedManifestBytes(record, action.ManifestPath, action.ManifestSHA256)
	if err != nil {
		return err
	}
	services, err := rootStackServices(record.App, payload)
	if err != nil {
		return err
	}
	if record.Kind == "deploy" {
		// Recheck after the coordinator's confirmation observation. This catches
		// intervening service changes before deploy; the accepted interval after
		// this inspection needs a separate host-level lock to close.
		keepImages, _, allowed, unresolved := rt.assessInfrastructureImages(ctx, record.App, services)
		if len(unresolved) > 0 || !allowed {
			return fmt.Errorf("infrastructure recovery decision changed before stack deploy: %s", strings.Join(unresolved, "; "))
		}
		if !recoveryInfrastructureMapsEqual(keepImages, action.KeepInfrastructureImages) {
			return errors.New("kept infrastructure image references changed before stack deploy")
		}
		payload, err = replaceKeptInfrastructureImages(payload, keepImages)
		if err != nil {
			return fmt.Errorf("prepare kept infrastructure images: %w", err)
		}
		services = applyKeptInfrastructureImages(services, keepImages)
	} else if len(action.KeepInfrastructureImages) > 0 {
		return errors.New("rollback recovery cannot keep infrastructure images")
	}
	stackFile, err := rt.materializeManifestFile(record.App, action.ManifestPath, payload)
	if err != nil {
		return err
	}
	if err := rt.dockerRun(ctx, "stack", "deploy", "--detach", "-c", stackFile, record.App); err != nil {
		return err
	}
	if err := rt.waitStack(record.App, stackFile, rt.clock(), config.SwarmWorstCaseWaits(config.DefaultDeploySLOSeconds("")).StackConvergence); err != nil {
		return err
	}
	services, err = rootStackServices(record.App, payload)
	if err != nil {
		return err
	}
	return rt.inspectApplicationContainers(ctx, record.App, services)
}

func (rt *rootRecoveryRuntime) executeRemoveFirstRelease(ctx context.Context, record coord.Record, action recoveryAction) error {
	if record.Kind != "deploy" || !rootAppName.MatchString(record.App) || action.App != record.App {
		return errors.New("first-release removal action is not bound to a deploy application")
	}
	currentPath, err := rt.allowlistedManifestPath(record.App, "current.yml")
	if err != nil {
		return err
	}
	if action.ManifestPath != currentPath || action.ManifestSHA256 == "" || !sameDigest(action.ManifestSHA256, record.CurrentManifestSHA256) {
		return errors.New("first-release removal action is not bound to the deploy's current manifest")
	}
	if err := rt.requireAllowlistedManifestPath(record.App, action.ManifestPath); err != nil {
		return err
	}
	journal, err := rt.readFirstReleaseRemovalJournal(record)
	if err != nil {
		return fmt.Errorf("read first-release removal journal: %w", err)
	}
	switch record.FirstReleaseConvergenceState {
	case coord.FirstReleaseConvergencePending, coord.FirstReleaseConvergenceFailed:
		if !sameDigest(record.FirstReleaseConvergenceManifestSHA256, record.CurrentManifestSHA256) {
			return errors.New("first-release removal is not bound to a proven non-converged manifest")
		}
	default:
		return errors.New("operation journal does not prove first-release non-convergence")
	}
	current, err := rt.readBoundedRegular(currentPath, rootplan.MaxSize)
	if err != nil {
		if !os.IsNotExist(err) || journal == nil || !journal.CurrentDirectorySyncPending || journal.RouteReloadPending {
			return fmt.Errorf("read first-release current manifest before removal: %w", err)
		}
		if err := rt.waitFirstReleaseRemoval(ctx, record.App); err != nil {
			return err
		}
		return rt.syncAndFinishFirstReleaseRemoval(currentPath, journal)
	}
	if !sameDigest(rootRecoveryDigest(current), action.ManifestSHA256) {
		return errors.New("first-release current manifest changed after the recovery plan")
	}
	if journal == nil {
		journal = &firstReleaseRemovalJournal{
			Schema: rootRecoveryFirstRemovalSchema, OperationID: record.ID,
			App: record.App, ManifestSHA256: action.ManifestSHA256,
		}
	}
	if journal.CurrentDirectorySyncPending {
		// The helper may stop after writing the intent but before unlinking.
		// An exact current digest lets recovery restart that step safely.
		journal.CurrentDirectorySyncPending = false
		if err := rt.writeFirstReleaseRemovalJournal(record, journal); err != nil {
			return fmt.Errorf("reset first-release current.yml removal intent: %w", err)
		}
	}
	// stack rm also removes stack-owned secrets. Remove only the app's services,
	// wait for their tasks to disappear, then remove only stack-labelled networks.
	serviceIDs, err := rt.firstReleaseObjectIDs(ctx, "service", record.App)
	if err != nil {
		return fmt.Errorf("list first-release services before removal: %w", err)
	}
	if err := removeFirstReleaseDockerObjects(ctx, rt.dockerRun, "service", serviceIDs); err != nil {
		return fmt.Errorf("remove first-release services: %w", err)
	}
	if err := rt.waitFirstReleaseServicesRemoved(ctx, record.App); err != nil {
		return err
	}
	networkIDs, err := rt.firstReleaseObjectIDs(ctx, "network", record.App)
	if err != nil {
		return fmt.Errorf("list first-release networks before removal: %w", err)
	}
	if err := removeFirstReleaseDockerObjects(ctx, rt.dockerRun, "network", networkIDs); err != nil {
		return fmt.Errorf("remove first-release networks: %w", err)
	}
	if err := rt.waitFirstReleaseRemoval(ctx, record.App); err != nil {
		return err
	}
	routePath := filepath.Join(rt.caddyDir, "50-"+record.App+".caddy")
	routeExists, err := rt.firstReleaseRouteExists(routePath)
	if err != nil {
		return fmt.Errorf("inspect first-release Caddy route: %w", err)
	}
	if routeExists || journal.RouteReloadPending {
		if !journal.RouteReloadPending {
			// A route reload can fail after its file is unlinked. Keep that progress
			// so retry does not mistake a missing file for an internal app.
			journal.RouteReloadPending = true
			if err := rt.writeFirstReleaseRemovalJournal(record, journal); err != nil {
				return fmt.Errorf("journal first-release Caddy route removal: %w", err)
			}
		}
		if routeExists {
			if err := rt.remove(routePath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove first-release Caddy route: %w", err)
			}
		}
		if rt.syncDir == nil {
			return errors.New("Caddy configuration directory cannot be synced after first-release route removal")
		}
		if err := rt.syncDir(filepath.Dir(routePath)); err != nil {
			return fmt.Errorf("sync Caddy configuration directory after first-release route removal: %w", err)
		}
		if rt.reloadEdge == nil {
			return errors.New("shared edge reloader is not bound")
		}
		if err := rt.reloadEdge(); err != nil {
			return fmt.Errorf("reload shared edge after first-release route removal: %w", err)
		}
		journal.RouteReloadPending = false
		if err := rt.writeFirstReleaseRemovalJournal(record, journal); err != nil {
			return fmt.Errorf("record first-release Caddy route reload: %w", err)
		}
	}
	current, err = rt.readBoundedRegular(currentPath, rootplan.MaxSize)
	if err != nil {
		return fmt.Errorf("recheck first-release current manifest before unlink: %w", err)
	}
	if !sameDigest(rootRecoveryDigest(current), action.ManifestSHA256) {
		return errors.New("first-release current manifest changed before unlink")
	}
	// Persist this marker before unlinking. If the parent sync fails or the
	// helper stops here, the next recovery still knows it must sync the unlink.
	journal.CurrentDirectorySyncPending = true
	if err := rt.writeFirstReleaseRemovalJournal(record, journal); err != nil {
		return fmt.Errorf("journal first-release current.yml removal: %w", err)
	}
	if err := rt.remove(currentPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove first-release current manifest: %w", err)
	}
	return rt.syncAndFinishFirstReleaseRemoval(currentPath, journal)
}

func (rt *rootRecoveryRuntime) firstReleaseRemovalJournalPath(record coord.Record) (string, error) {
	if !rootAppName.MatchString(record.App) || record.ID == "" || rt.appStateRoot == "" {
		return "", errors.New("first-release removal journal identity is invalid")
	}
	operationDigest := strings.TrimPrefix(rootRecoveryDigest([]byte(record.ID)), "sha256:")
	return filepath.Join(rt.appStateRoot, record.App, ".first-release-removal-"+operationDigest+".json"), nil
}

func (rt *rootRecoveryRuntime) readFirstReleaseRemovalJournal(record coord.Record) (*firstReleaseRemovalJournal, error) {
	path, err := rt.firstReleaseRemovalJournalPath(record)
	if err != nil {
		return nil, err
	}
	body, err := rt.readBoundedRegular(path, rootRecoveryFirstRemovalMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var journal firstReleaseRemovalJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("first-release removal journal contains trailing JSON")
	}
	if journal.Schema != rootRecoveryFirstRemovalSchema || journal.OperationID != record.ID || journal.App != record.App ||
		journal.ManifestSHA256 == "" || !sameDigest(journal.ManifestSHA256, record.CurrentManifestSHA256) ||
		journal.CurrentDirectorySyncPending && journal.RouteReloadPending {
		return nil, errors.New("first-release removal journal does not match the deploy")
	}
	return &journal, nil
}

func (rt *rootRecoveryRuntime) writeFirstReleaseRemovalJournal(record coord.Record, journal *firstReleaseRemovalJournal) error {
	if journal == nil || journal.Schema != rootRecoveryFirstRemovalSchema || journal.OperationID != record.ID ||
		journal.App != record.App || !sameDigest(journal.ManifestSHA256, record.CurrentManifestSHA256) {
		return errors.New("first-release removal journal identity is invalid")
	}
	path, err := rt.firstReleaseRemovalJournalPath(record)
	if err != nil {
		return err
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeRootFile(path, append(body, '\n'), 0o600)
}

func (rt *rootRecoveryRuntime) syncAndFinishFirstReleaseRemoval(currentPath string, journal *firstReleaseRemovalJournal) error {
	if journal == nil || !journal.CurrentDirectorySyncPending || journal.RouteReloadPending {
		return errors.New("first-release current.yml removal has no durable sync journal")
	}
	lstat := rt.lstat
	if lstat == nil {
		lstat = os.Lstat
	}
	if _, err := lstat(currentPath); err == nil {
		return errors.New("current.yml reappeared before its parent directory sync")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect current.yml before its parent directory sync: %w", err)
	}
	if rt.syncDir == nil {
		return errors.New("current.yml parent cannot be synced after first-release removal")
	}
	if err := rt.syncDir(filepath.Dir(currentPath)); err != nil {
		return fmt.Errorf("sync current.yml parent after first-release removal: %w", err)
	}
	path, err := rt.firstReleaseRemovalJournalPath(coord.Record{ID: journal.OperationID, App: journal.App})
	if err != nil {
		return err
	}
	if err := rt.remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove completed first-release removal journal: %w", err)
	}
	return nil
}

func (rt *rootRecoveryRuntime) firstReleaseObjectIDs(ctx context.Context, kind, app string) ([]string, error) {
	if kind != "service" && kind != "network" {
		return nil, errors.New("unsupported first-release Docker object type")
	}
	body, err := rt.dockerRead(ctx, kind, "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(body, "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		if !safeDockerRemovalReference(id) {
			return nil, errors.New("Docker returned an invalid first-release object id")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func safeDockerRemovalReference(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, char := range value {
		alpha := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
		digit := char >= '0' && char <= '9'
		if index == 0 {
			if !alpha && !digit {
				return false
			}
		} else if !alpha && !digit && char != '_' && char != '.' && char != '-' {
			return false
		}
	}
	return true
}

func removeFirstReleaseDockerObjects(ctx context.Context, run func(context.Context, ...string) error, kind string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	args := append([]string{kind, "rm"}, ids...)
	return run(ctx, args...)
}

func (rt *rootRecoveryRuntime) firstReleaseRouteExists(path string) (bool, error) {
	lstat := rt.lstat
	if lstat == nil {
		lstat = os.Lstat
	}
	info, err := lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("first-release Caddy route is not a regular file")
	}
	return true, nil
}

func (rt *rootRecoveryRuntime) waitFirstReleaseServicesRemoved(ctx context.Context, app string) error {
	return rt.waitFirstReleaseObjects(ctx, app, false)
}

func (rt *rootRecoveryRuntime) waitFirstReleaseRemoval(ctx context.Context, app string) error {
	return rt.waitFirstReleaseObjects(ctx, app, true)
}

func (rt *rootRecoveryRuntime) waitFirstReleaseObjects(ctx context.Context, app string, includeNetworks bool) error {
	if !rootAppName.MatchString(app) {
		return errors.New("first-release removal application name is invalid")
	}
	budget := recoveryFirstReleaseRemovalBudget
	deadline := rt.clock().Add(budget)
	for {
		services, err := rt.dockerRead(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", "{{.ID}}")
		if err != nil {
			return fmt.Errorf("inspect first-release services during removal: %w", err)
		}
		networks := ""
		if includeNetworks {
			networks, err = rt.dockerRead(ctx, "network", "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", "{{.ID}}")
			if err != nil {
				return fmt.Errorf("inspect first-release networks during removal: %w", err)
			}
		}
		containers, err := rt.dockerRead(ctx, "ps", "-a", "-q", "--filter", "label=com.docker.stack.namespace="+app)
		if err != nil {
			return fmt.Errorf("inspect first-release containers during removal: %w", err)
		}
		if strings.TrimSpace(services) == "" && strings.TrimSpace(networks) == "" && strings.TrimSpace(containers) == "" {
			return nil
		}
		remaining := deadline.Sub(rt.clock())
		if remaining <= 0 {
			return fmt.Errorf("first release of %s was not removed within %s", app, budget)
		}
		interval := 500 * time.Millisecond
		if remaining < interval {
			interval = remaining
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rt.after(interval):
		}
	}
}

func (rt *rootRecoveryRuntime) executeApplyCaddy(record coord.Record, action recoveryAction) error {
	payload, err := rt.loadAuthorizedManifestBytes(record, action.ManifestPath, action.ManifestSHA256)
	if err != nil {
		return err
	}
	timeout := config.SwarmWorstCaseWaits(config.DefaultDeploySLOSeconds("")).CaddyReload
	if rt.applyCaddy == nil {
		return errors.New("Caddy route applier is not bound")
	}
	if err := rt.applyCaddy(record.App, payload, timeout); err != nil {
		return err
	}
	if rt.verifyCaddy == nil {
		return errors.New("Caddy route verifier is not bound")
	}
	return rt.verifyCaddy(record.App, payload)
}

func (rt *rootRecoveryRuntime) verifyRetainedCaddyRoute(app string, payload []byte) error {
	want, err := caddyRouteFragment(app, payload)
	if err != nil {
		return err
	}
	if want == "" {
		return nil
	}
	if rt.loadedRoute != nil {
		loaded, loadedErr := rt.loadedRoute(app)
		if loadedErr != nil {
			return fmt.Errorf("verify loaded Caddy route: %w", loadedErr)
		}
		if !loadedRouteMatches(loaded, want) {
			return errors.New("loaded Caddy route does not match the selected retained manifest")
		}
		return nil
	}
	return errors.New("loaded Caddy route proof is unavailable")
}

func (rt *rootRecoveryRuntime) waitRegistryHealthy(ctx context.Context) error {
	deadline := rt.clock().Add(30 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !rt.clock().Before(deadline) {
			return errors.New("existing loopback registry did not become healthy")
		}
		// Keep health checks in the same container namespace as observeRegistry.
		body, err := rt.dockerRead(ctx, "container", "inspect", "--format", "{{json .State.Health.Status}}", rootRegistryContainer)
		if err == nil && strings.Trim(strings.TrimSpace(body), "\"") == "healthy" {
			return nil
		}
		after := rt.after
		if after == nil {
			after = time.After
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-after(500 * time.Millisecond):
		}
	}
}

func (rt *rootRecoveryRuntime) readClosedWriterState(ctx context.Context, record coord.Record) (operationwriters.State, string, []string) {
	if rt.reader == nil {
		return operationwriters.State{}, "", []string{"closed writer reader is not bound: ROOT B must assign rootRecoveryWriterReader"}
	}
	state, err := rt.reader(ctx, record)
	if err != nil {
		if record.Kind == "helper-update" && errors.Is(err, operationwriters.ErrNotFound) {
			// Signed helper-update skips writer initialization. Failure in
			// phase helper-update before replaceRootHelper therefore has no
			// state file. Requiring a closed proof here refused the global
			// reservation forever and blocked every later deploy, reboot,
			// and helper update.
			return operationwriters.State{}, "", nil
		}
		return operationwriters.State{}, "", []string{"closed writer proof is missing: " + boundedRecoveryText(err.Error())}
	}
	if state.Binding.OperationID != record.ID {
		return operationwriters.State{}, "", []string{"closed writer binding does not match the operation id"}
	}
	if record.Host != "" && state.Binding.HostKey != record.Host {
		return operationwriters.State{}, "", []string{"closed writer binding does not match the operation host key"}
	}
	if record.HostBootID != "" && state.Binding.BootID != record.HostBootID {
		return operationwriters.State{}, "", []string{"closed writer binding does not match the operation boot identity"}
	}
	if state.Admissions != operationwriters.AdmissionsClosed || state.Closure == nil {
		return operationwriters.State{}, "", []string{"closed writer admissions are not proven closed"}
	}
	proof, err := state.ClosedProofHash()
	if err != nil || proof == "" || proof != state.Closure.ProofHash {
		return operationwriters.State{}, "", []string{"closed writer closure proof is invalid"}
	}
	return state, proof, nil
}

func (rt *rootRecoveryRuntime) observePostgres(baseline operationwriters.Baseline) (string, []string) {
	version := strings.TrimSpace(baseline.ConfiguredNativePGVersion)
	cluster := strings.TrimSpace(baseline.ConfiguredNativePGCluster)
	if version == postgresNotConfigured && cluster == postgresNotConfigured {
		return dataStateNotApplicable, nil
	}
	if version == "" || cluster == "" {
		return dataStateUnconfigured, []string{"native PostgreSQL is not configured in the closed baseline"}
	}
	if version == postgresNotConfigured || cluster == postgresNotConfigured {
		return dataStateUnconfigured, []string{"native PostgreSQL is not configured in the closed baseline"}
	}
	// A host with several clusters (production `18/main` next to preprod
	// `18/preprod`) records them as aligned comma-separated lists, e.g.
	// "18,18" and "main,preprod". Joining the raw lists into one path looked
	// for /etc/postgresql/18,18/main,preprod, which never exists, so every
	// recovery on such a host was refused as unsafe. Each pair is checked on
	// its own instead, and every recorded cluster must still be present.
	// Baselines written before the pairs were sorted together had each list
	// sorted on its own: index pairing stays exact while the majors are equal,
	// and a mismatched pair only ever fails closed.
	versions := strings.Split(version, ",")
	clusters := strings.Split(cluster, ",")
	if len(versions) != len(clusters) {
		return dataStateUnconfigured, []string{"native PostgreSQL is not configured in the closed baseline"}
	}
	for i := range versions {
		major, _, _ := strings.Cut(strings.TrimSpace(versions[i]), ".")
		name := strings.TrimSpace(clusters[i])
		if major == "" || name == "" || strings.ContainsAny(major, `/\`) || strings.ContainsAny(name, `/\`) || major == ".." || name == ".." {
			return dataStateUnconfigured, []string{"native PostgreSQL is not configured in the closed baseline"}
		}
		info, err := rt.lstat(filepath.Join(rt.postgresRoot, major, name))
		if err != nil || info == nil || !info.IsDir() {
			return dataStateMissing, []string{"configured native PostgreSQL version and cluster are not present on the host"}
		}
	}
	return dataStateMatch, nil
}

func (rt *rootRecoveryRuntime) observeRegistry(ctx context.Context, intent *coord.RegistryReplacement) (recoveryRegistryIdentity, string, []string) {
	// The volume is also named shuttle-registry. After rm, generic inspect
	// returns that volume instead of proving the container is absent.
	body, err := rt.dockerRead(ctx, "container", "inspect", "--format", "{{json .}}", rootRegistryContainer)
	if err != nil {
		if dockerObjectNotFound(err.Error()) {
			return recoveryRegistryIdentity{}, registryStateMissing, []string{"existing loopback registry is unavailable"}
		}
		return recoveryRegistryIdentity{}, registryStateUnreadable, []string{"registry inspection is unavailable"}
	}
	var inspected recoveryRegistryInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &inspected); err != nil {
		return recoveryRegistryIdentity{}, registryStateUnreadable, []string{"registry configuration is unreadable"}
	}
	identity := recoveryRegistryIdentity{
		Image:         strings.TrimSpace(inspected.Config.Image),
		ImageID:       strings.TrimSpace(inspected.Image),
		Running:       inspected.State.Running,
		HealthStatus:  strings.TrimSpace(inspected.State.Health.Status),
		RestartPolicy: strings.TrimSpace(inspected.HostConfig.RestartPolicy.Name),
		Bindings:      canonicalRegistryBindings(inspected.HostConfig.PortBindings),
	}
	if intent != nil {
		if intent.Validate() != nil || validateRootRegistryVolume(inspected.Mounts) != nil {
			return identity, registryStateUnsafe, []string{"registry does not mount the journaled data volume"}
		}
		volume, err := rt.dockerRead(ctx, "volume", "inspect", rootRegistryVolume, "--format", "{{json .}}")
		proof, proofErr := rootRegistryVolumeProof(volume)
		if err != nil || proofErr != nil || proof != intent.VolumeSHA256 {
			return identity, registryStateUnsafe, []string{"registry volume does not match the journaled replacement"}
		}
		identity.VolumeSHA256 = proof
	}
	// Docker's .Image is the local config digest, not the registry manifest
	// digest in the signed reference. Prove that the official pinned reference
	// resolves to a RepoDigest attached to this container's image.
	imageBody, err := rt.dockerRead(ctx, "image", "inspect", identity.ImageID)
	if err != nil {
		return identity, registryStateWrongImage, []string{"registry image identity is unsafe"}
	}
	var images []recoveryImageInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(imageBody)), &images); err != nil || len(images) == 0 {
		return identity, registryStateUnreadable, []string{"registry image metadata is unreadable"}
	}
	if !registryImageMatchesPin(identity.Image, images[0].RepoDigests) || inspected.Config.Labels[shuttleOwnerLabel] != "system" {
		return identity, registryStateWrongImage, []string{"registry image identity is unsafe"}
	}
	if identity.RestartPolicy != "always" {
		return identity, registryStateUnsafe, []string{"registry restart policy or loopback binding is unsafe"}
	}
	if err := validateLoopbackRegistryBindings(inspected.HostConfig.PortBindings); err != nil {
		return identity, registryStateUnsafe, []string{err.Error()}
	}
	if identity.Running && strings.EqualFold(identity.HealthStatus, "healthy") {
		return identity, registryStateHealthy, nil
	}
	if !identity.Running {
		return identity, registryStateStopped, nil
	}
	return identity, registryStateUnhealthy, nil
}

func (rt *rootRecoveryRuntime) observeApplication(ctx context.Context, record coord.Record, baseline operationwriters.Baseline, firstRelease bool) ([]recoveryManifestBinding, recoveryManifestBinding, []byte, string, string, string, string, []recoveryServiceIdentity, string, map[string]recoveryInfrastructureImageProof, map[string]recoveryInfrastructureKeepVersions, bool, []string) {
	bindings, selected, payload, currentDigest, previousDigest, unresolved := rt.resolveAuthorizedManifests(record, baseline, firstRelease)
	manifestProof := canonicalManifestProof(bindings)
	var keepImages map[string]recoveryInfrastructureImageProof
	var keepVersions map[string]recoveryInfrastructureKeepVersions
	infrastructureReapplyAllowed := true
	if selected.SHA256 == "" || len(payload) == 0 {
		if firstRelease && len(bindings) >= 2 && !bindings[0].Present && !bindings[1].Present && len(unresolved) == 0 {
			// errortrack path A, 30-10-2026: a secrets-host phase can precede a
			// deterministic stack preflight refusal. With a closed empty baseline,
			// no manifest and no stack services prove that nothing was deployed.
			services, err := rt.dockerRead(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+record.App, "--format", "{{.ID}}")
			if err != nil {
				unresolved = append(unresolved, "cannot inspect first-release services: "+boundedRecoveryText(err.Error()))
				return bindings, selected, payload, currentDigest, previousDigest, manifestProof, serviceStateNotObserved, nil, routeStateNotObserved, keepImages, keepVersions, infrastructureReapplyAllowed, unresolved
			}
			if strings.TrimSpace(services) != "" {
				unresolved = append(unresolved, "first-release services exist without a retained manifest")
				return bindings, selected, payload, currentDigest, previousDigest, manifestProof, serviceStateNotObserved, nil, routeStateNotObserved, keepImages, keepVersions, infrastructureReapplyAllowed, unresolved
			}
			return bindings, selected, payload, currentDigest, previousDigest, manifestProof, serviceStateFirstReleaseNoServices, nil, routeStateNotRequired, keepImages, keepVersions, infrastructureReapplyAllowed, unresolved
		}
		if record.Kind != "registry-gc" && len(unresolved) == 0 {
			unresolved = append(unresolved, "retained current manifest is unavailable")
		}
		return bindings, selected, payload, currentDigest, previousDigest, manifestProof, serviceStateNotObserved, nil, routeStateNotObserved, keepImages, keepVersions, infrastructureReapplyAllowed, unresolved
	}
	services, parseErr := rootStackServices(record.App, payload)
	if parseErr != nil {
		unresolved = append(unresolved, "selected retained manifest is invalid")
		return bindings, selected, payload, currentDigest, previousDigest, manifestProof, serviceStateNotObserved, nil, routeStateNotObserved, keepImages, keepVersions, infrastructureReapplyAllowed, unresolved
	}
	if record.Kind == "deploy" {
		var unresolvedInfra []string
		keepImages, keepVersions, infrastructureReapplyAllowed, unresolvedInfra = rt.assessInfrastructureImages(ctx, record.App, services)
		unresolved = append(unresolved, unresolvedInfra...)
		services = applyKeptInfrastructureImages(services, keepImages)
		if infrastructureReapplyAllowed && len(keepImages) > 0 {
			probe := recoveryAction{Kind: recoveryActionReapplyCurrent, KeepInfrastructureImages: keepImages}
			if len(probe.display(keepVersions)) > coord.MaxReasonBytes {
				unresolved = append(unresolved, "kept infrastructure recovery action exceeds the 512 byte action limit")
				infrastructureReapplyAllowed = false
			}
		}
	}
	identities, converged, inspectUnresolved := rt.observeServiceIdentities(ctx, record.App, services)
	unresolved = append(unresolved, inspectUnresolved...)
	serviceState := serviceStateMismatch
	if converged && len(inspectUnresolved) == 0 {
		serviceState = serviceStateMatch
	}
	routeState, routeUnresolved := rt.observeLoadedRoute(record.App, payload)
	unresolved = append(unresolved, routeUnresolved...)
	return bindings, selected, payload, currentDigest, previousDigest, manifestProof, serviceState, identities, routeState, keepImages, keepVersions, infrastructureReapplyAllowed, unresolved
}

// A build-only deploy failure can leave current.yml on an older Redis or
// RabbitMQ release while the stateful service has moved ahead (production-host,
// 2026-10-26). Reapplying that pin over newer data can downgrade the runtime.
// Read local image metadata only, keeping a newer same-major official image
// and refusing ambiguous or major-step decisions without contacting a registry.
func (rt *rootRecoveryRuntime) assessInfrastructureImages(ctx context.Context, app string, services []rootStackService) (map[string]recoveryInfrastructureImageProof, map[string]recoveryInfrastructureKeepVersions, bool, []string) {
	keepImages := make(map[string]recoveryInfrastructureImageProof)
	keepVersions := make(map[string]recoveryInfrastructureKeepVersions)
	allowed := true
	var unresolved []string
	byName := make(map[string]rootStackService, len(services))
	for _, service := range services {
		byName[service.Name] = service
	}
	for _, runtime := range infrastructureRuntimes {
		retainedService, present := byName[runtime.service]
		if !present {
			continue
		}
		assessment := assessInfrastructureService(ctx, rt.dockerRead, app, runtime, retainedService.Image)
		switch assessment.Verdict {
		case infrastructureImageRefused:
			allowed = false
			unresolved = append(unresolved, assessment.Refusal)
		case infrastructureImageKeepLive:
			keepImages[runtime.service] = recoveryInfrastructureImageProof{Live: assessment.Live, Retained: assessment.Retained}
			keepVersions[runtime.service] = recoveryInfrastructureKeepVersions{Live: assessment.LiveVersion, Retained: assessment.RetainedVersion}
		}
	}
	return keepImages, keepVersions, allowed, uniqueNonEmpty(unresolved)
}

func validateRecoveryInfrastructureImage(runtime infrastructureRuntime, image string) error {
	match := officialInfrastructureImage.FindStringSubmatch(strings.TrimSpace(image))
	if match == nil || match[1] != runtime.service {
		return fmt.Errorf("%s is not an official %s image pinned by digest", image, runtime.service)
	}
	return nil
}

func refusalToReplaceInfrastructure(service, live, retained string, reason error) string {
	return fmt.Sprintf("refusing to replace running %s %s with retained %s: %v; recover this service by hand", service, live, retained, reason)
}

func readRecoveryInfrastructureVersion(ctx context.Context, read infrastructureDockerRead, runtime infrastructureRuntime, role, image string) (string, error) {
	lookup := recoveryInfrastructureInspectReference(image)
	body, err := read(ctx, "image", "inspect", "--format", "{{json .Config.Env}}", lookup)
	if err != nil {
		return "", fmt.Errorf("cannot read the version of %s %s %s: image absent from the host; pull it as the administrator, then run recover again", role, runtime.service, image)
	}
	var environment []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &environment); err != nil {
		return "", fmt.Errorf("cannot read the version of %s %s %s: invalid image Config.Env: %v", role, runtime.service, image, err)
	}
	version, err := infrastructureVersionFromEnvironment(ctx, read, lookup, runtime.versionEnv, environment)
	if err != nil {
		return "", fmt.Errorf("cannot read the version of %s %s %s: %w", role, runtime.service, image, err)
	}
	return version, nil
}

func recoveryInfrastructureInspectReference(image string) string {
	repository := rootImageRepository(image)
	if slash := strings.LastIndex(repository, "/"); strings.LastIndex(repository, ":") > slash {
		repository = repository[:strings.LastIndex(repository, ":")]
	}
	return repository + "@" + rootImageDigest(image)
}

func compareInfrastructureVersions(left, right []int) int {
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func applyKeptInfrastructureImages(services []rootStackService, keepImages map[string]recoveryInfrastructureImageProof) []rootStackService {
	if len(keepImages) == 0 {
		return services
	}
	updated := append([]rootStackService(nil), services...)
	for index := range updated {
		if proof, kept := keepImages[updated[index].Name]; kept {
			updated[index].Image = proof.Live
			updated[index].Digest = rootImageDigest(proof.Live)
		}
	}
	return updated
}

func recoveryInfrastructureMapsEqual(left, right map[string]recoveryInfrastructureImageProof) bool {
	if len(left) != len(right) {
		return false
	}
	for service, image := range left {
		if right[service] != image {
			return false
		}
	}
	return true
}

func replaceKeptInfrastructureImages(payload []byte, keepImages map[string]recoveryInfrastructureImageProof) ([]byte, error) {
	if len(keepImages) == 0 {
		return payload, nil
	}
	// Change only the image scalars on a materialized copy. The authorized
	// retained bytes and their journaled SHA-256 remain the recovery authority.
	var document yaml.Node
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, err
	}
	root := documentRootMapping(&document)
	if root == nil {
		return nil, errors.New("manifest root is not a mapping")
	}
	services := yamlMappingValue(root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, errors.New("manifest services are not a mapping")
	}
	for service, proof := range keepImages {
		serviceNode := yamlMappingValue(services, service)
		if serviceNode == nil || serviceNode.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("kept infrastructure service %s is missing from manifest", service)
		}
		imageNode := yamlMappingValue(serviceNode, "image")
		if imageNode == nil || imageNode.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("kept infrastructure service %s has no image scalar", service)
		}
		imageNode.Value = proof.Live
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type yamlByteSpan struct {
	start int
	end   int
	value string
}

// replaceKeptInfrastructureImageSpans preserves every byte outside the
// selected image scalar values. yaml.Node columns count runes and do not give
// scalar ends, so each position is translated to a byte offset and the token
// extent is scanned according to its scalar style. Re-encoding this retained
// file would erase operator comments and formatting; uncertain syntax is refused.
func replaceKeptInfrastructureImageSpans(payload []byte, keepImages map[string]recoveryInfrastructureImageProof) ([]byte, error) {
	if len(keepImages) == 0 {
		return append([]byte(nil), payload...), nil
	}
	var document yaml.Node
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("parse retained manifest: %w", err)
	}
	root := documentRootMapping(&document)
	if root == nil {
		return nil, errors.New("manifest root is not a mapping")
	}
	services := yamlMappingValue(root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, errors.New("manifest services are not a mapping")
	}
	spans := make([]yamlByteSpan, 0, len(keepImages))
	for service, proof := range keepImages {
		serviceNode := yamlMappingValue(services, service)
		if serviceNode == nil || serviceNode.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("kept infrastructure service %s is missing from manifest", service)
		}
		imageNode := yamlMappingValue(serviceNode, "image")
		if imageNode == nil || imageNode.Kind != yaml.ScalarNode || imageNode.Value != proof.Retained {
			return nil, fmt.Errorf("kept infrastructure service %s image does not match the retained reference", service)
		}
		start, end, err := yamlScalarByteSpan(payload, imageNode)
		if err != nil {
			return nil, fmt.Errorf("locate %s image scalar: %w", service, err)
		}
		spans = append(spans, yamlByteSpan{start: start, end: end, value: proof.Live})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	for index := 1; index < len(spans); index++ {
		if spans[index].end > spans[index-1].start {
			return nil, errors.New("kept infrastructure image scalar spans overlap")
		}
	}
	prospective := append([]byte(nil), payload...)
	for _, span := range spans {
		updated := make([]byte, 0, len(prospective)-(span.end-span.start)+len(span.value))
		updated = append(updated, prospective[:span.start]...)
		updated = append(updated, span.value...)
		updated = append(updated, prospective[span.end:]...)
		prospective = updated
	}
	if err := validateOnlyKeptInfrastructureImagesDiffer(payload, prospective, keepImages); err != nil {
		return nil, err
	}
	if err := validateRetainedRootStack(prospective); err != nil {
		return nil, fmt.Errorf("rewritten current.yml is not a valid root stack: %w", err)
	}
	return prospective, nil
}

func yamlScalarByteSpan(payload []byte, node *yaml.Node) (int, int, error) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Line < 1 || node.Column < 1 || node.Style&yaml.TaggedStyle != 0 {
		return 0, 0, errors.New("scalar has no unambiguous source position or uses an explicit tag")
	}
	lineStart := 0
	for line := 1; line < node.Line; line++ {
		relative := bytes.IndexByte(payload[lineStart:], '\n')
		if relative < 0 {
			return 0, 0, errors.New("scalar line is outside the source document")
		}
		lineStart += relative + 1
	}
	lineEnd := len(payload)
	if relative := bytes.IndexByte(payload[lineStart:], '\n'); relative >= 0 {
		lineEnd = lineStart + relative
	}
	if lineEnd > lineStart && payload[lineEnd-1] == '\r' {
		lineEnd--
	}
	lineBytes := payload[lineStart:lineEnd]
	position := 0
	for column := 1; column < node.Column; column++ {
		if position >= len(lineBytes) {
			return 0, 0, errors.New("scalar column is outside its source line")
		}
		_, width := utf8.DecodeRune(lineBytes[position:])
		if width == 0 || width == 1 && lineBytes[position] >= utf8.RuneSelf {
			return 0, 0, errors.New("scalar source line is not valid UTF-8")
		}
		position += width
	}
	if position >= len(lineBytes) {
		return 0, 0, errors.New("scalar starts past the end of its source line")
	}
	start := position
	end := -1
	replacementStart := start
	replacementEnd := -1
	switch {
	case node.Style&yaml.DoubleQuotedStyle != 0:
		if lineBytes[position] != '"' {
			return 0, 0, errors.New("double-quoted scalar does not start with a quote")
		}
		for cursor := position + 1; cursor < len(lineBytes); cursor++ {
			if lineBytes[cursor] == '\\' {
				cursor++
				continue
			}
			if lineBytes[cursor] == '"' {
				end = cursor + 1
				replacementStart = start + 1
				replacementEnd = cursor
				break
			}
		}
	case node.Style&yaml.SingleQuotedStyle != 0:
		if lineBytes[position] != '\'' {
			return 0, 0, errors.New("single-quoted scalar does not start with a quote")
		}
		for cursor := position + 1; cursor < len(lineBytes); cursor++ {
			if lineBytes[cursor] != '\'' {
				continue
			}
			if cursor+1 < len(lineBytes) && lineBytes[cursor+1] == '\'' {
				cursor++
				continue
			}
			end = cursor + 1
			replacementStart = start + 1
			replacementEnd = cursor
			break
		}
	default:
		for cursor := position; cursor < len(lineBytes); cursor++ {
			if lineBytes[cursor] == ' ' || lineBytes[cursor] == '\t' || lineBytes[cursor] == ',' || lineBytes[cursor] == ']' || lineBytes[cursor] == '}' {
				end = cursor
				break
			}
		}
		if end < 0 {
			end = len(lineBytes)
		}
		replacementEnd = end
	}
	if end <= start {
		return 0, 0, errors.New("scalar token extent cannot be determined")
	}
	var scalar string
	if err := yaml.Unmarshal(lineBytes[start:end], &scalar); err != nil || scalar != node.Value {
		return 0, 0, errors.New("source token does not exactly decode to the image scalar")
	}
	if replacementEnd < replacementStart {
		return 0, 0, errors.New("scalar value byte span cannot be determined")
	}
	return lineStart + replacementStart, lineStart + replacementEnd, nil
}

func validateOnlyKeptInfrastructureImagesDiffer(original, prospective []byte, keepImages map[string]recoveryInfrastructureImageProof) error {
	var before, after yaml.Node
	if err := yaml.Unmarshal(original, &before); err != nil {
		return fmt.Errorf("parse retained manifest for structural comparison: %w", err)
	}
	if err := yaml.Unmarshal(prospective, &after); err != nil {
		return fmt.Errorf("parse rewritten manifest for structural comparison: %w", err)
	}
	beforeImages, err := keptInfrastructureImageNodes(&before, keepImages)
	if err != nil {
		return err
	}
	afterImages, err := keptInfrastructureImageNodes(&after, keepImages)
	if err != nil {
		return err
	}
	for service, proof := range keepImages {
		if beforeImages[service].Value != proof.Retained || afterImages[service].Value != proof.Live {
			return fmt.Errorf("rewritten %s image does not match the planned kept reference", service)
		}
	}
	if !yamlNodesEqualExceptValues(&before, &after, beforeImages) {
		return errors.New("rewritten manifest changes fields outside the kept infrastructure image values")
	}
	return nil
}

func keptInfrastructureImageNodes(document *yaml.Node, keepImages map[string]recoveryInfrastructureImageProof) (map[string]*yaml.Node, error) {
	root := documentRootMapping(document)
	services := yamlMappingValue(root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, errors.New("manifest services are not a mapping")
	}
	images := make(map[string]*yaml.Node, len(keepImages))
	for service := range keepImages {
		serviceNode := yamlMappingValue(services, service)
		if serviceNode == nil || serviceNode.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("kept infrastructure service %s is missing from manifest", service)
		}
		image := yamlMappingValue(serviceNode, "image")
		if image == nil || image.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("kept infrastructure service %s has no image scalar", service)
		}
		images[service] = image
	}
	return images, nil
}

func yamlNodesEqualExceptValues(before, after *yaml.Node, beforeImages map[string]*yaml.Node) bool {
	if before == nil || after == nil || before.Kind != after.Kind || before.Style != after.Style || before.Tag != after.Tag || before.Anchor != after.Anchor || before.HeadComment != after.HeadComment || before.LineComment != after.LineComment || before.FootComment != after.FootComment || len(before.Content) != len(after.Content) {
		return false
	}
	ignoreValue := false
	for _, image := range beforeImages {
		if before == image {
			ignoreValue = true
			break
		}
	}
	if !ignoreValue && before.Value != after.Value {
		return false
	}
	if (before.Alias == nil) != (after.Alias == nil) {
		return false
	}
	if before.Alias != nil && after.Alias != nil && before.Alias.Value != after.Alias.Value {
		return false
	}
	for index := range before.Content {
		if !yamlNodesEqualExceptValues(before.Content[index], after.Content[index], beforeImages) {
			return false
		}
	}
	return true
}

func documentRootMapping(document *yaml.Node) *yaml.Node {
	if document == nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	return document.Content[0]
}

func yamlMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	var value *yaml.Node
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			if value != nil {
				return nil
			}
			value = mapping.Content[index+1]
		}
	}
	return value
}

func (rt *rootRecoveryRuntime) resolveAuthorizedManifests(record coord.Record, baseline operationwriters.Baseline, firstRelease bool) ([]recoveryManifestBinding, recoveryManifestBinding, []byte, string, string, []string) {
	var unresolved []string
	currentPath, err := rt.allowlistedManifestPath(record.App, "current.yml")
	if err != nil {
		return nil, recoveryManifestBinding{}, nil, "", "", []string{err.Error()}
	}
	previousPath, err := rt.allowlistedManifestPath(record.App, "previous.yml")
	if err != nil {
		return nil, recoveryManifestBinding{}, nil, "", "", []string{err.Error()}
	}
	currentBody, currentPresent, currentDigest, currentErr := rt.readOptionalManifest(currentPath)
	previousBody, previousPresent, previousDigest, previousErr := rt.readOptionalManifest(previousPath)
	if currentErr != nil {
		unresolved = append(unresolved, "retained current manifest is unavailable")
	}
	if previousErr != nil {
		unresolved = append(unresolved, "retained previous manifest is unavailable")
	}
	byHash := map[string]struct {
		path string
		body []byte
		role string
	}{}
	if currentPresent {
		byHash[normalizeDigest(currentDigest)] = struct {
			path string
			body []byte
			role string
		}{path: currentPath, body: currentBody, role: "current"}
	}
	if previousPresent {
		if _, exists := byHash[normalizeDigest(previousDigest)]; !exists {
			byHash[normalizeDigest(previousDigest)] = struct {
				path string
				body []byte
				role string
			}{path: previousPath, body: previousBody, role: "previous"}
		}
	}
	// ownCurrent accepts the deploy's original stack-apply proof or the exact
	// digest rebound by its recovery. Only this current slot and this record's
	// full digest qualify; CurrentManifestSHA256 remains the original deploy
	// proof so a recovery rewrite cannot alter ownPrevious authorization.
	recoveryOwnCurrent := currentPresent && record.RecoveryCurrentManifestSHA256 != "" && sameDigest(currentDigest, record.RecoveryCurrentManifestSHA256)
	ownCurrent := currentPresent && ((record.CurrentManifestSHA256 != "" && sameDigest(currentDigest, record.CurrentManifestSHA256)) || recoveryOwnCurrent)
	currentKnown := ownCurrent || hashAuthorized(currentDigest, baseline)
	if currentPresent && !currentKnown {
		// Leaving C1 Authorized=false only would let recovery look Safe while
		// an unknown live slot remains the file Swarm would keep serving.
		unresolved = append(unresolved, "unknown retained current artifact is not authorized")
	}
	// A deploy whose promotion rolled back rotates its own journaled manifest
	// into the previous slot. The same exact-digest, own-record proof makes it
	// known there; it is never selected, so recovery still converges on the
	// release the rollback restored (preprod, 2026-10-19).
	ownPrevious := previousPresent && record.CurrentManifestSHA256 != "" && sameDigest(previousDigest, record.CurrentManifestSHA256)
	previousKnown := ownPrevious || hashAuthorized(previousDigest, baseline)
	if previousPresent && !previousKnown {
		unresolved = append(unresolved, "unknown retained previous artifact is not authorized")
	}
	currentAuthorized := baseline.Current.Present && baseline.Current.FullSHA256 != ""
	previousAuthorized := baseline.Previous.Present && baseline.Previous.FullSHA256 != ""
	if currentAuthorized && !recoveryOwnCurrent {
		digest := normalizeDigest(baseline.Current.FullSHA256)
		if _, ok := byHash[digest]; !ok {
			body, archiveErr := rt.readArchivedBaseline(record.ID, "current", baseline.Current)
			if archiveErr != nil || len(body) == 0 {
				unresolved = append(unresolved, absentBaselineArtifact)
			} else {
				byHash[digest] = struct {
					path string
					body []byte
					role string
				}{path: currentPath, body: body, role: "current"}
			}
		}
	}
	if previousAuthorized {
		digest := normalizeDigest(baseline.Previous.FullSHA256)
		if _, ok := byHash[digest]; !ok {
			body, archiveErr := rt.readArchivedBaseline(record.ID, "previous", baseline.Previous)
			if archiveErr != nil || len(body) == 0 {
				unresolved = append(unresolved, absentBaselineArtifact)
			} else {
				byHash[digest] = struct {
					path string
					body []byte
					role string
				}{path: previousPath, body: body, role: "previous"}
			}
		}
	}
	firstReleaseNoArtifacts := firstRelease && !currentPresent && !previousPresent && currentErr == nil && previousErr == nil
	if !currentAuthorized && !currentPresent && record.Kind != "registry-gc" && !firstReleaseNoArtifacts {
		unresolved = append(unresolved, "retained current manifest is unavailable")
	}
	wanted := ""
	// A deploy that wrote its own current.yml converges on that file: the
	// stack Swarm was told to run is the operation's, so recovery observes the
	// live tasks against it and, if they differ, reapplies that same file and
	// proves convergence. Selecting the baseline here instead would roll back a
	// release that was healthy (web, 2026-10-08: running the journaled
	// digest, 1/1, while recovery planned to redeploy the one before it), and
	// would leave current.yml naming a stack that no longer runs.
	if record.Kind == "deploy" && ownCurrent {
		wanted = normalizeDigest(currentDigest)
	}
	if wanted == "" && record.Kind == "rollback" && previousAuthorized {
		wanted = normalizeDigest(baseline.Previous.FullSHA256)
	}
	if wanted == "" && currentAuthorized {
		wanted = normalizeDigest(baseline.Current.FullSHA256)
	}
	if wanted == "" && previousAuthorized {
		wanted = normalizeDigest(baseline.Previous.FullSHA256)
	}
	var selected recoveryManifestBinding
	var payload []byte
	if wanted != "" {
		if found, ok := byHash[wanted]; ok {
			selected = recoveryManifestBinding{Role: found.role, Path: found.path, SHA256: wanted, Present: true, Authorized: true, Selected: true}
			payload = found.body
		}
	}
	bindings := []recoveryManifestBinding{
		{Role: "current", Path: currentPath, SHA256: currentDigest, Present: currentPresent, Authorized: currentPresent && currentKnown, Selected: selected.Path == currentPath},
		{Role: "previous", Path: previousPath, SHA256: previousDigest, Present: previousPresent, Authorized: previousPresent && previousKnown, Selected: selected.Path == previousPath},
	}
	return bindings, selected, payload, currentDigest, previousDigest, uniqueNonEmpty(unresolved)
}

func (rt *rootRecoveryRuntime) readArchivedBaseline(operationID, role string, artifact operationwriters.BaselineArtifact) ([]byte, error) {
	if rt.readBaselineArtifact != nil {
		return rt.readBaselineArtifact(operationID, role, artifact)
	}
	return readRootOperationBaselineArtifact(operationID, role, artifact)
}

func (rt *rootRecoveryRuntime) loadAuthorizedManifestBytes(record coord.Record, path, wantSHA string) ([]byte, error) {
	if path != "" {
		if err := rt.requireAllowlistedManifestPath(record.App, path); err != nil {
			return nil, err
		}
		payload, err := rt.readBoundedRegular(path, rootplan.MaxSize)
		if err == nil && (wantSHA == "" || rootRecoveryDigest(payload) == wantSHA) {
			return payload, nil
		}
	} else if wantSHA == "" {
		var err error
		path, err = rt.allowlistedManifestPath(record.App, "current.yml")
		if err != nil {
			return nil, err
		}
		payload, err := rt.readBoundedRegular(path, rootplan.MaxSize)
		if err != nil {
			return nil, fmt.Errorf("read retained current manifest: %w", err)
		}
		return payload, nil
	}
	if wantSHA == "" {
		return nil, errors.New("retained selected manifest changed before apply")
	}
	body, err := rt.readArchivedManifest(record.ID, wantSHA)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (rt *rootRecoveryRuntime) readArchivedManifest(operationID, digest string) ([]byte, error) {
	artifact := operationwriters.BaselineArtifact{Present: true, FullSHA256: digest}
	for _, role := range []string{"current", "previous"} {
		body, err := rt.readArchivedBaseline(operationID, role, artifact)
		if err == nil && len(body) > 0 && rootRecoveryDigest(body) == normalizeDigest(digest) {
			return body, nil
		}
	}
	return nil, errors.New(absentBaselineArtifact)
}

func (rt *rootRecoveryRuntime) materializeManifestFile(app, path string, payload []byte) (string, error) {
	source := path
	if path != "" {
		if err := rt.requireAllowlistedManifestPath(app, path); err != nil {
			return "", err
		}
		existing, err := rt.readBoundedRegular(path, rootplan.MaxSize)
		if err != nil || !bytes.Equal(existing, payload) {
			tmp := filepath.Join(filepath.Dir(path), ".recovery-"+filepath.Base(path))
			if err := os.WriteFile(tmp, payload, 0o600); err != nil {
				return "", fmt.Errorf("materialize retained manifest: %w", err)
			}
			source = tmp
		}
	} else {
		var err error
		path, err = rt.allowlistedManifestPath(app, "current.yml")
		if err != nil {
			return "", err
		}
		tmp := filepath.Join(filepath.Dir(path), ".recovery-"+filepath.Base(path))
		if err := os.WriteFile(tmp, payload, 0o600); err != nil {
			return "", fmt.Errorf("materialize retained manifest: %w", err)
		}
		source = tmp
	}
	if rt.prepareStack != nil {
		return rt.prepareStack(app, source)
	}
	return source, nil
}

func (rt *rootRecoveryRuntime) loadDurableBackupReplicas(operationID string) (map[string]int, error) {
	if rt.readBackupReplicas != nil {
		return rt.readBackupReplicas(operationID)
	}
	return readRootOperationBackupReplicaProof(operationID)
}

func (rt *rootRecoveryRuntime) storeDurableBackupReplicas(operationID, app string, replicas map[string]int) error {
	if rt.preserveBackupReplicas != nil {
		return rt.preserveBackupReplicas(operationID, app, replicas)
	}
	return preserveRootOperationBackupReplicaProof(operationID, app, replicas)
}

func hashAuthorized(digest string, baseline operationwriters.Baseline) bool {
	digest = normalizeDigest(digest)
	if digest == "" {
		return false
	}
	if baseline.Current.Present && normalizeDigest(baseline.Current.FullSHA256) == digest {
		return true
	}
	if baseline.Previous.Present && normalizeDigest(baseline.Previous.FullSHA256) == digest {
		return true
	}
	return false
}

func (rt *rootRecoveryRuntime) observeLoadedRoute(app string, payload []byte) (string, []string) {
	want, err := caddyRouteFragment(app, payload)
	if err != nil {
		return routeStateNotObserved, []string{"retained Caddy route cannot be derived"}
	}
	if want == "" {
		return routeStateNotRequired, nil
	}
	if rt.loadedRoute == nil {
		return routeStateMismatch, nil
	}
	loaded, err := rt.loadedRoute(app)
	if err != nil {
		return routeStateMismatch, nil
	}
	if loadedRouteMatches(loaded, want) {
		return routeStateMatch, nil
	}
	return routeStateMismatch, nil
}

func loadedRouteMatches(loaded, want string) bool {
	if loaded == want {
		return true
	}
	if want == "" || loaded == "" {
		return false
	}
	addresses := caddyFragmentSiteAddresses(want)
	if len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if address == "" || !strings.Contains(loaded, address) {
			return false
		}
	}
	targets := caddyFragmentReverseProxyTargets(want)
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if target == "" || !strings.Contains(loaded, target) {
			return false
		}
	}
	return true
}

func caddyFragmentReverseProxyTargets(fragment string) []string {
	var targets []string
	for _, line := range strings.Split(fragment, "\n") {
		trimmed := strings.TrimSpace(line)
		rest, found := strings.CutPrefix(trimmed, "reverse_proxy ")
		if !found || strings.TrimSpace(rest) == "" {
			continue
		}
		targets = append(targets, strings.TrimSpace(rest))
	}
	return targets
}

func (rt *rootRecoveryRuntime) observeServiceIdentities(ctx context.Context, app string, services []rootStackService) ([]recoveryServiceIdentity, bool, []string) {
	roster, rosterErr := rt.serviceRoster(ctx, app)
	if rosterErr != nil {
		return nil, false, []string{"application service roster unavailable"}
	}
	identities := make([]recoveryServiceIdentity, 0, len(services))
	converged := true
	var unresolved []string
	for _, service := range services {
		tasks, tasksErr := rt.serviceTasks(ctx, service.Service)
		entry, listed := roster[service.Service]
		identity := recoveryServiceIdentity{Service: service.Service, WantDigest: service.Digest}
		if tasksErr != nil || !listed {
			converged = false
			identities = append(identities, identity)
			continue
		}
		verdict := evaluateRootServiceConvergence(service, entry, listed, tasks)
		if !verdict.Converged {
			converged = false
		}
		repairable, collectErr := rt.collectContainerIdentities(ctx, service, tasks, &identity)
		if collectErr != nil {
			unresolved = append(unresolved, boundedRecoveryText(collectErr.Error()))
			converged = false
		} else if repairable {
			converged = false
		}
		identity.Converged = verdict.Converged && !repairable && collectErr == nil
		sort.Slice(identity.Tasks, func(i, j int) bool { return identity.Tasks[i].ID < identity.Tasks[j].ID })
		identities = append(identities, identity)
	}
	return identities, converged, unresolved
}

func (rt *rootRecoveryRuntime) collectContainerIdentities(ctx context.Context, want rootStackService, tasks []rootServiceTask, identity *recoveryServiceIdentity) (repairable bool, err error) {
	found := 0
	for _, task := range tasks {
		item := recoveryTaskIdentity{
			ID:     strings.TrimSpace(task.ID),
			Digest: rootImageDigest(task.Image),
			State:  normalizeTaskState(task.CurrentState),
		}
		if !rootTaskStateIs(task.DesiredState, "running") {
			identity.Tasks = append(identity.Tasks, item)
			continue
		}
		if !rootTaskStateIs(task.CurrentState, "running") {
			identity.Tasks = append(identity.Tasks, item)
			repairable = true
			continue
		}
		containerID, containerErr := rt.taskContainerID(ctx, task.ID)
		if containerErr != nil || containerID == "" {
			identity.Tasks = append(identity.Tasks, item)
			repairable = true
			continue
		}
		inspected, inspectErr := rt.inspectContainer(ctx, containerID)
		if inspectErr != nil {
			return true, fmt.Errorf("inspect container of %s: %w", want.Service, inspectErr)
		}
		item.ContainerID = containerID
		item.Health = strings.ToLower(strings.TrimSpace(inspected.State.Health.Status))
		identity.Tasks = append(identity.Tasks, item)
		if !inspected.State.Running || !strings.EqualFold(inspected.State.Status, "running") {
			repairable = true
			continue
		}
		if !strings.EqualFold(item.Health, "healthy") {
			repairable = true
			continue
		}
		if !containerDigestMatches(want.Digest, inspected.Config.Image, inspected.Image) {
			repairable = true
			continue
		}
		found++
	}
	if found == 0 && want.Replicas != 0 {
		return true, nil
	}
	return repairable, nil
}

func (rt *rootRecoveryRuntime) inspectApplicationContainers(ctx context.Context, app string, services []rootStackService) error {
	_, converged, unresolved := rt.observeServiceIdentities(ctx, app, services)
	if len(unresolved) > 0 {
		return errors.New(unresolved[0])
	}
	if !converged {
		return fmt.Errorf("application %s tasks are not running the retained current release", app)
	}
	return nil
}

func (rt *rootRecoveryRuntime) waitCapturedReplicas(ctx context.Context, app string, services []rootStackService, replicas map[string]int) error {
	timeout := config.SwarmWorstCaseWaits(config.DefaultDeploySLOSeconds("")).StackConvergence
	deadline := rt.clock().Add(timeout)
	var last error
	for {
		last = rt.inspectCapturedReplicas(ctx, app, services, replicas)
		if last == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !rt.clock().Before(deadline) {
			return last
		}
		after := rt.after
		if after == nil {
			after = time.After
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-after(500 * time.Millisecond):
		}
	}
}

func (rt *rootRecoveryRuntime) inspectCapturedReplicas(ctx context.Context, app string, services []rootStackService, replicas map[string]int) error {
	wanted := make([]rootStackService, 0, len(services))
	for _, service := range services {
		count, ok := replicas[service.Service]
		if !ok {
			return errors.New("pending backup replica map membership does not match retained services")
		}
		service.Replicas = count
		wanted = append(wanted, service)
	}
	return rt.inspectApplicationContainers(ctx, app, wanted)
}

func confirmFreshRecoveryObservation(live, confirmed coord.RecoveryObservation) error {
	if !live.Safe {
		return errors.New("fresh recovery observation is unsafe")
	}
	if len(live.MissingProof) > 0 {
		return errors.New("fresh recovery observation is missing proof")
	}
	if live.ExecutorProof == "" || live.ExecutorProof != confirmed.ExecutorProof {
		return errors.New("closed writer proof changed before apply")
	}
	if live.ResourceVersion == "" || live.ResourceVersion != confirmed.ResourceVersion {
		return errors.New("resource version changed before apply")
	}
	if live.ActionProof != confirmed.ActionProof || live.ManifestProof != confirmed.ManifestProof || live.MarkerProof != confirmed.MarkerProof {
		return errors.New("recovery confirmation changed before apply")
	}
	if live.BootVersion != confirmed.BootVersion || live.ProcessVersion != confirmed.ProcessVersion || live.PhaseVersion != confirmed.PhaseVersion {
		return errors.New("recovery version proof changed before apply")
	}
	if live.ResourceProof != confirmed.ResourceProof {
		return errors.New("resource proof changed before apply")
	}
	return nil
}

func normalizeTaskState(state string) string {
	word, _ := rootFirstWord(state)
	return strings.ToLower(strings.TrimSpace(word))
}

func readAnchoredBoundedFile(root, path string, maxBytes int64) ([]byte, error) {
	cleanRoot := filepath.Clean(root)
	cleanPath := filepath.Clean(path)
	if !pathWithin(cleanRoot, cleanPath) {
		return nil, errors.New("path is not anchored")
	}
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, errors.New("path is not anchored")
	}
	if err := refuseSymlinkAncestors(cleanRoot); err != nil {
		return nil, err
	}
	dirfd, err := syscall.Open(cleanRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	components := strings.Split(rel, string(os.PathSeparator))
	for i, component := range components {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			_ = syscall.Close(dirfd)
			return nil, errors.New("path is not anchored")
		}
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if i < len(components)-1 {
			flags |= syscall.O_DIRECTORY
		} else {
			// FIFO current.yml would block Read without this, so recovery
			// could hang instead of refusing a non-regular file.
			flags |= syscall.O_NONBLOCK
		}
		next, openErr := syscall.Openat(dirfd, component, flags, 0)
		_ = syscall.Close(dirfd)
		if openErr != nil {
			if errors.Is(openErr, syscall.ENOENT) {
				return nil, os.ErrNotExist
			}
			return nil, openErr
		}
		dirfd = next
	}
	file := os.NewFile(uintptr(dirfd), cleanPath)
	if file == nil {
		_ = syscall.Close(dirfd)
		return nil, errors.New("anchored file descriptor is invalid")
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("retained stack manifest is not a bounded regular file")
	}
	if maxBytes > 0 && int64(stat.Size) > maxBytes {
		return nil, errors.New("retained stack manifest is not a bounded regular file")
	}
	limit := maxBytes
	if limit <= 0 {
		limit = rootplan.MaxSize
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("retained stack manifest is not a bounded regular file")
	}
	return body, nil
}

func (rt *rootRecoveryRuntime) serviceRoster(ctx context.Context, app string) (map[string]rootServiceRoster, error) {
	body, err := rt.dockerRead(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", rootServiceRosterFormat)
	if err != nil {
		return nil, err
	}
	return parseRootServiceRoster(body), nil
}

func (rt *rootRecoveryRuntime) serviceTasks(ctx context.Context, service string) ([]rootServiceTask, error) {
	body, err := rt.dockerRead(ctx, "service", "ps", "--no-trunc", "--no-resolve", "--format", rootServiceTaskFormat, service)
	if err != nil {
		return nil, err
	}
	return parseRootServiceTasks(body), nil
}

func (rt *rootRecoveryRuntime) taskContainerID(ctx context.Context, taskID string) (string, error) {
	body, err := rt.dockerRead(ctx, "inspect", "--format", "{{json .}}", taskID)
	if err != nil {
		return "", err
	}
	var inspected recoveryTaskInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &inspected); err != nil {
		return "", err
	}
	return strings.TrimSpace(inspected.Status.ContainerStatus.ContainerID), nil
}

func (rt *rootRecoveryRuntime) inspectContainer(ctx context.Context, containerID string) (recoveryContainerInspect, error) {
	body, err := rt.dockerRead(ctx, "inspect", "--format", "{{json .}}", containerID)
	if err != nil {
		return recoveryContainerInspect{}, err
	}
	var inspected recoveryContainerInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &inspected); err != nil {
		return recoveryContainerInspect{}, err
	}
	return inspected, nil
}

func (rt *rootRecoveryRuntime) deriveActions(record coord.Record, kindSupported bool, marker *pendingBackupMarker, markerProof string, durableReplicas map[string]int, registryState, serviceState, routeState string, selected recoveryManifestBinding, identities []recoveryServiceIdentity, runTargetState string, infrastructureReapplyAllowed bool, keepInfrastructureImages map[string]recoveryInfrastructureImageProof, recordKeptInfrastructure, syncRecoveryCurrentDirectory, removeFirstRelease bool) []recoveryAction {
	if !kindSupported {
		return nil
	}
	if record.Kind == "run" {
		if runTargetState == "running" && record.RunTarget != nil && selected.Selected && selected.SHA256 != "" {
			return []recoveryAction{{
				Kind: recoveryActionReplaceRunTasks, App: record.App,
				Service: record.RunTarget.Service, Container: record.RunTarget.Container,
				ManifestPath: selected.Path, ManifestSHA256: selected.SHA256,
			}}
		}
		return nil
	}
	if record.Kind == "helper-update" || record.Kind == "secrets-sync" {
		// Failed helper-update before replacement is verification only.
		// Registry, stack, and Caddy repairs belong to other kinds. A
		// secrets-sync never changes the stack, the registry or the edge: an
		// interrupted one (watchdog, crash) only needs its state observed so
		// the fence it left can be released.
		return nil
	}
	var actions []recoveryAction
	if record.Kind == "backup" {
		replicas := map[string]int(nil)
		if marker != nil {
			replicas = marker.Replicas
		} else if replicaTargetsNeedRestore(identities, durableReplicas) {
			replicas = durableReplicas
		}
		if len(replicas) > 0 {
			action := recoveryAction{
				Kind:        recoveryActionRestoreBackupReplicas,
				App:         record.App,
				MarkerPath:  rt.pendingBackupMarkerPath(record.App),
				MarkerProof: markerProof,
				Replicas:    copyReplicaMap(replicas),
			}
			if selected.Selected {
				action.ManifestPath = selected.Path
				action.ManifestSHA256 = selected.SHA256
			}
			actions = append(actions, action)
		}
	}
	if registryState == registryStateRecreatable {
		actions = append(actions, recoveryAction{Kind: recoveryActionRecreateRegistry})
	}
	if registryState == registryStateStopped || registryState == registryStateUnhealthy {
		actions = append(actions, recoveryAction{Kind: recoveryActionRestartRegistry})
	}
	if record.Kind == "deploy" || record.Kind == "rollback" {
		if selected.Selected && selected.SHA256 != "" {
			if removeFirstRelease {
				actions = append(actions, recoveryAction{
					Kind: recoveryActionRemoveFirstRelease, App: record.App,
					ManifestPath: selected.Path, ManifestSHA256: selected.SHA256,
				})
			} else if serviceState == serviceStateMismatch && (record.Kind != "deploy" || infrastructureReapplyAllowed) {
				action := recoveryAction{Kind: recoveryActionReapplyCurrent, App: record.App, ManifestPath: selected.Path, ManifestSHA256: selected.SHA256}
				if record.Kind == "deploy" && len(keepInfrastructureImages) > 0 {
					action.KeepInfrastructureImages = copyRecoveryInfrastructureImageProofMap(keepInfrastructureImages)
				}
				actions = append(actions, action)
			}
			if !removeFirstRelease && routeState == routeStateMismatch {
				actions = append(actions, recoveryAction{Kind: recoveryActionApplyCaddyRoute, App: record.App, ManifestPath: selected.Path, ManifestSHA256: selected.SHA256})
			}
		}
	}
	if !removeFirstRelease && record.Kind == "deploy" && recordKeptInfrastructure && selected.Selected && selected.Path != "" && selected.SHA256 != "" {
		actions = append(actions, recoveryAction{
			Kind: recoveryActionRecordKeptInfrastructure, App: record.App,
			ManifestPath: selected.Path, ManifestSHA256: selected.SHA256,
			KeepInfrastructureImages: copyRecoveryInfrastructureImageProofMap(keepInfrastructureImages),
		})
	}
	if !removeFirstRelease && syncRecoveryCurrentDirectory && selected.Selected && selected.Path != "" && selected.SHA256 != "" {
		actions = append(actions, recoveryAction{
			Kind: recoveryActionSyncCurrentDirectory, App: record.App,
			ManifestPath: selected.Path, ManifestSHA256: selected.SHA256,
		})
	}
	return actions
}

func (rt *rootRecoveryRuntime) readPendingBackupMarker(record coord.Record) (*pendingBackupMarker, string, []string) {
	marker, path, err := rt.loadPendingBackupMarker(record)
	if err != nil {
		return nil, "", []string{err.Error()}
	}
	if marker == nil {
		return nil, rootRecoveryDigest([]byte(`{"pending_backup":false}`)), nil
	}
	return marker, canonicalMarkerProof(*marker, path), nil
}

func (rt *rootRecoveryRuntime) loadPendingBackupMarker(record coord.Record) (*pendingBackupMarker, string, error) {
	if record.App == "" || !rootAppName.MatchString(record.App) {
		return nil, "", nil
	}
	path := rt.pendingBackupMarkerPath(record.App)
	if !pathWithin(rt.backupStaging, path) || path != filepath.Join(rt.backupStaging, record.App+".pending.json") {
		return nil, "", errors.New("pending backup marker path is not a bounded anchored file")
	}
	body, err := rt.readBoundedRegular(path, rootRecoveryMaxMarkerBytes)
	if os.IsNotExist(err) {
		return nil, path, nil
	}
	if err != nil {
		return nil, path, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var marker pendingBackupMarker
	if err := decoder.Decode(&marker); err != nil {
		return nil, path, errors.New("pending backup marker identity or replica record is invalid")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, path, errors.New("pending backup marker contains trailing JSON")
	}
	if marker.App != record.App || marker.OperationID != record.ID || len(marker.Replicas) == 0 {
		return nil, path, errors.New("pending backup marker identity or replica record is invalid")
	}
	if marker.Work != "" {
		work := filepath.Clean(marker.Work)
		if !filepath.IsAbs(work) || !pathWithin(rt.backupStaging, work) {
			return nil, path, errors.New("pending backup marker staging path is invalid")
		}
		marker.Work = work
	}
	for service, replicas := range marker.Replicas {
		if !rootServiceName.MatchString(service) || !strings.HasPrefix(service, record.App+"_") || replicas < 0 || replicas > 1000 {
			return nil, path, errors.New("pending backup marker contains an unsafe service or replica count")
		}
	}
	return &marker, path, nil
}

func (rt *rootRecoveryRuntime) removeVerifiedPendingBackupMarker(record coord.Record, marker *pendingBackupMarker) error {
	path := rt.pendingBackupMarkerPath(record.App)
	current, _, err := rt.loadPendingBackupMarker(record)
	if err != nil || current == nil {
		return errors.New("pending backup marker changed before verified removal")
	}
	if canonicalMarkerProof(*current, path) != canonicalMarkerProof(*marker, path) || !replicaMapsEqual(current.Replicas, marker.Replicas) {
		return errors.New("pending backup marker changed before verified removal")
	}
	if err := rt.remove(path); err != nil {
		return err
	}
	if rt.syncDir == nil {
		return errors.New("pending backup marker parent cannot be synced")
	}
	if err := rt.syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync pending backup marker parent: %w", err)
	}
	return nil
}

func (rt *rootRecoveryRuntime) pendingBackupMarkerPath(app string) string {
	return filepath.Join(rt.backupStaging, app+".pending.json")
}

func (rt *rootRecoveryRuntime) allowlistedManifestPath(app, name string) (string, error) {
	if !rootAppName.MatchString(app) || (name != "current.yml" && name != "previous.yml") {
		return "", errors.New("retained stack path is not allowlisted")
	}
	path := filepath.Clean(filepath.Join(rt.appStateRoot, app, name))
	if !pathWithin(rt.appStateRoot, path) {
		return "", errors.New("retained stack path is not allowlisted")
	}
	return path, nil
}

func (rt *rootRecoveryRuntime) requireAllowlistedManifestPath(app, path string) error {
	current, err := rt.allowlistedManifestPath(app, "current.yml")
	if err != nil {
		return err
	}
	previous, err := rt.allowlistedManifestPath(app, "previous.yml")
	if err != nil {
		return err
	}
	if path != current && path != previous {
		return errors.New("retained stack path is not allowlisted")
	}
	return nil
}

func (rt *rootRecoveryRuntime) readOptionalManifest(path string) ([]byte, bool, string, error) {
	body, err := rt.readBoundedRegular(path, rootplan.MaxSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, "", nil
		}
		return nil, false, "", err
	}
	return body, true, rootRecoveryDigest(body), nil
}

func (rt *rootRecoveryRuntime) readBoundedRegular(path string, maxBytes int64) ([]byte, error) {
	root := rt.anchorRootFor(path)
	if rt.readAnchored != nil {
		return rt.readAnchored(root, path, maxBytes)
	}
	return readAnchoredBoundedFile(root, path, maxBytes)
}

func (rt *rootRecoveryRuntime) anchorRootFor(path string) string {
	switch {
	case rt.appStateRoot != "" && pathWithin(rt.appStateRoot, path):
		return rt.appStateRoot
	case rt.backupStaging != "" && pathWithin(rt.backupStaging, path):
		return rt.backupStaging
	case rt.caddyDir != "" && pathWithin(rt.caddyDir, path):
		return rt.caddyDir
	case rt.helperMigrationIntent != "":
		root := filepath.Dir(filepath.Clean(rt.helperMigrationIntent))
		if pathWithin(root, path) {
			return root
		}
		fallthrough
	default:
		return filepath.Dir(filepath.Clean(path))
	}
}

func (rt *rootRecoveryRuntime) readTrimmed(path string) (string, error) {
	body, err := rt.readFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (rt *rootRecoveryRuntime) clock() time.Time {
	if rt.now == nil {
		return time.Now().UTC()
	}
	return rt.now()
}

func helperUpdateRecordIdle(record coord.Record) bool {
	// A live helper-update lease still owns the global fence. Recovery is
	// only the failed-before-replacement case already marked recovery_required.
	return record.State == coord.RecoveryRequired && record.RecoveryRequired
}

func helperUpdateRecordExecutorProof(record coord.Record) string {
	// Bind only journal identity and lease evidence. Revision, events, and
	// recovery-start intent change under the apply flock and must not break
	// the existing dry-run digest confirmation.
	payload, _ := json.Marshal(struct {
		ID               string `json:"id"`
		Kind             string `json:"kind"`
		State            string `json:"state"`
		RecoveryRequired bool   `json:"recovery_required"`
		LeaseUntil       string `json:"lease_until"`
		HostBootID       string `json:"host_boot_id"`
	}{ID: record.ID, Kind: record.Kind, State: record.State, RecoveryRequired: record.RecoveryRequired, LeaseUntil: record.LeaseUntil, HostBootID: record.HostBootID})
	return rootRecoveryDigest(payload)
}

func (rt *rootRecoveryRuntime) observeHelperMigrationIntent(record coord.Record) []string {
	// Two host files can show that a helper swap was reached, and both must
	// rule it out before the global record is released:
	//
	// intent.json is written in phase prepared before a migration swap and
	// only reaches completed after finalization. Prepared or replaced means a
	// helper may be half migrated; releasing the fence then would let a deploy
	// or a second helper update run against a helper nobody finalized. A
	// completed intent is terminal and says nothing about this reservation,
	// because its id is a random migration id and never an operation id. An
	// earlier draft compared that id with the operation id, which is always
	// different, so it proved nothing.
	//
	// own-reservation.json is written by admitHelperMigrationOwnReservation,
	// naming the operation, before the candidate probe and replacement. It is
	// cleared on completion or a confirmed failed probe without any intent. If it names this
	// operation, the rename may have happened, so "failed before replacement"
	// is not proven and recovery stays refused. A proof left by another
	// operation does not concern this one.
	//
	// Both files are decoded strictly and validated with the same rules the
	// migration code applies, so a truncated or hand-edited file is refused
	// instead of being read as "absent" or "completed".
	path := filepath.Clean(strings.TrimSpace(rt.helperMigrationIntent))
	if path == "." || !filepath.IsAbs(path) {
		return []string{"helper-update migration intent path is not configured"}
	}
	var unresolved []string
	var intent helperMigrationIntent
	present, err := rt.decodeHelperMigrationFile(path, &intent)
	switch {
	case err != nil:
		unresolved = append(unresolved, "helper-update migration intent cannot be read")
	case !present:
	case intent.validate() != nil:
		unresolved = append(unresolved, "helper-update migration intent is invalid or has an unknown phase")
	case intent.Phase != helperMigrationPhaseComplete:
		unresolved = append(unresolved, "helper-update migration intent is still pending")
	}
	var own helperMigrationOwnReservationProof
	present, err = rt.decodeHelperMigrationFile(helperMigrationOwnReservationPath(helperMigrationPaths{IntentPath: path}), &own)
	switch {
	case err != nil:
		unresolved = append(unresolved, "helper-update own reservation proof cannot be read")
	case !present:
	case own.validate() != nil:
		unresolved = append(unresolved, "helper-update own reservation proof is invalid")
	case own.OperationID == record.ID:
		unresolved = append(unresolved, "helper-update candidate was admitted for this operation; helper replacement is not excluded")
	}
	return unresolved
}

// decodeHelperMigrationFile reads one bounded, anchored, non-symlink JSON
// document. A missing file is reported as not present, never as an error, and
// unknown fields or trailing JSON are refused.
func (rt *rootRecoveryRuntime) decodeHelperMigrationFile(path string, target any) (bool, error) {
	body, err := rt.readBoundedRegular(path, helperMigrationMaxIntentBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false, err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return false, errors.New("helper migration file contains trailing JSON")
	}
	return true, nil
}

func (a recoveryAction) display(keepVersions map[string]recoveryInfrastructureKeepVersions) string {
	switch a.Kind {
	case recoveryActionRestoreBackupReplicas:
		return "restore original backup replica counts and verify every application task"
	case recoveryActionRestartRegistry:
		return "start the existing loopback registry and verify health"
	case recoveryActionRecreateRegistry:
		return "recreate the journaled loopback registry on its verified existing volume and verify health"
	case recoveryActionReapplyCurrent:
		display := "reapply the retained current manifest and revalidate application task digests"
		for _, runtime := range infrastructureRuntimes {
			versions, kept := keepVersions[runtime.service]
			if kept {
				display += fmt.Sprintf("; keep %s %s (retained %s)", runtime.service, versions.Live, versions.Retained)
			}
		}
		return display
	case recoveryActionRemoveFirstRelease:
		return "remove unconverged first-release services, current.yml and its route; keep volumes, secrets and databases"
	case recoveryActionApplyCaddyRoute:
		return "apply the retained Caddy route and verify the route"
	case recoveryActionRecordKeptInfrastructure:
		return "record kept infrastructure images in current.yml"
	case recoveryActionSyncCurrentDirectory:
		return "sync current.yml directory"
	case recoveryActionReplaceRunTasks:
		return "replace tasks for " + a.App + "_" + a.Service + " and verify the journaled container stopped and healthy replicas returned"
	case recoveryActionCompleteDestroy:
		return "complete destroy cleanup for " + a.App + ": remove remaining services, networks, containers, volumes, secrets, credentials, state and Caddy route, then reload Caddy; PostgreSQL decisions and dump paths are listed in details"
	default:
		return string(a.Kind)
	}
}

func recoveryActionDisplays(actions []recoveryAction, keepVersions map[string]recoveryInfrastructureKeepVersions) []string {
	if len(actions) == 0 {
		return nil
	}
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		out = append(out, action.display(keepVersions))
	}
	return out
}

func canonicalActionProof(actions []recoveryAction) (string, error) {
	if actions == nil {
		actions = []recoveryAction{}
	}
	cloned := make([]recoveryAction, len(actions))
	for i, action := range actions {
		cloned[i] = action
		cloned[i].Replicas = copyReplicaMap(action.Replicas)
		cloned[i].KeepInfrastructureImages = copyRecoveryInfrastructureImageProofMap(action.KeepInfrastructureImages)
	}
	body, err := json.Marshal(cloned)
	if err != nil {
		return "", err
	}
	return rootRecoveryDigest(body), nil
}

func canonicalManifestProof(bindings []recoveryManifestBinding) string {
	body, _ := json.Marshal(bindings)
	return rootRecoveryDigest(body)
}

func canonicalMarkerProof(marker pendingBackupMarker, path string) string {
	payload := struct {
		Path        string         `json:"path"`
		App         string         `json:"app"`
		OperationID string         `json:"operation_id"`
		Replicas    map[string]int `json:"replicas"`
		Work        string         `json:"work"`
	}{Path: path, App: marker.App, OperationID: marker.OperationID, Replicas: copyReplicaMap(marker.Replicas), Work: marker.Work}
	body, _ := json.Marshal(payload)
	return rootRecoveryDigest(body)
}

func recoveryResourceProof(closedProof string, observation coord.RecoveryObservation, baseline operationwriters.Baseline, registry recoveryRegistryIdentity, manifests []recoveryManifestBinding, marker *pendingBackupMarker, services []recoveryServiceIdentity, actionProof, routeState string, selectedPayload []byte) []byte {
	payload := struct {
		ClosedProof    string                    `json:"closed_proof"`
		ProcessVersion string                    `json:"process_version"`
		BootVersion    string                    `json:"boot_version"`
		PhaseVersion   string                    `json:"phase_version"`
		Baseline       operationwriters.Baseline `json:"baseline"`
		Registry       recoveryRegistryIdentity  `json:"registry"`
		Manifests      []recoveryManifestBinding `json:"manifests"`
		MarkerProof    string                    `json:"marker_proof"`
		PendingBackup  bool                      `json:"pending_backup"`
		Replicas       int                       `json:"original_replicas"`
		Services       []recoveryServiceIdentity `json:"services"`
		ActionProof    string                    `json:"action_proof"`
		RouteState     string                    `json:"route_state"`
		SelectedSHA    string                    `json:"selected_manifest_sha256,omitempty"`
		PGVersion      string                    `json:"configured_native_pg_version"`
		PGCluster      string                    `json:"configured_native_pg_cluster"`
		CurrentDigest  string                    `json:"current_digest"`
		PreviousDigest string                    `json:"previous_digest"`
	}{
		ClosedProof: closedProof, ProcessVersion: observation.ProcessVersion, BootVersion: observation.BootVersion,
		PhaseVersion: observation.PhaseVersion, Baseline: baseline, Registry: registry, Manifests: manifests,
		MarkerProof: observation.MarkerProof, PendingBackup: observation.PendingBackup, Replicas: observation.OriginalReplicas,
		Services: services, ActionProof: actionProof, RouteState: routeState, SelectedSHA: rootRecoveryDigest(selectedPayload),
		PGVersion: baseline.ConfiguredNativePGVersion, PGCluster: baseline.ConfiguredNativePGCluster,
		CurrentDigest: observation.CurrentDigest, PreviousDigest: observation.PreviousDigest,
	}
	body, _ := json.Marshal(payload)
	return body
}

func validateLoopbackRegistryBindings(bindings map[string][]recoveryPortBinding) error {
	if len(bindings) == 0 {
		return errors.New("registry restart policy or loopback binding is unsafe")
	}
	found := false
	for port, entries := range bindings {
		if len(entries) == 0 {
			return errors.New("registry has an additional public binding")
		}
		for _, entry := range entries {
			if entry.HostPort != "5000" || !loopbackHostIP(entry.HostIP) || port != "5000/tcp" {
				return errors.New("registry has an additional public binding")
			}
			found = true
		}
	}
	if !found {
		return errors.New("registry restart policy or loopback binding is unsafe")
	}
	return nil
}

func canonicalRegistryBindings(bindings map[string][]recoveryPortBinding) []string {
	out := make([]string, 0, len(bindings))
	for port, entries := range bindings {
		for _, entry := range entries {
			out = append(out, entry.HostIP+"|"+entry.HostPort+"|"+port)
		}
	}
	sort.Strings(out)
	return out
}

func loopbackHostIP(value string) bool {
	switch strings.TrimSpace(value) {
	case "127.0.0.1", "127.0.0.1/32":
		return true
	default:
		return false
	}
}

func registryImageMatchesPin(configImage string, repoDigests []string) bool {
	match := officialInfrastructureImage.FindStringSubmatch(strings.TrimSpace(configImage))
	if match == nil || match[1] != "registry" {
		return false
	}
	digest := rootImageDigest(configImage)
	if digest == "" {
		return false
	}
	want := "registry@" + digest
	for _, repoDigest := range repoDigests {
		if strings.TrimSpace(repoDigest) == want {
			return true
		}
	}
	return false
}

func containerDigestMatches(wantDigest, configImage, imageID string) bool {
	if wantDigest == "" {
		return false
	}
	if digest := rootImageDigest(configImage); digest != "" {
		return digest == wantDigest
	}
	return imageID == wantDigest
}

func sameDigest(left, right string) bool {
	left, right = normalizeDigest(left), normalizeDigest(right)
	return left != "" && left == right
}

func normalizeDigest(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "sha256:") {
		return value
	}
	if len(value) == 64 {
		return "sha256:" + value
	}
	return value
}

func replicaMembershipMatches(services []rootStackService, replicas map[string]int) error {
	names := make(map[string]struct{}, len(services))
	for _, service := range services {
		names[service.Service] = struct{}{}
	}
	if len(names) != len(replicas) {
		return errors.New("pending backup replica map membership does not match retained services")
	}
	for service := range replicas {
		if _, ok := names[service]; !ok {
			return errors.New("pending backup replica map membership does not match retained services")
		}
	}
	return nil
}

func copyReplicaMap(values map[string]int) map[string]int {
	if values == nil {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func copyStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func copyRecoveryInfrastructureImageProofMap(values map[string]recoveryInfrastructureImageProof) map[string]recoveryInfrastructureImageProof {
	if values == nil {
		return nil
	}
	out := make(map[string]recoveryInfrastructureImageProof, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func copyRecoveryInfrastructureKeepVersions(values map[string]recoveryInfrastructureKeepVersions) map[string]recoveryInfrastructureKeepVersions {
	if values == nil {
		return nil
	}
	out := make(map[string]recoveryInfrastructureKeepVersions, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func replicaTargetsNeedRestore(identities []recoveryServiceIdentity, replicas map[string]int) bool {
	if len(replicas) == 0 {
		return false
	}
	healthy := make(map[string]int, len(replicas))
	for _, identity := range identities {
		count := 0
		for _, task := range identity.Tasks {
			if task.State == "running" && task.ContainerID != "" && (task.Health == "" || strings.EqualFold(task.Health, "healthy")) {
				count++
			}
		}
		healthy[identity.Service] = count
	}
	return !replicaMapsEqual(healthy, replicas)
}

func replicaMapsEqual(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		rightValue, ok := right[key]
		if !ok || rightValue != value {
			return false
		}
	}
	return true
}

func replicaTotal(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func sortedReplicaServices(replicas map[string]int) []string {
	services := make([]string, 0, len(replicas))
	for service := range replicas {
		services = append(services, service)
	}
	sort.Strings(services)
	return services
}

func manifestBinding(bindings []recoveryManifestBinding, role string) recoveryManifestBinding {
	for _, binding := range bindings {
		if binding.Role == role {
			return binding
		}
	}
	return recoveryManifestBinding{}
}

// refuseSymlinkAncestors rejects a recovery read whose anchor was reached
// through a symlink. Open of the last component with O_NOFOLLOW still follows
// parent directories, which would let a swapped ancestor redirect the read.
func refuseSymlinkAncestors(path string) error {
	current := filepath.Clean(path)
	for current != string(os.PathSeparator) && current != "." {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path is not anchored")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return true
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = boundedRecoveryText(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func boundedRecoveryText(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

func rootRecoveryDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Only stable identity metadata enters this proof, never usage statistics.
// Docker can reuse a deleted volume's name and mountpoint; its creation time
// must match too, otherwise recreating the registry would conceal lost data.
func rootRegistryVolumeProof(body string) (string, error) {
	var volume struct {
		Name       string
		Driver     string
		Scope      string
		Mountpoint string
		CreatedAt  string
		Options    map[string]string
		Labels     map[string]string
	}
	if err := json.Unmarshal([]byte(body), &volume); err != nil {
		return "", errors.New("registry volume metadata is unreadable")
	}
	if volume.Name != rootRegistryVolume || volume.Driver != "local" || volume.Scope != "local" || !filepath.IsAbs(volume.Mountpoint) || strings.ContainsAny(volume.Mountpoint, "\x00\r\n") {
		return "", errors.New("registry volume identity is unsafe")
	}
	if _, err := time.Parse(time.RFC3339Nano, volume.CreatedAt); err != nil {
		return "", errors.New("registry volume creation identity is unavailable")
	}
	canonical, err := json.Marshal(volume)
	if err != nil {
		return "", err
	}
	return rootRecoveryDigest(canonical), nil
}

func (rt *rootRecoveryRuntime) observeMissingRegistry(ctx context.Context, record coord.Record) (recoveryRegistryIdentity, string, []string) {
	intent := record.RegistryReplacement
	identity := recoveryRegistryIdentity{}
	if record.Kind != "deploy" || intent == nil || intent.Validate() != nil {
		return identity, registryStateUnsafe, []string{"missing registry has no valid replacement proof"}
	}
	identity.Image = intent.Image
	identity.RestartPolicy = "always"
	identity.Bindings = canonicalRegistryBindings(map[string][]recoveryPortBinding{"5000/tcp": {{HostIP: "127.0.0.1", HostPort: "5000"}}})
	volume, err := rt.dockerRead(ctx, "volume", "inspect", rootRegistryVolume, "--format", "{{json .}}")
	if err != nil {
		return identity, registryStateUnsafe, []string{"journaled registry volume is unavailable"}
	}
	proof, err := rootRegistryVolumeProof(volume)
	if err != nil || proof != intent.VolumeSHA256 {
		return identity, registryStateUnsafe, []string{"registry volume does not match the journaled replacement"}
	}
	identity.VolumeSHA256 = proof
	body, err := rt.dockerRead(ctx, "image", "inspect", intent.Image)
	var images []struct {
		ID          string `json:"Id"`
		RepoDigests []string
	}
	if err != nil || json.Unmarshal([]byte(body), &images) != nil || len(images) != 1 || !registryImageMatchesPin(intent.Image, images[0].RepoDigests) {
		return identity, registryStateWrongImage, []string{"journaled registry image is unavailable or does not match its digest"}
	}
	identity.ImageID = images[0].ID
	return identity, registryStateRecreatable, nil
}

func (rt *rootRecoveryRuntime) executeRecreateRegistry(ctx context.Context, record coord.Record) error {
	// ApplyRecovery holds the host journal flock, rejects other live operations
	// and rechecks the confirmed resource proof. Recheck absence and the volume
	// here as well; a Docker inspection error is never permission to create data.
	_, state, _ := rt.observeRegistry(ctx, nil)
	if state != registryStateMissing {
		return errors.New("registry is no longer proven absent before recreation")
	}
	identity, state, unresolved := rt.observeMissingRegistry(ctx, record)
	if state != registryStateRecreatable {
		return fmt.Errorf("refuse registry recreation: %s", strings.Join(unresolved, "; "))
	}
	rootRegistryImage = identity.Image
	if err := rt.dockerRun(ctx, rootRegistryChownArgs()...); err != nil {
		return err
	}
	if err := rt.dockerRun(ctx, rootRegistryCreateArgs()...); err != nil {
		return err
	}
	return rt.waitRegistryHealthy(ctx)
}
