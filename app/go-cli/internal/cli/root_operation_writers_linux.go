//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func operationWriterBinding(record coord.Record) operationwriters.Binding {
	return operationwriters.Binding{OperationID: record.ID, Generation: 1, HostKey: record.Host, BootID: record.HostBootID}
}

func writerPhaseRequest(plan rootplan.Plan, phase string) (coord.PhaseRequest, error) {
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		return coord.PhaseRequest{}, err
	}
	return coord.PhaseRequest{ID: plan.OperationID, Kind: plan.OperationKind, App: plan.OperationApp, Principal: plan.OperatorKeyFingerprint, OwnerKeyFingerprint: plan.OperatorKeyFingerprint, Host: plan.RequiredHostFingerprint, HostIdentity: plan.RequiredHostFingerprint, Name: phase, PlanExpiresAt: expires, Validate: func(coord.Record) error {
		if err := rootCoordinatedMutationGuard(plan.Action); err != nil {
			return err
		}
		return rootCoordinatedIdentityVerifier(plan)
	}}, nil
}

var errWritersAlreadyInitialized = errors.New("operation writers are already initialized")

// writersInitializeReplay adopts a completed writers phase after a lost SSH
// reply. An open or failed phase may have captured only part of the baseline,
// so it must stay fenced for explicit recovery instead of observing again.
func writersInitializeReplay(record coord.Record) error {
	found := false
	for _, phase := range record.Phases {
		if phase.Name != "writers-initialize" {
			continue
		}
		found = true
		if phase.EndedAt != "" && phase.Error == "" {
			return errWritersAlreadyInitialized
		}
	}
	if !found {
		return nil
	}
	return fmt.Errorf("operation %s writer initialization did not complete; recovery is required", record.ID)
}

// initializeOperationWritersWith checks replay while beginPhaseLocked holds
// the journal lock, before another phase-start or baseline observation can be
// written after the SSH reply to the original reservation was lost.
func initializeOperationWritersWith(ctx context.Context, c *coord.Coordinator, request coord.PhaseRequest, observe func(context.Context, string) (operationwriters.Baseline, error)) error {
	validate := request.Validate
	request.Validate = func(record coord.Record) error {
		if err := writersInitializeReplay(record); err != nil {
			return err
		}
		if validate != nil {
			return validate(record)
		}
		return nil
	}
	err := c.ExecutePhase(ctx, request, func(ctx context.Context, record coord.Record) error {
		baseline, err := observe(ctx, record.App)
		if err != nil {
			return err
		}
		if err := preserveRootOperationBaselineArtifactsAt(c.Root(), rootOperationBaselineSourceRoot, record.ID, record.App, baseline); err != nil {
			return err
		}
		_, err = operationwriters.NewStore(c.Root()).InitializeLocked(operationWriterBinding(record), baseline)
		return err
	})
	if errors.Is(err, errWritersAlreadyInitialized) {
		return nil
	}
	return err
}

func initializeRootOperationWriters(ctx context.Context, c *coord.Coordinator, plan rootplan.Plan) error {
	request, err := writerPhaseRequest(plan, "writers-initialize")
	if err != nil {
		return err
	}
	return initializeOperationWritersWith(ctx, c, request, observeWriterBaseline)
}

func controlRootOperationWriters(ctx context.Context, plan rootplan.Plan) ([]byte, error) {
	request, err := writerPhaseRequest(plan, plan.Action)
	if err != nil {
		return nil, err
	}
	c := rootOperationCoordinator()
	var state operationwriters.State
	err = c.WithWriterInventory(ctx, request, plan.Action == "operation-writer-register", func(record coord.Record) error {
		binding := operationWriterBinding(record)
		if plan.Writers == nil || plan.Writers.Generation != binding.Generation {
			return errors.New("writer generation mismatch")
		}
		store := operationwriters.NewStore(c.Root())
		var err error
		switch plan.Action {
		case "operation-writer-register":
			if plan.Writers.Writer == nil {
				return errors.New("missing writer")
			}
			state, err = store.RegisterLocked(binding, *plan.Writers.Writer)
		case "operation-writers-close":
			state, err = store.CloseAdmissionsLocked(binding)
		case "operation-writers-commit":
			state, err = store.CommitClosureLocked(binding, plan.Writers.Receipts)
		default:
			return errors.New("unsupported writer transition")
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

func readCoordinatedRootWriterState(ctx context.Context, record coord.Record) (operationwriters.State, error) {
	if err := ctx.Err(); err != nil {
		return operationwriters.State{}, err
	}
	return operationwriters.NewStore(coord.DefaultRoot).Read(operationWriterBinding(record))
}

func requireRootWritersClosed(c *coord.Coordinator, record coord.Record) error {
	state, err := operationwriters.NewStore(c.Root()).Read(operationWriterBinding(record))
	if err != nil {
		return fmt.Errorf("writer closure cannot be read: %w", err)
	}
	if _, err := state.ClosedProofHash(); err != nil {
		return fmt.Errorf("writer closure is not proven: %w", err)
	}
	return nil
}

func observeWriterBaseline(ctx context.Context, app string) (operationwriters.Baseline, error) {
	baseline := operationwriters.Baseline{ConfiguredNativePGVersion: "not-configured", ConfiguredNativePGCluster: "not-configured"}
	if app != "" {
		var err error
		baseline.Current, err = readWriterBaselineArtifact(filepath.Join(rootOperationBaselineSourceRoot, app, "current.yml"))
		if err != nil {
			return baseline, err
		}
		baseline.Previous, err = readWriterBaselineArtifact(filepath.Join(rootOperationBaselineSourceRoot, app, "previous.yml"))
		if err != nil {
			return baseline, err
		}
	}
	if _, err := os.Stat("/usr/bin/pg_lsclusters"); os.IsNotExist(err) {
		return baseline, nil
	} else if err != nil {
		return baseline, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, err := exec.CommandContext(ctx, "/usr/bin/pg_lsclusters", "--json").Output()
	if err != nil {
		return baseline, fmt.Errorf("observe native PostgreSQL baseline: %w", err)
	}
	var clusters []struct {
		Version string `json:"version"`
		Cluster string `json:"cluster"`
	}
	if err := json.Unmarshal(body, &clusters); err != nil {
		return baseline, err
	}
	if len(clusters) > 0 {
		// Sort the pairs, not each list on its own: recovery reads the two
		// lists index by index, and sorting them apart could pair 16 with
		// the cluster that belongs to 18.
		sort.Slice(clusters, func(i, j int) bool {
			if clusters[i].Version != clusters[j].Version {
				return clusters[i].Version < clusters[j].Version
			}
			return clusters[i].Cluster < clusters[j].Cluster
		})
		var versions, names []string
		for _, cluster := range clusters {
			versions = append(versions, cluster.Version)
			names = append(names, cluster.Cluster)
		}
		baseline.ConfiguredNativePGVersion = strings.Join(versions, ",")
		baseline.ConfiguredNativePGCluster = strings.Join(names, ",")
	}
	return baseline, baseline.Validate()
}
