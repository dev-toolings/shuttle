//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
)

func TestWritersInitializeReplayDecision(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	for _, tc := range []struct {
		name      string
		phases    []coord.Phase
		wantErr   error
		wantError string
	}{
		{name: "no phase"},
		{name: "completed", phases: []coord.Phase{{Name: "writers-initialize", EndedAt: "done"}}, wantErr: errWritersAlreadyInitialized},
		{name: "open", phases: []coord.Phase{{Name: "writers-initialize", StartedAt: "started"}}, wantError: "operation " + id + " writer initialization did not complete; recovery is required"},
		{name: "failed", phases: []coord.Phase{{Name: "writers-initialize", StartedAt: "started", EndedAt: "done", Error: "baseline observation failed"}}, wantError: "operation " + id + " writer initialization did not complete; recovery is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := writersInitializeReplay(coord.Record{ID: id, Phases: tc.phases})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("writersInitializeReplay error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("writersInitializeReplay error = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantError {
				t.Fatalf("writersInitializeReplay error = %v, want %q", err, tc.wantError)
			}
		})
	}
}

func TestWritersInitializeReplayRunsOnce(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	previousSource := rootOperationBaselineSourceRoot
	rootOperationBaselineSourceRoot = source
	t.Cleanup(func() { rootOperationBaselineSourceRoot = previousSource })
	owner := "SHA256:" + strings.Repeat("a", 43)
	host := "SHA256:" + strings.Repeat("b", 43)
	c := coord.New(coord.Options{Root: root, LockPath: filepath.Join(root, "root.lock"), BootID: func() (string, error) { return "boot-a", nil }})
	handle, err := c.Reserve(context.Background(), coord.Request{Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	request := coord.PhaseRequest{ID: handle.ID(), Kind: "run", App: "demo", Principal: owner, OwnerKeyFingerprint: owner, Host: host, Name: "writers-initialize"}
	baseline := operationwriters.Baseline{ConfiguredNativePGVersion: "not-configured", ConfiguredNativePGCluster: "not-configured"}
	observations := 0
	observe := func(context.Context, string) (operationwriters.Baseline, error) {
		observations++
		return baseline, nil
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := initializeOperationWritersWith(context.Background(), c, request, observe); err != nil {
			t.Fatalf("writers initialization attempt %d: %v", attempt, err)
		}
	}
	if observations != 1 {
		t.Fatalf("baseline observations = %d, want one", observations)
	}
	record, err := c.Get(context.Background(), handle.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Phases) != 1 || record.Phases[0].Name != "writers-initialize" || record.Phases[0].EndedAt == "" || record.Phases[0].Error != "" {
		t.Fatalf("writers initialization phases = %+v, want one completed phase", record.Phases)
	}
}
