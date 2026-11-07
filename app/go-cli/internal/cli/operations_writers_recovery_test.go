package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestCloseRecoveryWritersAfterAbortError(t *testing.T) {
	for _, tc := range []struct {
		name                                           string
		recovery, statusFails, closeFails, wantSuccess bool
	}{
		{name: "reboot moved operation to recovery", recovery: true, wantSuccess: true},
		{name: "operation remains active"},
		{name: "status read fails", statusFails: true},
		{name: "writer close fails", closeFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldClose := remoteOperationCloseWriters
			t.Cleanup(func() { remoteOperationCloseWriters = oldClose })
			closeErr := errors.New("close failed")
			remoteOperationCloseWriters = func(*remoteOperation) error {
				if tc.closeFails {
					return closeErr
				}
				return nil
			}
			id := "01234567-89ab-cdef-0123-456789abcdef"
			var actions []string
			fixture, pin := administratorSSHFixture(t, func(_, _ string, input []byte) shuttlessh.Result {
				plan, _, err := decodeRootHelperEnvelope(bytes.NewReader(input))
				if err != nil {
					return shuttlessh.Result{Code: 1, Stderr: err.Error()}
				}
				actions = append(actions, plan.Action)
				if plan.Action == "operation-abort" {
					return shuttlessh.Result{Code: 1, Stderr: "operation lease or boot expired; recovery required"}
				}
				if plan.Action != "operations-status" || tc.statusFails {
					return shuttlessh.Result{Code: 1, Stderr: "status failed"}
				}
				state := "active"
				if tc.recovery {
					state = coord.RecoveryRequired
				}
				body, _ := json.Marshal([]coord.Record{{ID: id, Kind: "deploy", App: "demo", State: state, RecoveryRequired: tc.recovery}})
				return shuttlessh.Result{Stdout: string(body)}
			})
			client, err := shuttlessh.NewClientExactWithFingerprint(fixture.host, fixture.user, fixture.port, pin)
			if err != nil {
				t.Fatal(err)
			}
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			op := &remoteOperation{id: id, kind: "deploy", app: "demo", client: client, key: key, identity: trustedHostIdentity{HostKeyFingerprint: pin, OperatorKeyFingerprint: fixture.operatorKeyFingerprint}}
			got, note := closeRecoveryWriters(op, "active")
			if tc.wantSuccess {
				if got != nil || note == nil || !strings.Contains(note.Error(), "operation lease or boot expired") {
					t.Fatalf("got error %v note %v", got, note)
				}
			} else if got == nil || (tc.closeFails && !errors.Is(got, closeErr)) || (!tc.closeFails && !strings.Contains(got.Error(), "operation lease or boot expired")) {
				t.Fatalf("original failure lost: %v", got)
			}
			if tc.closeFails && len(actions) != 0 {
				t.Fatalf("close failure sent controls: %v", actions)
			}
			if !tc.closeFails && (len(actions) != 2 || actions[0] != "operation-abort" || actions[1] != "operations-status") {
				t.Fatalf("actions = %v", actions)
			}
		})
	}
}

func TestOperationsWritersCommandIsRegisteredWithConfirmationFlags(t *testing.T) {
	root := NewRootCommand()
	command, _, err := root.Find([]string{"operations", "writers"})
	if err != nil || command == nil || command.Name() != "writers" {
		t.Fatalf("operations writers is not registered: command=%v err=%v", command, err)
	}
	cmd := newOperationsWritersCommand()
	for _, name := range []string{"dry-run", "yes", "plan-digest", "json"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("writer recovery command lost flag %s", name)
		}
	}
}

func TestOperationsWritersCommandRefusesInvalidIDAndUnconfirmedApply(t *testing.T) {
	cmd := newOperationsWritersCommand()
	cmd.SetArgs([]string{"not-an-id"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid operation identifier") {
		t.Fatalf("invalid identifier was accepted: %v", err)
	}

	cmd = newOperationsWritersCommand()
	cmd.SetArgs([]string{"01234567-89ab-cdef-0123-456789abcdef"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("unconfirmed writer closure was accepted: %v", err)
	}
}

func TestWriterRecoveryPlanDigestChangesWithInventory(t *testing.T) {
	snapshot := testWriterRecoverySnapshot()
	first, err := writerRecoveryPlanDigest(snapshot)
	if err != nil || !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("unexpected digest %q err=%v", first, err)
	}
	again, err := writerRecoveryPlanDigest(snapshot)
	if err != nil || again != first {
		t.Fatalf("digest is not stable: %q vs %q err=%v", first, again, err)
	}
	snapshot.Writers.Writers[0].ID = "ssh-build-runner-other"
	changed, err := writerRecoveryPlanDigest(snapshot)
	if err != nil || changed == first {
		t.Fatalf("digest ignored writer identity change: %q err=%v", changed, err)
	}
	if err := confirmWriterRecoveryDigest("", first); err == nil {
		t.Fatal("missing confirmation digest was accepted")
	}
	if err := confirmWriterRecoveryDigest(changed, first); err == nil {
		t.Fatal("stale confirmation digest was accepted")
	}
	if err := confirmWriterRecoveryDigest(first, first); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWriterRecoveryIdentitiesBindsOperationHostAndBoot(t *testing.T) {
	snapshot := testWriterRecoverySnapshot()
	id := snapshot.Record.ID
	app := snapshot.Record.App
	host := snapshot.Record.Host
	owner := snapshot.Record.OwnerKeyFingerprint
	if err := validateWriterRecoveryIdentities(id, app, host, owner, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := validateWriterRecoveryIdentities("01234567-89ab-cdef-0123-456789abcdee", app, host, owner, snapshot); err == nil {
		t.Fatal("another operation id was bound")
	}
	if err := validateWriterRecoveryIdentities(id, "other", host, owner, snapshot); err == nil {
		t.Fatal("another application was bound")
	}
	if err := validateWriterRecoveryIdentities(id, app, "SHA256:"+strings.Repeat("Z", 43), owner, snapshot); err == nil {
		t.Fatal("another host key was bound")
	}
	if err := validateWriterRecoveryIdentities(id, app, host, "SHA256:"+strings.Repeat("Y", 43), snapshot); err == nil {
		t.Fatal("another operator key was bound")
	}

	mismatch := snapshot
	mismatch.Writers.Binding.BootID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
	if err := validateWriterRecoveryIdentities(id, app, host, owner, mismatch); err == nil {
		t.Fatal("writer boot identity was not bound to the journal")
	}
	mismatch = snapshot
	mismatch.Writers.Binding.HostKey = "SHA256:" + strings.Repeat("D", 43)
	if err := mismatch.Writers.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateWriterRecoveryIdentities(id, app, host, owner, mismatch); err == nil {
		t.Fatal("writer host key was not bound to the journal")
	}
	mismatch = snapshot
	mismatch.Writers.Binding.OperationID = "01234567-89ab-cdef-0123-456789abcdee"
	if err := mismatch.Writers.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateWriterRecoveryIdentities(id, app, host, owner, mismatch); err == nil {
		t.Fatal("writer operation id was not bound to the journal")
	}
}

func TestRecordedWriterCloserRefusesVPSLocalAndUnidentifiedSSH(t *testing.T) {
	snapshot := testWriterRecoverySnapshot()
	op := &remoteOperation{id: snapshot.Record.ID, app: snapshot.Record.App}
	local := operationwriters.Writer{ID: "vps-group", Kind: operationwriters.WriterKindLocalGroup, Local: &operationwriters.LocalGroup{LeaderPID: 7, LeaderStartTicks: 9, PGID: 7, SID: 7}}
	if _, _, err := recordedWriterCloser(&config.Config{}, op, snapshot, local); err == nil || !strings.Contains(err.Error(), "VPS recovery executor") {
		t.Fatalf("local VPS writer was closed from the workstation: %v", err)
	}

	remote := snapshot.Writers.Writers[0]
	if _, _, err := recordedWriterCloser(&config.Config{App: "demo"}, op, snapshot, remote); err == nil || !strings.Contains(err.Error(), "recorded SSH runner") {
		t.Fatalf("local builder closed a remote runner: %v", err)
	}
	cfg := &config.Config{App: "demo", Build: config.Build{Runner: config.BuildRunnerSSH, HostKey: "SHA256:" + strings.Repeat("Z", 43)}}
	if _, _, err := recordedWriterCloser(cfg, op, snapshot, remote); err == nil || !strings.Contains(err.Error(), "recorded SSH runner") {
		t.Fatalf("another runner host key was accepted: %v", err)
	}

	fence, cleanup, err := recordedWriterCloser(&config.Config{}, op, snapshot, operationwriters.Writer{ID: "client-origin:token", Kind: operationwriters.WriterKindClientOrigin, Client: &operationwriters.ClientOrigin{}})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup == nil || fence == nil {
		t.Fatal("client origin closer was not retained")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

func testWriterRecoverySnapshot() writerRecoverySnapshot {
	id := "01234567-89ab-cdef-0123-456789abcdef"
	host := "SHA256:" + strings.Repeat("A", 43)
	owner := "SHA256:" + strings.Repeat("B", 43)
	boot := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	return writerRecoverySnapshot{
		Record: coord.Record{
			Schema:              coord.Schema,
			ID:                  id,
			Kind:                "deploy",
			App:                 "demo",
			OwnerKeyFingerprint: owner,
			Host:                host,
			HostBootID:          boot,
			State:               "active",
		},
		Writers: operationwriters.State{
			Schema:     operationwriters.Schema,
			Binding:    operationwriters.Binding{OperationID: id, Generation: 1, HostKey: host, BootID: boot},
			Revision:   2,
			Admissions: operationwriters.AdmissionsOpen,
			Writers: []operationwriters.Writer{{
				ID:     "ssh-build-runner",
				Kind:   operationwriters.WriterKindRemoteRunner,
				Remote: &operationwriters.RemoteRunner{HostKey: "SHA256:" + strings.Repeat("C", 43), RunToken: "aabbccdd1122334455667788"},
			}},
			Baseline: operationwriters.Baseline{ConfiguredNativePGVersion: "18.6", ConfiguredNativePGCluster: "main"},
		},
	}
}
