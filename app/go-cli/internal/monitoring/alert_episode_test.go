package monitoring

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStoreRecoveryRemainsAcknowledgedAfterRestart(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(privateRuntimeDir(t), "incidents.json")
	notifier := &recordingNotifier{}
	run := func(state string) IncidentState {
		t.Helper()
		manager := AlertManager{Store: FileStore{Path: path}, Notifier: notifier, Retries: 1, Debounce: time.Minute, Now: func() time.Time { return now }}
		result, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", state, now)))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	run(StateDegraded)
	now = now.Add(2 * time.Minute)
	run(StateDegraded)
	now = now.Add(time.Minute)
	run(StateHealthy)
	now = now.Add(time.Minute)
	state := run(StateHealthy)
	if len(notifier.events) != 2 || notifier.events[1].Kind != "recovery" || !state.Incidents["services.application"].RecoverySent {
		t.Fatalf("initial recovery was not acknowledged: events=%#v state=%#v", notifier.events, state)
	}
	recoveryID := notifier.events[1].ID
	for range 3 {
		now = now.Add(time.Minute)
		state = run(StateHealthy)
	}
	if len(notifier.events) != 2 || notifier.events[1].ID != recoveryID || state.Incidents["services.application"].RecoveryPending {
		t.Fatalf("healthy cycles requeued an acknowledged recovery: events=%#v state=%#v", notifier.events, state)
	}
}

func TestEpisodeEventsKeepOldOutageSeparateFromNewFailure(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(privateRuntimeDir(t), "incidents.json")
	failureLog := filepath.Join(filepath.Dir(path), "delivery-failures.jsonl")
	failing := &alwaysFailNotifier{}
	manager := AlertManager{Store: FileStore{Path: path}, Notifier: failing, FailureLog: failureLog, Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err == nil {
		t.Fatal("first episode failure was silently acknowledged")
	}
	now = now.Add(time.Minute)
	if _, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateHealthy, now))); err == nil {
		t.Fatal("recovery outage was silently acknowledged")
	}
	now = now.Add(time.Minute)
	state, err := manager.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now)))
	if err == nil || len(state.Pending) != 2 {
		t.Fatalf("new episode displaced the old pending incident: state=%#v err=%v", state, err)
	}
	if state.Pending[0].EpisodeID == state.Pending[1].EpisodeID || state.Pending[0].Kind != "incident" || state.Pending[1].Kind != "incident" {
		t.Fatalf("pending events did not retain distinct ordered episodes: %#v", state.Pending)
	}
	oldEpisode := state.Pending[0].EpisodeID
	newEpisode := state.Pending[1].EpisodeID
	success := &recordingNotifier{}
	restarted := AlertManager{Store: FileStore{Path: path}, Notifier: success, FailureLog: failureLog, Retries: 1, Debounce: 0, Now: func() time.Time { return now }}
	if _, err := restarted.Process(context.Background(), alertReport(alertCheck("services.application", StateDegraded, now))); err != nil {
		t.Fatal(err)
	}
	if len(success.events) < 3 || success.events[0].EpisodeID != oldEpisode || success.events[1].EpisodeID != oldEpisode || success.events[2].EpisodeID != newEpisode {
		t.Fatalf("old incident and recovery were not delivered before the new episode: %#v", success.events)
	}
	if success.events[0].Kind != "incident" || success.events[1].Kind != "recovery" || success.events[2].Kind != "incident" {
		t.Fatalf("episode event order was not meaningful: %#v", success.events)
	}
}

type alwaysFailNotifier struct{}

func (*alwaysFailNotifier) Notify(context.Context, Notification) error {
	return errors.New("synthetic notification outage")
}
