package monitoring

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryDebounceSurvivesSeparateProbeProcesses(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(recettePrivateDir(t), "incidents.json")
	notifier := &recordingNotifier{}
	cycle := func(state string) IncidentState {
		t.Helper()
		// Reopen persistent state as each independent CLI invocation does.
		manager := AlertManager{Store: FileStore{Path: path}, Notifier: notifier, Retries: 1, Debounce: time.Second, Now: func() time.Time { return now }}
		result, err := manager.Process(context.Background(), reportFor(state, now))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	cycle(StateDegraded)
	now = now.Add(2 * time.Second)
	cycle(StateDegraded)
	if len(notifier.events) != 1 || notifier.events[0].Kind != "incident" {
		t.Fatalf("incident not delivered: %#v", notifier.events)
	}
	now = now.Add(time.Second)
	cycle(StateHealthy)
	if len(notifier.events) != 1 {
		t.Fatal("recovery bypassed debounce")
	}
	now = now.Add(2 * time.Second)
	state := cycle(StateHealthy)
	now = now.Add(time.Second)
	cycle(StateHealthy)
	if len(notifier.events) != 2 || notifier.events[1].Kind != "recovery" || !state.Incidents["services.application"].RecoverySent || len(state.Pending) != 0 {
		t.Fatalf("recovery was lost or duplicated: events=%#v state=%#v", notifier.events, state)
	}
}

func TestDelayedIncidentDeliveryDoesNotBypassRecoveryDebounce(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	notifier := &recordingNotifier{fails: 1}
	manager := AlertManager{Store: &MemoryStore{}, Notifier: notifier, Retries: 1, Debounce: time.Second, Now: func() time.Time { return now }, FailureLog: filepath.Join(recettePrivateDir(t), "failed.jsonl")}
	_, _ = manager.Process(context.Background(), reportFor(StateDegraded, now))
	now = now.Add(2 * time.Second)
	if _, err := manager.Process(context.Background(), reportFor(StateDegraded, now)); err == nil {
		t.Fatal("delivery failure hidden")
	}
	now = now.Add(time.Second)
	if _, err := manager.Process(context.Background(), reportFor(StateHealthy, now)); err != nil {
		t.Fatal(err)
	}
	if len(notifier.events) != 2 || notifier.events[1].Kind != "incident" {
		t.Fatalf("recovery delivered before debounce: %#v", notifier.events)
	}
	now = now.Add(2 * time.Second)
	if _, err := manager.Process(context.Background(), reportFor(StateHealthy, now)); err != nil {
		t.Fatal(err)
	}
	if len(notifier.events) != 3 || notifier.events[2].Kind != "recovery" {
		t.Fatalf("recovery missing after delayed incident: %#v", notifier.events)
	}
}

func recettePrivateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
