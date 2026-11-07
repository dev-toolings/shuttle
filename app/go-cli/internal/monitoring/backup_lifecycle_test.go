package monitoring

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backuplifecycle"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func backupStatusForTest(attempt, phase, cloud string) backuplifecycle.Status {
	stamp := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	status := backuplifecycle.Status{Schema: backuplifecycle.Schema, App: "demo", AttemptID: attempt, Host: "vps.example", HostKey: "SHA256:" + strings.Repeat("A", 43), CreatedAt: stamp, UpdatedAt: stamp, State: backuplifecycle.StatePending, Phase: backuplifecycle.PhaseSource, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: cloud}
	switch phase {
	case backuplifecycle.PhaseSourceDone:
		status.SourceCapture = backuplifecycle.StageComplete
		status.Phase = phase
	case backuplifecycle.PhaseReceipt:
		status.SourceCapture = backuplifecycle.StageComplete
		status.Encryption = backuplifecycle.StageComplete
		status.Receipt = backuplifecycle.StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.Phase = phase
	case backuplifecycle.PhaseCloud:
		status.SourceCapture = backuplifecycle.StageComplete
		status.Encryption = backuplifecycle.StageComplete
		status.Receipt = backuplifecycle.StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.Cloud = backuplifecycle.CloudComplete
		status.Phase = phase
	case backuplifecycle.PhaseCloudFailed:
		status.SourceCapture = backuplifecycle.StageComplete
		status.Encryption = backuplifecycle.StageComplete
		status.Receipt = backuplifecycle.StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.Cloud = backuplifecycle.CloudFailed
		status.State = backuplifecycle.StateFailed
		status.Phase = phase
	case backuplifecycle.PhaseComplete:
		status.SourceCapture = backuplifecycle.StageComplete
		status.Encryption = backuplifecycle.StageComplete
		status.Receipt = backuplifecycle.StageComplete
		status.ArchiveSHA256 = strings.Repeat("b", 64)
		status.State = backuplifecycle.StateComplete
		status.Phase = phase
	}
	return status
}

func isolatedBackupStore(t *testing.T) backuplifecycle.Store {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return backuplifecycle.Store{Root: filepath.Join(parent, "backups")}
}

func applyBackupPhases(t *testing.T, store backuplifecycle.Store, attempt, cloud string, phases ...string) {
	t.Helper()
	for _, phase := range phases {
		status := backupStatusForTest(attempt, phase, cloud)
		if attempt == "backup-2" {
			status.CreatedAt = time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC).Format(time.RFC3339Nano)
			status.UpdatedAt = status.CreatedAt
		}
		if err := store.Apply(status); err != nil {
			t.Fatalf("apply %s %s: %v", attempt, phase, err)
		}
	}
}

func TestBackupCollectorReadsRealSharedJournalAndRetainsLocalSuccess(t *testing.T) {
	store := isolatedBackupStore(t)
	applyBackupPhases(t, store, "backup-1", backuplifecycle.CloudNotConfigured, backuplifecycle.PhaseSource, backuplifecycle.PhaseSourceDone, backuplifecycle.PhaseReceipt, backuplifecycle.PhaseComplete)
	applyBackupPhases(t, store, "backup-2", backuplifecycle.StageNotStarted, backuplifecycle.PhaseSource, backuplifecycle.PhaseSourceDone, backuplifecycle.PhaseReceipt, backuplifecycle.PhaseCloudFailed)
	cfg := config.MonitoringConfig{Enabled: true, StateDir: t.TempDir(), Backup: config.MonitoringBackupConfig{Expected: true, MaxAgeSeconds: 3600}}
	now := time.Now().UTC().Add(time.Minute)
	engine := New("demo", cfg, Adapters{Read: func(path string) ([]byte, error) {
		if path != backuplifecycle.DefaultStatusPath("demo") {
			t.Fatalf("collector used non-production journal path %s", path)
		}
		return os.ReadFile(store.Path("demo"))
	}, Now: func() time.Time { return now }})
	state, summary, evidence := engine.backup(context.Background())
	if state != StateDegraded || !strings.Contains(summary, "cloud export failed") || evidence["last_success"] == nil {
		t.Fatalf("cloud failure did not retain local success: state=%s summary=%s evidence=%#v", state, summary, evidence)
	}
	lastSuccess, _ := evidence["last_success"].(map[string]any)
	if lastSuccess["attempt_id"] != "backup-2" {
		t.Fatalf("new local receipt did not become last success: %#v", evidence)
	}
	if evidence["status_path"] != backuplifecycle.DefaultStatusPath("demo") {
		t.Fatalf("collector evidence did not name the production journal: %#v", evidence)
	}
}

func TestProducerDTOHelperDecodeStoreCollector(t *testing.T) {
	store := isolatedBackupStore(t)
	begin := backupStatusForTest("backup-1", backuplifecycle.PhaseSource, backuplifecycle.CloudNotConfigured)
	body, err := backuplifecycle.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backuplifecycle.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(decoded); err != nil {
		t.Fatal(err)
	}
	applyBackupPhases(t, store, "backup-1", backuplifecycle.CloudNotConfigured, backuplifecycle.PhaseSourceDone, backuplifecycle.PhaseReceipt, backuplifecycle.PhaseComplete)
	cfg := config.MonitoringConfig{Enabled: true, Backup: config.MonitoringBackupConfig{Expected: true, MaxAgeSeconds: 3600}}
	now := time.Now().UTC().Add(time.Minute)
	engine := New("demo", cfg, Adapters{Read: func(path string) ([]byte, error) {
		if path != backuplifecycle.DefaultStatusPath("demo") {
			t.Fatalf("collector used non-production journal path %s", path)
		}
		return os.ReadFile(store.Path("demo"))
	}, Now: func() time.Time { return now }})
	state, _, evidence := engine.backup(context.Background())
	if state != StateHealthy || evidence["last_success"] == nil {
		t.Fatalf("producer/helper/store round trip was not collected: state=%s evidence=%#v", state, evidence)
	}
}

func TestBackupCollectorDistinguishesNotConfiguredAndMissing(t *testing.T) {
	cfg := config.MonitoringConfig{Enabled: true}
	cfg.NormalizeMonitoring()
	engine := New("demo", cfg, Adapters{Read: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if state, _, _ := engine.backup(context.Background()); state != StateNotApplicable {
		t.Fatal("backup monitoring without expectation was not not_applicable")
	}
	engine.Config.Backup.Expected = true
	if state, summary, _ := engine.backup(context.Background()); state != StateDegraded || !strings.Contains(summary, "No authenticated VPS") {
		t.Fatalf("missing VPS status was not visible: %s %s", state, summary)
	}
}
