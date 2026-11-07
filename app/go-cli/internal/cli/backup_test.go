package cli

import (
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"os"
	"testing"
)

func TestRecoveryConfigCanBeLoadedAfterNormalization(t *testing.T) {
	t.Chdir(t.TempDir())
	root := NewRootCommand()
	root.SetArgs([]string{"init", "--app", "backup-test", "--preset", "node-api", "--domain", "backup.example.com", "--host", "192.0.2.1", "--email", "", "--with-db", "postgres"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("config.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) == 0 {
		t.Fatal("test must exercise normalized server groups")
	}
	body, err := recoveryConfiguration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("recovered.json", body, 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := config.Load("recovered.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if restored.App != cfg.App || restored.Database.Version != 18 {
		t.Fatal("recovery config lost application or current native PostgreSQL default")
	}
}
