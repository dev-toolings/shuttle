package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// A host carrying only postgresql-client answers `command -v psql`, so guarding
// the install on that probe skipped it and left the first sed editing a file
// that was never going to exist. The guard has to be the artifact the step
// edits, which is the only thing that makes the check and the work agree.
func TestPostgresStepGuardsOnTheConfigurationItEdits(t *testing.T) {
	body := setupPostgresCommand(config.DefaultDatabaseVersion)
	if strings.Contains(body, "command -v psql") {
		t.Error("the install is still gated on `command -v psql`, which a client-only host satisfies")
	}
	if !strings.Contains(body, `if [ ! -f "$conf" ]; then`) {
		t.Error("the install must be gated on the postgresql.conf the step goes on to edit")
	}
	// Guarding is not enough on its own: if the install silently produces no
	// server, the step must say so instead of failing later on a raw sed.
	if !strings.Contains(body, "is not installed at /etc/postgresql/18/main") {
		t.Error("a missing server after the install step must fail with a message that names it")
	}
	if !strings.Contains(body, "gpg --dearmor --yes") {
		t.Error("gpg refuses to overwrite, so a retried checkpoint needs --yes to get past its own keyring")
	}
}

// Invariant 5: generated shell is testable as text, and must parse. Every shape
// the version resolution can produce is parsed, not just the default one.
func TestPostgresStepIsValidShell(t *testing.T) {
	for name, version := range map[string]int{"declared-16": 16, "declared-17": 17, "declared-18": 18, "resolved-on-host": 0} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "30-postgres.sh")
			if err := os.WriteFile(path, []byte(setupPostgresCommand(version)), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
				t.Fatalf("sh -n: %v\n%s", err, out)
			}
		})
	}
}
