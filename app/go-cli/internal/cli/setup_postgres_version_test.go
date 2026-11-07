package cli

import (
	"strconv"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

// A declared major is the one the checkpoint installs and configures, end to
// end: the paths it edits, the packages it installs and the refusals it prints
// must all name the same number, or the step would configure one cluster while
// proving another.
func TestPostgresCheckpointFollowsTheDeclaredMajor(t *testing.T) {
	for _, major := range config.SupportedDatabaseVersions {
		version := strconv.Itoa(major)
		t.Run(version, func(t *testing.T) {
			body := setupPostgresCommand(major)
			for _, required := range []string{
				"conf=/etc/postgresql/" + version + "/main/postgresql.conf",
				"hba=/etc/postgresql/" + version + "/main/pg_hba.conf",
				"apt-get install -y postgresql-" + version + " postgresql-client-" + version,
				"PostgreSQL " + version + " is not installed at /etc/postgresql/" + version + "/main",
			} {
				if !strings.Contains(body, required) {
					t.Fatalf("the checkpoint for %s is missing %q:\n%s", version, required, body)
				}
			}
			// A declared major settles the question, so the script must not
			// also go looking on the host: two answers is one too many.
			if strings.Contains(body, "for candidate in") {
				t.Fatalf("a declared major must not be re-resolved on the host:\n%s", body)
			}
			other := map[string]string{"16": "17", "17": "16"}[version]
			if strings.Contains(body, "/etc/postgresql/"+other+"/") || strings.Contains(body, "postgresql-"+other+" ") {
				t.Fatalf("the checkpoint for %s also names %s:\n%s", version, other, body)
			}
		})
	}
}

// With no declared major the host decides, because /etc/postgresql is on the
// host. The script must probe only the supported majors — a residual 13 is not
// a candidate — and it must refuse rather than guess when it finds several.
func TestPostgresCheckpointResolvesTheMajorOnTheHostWhenNoneIsDeclared(t *testing.T) {
	body := setupPostgresCommand(0)
	for _, required := range []string{
		"for candidate in " + supportedDatabaseVersionsShellList() + "; do",
		`if [ -f "/etc/postgresql/$candidate/main/postgresql.conf" ]; then`,
		`if [ "$matched" -gt 1 ]; then`,
		"declare database.version in config.json to name the one Shuttle must use",
		"conf=/etc/postgresql/$version/main/postgresql.conf",
		"apt-get install -y postgresql-$version postgresql-client-$version",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("the resolving checkpoint is missing %q:\n%s", required, body)
		}
	}
	// A bare host gets the current stable default; existing declared majors
	// retain their own cluster.
	if !strings.Contains(body, "if [ \"$matched\" -eq 0 ]; then\n  version=18\n") {
		t.Fatalf("a host with no supported cluster must fall back to the default major:\n%s", body)
	}
	if strings.Contains(body, "/etc/postgresql/13") {
		t.Fatalf("only supported majors may be adopted:\n%s", body)
	}
}

// The `ss` assertions further down prove something answers on 5432, not that
// the configured cluster is the thing answering. On a multi-cluster host the
// target can sit on 5433 and every one of them would pass against the wrong
// database, so the port is checked before the first edit.
func TestPostgresCheckpointRefusesATargetClusterThatIsNotOn5432(t *testing.T) {
	for _, version := range []int{0, 16, 17, 18} {
		body := setupPostgresCommand(version)
		if !strings.Contains(body, `port=$(grep -E "^[[:space:]]*port[[:space:]]*=" "$conf" | tail -n 1`) {
			t.Fatalf("the checkpoint must read the target cluster's configured port:\n%s", body)
		}
		if !strings.Contains(body, `if [ "$port" != 5432 ]; then`) {
			t.Fatalf("the checkpoint must refuse a target cluster that is not on 5432:\n%s", body)
		}
		if !strings.Contains(body, "not 5432; Shuttle addresses the managed cluster on 5432") {
			t.Fatalf("the refusal must name the port it found:\n%s", body)
		}
		if strings.Index(body, `if [ "$port" != 5432 ]`) > strings.Index(body, "sed -i") {
			t.Fatalf("a cluster Shuttle is going to refuse must not be edited first:\n%s", body)
		}
	}
}

// An operator who declared 16 on a host running 17 has to see it here, in the
// step that fails, rather than in a later assertion about a cluster that was
// never installed.
func TestPostgresCheckpointNamesTheClustersItFoundWhenTheInstallProducedNothing(t *testing.T) {
	body := setupPostgresCommand(17)
	if !strings.Contains(body, `echo "clusters present: $(ls -1 /etc/postgresql 2>/dev/null | tr '\n' ' ')" >&2`) {
		t.Fatalf("a missing server must be reported next to the clusters the host does have:\n%s", body)
	}
}

// setupStages is where the configuration reaches the checkpoint. A declared
// major has to survive that trip, and an absent block has to arrive as the
// resolve-on-host form — declaring a version is not free, it is what makes
// Shuttle own the application's role and password.
func TestSetupStagesCarryTheConfiguredMajorIntoTheCheckpoint(t *testing.T) {
	cfg := adoptionApplyConfig(t)
	if resolvedSetupDatabaseVersion(cfg) != 0 {
		t.Fatal("a configuration with no database block declares no major")
	}
	if !strings.Contains(postgresStage(t, cfg), "for candidate in") {
		t.Fatal("an undeclared major must be resolved on the host")
	}
	cfg.Database.Version = 17
	if !strings.Contains(postgresStage(t, cfg), "/etc/postgresql/17/main") {
		t.Fatal("a declared major must reach the checkpoint")
	}
}

func postgresStage(t *testing.T, cfg *config.Config) string {
	t.Helper()
	for _, stage := range setupStages(cfg, 22, setupModeFresh) {
		if stage.name == "postgres" {
			return stage.command
		}
	}
	t.Fatal("no postgres stage")
	return ""
}

// The gateway address 30-postgres binds only exists once Docker has created
// docker_gwbridge, so the cluster unit must be ordered after docker.service.
// The ordering is its own checkpoint, so a host set up before it existed picks
// it up on its next setup run, and with no declared major that checkpoint has
// to resolve the version itself: 30's marker may already be there, and the
// resolver inside it would then never run.
func TestPostgresCheckpointOrdersTheClusterAfterDocker(t *testing.T) {
	for _, major := range append([]int{0}, config.SupportedDatabaseVersions...) {
		version := strconv.Itoa(major)
		if major == 0 {
			version = "$version"
		}
		t.Run(version, func(t *testing.T) {
			body := setupPostgresCommand(major)
			guard := "if [ ! -f /etc/shuttle/setup.d/32-postgres-boot-order ]"
			start := strings.Index(body, guard)
			if start < 0 {
				t.Fatalf("the boot-order step is not its own checkpoint:\n%s", body)
			}
			step := body[start:]
			for _, required := range []string{
				"dropin=/etc/systemd/system/postgresql@" + version + "-main.service.d",
				"'After=docker.service' 'Wants=docker.service'",
				"10-shuttle-after-docker.conf",
				"systemctl daemon-reload",
				"touch /etc/shuttle/setup.d/32-postgres-boot-order",
			} {
				if !strings.Contains(step, required) {
					t.Fatalf("the boot-order checkpoint for %s is missing %q:\n%s", version, required, step)
				}
			}
			if resolves := strings.Contains(step, "for candidate in"); resolves != (major == 0) {
				t.Fatalf("resolving the major on the host must happen exactly when none is declared (declared=%v, resolves=%v):\n%s", major != 0, resolves, step)
			}
		})
	}
}
