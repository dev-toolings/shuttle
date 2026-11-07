package cli

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
)

// These observations are separate from the satisfaction probes: the latter
// only say that Docker, Swarm and PostgreSQL are running, not that the later
// edge, firewall and managed database stages can use them.
const adoptionPrerequisiteSurveySource = `
if [ -f /etc/shuttle/setup.d/20-docker ]; then printf 'docker-checkpoint=present\n'; else printf 'docker-checkpoint=absent\n'; fi
if [ "$docker_ok" = yes ]; then
  if docker container inspect shuttle-registry >/dev/null 2>&1; then printf 'registry=present\n'; else printf 'registry=absent\n'; fi
  gateway=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || :)
  subnet=$(docker network inspect docker_gwbridge --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || :)
  [ -z "$gateway" ] || printf 'gateway=%s\n' "$gateway"
  [ -z "$subnet" ] || printf 'gateway-subnet=%s\n' "$subnet"
  edge=$(docker network inspect caddy_network --format '{{.Driver}}' 2>/dev/null || :)
  [ -z "$edge" ] || printf 'edge-network=%s\n' "$edge"
  iface=$(ip -o -4 route show default | awk '{print $5; exit}')
  if [ -n "$iface" ] && [ -r "/sys/class/net/$iface/mtu" ] && [ -r /sys/class/net/docker_gwbridge/mtu ]; then
    printf 'gateway-mtu=%s-%s\n' "$(cat "/sys/class/net/$iface/mtu")" "$(cat /sys/class/net/docker_gwbridge/mtu)"
  fi
fi
if have_postgres; then
  listen=$(runuser -u postgres -- psql -X -Atc 'show listen_addresses' 2>/dev/null) || listen=unavailable
  printf 'postgres-listen=%s\n' "$(printf '%s' "$listen" | base64 -w0)"
  cluster=$(pg_lsclusters -h 2>/dev/null | awk '$3 == 5432 && $4 ~ /^online/ {print $1 "-" $2}' || :)
  case "$cluster" in ''|*[!A-Za-z0-9_-]*|*' '* ) printf 'prerequisite-issue=postgres-cluster\n' ;; *)
    printf 'postgres-cluster=%s\n' "$cluster"
    systemctl show "postgresql@$cluster.service" -p After -p Requires >/dev/null 2>&1 || :
    ;;
  esac
fi
`

const adoptionBackupService = "[Unit]\nDescription=Shuttle local PostgreSQL backup\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/shuttle-postgres-backup\n"
const adoptionBackupTimer = "[Unit]\nDescription=Daily Shuttle PostgreSQL backup\n[Timer]\nOnCalendar=daily\nPersistent=true\nRandomizedDelaySec=10m\n[Install]\nWantedBy=timers.target\n"
const adoptionBootDropin = "# Written by shuttle setup (32-postgres-boot-order); do not edit.\n# listen_addresses includes the docker_gwbridge gateway: without this edge\n# PostgreSQL starts before Docker creates the bridge, binds loopback only,\n# and the managed database is unreachable from containers until a restart.\n[Unit]\nAfter=docker.service\nWants=docker.service\n"

// Compare complete contents, not just names or a comment that another file
// could carry. A foreign file at a Shuttle path must survive the adoption.
func adoptionOwnedFilesGuard() string {
	return `owned_file() {
  path=$1; expected=$2
  [ ! -L "$path" ] || return 1
  [ ! -e "$path" ] || printf '%s' "$expected" | cmp -s "$path" -
}
retention_owned() {
  path=$1
  [ ! -L "$path" ] || return 1
  [ -e "$path" ] || return 0
  [ -f "$path" ] || return 1
  for keep in 1 2 3 4 5 6 7; do
    if printf 'keep=%s\n' "$keep" | cmp -s "$path" -; then return 0; fi
  done
  return 1
}
backup_owned() {
  path=/usr/local/sbin/shuttle-postgres-backup
  [ ! -L "$path" ] || return 1
  [ ! -e "$path" ] || printf '%s' ` + shell.Escape(postgresBackupScript) + ` | cmp -s "$path" - || printf '%s' ` + shell.Escape(previousPostgresBackupScript) + ` | cmp -s "$path" - || printf '%s' ` + shell.Escape(legacyPostgresBackupScript) + ` | cmp -s "$path" -
}
backup_service_owned() { owned_file /etc/systemd/system/shuttle-postgres-backup.service ` + shell.Escape(adoptionBackupService) + `; }
backup_timer_owned() { owned_file /etc/systemd/system/shuttle-postgres-backup.timer ` + shell.Escape(adoptionBackupTimer) + `; }
boot_dropin_owned() { owned_file "/etc/systemd/system/postgresql@$cluster.service.d/10-shuttle-after-docker.conf" ` + shell.Escape(adoptionBootDropin) + `; }
`
}

func adoptionOwnedFilesSurvey(_ ...int) string {
	return adoptionOwnedFilesGuard() + `
retention_path="/etc/shuttle/postgres-backup.d/$app.conf"
if retention_owned "$retention_path"; then
  if [ -f "$retention_path" ]; then
    printf 'postgres-retention=%s\n' "$(cut -d= -f2 "$retention_path")"
  else
    printf 'postgres-retention=absent\n'
  fi
else
  printf 'prerequisite-issue=backup-retention\n'
fi
if have_postgres; then
  backup_owned || printf 'prerequisite-issue=backup-script\n'
  backup_service_owned || printf 'prerequisite-issue=backup-service\n'
  backup_timer_owned || printf 'prerequisite-issue=backup-timer\n'
  [ -z "$cluster" ] || boot_dropin_owned || printf 'prerequisite-issue=boot-dropin\n'
fi
`
}

func adoptionPrerequisiteError(s adoptionSurvey) error {
	for _, issue := range s.PrerequisiteIssues {
		switch issue {
		case "postgres-cluster":
			return fmt.Errorf("refusing adoption: cannot identify the active PostgreSQL cluster on port 5432")
		case "backup-script", "backup-service", "backup-timer", "backup-retention", "boot-dropin":
			return fmt.Errorf("refusing adoption: existing %s is not a known Shuttle file", issue)
		default:
			return fmt.Errorf("refusing adoption: unknown prerequisite issue %q", issue)
		}
	}
	docker := containsAdoptionStep(s.Satisfied, "20-docker")
	postgres := containsAdoptionStep(s.Satisfied, "30-postgres")
	if docker {
		if s.LiveRestore != "false" {
			return fmt.Errorf("refusing adoption: Docker live-restore must be off before skipping 20-docker")
		}
		if s.EdgeNetwork != "overlay" && !adoptionNeedsCaddyNetwork(s) {
			return fmt.Errorf("refusing adoption: caddy_network must exist with the overlay driver before skipping 20-docker")
		}
		parts := strings.Split(s.GatewayMTU, "-")
		if len(parts) != 2 {
			return fmt.Errorf("refusing adoption: cannot prove Docker gateway and host MTU")
		}
		host, e1 := strconv.Atoi(parts[0])
		bridge, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil || host < 1280 || bridge < 1280 || bridge > host {
			return fmt.Errorf("refusing adoption: Docker gateway MTU exceeds the host MTU or cannot be proven")
		}
	}
	if !docker && !postgres {
		return nil
	}
	gateway := net.ParseIP(s.Gateway)
	_, subnet, err := net.ParseCIDR(s.GatewaySubnet)
	if gateway == nil || err != nil || !subnet.Contains(gateway) {
		return fmt.Errorf("refusing adoption: docker_gwbridge gateway and subnet are missing or unreadable")
	}
	if !postgres {
		return nil
	}
	if s.PostgresCluster == "" {
		return fmt.Errorf("refusing adoption: PostgreSQL cluster on port 5432 is missing or unreadable")
	}
	listen, err := base64.StdEncoding.DecodeString(s.PostgresListen)
	if err != nil || string(listen) == "unavailable" {
		return fmt.Errorf("refusing adoption: cannot read PostgreSQL listen_addresses")
	}
	listening := false
	for _, item := range strings.Split(string(listen), ",") {
		item = strings.TrimSpace(item)
		if item == "*" || net.ParseIP(item) != nil && net.ParseIP(item).Equal(gateway) {
			listening = true
		}
	}
	if !listening {
		return fmt.Errorf("refusing adoption: PostgreSQL listen_addresses does not contain the Docker gateway or *")
	}

	return nil
}

// The setup-state claim precedes 20-docker, so an absent checkpoint and
// absent overlay can be the interrupted interval after Swarm initialization.
func adoptionNeedsCaddyNetwork(s adoptionSurvey) bool {
	return s.SetupState == "present" && s.DockerCheckpoint == "absent" && s.EdgeNetwork == "" && containsAdoptionStep(s.Satisfied, "20-docker")
}

func containsAdoptionStep(steps []string, target string) bool {
	for _, step := range steps {
		if step == target {
			return true
		}
	}
	return false
}

// Adoption may be interrupted at any command. Write the next policy beside
// the old one and rename only after a final ownership check, so a killed setup
// cannot leave an empty file that its next survey rejects as foreign.
func adoptionPostgresRetentionConfig(app string, backups int) string {
	if backups == 0 {
		backups = 7
	}
	return fmt.Sprintf(`(
set -eu
retention_file=%s
retention_owned "$retention_file" || { echo 'foreign PostgreSQL retention configuration' >&2; exit 1; }
install -d -o root -g root -m 0700 /etc/shuttle/postgres-backup.d
tmp=$(mktemp /etc/shuttle/postgres-backup.d/.shuttle-retention.XXXXXX)
trap 'rm -f -- "$tmp"' EXIT
chown root:root "$tmp"
chmod 0600 "$tmp"
printf 'keep=%%d\n' %d >"$tmp"
retention_owned "$retention_file" || { echo 'foreign PostgreSQL retention configuration' >&2; exit 1; }
mv -f -- "$tmp" "$retention_file"
trap - EXIT
)
`, shell.Escape("/etc/shuttle/postgres-backup.d/"+app+".conf"), backups)
}

func adoptionSetupStages(cfg *config.Config, port int, survey adoptionSurvey) []setupStage {
	original := setupStages(cfg, port, setupModeAdoption)
	stages := make([]setupStage, 0, len(original)+3)
	for _, stage := range original {
		switch {
		case stage.name == "docker" && containsAdoptionStep(survey.Satisfied, "20-docker"):
			if adoptionNeedsCaddyNetwork(survey) {
				stages = append(stages, setupStage{"20-caddy-network", `set -eu
if docker network inspect caddy_network >/dev/null 2>&1; then
  test "$(docker network inspect caddy_network --format '{{.Driver}}')" = overlay || { echo 'caddy_network is not an overlay' >&2; exit 1; }
else
  docker network create --driver overlay --attachable caddy_network
fi
`})
			}
			image := cfg.ResolvedInfrastructure["registry"]
			if image == "" {
				image = "__SHUTTLE_REGISTRY_IMAGE__"
			}
			body := strings.ReplaceAll(setupRegistryNonRootSource+setupRegistryCreateSource, "__SHUTTLE_REGISTRY_IMAGE__", image)
			// A container can exist but be stopped, and a name alone does not
			// prove it belongs to Shuttle. Do not let later stages start until
			// the registry answers its loopback health probe.
			registryGuard := `if docker container inspect shuttle-registry >/dev/null 2>&1; then
  test "$(docker container inspect shuttle-registry --format '{{index .Config.Labels "dev.shuttle.owner"}}')" = system || { echo 'refusing foreign shuttle-registry container' >&2; exit 1; }
fi
`
			registryReady := `if [ "$(docker container inspect shuttle-registry --format '{{.State.Running}}')" != true ]; then
  docker start shuttle-registry >/dev/null
fi
attempt=0
while [ "$attempt" -lt 24 ]; do
  if [ "$(docker container inspect shuttle-registry --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null)" = healthy ] && curl -fsS --max-time 2 http://127.0.0.1:5000/v2/ >/dev/null; then break; fi
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$attempt" -ge 24 ]; then echo 'loopback registry is not healthy' >&2; docker container logs --tail 50 shuttle-registry >&2 || :; exit 1; fi
`
			stages = append(stages, setupStage{"21-registry-nonroot", "set -eu\n" + registryGuard + body + registryReady})
		case stage.name == "postgres" && containsAdoptionStep(survey.Satisfied, "30-postgres"):
			guard := "set -eu\ncluster=" + shell.Escape(survey.PostgresCluster) + "\n" + adoptionOwnedFilesGuard()
			retentionPath := shell.Escape("/etc/shuttle/postgres-backup.d/" + cfg.App + ".conf")
			retentionGuard := fmt.Sprintf("retention_owned %s || { echo 'foreign PostgreSQL retention configuration' >&2; exit 1; }\n", retentionPath)
			script := guard + "backup_owned || { echo 'foreign PostgreSQL backup script' >&2; exit 1; }\n" + retentionGuard + "install -d -o root -g root -m 0700 /var/backups/shuttle-postgres\nprintf '%s' " + shell.Escape(postgresBackupScript) + " >/usr/local/sbin/shuttle-postgres-backup\nchmod 0700 /usr/local/sbin/shuttle-postgres-backup\n" + retentionGuard + adoptionPostgresRetentionConfig(cfg.App, cfg.Retention.Backups)
			timer := guard + "backup_service_owned && backup_timer_owned || { echo 'foreign PostgreSQL backup service or timer' >&2; exit 1; }\nprintf '%s' " + shell.Escape(adoptionBackupService) + " >/etc/systemd/system/shuttle-postgres-backup.service\nprintf '%s' " + shell.Escape(adoptionBackupTimer) + " >/etc/systemd/system/shuttle-postgres-backup.timer\nsystemctl daemon-reload\nsystemctl enable --now shuttle-postgres-backup.timer\n"
			boot := guard + "boot_dropin_owned || { echo 'foreign PostgreSQL boot-order drop-in' >&2; exit 1; }\ninstall -d -m 0755 \"/etc/systemd/system/postgresql@$cluster.service.d\"\nprintf '%s' " + shell.Escape(adoptionBootDropin) + " >\"/etc/systemd/system/postgresql@$cluster.service.d/10-shuttle-after-docker.conf\"\nsystemctl daemon-reload\nsystemctl show \"postgresql@$cluster.service\" -p After --value | tr ' ' '\\n' | grep -Fx docker.service >/dev/null || { echo 'PostgreSQL boot order does not include docker.service' >&2; exit 1; }\n"
			stages = append(stages, setupStage{"31-postgres-backup-script", script}, setupStage{"31-postgres-backup-timer", timer}, setupStage{"32-postgres-boot-order", boot})
		case stage.name == "postgres":
			path := shell.Escape("/etc/shuttle/postgres-backup.d/" + cfg.App + ".conf")
			retentionGuard := fmt.Sprintf("retention_owned %s || { echo 'foreign PostgreSQL retention configuration' >&2; exit 1; }\n", path)
			guard := "set -eu\n" + adoptionOwnedFilesGuard() + retentionGuard
			write := postgresBackupRetentionConfig(cfg.App, cfg.Retention.Backups)
			stage.command = guard + strings.ReplaceAll(stage.command, write, retentionGuard+adoptionPostgresRetentionConfig(cfg.App, cfg.Retention.Backups))
			stages = append(stages, stage)
		default:
			stages = append(stages, stage)
		}
	}
	return stages
}
