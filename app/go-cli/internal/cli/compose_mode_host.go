package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// Everything the compose strategy runs on the host is a `docker` or `docker
// compose` command executed as the configured account, over SSH, with no
// privilege. The commands are built as text by the functions below so the
// exact argv can be asserted without a host, and executed through two seams
// so the sequence can be exercised without one.

var composeRemoteRunner = func(client *ssh.Client, command string) ssh.Result {
	return client.Run(command)
}

var composeRemoteStreamRunner = func(client *ssh.Client, command string, input io.Reader) ssh.Result {
	return client.RunWithReader(command, input)
}

var composeRemoteStdinRunner = func(client *ssh.Client, command string, input []byte) ssh.Result {
	return client.RunWithStdin(command, input)
}

// composeHost is one host reached as one account for one application.
type composeHost struct {
	lock    *composeLock
	client  *ssh.Client
	cfg     *config.Config
	user    string
	address string
	// home is the account's home directory as the host reported it; every
	// path Shuttle writes is under it.
	home string
	// platform is what every image of the run is built for: the host's
	// architecture, not the workstation's.
	platform string
	// memInfo is the host's MemTotal and MemAvailable as the preflight read them.
	memInfo string
}

func (h composeHost) run(command string) ssh.Result {
	return h.observe(composeRemoteRunner(h.client, command))
}

func (h composeHost) project() string { return h.cfg.ComposeProjectName() }

// releaseRoot is where releases live: inside the account's home, so nothing
// outside it is ever written, and per application, so two applications
// deployed as the same account keep apart.
func (h composeHost) releaseRoot() string {
	return h.home + "/.shuttle/" + h.cfg.App + "/releases"
}

func (h composeHost) releaseDir(version string) string {
	return h.releaseRoot() + "/" + version
}

func (h composeHost) composeFile(release string) string {
	return release + "/docker-compose.yml"
}

// composePreflightCommand reads what the deploy depends on, and changes
// nothing: the account, its home, whether docker answers it, the compose
// plugin version, the image store, and the projects already present.
const composePreflightCommand = `set -eu
printf 'user=%s\n' "$(id -un)"
printf 'home=%s\n' "$HOME"
if ! docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
  printf 'docker=unreachable\n'
  exit 0
fi
printf 'docker=%s\n' "$(docker info --format '{{.ServerVersion}}')"
printf 'compose=%s\n' "$(docker compose version --short 2>/dev/null || printf none)"
printf 'driver=%s\n' "$(docker info --format '{{.Driver}}')"
printf 'arch=%s\n' "$(docker info --format '{{.Architecture}}')"
printf 'store=%s\n' "$(docker info --format '{{range .DriverStatus}}{{index . 0}}={{index . 1}};{{end}}')"
printf 'projects='
docker compose ls -a --format json 2>/dev/null || printf '[]'
printf '\n'
printf 'disk_free_percent=%s\n' "$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print 100-$5}')"
printf 'meminfo=%s\n' "$(awk '/^(MemTotal|MemAvailable):/ {printf "%s %s %s;", $1, $2, $3}' /proc/meminfo)"
`

type composePreflight struct {
	User     string
	Home     string
	Docker   string
	Compose  string
	Driver   string
	Store    string
	Arch     string
	Projects []composeProjectListing
	// DiskFreePercent and MemInfo travel in the same report as the rest, so
	// the free-disk and memory budgets cost no SSH round trip of their own:
	// each session is a handshake over a VPN, and a deploy made a dozen of
	// them in a row.
	DiskFreePercent int
	MemInfo         string
}

// composePlatform maps the architecture the host daemon reports to the
// platform every build of the run targets. The workstation and the host do
// not share one — an Apple-silicon laptop deploying to an x86 VPS is the
// ordinary case — and an image built for the wrong one loads without a
// complaint and fails at `exec` on the first container start.
func composePlatform(arch string) (string, error) {
	switch arch {
	case "x86_64", "amd64":
		return "linux/amd64", nil
	case "aarch64", "arm64":
		return "linux/arm64", nil
	default:
		return "", fmt.Errorf("the host daemon reports architecture %q, which this strategy does not know how to build for", arch)
	}
}

type composeProjectListing struct {
	Name        string `json:"Name"`
	Status      string `json:"Status"`
	ConfigFiles string `json:"ConfigFiles"`
}

// parseComposePreflight reads the report and refuses what the strategy cannot
// work with, naming the fact rather than the symptom it would otherwise
// become several minutes later.
func parseComposePreflight(body string) (composePreflight, error) {
	report := composePreflight{}
	for _, line := range strings.Split(body, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "user":
			report.User = value
		case "home":
			report.Home = value
		case "docker":
			report.Docker = value
		case "compose":
			report.Compose = value
		case "driver":
			report.Driver = value
		case "arch":
			report.Arch = value
		case "store":
			report.Store = value
		case "projects":
			if err := json.Unmarshal([]byte(strings.TrimSpace(value)), &report.Projects); err != nil {
				return composePreflight{}, fmt.Errorf("cannot read the host's compose project list: %w", err)
			}
		case "disk_free_percent":
			percent, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return composePreflight{}, errors.New("cannot verify remote free-disk policy")
			}
			report.DiskFreePercent = percent
		case "meminfo":
			report.MemInfo = strings.ReplaceAll(value, ";", "\n")
		}
	}
	if report.User == "" || !strings.HasPrefix(report.Home, "/") {
		return composePreflight{}, errors.New("the host did not report the deploy account and its home directory")
	}
	return report, nil
}

// checkComposePreflight is the verdict on the report, in the order an operator
// fixes things: the account first, then the tools, then the store.
func checkComposePreflight(report composePreflight, cfg *config.Config, releaseRoot string) error {
	if report.Docker == "unreachable" {
		return fmt.Errorf("docker does not answer %s on the host: the account must be in the docker group (or otherwise able to reach the daemon socket); deploy.strategy: compose never grants that itself", report.User)
	}
	if _, err := composePlatform(report.Arch); err != nil {
		return err
	}
	if report.DiskFreePercent < 20 {
		return fmt.Errorf("deployment refused: %d%% disk free, minimum is 20%%", report.DiskFreePercent)
	}
	major, minor, ok := parseComposeVersion(report.Compose)
	if !ok || major < 2 || (major == 2 && minor < 20) {
		return fmt.Errorf("docker compose v2.20 or later is required on the host for `up --wait`, found %q", report.Compose)
	}
	project := cfg.ComposeProjectName()
	for _, listed := range report.Projects {
		if listed.Name != project {
			continue
		}
		for _, file := range strings.Split(listed.ConfigFiles, ",") {
			if strings.TrimSpace(file) != "" && !strings.HasPrefix(strings.TrimSpace(file), releaseRoot+"/") {
				return fmt.Errorf("a compose project named %q already runs on the host from %s, which Shuttle did not write; deploying under that name would recreate and remove its containers. Name Shuttle's project differently with deploy.compose.project, or stop that project first", project, strings.TrimSpace(file))
			}
		}
	}
	return nil
}

func parseComposeVersion(value string) (major, minor int, ok bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	parts := strings.SplitN(value, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// localPlatform is what this machine's daemon builds for by default, from the
// CLI's own architecture: docker runs where the CLI runs.
func localPlatform() string {
	switch runtime.GOARCH {
	case "amd64":
		return "linux/amd64"
	case "arm64":
		return "linux/arm64"
	default:
		return "linux/" + runtime.GOARCH
	}
}

// resolveComposeBuildLocation decides where the images are built.
func resolveComposeBuildLocation(configured, hostPlatform, local string) string {
	switch configured {
	case config.ComposeBuildLocal, config.ComposeBuildHost:
		return configured
	default:
		if hostPlatform == local {
			return config.ComposeBuildLocal
		}
		return config.ComposeBuildHost
	}
}

// knownHostsHoldsFingerprint reads `ssh-keygen -lF <host>` and reports whether
// the host key OpenSSH would accept is the one config.json pins.
//
// A host build drives the daemon through the docker CLI's own SSH transport,
// which trusts ~/.ssh/known_hosts and not Shuttle's pinned fingerprint. The
// build context travels over that connection, so before using it Shuttle
// checks that what OpenSSH knows for the host is the fingerprint the operator
// wrote down; anything else is refused rather than trusted by proximity.
func knownHostsHoldsFingerprint(listing, fingerprint string) bool {
	for _, line := range strings.Split(listing, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, " ED25519 "+fingerprint) || strings.HasSuffix(strings.TrimSpace(line), " "+fingerprint) && strings.Contains(line, "ED25519") {
			return true
		}
	}
	return false
}

// composeUpCommand is the promotion: every service recreated as needed and
// waited on until healthy, inside the convergence share of the promotion
// budget. --remove-orphans is scoped by the project name, which is why the
// name is required and the preflight refuses one somebody else uses.
func composeUpCommand(project, file string, wait time.Duration) string {
	seconds := int(wait / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return "docker compose -p " + shell.Escape(project) + " -f " + shell.Escape(file) + " up -d --wait --wait-timeout " + strconv.Itoa(seconds) + " --remove-orphans"
}

func composePsCommand(project string) string {
	return "docker compose -p " + shell.Escape(project) + " ps -a --format json"
}

func composeStatusCommand(project string) string {
	return "docker compose -p " + shell.Escape(project) + " ps -a"
}

func composeLogsCommand(project, service string, lines int) string {
	return "docker compose -p " + shell.Escape(project) + " logs --no-color --tail " + strconv.Itoa(lines) + " " + shell.Escape(service)
}

// composeExecCommand runs a declared operation: an argv, never a shell
// string, escaped word by word.
func composeExecCommand(project, service string, argv []string) string {
	words := make([]string, 0, len(argv))
	for _, word := range argv {
		words = append(words, shell.Escape(word))
	}
	return "docker compose -p " + shell.Escape(project) + " exec -T " + shell.Escape(service) + " " + strings.Join(words, " ")
}

func composeDownCommand(project string, volumes bool) string {
	command := "docker compose -p " + shell.Escape(project) + " down --remove-orphans"
	if volumes {
		command += " --volumes"
	}
	return command
}

// composePrepareReleaseCommand creates the release directory, 0700 like its
// parents, so nothing outside the account can read a compose file that
// carries inlined configuration.
func composePrepareReleaseCommand(release string) string {
	// install -d accepts existing directories and symlinks. Reserve the leaf
	// exclusively before uploading anything, so even an identity collision
	// cannot overwrite a retained release or its materialised secrets.
	return "set -eu; install -d -m 0700 " + shell.Escape(path.Dir(release)) + "; mkdir -m 0700 " + shell.Escape(release)
}

// composeRotateCommand moves `current` to the new release and keeps the one
// it pointed to as `previous` only when the source changes. Attempt identities
// differ even for a redeploy: rotating on those would discard W after W, X, X.
func composeRotateCommand(root, version, sourceVersion string) string {
	return `set -eu
cd ` + shell.Escape(root) + `
if [ -L current ]; then
  old=$(readlink current)
  # Older releases used the source itself; attempts append one timestamp.
  if [ "$old" != ` + shell.Escape(sourceVersion) + ` ] && [ "${old%-*}" != ` + shell.Escape(sourceVersion) + ` ]; then
    ln -sfn "$old" previous
  fi
fi
ln -sfn ` + shell.Escape(version) + ` current
`
}

// composeSwapCommand exchanges current and previous after a rollback.
func composeSwapCommand(root string) string {
	return `set -eu
cd ` + shell.Escape(root) + `
test -L previous
old=$(readlink current)
ln -sfn "$(readlink previous)" current
ln -sfn "$old" previous
`
}

// composeRetainCommand removes the release directories that are neither
// current nor previous, and the images this application built that neither
// release references. Filtered by the application label, so an image anybody
// else loaded on the same daemon is not Shuttle's to remove; never
// `docker system prune`, never an unfiltered `-a`.
func composeRetainCommand(root, app string) string {
	return `set -eu
cd ` + shell.Escape(root) + `
keep_dirs=""
keep_images=""
for link in current previous; do
  if [ -L "$link" ]; then
    target=$(readlink "$link")
    keep_dirs="$keep_dirs $target"
    if [ -f "$target/docker-compose.yml" ]; then
      keep_images="$keep_images $(sed -n -e 's/^ *image: *//p' -e 's/^# shuttle-source-image: *//p' "$target/docker-compose.yml" | tr -d '"' | tr '\n' ' ')"
    fi
  fi
done
for dir in */; do
  dir=${dir%/}
  # The glob matches the two links too, since they point at directories, and
  # rm -rf on a link removes the link: the first real deploy lost its
  # "current" this way and reported success. Links are never candidates.
  [ -d "$dir" ] || continue
  [ -L "$dir" ] && continue
  # A newer preparation must survive even if it has not become current yet.
  if [ -f .lock ] && [ "$dir" -nt .lock ]; then continue; fi
  keep=0
  for kept in $keep_dirs; do
    [ "$dir" = "$kept" ] && keep=1
  done
  [ "$keep" = 1 ] || rm -rf -- "$dir"
done
docker images --filter ` + shell.Escape("label="+composeAppLabel+"="+app) + ` --format '{{.Repository}}:{{.Tag}}' | while read -r image; do
  keep=0
  for kept in $keep_images; do
    [ "$image" = "$kept" ] && keep=1
  done
  if [ "$keep" != 1 ]; then
    docker image rm "$image" >/dev/null 2>&1 || :
  fi
done
docker image prune -f --filter ` + shell.Escape("label="+composeAppLabel+"="+app) + ` >/dev/null 2>&1 || :
`
}

// composeLoadRecoveryCommand is run after a load that did not complete: the
// tar's manifest comes last, so an interrupted stream leaves untagged layers
// and no tag. The tag must be absent, and only dangling images carrying this
// application's label are reclaimed.
func composeLoadRecoveryCommand(app string, tags []string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	for _, tag := range tags {
		b.WriteString("docker image rm " + shell.Escape(tag) + " >/dev/null 2>&1 || :\n")
	}
	b.WriteString("docker image prune -f --filter " + shell.Escape("label="+composeAppLabel+"="+app) + " >/dev/null 2>&1 || :\n")
	return b.String()
}

// composeImageIDsCommand prints, per tag and in the order given, the image ID
// the host's daemon uses and the image's content identity, tab-separated, or
// fails on the first tag the daemon does not hold.
//
// Two values because they answer two questions. The content identity — the
// layer diff IDs — is the same for the same image on any daemon, whatever
// image store it runs, so it is what the loaded image is compared against
// the built one with. The daemon's own ID is what its containers report as
// their image, so it is what the running containers are compared against;
// under the containerd store it is a manifest digest, under the classic
// store a config digest, and only the host's own reading of it is used.
func composeImageIDsCommand(tags []string) string {
	quoted := make([]string, 0, len(tags))
	for _, tag := range tags {
		quoted = append(quoted, shell.Escape(tag))
	}
	return "docker image inspect --format '{{.Id}}\t{{json .RootFS.Layers}}' " + strings.Join(quoted, " ")
}

// composeImageIdentityFormat is the local reading of the same content
// identity, through the same field.
const composeImageIdentityFormat = "{{json .RootFS.Layers}}"

// composeContainerImagesCommand prints, for every container of the project,
// `service<TAB>state<TAB>imageID<TAB>reference<TAB>referenceID`: the image
// the container runs, by the daemon's ID; the reference it was created from,
// as the compose file of its release spelled it; and the ID that reference
// resolves to on the daemon now, empty when it no longer resolves.
//
// The first three are what the release identity check compares against the
// IDs the load produced. The last two are what lets the next release keep a
// reference alive, see reuseRunningImages.
func composeContainerImagesCommand(project string) string {
	return `set -eu
docker compose -p ` + shell.Escape(project) + ` ps -aq | while read -r id; do
  [ -n "$id" ] || continue
  docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}	{{.State.Status}}	{{.Image}}	{{.Config.Image}}' "$id" | while IFS='	' read -r service state image reference; do
    resolved=""
    if [ -n "$reference" ]; then
      resolved=$(docker image inspect --format '{{.Id}}' "$reference" 2>/dev/null || :)
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$service" "$state" "$image" "$reference" "$resolved"
  done
done
`
}

// composeContainerImage is one row of the report above.
type composeContainerImage struct {
	Service string
	State   string
	ImageID string
	// Reference is the image reference the container was created from, as
	// the compose file of its release spelled it.
	Reference string
	// ReferenceID is the ID the reference resolves to on the daemon at the
	// time of the report, or empty when it does not resolve any more.
	ReferenceID string
}

func parseComposeContainerImages(body string) []composeContainerImage {
	rows := []composeContainerImage{}
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) != 5 || strings.TrimSpace(fields[0]) == "" {
			continue
		}
		rows = append(rows, composeContainerImage{Service: fields[0], State: fields[1], ImageID: fields[2], Reference: fields[3], ReferenceID: fields[4]})
	}
	return rows
}

// reuseRunningImages decides, per built service, which image reference the
// release file carries: the tag this run built, or the reference the service
// already runs when the daemon says the two are the same image.
//
// Compose recreates a container when the hash of its service configuration
// changes, and the image reference is part of that hash. A tag per release is
// what makes a release immutable, but on a service whose code did not change
// it is also a configuration change that is not one. On the Demo
// pre-production, a deploy with nothing changed and a warm cache rebuilt
// three images to the exact IDs already running, and still recreated every
// service using them: the API that takes a minute to come up, the poller and
// the backup with it. Same ID, different string, restart.
//
// So a service keeps the reference it runs when the new tag and that
// reference resolve to the same image: same configuration hash, no
// recreation, and the retention keeps the reference alive because the new
// release file names it. Every ID in the comparison is the host's own reading
// from the one daemon — the new tag as loaded, the image the container runs,
// the reference as it resolves now — so a reference removed or re-tagged
// since the container started is never written into a release. Only a
// reference in the repository this run built for is eligible: a container
// someone started under the project by hand is not Shuttle's to name in a
// release.
//
// The result maps every service of planned; reused lists, sorted, the
// services that keep their immutable attempt reference. Mutable source aliases
// transition once to an attempt tag, at the cost of one recreation.
func reuseRunningImages(planned map[string]string, builtIDs map[string]string, running []composeContainerImage) (images map[string]string, reused []string) {
	byService := make(map[string]composeContainerImage, len(running))
	for _, row := range running {
		byService[row.Service] = row
	}
	images = make(map[string]string, len(planned))
	for service, tag := range planned {
		images[service] = tag
		row, listed := byService[service]
		if !listed || row.Reference == "" || row.Reference == tag {
			continue
		}
		// A source alias can move on the next build even if its ID matches
		// now. Only attempts carry a final timestamp after their source;
		// dirty sources themselves end in -dirty-<time> and are mutable.
		referenceTag := strings.TrimPrefix(row.Reference, imageRepository(row.Reference)+":")
		split := strings.LastIndex(referenceTag, "-")
		if split <= 0 || strings.HasSuffix(referenceTag[:split], "-dirty") {
			continue
		}
		stamp := referenceTag[split+1:]
		if len(stamp) != 24 || strings.Trim(stamp[15:], "0123456789") != "" {
			continue
		}
		if _, err := time.Parse("20060102T150405", stamp[:15]); err != nil {
			continue
		}
		builtID := builtIDs[tag]
		if builtID == "" || row.ImageID != builtID || row.ReferenceID != builtID {
			continue
		}
		if imageRepository(row.Reference) != imageRepository(tag) {
			continue
		}
		images[service] = row.Reference
		reused = append(reused, service)
	}
	sort.Strings(reused)
	return images, reused
}

// imageRepository is a reference without its tag and digest.
func imageRepository(reference string) string {
	if at := strings.Index(reference, "@"); at >= 0 {
		reference = reference[:at]
	}
	slash := strings.LastIndex(reference, "/")
	if colon := strings.LastIndex(reference, ":"); colon > slash {
		reference = reference[:colon]
	}
	return reference
}

// compareComposeRelease returns one complaint per built service that is not
// running the image this deploy loaded, in service order, or nil.
//
// Only the built services are compared: they are the ones whose identity the
// deploy established. A service the project no longer declares is not listed
// among the wanted ones, so dropping a service cannot fail a deploy.
func compareComposeRelease(wanted map[string]string, reported []composeContainerImage) []string {
	byService := map[string]composeContainerImage{}
	for _, row := range reported {
		byService[row.Service] = row
	}
	services := make([]string, 0, len(wanted))
	for service := range wanted {
		services = append(services, service)
	}
	sort.Strings(services)
	complaints := []string{}
	for _, service := range services {
		row, listed := byService[service]
		if !listed {
			complaints = append(complaints, fmt.Sprintf("%s: the project reports no container for this service", service))
			continue
		}
		if row.State != "running" {
			complaints = append(complaints, fmt.Sprintf("%s: container is %s, not running", service, row.State))
			continue
		}
		if row.ImageID != wanted[service] {
			complaints = append(complaints, fmt.Sprintf("%s: running %s, this release is %s", service, shortImageID(row.ImageID), shortImageID(wanted[service])))
		}
	}
	if len(complaints) == 0 {
		return nil
	}
	return complaints
}

func shortImageID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// composeTransferTimeout sizes the SSH deadline of the image stream from the
// bytes to move: the two-minute default is a transport deadline and a
// multi-hundred-megabyte archive on an ordinary uplink does not fit in it. A
// floor of one mebibyte per second on top of the default, capped at thirty
// minutes so a dead link is still reported this side of an hour.
func composeTransferTimeout(bytes int64) time.Duration {
	timeout := 2*time.Minute + time.Duration(bytes/(1<<20))*time.Second
	if timeout > 30*time.Minute {
		return 30 * time.Minute
	}
	return timeout
}

// composeStreamTimeout is the deadline the compose up command may hold its
// session: the convergence wait plus room for image creation and the
// command's own round trips.
func composeUpTimeout(promotionSLOSeconds int) time.Duration {
	return config.DeployWaits(promotionSLOSeconds).StackConvergence + rootHelperOperationMargin
}

// composeReleaseImages lists the images a project file references, which is
// the keep-set of the remote prune for that release.
func composeReleaseImages(project string) []string {
	images := []string{}
	for _, line := range strings.Split(project, "\n") {
		trimmed := strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(trimmed, "image:"); ok {
			images = append(images, strings.Trim(strings.TrimSpace(value), "\"'"))
		}
	}
	sort.Strings(images)
	return images
}

func composeAttemptImages(planned map[string]string, version string) map[string]string {
	images := make(map[string]string, len(planned))
	for service, tag := range planned {
		images[service] = imageRepository(tag) + ":" + version
	}
	return images
}

// Tag by the inspected ID, not by the mutable source alias. Docker adds a
// reference to the same image and layers; a later load cannot move this tag.
func (h composeHost) tagAttemptImages(planned, attempts, ids map[string]string) error {
	tags := make(map[string]string)
	for service, source := range planned {
		tags[attempts[service]] = ids[source]
	}
	names := make([]string, 0, len(tags))
	for tag := range tags {
		names = append(names, tag)
	}
	sort.Strings(names)
	for _, tag := range names {
		if result := h.run("docker tag " + shell.Escape(tags[tag]) + " " + shell.Escape(tag)); result.Code != 0 {
			return fmt.Errorf("retain attempt image %s: %s", tag, strings.TrimSpace(result.Stderr))
		}
	}
	return nil
}
