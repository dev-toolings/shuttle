package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
)

type existingStackRetention struct {
	KeepReleases *int `json:"keep_releases,omitempty"`
	// BuildCache caps the local BuildKit cache kept between deploys.
	BuildCache string `json:"build_cache,omitempty"`
}

func (r existingStackRetention) count() int {
	if r.KeepReleases == nil {
		return 1
	}
	return *r.KeepReleases
}

type existingRemoteRun func(string) (string, error)

// Cleanup is deliberately beyond the apply/verification barrier. The platform
// completes rollback inside apply; retained releases are only retired after it
// succeeds. Live service and task references always override the release count.
func finishExistingStack(cfg *existingStackConfig, images []string, run existingRemoteRun) {
	usageBefore, usageErr := run("df -B1 /; " + cfg.docker("system", "df"))
	if usageErr != nil {
		output.Attn("Retention disk usage: %v", usageErr)
	} else {
		output.Detail("Disk usage before retention:\n%s", usageBefore)
	}
	before, beforeErr := existingDiskFree(run)
	if beforeErr != nil {
		output.Attn("Retention disk measurement: %v", beforeErr)
	}
	reports, err := retainExistingStack(cfg, images, run)
	if err != nil {
		output.Attn("Upgrade verified, but release cleanup is incomplete: %v", err)
	}
	summaries, warnings, _ := formatExistingRetention(reports)
	for _, line := range summaries {
		output.Detail("%s", line)
	}
	for _, line := range warnings {
		output.Attn("%s", line)
	}
	after, afterErr := existingDiskFree(run)
	if afterErr != nil {
		output.Attn("Retention disk measurement: %v", afterErr)
	}
	if beforeErr == nil && afterErr == nil {
		freed := after - before
		if freed < 0 {
			freed = 0
		}
		output.Detail("Host disk free before: %d bytes; after: %d bytes; freed: %d bytes (concurrent host activity may affect this measurement)", before, after, freed)
	}
	usage, err := run("df -B1 /; " + cfg.docker("system", "df"))
	if err != nil {
		output.Attn("Retention disk usage: %v", err)
	} else {
		output.Detail("Disk usage after retention:\n%s", usage)
	}
	output.Detail("Registry manifest deletion does not reclaim blobs: run the platform-owned registry's offline garbage-collect during its maintenance window, with writes stopped; Shuttle's registry-gc/cache-prune target its managed registry only.")
}

func existingDiskFree(run existingRemoteRun) (int64, error) {
	body, err := run("df -B1 --output=avail / | tail -n 1")
	if err != nil {
		return 0, err
	}
	var free int64
	_, err = fmt.Sscan(body, &free)
	return free, err
}

const existingManifestAccept = "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json"

func existingRegistryRequest(cfg *existingStackConfig, run existingRemoteRun, method, path string) (*http.Response, error) {
	args := []string{"curl", "--silent", "--show-error", "--noproxy", "*", "--max-time", "20", "--dump-header", "-"}
	if method == "HEAD" {
		args = append(args, "--head", "--output", "/dev/null")
	} else {
		args = append(args, "--request", method)
	}
	args = append(args, "--header", "Accept: "+existingManifestAccept, "http://"+cfg.Registry+"/v2/"+path)
	command := existingStackArgv(args, nil)
	body, err := run(command)
	if err != nil {
		return nil, err
	}
	// The SSH runner trims trailing whitespace; HEAD and empty DELETE replies
	// consequently lose their final blank header line. Curl has also already
	// decoded any chunked body, so parse only headers and supply the decoded body.
	headers, payload, _ := strings.Cut(body, "\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(strings.TrimRight(headers, "\r\n")+"\r\n\r\n")), nil)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(strings.NewReader(payload))
	return response, nil
}

func existingRegistryDigest(cfg *existingStackConfig, run existingRemoteRun, repo, tag string) (string, error) {
	response, err := existingRegistryRequest(cfg, run, "HEAD", repo+"/manifests/"+tag)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	digest := response.Header.Get("Docker-Content-Digest")
	if response.StatusCode != 200 || !digestImage.MatchString(cfg.Registry+"/"+repo+"@"+digest) {
		return "", fmt.Errorf("cannot resolve registry digest for %s:%s (HTTP %d)", repo, tag, response.StatusCode)
	}
	return digest, nil
}

// Active references protect both host images and registry manifests. Stopped
// container history protects only host images because its manifest is no
// longer needed by the running platform.
type existingLiveReferences struct {
	Active  map[string]bool
	Stopped map[string]bool
}

func existingLiveImages(cfg *existingStackConfig, run existingRemoteRun) (existingLiveReferences, error) {
	references := existingLiveReferences{Active: map[string]bool{}, Stopped: map[string]bool{}}
	ids, err := run(cfg.docker("service", "ls", "-q"))
	if err != nil {
		return existingLiveReferences{}, err
	}
	services := strings.Fields(ids)
	if len(services) == 0 {
		return existingLiveReferences{}, fmt.Errorf("no live services visible; refusing cleanup")
	}
	body, err := run(cfg.docker(append([]string{"service", "inspect"}, services...)...))
	if err != nil {
		return existingLiveReferences{}, err
	}
	var specs []struct {
		Spec struct {
			TaskTemplate struct{ ContainerSpec struct{ Image string } }
		}
	}
	if err := json.Unmarshal([]byte(body), &specs); err != nil {
		return existingLiveReferences{}, err
	}
	if len(specs) != len(services) {
		return existingLiveReferences{}, fmt.Errorf("incomplete service inspection")
	}
	for _, spec := range specs {
		if spec.Spec.TaskTemplate.ContainerSpec.Image == "" {
			return existingLiveReferences{}, fmt.Errorf("service image missing")
		}
		references.Active[spec.Spec.TaskTemplate.ContainerSpec.Image] = true
	}
	tasks, err := run(cfg.docker(append([]string{"service", "ps", "--no-trunc", "--filter", "desired-state=running", "-q"}, services...)...))
	if err != nil {
		return existingLiveReferences{}, err
	}
	if ids := strings.Fields(tasks); len(ids) > 0 {
		body, err := run(cfg.docker(append([]string{"inspect", "--type", "task"}, ids...)...))
		if err != nil {
			return existingLiveReferences{}, err
		}
		var tasks []struct {
			Spec struct{ ContainerSpec struct{ Image string } }
		}
		if err := json.Unmarshal([]byte(body), &tasks); err != nil {
			return existingLiveReferences{}, err
		}
		if len(tasks) != len(ids) {
			return existingLiveReferences{}, fmt.Errorf("incomplete task inspection")
		}
		for _, task := range tasks {
			if task.Spec.ContainerSpec.Image == "" {
				return existingLiveReferences{}, fmt.Errorf("task image missing")
			}
			references.Active[task.Spec.ContainerSpec.Image] = true
		}
	}
	// A task can still be running while its desired state has changed to
	// shutdown during an update. Stopped task history remains relevant to the
	// host image store, but does not retain registry manifests.
	containers, err := run(cfg.docker("ps", "-a", "-q"))
	if err != nil {
		return existingLiveReferences{}, err
	}
	if ids := strings.Fields(containers); len(ids) > 0 {
		body, err := run(cfg.docker(append([]string{"container", "inspect"}, ids...)...))
		if err != nil {
			return existingLiveReferences{}, err
		}
		var containers []struct {
			Config struct{ Image string }
			Image  string
			State  *struct{ Running, Restarting bool }
		}
		if err := json.Unmarshal([]byte(body), &containers); err != nil {
			return existingLiveReferences{}, err
		}
		if len(containers) != len(ids) {
			return existingLiveReferences{}, fmt.Errorf("incomplete container inspection")
		}
		for _, container := range containers {
			if container.State == nil {
				return existingLiveReferences{}, fmt.Errorf("container state missing")
			}
			set := references.Stopped
			if container.State.Running || container.State.Restarting {
				set = references.Active
			}
			if container.Config.Image != "" {
				set[container.Config.Image] = true
			}
			if container.Image != "" {
				set[container.Image] = true
			}
		}
	}
	// A service, task or container can refer to an image ID instead of a
	// registry ref. Resolve all such IDs in one remote call while the image
	// store still holds them, preserving each ID's active/stopped classification.
	for _, set := range []map[string]bool{references.Active, references.Stopped} {
		var imageIDs []string
		for ref := range set {
			if strings.HasPrefix(ref, "sha256:") {
				imageIDs = append(imageIDs, ref)
			}
		}
		if len(imageIDs) == 0 {
			continue
		}
		sort.Strings(imageIDs)
		body, err := run(cfg.docker(append([]string{"image", "inspect", "--format", "{{json .RepoDigests}}"}, imageIDs...)...))
		if err != nil {
			return existingLiveReferences{}, err
		}
		lines := strings.Split(body, "\n")
		if len(lines) != len(imageIDs) {
			return existingLiveReferences{}, fmt.Errorf("incomplete image inspection")
		}
		for i, line := range lines {
			var digests []string
			if err := json.Unmarshal([]byte(line), &digests); err != nil {
				return existingLiveReferences{}, err
			}
			for _, digest := range digests {
				set[digest] = true
				set[digestImageID(imageIDs[i])] = true
			}
		}
	}
	return references, nil
}

func digestImageID(ref string) string {
	if _, digest, ok := strings.Cut(ref, "@"); ok {
		return digest
	}
	return ref
}

func existingReferenceSetContains(references map[string]bool, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if references[candidate] {
			return true
		}
		digest := digestImageID(candidate)
		if !strings.HasPrefix(digest, "sha256:") {
			continue
		}
		if references[digest] {
			return true
		}
		for reference := range references {
			if strings.HasSuffix(reference, "@"+digest) {
				return true
			}
		}
	}
	return false
}

func existingUnreadableActiveAlias(references map[string]bool, unreadable map[string]bool, prefix string) bool {
	for tag := range unreadable {
		if references[prefix+tag] {
			return true
		}
	}
	return false
}

var existingReleaseTag = regexp.MustCompile(`^.+-[0-9]{8}T[0-9]{9,}$`)

type existingRetentionStep string

const (
	existingRetentionHostImage        existingRetentionStep = "host image"
	existingRetentionRegistryManifest existingRetentionStep = "registry manifest"
)

type existingRetentionOutcome string

const (
	existingRetentionRemoved existingRetentionOutcome = "removed"
	existingRetentionSkipped existingRetentionOutcome = "skipped"
	existingRetentionFailed  existingRetentionOutcome = "failed"
)

type existingRetentionEvent struct {
	Tag     string
	Step    existingRetentionStep
	Outcome existingRetentionOutcome
	Reason  string
}

type existingRepositoryRetention struct {
	Repository  string
	Events      []existingRetentionEvent
	Err         error
	ErrStep     existingRetentionStep
	Unattempted map[existingRetentionStep]int
}

func (report *existingRepositoryRetention) stop(step existingRetentionStep, err error) {
	report.Err = err
	report.ErrStep = step
}

func (report *existingRepositoryRetention) markUnattempted(step existingRetentionStep, count int) {
	if count < 1 {
		return
	}
	if report.Unattempted == nil {
		report.Unattempted = map[existingRetentionStep]int{}
	}
	report.Unattempted[step] += count
}

func (report *existingRepositoryRetention) hasOutcome(tag string, step existingRetentionStep) bool {
	for _, event := range report.Events {
		if event.Tag == tag && event.Step == step {
			return true
		}
	}
	return false
}

func (report *existingRepositoryRetention) markTagUnattempted(tag string, step existingRetentionStep) {
	if !report.hasOutcome(tag, step) {
		report.markUnattempted(step, 1)
	}
}

func retainExistingStack(cfg *existingStackConfig, images []string, run existingRemoteRun) ([]existingRepositoryRetention, error) {
	// Only exact repositories from this build plan are walked, never a catalog
	// or prefix matching an application. Non-release tags are also preserved.
	repositories := map[string]string{}
	for _, image := range images {
		at := strings.LastIndex(image, ":")
		if at < 0 || !strings.HasPrefix(image, cfg.Registry+"/") {
			return nil, fmt.Errorf("invalid published image %q", image)
		}
		repositories[strings.TrimPrefix(image[:at], cfg.Registry+"/")] = image[at+1:]
	}
	repos := make([]string, 0, len(repositories))
	for repo := range repositories {
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	reports := make([]existingRepositoryRetention, 0, len(repos))
	for _, repo := range repos {
		reports = append(reports, retainExistingRepository(cfg, run, repo, repositories[repo]))
	}
	return reports, nil
}

func retainExistingRepository(cfg *existingStackConfig, run existingRemoteRun, repo, current string) existingRepositoryRetention {
	report := existingRepositoryRetention{Repository: repo}
	response, err := existingRegistryRequest(cfg, run, "GET", repo+"/tags/list")
	if err != nil {
		report.stop(existingRetentionRegistryManifest, err)
		report.markUnattempted(existingRetentionHostImage, 1)
		report.markUnattempted(existingRetentionRegistryManifest, 1)
		return report
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		report.stop(existingRetentionRegistryManifest, fmt.Errorf("list %s: HTTP %d", repo, response.StatusCode))
		report.markUnattempted(existingRetentionHostImage, 1)
		report.markUnattempted(existingRetentionRegistryManifest, 1)
		return report
	}
	// Refuse an incomplete index rather than delete against a partial snapshot.
	if response.Header.Get("Link") != "" {
		report.stop(existingRetentionRegistryManifest, fmt.Errorf("registry paginated %s tags; cleanup skipped", repo))
		report.markUnattempted(existingRetentionHostImage, 1)
		report.markUnattempted(existingRetentionRegistryManifest, 1)
		return report
	}
	var index struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(response.Body).Decode(&index); err != nil {
		report.stop(existingRetentionRegistryManifest, err)
		report.markUnattempted(existingRetentionHostImage, 1)
		report.markUnattempted(existingRetentionRegistryManifest, 1)
		return report
	}
	tags := map[string]string{}
	listed := map[string]bool{}
	headFailed := map[string]bool{}
	for _, tag := range index.Tags {
		listed[tag] = true
	}
	for _, tag := range index.Tags {
		if _, seen := tags[tag]; seen {
			continue
		}
		digest, err := existingRegistryDigest(cfg, run, repo, tag)
		if err != nil {
			headFailed[tag] = true
			tags[tag] = ""
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionFailed, Reason: err.Error()})
			continue
		}
		tags[tag] = digest
	}
	if _, found := tags[current]; !found {
		report.stop(existingRetentionRegistryManifest, fmt.Errorf("current tag missing for %s", repo))
		for tag := range tags {
			if tag == current || !existingReleaseTag.MatchString(tag) {
				continue
			}
			report.markTagUnattempted(tag, existingRetentionHostImage)
			report.markTagUnattempted(tag, existingRetentionRegistryManifest)
		}
		return report
	}
	hostTags, err := run(cfg.docker("image", "ls", "--format", "{{.Repository}}:{{.Tag}}"))
	hostInventoryErr := err
	local := map[string]bool{}
	prefix := cfg.Registry + "/" + repo + ":"
	if hostInventoryErr == nil {
		for _, image := range strings.Fields(hostTags) {
			if strings.HasPrefix(image, prefix) {
				tag := strings.TrimPrefix(image, prefix)
				local[tag] = true
				if _, found := tags[tag]; !found {
					tags[tag] = ""
				}
			}
		}
	}
	kept := map[string]bool{current: true}
	var releases []string
	for tag := range tags {
		if existingReleaseTag.MatchString(tag) && tag != current {
			releases = append(releases, tag)
		}
	}
	sort.Slice(releases, func(i, j int) bool {
		return releases[i][strings.LastIndex(releases[i], "-")+1:] > releases[j][strings.LastIndex(releases[j], "-")+1:]
	})
	for i, tag := range releases {
		if i < cfg.Retention.count()-1 {
			kept[tag] = true
		}
	}
	if hostInventoryErr != nil {
		// Keep this repository-level failure even when no obsolete tag exists.
		report.Events = append(report.Events, existingRetentionEvent{Step: existingRetentionHostImage, Outcome: existingRetentionFailed, Reason: hostInventoryErr.Error()})
		for _, tag := range releases {
			if !kept[tag] {
				report.markTagUnattempted(tag, existingRetentionHostImage)
			}
		}
	}
	unreadableRetainedAlias := false
	for tag := range headFailed {
		if kept[tag] || !existingReleaseTag.MatchString(tag) {
			unreadableRetainedAlias = true
		}
	}
	protected := map[string]bool{}
	for tag, digest := range tags {
		if digest != "" && (kept[tag] || !existingReleaseTag.MatchString(tag)) {
			protected[digest] = true
		}
	}
	deleted := map[string]bool{}
	deletedBy := map[string]string{}
	registryDeletionDisabled := false
	// One snapshot covers local checks until a failed recheck invalidates it.
	// Only the first snapshot failure stops this repository; later failures are
	// recorded for their tag, and the next tag requests a fresh snapshot.
	var live *existingLiveReferences
	initialSnapshotAttempted := false
	for _, tag := range releases {
		if kept[tag] {
			continue
		}
		if live == nil {
			initialSnapshot := !initialSnapshotAttempted
			initialSnapshotAttempted = true
			snapshot, snapshotErr := existingLiveImages(cfg, run)
			if snapshotErr != nil {
				if initialSnapshot {
					report.stop(existingRetentionRegistryManifest, snapshotErr)
					for _, pendingTag := range releases {
						if kept[pendingTag] {
							continue
						}
						if hostInventoryErr == nil && local[pendingTag] {
							report.markTagUnattempted(pendingTag, existingRetentionHostImage)
						}
						if tags[pendingTag] != "" {
							report.markTagUnattempted(pendingTag, existingRetentionRegistryManifest)
						}
					}
					return report
				}
				if tags[tag] != "" && !report.hasOutcome(tag, existingRetentionRegistryManifest) {
					report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionFailed, Reason: snapshotErr.Error()})
				}
				if hostInventoryErr == nil && local[tag] {
					report.markTagUnattempted(tag, existingRetentionHostImage)
				}
				continue
			}
			live = &snapshot
		}
		image := cfg.Registry + "/" + repo + ":" + tag
		digest := tags[tag]
		var localImage struct {
			ID          string `json:"Id"`
			RepoDigests []string
		}
		var localInspectErr error
		localInspectFailed := false
		// Only remove a tag known to exist locally. A failed inspect means the
		// active image ID and RepoDigests cannot be checked, so its registry
		// manifest is held for this run.
		if hostInventoryErr == nil && local[tag] {
			body, err := run(cfg.docker("image", "inspect", "--format", "{{json .}}", image))
			if err != nil {
				localInspectErr = err
				localInspectFailed = true
			} else if err := json.Unmarshal([]byte(body), &localImage); err != nil {
				localInspectErr = err
				localInspectFailed = true
			} else if localImage.ID == "" {
				localInspectErr = fmt.Errorf("missing image ID for %s", image)
				localInspectFailed = true
			}
			if localInspectFailed {
				report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionHostImage, Outcome: existingRetentionFailed, Reason: localInspectErr.Error()})
			} else {
				candidates := append([]string{image, localImage.ID}, localImage.RepoDigests...)
				if digest != "" {
					candidates = append(candidates, cfg.Registry+"/"+repo+"@"+digest)
				}
				if existingReferenceSetContains(live.Active, candidates...) {
					report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionHostImage, Outcome: existingRetentionSkipped, Reason: "used by a running service, task or container"})
				} else if existingReferenceSetContains(live.Stopped, candidates...) {
					report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionHostImage, Outcome: existingRetentionSkipped, Reason: "used by a stopped container; never forced"})
				} else if _, err := run(cfg.docker("image", "rm", image)); err != nil {
					report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionHostImage, Outcome: existingRetentionFailed, Reason: err.Error()})
				} else {
					report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionHostImage, Outcome: existingRetentionRemoved})
				}
			}
		}
		if digest == "" {
			if listed[tag] && !headFailed[tag] {
				report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "registry digests of this repository are unreadable"})
			}
			continue
		}
		if localInspectFailed {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: localInspectErr.Error()})
			continue
		}
		if deleted[digest] {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "digest already deleted with tag " + deletedBy[digest]})
			continue
		}
		if unreadableRetainedAlias {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "registry digests of this repository are unreadable"})
			continue
		}
		if registryDeletionDisabled {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "registry deletion is disabled for this repository"})
			continue
		}
		if protected[digest] {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "shares a manifest with a retained tag"})
			continue
		}
		candidates := []string{digest, cfg.Registry + "/" + repo + "@" + digest, image, localImage.ID}
		candidates = append(candidates, localImage.RepoDigests...)
		for aliasTag, aliasDigest := range tags {
			if aliasDigest == digest {
				candidates = append(candidates, prefix+aliasTag)
			}
		}
		if existingUnreadableActiveAlias(live.Active, headFailed, prefix) {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "registry digests of this repository are unreadable"})
			continue
		}
		if existingReferenceSetContains(live.Active, candidates...) {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "used by a running service, task or container"})
			continue
		}
		// Re-resolve retained aliases immediately before DELETE: manifests may be
		// shared by several tags, and deleting a digest removes all those tags.
		aliasResolveFailed := false
		for keptTag := range tags {
			if tags[keptTag] == "" || (!kept[keptTag] && existingReleaseTag.MatchString(keptTag)) {
				continue
			}
			keptDigest, err := existingRegistryDigest(cfg, run, repo, keptTag)
			if err != nil {
				report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionFailed, Reason: err.Error()})
				aliasResolveFailed = true
				break
			}
			if keptDigest == digest {
				protected[digest] = true
			}
		}
		if aliasResolveFailed {
			continue
		}
		if protected[digest] {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "shares a manifest with a retained tag"})
			continue
		}
		// Local image removal and alias resolution take time. Recheck immediately
		// before the registry mutation as well.
		rechecked, err := existingLiveImages(cfg, run)
		if err != nil {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionFailed, Reason: err.Error()})
			live = nil
			continue
		}
		live = &rechecked
		if existingUnreadableActiveAlias(live.Active, headFailed, prefix) {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "registry digests of this repository are unreadable"})
			continue
		}
		stillNeeded := existingReferenceSetContains(live.Active, candidates...)
		for liveTag, liveDigest := range tags {
			if liveDigest == digest && existingReferenceSetContains(live.Active, prefix+liveTag) {
				stillNeeded = true
			}
		}
		if stillNeeded {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "used by a running service, task or container"})
			continue
		}
		response, err := existingRegistryRequest(cfg, run, "DELETE", repo+"/manifests/"+digest)
		if err != nil {
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionFailed, Reason: err.Error()})
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != 202 {
			reason := fmt.Sprintf("registry manifest deletion refused for %s (HTTP %d): %s; enable REGISTRY_STORAGE_DELETE_ENABLED=true in the platform registry", repo, response.StatusCode, strings.TrimSpace(string(bodyBytes)))
			report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionFailed, Reason: reason})
			if response.StatusCode == http.StatusMethodNotAllowed {
				registryDeletionDisabled = true
			}
			continue
		}
		deleted[digest] = true
		deletedBy[digest] = tag
		report.Events = append(report.Events, existingRetentionEvent{Tag: tag, Step: existingRetentionRegistryManifest, Outcome: existingRetentionRemoved})
	}
	return report
}

func formatExistingRetention(reports []existingRepositoryRetention) (summary, warnings []string, failures int) {
	for _, report := range reports {
		counts := map[existingRetentionStep]map[existingRetentionOutcome]int{
			existingRetentionHostImage:        {},
			existingRetentionRegistryManifest: {},
		}
		for _, event := range report.Events {
			counts[event.Step][event.Outcome]++
			if event.Outcome == existingRetentionFailed {
				failures++
			}
			if event.Tag == "" && event.Step == existingRetentionHostImage && event.Outcome == existingRetentionFailed {
				warnings = append(warnings, fmt.Sprintf("Release cleanup %s: host image inventory failed: %s", report.Repository, event.Reason))
			} else if event.Outcome == existingRetentionSkipped || event.Outcome == existingRetentionFailed {
				warnings = append(warnings, fmt.Sprintf("Release cleanup %s:%s: %s %s: %s", report.Repository, event.Tag, event.Step, event.Outcome, event.Reason))
			}
		}
		if report.Err != nil {
			step := report.ErrStep
			if step == "" {
				step = existingRetentionRegistryManifest
			}
			counts[step][existingRetentionFailed]++
			failures++
			warnings = append(warnings, fmt.Sprintf("Release cleanup %s stopped: %v", report.Repository, report.Err))
		}
		line := fmt.Sprintf("Release cleanup %s: host images %d removed, %d skipped, %d failed; registry manifests %d removed, %d skipped, %d failed",
			report.Repository,
			counts[existingRetentionHostImage][existingRetentionRemoved], counts[existingRetentionHostImage][existingRetentionSkipped], counts[existingRetentionHostImage][existingRetentionFailed],
			counts[existingRetentionRegistryManifest][existingRetentionRemoved], counts[existingRetentionRegistryManifest][existingRetentionSkipped], counts[existingRetentionRegistryManifest][existingRetentionFailed])
		hostUnattempted := report.Unattempted[existingRetentionHostImage]
		registryUnattempted := report.Unattempted[existingRetentionRegistryManifest]
		if hostUnattempted > 0 || registryUnattempted > 0 {
			line += fmt.Sprintf("; %d host image step(s), %d registry manifest step(s) unattempted", hostUnattempted, registryUnattempted)
		}
		summary = append(summary, line)
	}
	if failures > 0 {
		warnings = append(warnings, fmt.Sprintf("Upgrade verified, but release cleanup is incomplete: %d failure(s); see the lines above", failures))
	}
	return summary, warnings, failures
}
