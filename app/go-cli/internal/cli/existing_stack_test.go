package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func existingStackFixture(t *testing.T) *existingStackConfig {
	t.Helper()
	var cfg existingStackConfig
	err := json.Unmarshal([]byte(`{
  "version":1,"app":"platform","stack":"platform",
  "server":{"host":"192.0.2.1","user":"ops","host_key":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sudo":true},
  "registry":"127.0.0.1:5000",
  "build":{"services":{"web":{"context":".","services":["web"]}}},
  "manifest":{"PLATFORM_WEB_IMAGE":"web"},
  "apply":["/usr/local/bin/platform-upgrade","--manifest={{manifest}}"]
 }`), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &cfg
}

func TestExistingStackConfigRequiresExplicitTargetAndCompleteImageMapping(t *testing.T) {
	if err := existingStackFixture(t).validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*existingStackConfig)
	}{
		{"unverified host", func(c *existingStackConfig) { c.Server.HostKey = "" }},
		{"root login", func(c *existingStackConfig) { c.Server.User = "root" }},
		{"public registry", func(c *existingStackConfig) { c.Registry = "192.0.2.1:5000" }},
		{"wrong image", func(c *existingStackConfig) { c.Manifest["PLATFORM_WEB_IMAGE"] = "missing" }},
		{"missing manifest consumer", func(c *existingStackConfig) { c.Apply = []string{"/usr/local/bin/platform-upgrade"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := existingStackFixture(t)
			tc.change(cfg)
			if cfg.validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	body, err := json.Marshal(existingStackFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	body = append(body[:len(body)-1], []byte(`,"secret":"not-a-supported-field"}`)...)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExistingStackConfig(path); err == nil {
		t.Fatal("unknown configuration field accepted")
	}
}

func TestExistingStackManifestContainsOnlyResolvedImmutableImages(t *testing.T) {
	digest := "127.0.0.1:5000/platform-web@sha256:" + strings.Repeat("a", 64)
	body, err := existingStackManifest(map[string]string{"PLATFORM_WEB_IMAGE": "web"}, map[string]string{"web": digest})
	if err != nil || body != "PLATFORM_WEB_IMAGE="+digest+"\n" {
		t.Fatalf("unexpected manifest %q: %v", body, err)
	}
	for _, image := range []string{"127.0.0.1:5000/platform-web:latest", ""} {
		if _, err := existingStackManifest(map[string]string{"PLATFORM_WEB_IMAGE": "web"}, map[string]string{"web": image}); err == nil {
			t.Fatalf("accepted mutable or missing image %q", image)
		}
	}
}

// The remote runner models both the registry API and Docker without requiring
// a daemon or changing host data. Unexpected commands fail closed.
type existingRetentionRemote struct {
	t                    *testing.T
	cfg                  *existingStackConfig
	tags                 map[string]string
	repositoryTags       map[string]map[string]string
	local                []string
	live                 string
	task                 string
	stopped              string
	runningContainer     string
	disabled             bool
	listStatuses         map[string]int
	failedHeads          map[string]bool
	headCalls            map[string]int
	failedHeadCalls      map[string]int
	failedRemovals       map[string]error
	deleteStatuses       map[string]int
	imageIDs             map[string]string
	imageRepoDigests     map[string][]string
	imageInventoryErr    error
	failedLiveSnapshots  map[int]error
	liveSnapshotCalls    int
	containerStateAbsent bool
	calls                []string
}

func (r *existingRetentionRemote) run(cmd string) (result string, runErr error) {
	defer func() { result = strings.TrimSpace(result) }()
	r.calls = append(r.calls, cmd)
	switch {
	case strings.Contains(cmd, "'curl'"):
		if !strings.Contains(cmd, existingManifestAccept) {
			r.t.Fatal("missing Docker/OCI Accept headers")
		}
		pathStart := strings.Index(cmd, "/v2/")
		if pathStart < 0 {
			r.t.Fatalf("registry path missing: %s", cmd)
		}
		path := cmd[pathStart+4:]
		if end := strings.Index(path, "'"); end >= 0 {
			path = path[:end]
		}
		if strings.HasSuffix(path, "/tags/list") {
			repo := strings.TrimSuffix(path, "/tags/list")
			tagsForRepo := r.tagsFor(repo)
			if status := r.listStatuses[repo]; status != 0 && status != 200 {
				return fmt.Sprintf("HTTP/1.1 %d Test Failure\r\n\r\n", status), nil
			}
			tagNames := []string{}
			for tag := range tagsForRepo {
				tagNames = append(tagNames, tag)
			}
			body, _ := json.Marshal(map[string]any{"tags": tagNames})
			return "HTTP/1.1 200 OK\r\n\r\n" + string(body), nil
		}
		manifestPath := path
		marker := "/manifests/"
		manifestAt := strings.LastIndex(manifestPath, marker)
		if manifestAt < 0 {
			r.t.Fatalf("unexpected registry request: %s", cmd)
		}
		repo, name := manifestPath[:manifestAt], manifestPath[manifestAt+len(marker):]
		tagsForRepo := r.tagsFor(repo)
		if strings.Contains(cmd, "'--head'") {
			key := repo + "/" + name
			if r.headCalls == nil {
				r.headCalls = map[string]int{}
			}
			r.headCalls[key]++
			if r.failedHeads[key] || r.failedHeadCalls[key] == r.headCalls[key] {
				return "HTTP/1.1 500 Test Failure\r\n\r\n", nil
			}
			for tag, digest := range tagsForRepo {
				if tag == name || digest == name {
					return "HTTP/1.1 200 OK\r\nDocker-Content-Digest: " + digest + "\r\n\r\n", nil
				}
			}
			return "HTTP/1.1 404 Not Found\r\n\r\n", nil
		}
		if strings.Contains(cmd, "'DELETE'") {
			if r.disabled {
				return "HTTP/1.1 405 Method Not Allowed\r\n\r\n{\"code\":\"UNSUPPORTED\"}", nil
			}
			if status := r.deleteStatuses[repo+"@"+name]; status != 0 && status != 202 {
				return fmt.Sprintf("HTTP/1.1 %d Test Failure\r\n\r\n", status), nil
			}
			return "HTTP/1.1 202 Accepted\r\n\r\n", nil
		}
	case cmd == r.cfg.docker("image", "ls", "--format", "{{.Repository}}:{{.Tag}}"):
		if r.imageInventoryErr != nil {
			return "", r.imageInventoryErr
		}
		return strings.Join(r.local, "\n"), nil
	case cmd == r.cfg.docker("service", "ls", "-q"):
		r.liveSnapshotCalls++
		if err := r.failedLiveSnapshots[r.liveSnapshotCalls]; err != nil {
			return "", err
		}
		return "service1", nil
	case cmd == r.cfg.docker("service", "inspect", "service1"):
		body, _ := json.Marshal([]any{map[string]any{"Spec": map[string]any{"TaskTemplate": map[string]any{"ContainerSpec": map[string]string{"Image": r.live}}}}})
		return string(body), nil
	case cmd == r.cfg.docker("service", "ps", "--no-trunc", "--filter", "desired-state=running", "-q", "service1"):
		if r.task != "" {
			return "task1", nil
		}
		return "", nil
	case cmd == r.cfg.docker("inspect", "--type", "task", "task1"):
		body, _ := json.Marshal([]any{map[string]any{"Spec": map[string]any{"ContainerSpec": map[string]string{"Image": r.task}}}})
		return string(body), nil
	case cmd == r.cfg.docker("ps", "-a", "-q"):
		var ids []string
		if r.stopped != "" {
			ids = append(ids, "container1")
		}
		if r.runningContainer != "" {
			ids = append(ids, "container2")
		}
		return strings.Join(ids, "\n"), nil
	case strings.HasPrefix(cmd, r.cfg.docker("container", "inspect")+" "):
		var containers []any
		for _, item := range []struct {
			id      string
			image   string
			running bool
		}{{"container1", r.stopped, false}, {"container2", r.runningContainer, true}} {
			if item.image == "" || !strings.Contains(cmd, item.id) {
				continue
			}
			container := map[string]any{"Config": map[string]string{"Image": item.image}, "Image": "sha256:" + strings.Repeat("e", 64)}
			if !r.containerStateAbsent {
				container["State"] = map[string]bool{"Running": item.running, "Restarting": false}
			}
			containers = append(containers, container)
		}
		body, _ := json.Marshal(containers)
		return string(body), nil
	case strings.Contains(cmd, "'image' 'inspect' '--format' '{{json .RepoDigests}}'"):
		count := strings.Count(cmd, "'sha256:")
		lines := make([]string, count)
		for i := range lines {
			lines[i] = "[]"
		}
		return strings.Join(lines, "\n"), nil
	case strings.Contains(cmd, "'image' 'inspect'"):
		for _, image := range r.local {
			if strings.Contains(cmd, "'"+image+"'") {
				if id := r.imageIDs[image]; id != "" {
					body, _ := json.Marshal(map[string]any{"Id": id, "RepoDigests": r.imageRepoDigests[image]})
					return string(body), nil
				}
				return `{"Id":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","RepoDigests":[]}`, nil
			}
		}
		return "", fmt.Errorf("unexpected image inspect: %s", cmd)
	case strings.Contains(cmd, "'image' 'rm'"):
		for image, err := range r.failedRemovals {
			if strings.Contains(cmd, "'"+image+"'") {
				return "", err
			}
		}
		return "removed", nil
	}
	return "", fmt.Errorf("unexpected remote command: %s", cmd)
}

func (r *existingRetentionRemote) tagsFor(repo string) map[string]string {
	if r.repositoryTags != nil {
		tags, found := r.repositoryTags[repo]
		if !found {
			r.t.Fatalf("foreign repository accessed: %s", repo)
		}
		return tags
	}
	if repo == "platform-web" {
		return r.tags
	}
	r.t.Fatalf("foreign repository accessed: %s", repo)
	return nil
}

func TestExistingStackReleaseRetention(t *testing.T) {
	const current = "aaaaaaa-20261018T214628522577065"
	const old = "bbbbbbb-20261015T205432339537626"
	const older = "ccccccc-20261014T205432339537626"
	repo := "127.0.0.1:5000/platform-web"
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	c := "sha256:" + strings.Repeat("c", 64)
	for _, tc := range []struct {
		name           string
		live, task     string
		stopped        string
		same, disabled bool
		hostOnly       bool
		keep           int
	}{
		{name: "older tags removed and foreign repositories untouched"},
		{name: "running older digest survives", live: repo + "@" + b},
		{name: "running task older digest survives", task: repo + "@" + b},
		{name: "stopped task container keeps its host image, registry manifest deleted", stopped: repo + ":" + old},
		{name: "shared kept manifest survives", same: true},
		{name: "delete disabled warns", disabled: true},
		{name: "host tag without registry manifest removed", hostOnly: true},
		{name: "keep additional release by timestamp", keep: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := existingStackFixture(t)
			if tc.keep > 0 {
				cfg.Retention.KeepReleases = &tc.keep
			}
			if tc.same {
				b = a
			} else {
				b = "sha256:" + strings.Repeat("b", 64)
			}
			r := &existingRetentionRemote{t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c}, local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older, "127.0.0.1:5000/foreign:old"}, live: repo + "@" + a, task: tc.task, stopped: tc.stopped, disabled: tc.disabled}
			if tc.hostOnly {
				delete(r.tags, old)
			}
			if tc.same {
				r.imageRepoDigests = map[string][]string{repo + ":" + old: {repo + "@" + a}}
			}
			if tc.live != "" {
				r.live = tc.live
			}
			reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
			if err != nil {
				t.Fatal(err)
			}
			if len(reports) != 1 || reports[0].Err != nil {
				t.Fatalf("unexpected repository report: %+v", reports)
			}
			report := reports[0]
			oldHost := retentionEventFor(report, old, existingRetentionHostImage)
			oldRegistry := retentionEventFor(report, old, existingRetentionRegistryManifest)
			if tc.stopped != "" {
				if oldHost == nil || oldHost.Outcome != existingRetentionSkipped || oldHost.Reason != "used by a stopped container; never forced" {
					t.Fatalf("stopped host image was not kept with its reason: %+v", oldHost)
				}
				if oldRegistry == nil || oldRegistry.Outcome != existingRetentionRemoved {
					t.Fatalf("stopped history manifest was not removed: %+v", oldRegistry)
				}
			} else if tc.live == repo+"@"+b || tc.task == repo+"@"+b {
				if oldHost == nil || oldHost.Outcome != existingRetentionSkipped || oldRegistry == nil || oldRegistry.Outcome != existingRetentionSkipped {
					t.Fatalf("active image was not retained: host=%+v registry=%+v", oldHost, oldRegistry)
				}
			}
			if tc.disabled {
				if oldRegistry == nil || oldRegistry.Outcome != existingRetentionFailed || !strings.Contains(oldRegistry.Reason, "REGISTRY_STORAGE_DELETE_ENABLED=true") {
					t.Fatalf("missing delete-disabled registry event: %+v", oldRegistry)
				}
				olderRegistry := retentionEventFor(report, older, existingRetentionRegistryManifest)
				if olderRegistry == nil || olderRegistry.Outcome != existingRetentionSkipped || olderRegistry.Reason != "registry deletion is disabled for this repository" {
					t.Fatalf("later registry step was not skipped after HTTP 405: %+v", olderRegistry)
				}
			}
			oldHostRemoved := false
			for _, cmd := range r.calls {
				if cmd == cfg.docker("image", "rm", repo+":"+old) {
					oldHostRemoved = true
				}
				if strings.Contains(cmd, "'image' 'rm'") && strings.Contains(cmd, "foreign") {
					t.Fatal("foreign image removed")
				}
				if strings.Contains(cmd, "'DELETE'") && strings.Contains(cmd, a) {
					t.Fatalf("current manifest deleted: %s", cmd)
				}
				if strings.Contains(cmd, "'DELETE'") && strings.Contains(cmd, b) && (tc.live != "" || tc.task != "" || tc.same) {
					t.Fatalf("active or shared manifest deleted: %s", cmd)
				}
			}
			if tc.stopped != "" && oldHostRemoved {
				t.Fatal("stopped container host image was removed")
			}
			wantOldHostRemoved := tc.stopped == "" && tc.live != repo+"@"+b && tc.task != repo+"@"+b && !tc.same && tc.keep != 2
			if oldHostRemoved != wantOldHostRemoved {
				t.Fatalf("old host image removed=%v, want %v", oldHostRemoved, wantOldHostRemoved)
			}
			if !tc.disabled {
				if !hasDelete(r.calls, c) {
					t.Fatal("older release was not deleted")
				}
			} else if tc.disabled && hasDelete(r.calls, c) {
				t.Fatal("registry deletion continued after HTTP 405")
			}
		})
	}
}
func retentionEventFor(report existingRepositoryRetention, tag string, step existingRetentionStep) *existingRetentionEvent {
	for i := range report.Events {
		if report.Events[i].Tag == tag && report.Events[i].Step == step {
			return &report.Events[i]
		}
	}
	return nil
}

func hasDelete(calls []string, digest string) bool {
	for _, call := range calls {
		if strings.Contains(call, "'DELETE'") && strings.Contains(call, digest) {
			return true
		}
	}
	return false
}

// Each remote command is one SSH round trip plus a sudo session on the host.
// Live snapshots must not scale with the number of retained tags.
func TestExistingStackRetentionBoundsLiveSnapshots(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	const current = "aaaaaaa-20261019T102609804115943"
	tags := map[string]string{current: "sha256:" + strings.Repeat("a", 64)}
	local := []string{repo + ":" + current}
	const oldTags = 20
	for i := 0; i < oldTags; i++ {
		tag := fmt.Sprintf("bbbbbbb-20261018T10%02d00000000000", i)
		tags[tag] = fmt.Sprintf("sha256:%064x", i+1)
		local = append(local, repo+":"+tag)
	}
	r := &existingRetentionRemote{t: t, cfg: cfg, tags: tags, local: local, live: repo + "@" + tags[current]}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("unexpected repository report: %+v", reports)
	}
	for _, event := range reports[0].Events {
		if event.Outcome == existingRetentionFailed {
			t.Fatalf("unexpected failed event: %+v", event)
		}
	}
	snapshots, deletes := 0, 0
	for _, cmd := range r.calls {
		if cmd == cfg.docker("service", "ls", "-q") {
			snapshots++
		}
		if strings.Contains(cmd, "'DELETE'") {
			deletes++
		}
	}
	if deletes != oldTags {
		t.Fatalf("deleted %d manifests, want %d", deletes, oldTags)
	}
	// One initial snapshot, then one recheck immediately before each DELETE.
	if snapshots > 1+deletes {
		t.Fatalf("%d live snapshots for %d deletions", snapshots, deletes)
	}
}

func TestExistingStackRetentionImageRemovalRefusalContinues(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	failure := fmt.Errorf("Error response from daemon: conflict: unable to delete image reference \"%s\" (must be forced)", repo+":"+old)
	r := &existingRetentionRemote{
		t: t, cfg: cfg,
		tags:           map[string]string{current: a, old: b, older: c},
		local:          []string{repo + ":" + current, repo + ":" + old, repo + ":" + older},
		live:           repo + "@" + a,
		failedRemovals: map[string]error{repo + ":" + old: failure},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	failedHost := 0
	for _, event := range reports[0].Events {
		if event.Step == existingRetentionHostImage && event.Outcome == existingRetentionFailed {
			failedHost++
			if event.Tag != old || event.Reason != failure.Error() {
				t.Fatalf("unexpected host failure event: %+v", event)
			}
		}
	}
	if failedHost != 1 || !hasDelete(r.calls, b) || !hasDelete(r.calls, c) {
		t.Fatalf("host refusal blocked registry cleanup: failed=%d calls=%v events=%+v", failedHost, r.calls, reports[0].Events)
	}
	if !hasCall(r.calls, cfg.docker("image", "rm", repo+":"+older)) {
		t.Fatal("older host image was not removed after refusal")
	}
	for _, call := range r.calls {
		if strings.Contains(call, "'image' 'rm'") && (strings.Contains(call, "'--force'") || strings.Contains(call, "'-f'")) {
			t.Fatalf("forced image removal attempted: %s", call)
		}
	}
}

func TestExistingStackRetentionFailedLiveRecheckContinuesWithFreshSnapshot(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	transient := errors.New("transient live inspection failure")
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older},
		live:  repo + "@" + a, failedLiveSnapshots: map[int]error{2: transient},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("retention abandoned the repository: reports=%+v err=%v", reports, err)
	}
	failed := retentionEventFor(reports[0], old, existingRetentionRegistryManifest)
	removed := retentionEventFor(reports[0], older, existingRetentionRegistryManifest)
	if failed == nil || failed.Outcome != existingRetentionFailed || failed.Reason != transient.Error() {
		t.Fatalf("failed recheck was not recorded for its tag: %+v", failed)
	}
	if hasDelete(r.calls, b) || !hasDelete(r.calls, c) {
		t.Fatalf("cleanup used a failed snapshot or abandoned later tags: calls=%v", r.calls)
	}
	if removed == nil || removed.Outcome != existingRetentionRemoved || r.liveSnapshotCalls != 4 {
		t.Fatalf("later tag did not use fresh live snapshots: event=%+v snapshots=%d", removed, r.liveSnapshotCalls)
	}
}

func TestExistingStackRetentionRepeatedRefreshFailuresContinueLaterTags(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	oldest := "ddddddd-20261016T102609804115943"
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	c := "sha256:" + strings.Repeat("c", 64)
	d := "sha256:" + strings.Repeat("d", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c, oldest: d},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older, repo + ":" + oldest},
		live:  repo + "@" + a, failedLiveSnapshots: map[int]error{2: errors.New("recheck 1 failed"), 3: errors.New("refresh 2 failed")},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("refresh failures stopped the repository: reports=%+v err=%v", reports, err)
	}
	for _, tag := range []string{old, older} {
		event := retentionEventFor(reports[0], tag, existingRetentionRegistryManifest)
		if event == nil || event.Outcome != existingRetentionFailed {
			t.Fatalf("refresh failure was not recorded for %s: %+v", tag, event)
		}
	}
	if !hasDelete(r.calls, d) || hasDelete(r.calls, b) || hasDelete(r.calls, c) || r.liveSnapshotCalls != 5 {
		t.Fatalf("later tag did not recover with a fresh snapshot: snapshots=%d calls=%v", r.liveSnapshotCalls, r.calls)
	}
	if hasCall(r.calls, cfg.docker("image", "rm", repo+":"+older)) {
		t.Fatalf("host image deletion ran without a successful snapshot: %v", r.calls)
	}
}

func TestExistingStackRetentionFailedRefreshCountsOnlyUnattemptedSteps(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	oldest := "ddddddd-20261016T102609804115943"
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	c := "sha256:" + strings.Repeat("c", 64)
	d := "sha256:" + strings.Repeat("d", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c, oldest: d},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older, repo + ":" + oldest},
		live:  repo + "@" + a, failedLiveSnapshots: map[int]error{2: errors.New("recheck failed"), 3: errors.New("refresh failed")},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	if got := reports[0].Unattempted[existingRetentionHostImage]; got != 1 {
		t.Fatalf("unattempted host count includes completed tags: got %d, want 1", got)
	}
	if got := reports[0].Unattempted[existingRetentionRegistryManifest]; got != 0 {
		t.Fatalf("registry failure outcomes were counted as unattempted: got %d", got)
	}
	if retentionEventFor(reports[0], old, existingRetentionHostImage) == nil || retentionEventFor(reports[0], old, existingRetentionHostImage).Outcome != existingRetentionRemoved {
		t.Fatalf("completed host removal lost its outcome: %+v", reports[0].Events)
	}
	if retentionEventFor(reports[0], oldest, existingRetentionRegistryManifest) == nil || retentionEventFor(reports[0], oldest, existingRetentionRegistryManifest).Outcome != existingRetentionRemoved {
		t.Fatalf("later registry cleanup did not complete: %+v", reports[0].Events)
	}
}

func TestExistingStackRetentionRegistryFailureContinues(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older},
		live:  repo + "@" + a, deleteStatuses: map[string]int{"platform-web@" + b: 500},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	failed := retentionEventFor(reports[0], old, existingRetentionRegistryManifest)
	removed := retentionEventFor(reports[0], older, existingRetentionRegistryManifest)
	if failed == nil || failed.Outcome != existingRetentionFailed || removed == nil || removed.Outcome != existingRetentionRemoved || !hasDelete(r.calls, c) {
		t.Fatalf("registry failure blocked later tag cleanup: failed=%+v removed=%+v calls=%v", failed, removed, r.calls)
	}
}

func TestExistingStackRetentionAliasResolutionFailureContinues(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older},
		live:  repo + "@" + a, failedHeadCalls: map[string]int{"platform-web/" + current: 2},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	failed := retentionEventFor(reports[0], old, existingRetentionRegistryManifest)
	if failed == nil || failed.Outcome != existingRetentionFailed || hasDelete(r.calls, b) || !hasDelete(r.calls, c) {
		t.Fatalf("alias re-resolution did not fail closed for one tag and continue: event=%+v calls=%v", failed, r.calls)
	}
}

func TestExistingStackRetentionDeletedDigestReportsAliasSkip(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: b},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older}, live: repo + "@" + a,
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	deleteCount := 0
	for _, call := range r.calls {
		if strings.Contains(call, "'DELETE'") && strings.Contains(call, b) {
			deleteCount++
		}
	}
	event := retentionEventFor(reports[0], older, existingRetentionRegistryManifest)
	if deleteCount != 1 || event == nil || event.Outcome != existingRetentionSkipped || event.Reason != "digest already deleted with tag "+old {
		t.Fatalf("shared superseded digest was not explained: count=%d event=%+v calls=%v", deleteCount, event, r.calls)
	}
}

func TestExistingStackRetentionRunningContainerProtectsRegistry(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	r := &existingRetentionRemote{t: t, cfg: cfg, tags: map[string]string{current: a, old: b}, local: []string{repo + ":" + current, repo + ":" + old}, live: repo + "@" + a, runningContainer: repo + ":" + old}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	for _, step := range []existingRetentionStep{existingRetentionHostImage, existingRetentionRegistryManifest} {
		event := retentionEventFor(reports[0], old, step)
		if event == nil || event.Outcome != existingRetentionSkipped || event.Reason != "used by a running service, task or container" {
			t.Fatalf("unexpected %s event: %+v", step, event)
		}
	}
	if hasCall(r.calls, cfg.docker("image", "rm", repo+":"+old)) || hasDelete(r.calls, b) {
		t.Fatalf("running container image was removed: calls=%v", r.calls)
	}
}

func TestExistingStackRetentionMissingContainerStateStopsCleanup(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b},
		local: []string{repo + ":" + current, repo + ":" + old},
		live:  repo + "@" + a, stopped: repo + ":" + old, containerStateAbsent: true,
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err == nil || !strings.Contains(reports[0].Err.Error(), "container state missing") {
		t.Fatalf("missing container state did not stop cleanup: reports=%+v err=%v", reports, err)
	}
	if hasCall(r.calls, cfg.docker("image", "rm", repo+":"+old)) || hasDelete(r.calls, b) {
		t.Fatalf("cleanup used an incomplete container snapshot: %v", r.calls)
	}
}

func TestExistingStackRetentionRepositoryFailureContinuesOthers(t *testing.T) {
	cfg := existingStackFixture(t)
	const currentA = "aaaaaaa-20261019T102609804115943"
	const oldA = "bbbbbbb-20261018T102609804115943"
	const currentB = "ccccccc-20261019T102609804115943"
	const oldB = "ddddddd-20261018T102609804115943"
	repoA, repoB := "platform-alpha", "platform-beta"
	refA, refB := cfg.Registry+"/"+repoA, cfg.Registry+"/"+repoB
	digestA, digestOldA := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	digestB, digestOldB := "sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg,
		repositoryTags: map[string]map[string]string{
			repoA: {currentA: digestA, oldA: digestOldA},
			repoB: {currentB: digestB, oldB: digestOldB},
		},
		listStatuses: map[string]int{repoA: 500},
		local:        []string{refA + ":" + currentA, refA + ":" + oldA, refB + ":" + currentB, refB + ":" + oldB},
		live:         refB + "@" + digestB,
	}
	reports, err := retainExistingStack(cfg, []string{refB + ":" + currentB, refA + ":" + currentA}, r.run)
	if err != nil || len(reports) != 2 {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	if reports[0].Repository != repoA || reports[0].Err == nil || reports[1].Repository != repoB || reports[1].Err != nil {
		t.Fatalf("reports not sorted or repository failure leaked: %+v", reports)
	}
	if !hasCall(r.calls, cfg.docker("image", "rm", refB+":"+oldB)) || !hasDelete(r.calls, digestOldB) {
		t.Fatalf("second repository did not complete cleanup: calls=%v", r.calls)
	}
	if hasCall(r.calls, cfg.docker("image", "rm", refA+":"+oldA)) || hasDelete(r.calls, digestOldA) {
		t.Fatalf("failed repository was partially cleaned: calls=%v", r.calls)
	}
}

func TestExistingStackRetentionUnreadableDigestKeepsRegistry(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older},
		live:  repo + "@" + a, failedHeads: map[string]bool{"platform-web/" + old: true},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("retention failed: reports=%+v err=%v", reports, err)
	}
	if hasDelete(r.calls, a) || hasDelete(r.calls, b) || !hasDelete(r.calls, c) {
		t.Fatalf("unreadable superseded tag blocked unrelated cleanup: %v", r.calls)
	}
	if !hasCall(r.calls, cfg.docker("image", "rm", repo+":"+old)) || !hasCall(r.calls, cfg.docker("image", "rm", repo+":"+older)) {
		t.Fatalf("host removals did not continue with unreadable digest: %v", r.calls)
	}
	if event := retentionEventFor(reports[0], old, existingRetentionRegistryManifest); event == nil || event.Outcome != existingRetentionFailed {
		t.Fatalf("unreadable tag failure was not isolated to its registry step: %+v", event)
	}
	if event := retentionEventFor(reports[0], older, existingRetentionRegistryManifest); event == nil || event.Outcome != existingRetentionRemoved {
		t.Fatalf("readable later tag did not get cleaned: %+v", event)
	}

	active := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older},
		live:  repo + ":" + old, failedHeads: map[string]bool{"platform-web/" + old: true},
	}
	activeReports, err := retainExistingStack(cfg, []string{repo + ":" + current}, active.run)
	if err != nil || len(activeReports) != 1 || activeReports[0].Err != nil {
		t.Fatalf("active unreadable alias report failed: reports=%+v err=%v", activeReports, err)
	}
	if hasDelete(active.calls, b) || hasDelete(active.calls, c) {
		t.Fatalf("unreadable active alias did not protect its possible manifest: %v", active.calls)
	}
	if event := retentionEventFor(activeReports[0], older, existingRetentionRegistryManifest); event == nil || event.Outcome != existingRetentionSkipped || event.Reason != "registry digests of this repository are unreadable" {
		t.Fatalf("unreadable active alias was not reported as a protection dependency: %+v", event)
	}
}

func TestExistingStackRetentionHostInventoryFailureContinuesRegistry(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	old := "bbbbbbb-20261018T102609804115943"
	older := "ccccccc-20261017T102609804115943"
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	inventoryErr := errors.New("docker image ls unavailable")
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: a, old: b, older: c},
		local: []string{repo + ":" + current, repo + ":" + old, repo + ":" + older},
		live:  repo + "@" + a, imageInventoryErr: inventoryErr,
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("registry cleanup did not continue after host inventory failure: reports=%+v err=%v", reports, err)
	}
	inventoryFailure := retentionEventFor(reports[0], "", existingRetentionHostImage)
	if inventoryFailure == nil || inventoryFailure.Outcome != existingRetentionFailed || inventoryFailure.Reason != inventoryErr.Error() {
		t.Fatalf("repository host inventory failure was not retained: %+v", reports[0])
	}
	for _, tag := range []string{old, older} {
		host := retentionEventFor(reports[0], tag, existingRetentionHostImage)
		registry := retentionEventFor(reports[0], tag, existingRetentionRegistryManifest)
		if host != nil {
			t.Fatalf("repository inventory failure was repeated for %s: %+v", tag, host)
		}
		if registry == nil || registry.Outcome != existingRetentionRemoved {
			t.Fatalf("registry cleanup did not continue for %s: %+v", tag, registry)
		}
		if hasCall(r.calls, cfg.docker("image", "rm", repo+":"+tag)) {
			t.Fatalf("host image removal ran without an inventory: %s", tag)
		}
	}
	if !hasDelete(r.calls, b) || !hasDelete(r.calls, c) {
		t.Fatalf("registry manifests were not evaluated independently: %v", r.calls)
	}
	if reports[0].Unattempted[existingRetentionHostImage] != 2 {
		t.Fatalf("host steps blocked by inventory failure were not counted: %+v", reports[0].Unattempted)
	}
	_, warnings, failures := formatExistingRetention(reports)
	if failures != 1 || len(warnings) != 2 || warnings[0] != "Release cleanup platform-web: host image inventory failed: "+inventoryErr.Error() {
		t.Fatalf("inventory failure was not counted once: warnings=%v failures=%d", warnings, failures)
	}
}

func TestExistingStackRetentionHostInventoryFailureWithOnlyCurrentTag(t *testing.T) {
	cfg := existingStackFixture(t)
	repo := "127.0.0.1:5000/platform-web"
	current := "aaaaaaa-20261019T102609804115943"
	inventoryErr := errors.New("docker image ls unavailable")
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: "sha256:" + strings.Repeat("a", 64)},
		local: []string{repo + ":" + current}, live: repo + "@sha256:" + strings.Repeat("a", 64), imageInventoryErr: inventoryErr,
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("current-only repository lost inventory failure: reports=%+v err=%v", reports, err)
	}
	inventoryFailure := retentionEventFor(reports[0], "", existingRetentionHostImage)
	if inventoryFailure == nil || inventoryFailure.Outcome != existingRetentionFailed || inventoryFailure.Reason != inventoryErr.Error() {
		t.Fatalf("current-only repository did not record inventory failure: %+v", reports[0])
	}
	summary, warnings, failures := formatExistingRetention(reports)
	wantSummary := []string{"Release cleanup platform-web: host images 0 removed, 0 skipped, 1 failed; registry manifests 0 removed, 0 skipped, 0 failed"}
	wantWarnings := []string{
		"Release cleanup platform-web: host image inventory failed: " + inventoryErr.Error(),
		"Upgrade verified, but release cleanup is incomplete: 1 failure(s); see the lines above",
	}
	if fmt.Sprint(summary) != fmt.Sprint(wantSummary) || fmt.Sprint(warnings) != fmt.Sprint(wantWarnings) || failures != 1 {
		t.Fatalf("current-only inventory failure was omitted: summary=%q warnings=%q failures=%d", summary, warnings, failures)
	}
	if r.headCalls["platform-web/"+current] != 1 {
		t.Fatalf("registry tag evaluation stopped before resolving the current tag: calls=%v", r.calls)
	}
}

func TestExistingStackRetentionSummaryLines(t *testing.T) {
	report := existingRepositoryRetention{
		Repository: "platform-web",
		Events: []existingRetentionEvent{
			{Tag: "host-removed", Step: existingRetentionHostImage, Outcome: existingRetentionRemoved},
			{Tag: "host-skipped", Step: existingRetentionHostImage, Outcome: existingRetentionSkipped, Reason: "used by a stopped container; never forced"},
			{Tag: "host-failed", Step: existingRetentionHostImage, Outcome: existingRetentionFailed, Reason: "daemon refused"},
			{Tag: "registry-removed", Step: existingRetentionRegistryManifest, Outcome: existingRetentionRemoved},
			{Tag: "registry-skipped", Step: existingRetentionRegistryManifest, Outcome: existingRetentionSkipped, Reason: "shares a manifest with a retained tag"},
			{Tag: "registry-failed", Step: existingRetentionRegistryManifest, Outcome: existingRetentionFailed, Reason: "registry unavailable"},
		},
		Err:         fmt.Errorf("live state unreadable"),
		ErrStep:     existingRetentionRegistryManifest,
		Unattempted: map[existingRetentionStep]int{existingRetentionHostImage: 2, existingRetentionRegistryManifest: 3},
	}
	summary, warnings, failures := formatExistingRetention([]existingRepositoryRetention{report})
	wantSummary := []string{"Release cleanup platform-web: host images 1 removed, 1 skipped, 1 failed; registry manifests 1 removed, 1 skipped, 2 failed; 2 host image step(s), 3 registry manifest step(s) unattempted"}
	wantWarnings := []string{
		"Release cleanup platform-web:host-skipped: host image skipped: used by a stopped container; never forced",
		"Release cleanup platform-web:host-failed: host image failed: daemon refused",
		"Release cleanup platform-web:registry-skipped: registry manifest skipped: shares a manifest with a retained tag",
		"Release cleanup platform-web:registry-failed: registry manifest failed: registry unavailable",
		"Release cleanup platform-web stopped: live state unreadable",
		"Upgrade verified, but release cleanup is incomplete: 3 failure(s); see the lines above",
	}
	if fmt.Sprint(summary) != fmt.Sprint(wantSummary) || fmt.Sprint(warnings) != fmt.Sprint(wantWarnings) || failures != 3 {
		t.Fatalf("unexpected format: summary=%q warnings=%q failures=%d", summary, warnings, failures)
	}
}

func TestExistingStackRetentionSummaryCountsEarlyRepositoryFailure(t *testing.T) {
	cfg := existingStackFixture(t)
	current := "aaaaaaa-20261019T102609804115943"
	repo := "127.0.0.1:5000/platform-web"
	r := &existingRetentionRemote{
		t: t, cfg: cfg, tags: map[string]string{current: "sha256:" + strings.Repeat("a", 64)},
		listStatuses: map[string]int{"platform-web": 500},
	}
	reports, err := retainExistingStack(cfg, []string{repo + ":" + current}, r.run)
	if err != nil || len(reports) != 1 || reports[0].Err == nil {
		t.Fatalf("expected a repository-level list failure: reports=%+v err=%v", reports, err)
	}
	summary, warnings, failures := formatExistingRetention(reports)
	wantSummary := []string{"Release cleanup platform-web: host images 0 removed, 0 skipped, 0 failed; registry manifests 0 removed, 0 skipped, 1 failed; 1 host image step(s), 1 registry manifest step(s) unattempted"}
	wantWarnings := []string{
		"Release cleanup platform-web stopped: list platform-web: HTTP 500",
		"Upgrade verified, but release cleanup is incomplete: 1 failure(s); see the lines above",
	}
	if fmt.Sprint(summary) != fmt.Sprint(wantSummary) || fmt.Sprint(warnings) != fmt.Sprint(wantWarnings) || failures != 1 {
		t.Fatalf("early repository failure was omitted from summary: summary=%q warnings=%q failures=%d", summary, warnings, failures)
	}
}

func hasCall(calls []string, expected string) bool {
	for _, call := range calls {
		if call == expected {
			return true
		}
	}
	return false
}

func TestExistingStackFailureSkipsReleaseCleanup(t *testing.T) {
	cfg := existingStackFixture(t)
	plan := buildPlan{Builds: []plannedBuild{{Service: "web", Image: "127.0.0.1:5000/platform-web:release"}}, ServiceImages: map[string]string{"web": "127.0.0.1:5000/platform-web:release"}}
	for _, inspectFails := range []bool{false, true} {
		err := completeExistingStackRelease(cfg, plan, map[string]string{"web": "expected-digest"}, func(command string) (string, error) {
			if command != cfg.docker("service", "inspect", "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}", "platform_web") {
				t.Fatalf("cleanup ran after failed verification: %s", command)
			}
			if inspectFails {
				return "", fmt.Errorf("inspection failed")
			}
			return "wrong-digest", nil
		})
		if err == nil {
			t.Fatal("failed verification accepted")
		}
	}
}

func TestExistingStackRetentionMinimum(t *testing.T) {
	cfg := existingStackFixture(t)
	if cfg.Retention.count() != 1 {
		t.Fatal("retention must default to one release")
	}
	for _, n := range []int{0, -1} {
		cfg.Retention.KeepReleases = &n
		if cfg.validate() == nil {
			t.Fatalf("accepted keep_releases=%d", n)
		}
	}
}

// The builder survives the run so the next deploy reuses its layers; only its
// cache size is bounded and its BuildKit process stopped.
func TestExistingStackBuilderCacheIsCappedNotRemoved(t *testing.T) {
	var calls []string
	previous := dockerBuilderRunner
	dockerBuilderRunner = func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	}
	defer func() { dockerBuilderRunner = previous }()
	retention := existingStackRetention{}
	builder := persistentBuilderName("platform-existing")
	if err := errors.Join(pruneExistingBuilderCache(builder, retention.buildCacheBytes()), stopPersistentBuilder("platform-existing")); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "buildx prune --builder "+builder+" --force --max-used-space 21474836480") {
		t.Fatalf("cache not capped at the 20GB default:\n%s", joined)
	}
	if !strings.Contains(joined, "buildx stop "+builder) || strings.Contains(joined, "buildx rm") {
		t.Fatalf("builder must be stopped and kept:\n%s", joined)
	}
	for _, value := range []string{"0", "abc"} {
		if (existingStackRetention{BuildCache: value}).validateBuildCache() == nil {
			t.Fatalf("accepted build_cache %q", value)
		}
	}
}

// An unchanged ingress image must keep its running digest: a new digest makes
// Swarm restart a host-port service, which cannot start its replacement first.
func TestExistingStackReusesUnchangedImages(t *testing.T) {
	cfg := existingStackFixture(t)
	running := "127.0.0.1:5000/platform-caddy@sha256:" + strings.Repeat("a", 64)
	plan := buildPlan{Builds: []plannedBuild{{Service: "caddy", Image: "127.0.0.1:5000/platform-caddy:new-20261019T102609804115943", Services: []string{"caddy", "caddy-admin"}}}}
	const fingerprint = `["sha256:1"] {"Cmd":["caddy"]} linux/amd64`
	previous := localImageFingerprint
	defer func() { localImageFingerprint = previous }()
	for _, tc := range []struct {
		name                 string
		local, admin, remote string
		remoteFails, reused  bool
	}{
		{name: "same layers and config", local: fingerprint, admin: running, remote: fingerprint, reused: true},
		{name: "changed content", local: `["sha256:2"] {"Cmd":["caddy"]} linux/amd64`, admin: running, remote: fingerprint},
		{name: "services run different digests", local: fingerprint, admin: "127.0.0.1:5000/platform-caddy@sha256:" + strings.Repeat("b", 64), remote: fingerprint},
		{name: "running image absent from the host", local: fingerprint, admin: running, remoteFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			localImageFingerprint = func(string) (string, error) { return tc.local, nil }
			reused, err := existingReusableImages(cfg, plan, func(cmd string) (string, error) {
				switch {
				case strings.Contains(cmd, "'platform_caddy'"):
					return "127.0.0.1:5000/platform-caddy:old-20261018T102609804115943@sha256:" + strings.Repeat("a", 64), nil
				case strings.Contains(cmd, "'platform_caddy-admin'"):
					return tc.admin, nil
				case strings.Contains(cmd, "'image' 'inspect'"):
					if tc.remoteFails {
						return "", fmt.Errorf("no such image")
					}
					return tc.remote, nil
				}
				return "", fmt.Errorf("unexpected remote command: %s", cmd)
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := reused["caddy"] == running; got != tc.reused {
				t.Fatalf("reused=%v (%q), want %v", got, reused["caddy"], tc.reused)
			}
		})
	}
}

func TestExistingStackVersionCarriesOneTimestamp(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 32, 30, 827529632, time.UTC)
	for base, want := range map[string]string{
		"e301180":                                "e301180-20261019T123230827529632",
		"e301180-dirty-20261019T123230827529632": "e301180-dirty-20261019T123230827529632",
	} {
		if got := existingStackVersion(base, now); got != want || !existingReleaseTag.MatchString(got) {
			t.Fatalf("existingStackVersion(%q) = %q, want %q", base, got, want)
		}
	}
}
