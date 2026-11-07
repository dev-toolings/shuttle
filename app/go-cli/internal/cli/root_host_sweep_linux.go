//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// rootHostImageMinAge gives host-side builds a day to be deployed before this
// pass can see them as stale. An unreadable creation time is kept as young.
const (
	rootHostImageMinAge     = 24 * time.Hour
	rootHostImageListFormat = "{{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.ID}}\t{{.CreatedAt}}\t{{.Size}}"
)

type rootHostImageEntry struct {
	Repository string
	Tag        string
	Digest     string
	ID         string
	Size       string
	Created    time.Time
}

// parseRootHostImageStore is strict about row shape: an incomplete image-to-ID
// map could hide a retained reference. CreatedAt is the exception, because an
// unrecognized date is represented as zero and therefore cannot pass the age
// check.
func parseRootHostImageStore(listing string) ([]rootHostImageEntry, error) {
	entries := []rootHostImageEntry{}
	for number, line := range strings.Split(listing, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			return nil, fmt.Errorf("image listing row %d is malformed: %q", number+1, line)
		}
		for index, value := range fields {
			if value == "<none>" {
				fields[index] = ""
			}
		}
		if fields[3] == "" || fields[5] == "" {
			return nil, fmt.Errorf("image listing row %d is malformed: %q", number+1, line)
		}
		created, _ := parseRootHostImageCreatedAt(fields[4])
		entries = append(entries, rootHostImageEntry{
			Repository: fields[0],
			Tag:        fields[1],
			Digest:     fields[2],
			ID:         fields[3],
			Created:    created,
			Size:       fields[5],
		})
	}
	return entries, nil
}

func parseRootHostImageCreatedAt(value string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999 Z07:00",
		"2006-01-02 15:04:05 Z07:00",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable Docker image creation time %q", value)
}

type rootHostProtection struct {
	HeldIDs      map[string]bool
	Digests      map[string]bool
	TagRefs      map[string]bool
	ServiceRepos map[string]bool
}

type rootHostImageRemoval struct {
	ID   string
	Refs []string
	// Pinned holds, per tag reference, the digest-qualified names to try when
	// the plain tag does not resolve. With Docker's containerd image store,
	// Swarm pulls `busybox:1.36` as `busybox:1.36@sha256:...`: `docker image
	// ls` shows the tag, but `docker image rm busybox:1.36` answers "No such
	// image", so a superseded third-party image was never reclaimed (e2e on
	// Docker 29.9.2, 30-10-2026).
	Pinned map[string][]string
	Size   string
}

type rootHostSnapshot struct {
	Protection rootHostProtection
	Containers []rootInfraContainerEntry
	Images     []rootHostImageEntry
}

func rootHostRepository(ref string) string {
	if repository, _, ok := strings.Cut(ref, "@"); ok {
		ref = repository
	}
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		ref = ref[:colon]
	}
	ref = strings.TrimPrefix(ref, "docker.io/library/")
	ref = strings.TrimPrefix(ref, "docker.io/")
	return ref
}

func rootHostTagRef(ref string) string {
	if strings.Contains(ref, "@") {
		return ""
	}
	colon := strings.LastIndex(ref, ":")
	if colon <= strings.LastIndex(ref, "/") {
		repository := rootHostRepository(ref)
		if repository == "" {
			return ""
		}
		return repository + ":latest"
	}
	if colon == len(ref)-1 {
		return ""
	}
	repository := rootHostRepository(ref[:colon])
	if repository == "" {
		return ""
	}
	return repository + ":" + ref[colon+1:]
}

// rootHostTaskSlot reads a replicated slot or the local node identity from
// Swarm's container labels. Unrecognized or incomplete labels are not proof of
// slot identity and therefore cannot authorize removing a stopped container.
func rootHostTaskSlot(service, taskName, taskID, nodeID, taskSlot string) string {
	if service == "" {
		return ""
	}
	if taskName == "" {
		return rootHostTaskSlotLabel(taskID, nodeID, taskSlot)
	}
	suffix, ok := strings.CutPrefix(taskName, service+".")
	if !ok {
		return ""
	}
	parts := strings.Split(suffix, ".")
	if len(parts) > 2 || parts[0] == "" {
		return ""
	}
	if len(parts) == 2 && (taskID == "" || parts[1] != taskID) {
		return ""
	}
	identity := parts[0]
	if slot, err := strconv.Atoi(identity); err == nil && slot > 0 {
		if taskSlot != "" {
			labelSlot, labelErr := strconv.Atoi(taskSlot)
			if labelErr != nil || labelSlot != slot {
				return ""
			}
		}
		return "replica:" + strconv.Itoa(slot)
	}
	if nodeID != "" && identity == nodeID {
		if taskSlot != "" {
			labelSlot, err := strconv.Atoi(taskSlot)
			if err != nil || labelSlot > 0 {
				return ""
			}
		}
		return "node:" + nodeID
	}
	return rootHostTaskSlotLabel(taskID, nodeID, taskSlot)
}

func rootHostTaskSlotLabel(taskID, nodeID, taskSlot string) string {
	if taskID == "" {
		return ""
	}
	if slot, err := strconv.Atoi(taskSlot); err == nil && slot > 0 {
		return "replica:" + strconv.Itoa(slot)
	}
	if taskSlot == "0" && nodeID != "" {
		return "node:" + nodeID
	}
	return ""
}

func rootHostProtectedImageIDs(entries []rootHostImageEntry, protect rootHostProtection) map[string]bool {
	if protect.Digests == nil || protect.TagRefs == nil {
		return nil
	}
	protected := map[string]bool{}
	for _, entry := range entries {
		tagRef := ""
		if entry.Repository != "" && entry.Tag != "" {
			tagRef = rootHostTagRef(entry.Repository + ":" + entry.Tag)
		}
		if protect.Digests[entry.Digest] || tagRef != "" && protect.TagRefs[tagRef] {
			protected[entry.ID] = true
		}
	}
	return protected
}

// planRootHostTaskContainers removes old task containers only after a newer
// task of the same service and slot is running on this node. Missing slot or
// creation-time evidence, and services in a crash loop, keep stopped tasks.
func planRootHostTaskContainers(protectedIDs map[string]bool, containers []rootInfraContainerEntry) []string {
	if protectedIDs == nil {
		return nil
	}
	runningTasks := map[string]time.Time{}
	liveImages := map[string]bool{}
	for _, container := range containers {
		stopped := container.State == "exited" || container.State == "dead"
		if !stopped && container.ImageID != "" {
			liveImages[container.ImageID] = true
		}
		if container.State == "running" && container.TaskID != "" && container.ServiceID != "" && container.Slot != "" && !container.Created.IsZero() {
			key := container.ServiceID + "\x00" + container.Slot
			if container.Created.After(runningTasks[key]) {
				runningTasks[key] = container.Created
			}
		}
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, container := range containers {
		if (container.State != "exited" && container.State != "dead") || container.TaskID == "" || container.Service == "" || container.ID == "" {
			continue
		}
		if container.ServiceID == "" || container.Slot == "" || container.Created.IsZero() || !runningTasks[container.ServiceID+"\x00"+container.Slot].After(container.Created) || protectedIDs[container.ImageID] || liveImages[container.ImageID] || seen[container.ID] {
			continue
		}
		seen[container.ID] = true
		ids = append(ids, container.ID)
	}
	sort.Strings(ids)
	return ids
}

// planRootHostImages groups every tag and digest row by local image ID. One
// retained reference, container, or loopback-registry row protects the whole
// ID. The narrow host scope reclaims dangling images and old versions only in
// repositories a current Swarm service uses, leaving abandoned repositories
// for the explicit-consent disk workflow.
func planRootHostImages(entries []rootHostImageEntry, protect rootHostProtection, now time.Time) []rootHostImageRemoval {
	if protect.HeldIDs == nil || protect.Digests == nil || protect.TagRefs == nil || protect.ServiceRepos == nil {
		return nil
	}
	type imageGroup struct {
		rows []rootHostImageEntry
	}
	groups := map[string]*imageGroup{}
	for _, entry := range entries {
		if entry.ID == "" {
			continue
		}
		group := groups[entry.ID]
		if group == nil {
			group = &imageGroup{}
			groups[entry.ID] = group
		}
		group.rows = append(group.rows, entry)
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	removals := []rootHostImageRemoval{}
	for _, id := range ids {
		group := groups[id]
		if protect.HeldIDs[id] {
			continue
		}
		created := time.Time{}
		loopback := false
		protected := false
		hasTag := false
		allTagsInServiceRepos := true
		hasDigestOnly := false
		allDigestOnlyReposEligible := true
		hasReference := false
		unknownAge := false
		refs := []string{}
		refSeen := map[string]bool{}
		pinned := map[string][]string{}
		size := ""
		for _, row := range group.rows {
			if size == "" && row.Size != "" {
				size = row.Size
			}
			if row.Created.IsZero() {
				unknownAge = true
			} else if created.IsZero() || row.Created.After(created) {
				created = row.Created
			}
			if strings.HasPrefix(row.Repository, rootRegistryImagePrefix) || strings.HasPrefix(row.Repository, "localhost:5000/") {
				loopback = true
			}
			if row.Repository != "" || row.Tag != "" || row.Digest != "" {
				hasReference = true
			}
			if row.Digest != "" && protect.Digests[row.Digest] {
				protected = true
			}
			if row.Tag != "" {
				hasTag = true
				repository := rootHostRepository(row.Repository)
				if repository == "" || !protect.ServiceRepos[repository] {
					allTagsInServiceRepos = false
				}
				ref := row.Repository + ":" + row.Tag
				tagRef := rootHostTagRef(ref)
				if tagRef == "" {
					protected = true
				} else {
					if protect.TagRefs[tagRef] {
						protected = true
					}
					if !refSeen[ref] {
						refSeen[ref] = true
						refs = append(refs, ref)
					}
					if row.Digest != "" && rootRegistryDigestName.MatchString(row.Digest) {
						pinned[ref] = append(pinned[ref], ref+"@"+row.Digest, row.Repository+"@"+row.Digest)
					}
				}
			} else if row.Repository != "" || row.Digest != "" {
				// A digest or repository without a tag is still an image reference.
				hasDigestOnly = true
				repository := rootHostRepository(row.Repository)
				if row.Repository == "" || row.Digest == "" || repository == "" || !protect.ServiceRepos[repository] {
					allDigestOnlyReposEligible = false
				}
			}
		}
		if loopback || protected || unknownAge || created.IsZero() || !created.Before(now.Add(-rootHostImageMinAge)) {
			continue
		}
		if hasTag && (!allTagsInServiceRepos || !allDigestOnlyReposEligible) {
			continue
		}
		if !hasTag {
			if hasReference && (!hasDigestOnly || !allDigestOnlyReposEligible) {
				continue
			}
			refs = []string{id}
		}
		sort.Strings(refs)
		removals = append(removals, rootHostImageRemoval{ID: id, Refs: refs, Pinned: pinned, Size: size})
	}
	return removals
}

// addRootHostServiceProtection lets current specs establish repository scope.
// Previous specs retain exact images for rollback without widening that scope.
func addRootHostServiceProtection(protect *rootHostProtection, currentRefs, previousRefs []string) error {
	for _, ref := range currentRefs {
		repository := rootHostRepository(ref)
		if repository == "" {
			return fmt.Errorf("Swarm service image reference %q has no repository", ref)
		}
		protect.ServiceRepos[repository] = true
	}
	for _, ref := range append(append([]string(nil), currentRefs...), previousRefs...) {
		if _, digest, ok := strings.Cut(ref, "@"); ok {
			if !rootRegistryDigestName.MatchString(digest) {
				return fmt.Errorf("Swarm service image %q has invalid digest", ref)
			}
			protect.Digests[digest] = true
		} else {
			tagRef := rootHostTagRef(ref)
			if tagRef == "" {
				return fmt.Errorf("Swarm service image reference %q has no valid tag reference", ref)
			}
			protect.TagRefs[tagRef] = true
		}
	}
	return nil
}

// readRootHostSnapshot builds every protection set from host state and fails
// closed if any source cannot be read. The caller takes a fresh snapshot before
// each removal pass so newly held images can only cancel planned removals.
func readRootHostSnapshot(currentPath, previousPath string) (rootHostSnapshot, error) {
	protect := rootHostProtection{
		HeldIDs:      map[string]bool{},
		Digests:      map[string]bool{},
		TagRefs:      map[string]bool{},
		ServiceRepos: map[string]bool{},
	}
	releaseDigests, err := rootImageStoreKeepDigests(currentPath, previousPath)
	if err != nil {
		return rootHostSnapshot{}, fmt.Errorf("read retained release digests: %w", err)
	}
	retained, err := rootImageStoreRetainedStacksExist(currentPath, previousPath)
	if err != nil {
		return rootHostSnapshot{}, fmt.Errorf("check retained stack files: %w", err)
	}
	if retained && len(releaseDigests) == 0 {
		return rootHostSnapshot{}, errors.New("retained stack files exist but no retained release digest could be read")
	}
	for digest := range releaseDigests {
		protect.Digests[digest] = true
	}
	infraKeep, currentRefs, previousRefs, err := rootInfraKeepSetReadWithRefs(currentPath, previousPath)
	if err != nil {
		return rootHostSnapshot{}, err
	}
	for digest := range infraKeep.digests {
		protect.Digests[digest] = true
	}
	if err := addRootHostServiceProtection(&protect, currentRefs, previousRefs); err != nil {
		return rootHostSnapshot{}, err
	}
	containers, err := rootInfraListContainers()
	if err != nil {
		return rootHostSnapshot{}, fmt.Errorf("read host containers: %w", err)
	}
	for _, container := range containers {
		if container.ImageID != "" {
			protect.HeldIDs[container.ImageID] = true
		}
	}
	listing, err := rootImageStoreDockerValue(30*time.Second, "/usr/bin/docker", "image", "ls", "--digests", "--no-trunc", "--format", rootHostImageListFormat)
	if err != nil {
		return rootHostSnapshot{}, fmt.Errorf("list host images: %w", err)
	}
	images, err := parseRootHostImageStore(listing)
	if err != nil {
		return rootHostSnapshot{}, err
	}
	return rootHostSnapshot{Protection: protect, Containers: containers, Images: images}, nil
}

func intersectRootHostTaskContainers(first, fresh []string) []string {
	return intersectRootImageCandidates(first, fresh)
}

func intersectRootHostImages(first, fresh []rootHostImageRemoval) []rootHostImageRemoval {
	byID := map[string]rootHostImageRemoval{}
	for _, candidate := range first {
		byID[candidate.ID] = candidate
	}
	intersection := []rootHostImageRemoval{}
	for _, candidate := range fresh {
		original, ok := byID[candidate.ID]
		if !ok || !equalRootHostImageRefs(original.Refs, candidate.Refs) {
			continue
		}
		intersection = append(intersection, candidate)
	}
	return intersection
}

func equalRootHostImageRefs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// pruneRootHostImages first clears eligible stopped task containers, then
// re-reads the host before considering images. Daemon refusals are logged and
// counted as held, while uncertainty in any listing defers the pass to the
// caller's warning path. Image removals use the existing sole-operation fence.
func pruneRootHostImages(currentPath, previousPath, operationID string, concurrent bool) error {
	removedContainers, removedImages, held := 0, 0, 0
	removedSizes := []string{}
	defer func() {
		sizeSummary := strings.Join(removedSizes, ", ")
		if sizeSummary == "" {
			sizeSummary = "0 B"
		}
		rootLog("host images: %d stopped task containers removed, %d images removed (%s), %d kept because held", removedContainers, removedImages, sizeSummary, held)
	}()

	initial, err := readRootHostSnapshot(currentPath, previousPath)
	if err != nil {
		rootLog("host images: sweep deferred, protection or host state could not be read: %v", err)
		return err
	}
	firstContainers := planRootHostTaskContainers(rootHostProtectedImageIDs(initial.Images, initial.Protection), initial.Containers)
	imageBaseline := initial
	if len(firstContainers) != 0 {
		fresh, readErr := readRootHostSnapshot(currentPath, previousPath)
		if readErr != nil {
			rootLog("host images: task container pass deferred, host state could not be re-read: %v", readErr)
			return readErr
		}
		freshContainers := planRootHostTaskContainers(rootHostProtectedImageIDs(fresh.Images, fresh.Protection), fresh.Containers)
		removedIDs := []string{}
		for _, id := range intersectRootHostTaskContainers(firstContainers, freshContainers) {
			if removeErr := rootImageStoreDockerCommand("/usr/bin/docker", "container", "rm", id); removeErr != nil {
				held++
				rootLog("host images: kept stopped task container %s because removal was refused: %v", id, removeErr)
				continue
			}
			removedContainers++
			removedIDs = append(removedIDs, id)
			rootLog("host images: removed stopped task container %s", id)
		}
		if len(removedIDs) != 0 {
			services := rootHostContainerServices(removedIDs, fresh.Containers)
			fmt.Fprintf(os.Stderr, "%s%d stopped task containers (%s)\n", rootHelperReclaimedPrefix, len(removedIDs), strings.Join(services, ", "))
		}
		imageBaseline, err = readRootHostSnapshot(currentPath, previousPath)
		if err != nil {
			rootLog("host images: image pass deferred, host state could not be re-read: %v", err)
			return err
		}
	}

	imagePass := func() error {
		fresh, readErr := readRootHostSnapshot(currentPath, previousPath)
		if readErr != nil {
			return readErr
		}
		first := planRootHostImages(imageBaseline.Images, imageBaseline.Protection, rootImageStoreNow())
		current := planRootHostImages(fresh.Images, fresh.Protection, rootImageStoreNow())
		for _, candidate := range intersectRootHostImages(first, current) {
			complete := true
			groupHeld := false
			for _, ref := range candidate.Refs {
				if removeErr := removeRootHostImageRef(ref, candidate.Pinned[ref]); removeErr != nil {
					complete = false
					groupHeld = true
					rootLog("host images: kept %s because removal was refused: %v", ref, removeErr)
					continue
				}
				fmt.Fprintf(os.Stderr, "%simage %s (%s)\n", rootHelperReclaimedPrefix, ref, candidate.Size)
				rootLog("host images: removed %s (%s)", ref, candidate.Size)
			}
			if groupHeld {
				held++
			}
			if complete {
				removedImages++
				removedSizes = append(removedSizes, candidate.Size)
			}
		}
		return nil
	}
	if concurrent {
		entered := false
		err = rootInfraSoleOperation(operationID, func() error { entered = true; return imagePass() })
		if err != nil {
			if !entered {
				rootLog("host images: image pass deferred while another operation is active: %v", err)
				return nil
			}
			rootLog("host images: image pass deferred: %v", err)
			return err
		}
	} else if err = imagePass(); err != nil {
		rootLog("host images: image pass deferred: %v", err)
		return err
	}
	return nil
}

func rootHostContainerServices(ids []string, containers []rootInfraContainerEntry) []string {
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	services := map[string]bool{}
	for _, container := range containers {
		if wanted[container.ID] && container.Service != "" {
			services[container.Service] = true
		}
	}
	names := make([]string, 0, len(services))
	for service := range services {
		names = append(names, service)
	}
	sort.Strings(names)
	return names
}

// removeRootHostImageRef removes one planned reference without --force. When
// the plain tag does not resolve ("No such image"), it tries the same image's
// digest-qualified names recorded at planning time, in order; any other
// refusal (an image in use) is returned unchanged so the image stays.
func removeRootHostImageRef(ref string, pinned []string) error {
	err := rootImageStoreDockerCommand("/usr/bin/docker", "image", "rm", ref)
	if err == nil || !strings.Contains(err.Error(), "No such image") {
		return err
	}
	for _, alternate := range pinned {
		alternateErr := rootImageStoreDockerCommand("/usr/bin/docker", "image", "rm", alternate)
		if alternateErr == nil {
			return nil
		}
		if !strings.Contains(alternateErr.Error(), "No such image") {
			return alternateErr
		}
	}
	return err
}
