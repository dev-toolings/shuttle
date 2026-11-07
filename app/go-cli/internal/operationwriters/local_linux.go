//go:build linux

package operationwriters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const localKernelProof = "linux-pidfd-v1"

func inspectLocalGroups(ctx context.Context, snapshot any) (LocalInspection, error) {
	input, err := normalizeLocalSnapshot(snapshot)
	if err != nil {
		return LocalInspection{}, err
	}
	if err := verifyBootID(input.binding); err != nil {
		return LocalInspection{}, err
	}
	return inspectGroups(ctx, input.procRoot, input.groups)
}

func inspectGroups(ctx context.Context, procRoot string, groups []LocalGroup) (LocalInspection, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	procInfo, err := os.Lstat(procRoot)
	if err != nil {
		return LocalInspection{}, fmt.Errorf("%w: proc root: %v", ErrProcessMissing, err)
	}
	if procInfo.Mode()&os.ModeSymlink != 0 || !procInfo.IsDir() {
		return LocalInspection{}, fmt.Errorf("%w: proc root is not a trusted directory", ErrAmbiguousProcess)
	}
	processes, err := readProcTable(ctx, procRoot)
	if err != nil {
		return LocalInspection{}, err
	}
	inspection := LocalInspection{ObservedAt: formatTime(time.Now().UTC())}
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return LocalInspection{}, fmt.Errorf("%w: %v", ErrFenceTimeout, err)
		}
		observation, err := observeGroup(group, processes)
		if err != nil {
			return LocalInspection{}, err
		}
		inspection.Groups = append(inspection.Groups, observation)
	}
	localInspectionSort(&inspection)
	hash, err := hashInspection(inspection)
	if err != nil {
		return LocalInspection{}, err
	}
	inspection.EvidenceSHA256 = hash
	return inspection, nil
}

func readProcTable(ctx context.Context, procRoot string) (map[int]ProcessIdentity, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: read proc directory: %v", ErrAmbiguousProcess, err)
	}
	processes := make(map[int]ProcessIdentity)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFenceTimeout, err)
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		identity, err := readProcIdentity(procRoot, pid)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read /proc/%d/stat: %v", ErrAmbiguousProcess, pid, err)
		}
		processes[pid] = identity
	}
	return processes, nil
}

func readProcIdentity(procRoot string, pid int) (ProcessIdentity, error) {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "stat")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ProcessIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return ProcessIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ProcessIdentity{}, fmt.Errorf("proc stat is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil {
		return ProcessIdentity{}, err
	}
	if len(data) == 4096 {
		return ProcessIdentity{}, fmt.Errorf("proc stat exceeded bounded read")
	}
	return parseProcStat(data, pid)
}

func parseProcStat(data []byte, pid int) (ProcessIdentity, error) {
	text := string(data)
	closeParen := strings.LastIndexByte(text, ')')
	if closeParen < 0 || closeParen+2 >= len(text) {
		return ProcessIdentity{}, fmt.Errorf("malformed proc stat for pid %d", pid)
	}
	fields := strings.Fields(text[closeParen+2:])
	// After comm, fields[0] is field 3 (state). Start time is field 22,
	// therefore index 19 in this suffix.
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return ProcessIdentity{}, fmt.Errorf("short proc stat for pid %d", pid)
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("invalid proc parent for pid %d", pid)
	}
	pgid, err := strconv.Atoi(fields[2])
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("invalid proc group for pid %d", pid)
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("invalid proc session for pid %d", pid)
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return ProcessIdentity{}, fmt.Errorf("invalid proc start time for pid %d", pid)
	}
	return ProcessIdentity{PID: pid, StartTicks: startTicks, PPID: ppid, PGID: pgid, SID: sid, State: fields[0]}, nil
}

func observeGroup(group LocalGroup, processes map[int]ProcessIdentity) (LocalGroupObservation, error) {
	leader, leaderPresent := processes[group.LeaderPID]
	if leaderPresent {
		if leader.StartTicks != group.LeaderStartTicks {
			return LocalGroupObservation{}, fmt.Errorf("%w: leader pid %d has a different start time", ErrPIDReused, group.LeaderPID)
		}
		if leader.PGID != group.PGID || leader.SID != group.SID {
			return LocalGroupObservation{}, fmt.Errorf("%w: leader pid %d changed process group", ErrAmbiguousProcess, group.LeaderPID)
		}
	}
	observation := LocalGroupObservation{Group: group, LeaderPresent: leaderPresent}
	for _, process := range processes {
		if process.PGID == group.PGID {
			if process.SID != group.SID {
				return LocalGroupObservation{}, fmt.Errorf("%w: pid %d reuses the writer process group in another session", ErrAmbiguousProcess, process.PID)
			}
			observation.Members = append(observation.Members, process)
		}
	}
	if leaderPresent {
		for _, process := range processes {
			if process.PID == group.LeaderPID || !isDescendant(process.PID, group.LeaderPID, processes) {
				continue
			}
			if process.PGID != group.PGID || process.SID != group.SID {
				return LocalGroupObservation{}, fmt.Errorf("%w: child pid %d escaped the registered process group", ErrAmbiguousProcess, process.PID)
			}
		}
	}
	sort.Slice(observation.Members, func(i, j int) bool { return observation.Members[i].PID < observation.Members[j].PID })
	return observation, nil
}

func isDescendant(pid, leaderPID int, processes map[int]ProcessIdentity) bool {
	seen := make(map[int]struct{})
	current := pid
	for steps := 0; steps < 128; steps++ {
		if current == leaderPID {
			return true
		}
		if _, ok := seen[current]; ok {
			return false
		}
		seen[current] = struct{}{}
		process, ok := processes[current]
		if !ok || process.PPID <= 0 || process.PPID == 1 {
			return false
		}
		current = process.PPID
	}
	return false
}

func hashInspection(inspection LocalInspection) (string, error) {
	payload := struct {
		Groups []LocalGroupObservation `json:"groups"`
	}{Groups: inspection.Groups}
	data, err := marshalCanonical(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func fenceLocalGroups(ctx context.Context, snapshot any) ([]Receipt, error) {
	input, err := normalizeLocalSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	if !input.admissionsClosed {
		return nil, fmt.Errorf("%w: local fencing requires CloseAdmissionsLocked first", ErrAdmissionsClosed)
	}
	if err := ensurePidfdsAvailable(); err != nil {
		return nil, err
	}
	ctx, cancel := contextWithFenceDeadline(ctx)
	defer cancel()
	termSent := make(map[LocalGroup]bool, len(input.groups))
	termAt := make(map[LocalGroup]time.Time, len(input.groups))
	observedMembers := make(map[LocalGroup]map[int]ProcessIdentity, len(input.groups))
	observedGroup := make(map[LocalGroup]bool, len(input.groups))
	for _, group := range input.groups {
		observedMembers[group] = make(map[int]ProcessIdentity)
	}
	const termGrace = 250 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFenceTimeout, err)
		}
		if err := verifyBootID(input.binding); err != nil {
			return nil, err
		}
		inspection, err := inspectGroups(ctx, input.procRoot, input.groups)
		if err != nil {
			return nil, err
		}
		allGone := true
		now := time.Now()
		for _, observation := range inspection.Groups {
			if observation.LeaderPresent || len(observation.Members) > 0 {
				observedGroup[observation.Group] = true
			}
			for _, member := range observation.Members {
				observedMembers[observation.Group][member.PID] = member
			}
			// Exited tasks retain kernel identities until reaped, but have no
			// executable userspace or file descriptors and cannot write again.
			liveMembers := make([]ProcessIdentity, 0, len(observation.Members))
			for _, member := range observation.Members {
				if member.State != "Z" && member.State != "X" && member.State != "x" {
					liveMembers = append(liveMembers, member)
				}
			}
			if len(liveMembers) == 0 {
				continue
			}
			allGone = false
			group := observation.Group
			signal := unix.SIGTERM
			if termSent[group] && now.Sub(termAt[group]) >= termGrace {
				signal = unix.SIGKILL
			}
			if !termSent[group] {
				termSent[group] = true
				termAt[group] = now
			}
			if err := signalObservedMembers(input.procRoot, group, liveMembers, signal); err != nil {
				return nil, err
			}
		}
		if allGone {
			for _, group := range input.groups {
				if !observedGroup[group] && input.binding == (Binding{}) {
					return nil, fmt.Errorf("%w: registered leader and every member disappeared before a complete fence observation", ErrProcessMissing)
				}
			}
			return makeLocalReceipts(input, inspection.ObservedAt, observedMembers), nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, fmt.Errorf("%w: %v", ErrFenceTimeout, ctx.Err())
		case <-timer.C:
		}
	}
}

func verifyBootID(binding Binding) error {
	if binding == (Binding{}) {
		return nil
	}
	file, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fmt.Errorf("%w: read current boot identity: %v", ErrAmbiguousProcess, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return fmt.Errorf("%w: read current boot identity: %v", ErrAmbiguousProcess, err)
	}
	if len(data) == 128 {
		return fmt.Errorf("%w: current boot identity exceeded the bounded read", ErrAmbiguousProcess)
	}
	if strings.TrimSpace(string(data)) != binding.BootID {
		return fmt.Errorf("%w: registered %q, current %q", ErrBootMismatch, binding.BootID, strings.TrimSpace(string(data)))
	}
	return nil
}

func ensurePidfdsAvailable() error {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return fmt.Errorf("%w: pidfd_open is unavailable", ErrUnsupported)
	}
	if err != nil {
		return fmt.Errorf("%w: probe pidfd_open: %v", ErrUnsupported, err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close pidfd capability probe: %w", err)
	}
	return nil
}

func signalObservedMembers(procRoot string, group LocalGroup, members []ProcessIdentity, signal unix.Signal) error {
	for _, member := range members {
		fd, err := unix.PidfdOpen(member.PID, 0)
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return fmt.Errorf("%w: pidfd_open is unavailable", ErrUnsupported)
		}
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return fmt.Errorf("open pidfd for owned pid %d: %w", member.PID, err)
		}
		current, readErr := readProcIdentity(procRoot, member.PID)
		if readErr != nil {
			_ = unix.Close(fd)
			if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, unix.ESRCH) {
				continue
			}
			return fmt.Errorf("%w: reread owned pid %d: %v", ErrAmbiguousProcess, member.PID, readErr)
		}
		if current.StartTicks != member.StartTicks {
			_ = unix.Close(fd)
			return fmt.Errorf("%w: pid %d changed while fencing", ErrPIDReused, member.PID)
		}
		if current.PGID != group.PGID || current.SID != group.SID {
			_ = unix.Close(fd)
			return fmt.Errorf("%w: pid %d left the registered process group", ErrAmbiguousProcess, member.PID)
		}
		err = unix.PidfdSendSignal(fd, signal, nil, 0)
		_ = unix.Close(fd)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return fmt.Errorf("signal owned pid %d through pidfd: %w", member.PID, err)
		}
	}
	return nil
}

func makeLocalReceipts(input localFenceInput, observedAt string, observedByGroup map[LocalGroup]map[int]ProcessIdentity) []Receipt {
	receipts := make([]Receipt, 0, len(input.groups))
	for i, group := range input.groups {
		observedMembers := make([]ProcessIdentity, 0, len(observedByGroup[group]))
		for _, member := range observedByGroup[group] {
			observedMembers = append(observedMembers, member)
		}
		sort.Slice(observedMembers, func(left, right int) bool { return observedMembers[left].PID < observedMembers[right].PID })
		evidenceHash, _ := localEvidenceHash(input.generation, []LocalGroup{group}, observedMembers)
		local := &LocalFenceReceipt{Generation: input.generation, ObservedAt: observedAt, AdmissionsClosed: true, ResourcesClosed: true, EvidenceSHA256: evidenceHash, KernelProof: localKernelProof, Groups: []LocalGroup{group}, ObservedMembers: observedMembers}
		receipts = append(receipts, Receipt{WriterID: input.writerIDs[i], Kind: WriterKindLocalGroup, Generation: input.generation, ObservedAt: observedAt, AdmissionsClosed: true, ResourcesClosed: true, EvidenceSHA256: evidenceHash, Local: local})
	}
	return receipts
}

// EndedBootLocalReceipt closes a local group whose kernel boot has ended.
//
// A client_origin writer is fenced on the machine that ran it, inside the boot
// that ran it. When that machine reboots before the CLI closes its writer (lid
// closed, crash, power loss), the operation stays recovery_required forever:
// the pidfd fence refuses a foreign boot, and nothing else can close the writer.
// Measured 2026-10-05 on api: a deploy finished stack-apply, the laptop
// rebooted, and every later deploy of the application was refused as busy.
//
// The end of a boot is a stronger proof than a pidfd fence: no process of a
// previous boot can exist, so the group has no member left to observe. This
// receipt therefore records no observed member and never probes or signals a
// PID, because the numbers now belong to unrelated processes of the current
// boot. The caller must prove the same machine and a different boot before
// using it; the evidence hash is the one a pidfd fence that found the group
// already gone would produce, so a VPS helper verifies it unchanged.
func EndedBootLocalReceipt(generation uint64, group LocalGroup, observedAt time.Time) (*LocalFenceReceipt, error) {
	if generation == 0 {
		return nil, fmt.Errorf("%w: ended-boot receipt requires a writer generation", ErrInvalidReceipt)
	}
	if err := validateLocalGroup(group); err != nil {
		return nil, err
	}
	members := []ProcessIdentity{}
	evidenceHash, err := localEvidenceHash(generation, []LocalGroup{group}, members)
	if err != nil {
		return nil, fmt.Errorf("%w: ended-boot evidence: %v", ErrInvalidReceipt, err)
	}
	return &LocalFenceReceipt{Generation: generation, ObservedAt: formatTime(observedAt.UTC()), AdmissionsClosed: true, ResourcesClosed: true, EvidenceSHA256: evidenceHash, KernelProof: localKernelProof, Groups: []LocalGroup{group}, ObservedMembers: members}, nil
}

func marshalCanonical(value any) ([]byte, error) {
	return json.Marshal(value)
}
