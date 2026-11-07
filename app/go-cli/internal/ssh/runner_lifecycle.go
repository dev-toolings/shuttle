package ssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	runnerSupervisorReadyTimeout = 15 * time.Second
	runnerCleanupTimeout         = 30 * time.Second
	runnerDockerCommandTimeout   = 20 * time.Second
)

// FenceStatus describes what was proven after a runner lease was revoked.
// Only FenceStatusFenced is safe to hand to a recovery coordinator.
type FenceStatus string

const (
	FenceStatusClosed     FenceStatus = "closed"
	FenceStatusFenced     FenceStatus = "fenced"
	FenceStatusUnresolved FenceStatus = "unresolved"
)

// FenceResult is the bounded, runner-scoped proof returned by Fence. It does
// not claim cleanup merely because an SSH transport disappeared.
type FenceResult struct {
	Status             FenceStatus `json:"status"`
	RunToken           string      `json:"run_token"`
	RunnerHost         string      `json:"runner_host"`
	RunnerHostKey      string      `json:"runner_host_key"`
	BootID             string      `json:"boot_id"`
	Namespace          string      `json:"namespace"`
	ActualContainerIDs []string    `json:"actual_container_ids,omitempty"`
	TunnelIdentity     string      `json:"tunnel_identity"`
	AdmissionState     string      `json:"admission_state"`
	StartedAt          time.Time   `json:"started_at"`
	FinishedAt         time.Time   `json:"finished_at"`
	ProofHash          string      `json:"proof_hash"`
	Reasons            []string    `json:"reasons,omitempty"`
}

// RunnerFenceResult is retained as a descriptive alias for callers that want
// to name the result by its owner.
type RunnerFenceResult = FenceResult

// RunnerIdentity is a read-only snapshot of the current leased run.
type RunnerIdentity struct {
	RunToken           string    `json:"run_token"`
	RunnerHost         string    `json:"runner_host"`
	RunnerHostKey      string    `json:"runner_host_key"`
	BootID             string    `json:"boot_id"`
	Namespace          string    `json:"namespace"`
	ActualContainerIDs []string  `json:"actual_container_ids,omitempty"`
	TunnelIdentity     string    `json:"tunnel_identity"`
	AdmissionState     string    `json:"admission_state"`
	StartedAt          time.Time `json:"started_at"`
}

func (r *BuildRunner) commandContext() context.Context {
	if r == nil {
		return context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runContext != nil {
		return r.runContext
	}
	return context.Background()
}

func (r *BuildRunner) trackCommand(command *exec.Cmd) {
	if r == nil || command == nil {
		return
	}
	r.mu.Lock()
	if r.active == nil {
		r.active = make(map[*exec.Cmd]struct{})
	}
	r.active[command] = struct{}{}
	r.mu.Unlock()
}

func (r *BuildRunner) untrackCommand(command *exec.Cmd) {
	if r == nil || command == nil {
		return
	}
	r.mu.Lock()
	delete(r.active, command)
	r.mu.Unlock()
}

func (r *BuildRunner) cancelActiveCommands() {
	if r == nil {
		return
	}
	r.mu.Lock()
	commands := make([]*exec.Cmd, 0, len(r.active))
	for command := range r.active {
		commands = append(commands, command)
	}
	r.mu.Unlock()
	for _, command := range commands {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	}
}

// admitDockerOperation is the single local admission gate for Docker, Buildx
// and bootstrap calls. Unmanaged value-constructed runners remain available to
// the narrow transport tests; production runners are always leased first.
func (r *BuildRunner) admitDockerOperation() error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	r.leaseMu.Lock()
	defer r.leaseMu.Unlock()
	r.mu.Lock()
	closed := r.closed
	managed := r.client != nil || r.remoteRun != nil || r.lease != nil || r.leaseStarting
	r.mu.Unlock()
	if !managed {
		return nil
	}
	if closed {
		return errors.New("build runner admissions are closed")
	}
	if r.lease == nil {
		return errors.New("build runner lease is required")
	}
	if r.lease.revoked || r.lease.admission != "open" {
		return errors.New("build runner lease is no longer admitted")
	}
	return nil
}

func (r *BuildRunner) managedLeaseActive() bool {
	if r == nil {
		return false
	}
	r.leaseMu.Lock()
	defer r.leaseMu.Unlock()
	return r.lease != nil && !r.lease.revoked && r.lease.admission == "open"
}

func (r *BuildRunner) tunnelAdmission(token string) bool {
	if r == nil {
		return false
	}
	r.leaseMu.Lock()
	defer r.leaseMu.Unlock()
	if r.lease == nil || r.lease.token != token || r.lease.revoked || r.lease.admission != "open" {
		return false
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	return !closed
}

func (r *BuildRunner) currentLease() *runnerLease {
	if r == nil {
		return nil
	}
	r.leaseMu.Lock()
	defer r.leaseMu.Unlock()
	return r.lease
}

// AcquireLease starts the lease acquisition and foreground supervisor in one
// remote SSH command. The local runner is admitted only after the supervisor
// has installed its traps and control reader and emitted its ready marker.
func (r *BuildRunner) AcquireLease(app, targetHost string, targetPort int) error {
	if r == nil {
		return errors.New("build runner is nil")
	}
	if !validRunnerComponent(app) {
		return errors.New("build runner application name is invalid")
	}
	if err := r.Prepare(); err != nil {
		return err
	}
	if r.client == nil {
		return errors.New("build runner SSH client is unavailable")
	}
	if r.BuilderName() == "" {
		return errors.New("build runner identity must be set before acquiring its lease")
	}
	if targetPort == 0 {
		targetPort = 22
	}
	r.leaseMu.Lock()
	if r.lease != nil {
		r.leaseMu.Unlock()
		return errors.New("build runner lease is already active")
	}
	if r.leaseStarting {
		r.leaseMu.Unlock()
		return errors.New("build runner lease acquisition is already active")
	}
	r.leaseStarting = true
	r.leaseMu.Unlock()

	token, err := randomToken()
	if err != nil {
		r.finishLeaseStart()
		return fmt.Errorf("create build runner lease identifier: %w", err)
	}
	runnerHost, _, _ := r.endpoint()
	verifiedTargetHost := targetHost
	r.mu.Lock()
	if r.production != nil && r.production.Host != "" {
		verifiedTargetHost = r.production.Host
	}
	r.mu.Unlock()
	command := runnerSupervisorCommand(r, app, verifiedTargetHost, targetPort, token)
	supervisor, err := r.client.StartManagedReady(command, runnerSupervisorReadyMarker(token))
	if err != nil {
		r.finishLeaseStart()
		return fmt.Errorf("start build runner %s supervision: %w", runnerHost, err)
	}
	readyContext, cancelReady := context.WithTimeout(context.Background(), runnerSupervisorReadyTimeout)
	err = supervisor.WaitReady(readyContext)
	cancelReady()
	if err != nil {
		result := supervisor.Close()
		r.finishLeaseStart()
		if result.Code != 0 {
			return fmt.Errorf("build runner %s supervision was not ready: %w; cleanup: %s", runnerHost, err, boundedDiagnostic(result.Stderr, result.Stdout))
		}
		return fmt.Errorf("build runner %s supervision was not ready: %w", runnerHost, err)
	}

	leaseContext, cancel := context.WithCancel(context.Background())
	lease := &runnerLease{
		token: token, app: app, supervisor: supervisor, stop: make(chan struct{}), done: make(chan struct{}),
		ctx: leaseContext, cancel: cancel, heartbeatErr: make(chan error, 1), startedAt: time.Now(),
		admission: "open", namespace: r.runnerID,
	}
	if r.production != nil {
		lease.tunnelIdentity = token + ":" + r.production.User + "@" + r.production.Host + ":" + strconv.Itoa(r.production.Port)
	}

	r.leaseMu.Lock()
	r.leaseStarting = false
	if r.closed || r.lease != nil {
		r.leaseMu.Unlock()
		cancel()
		_ = supervisor.Close()
		return errors.New("build runner closed while acquiring its lease")
	}
	r.lease = lease
	r.leaseMu.Unlock()
	r.mu.Lock()
	r.runContext = leaseContext
	r.mu.Unlock()
	go r.heartbeatLease(lease)
	go r.monitorLease(lease)
	return nil
}

func (r *BuildRunner) finishLeaseStart() {
	r.leaseMu.Lock()
	r.leaseStarting = false
	r.leaseMu.Unlock()
}

func runnerSupervisorReadyMarker(token string) string {
	return "runner-supervisor-ready " + token
}

func (r *BuildRunner) heartbeatLease(lease *runnerLease) {
	ticker := time.NewTicker(runnerHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-lease.stop:
			return
		case <-lease.ctx.Done():
			return
		case <-ticker.C:
			if err := lease.supervisor.Write("heartbeat " + lease.token + "\n"); err != nil {
				select {
				case lease.heartbeatErr <- err:
				default:
				}
				return
			}
		}
	}
}

func (r *BuildRunner) monitorLease(lease *runnerLease) {
	select {
	case result := <-lease.supervisor.Done():
		r.finishLease(lease, result)
	case err := <-lease.heartbeatErr:
		r.revokeLease(lease, fmt.Errorf("runner heartbeat failed: %w", err))
		result := lease.supervisor.Close()
		r.recordSupervisorResult(lease, result)
	}
}

func (r *BuildRunner) revokeLease(lease *runnerLease, reason error) {
	r.leaseMu.Lock()
	if lease.revoked {
		r.leaseMu.Unlock()
		return
	}
	lease.revoked = true
	lease.admission = "closed"
	if reason != nil {
		lease.supervisorResult.Stderr = boundedDiagnostic(reason.Error(), "")
	}
	r.leaseMu.Unlock()
	if lease.cancel != nil {
		lease.cancel()
	}
	r.cancelActiveCommands()
}

func (r *BuildRunner) finishLease(lease *runnerLease, result Result) {
	r.recordSupervisorResult(lease, result)
	r.revokeLease(lease, nil)
}

func (r *BuildRunner) recordSupervisorResult(lease *runnerLease, result Result) {
	r.leaseMu.Lock()
	lease.supervisorResult = result
	r.leaseMu.Unlock()
	lease.finishOnce.Do(func() { close(lease.done) })
	if r != nil {
		r.mu.Lock()
		if r.runContext == lease.ctx {
			r.runContext = nil
		}
		r.mu.Unlock()
	}
	r.cancelActiveCommands()
}

func (r *BuildRunner) beginMutation(action, builder string) error {
	if err := r.admitDockerOperation(); err != nil {
		return err
	}
	lease := r.currentLease()
	if lease == nil {
		return nil
	}
	r.leaseMu.Lock()
	if lease.revoked || lease.admission != "open" {
		r.leaseMu.Unlock()
		return errors.New("build runner lease is no longer admitted")
	}
	lease.mutationPending = true
	r.leaseMu.Unlock()
	result := r.runRemote(runnerMutationPendingCommand(r, lease, action, builder))
	if result.Code != 0 {
		return fmt.Errorf("record build runner mutation pending: %s", boundedDiagnostic(result.Stderr, result.Stdout))
	}
	return nil
}

func (r *BuildRunner) clearMutation(action, builder string) error {
	lease := r.currentLease()
	if lease == nil {
		return nil
	}
	if err := r.admitDockerOperation(); err != nil {
		return err
	}
	result := r.runRemote(runnerMutationClearCommand(r, lease, action, builder))
	if result.Code != 0 {
		return fmt.Errorf("clear build runner mutation pending: %s", boundedDiagnostic(result.Stderr, result.Stdout))
	}
	r.leaseMu.Lock()
	lease.mutationPending = false
	r.leaseMu.Unlock()
	return nil
}

func (r *BuildRunner) recordBuilderContainer(name string) error {
	lease := r.currentLease()
	if lease == nil {
		return nil
	}
	container := buildkitContainerName(name)
	out, err := r.runDocker("inspect", container, "--format", "{{.Id}}|{{.Config.Image}}|{{.HostConfig.NetworkMode}}")
	if err != nil {
		if isMissingBuilder(string(out), err) {
			return nil
		}
		return r.dockerError("inspect remote BuildKit container", name)
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) != 3 || !validContainerID(parts[0]) || parts[1] != r.builderImage || parts[2] != "host" {
		return fmt.Errorf("remote BuildKit container for %s has an unexpected identity", name)
	}
	r.leaseMu.Lock()
	lease.actualContainerIDs = []string{parts[0]}
	r.leaseMu.Unlock()
	result := r.runRemote(runnerRegisterContainerCommand(r, lease, name, parts[0], parts[1], parts[2]))
	if result.Code != 0 {
		return fmt.Errorf("register remote BuildKit container %s: %s", parts[0], boundedDiagnostic(result.Stderr, result.Stdout))
	}
	return nil
}

func validContainerID(value string) bool {
	if len(value) < 12 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') {
			continue
		}
		return false
	}
	return true
}

func (r *BuildRunner) verifyBuilderStopped(name string) error {
	lease := r.currentLease()
	if lease == nil {
		return nil
	}
	r.leaseMu.Lock()
	ids := append([]string(nil), lease.actualContainerIDs...)
	r.leaseMu.Unlock()
	for _, id := range ids {
		out, err := r.runDocker("inspect", id, "--format", "{{.Id}}|{{.State.Status}}")
		if err != nil {
			return fmt.Errorf("verify stopped remote BuildKit container %s for %s: %w", id, name, err)
		}
		parts := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(parts) != 2 || parts[0] != id {
			return fmt.Errorf("remote BuildKit container identity changed while stopping %s", name)
		}
		switch parts[1] {
		case "created", "exited", "dead":
		default:
			return fmt.Errorf("remote BuildKit container %s remains in state %s", id, parts[1])
		}
	}
	return nil
}

func (r *BuildRunner) verifyBuilderRunning(name string) error {
	lease := r.currentLease()
	if lease == nil {
		return nil
	}
	r.leaseMu.Lock()
	ids := append([]string(nil), lease.actualContainerIDs...)
	r.leaseMu.Unlock()
	if len(ids) == 0 {
		return fmt.Errorf("remote BuildKit container for %s was not registered", name)
	}
	for _, id := range ids {
		out, err := r.runDocker("inspect", id, "--format", "{{.Id}}|{{.State.Status}}")
		if err != nil {
			return fmt.Errorf("verify running remote BuildKit container %s for %s: %w", id, name, err)
		}
		parts := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(parts) != 2 || parts[0] != id || parts[1] != "running" {
			return fmt.Errorf("remote BuildKit container %s is not running", id)
		}
	}
	return nil
}

func runnerRunDir(r *BuildRunner, app, token string) string {
	return remoteTunnelStateDir + "/" + app + "/runs/" + token
}

func runnerSupervisorCommand(r *BuildRunner, app, targetHost string, targetPort int, token string) string {
	lock := shellPath(remoteTunnelStateDir + "/leases/" + r.runnerID)
	runDir := shellPath(runnerRunDir(r, app, token))
	tunnelDir := shellPath(remoteTunnelStateDir + "/" + app)
	known := shellPath(remoteTunnelStateDir + "/" + app + "/" + token + ".known_hosts")
	pidfile := shellPath(remoteTunnelStateDir + "/" + app + "/" + token + ".pid")
	targetMarker := targetHost
	r.mu.Lock()
	if r.production != nil && r.production.User != "" {
		targetMarker = sshTarget(r.production.User, targetHost)
	}
	r.mu.Unlock()
	targetPortMarker := "-p " + strconv.Itoa(targetPort)
	containerFile := runDir + "/containers"
	pendingFile := runDir + "/mutation_pending"
	receiptFile := runDir + "/receipt"
	return strings.Join([]string{
		"set -eu",
		// The closure observer refuses group or world bits on the receipt and
		// container inventory. Under the runner account's default umask 0002
		// the live recette wrote both as 0664, so a genuinely fenced run could
		// never be closed through operations writers.
		"umask 077",
		"lock=" + lock,
		"token=" + shellQuote(token),
		"app=" + shellQuote(app),
		"runner_host=" + shellQuote(r.Config.Host),
		"target_value=" + shellQuote(targetHost+":"+strconv.Itoa(targetPort)),
		"state=" + shellPath(remoteTunnelStateDir),
		"run_dir=" + runDir,
		"container_file=" + containerFile,
		"pending_file=" + pendingFile,
		"receipt_file=" + receiptFile,
		"heartbeat=\"$lock/heartbeat\"",
		"tunnel_dir=" + tunnelDir,
		"tunnel_known=" + known,
		"tunnel_pidfile=" + pidfile,
		"tunnel_target=" + shellQuote(targetMarker),
		"tunnel_port=" + shellQuote(targetPortMarker),
		"mkdir -p -- \"$state/leases\" \"$run_dir\"",
		"if ! mkdir -- \"$lock\" 2>/dev/null; then [ -r \"$lock/owner\" ] && grep -F -- \"run_token=$token\" \"$lock/owner\" >/dev/null 2>&1 || { echo 'runner lease busy' >&2; exit 75; }; fi",
		"boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf unknown)",
		"birth=$(awk '{print $22}' /proc/$$/stat 2>/dev/null || printf unknown)",
		"printf '%s\\n' \"run_token=$token\" \"app=$app\" \"runner=$runner_host\" \"target=$target_value\" \"started_unix=$(date +%s)\" \"lease_seconds=" + strconv.Itoa(int(runnerLeaseTTL/time.Second)) + "\" \"boot_id=$boot_id\" \"process_birth=$$:$birth\" > \"$lock/owner\"",
		// The heartbeat is replaced, never rewritten in place. `>` truncates
		// before it writes, and the watch loop below reads the same file every
		// second from another process: a read landing between the two saw an
		// empty value and ended the supervisor with exit 124, as if the client
		// had gone silent. CI caught it on 2026-10-08 (ubuntu, the heartbeat
		// sent right after start), and on a runner it tears down a live build.
		// A rename in the same directory is atomic, so the reader sees either
		// the old timestamp or the new one.
		"beat() { printf '%s\\n' \"$(date +%s)\" > \"$heartbeat.next\" && mv -f -- \"$heartbeat.next\" \"$heartbeat\"; }",
		"beat",
		"exec 3<&0",
		"docker_bin=$(command -v docker 2>/dev/null || true)",
		"timeout_bin=$(command -v timeout 2>/dev/null || true)",
		"docker_timeout() { [ -n \"$docker_bin\" ] && [ -n \"$timeout_bin\" ] || return 1; env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_CONFIG -u BUILDX_BUILDER -u BUILDX_CONFIG -u BUILDKIT_HOST \"$timeout_bin\" 20 \"$docker_bin\" \"$@\"; }",
		"process_owned() { [ -r \"$tunnel_pidfile\" ] || return 1; read pid birth_at_start < \"$tunnel_pidfile\" || return 1; case \"$pid:$birth_at_start\" in ''|*[!0-9:]*) return 1;; esac; [ -r /proc/\"$pid\"/cmdline ] || return 1; [ \"$(awk '{print $22}' /proc/\"$pid\"/stat 2>/dev/null)\" = \"$birth_at_start\" ] || return 1; command_line=$(tr '\\000' ' ' < /proc/\"$pid\"/cmdline); printf '%s' \"$command_line\" | grep -F -- \"$tunnel_known\" >/dev/null 2>&1 && printf '%s' \"$command_line\" | grep -F -- \"$tunnel_target\" >/dev/null 2>&1 && printf '%s' \"$command_line\" | grep -F -- \"$tunnel_port\" >/dev/null 2>&1; }",
		"kill_tunnel() { [ ! -e \"$tunnel_pidfile\" ] && return 0; process_owned || return 1; kill \"$pid\" 2>/dev/null || true; for n in $(seq 1 50); do kill -0 \"$pid\" 2>/dev/null || return 0; sleep 0.1; done; kill -9 \"$pid\" 2>/dev/null || true; ! kill -0 \"$pid\" 2>/dev/null; }",
		"stop_containers() { [ ! -s \"$container_file\" ] && return 0; [ -n \"$docker_bin\" ] && [ -n \"$timeout_bin\" ] || return 1; while IFS='|' read -r id image network builder_name; do case \"$id\" in ''|*[!a-f0-9]*) return 1;; esac; [ \"${#id}\" -ge 12 ] || return 1; observed=$(docker_timeout inspect \"$id\" --format '{{.Id}}|{{.Config.Image}}|{{.HostConfig.NetworkMode}}') || return 1; [ \"$observed\" = \"$id|$image|$network\" ] || return 1; docker_timeout stop -t 10 \"$id\" >/dev/null || return 1; state=$(docker_timeout inspect \"$id\" --format '{{.Id}}|{{.State.Status}}') || return 1; case \"$state\" in \"$id|created\"|\"$id|exited\"|\"$id|dead\") ;; *) return 1;; esac; done < \"$container_file\"; }",
		"cleanup() { status=0; if [ -r \"$lock/owner\" ] && grep -F -- \"run_token=$token\" \"$lock/owner\" >/dev/null 2>&1; then kill_tunnel || status=1; stop_containers || status=1; state_value=fenced; reason=; [ ! -s \"$pending_file\" ] || { state_value=unresolved; reason=mutation_pending; status=1; }; proof_hash=$(printf '%s' \"$token|$boot_id|$state_value|$status\" | sha256sum 2>/dev/null | awk '{print $1}' || true); [ -n \"$proof_hash\" ] || { state_value=unresolved; reason=proof_hash_unavailable; status=1; }; printf '%s\\n' \"state=$state_value\" \"run_token=$token\" \"boot_id=$boot_id\" \"finished_unix=$(date +%s)\" \"proof_hash=$proof_hash\" \"reason=$reason\" > \"$receipt_file\"; if [ \"$status\" -eq 0 ]; then rm -f -- \"$tunnel_pidfile\" \"$tunnel_known\" \"$tunnel_dir/$token.log\"; rm -rf -- \"$lock\"; else printf '%s\\n' cleanup_failed=1 run_token=$token state=$state_value > \"$lock/cleanup-failed\"; fi; fi; return \"$status\"; }",
		"reader() { while IFS= read -r line <&3; do case \"$line\" in \"heartbeat $token\") beat || return 74;; close) return 0;; *) return 64;; esac; done; return 0; }",
		"reader <&3 & reader_pid=$!",
		"trap 'exit 125' HUP INT TERM",
		"trap 'kill \"$reader_pid\" 2>/dev/null || true; cleanup' EXIT",
		"printf '%s\\n' " + shellQuote(runnerSupervisorReadyMarker(token)),
		"while kill -0 \"$reader_pid\" 2>/dev/null; do now=$(date +%s); last=$(cat \"$heartbeat\" 2>/dev/null || printf 0); case \"$last\" in ''|*[!0-9]*) exit 124;; esac; [ $((now-last)) -le 90 ] || exit 124; [ $((now-$(awk -F= '/^started_unix=/{print $2}' \"$lock/owner\"))) -le " + strconv.Itoa(int(runnerLeaseTTL/time.Second)) + " ] || exit 124; sleep 1; done",
		"exit 0",
	}, "\n")
}

func runnerMutationPendingCommand(r *BuildRunner, lease *runnerLease, action, builder string) string {
	dir := shellPath(runnerRunDir(r, lease.app, lease.token))
	return strings.Join([]string{
		"set -eu",
		"dir=" + dir,
		"mkdir -p -- \"$dir\"",
		"[ -r " + shellPath(remoteTunnelStateDir+"/leases/"+r.runnerID) + "/owner ]",
		"grep -F -- " + shellQuote("run_token="+lease.token) + " " + shellPath(remoteTunnelStateDir+"/leases/"+r.runnerID) + "/owner >/dev/null",
		"printf '%s\\n' action=" + shellQuote(action) + " builder=" + shellQuote(builder) + " run_token=" + shellQuote(lease.token) + " started_unix=$(date +%s) > \"$dir/mutation_pending\"",
	}, "\n")
}

func runnerMutationClearCommand(r *BuildRunner, lease *runnerLease, action, builder string) string {
	dir := shellPath(runnerRunDir(r, lease.app, lease.token))
	return strings.Join([]string{
		"set -eu",
		"dir=" + dir,
		"[ -r " + shellPath(remoteTunnelStateDir+"/leases/"+r.runnerID) + "/owner ]",
		"grep -F -- " + shellQuote("run_token="+lease.token) + " " + shellPath(remoteTunnelStateDir+"/leases/"+r.runnerID) + "/owner >/dev/null",
		"rm -f -- \"$dir/mutation_pending\"",
	}, "\n")
}

func runnerRegisterContainerCommand(r *BuildRunner, lease *runnerLease, builder, id, image, network string) string {
	dir := shellPath(runnerRunDir(r, lease.app, lease.token))
	return strings.Join([]string{
		"set -eu",
		"dir=" + dir,
		"mkdir -p -- \"$dir\"",
		"printf '%s\\n' " + shellQuote(id+"|"+image+"|"+network+"|"+builder) + " > \"$dir/containers\"",
	}, "\n")
}

// Fence revokes admissions before asking the already-started supervisor to
// close its owned resources. A receipt is read back over the pinned SSH
// client, and cached locally so repeat reads are idempotent.
func (r *BuildRunner) Fence(runToken string) (FenceResult, error) {
	if r == nil {
		return FenceResult{Status: FenceStatusUnresolved, Reasons: []string{"build runner is nil"}}, errors.New("build runner is nil")
	}
	if strings.TrimSpace(runToken) == "" {
		return FenceResult{Status: FenceStatusUnresolved, Reasons: []string{"run token is required"}}, errors.New("run token is required")
	}
	r.fenceMu.Lock()
	defer r.fenceMu.Unlock()
	r.mu.Lock()
	if r.fenceResults == nil {
		r.fenceResults = make(map[string]FenceResult)
	}
	if cached, ok := r.fenceResults[runToken]; ok {
		r.mu.Unlock()
		return cloneFenceResult(cached), nil
	}
	r.mu.Unlock()
	lease := r.currentLease()
	if lease != nil && lease.token != runToken {
		result := r.makeFenceResult(runToken, FenceStatusUnresolved, []string{"run token does not own the current runner lease"}, nil)
		return result, errors.New("run token does not own the current runner lease")
	}
	if lease == nil {
		result, err := r.readPersistedFenceReceipt(runToken)
		if err == nil {
			r.cacheFenceResult(result)
			return result, nil
		}
		result = r.makeFenceResult(runToken, FenceStatusUnresolved, []string{boundedDiagnostic(err.Error(), "")}, nil)
		return result, err
	}

	r.revokeLease(lease, errors.New("fence requested"))
	result := lease.supervisor.Close()
	r.recordSupervisorResult(lease, result)
	closeContext, cancel := context.WithTimeout(context.Background(), runnerCleanupTimeout)
	select {
	case <-lease.done:
	case <-closeContext.Done():
	}
	cancel()
	receipt, receiptErr := r.readPersistedFenceReceipt(runToken)
	if receiptErr == nil {
		if result.Code != 0 {
			receipt.Status = FenceStatusUnresolved
			receipt.Reasons = append(receipt.Reasons, boundedDiagnostic(result.Stderr, result.Stdout))
		}
		r.cacheFenceResult(receipt)
		if receipt.Status == FenceStatusFenced {
			return receipt, nil
		}
		return receipt, errors.New("runner closure is unresolved")
	}
	reasons := []string{boundedDiagnostic(receiptErr.Error(), "")}
	if result.Code != 0 {
		reasons = append(reasons, boundedDiagnostic(result.Stderr, result.Stdout))
	}
	status := FenceStatusClosed
	if lease.mutationPending || result.Code != 0 {
		status = FenceStatusUnresolved
	}
	fenced := r.makeFenceResult(runToken, status, reasons, lease)
	r.cacheFenceResult(fenced)
	if status == FenceStatusFenced {
		return fenced, nil
	}
	return fenced, errors.New("runner closure could not be proven")
}

func cloneFenceResult(value FenceResult) FenceResult {
	value.ActualContainerIDs = append([]string(nil), value.ActualContainerIDs...)
	value.Reasons = append([]string(nil), value.Reasons...)
	return value
}

func (r *BuildRunner) cacheFenceResult(result FenceResult) {
	r.mu.Lock()
	if r.fenceResults == nil {
		r.fenceResults = make(map[string]FenceResult)
	}
	r.fenceResults[result.RunToken] = cloneFenceResult(result)
	r.mu.Unlock()
}

func (r *BuildRunner) makeFenceResult(token string, status FenceStatus, reasons []string, lease *runnerLease) FenceResult {
	host, _, _ := r.endpoint()
	result := FenceResult{
		Status: status, RunToken: token, RunnerHost: host, RunnerHostKey: r.Config.HostKey,
		Namespace: r.runnerID, AdmissionState: "closed", FinishedAt: time.Now(),
		Reasons: boundedReasons(reasons),
	}
	if lease != nil {
		result.StartedAt = lease.startedAt
		result.BootID = lease.bootID
		result.TunnelIdentity = lease.tunnelIdentity
		result.ActualContainerIDs = append([]string(nil), lease.actualContainerIDs...)
	}
	return result
}

func boundedReasons(reasons []string) []string {
	result := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if reason = strings.TrimSpace(reason); reason == "" {
			continue
		}
		if len(reason) > 1024 {
			reason = reason[:1024]
		}
		result = append(result, reason)
		if len(result) == 8 {
			break
		}
	}
	return result
}

func (r *BuildRunner) readPersistedFenceReceipt(token string) (FenceResult, error) {
	if r == nil || r.remoteRun == nil {
		return FenceResult{}, errors.New("persisted runner receipt is unavailable")
	}
	app := ""
	if lease := r.currentLease(); lease != nil && lease.token == token {
		app = lease.app
	}
	if app == "" {
		return FenceResult{}, errors.New("persisted runner receipt application is unknown")
	}
	path := shellPath(runnerRunDir(r, app, token) + "/receipt")
	result := r.runRemote("set -eu; [ -r " + path + " ] && cat -- " + path)
	if result.Code != 0 {
		return FenceResult{}, errors.New(boundedDiagnostic(result.Stderr, result.Stdout))
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(result.Stdout, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			fields[key] = value
		}
	}
	status := FenceStatus(fields["state"])
	if status != FenceStatusFenced && status != FenceStatusClosed && status != FenceStatusUnresolved {
		return FenceResult{}, errors.New("persisted runner receipt has an unknown state")
	}
	resultValue := r.makeFenceResult(token, status, nil, r.currentLease())
	resultValue.BootID = fields["boot_id"]
	resultValue.ProofHash = fields["proof_hash"]
	if fields["reason"] != "" {
		resultValue.Reasons = boundedReasons([]string{fields["reason"]})
	}
	if resultValue.ProofHash == "" {
		resultValue.Status = FenceStatusUnresolved
		resultValue.Reasons = boundedReasons(append(resultValue.Reasons, "persisted runner receipt has no proof hash"))
	}
	return resultValue, nil
}

func (r *BuildRunner) CurrentRunIdentity() (RunnerIdentity, bool) {
	lease := r.currentLease()
	if lease == nil {
		return RunnerIdentity{}, false
	}
	host, _, _ := r.endpoint()
	r.leaseMu.Lock()
	defer r.leaseMu.Unlock()
	return RunnerIdentity{
		RunToken: lease.token, RunnerHost: host, RunnerHostKey: r.Config.HostKey, BootID: lease.bootID,
		Namespace: lease.namespace, ActualContainerIDs: append([]string(nil), lease.actualContainerIDs...),
		TunnelIdentity: lease.tunnelIdentity, AdmissionState: lease.admission, StartedAt: lease.startedAt,
	}, true
}

// CurrentRun is a concise alias for callers that treat the identity as a
// snapshot rather than a lifecycle operation.
func (r *BuildRunner) CurrentRun() (RunnerIdentity, bool) {
	return r.CurrentRunIdentity()
}

// Close waits for the first closure to finish, including when an interrupt
// cancels a running build and its normal defer calls Close concurrently.
func (r *BuildRunner) Close() (closeErr error) {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		done := r.closeDone
		r.mu.Unlock()
		if done != nil {
			<-done
		}
		r.mu.Lock()
		err := r.closeErr
		r.mu.Unlock()
		return err
	}
	r.closed = true
	r.closeDone = make(chan struct{})
	done := r.closeDone
	transportDir := r.transportDir
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.closeErr = closeErr
		close(done)
		r.mu.Unlock()
	}()
	lease := r.currentLease()
	if lease != nil {
		result, err := r.Fence(lease.token)
		if err == nil && result.Status == FenceStatusFenced {
			if removeErr := os.RemoveAll(transportDir); removeErr != nil {
				return fmt.Errorf("remove build runner transport: %w", removeErr)
			}
		}
		return err
	}
	if transportDir != "" {
		if err := os.RemoveAll(transportDir); err != nil {
			return fmt.Errorf("remove build runner transport: %w", err)
		}
	}
	return nil
}
