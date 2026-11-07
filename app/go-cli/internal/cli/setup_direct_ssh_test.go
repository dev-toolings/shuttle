package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sshProc is one fixture directory in the /proc layout (stat, comm, cgroup,
// cmdline). The script reads processes from the single `proc=/proc` line, which
// the test swaps for the fixture root, so the real parsing runs on real-shaped
// files.
type sshProc struct {
	pid      string
	comm     string // content of comm, and of the stat comm field unless statComm is set
	statComm string // overrides the comm field inside stat
	state    string
	ppid     string
	start    string
	cgroup   string // content of the cgroup file
	cmdline  string // raw bytes, NUL separated like the kernel does
	// next holds file contents served from the SECOND read of that file, which
	// is how a test changes a process between the ownership check and the kill.
	next map[string]string
}

const (
	sshUnitCgroup    = "0::/system.slice/ssh.service\n"
	sshListenerTitle = "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
)

// sshOrphan is the process of the incident: an sshd listener of PPID 1 inside
// ssh.service's cgroup, with the title OpenSSH sets (NUL padded as on a host).
func sshOrphan(pid string) sshProc {
	return sshProc{pid: pid, comm: "sshd", state: "S", ppid: "1", start: "123456", cgroup: sshUnitCgroup, cmdline: sshListenerTitle + "\x00\x00\x00"}
}

func (p sshProc) statLine() string {
	comm := p.statComm
	if comm == "" {
		comm = p.comm
	}
	// Fields 1-21, then starttime (22), as proc(5) lays them out.
	return fmt.Sprintf("%s (%s) %s %s 8655 8655 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %s 1000000 500 18446744073709551615 0 0 0\n", p.pid, comm, p.state, p.ppid, p.start)
}

// sshStubbedHost is a fake host for setupDirectSSHServiceCommand: shell stubs
// for the commands the script calls and a /proc fixture, so the script's real
// control flow runs without a real sshd. Listener lines are "pid|name" as ss
// reports them; the restart stub mimics the incident: it fails to bind while
// any listener other than the old MainPID still holds port 22.
type sshStubbedHost struct {
	main      string
	listeners []string
	procs     []sshProc
	socket    bool // ssh.socket is enabled
	inactive  bool // ssh.service is not active
	stubborn  bool // SIGTERM has no effect
	zombie    bool // SIGTERM leaves a zombie instead of removing the process
	// initHolds adds systemd (PID 1) to every ss line, as when the socket fd
	// is still shared: "until-restart" drops it on restart, "forever" keeps it.
	initHolds string
	// afterRestart replaces the listeners the restart creates; nil keeps the
	// default single healthy listener (PID 9000).
	afterRestart []string
	vanish       string // ss stops listing this PID from its second call on
}

func (h sshStubbedHost) run(t *testing.T) (calls []string, stderr string, err error) {
	t.Helper()
	if _, lookErr := exec.LookPath("sh"); lookErr != nil {
		t.Skip("sh is not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	state := filepath.Join(dir, "state")
	procRoot := filepath.Join(state, "proc")
	for _, d := range []string{bin, state, procRoot} {
		if mkErr := os.MkdirAll(d, 0o755); mkErr != nil {
			t.Fatal(mkErr)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if writeErr := os.WriteFile(path, []byte(content), 0o755); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	lines := func(items []string) string {
		if len(items) == 0 {
			return ""
		}
		return strings.Join(items, "\n") + "\n"
	}
	for _, p := range h.procs {
		pdir := filepath.Join(procRoot, p.pid)
		if mkErr := os.MkdirAll(pdir, 0o755); mkErr != nil {
			t.Fatal(mkErr)
		}
		write(filepath.Join(pdir, "stat"), p.statLine())
		write(filepath.Join(pdir, "comm"), p.comm+"\n")
		write(filepath.Join(pdir, "cgroup"), p.cgroup)
		write(filepath.Join(pdir, "cmdline"), p.cmdline)
		for file, content := range p.next {
			write(filepath.Join(pdir, file+".next"), content)
		}
	}
	write(filepath.Join(state, "main"), h.main+"\n")
	write(filepath.Join(state, "listeners"), lines(h.listeners))
	if !h.inactive {
		write(filepath.Join(state, "active"), "")
	}
	for flag, on := range map[string]bool{"socket": h.socket, "stubborn": h.stubborn, "zombie": h.zombie} {
		if on {
			write(filepath.Join(state, flag), "")
		}
	}
	if h.initHolds != "" {
		write(filepath.Join(state, "initholds"), h.initHolds+"\n")
	}
	if h.afterRestart != nil {
		write(filepath.Join(state, "after"), lines(h.afterRestart))
	}
	if h.vanish != "" {
		write(filepath.Join(state, "vanish"), h.vanish+"\n")
	}
	write(filepath.Join(bin, "systemctl"), `#!/bin/sh
echo "systemctl $*" >> "$LOG"
case "$1" in
is-enabled) [ -f "$S/socket" ] ;;
is-active) [ -f "$S/active" ] ;;
disable) rm -f "$S/socket" ;;
enable) : ;;
stop)
  # Stopping an active unit kills its MainPID listener. On a unit that is
  # already inactive with a stale MainPID (the 2026-10-28 incident) it is a
  # no-op and the stranded listener stays.
  if [ -f "$S/active" ]; then
    old=$(cat "$S/main")
    grep -v "^$old|" "$S/listeners" > "$S/l.tmp" || true
    mv "$S/l.tmp" "$S/listeners"
    rm -f "$S/active"
  fi
  ;;
show) cat "$S/main" ;;
restart)
  old=$(cat "$S/main")
  gone="$old"
  [ -f "$S/vanish" ] && gone=$(cat "$S/vanish")
  grep -v "^$old|" "$S/listeners" | grep -v "^$gone|" > "$S/l.tmp" || true
  if [ -s "$S/l.tmp" ]; then
    echo "Job for ssh.service failed because the control process exited with error code." >&2
    exit 1
  fi
  if [ -f "$S/after" ]; then
    cp "$S/after" "$S/listeners"
  else
    echo "9000|sshd" > "$S/listeners"
  fi
  echo 9000 > "$S/main"
  touch "$S/active"
  [ "$(cat "$S/initholds" 2>/dev/null)" = forever ] || rm -f "$S/initholds"
  ;;
esac
`)
	write(filepath.Join(bin, "ss"), `#!/bin/sh
echo "ss $*" >> "$LOG"
n=$(cat "$S/ss.count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$S/ss.count"
extra=""
[ -f "$S/initholds" ] && extra=',("systemd",pid=1,fd=40)'
while IFS='|' read -r pid name; do
  [ -n "$pid" ] || continue
  if [ -f "$S/vanish" ] && [ "$n" -ge 2 ] && [ "$(cat "$S/vanish")" = "$pid" ]; then continue; fi
  printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("%s",pid=%s,fd=3)%s)\n' "$name" "$pid" "$extra"
done < "$S/listeners"
`)
	// ps must not be used to establish identity: any call fails the test.
	write(filepath.Join(bin, "ps"), "#!/bin/sh\necho \"ps $*\" >> \"$LOG\"\nexit 99\n")
	// cat serves "<file>.next" from the second read of a fixture file, so a
	// test can change a process between the ownership check and the kill.
	write(filepath.Join(bin, "cat"), `#!/bin/sh
case "$1" in
"$S"/proc/*)
  if [ -f "$1.read" ] && [ -f "$1.next" ]; then mv "$1.next" "$1"; fi
  : > "$1.read"
  ;;
esac
command -p cat "$@"
`)
	for _, name := range []string{"install", "sshd", "sleep"} {
		write(filepath.Join(bin, name), "#!/bin/sh\necho \""+name+" $*\" >> \"$LOG\"\n")
	}
	// kill is a shell builtin, which a PATH stub cannot shadow; a function
	// defined ahead of the script does.
	prelude := `kill() {
  if [ "$1" = -0 ]; then [ -d "$S/proc/$2" ]; return; fi
  echo "kill $*" >> "$LOG"
  if [ -f "$S/stubborn" ]; then return 0; fi
  grep -v "^$2|" "$S/listeners" > "$S/l.tmp" || true
  mv "$S/l.tmp" "$S/listeners"
  if [ -f "$S/zombie" ]; then
    sed 's/) S /) Z /' "$S/proc/$2/stat" > "$S/proc/$2/stat.z"
    mv "$S/proc/$2/stat.z" "$S/proc/$2/stat"
  else
    rm -rf "$S/proc/$2"
  fi
}
`
	script := setupDirectSSHServiceCommand()
	swapped := strings.Replace(script, "\nproc=/proc\n", "\nproc="+procRoot+"\n", 1)
	if swapped == script {
		t.Fatal("the script no longer has the single proc=/proc line the tests swap for a fixture")
	}
	logPath := filepath.Join(dir, "calls.log")
	write(logPath, "")
	var errBuf strings.Builder
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(prelude + swapped)
	cmd.Stderr = &errBuf
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "LOG=" + logPath, "S=" + state}
	err = cmd.Run()
	logged, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	calls = strings.Split(strings.TrimSpace(string(logged)), "\n")
	for _, call := range calls {
		if strings.HasPrefix(call, "ps ") {
			t.Fatalf("process identity must come from /proc, not ps: %q", calls)
		}
	}
	return calls, errBuf.String(), err
}

// mutating drops the read-only probes (systemctl show, ss, sleep) so a test can
// compare what the script changes on the host.
func mutating(calls []string) []string {
	var kept []string
	for _, call := range calls {
		if call == "" || strings.HasPrefix(call, "systemctl show") || strings.HasPrefix(call, "ss ") || strings.HasPrefix(call, "sleep") {
			continue
		}
		kept = append(kept, call)
	}
	return kept
}

func countCalls(calls []string, prefix string) int {
	count := 0
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}

func requireNoDestructiveCall(t *testing.T, calls []string) {
	t.Helper()
	for _, call := range calls {
		if strings.HasPrefix(call, "kill") || strings.HasPrefix(call, "systemctl restart") || strings.HasPrefix(call, "install") {
			t.Fatalf("nothing may be killed or restarted, got %q in %q", call, calls)
		}
	}
}

const (
	sshOrphanListener = "8655|sshd"
	sshUnitListener   = "7000|sshd"
)

// reapedSequence is what the script changes on a host whose socket was enabled
// and which carried one orphan listener (PID 8655).
var reapedSequence = []string{
	"systemctl is-enabled --quiet ssh.socket",
	"systemctl disable --now ssh.socket",
	"systemctl stop ssh.service",
	"systemctl is-active --quiet ssh.service",
	"kill -TERM 8655",
	"install -d -m 0755 /run/sshd",
	"systemctl enable ssh.service",
	"systemctl restart ssh.service",
	"systemctl is-active --quiet ssh.service",
	"sshd -t",
}

func TestDirectSSHServiceKeepsItsCommandsWhenNoOrphanExists(t *testing.T) {
	calls, stderr, err := sshStubbedHost{main: "7000", listeners: []string{sshUnitListener}, socket: true}.run(t)
	if err != nil {
		t.Fatalf("nominal path failed: %v\n%s", err, stderr)
	}
	want := []string{
		"systemctl is-enabled --quiet ssh.socket",
		"systemctl disable --now ssh.socket",
		"systemctl stop ssh.service",
		"systemctl is-active --quiet ssh.service",
		"install -d -m 0755 /run/sshd",
		"systemctl enable ssh.service",
		"systemctl restart ssh.service",
		"systemctl is-active --quiet ssh.service",
		"sshd -t",
	}
	if got := mutating(calls); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("nominal command sequence changed:\n got %q\nwant %q", got, want)
	}
}

func TestDirectSSHServiceLeavesAHealthyDirectServiceAlone(t *testing.T) {
	calls, stderr, err := sshStubbedHost{main: "7000", listeners: []string{sshUnitListener}}.run(t)
	if err != nil {
		t.Fatalf("direct service path failed: %v\n%s", err, stderr)
	}
	// The second is-active is the "is the service dead" gate; it is a read.
	want := "systemctl is-enabled --quiet ssh.socket\nsystemctl is-active --quiet ssh.service\nsystemctl is-active --quiet ssh.service\nsshd -t"
	if got := strings.Join(mutating(calls), "\n"); got != want {
		t.Fatalf("a host already on ssh.service must not be touched, got:\n%s", got)
	}
}

func TestDirectSSHServiceRerunConvergesWhenTheSocketIsAlreadyDisabledAndTheServiceIsDown(t *testing.T) {
	calls, stderr, err := sshStubbedHost{main: "0", inactive: true}.run(t)
	if err != nil {
		t.Fatalf("rerun after a partial failure did not converge: %v\n%s", err, stderr)
	}
	want := []string{
		"systemctl is-enabled --quiet ssh.socket",
		"systemctl is-active --quiet ssh.service",
		"systemctl disable --now ssh.socket",
		"systemctl stop ssh.service",
		"systemctl is-active --quiet ssh.service",
		"install -d -m 0755 /run/sshd",
		"systemctl enable ssh.service",
		"systemctl restart ssh.service",
		"systemctl is-active --quiet ssh.service",
		"sshd -t",
	}
	if got := mutating(calls); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected rerun sequence:\n got %q\nwant %q", got, want)
	}
}

func TestDirectSSHServiceReapsAnOrphanListenerBeforeRestarting(t *testing.T) {
	preTitle := sshOrphan("8655")
	preTitle.cmdline = "/usr/sbin/sshd -D\x00"
	// The comm field of stat holds ") S 99 (" so a parser that stops at the
	// first ")" would read ppid 99 and refuse; only the last ") " is right.
	trickyStat := sshOrphan("8655")
	trickyStat.statComm = "sshd) S 99 (x"
	// A scanner connected: the live counter differs between the two reads.
	counter := sshOrphan("8655")
	counter.next = map[string]string{"cmdline": "sshd: /usr/sbin/sshd -D [listener] 3 of 10-100 startups\x00\x00\x00"}
	zombie := sshOrphan("8655")
	for name, host := range map[string]sshStubbedHost{
		"unit inactive":                    {main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{sshOrphan("8655")}, socket: true},
		"unit listening too":               {main: "7000", listeners: []string{sshUnitListener, sshOrphanListener}, procs: []sshProc{sshOrphan("8655")}, socket: true},
		"pre-title -D command":             {main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{preTitle}, socket: true},
		"IPv4 and IPv6 lines":              {main: "0", listeners: []string{sshOrphanListener, sshOrphanListener}, procs: []sshProc{sshOrphan("8655")}, socket: true},
		"shared with systemd":              {main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{sshOrphan("8655")}, socket: true, initHolds: "until-restart"},
		"rerun after failure":              {main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{sshOrphan("8655")}, inactive: true},
		"comm with a paren in stat":        {main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{trickyStat}, socket: true},
		"startups counter changed":         {main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{counter}, socket: true},
		"zombie after SIGTERM counts gone": {main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{zombie}, socket: true, zombie: true},
	} {
		t.Run(name, func(t *testing.T) {
			calls, stderr, err := host.run(t)
			if err != nil {
				t.Fatalf("orphan was not replaced: %v\n%s", err, stderr)
			}
			got := mutating(calls)
			if name == "rerun after failure" {
				// socket already disabled and service down: same repair, plus the gate read.
				got = append([]string{got[0]}, got[2:]...)
			}
			if strings.Join(got, "\n") != strings.Join(reapedSequence, "\n") {
				t.Fatalf("unexpected sequence:\n got %q\nwant %q", got, reapedSequence)
			}
			if killed := countCalls(calls, "kill"); killed != 1 {
				t.Fatalf("the orphan must be killed exactly once, got %d in %q", killed, calls)
			}
		})
	}
}

func TestDirectSSHServiceNeverKillsWhatIsNotAnOrphanSSHDListener(t *testing.T) {
	proc := func(mutate func(*sshProc)) sshProc {
		p := sshOrphan("4321")
		mutate(&p)
		return p
	}
	for name, want := range map[string]struct {
		proc     sshProc
		contains string
	}{
		"web server on 22": {proc(func(p *sshProc) {
			p.comm, p.cgroup, p.cmdline = "nginx", "0::/system.slice/nginx.service\n", "nginx: master process /usr/sbin/nginx\x00"
		}), "comm=nginx"},
		"sshd with a live parent": {proc(func(p *sshProc) { p.ppid = "900" }), "ppid=900"},
		"sshd session":            {proc(func(p *sshProc) { p.cmdline = "sshd: root@pts/0\x00" }), "args=sshd: root@pts/0"},
		"renamed title only":      {proc(func(p *sshProc) { p.comm = "python3" }), "comm=python3"},
		"cgroup file with only a foreign unit": {proc(func(p *sshProc) {
			p.cgroup = "0::/system.slice/sshd-alt.service\n"
		}), "cgroup=0::/system.slice/sshd-alt.service"},
		"cgroup of a login session": {proc(func(p *sshProc) {
			p.cgroup = "0::/user.slice/user-1000.slice/session-3.scope\n"
		}), "cgroup=0::/user.slice/user-1000.slice/session-3.scope"},
		"cgroup v1 layout": {proc(func(p *sshProc) {
			p.cgroup = "1:name=systemd:/system.slice/ssh.service\n"
		}), "cgroup=1:name=systemd:/system.slice/ssh.service"},
		"comm with spaces and parens": {proc(func(p *sshProc) { p.comm = "web (x) y" }), "ppid=1 comm=web (x) y"},
	} {
		t.Run(name, func(t *testing.T) {
			calls, stderr, err := sshStubbedHost{main: "0", listeners: []string{"4321|x"}, procs: []sshProc{want.proc}, socket: true}.run(t)
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("script must fail, got err=%v", err)
			}
			if !strings.Contains(stderr, "PID 4321") || !strings.Contains(stderr, "args=") || !strings.Contains(stderr, want.contains) {
				t.Fatalf("failure must name the PID, its cgroup and its arguments (%q), got %q", want.contains, stderr)
			}
			requireNoDestructiveCall(t, calls)
		})
	}
}

func TestDirectSSHServiceRefusesAReusedPIDWhoseStartTimeChanges(t *testing.T) {
	reused := sshOrphan("8655")
	reused.next = map[string]string{"stat": sshOrphan("8655").statLine()}
	// Same PID, same shape, a different process: only the start time differs.
	later := sshOrphan("8655")
	later.start = "999999"
	reused.next["stat"] = later.statLine()
	calls, stderr, err := sshStubbedHost{main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{reused}, socket: true}.run(t)
	if err == nil || !strings.Contains(stderr, "PID 8655") || !strings.Contains(stderr, "changed between") {
		t.Fatalf("expected a refusal naming PID 8655, got err=%v stderr=%q", err, stderr)
	}
	requireNoDestructiveCall(t, calls)
}

func TestDirectSSHServiceRefusesAnOrphanThatChangesParentOrCgroupBeforeTheKill(t *testing.T) {
	for name, next := range map[string]map[string]string{
		"parent":  {"stat": func() string { p := sshOrphan("8655"); p.ppid = "300"; return p.statLine() }()},
		"cgroup":  {"cgroup": "0::/system.slice/other.service\n"},
		"command": {"cmdline": "sshd: root@pts/0\x00"},
	} {
		t.Run(name, func(t *testing.T) {
			p := sshOrphan("8655")
			p.next = next
			calls, stderr, err := sshStubbedHost{main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{p}, socket: true}.run(t)
			if err == nil || !strings.Contains(stderr, "PID 8655") {
				t.Fatalf("expected a refusal naming PID 8655, got err=%v stderr=%q", err, stderr)
			}
			requireNoDestructiveCall(t, calls)
		})
	}
}

func TestDirectSSHServiceRefusesAListedPIDWhoseProcEntryIsUnreadable(t *testing.T) {
	calls, stderr, err := sshStubbedHost{main: "0", listeners: []string{sshOrphanListener}, socket: true}.run(t)
	if err == nil || !strings.Contains(stderr, "PID 8655") || !strings.Contains(stderr, "cannot be read") {
		t.Fatalf("expected a refusal naming PID 8655, got err=%v stderr=%q", err, stderr)
	}
	requireNoDestructiveCall(t, calls)
}

func TestDirectSSHServiceSkipsAListenerThatExitedBetweenSSAndProc(t *testing.T) {
	calls, stderr, err := sshStubbedHost{main: "0", listeners: []string{sshOrphanListener}, socket: true, vanish: "8655"}.run(t)
	if err != nil {
		t.Fatalf("a listener that already exited must not stop setup: %v\n%s", err, stderr)
	}
	if countCalls(calls, "kill") != 0 {
		t.Fatalf("an exited process must not be killed: %q", calls)
	}
}

func TestDirectSSHServiceFailsWhenTheOrphanSurvivesSIGTERM(t *testing.T) {
	calls, stderr, err := sshStubbedHost{main: "0", listeners: []string{sshOrphanListener}, procs: []sshProc{sshOrphan("8655")}, socket: true, stubborn: true}.run(t)
	if err == nil || !strings.Contains(stderr, "PID 8655 is still running") {
		t.Fatalf("expected a failure naming PID 8655, got err=%v stderr=%q", err, stderr)
	}
	if countCalls(calls, "systemctl restart") != 0 {
		t.Fatalf("must not restart while the port is still held: %q", calls)
	}
	if sleeps := countCalls(calls, "sleep"); sleeps != 5 {
		t.Fatalf("the wait must be bounded at 5 seconds, slept %d times", sleeps)
	}
}

func TestDirectSSHServiceVerifiesTheListenersAfterRestart(t *testing.T) {
	for name, host := range map[string]sshStubbedHost{
		"unexpected extra listener": {main: "7000", listeners: []string{sshUnitListener}, socket: true,
			afterRestart: []string{"9000|sshd", "5555|nginx"}},
		"no listener at all":           {main: "7000", listeners: []string{sshUnitListener}, socket: true, afterRestart: []string{}},
		"systemd still holds the port": {main: "7000", listeners: []string{sshUnitListener}, socket: true, initHolds: "forever"},
	} {
		t.Run(name, func(t *testing.T) {
			calls, stderr, err := host.run(t)
			if err == nil || !strings.Contains(stderr, "not exactly its MainPID") {
				t.Fatalf("expected a verification failure, got err=%v stderr=%q", err, stderr)
			}
			if sleeps := countCalls(calls, "sleep"); sleeps != 4 {
				t.Fatalf("the verification must retry a bounded number of times, slept %d times", sleeps)
			}
			if countCalls(calls, "kill") != 0 {
				t.Fatalf("verification must never kill: %q", calls)
			}
			// A failed conversion must give port 22 back to ssh.socket, never
			// leave the host without a listener (Ubuntu VM e2e, 2026-10-28).
			restored := false
			for _, call := range calls {
				if strings.Contains(call, "enable --now ssh.socket") {
					restored = true
				}
			}
			if !restored || !(strings.Contains(stderr, "ssh.socket now listens on TCP 22 again") || strings.Contains(stderr, "ssh.socket could not take TCP 22 back")) {
				t.Fatalf("failed conversion did not restore ssh.socket: calls=%q stderr=%q", calls, stderr)
			}
		})
	}
}

// A successful conversion that reaped an orphan must say so on the setup
// output; systemctl's own stderr chatter must not be forwarded.
func TestReportReapedSSHListenersForwardsOnlyReapLines(t *testing.T) {
	var out strings.Builder
	reportReapedSSHListeners(&out, "Removed \"/etc/systemd/system/sockets.target.wants/ssh.socket\".\n"+
		"stopping orphan sshd listener PID 11025 (left in ssh.service's cgroup, not its MainPID)\n"+
		"Created symlink /etc/systemd/system/multi-user.target.wants/ssh.service.\n")
	want := "  -> stopping orphan sshd listener PID 11025 (left in ssh.service's cgroup, not its MainPID)\n"
	if out.String() != want {
		t.Fatalf("setup output = %q, want %q", out.String(), want)
	}
}

// Fresh Ubuntu 24.04 (2026-10-28): after ssh.socket stopped, ssh.service was
// already inactive but systemd still reported the needrestart-started sshd as
// its MainPID, and that sshd kept TCP 22. Sparing MainPID then left the port
// held, the restart failed and SSH was lost. An inactive unit's MainPID is
// stale and its listener is reaped like any orphan.
func TestDirectSSHServiceReapsAListenerBehindAStaleMainPID(t *testing.T) {
	stale := sshOrphan("7000")
	calls, stderr, err := sshStubbedHost{main: "7000", listeners: []string{"7000|sshd"}, procs: []sshProc{stale}, socket: true, inactive: true}.run(t)
	if err != nil {
		t.Fatalf("stale MainPID listener was not replaced: %v\n%s", err, stderr)
	}
	if countCalls(calls, "kill") != 1 {
		t.Fatalf("the stranded listener must be killed exactly once: %q", calls)
	}
}
