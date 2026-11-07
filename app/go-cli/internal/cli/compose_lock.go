package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/shell"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

type composeLock struct {
	id      string
	unknown bool
}

func composeLockDir(root string) string { return root + "/.lock" }

// Retention removes every unreferenced release. Without an exclusive reservation,
// that includes another deploy's freshly prepared, not yet promoted directory.
func composeLockAcquireCommand(root, id, holder, command string) string {
	lock := shell.Escape(composeLockDir(root))
	tmp := shell.Escape(composeLockDir(root) + "-" + id)
	return "set -eu\numask 077\nmkdir -p -- " + shell.Escape(root) + "\nlock=" + lock + "\ntmp=" + tmp + `
# Publish only complete metadata. A hard link in the same directory is atomic
# and fails if another client already reserved this project.
(set -C; : > "$tmp")
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
started=$(date +%s)
` + "printf '%s\\n' " + shell.Escape("attempt="+id) + " " + shell.Escape("holder="+holder) + " " + shell.Escape("command="+command) + ` "started=$started" > "$tmp"
# A directory here belongs to an older lock format. Do not let ln create a
# link inside it and then claim that this client acquired the project.
if [ -d "$lock" ]; then
  echo "Compose project is locked (older directory format); inspect it manually" >&2
  exit 1
fi
if ln "$tmp" "$lock" 2>/dev/null; then
  if [ ! -f "$lock" ]; then echo "Compose lock publication failed" >&2; exit 1; fi
else
  if [ -e "$lock" ] || [ -L "$lock" ]; then
    echo "Compose project is locked:" >&2
    if [ -r "$lock" ] && [ -f "$lock" ]; then
      cat "$lock" >&2
      started=$(sed -n 's/^started=//p' "$lock")
      now=$(date +%s)
      case "$started" in ''|*[!0-9]*) ;; *) echo "age_seconds=$((now-started))" >&2;; esac
    else echo "holder metadata unavailable" >&2; fi
  else
    echo "Compose lock could not be published" >&2
  fi
  exit 1
fi
`
}

func composeLockReleaseCommand(root, id string) string {
	return "set -eu\nlock=" + shell.Escape(composeLockDir(root)) + "\ntest -f \"$lock\"\ngrep -Fx -- " + shell.Escape("attempt="+id) + " \"$lock\" >/dev/null || { echo 'Compose lock owner changed' >&2; exit 1; }\nrm -f -- \"$lock\"\n"
}

func composeLockedRetentionCommand(root, app, id string) string {
	return "grep -Fx -- " + shell.Escape("attempt="+id) + " " + shell.Escape(composeLockDir(root)) + " >/dev/null || exit 1\n" + composeRetainCommand(root, app)
}

func (h *composeHost) acquireLock(command string) error {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(token[:])
	result := composeRemoteRunner(h.client, composeLockAcquireCommand(h.releaseRoot(), id, h.user, command))
	if result.Code != 0 {
		return fmt.Errorf("cannot acquire Compose lock: %s", strings.TrimSpace(result.Stderr))
	}
	h.lock = &composeLock{id: id}
	return nil
}

func (h composeHost) observe(result ssh.Result) ssh.Result {
	if h.lock != nil && result.OutcomeUnknown {
		h.lock.unknown = true
	}
	return result
}

func (h composeHost) releaseLock() error {
	if h.lock == nil {
		return nil
	}
	if h.lock.unknown {
		return errors.New("Compose lock retained because a remote mutation may still be running; inspect the host before using --break-lock")
	}
	result := composeRemoteRunner(h.client, composeLockReleaseCommand(h.releaseRoot(), h.lock.id))
	if result.Code != 0 {
		return fmt.Errorf("release Compose lock: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

func composeBreakLock(cfg *config.Config, input io.Reader, output io.Writer) error {
	host, err := composeHostConnector(cfg)
	if err != nil {
		return err
	}
	lock := shell.Escape(composeLockDir(host.releaseRoot()))
	result := host.run("set -eu; lock=" + lock + `; test -f "$lock"; test -r "$lock"; cat "$lock"; started=$(sed -n 's/^started=//p' "$lock"); case "$started" in ''|*[!0-9]*) exit 1;; esac; now=$(date +%s); echo "age_seconds=$((now-started))"`)
	if result.Code != 0 {
		return fmt.Errorf("cannot inspect Compose lock: %s", strings.TrimSpace(result.Stderr))
	}
	var id string
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.HasPrefix(line, "attempt=") {
			id = strings.TrimPrefix(line, "attempt=")
		}
	}
	if len(id) != 32 {
		return errors.New("invalid or missing Compose lock attempt id; inspect the host manually")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return errors.New("invalid Compose lock attempt id")
	}
	fmt.Fprint(output, result.Stdout)
	fmt.Fprint(output, "Check that no docker compose process for this project is running. Type the attempt id to break the lock: ")
	answer, err := bufio.NewReader(input).ReadString('\n')
	if err != nil || strings.TrimSpace(answer) != id {
		return errors.New("Compose lock break not confirmed")
	}
	result = host.run(composeLockReleaseCommand(host.releaseRoot(), id))
	if result.Code != 0 {
		return fmt.Errorf("Compose lock was not removed: %s", strings.TrimSpace(result.Stderr))
	}
	fmt.Fprintln(output, "Compose lock removed.")
	return nil
}
