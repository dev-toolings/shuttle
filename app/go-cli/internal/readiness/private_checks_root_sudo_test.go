package readiness

import (
	"os"
	"strings"
	"testing"
)

// As root (the monitoring unit), the probes must not run sudo at all: under
// NoNewPrivileges and ProtectSystem=strict, `sudo -n true` logged "unable to
// open /etc/sudoers" and a failed mail to root on every run (demo prod,
// 2026-10-28).
func TestPrivateProbesAskSudoOnlyWhenNotRoot(t *testing.T) {
	source, err := os.ReadFile("private_checks.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, "if sudo -n true") {
		t.Fatal("a probe runs `sudo -n true` without checking for root first")
	}
	if got := strings.Count(text, "if [ $(id -u) != 0 ] && sudo -n true"); got != 5 {
		t.Fatalf("root-guarded sudo probes = %d, want 5", got)
	}
}
