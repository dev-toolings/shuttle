package cli

import (
	"strings"
	"testing"
)

// `sshd -T` prints one `allowusers` line per account, not the joined list the
// drop-in was written with. Comparing the joined form found nothing as soon as
// the baseline named more than one account, so a two-account hardening failed
// against a configuration that was in fact exactly right — and rolled back.
func TestEffectiveAllowUsersMatchesOneLinePerAccount(t *testing.T) {
	effective := []byte("permitrootlogin no\nallowusers deploy\nallowusers ops\nx11forwarding no\n")
	if err := verifyEffectiveAllowUsers(effective, "deploy ops"); err != nil {
		t.Fatalf("a configuration that allows exactly the named accounts must pass: %v", err)
	}
	if err := verifyEffectiveAllowUsers([]byte("allowusers deploy\n"), "deploy"); err != nil {
		t.Errorf("the single-account case must keep working: %v", err)
	}
}

// A missing account is the lockout this check exists to prevent.
func TestEffectiveAllowUsersRefusesAMissingAccount(t *testing.T) {
	err := verifyEffectiveAllowUsers([]byte("allowusers deploy\n"), "deploy ops")
	if err == nil {
		t.Fatal("an account the baseline names but sshd does not allow must fail: that account is locked out")
	}
	if !strings.Contains(err.Error(), "ops") {
		t.Errorf("the error should name what is missing, got %q", err)
	}
}

// An extra account is the same question from the other side: the host allows
// somebody the signed baseline never approved.
func TestEffectiveAllowUsersRefusesAnUnapprovedAccount(t *testing.T) {
	if err := verifyEffectiveAllowUsers([]byte("allowusers deploy\nallowusers intruder\n"), "deploy"); err == nil {
		t.Error("an account sshd allows that the baseline does not name must fail")
	}
}

// A drop-in that is installed but inert produces no allowusers line at all.
func TestEffectiveAllowUsersRefusesAnInertDropIn(t *testing.T) {
	err := verifyEffectiveAllowUsers([]byte("permitrootlogin no\nx11forwarding no\n"), "deploy ops")
	if err == nil {
		t.Fatal("no allowusers in effect means the drop-in was not read; that must fail")
	}
	if !strings.Contains(err.Error(), "Include") {
		t.Errorf("the error should point at the Include that makes drop-ins effective, got %q", err)
	}
}
