package rootplan

import (
	"strings"
	"testing"
	"time"
)

func baseline(t *testing.T, users ...string) Plan {
	t.Helper()
	plan, err := NewBaselineWithSSHUsers(testOperatorKey, testHostKey, users, time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatalf("NewBaselineWithSSHUsers(%v): %v", users, err)
	}
	return plan
}

// Invariant 4: a host converged from scratch must produce the plan it always
// produced, byte for byte, including its digest.
func TestBaselineWithoutExtraUsersIsUnchanged(t *testing.T) {
	now := time.Now()
	before, err := NewBaseline(testOperatorKey, testHostKey, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	after, err := NewBaselineWithSSHUsers(testOperatorKey, testHostKey, nil, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if after.Baseline != nil {
		t.Error("a baseline with no extra account must carry no payload at all")
	}
	if before.Digest != after.Digest {
		t.Errorf("digest changed: %q vs %q", before.Digest, after.Digest)
	}
}

// The account list is the one value this payload exists to carry. If the
// digest did not cover it, it would be the one value the signature does not
// protect — and the one an attacker would most want to edit in flight.
func TestBaselineAccountListIsCoveredByTheDigest(t *testing.T) {
	one := baseline(t, "ops")
	other := baseline(t, "intruder")
	if one.Digest == other.Digest {
		t.Fatal("two different account lists produced the same digest")
	}
	// Re-seal the same plan with only the account list changed: if the digest
	// did not cover it, both would seal identically.
	resealed, err := seal(Plan{
		Schema: one.Schema, Action: one.Action, GeneratedAt: one.GeneratedAt,
		ExpiresAt: one.ExpiresAt, OperatorUser: one.OperatorUser,
		OperatorKeyFingerprint: one.OperatorKeyFingerprint, RequiredHostFingerprint: one.RequiredHostFingerprint,
		Baseline: &BaselineOperation{AllowedSSHUsers: []string{"deploy", "intruder"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resealed.Digest == one.Digest {
		t.Error("editing the account list left the digest unchanged")
	}
}

// The list goes verbatim into an sshd AllowUsers directive, where a stray
// space or pattern character does not fail — it widens who may log in.
func TestBaselineRefusesAnAccountListItWouldHaveToClean(t *testing.T) {
	cases := map[string][]string{
		"unsorted":       {"ops", "deploy"},
		"repeated":       {"deploy", "deploy"},
		"without deploy": {"ops"},
		"embedded space": {"deploy", "ops root"},
		"glob":           {"deploy", "op*"},
		"uppercase":      {"Deploy", "deploy"},
		"newline":        {"deploy", "ops\nroot"},
		"empty":          {"deploy", ""},
	}
	for name, users := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateAllowedSSHUsers(users); err == nil {
				t.Errorf("%v was accepted; it would be written into AllowUsers as-is", users)
			}
		})
	}
	if err := validateAllowedSSHUsers([]string{"deploy", "ops"}); err != nil {
		t.Errorf("a sorted list including deploy must be accepted: %v", err)
	}
}

// Adoption's whole point is not to lock out the account the operator is
// converging from.
func TestBaselineKeepsTheAdoptionOperator(t *testing.T) {
	plan := baseline(t, "ops")
	if plan.Baseline == nil {
		t.Fatal("the payload is missing")
	}
	got := strings.Join(plan.Baseline.AllowedSSHUsers, " ")
	if got != "deploy ops" {
		t.Errorf("AllowedSSHUsers = %q, want \"deploy ops\"", got)
	}
}

// Only the hardening action takes these parameters; rollback and commit must
// not be a second place the account list can be set.
func TestOnlyTheBaselineActionCarriesAccountParameters(t *testing.T) {
	plan := baseline(t, "ops")
	for _, action := range []string{"baseline-rollback", "baseline-commit"} {
		other := plan
		other.Action = action
		if err := validate(other, false); err == nil {
			t.Errorf("%s accepted baseline parameters", action)
		}
	}
}
