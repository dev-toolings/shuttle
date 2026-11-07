package config

import (
	"reflect"
	"strings"
	"testing"
)

const retainedSetupBlock = "setup:\n  slo_seconds: 600\n  operator_user: ops\n  operator_public_key: keys/ops.pub\n  retained_users: [bob, alice]"

// A shared host keeps the colleagues it already had: the retained accounts
// join deploy and the operator in the one sorted list every signed plan and
// every audit derives from.
func TestSetupRetainedUsersJoinTheSignedAllowList(t *testing.T) {
	cfg, err := loadYAML(t, strings.Replace(validConfig, "setup:\n  slo_seconds: 600", retainedSetupBlock, 1))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.AllowedSSHUsers(), []string{"alice", "bob", "deploy", "ops"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowedSSHUsers() = %v, want %v", got, want)
	}

	// Retained accounts do not need an operator to be valid: a deployment-only
	// configuration carries them so `shuttle doctor` audits the right list.
	withoutOperator := strings.Replace(validConfig, "setup:\n  slo_seconds: 600", "setup:\n  slo_seconds: 600\n  retained_users: [bob]", 1)
	cfg, err = loadYAML(t, withoutOperator)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.AllowedSSHUsers(), []string{"bob", "deploy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowedSSHUsers() = %v, want %v", got, want)
	}
}

// Every entry is written verbatim into an sshd directive, so anything that
// would need cleaning, would widen the list, or contradicts another account is
// refused at the desk with the offending value named.
func TestSetupRetainedUsersRefuseUnsafeOrContradictoryEntries(t *testing.T) {
	base := strings.Replace(validConfig, "setup:\n  slo_seconds: 600", retainedSetupBlock, 1)
	for name, tc := range map[string]struct{ body, want string }{
		"root":         {strings.Replace(base, "[bob, alice]", "[root]", 1), `"root"`},
		"deploy":       {strings.Replace(base, "[bob, alice]", "[deploy]", 1), `"deploy"`},
		"operator":     {strings.Replace(base, "[bob, alice]", "[ops]", 1), "names the operator"},
		"duplicate":    {strings.Replace(base, "[bob, alice]", "[bob, bob]", 1), "repeats"},
		"pattern":      {strings.Replace(base, "[bob, alice]", "['bob root']", 1), `"bob root"`},
		"uppercase":    {strings.Replace(base, "[bob, alice]", "[Bob]", 1), `"Bob"`},
		"padded":       {strings.Replace(base, "[bob, alice]", "[' bob']", 1), `" bob"`},
		"over helper":  {strings.Replace(base, "[bob, alice]", "[u1, u2, u3, u4, u5, u6, u7]", 1), "at most 8"},
		"over no ops":  {strings.Replace(validConfig, "setup:\n  slo_seconds: 600", "setup:\n  slo_seconds: 600\n  retained_users: [u1, u2, u3, u4, u5, u6, u7, u8]", 1), "at most 8"},
		"empty string": {strings.Replace(base, "[bob, alice]", "['']", 1), `""`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, tc.body)
			if err == nil {
				t.Fatal("unsafe retained_users was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name %q", err, tc.want)
			}
		})
	}

	// Exactly at the helper's bound is accepted: deploy, ops and six retained.
	atBound := strings.Replace(base, "[bob, alice]", "[u1, u2, u3, u4, u5, u6]", 1)
	if _, err := loadYAML(t, atBound); err != nil {
		t.Fatalf("eight accounts in total must be accepted: %v", err)
	}
}

// Rule 4: a configuration that does not name the key produces what it always
// produced. The operator-only list is asserted by
// TestSetupOperatorAccessIsExplicitAndPaired; here the direct validator is
// checked on the empty case so a future default cannot slip a name in.
func TestValidateRetainedUsersAcceptsNothingToRetain(t *testing.T) {
	if err := ValidateRetainedUsers(nil, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRetainedUsers(nil, ""); err != nil {
		t.Fatal(err)
	}
}
