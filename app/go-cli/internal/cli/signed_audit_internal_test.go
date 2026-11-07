package cli

import "testing"

func TestInternalReadinessOldHelperMessageRequiresExactRefusal(t *testing.T) {
	message := "the host helper is too old for an internal app readiness audit; run `shuttle helper update`"
	if err := internalReadinessHelperCompatibilityError("", "invalid readiness audit\n"); err == nil || err.Error() != message {
		t.Fatalf("internal old-helper error = %v", err)
	}
	for _, test := range []struct{ domain, stderr string }{
		{"demo.example.com", "invalid readiness audit"},
		{"", "invalid readiness audit: extra detail"},
		{"", "other refusal"},
	} {
		if err := internalReadinessHelperCompatibilityError(test.domain, test.stderr); err != nil {
			t.Errorf("unexpected compatibility message for domain=%q stderr=%q: %v", test.domain, test.stderr, err)
		}
	}
}
