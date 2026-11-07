package cli

import (
	"encoding/json"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestSignedReadinessAuditRequiresPublicHealthcheckPath(t *testing.T) {
	var cfg config.Config
	if err := json.Unmarshal([]byte(`{"domain":"app.example.com"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	_, err := runSignedReadinessAudit(&cfg)
	want := `readiness.healthcheck_path is required for a public app: add it to config.json, for example {"readiness": {"healthcheck_path": "/health"}}`
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

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
