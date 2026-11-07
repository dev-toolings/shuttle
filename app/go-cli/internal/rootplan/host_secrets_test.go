package rootplan

import (
	"strings"
	"testing"
	"time"
)

func hostSecretsPlan(t *testing.T, envFile string, keys []string) (Plan, error) {
	t.Helper()
	operator := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	return NewHostSecretsAction("demo", envFile, keys, operator, host, time.Now(), 5*time.Minute)
}

// The material never leaves the host, so there is nothing for the client to
// hash. What the signature has to cover is the coordinates, because they are
// what decides which bytes become a credential.
func TestHostSecretsPlanCarriesCoordinatesAndNoMaterial(t *testing.T) {
	plan, err := hostSecretsPlan(t, "/opt/demo/.env", []string{"JWT_SECRET_KEY", "HMAC_SECRET_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "secrets-host" || plan.HostSecrets == nil {
		t.Fatalf("expected a host secrets action, got %q", plan.Action)
	}
	if plan.Secrets != nil {
		t.Fatal("a host secrets plan must not carry a secrets payload descriptor")
	}
	if strings.Join(plan.HostSecrets.Keys, ",") != "HMAC_SECRET_KEY,JWT_SECRET_KEY" {
		t.Fatalf("keys must be sorted so the same request always signs the same digest, got %v", plan.HostSecrets.Keys)
	}
}

// An operator comparing two deploys in the helper's journal should not have to
// decide whether a reordered list is a different request.
func TestHostSecretsPlanIsStableAcrossKeyOrder(t *testing.T) {
	first, err := hostSecretsPlan(t, "/opt/demo/.env", []string{"B_KEY", "A_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := hostSecretsPlan(t, "/opt/demo/.env", []string{"A_KEY", "B_KEY", "A_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatal("the same intent must produce the same digest, whatever order it was written in")
	}
}

// Absolute and traversal-free are the two properties that make the path mean
// the same thing to the operator who signed it and to the helper resolving it.
func TestHostSecretsPlanRefusesAPathTheOperatorDidNotPin(t *testing.T) {
	if _, err := hostSecretsPlan(t, ".env", []string{"JWT_SECRET_KEY"}); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("a relative path must be refused, got %v", err)
	}
	if _, err := hostSecretsPlan(t, "/opt/demo/../../etc/shadow", []string{"JWT_SECRET_KEY"}); err == nil || !strings.Contains(err.Error(), "traverse") {
		t.Fatalf("a traversing path must be refused, got %v", err)
	}
	if _, err := hostSecretsPlan(t, "/opt/demo/.env\nAllowUsers root", []string{"JWT_SECRET_KEY"}); err == nil {
		t.Fatal("a path carrying a newline must be refused")
	}
}

// The helper looks these names up in a file it reads as root, so the charset is
// checked in the contract rather than trusted from the caller.
func TestHostSecretsPlanRefusesAnUnusableKey(t *testing.T) {
	if _, err := hostSecretsPlan(t, "/opt/demo/.env", nil); err == nil || !strings.Contains(err.Error(), "between 1 and") {
		t.Fatalf("a plan naming no key does nothing and must be refused, got %v", err)
	}
	if _, err := hostSecretsPlan(t, "/opt/demo/.env", []string{"lowercase"}); err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Fatalf("an invalid key must be refused, got %v", err)
	}
}

// No other action may inherit the right to point the root helper at a path by
// forgetting to refuse the field, which is the same reasoning that keeps secret
// material on exactly one action.
func TestNoOtherActionAcceptsHostSecretCoordinates(t *testing.T) {
	plan, err := hostSecretsPlan(t, "/opt/demo/.env", []string{"JWT_SECRET_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	plan.Action = "run"
	if err := validate(plan, false); err == nil || !strings.Contains(err.Error(), "host secret coordinates") {
		t.Fatalf("expected the coordinates to be refused on another action, got %v", err)
	}
}
