package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testOperatorKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testHostKey     = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func TestRunPlanCarriesANameAndNoCommand(t *testing.T) {
	plan, err := NewRun("api", "reindex", RunOptions{}, testOperatorKey, testHostKey, time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "run" || plan.Run == nil || plan.Run.Operation != "reindex" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	// The wire contract must have nowhere to put a command line. If a field for
	// one ever appears, an unprivileged caller stops being limited to the
	// operations an operator approved.
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"command", "argv", "shell", "exec"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("a run plan must not be able to carry %q:\n%s", forbidden, encoded)
		}
	}
}

func TestRunPlanDefaultAndBackupOptionsWireEncoding(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	plan, err := NewRun("api", "reindex", RunOptions{}, testOperatorKey, testHostKey, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"shuttle.root-operation/v2","digest":"sha256:b04b4d937b8190ee8d95a08028de7ca58398a3a22a7793e465c044f127f43cb6","action":"run","generated_at":"2026-10-26T12:00:00Z","expires_at":"2026-10-26T12:10:00Z","operator_user":"deploy","operator_key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","required_host_fingerprint":"SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","run":{"app":"api","operation":"reindex"}}`
	if string(encoded) != want {
		t.Fatalf("default run plan bytes changed:\n got %s\nwant %s", encoded, want)
	}
	withBackup, err := NewRun("api", "reindex", RunOptions{RequireBackup: true, SkipBackup: true}, testOperatorKey, testHostKey, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(withBackup)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"require_backup":true`) || !strings.Contains(string(encoded), `"skip_backup":true`) {
		t.Fatalf("backup options absent: %s", encoded)
	}
	unsignedBackup := withBackup
	unsignedBackup.Digest = ""
	if err := validate(unsignedBackup, false); err != nil {
		t.Fatalf("backup options should validate: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(withBackup, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, publicKey, now); err != nil {
		t.Fatalf("backup option plan did not verify: %v", err)
	}
	invalid := *withBackup.Run
	invalid.RequireBackup, invalid.SkipBackup = false, true
	withBackup.Run = &invalid
	withBackup.Digest = ""
	if err := validate(withBackup, false); err == nil || err.Error() != "skip_backup requires require_backup" {
		t.Fatalf("invalid skip request accepted: %v", err)
	}
}

func TestRunPlanRejectsUnusableNames(t *testing.T) {
	cases := map[string][2]string{
		"empty operation":     {"api", ""},
		"uppercase operation": {"api", "Reindex"},
		"path traversal":      {"api", "../../etc/passwd"},
		"shell metacharacter": {"api", "reindex;rm"},
		"empty app":           {"", "reindex"},
		"invalid app":         {"Api_Core", "reindex"},
	}
	for name, pair := range cases {
		plan := Plan{
			Schema: Schema, Action: "run",
			GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
			ExpiresAt:    time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			OperatorUser: "deploy", OperatorKeyFingerprint: testOperatorKey,
			RequiredHostFingerprint: testHostKey,
			Run:                     &RunOperation{App: pair[0], Operation: pair[1]},
		}
		if err := validate(plan, false); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// A run mutates state. Folding it into "audit" would make an audit something an
// operator can no longer authorise without reading further.
func TestRunAndAuditAreMutuallyExclusive(t *testing.T) {
	base := func() Plan {
		return Plan{
			Schema: Schema, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			ExpiresAt:    time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			OperatorUser: "deploy", OperatorKeyFingerprint: testOperatorKey,
			RequiredHostFingerprint: testHostKey,
		}
	}
	mixed := base()
	mixed.Action = "run"
	mixed.Run = &RunOperation{App: "api", Operation: "reindex"}
	mixed.Audit = &AuditOperation{Mode: "status", App: "api"}
	if err := validate(mixed, false); err == nil {
		t.Fatal("a run plan carrying audit parameters must be refused")
	}

	smuggled := base()
	smuggled.Action = "audit"
	smuggled.Audit = &AuditOperation{Mode: "status", App: "api"}
	smuggled.Run = &RunOperation{App: "api", Operation: "reindex"}
	if err := validate(smuggled, false); err == nil {
		t.Fatal("an audit plan carrying a run must be refused")
	}

	onStack := base()
	onStack.Action = "stack-apply"
	onStack.Stack = &StackOperation{App: "api", PayloadSHA256: "sha256:" + strings.Repeat("a", 64)}
	onStack.Run = &RunOperation{App: "api", Operation: "reindex"}
	if err := validate(onStack, false); err == nil {
		t.Fatal("a stack plan carrying a run must be refused")
	}
}
