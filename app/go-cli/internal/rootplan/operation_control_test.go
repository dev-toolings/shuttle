package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestOperationControlSignatureBindsOutcomeAndIdentity(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	for _, action := range []string{"operation-renew", "operation-finish", "operation-abort", "operation-refuse"} {
		p, err := NewOperationControl(action, strings.Repeat("a", 32), "deploy", "demo", "writers stopped", testOperatorKey, testHostKey, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		p, err = Sign(p, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(p, pub, now); err != nil {
			t.Fatal(err)
		}
		p.Control.Result = "different outcome"
		if err := Verify(p, pub, now); err == nil {
			t.Fatal("outcome changed without invalidating signature")
		}
	}
}

func TestOperationControlRejectsMissingIdentityAndMixedPayload(t *testing.T) {
	now := time.Now()
	if _, err := NewOperationControl("operation-finish", "", "deploy", "demo", "ok", testOperatorKey, testHostKey, now, time.Minute); err == nil {
		t.Fatal("finish without reservation accepted")
	}
	if _, err := NewOperationControl("operation-finish", strings.Repeat("a", 32), "deploy", "demo", "", testOperatorKey, testHostKey, now, time.Minute); err == nil {
		t.Fatal("empty success outcome accepted")
	}
	p, err := NewOperationControl("operation-finish", strings.Repeat("a", 32), "deploy", "demo", "ok", testOperatorKey, testHostKey, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p.Stack = &StackOperation{App: "demo"}
	p.Digest = ""
	if _, err := seal(p); err == nil {
		t.Fatal("control with hidden mutation accepted")
	}
}
