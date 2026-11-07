package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHelperUpdateRollbackConsentIsSigned(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	plan, err := NewHelperUpdate("sha256:"+strings.Repeat("b", 64), 1024, fingerprint, fingerprint, now, time.Minute)
	if err == nil {
		plan, err = Sign(plan, privateKey)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Model a transport that adds rollback consent after the operator signed.
	body = []byte(strings.Replace(string(body), `"helper":{`, `"helper":{"allow_downgrade":true,`, 1))
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatal(err)
	}
	if err := Verify(plan, publicKey, now); err == nil {
		t.Fatal("unsigned rollback consent was accepted")
	}
	plan, err = Sign(plan, privateKey)
	if err != nil || Verify(plan, publicKey, now) != nil {
		t.Fatalf("signed rollback consent refused: %v", err)
	}
}

func TestCapabilitiesAuditIsTypedAndSigned(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	plan, err := NewCapabilitiesAudit(fingerprint, fingerprint, now, time.Minute)
	if err == nil {
		plan, err = Sign(plan, privateKey)
	}
	if err != nil || Verify(plan, publicKey, now) != nil || plan.Audit == nil || plan.Audit.Mode != "capabilities" {
		t.Fatalf("invalid capabilities audit: %#v %v", plan, err)
	}
}

func TestHelperUpdateBindsDigestAndBoundedSize(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	digest := "sha256:" + strings.Repeat("b", 64)
	plan, err := NewHelperUpdate(digest, 12<<20, fingerprint, fingerprint, now, time.Minute)
	if err == nil {
		plan, err = Sign(plan, privateKey)
	}
	if err != nil || Verify(plan, publicKey, now) != nil || plan.Helper == nil || plan.Helper.Size != 12<<20 {
		t.Fatalf("invalid helper update: %#v %v", plan, err)
	}

	for _, size := range []int64{0, -1, MaxHelperPayload + 1} {
		if _, err := NewHelperUpdate(digest, size, fingerprint, fingerprint, now, time.Minute); err == nil {
			t.Fatalf("helper size %d must be refused", size)
		}
	}
	if _, err := NewHelperUpdate("sha256:not-a-digest", 1024, fingerprint, fingerprint, now, time.Minute); err == nil {
		t.Fatal("invalid helper digest must be refused")
	}

	tampered := plan
	helper := *plan.Helper
	helper.Size++
	tampered.Helper = &helper
	if err := Verify(tampered, publicKey, now); err == nil {
		t.Fatal("tampered helper size was accepted")
	}
}
