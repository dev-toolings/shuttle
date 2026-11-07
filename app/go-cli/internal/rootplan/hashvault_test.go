package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestHashvaultPlansBindMetadataAndAppScope(t *testing.T) {
	operator := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	p, err := NewHashvaultAction("demo", "swarm-main", PayloadDigest([]byte("manifest")), operator, host, time.Now(), time.Minute)
	if err != nil || p.Hashvault == nil || p.Secrets != nil {
		t.Fatal(p, err)
	}
	p.Digest = ""
	if err := validate(p, false); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, pub, time.Now()); err != nil {
		t.Fatal(err)
	}
	signed.Hashvault.Target = "other-target"
	if err := Verify(signed, pub, time.Now()); err == nil {
		t.Fatal("signature did not bind target coordinates")
	}
	p.Hashvault.Target = "swarm-main"
	p.Action = "secrets-host"
	if err := validate(p, false); err == nil {
		t.Fatal("another action accepted hashvault metadata")
	}
	if _, err := NewHashvaultAction("demo", "../../target", "digest", operator, host, time.Now(), time.Minute); err == nil {
		t.Fatal("invalid coordinates accepted")
	}
	sync, err := NewHashvaultSyncAction("demo", operator, host, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !operationBindingMatches(sync.Action, "secrets-sync") {
		t.Fatal("sync has no coordinated operation")
	}
	sync.Hashvault.PayloadSHA256 = PayloadDigest([]byte("unexpected"))
	if err := validate(sync, false); err == nil {
		t.Fatal("sync accepted a payload")
	}
}
