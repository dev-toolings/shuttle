package rootplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDestroyConsentAndPreviewTravelInSignedPlan(t *testing.T) {
	now := time.Now()
	fp := "SHA256:" + strings.Repeat("a", 43)
	base, err := NewStackRemove("demo", fp, fp, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(base)
	for _, field := range []string{"drop_databases", "dry_run"} {
		t.Run(field, func(t *testing.T) {
			changed := bytes.Replace(body, []byte(`"remove":true`), []byte(`"remove":true,"`+field+`":true`), 1)
			plan, err := Decode(bytes.NewReader(changed))
			if err != nil {
				t.Fatalf("destroy option must be part of the typed signed plan: %v", err)
			}
			sealed, err := seal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if sealed.Digest == base.Digest {
				t.Fatal("destroy option did not change the signed digest")
			}
		})
	}
}

func TestDestroyOptionsCannotBeTamperedOrUsedForPromotion(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fp := "SHA256:" + strings.Repeat("a", 43)
	for _, field := range []string{"drop", "preview"} {
		plan, err := NewStackRemove("demo", fp, fp, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := Sign(plan, private)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(signed, public, now); err != nil {
			t.Fatal(err)
		}
		if field == "drop" {
			signed.Stack.DropDatabases = true
		} else {
			signed.Stack.DryRun = true
		}
		if err := Verify(signed, public, now); err == nil {
			t.Fatalf("unsigned change to %s authorized", field)
		}
		plan.Stack = signed.Stack
		plan.Stack.Remove = false
		plan.Stack.PayloadSHA256 = PayloadDigest([]byte("stack"))
		if _, err := Sign(plan, private); err == nil {
			t.Fatalf("promotion accepted destroy option %s", field)
		}
	}
}
