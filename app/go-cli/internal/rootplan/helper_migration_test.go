package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestHelperMigrationSignatureBindsCandidateAndIntent(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	for _, action := range []string{"helper-migration-finalize", "helper-migration-reconcile"} {
		p, err := NewHelperMigrationAction(action, "sha256:"+strings.Repeat("a", 64), "12345678-1234-1234-1234-123456789abc", testOperatorKey, testHostKey, now, time.Minute)
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
		p.HelperMigration.CandidateSHA256 = "sha256:" + strings.Repeat("b", 64)
		if err := Verify(p, pub, now); err == nil {
			t.Fatal("another candidate retained a valid signature")
		}
	}
}

func TestHelperMigrationRejectsUnrelatedMutationAndReservation(t *testing.T) {
	for _, change := range []func(*Plan){
		func(p *Plan) { p.OperationID = strings.Repeat("a", 32); p.OperationKind = "helper-update" },
		func(p *Plan) {
			p.Helper = &HelperOperation{PayloadSHA256: "sha256:" + strings.Repeat("a", 64), Size: 1}
		},
		func(p *Plan) { p.Stack = &StackOperation{App: "demo"} },
		func(p *Plan) { p.HelperMigration.CandidateSHA256 = "latest" },
		func(p *Plan) { p.HelperMigration.IntentID = "invalid" },
		func(p *Plan) { p.Action = "baseline" },
	} {
		p, err := NewHelperMigrationFinalize("sha256:"+strings.Repeat("a", 64), testOperatorKey, testHostKey, time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		p.Digest = ""
		change(&p)
		if _, err := seal(p); err == nil {
			t.Fatal("invalid migration request accepted")
		}
	}
}
