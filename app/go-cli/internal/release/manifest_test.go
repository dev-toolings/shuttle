package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestValidateTrustedKeys(t *testing.T) {
	first, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	one := base64.StdEncoding.EncodeToString(first)
	two := base64.StdEncoding.EncodeToString(second)
	if err := ValidateTrustedKeys("old="+one+",new="+two, "new", two); err != nil {
		t.Fatalf("valid bridge keyring rejected: %v", err)
	}
	for _, keyring := range []string{
		"old=" + one,
		"old=" + one + ",old=" + two,
		"old=" + one + ",new=" + one,
		"old=not-base64,new=" + two,
		"old=" + one + ", new=" + two,
	} {
		if err := ValidateTrustedKeys(keyring, "new", two); err == nil {
			t.Fatalf("invalid keyring accepted: %q", keyring)
		}
	}
}
