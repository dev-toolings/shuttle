package cli

import (
	"bytes"
	"testing"
)

func TestReadLimitedSecretRejectsOversize(t *testing.T) {
	_, err := readLimitedSecret(bytes.NewReader(make([]byte, maxSecretBytes+1)))
	if err == nil {
		t.Fatal("expected oversized secret to be rejected")
	}
}

func TestSecretsSetRejectsPositionalValue(t *testing.T) {
	command := newSecretsCommand()
	command.SetArgs([]string{"set", "TOKEN", "must-not-appear"})
	if err := command.Execute(); err == nil {
		t.Fatal("expected positional secret value to be rejected")
	}
}
