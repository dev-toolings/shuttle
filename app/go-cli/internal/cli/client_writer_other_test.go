//go:build !linux

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os/exec"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
)

func TestRunClientWriterRefusesUnsupportedPlatform(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/true")
	err = runClientWriter(&remoteOperation{key: key}, cmd)
	if err == nil {
		t.Fatal("unsupported platform executed an untracked command")
	}
}

func TestCloseRecordedClientWriterRefusesUnsupportedPlatform(t *testing.T) {
	_, err := closeRecordedClientWriter(&remoteOperation{}, operationwriters.Writer{ID: "client-origin:token", Kind: operationwriters.WriterKindClientOrigin}, operationwriters.Binding{})
	if err == nil {
		t.Fatal("unsupported platform closed a recorded client writer")
	}
}
