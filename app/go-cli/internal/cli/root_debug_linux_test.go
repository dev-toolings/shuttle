//go:build linux

package cli

import (
	"strings"
	"testing"
)

func TestDebugInspectUsesAPositiveAllowList(t *testing.T) {
	payload := `[{
  "ID":"service-id",
  "Version":{"Index":4},
  "Spec":{
    "Name":"demo_web",
    "Labels":{"dev.shuttle.operations":"SECRET_COMMAND"},
    "TaskTemplate":{
      "ContainerSpec":{
        "Image":"registry/demo@sha256:abc",
        "User":"1000",
        "ReadOnly":true,
        "Env":["TOKEN=top-secret"],
        "Secrets":[{"SecretName":"database-password"}],
        "Command":["secret-command"],
        "Args":["secret-argument"],
        "Mounts":[{"Source":"private-volume"}]
      },
      "Resources":{"Limits":{"MemoryBytes":536870912}}
    },
    "EndpointSpec":{"Mode":"dnsrr"}
  }
}]`
	body, err := sanitizeRootServiceInspect([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"top-secret", "database-password", "SECRET_COMMAND", "secret-command", "secret-argument", "private-volume", "Env", "Secrets", "Labels", "Mounts"} {
		if strings.Contains(body, secret) {
			t.Errorf("redacted inspect contains %q:\n%s", secret, body)
		}
	}
	for _, visible := range []string{"service-id", "demo_web", "registry/demo@sha256:abc", "MemoryBytes", "dnsrr"} {
		if !strings.Contains(body, visible) {
			t.Errorf("inspect lost safe diagnostic field %q:\n%s", visible, body)
		}
	}
}

func TestDebugOutputRemovesTerminalControlsAndIsBounded(t *testing.T) {
	if got := sanitizeRootDebugText("ok\x1b[31m\rspoof\u202enext\tline"); strings.ContainsAny(got, "\x1b\r\u202e") || !strings.Contains(got, "next\tline") {
		t.Fatalf("unsafe or damaged debug text %q", got)
	}
	output := &limitedDebugOutput{limit: 4}
	written, err := output.Write([]byte("123456"))
	if err != nil || written != 6 || string(output.body) != "1234" || !output.truncated {
		t.Fatalf("bounded output = %q truncated=%t written=%d err=%v", output.body, output.truncated, written, err)
	}
}
