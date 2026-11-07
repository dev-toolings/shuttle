//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func TestRootStackPreflightRefusesBindVolumeBeforePhase(t *testing.T) {
	isolateRootStackPreflight(t)
	payload := []byte(strings.Replace(validRootStack(), "    read_only: true\n", "    volumes: [data:/data]\n    read_only: true\n", 1) + "volumes:\n  data: {external: true, name: demo_data}\n")
	rootStackObjectRead = func(_ context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") == "volume inspect --format {{json .}} demo_data" {
			return `{"Driver":"local","Options":{"type":"none","o":"bind","device":"/etc"},"Labels":{}}`, nil
		}
		return "", fmt.Errorf("unexpected docker command %v", args)
	}
	called := false
	rootStackPhase = func(rootplan.Plan, func(context.Context) error) error { called = true; return nil }
	err := applyRootStack(rootStackPreflightPlan(t, payload, time.Now()), payload)
	if err == nil || !strings.Contains(err.Error(), "demo_data") || called {
		t.Fatalf("bind volume passed preflight: err=%v phase=%t", err, called)
	}
}

func TestRootStackObjectsChecksOwnershipAndSharedVolumes(t *testing.T) {
	read := func(_ context.Context, args ...string) (string, error) {
		name := args[len(args)-1]
		switch args[0] {
		case "service":
			return `[{"Type":"volume","Source":"legacy_certs","Target":"/data"}]`, nil
		case "volume":
			switch name {
			case "demo_data", "shuttle-edge_shuttle_caddy_data", "legacy_certs":
				return `{"Driver":"local","Options":{},"Labels":{}}`, nil
			case "demo_stolen":
				return `{"Driver":"local","Options":{},"Labels":{"dev.shuttle.owner":"other"}}`, nil
			case "demo_plugin":
				return `{"Driver":"plugin","Options":{},"Labels":{}}`, nil
			}
		case "secret":
			switch name {
			case "demo_old":
				return `{"Spec":{"Labels":{}}}`, nil
			case "demo_stolen":
				return `{"Spec":{"Labels":{"dev.shuttle.owner":"other"}}}`, nil
			case "shared_token":
				return `{"Spec":{"Labels":{"dev.shuttle.owner":"demo"}}}`, nil
			case "other_token":
				return `{"Spec":{"Labels":{"dev.shuttle.owner":"other"}}}`, nil
			case "unlabelled_token":
				return `{"Spec":{"Labels":{}}}`, nil
			}
		}
		return "", errors.New("Error response from daemon: No such " + args[0] + ": " + name)
	}
	for _, tc := range []struct{ name, stack, rejected string }{
		{"app volume", "volumes:\n  data: {name: demo_data}\n", ""},
		{"edge volume", "volumes:\n  data: {external: true, name: shuttle-edge_shuttle_caddy_data}\n", ""},
		{"adopted certificate volume", "volumes:\n  data: {external: true, name: legacy_certs}\n", ""},
		{"foreign volume", "volumes:\n  data: {external: true, name: other_data}\n", "other_data"},
		{"foreign labelled volume", "volumes:\n  data: {name: demo_stolen}\n", "demo_stolen"},
		{"plugin volume", "volumes:\n  data: {external: true, name: demo_plugin}\n", "demo_plugin"},
		{"legacy app secret", "secrets:\n  demo_old: {external: true}\n", ""},
		{"labelled secret", "secrets:\n  shared_token: {external: true}\n", ""},
		{"foreign secret", "secrets:\n  other_token: {external: true}\n", "other_token"},
		{"unlabelled foreign secret", "secrets:\n  unlabelled_token: {external: true}\n", "unlabelled_token"},
		{"foreign labelled app secret", "secrets:\n  demo_stolen: {external: true}\n", "demo_stolen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRootStackObjects(context.Background(), "demo", []byte(tc.stack), read)
			if tc.rejected == "" && err != nil || tc.rejected != "" && (err == nil || !strings.Contains(err.Error(), tc.rejected)) {
				t.Fatalf("result: %v", err)
			}
		})
	}
}
