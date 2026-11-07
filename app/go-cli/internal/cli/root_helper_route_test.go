//go:build linux

package cli

import (
	"strings"
	"testing"
)

const routeStack = `services:
  api:
    image: registry/app@sha256:aa
    deploy:
      labels:
        dev.shuttle.domain: api.example.com
        dev.shuttle.port: "8000"
  worker-high:
    image: registry/app@sha256:aa
  web:
    image: nginx:alpine
`

// The published service is named by the stack, not by a literal. A stack that
// also contains a service called "web" must still route to the labelled one.
func TestCaddyRouteFragmentFollowsTheLabelledService(t *testing.T) {
	fragment, err := caddyRouteFragment("demo-core", []byte(routeStack))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fragment, "reverse_proxy demo-core_api:8000") {
		t.Fatalf("fragment must proxy to the labelled service, got:\n%s", fragment)
	}
	if strings.Contains(fragment, "demo-core_web") {
		t.Fatalf("fragment must not fall back to a service called web, got:\n%s", fragment)
	}
	if !strings.HasPrefix(fragment, "api.example.com {") {
		t.Fatalf("fragment must open on the labelled domain, got:\n%s", fragment)
	}
}

// An internal application carries no domain label. It must produce no fragment,
// which is also what keeps the shared edge from being reloaded for it.
func TestCaddyRouteFragmentIsEmptyForAnInternalStack(t *testing.T) {
	fragment, err := caddyRouteFragment("demo-agent", []byte("services:\n  agent-next:\n    image: registry/agent@sha256:aa\n"))
	if err != nil {
		t.Fatal(err)
	}
	if fragment != "" {
		t.Fatalf("an unlabelled stack must publish nothing, got:\n%s", fragment)
	}
}

// Go randomises map iteration, so two labelled services would route to a
// different one on different runs. Refuse instead of picking.
func TestCaddyRouteFragmentRejectsTwoPublishedServices(t *testing.T) {
	stack := routeStack + `  second:
    image: registry/app@sha256:aa
    deploy:
      labels:
        dev.shuttle.domain: other.example.com
        dev.shuttle.port: "9000"
`
	if _, err := caddyRouteFragment("demo-core", []byte(stack)); err == nil || !strings.Contains(err.Error(), "more than one service") {
		t.Fatalf("an ambiguous stack must be refused, got %v", err)
	}
}

func TestCaddyRouteFragmentRejectsUnusableRoutingValues(t *testing.T) {
	cases := map[string]string{
		"service name": "services:\n  bad/name:\n    deploy:\n      labels:\n        dev.shuttle.domain: api.example.com\n        dev.shuttle.port: \"8000\"\n",
		"domain":       "services:\n  api:\n    deploy:\n      labels:\n        dev.shuttle.domain: \"api.example.com {\\n}\\nevil.example.com {\"\n        dev.shuttle.port: \"8000\"\n",
		"port":         "services:\n  api:\n    deploy:\n      labels:\n        dev.shuttle.domain: api.example.com\n        dev.shuttle.port: \"70000\"\n",
	}
	for name, stack := range cases {
		if _, err := caddyRouteFragment("demo-core", []byte(stack)); err == nil {
			t.Fatalf("an invalid %s must be refused", name)
		}
	}
}
