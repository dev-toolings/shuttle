package config

import (
	"slices"
	"testing"
)

func accessConfig(ports ...int) *Config {
	cfg := &Config{Servers: map[string]ServerGroup{
		"default": {User: "deploy", Port: 22, Access: Access{AllowedPublicTCPPorts: ports}},
	}}
	return cfg
}

// Invariant 4: a configuration that does not set the key must produce exactly
// what it produced before the key could hold anything else.
func TestAllowedPublicPortsDefaultIsUnchanged(t *testing.T) {
	if got := accessConfig().AllowedPublicTCPPorts(); !slices.Equal(got, []int{80, 443}) {
		t.Errorf("AllowedPublicTCPPorts() = %v, want [80 443]", got)
	}
	if got := accessConfig(443, 80).AllowedPublicTCPPorts(); !slices.Equal(got, []int{80, 443}) {
		t.Errorf("AllowedPublicTCPPorts() = %v, want [80 443]", got)
	}
}

// A host legitimately serves more than the edge. Refusing to let the operator
// say so did not make those listeners safe, it made them unreachable and
// undeclarable at the same time.
func TestAllowedPublicPortsAcceptExtraListeners(t *testing.T) {
	if err := validateAccess("default", accessConfig(80, 443, 3000).Servers["default"]); err != nil {
		t.Fatalf("declaring an extra public port must be allowed: %v", err)
	}
	got := accessConfig(3000, 443, 80, 3000).AllowedPublicTCPPorts()
	if !slices.Equal(got, []int{80, 443, 3000}) {
		t.Errorf("AllowedPublicTCPPorts() = %v, want [80 443 3000] sorted and deduplicated", got)
	}
}

// What still has to be guaranteed is that the edge can answer. A list without
// 80 or 443 describes a host that cannot serve, and is still refused.
func TestAllowedPublicPortsStillRequireTheEdge(t *testing.T) {
	for _, ports := range [][]int{{80}, {443}, {3000}} {
		if err := validateAccess("default", accessConfig(ports...).Servers["default"]); err == nil {
			t.Errorf("ports %v: a list without both 80 and 443 must be refused", ports)
		}
	}
	// The SSH port is still off limits: opening it here would duplicate the
	// rule that already exists and let a typo silently widen it.
	if err := validateAccess("default", accessConfig(80, 443, 22).Servers["default"]); err == nil {
		t.Error("the SSH port must not be declarable as a public application port")
	}
}
