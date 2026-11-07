package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestSetupOperatorAccessIsExplicitAndPaired(t *testing.T) {
	body := strings.Replace(validConfig, "setup:\n  slo_seconds: 600", "setup:\n  slo_seconds: 600\n  operator_user: ops\n  operator_public_key: keys/ops.pub", 1)
	cfg, err := loadYAML(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.AllowedSSHUsers(), []string{"deploy", "ops"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowedSSHUsers() = %v, want %v", got, want)
	}

	for name, mutation := range map[string]string{
		"user only": strings.Replace(validConfig, "setup:\n  slo_seconds: 600", "setup:\n  slo_seconds: 600\n  operator_user: ops", 1),
		"key only":  strings.Replace(validConfig, "setup:\n  slo_seconds: 600", "setup:\n  slo_seconds: 600\n  operator_public_key: keys/ops.pub", 1),
		"root":      strings.Replace(body, "operator_user: ops", "operator_user: root", 1),
		"deploy":    strings.Replace(body, "operator_user: ops", "operator_user: deploy", 1),
		"pattern":   strings.Replace(body, "operator_user: ops", "operator_user: 'ops root'", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, mutation); err == nil {
				t.Fatal("unsafe or incomplete operator access was accepted")
			}
		})
	}
}

func TestDefaultAllowedSSHUsersRemainsDeployOnly(t *testing.T) {
	cfg, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.AllowedSSHUsers(), []string{"deploy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowedSSHUsers() = %v, want %v", got, want)
	}
}
