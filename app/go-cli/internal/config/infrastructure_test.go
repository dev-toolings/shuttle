package config

import (
	"strings"
	"testing"
)

func validInfrastructureConfig() InfrastructureConfig {
	return InfrastructureConfig{
		Driver: "pvecli", PVECLIConfig: "infrastructure/pvecli.local.yaml",
		TerraformResource: "proxmox_virtual_environment_container.shuttle",
		GuestType:         "lxc", GuestID: 240, AnsiblePlaybook: "bootstrap.yml",
		InventoryTag: "shuttle_example", PublicKey: "~/.ssh/id_ed25519.pub", AllowRecreate: true,
	}
}

func TestInfrastructureAcceptsOneExactPVECLIManagedLXC(t *testing.T) {
	if err := validateInfrastructure(validInfrastructureConfig()); err != nil {
		t.Fatalf("valid infrastructure rejected: %v", err)
	}
}

func TestInfrastructureRejectsBroadOrEscapingDestructiveTargets(t *testing.T) {
	for name, mutate := range map[string]func(*InfrastructureConfig){
		"whole resource family": func(value *InfrastructureConfig) { value.TerraformResource = "proxmox_virtual_environment_container" },
		"shell-like target":     func(value *InfrastructureConfig) { value.TerraformResource = "x.y;terraform destroy" },
		"escaping config":       func(value *InfrastructureConfig) { value.PVECLIConfig = "../pvecli.yaml" },
		"unsupported guest":     func(value *InfrastructureConfig) { value.GuestType = "vm" },
	} {
		t.Run(name, func(t *testing.T) {
			value := validInfrastructureConfig()
			mutate(&value)
			if err := validateInfrastructure(value); err == nil {
				t.Fatalf("unsafe infrastructure accepted: %#v", value)
			}
		})
	}
}

func TestHostOwnedKernelFacilitiesAreExplicit(t *testing.T) {
	cfg, err := loadYAML(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Setup.SwapMode != "managed" || cfg.Setup.AppArmorMode != "managed" {
		t.Fatalf("ordinary VPS defaults changed: %#v", cfg.Setup)
	}
	for _, value := range []string{"container", "off"} {
		body := strings.Replace(validConfig, "slo_seconds: 600", "slo_seconds: 600\n  swap_mode: "+value, 1)
		_, gotErr := loadYAML(t, body)
		if gotErr == nil || !strings.Contains(gotErr.Error(), "setup.swap_mode") {
			t.Fatalf("invalid swap mode %q was not rejected: %v", value, gotErr)
		}
	}
}
