package cli

import (
	"strings"
	"testing"
)

// docker_gwbridge can only take an MTU when it is created, and `swarm init`
// creates it at 1500 if it does not exist yet. The alignment must therefore run
// before swarm init in both modes, act only below 1500, and never touch a
// bridge a running Swarm already owns.
func TestDockerStageAlignsTheGatewayBridgeBeforeSwarmInit(t *testing.T) {
	for name, mode := range map[string]setupMode{"fresh": setupModeFresh, "adoption": setupModeAdoption} {
		t.Run(name, func(t *testing.T) {
			program := setupDockerCommand(mode)
			mtu := strings.Index(program, "--opt com.docker.network.driver.mtu=\"$host_mtu\"")
			swarm := strings.Index(program, "docker swarm init")
			if mtu < 0 || swarm < 0 || mtu > swarm {
				t.Fatalf("the gateway MTU must be set before swarm init creates docker_gwbridge:\n%s", program)
			}
			for _, required := range []string{
				`[ "$host_mtu" -lt 1500 ]`,
				`! docker network inspect docker_gwbridge >/dev/null 2>&1`,
				"--opt com.docker.network.bridge.name=docker_gwbridge",
				"--opt com.docker.network.bridge.enable_ip_masquerade=true",
			} {
				if !strings.Contains(program, required) {
					t.Fatalf("the docker stage is missing %q", required)
				}
			}
			if strings.Contains(program, "docker network rm docker_gwbridge") || strings.Contains(program, "systemctl restart docker") {
				t.Fatal("aligning the MTU must never recreate a live bridge or restart dockerd")
			}
		})
	}
}
