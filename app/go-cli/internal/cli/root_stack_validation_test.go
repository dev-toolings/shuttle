package cli

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func validRootStack() string {
	return `services:
  web:
    image: registry.invalid/demo@sha256:` + strings.Repeat("a", 64) + `
    read_only: true
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    healthcheck: {test: [CMD, /health]}
    deploy:
      resources:
        limits: {cpus: "1.0", memory: 256M}
`
}

func TestRootStackPolicyRejectsDangerousCapabilities(t *testing.T) {
	mutations := []string{
		"    privileged: true\n",
		"    cap_add: [SYS_ADMIN]\n",
		"    ports: [\"8080:8080\"]\n",
		"    volumes: [\"host:/var/run/docker.sock\"]\n",
		"    volumes: [\"/etc:/host\"]\n",
		"    volumes: [{type: bind, source: /etc, target: /host}]\n",
		"    devices: [\"/dev/kvm\"]\n",
		"    networks: [host]\n",
	}
	for _, mutation := range mutations {
		body := strings.Replace(validRootStack(), "    read_only: true\n", mutation+"    read_only: true\n", 1)
		if err := validateRootStack([]byte(body)); err == nil {
			t.Fatalf("dangerous stack accepted:\n%s", body)
		}
	}
}

func TestRootStackPolicyRejectsHostNetworkAliases(t *testing.T) {
	for _, suffix := range []string{
		"networks:\n  host: {external: true}\n",
		"networks:\n  escape: {name: host, external: true}\n",
		"networks:\n  escape:\n    external: {name: host}\n",
	} {
		body := strings.Replace(validRootStack(), "    read_only: true\n", "    networks: [escape]\n    read_only: true\n", 1) + suffix
		if err := validateRootStack([]byte(body)); err == nil {
			t.Fatalf("host-network alias accepted:\n%s", body)
		}
	}
}

func TestRootStackPolicyRequiresDigestAndRuntimeLimits(t *testing.T) {
	for _, body := range []string{
		strings.Replace(validRootStack(), "@sha256:"+strings.Repeat("a", 64), ":latest", 1),
		strings.Replace(validRootStack(), "        limits: {cpus: \"1.0\", memory: 256M}\n", "        limits: {memory: 256M}\n", 1),
	} {
		if err := validateRootStack([]byte(body)); err == nil {
			t.Fatal("unsafe stack accepted")
		}
	}
}

// A bind mount refused on the service must not come back through the global
// definition of a volume that looks ordinary from the service's side.
func TestRootStackPolicyRejectsHostBackedVolumes(t *testing.T) {
	mounted := strings.Replace(validRootStack(), "    read_only: true\n", "    volumes: [\"data:/mnt/data\"]\n    read_only: true\n", 1)
	for _, suffix := range []string{
		"volumes:\n  data:\n    driver: local\n    driver_opts: {type: none, o: bind, device: /etc}\n",
		"volumes:\n  data:\n    driver_opts: {type: none, o: bind, device: /}\n",
		"volumes:\n  data: {driver: vieux/sshfs}\n",
		"volumes: [data]\n",
		"volumes:\n  data: bind\n",
	} {
		if err := validateRootStack([]byte(mounted + suffix)); err == nil {
			t.Fatalf("host-backed volume accepted:\n%s", suffix)
		}
	}
	for _, suffix := range []string{
		"volumes:\n  data:\n",
		"volumes:\n  data: {}\n",
		"volumes:\n  data: {name: demo_data}\n",
		"volumes:\n  data: {driver: local}\n",
		"volumes:\n  data: {external: true}\n",
	} {
		if err := validateRootStack([]byte(mounted + suffix)); err != nil {
			t.Fatalf("plain volume refused: %v\n%s", err, suffix)
		}
	}
}

func TestRootStackPolicyNamesTheFirstRefusedVolumeInOrder(t *testing.T) {
	body := validRootStack() + "volumes:\n  zeta: {driver_opts: {o: bind}}\n  alpha: {driver_opts: {o: bind}}\n"
	for range 20 {
		err := validateRootStack([]byte(body))
		if err == nil || !strings.Contains(err.Error(), "volume alpha") {
			t.Fatalf("refusal is not deterministic: %v", err)
		}
	}
}

// Root reads a `file` secret, an env_file or a `file` config on behalf of the
// stack, which hands a host file to a container without any typed operation.
func TestRootStackPolicyRejectsHostFileReads(t *testing.T) {
	bodies := []string{
		strings.Replace(validRootStack(), "    read_only: true\n", "    env_file: [/root/.env]\n    read_only: true\n", 1),
		validRootStack() + "secrets:\n  leak: {file: /etc/shadow}\n",
		validRootStack() + "secrets:\n  leak: {external: true, file: /etc/shadow}\n",
		validRootStack() + "secrets:\n  leak: {environment: HOME}\n",
		validRootStack() + "secrets:\n  leak: {external: true, driver: vault}\n",
		validRootStack() + "secrets:\n  leak: {external: false}\n",
		validRootStack() + "secrets:\n  leak:\n",
		validRootStack() + "secrets: [leak]\n",
		validRootStack() + "configs:\n  leak: {file: /etc/shadow}\n",
	}
	for _, body := range bodies {
		if err := validateRootStack([]byte(body)); err == nil {
			t.Fatalf("host file read accepted:\n%s", body)
		}
	}
	for _, suffix := range []string{
		"secrets:\n  app_token_v1: {external: true}\n",
		"secrets:\n  app_token_v1: {external: true, name: app_token_v1}\n",
		"secrets:\n  app_token_v1:\n    external: {name: app_token_v1}\n",
	} {
		if err := validateRootStack([]byte(validRootStack() + suffix)); err != nil {
			t.Fatalf("published secret refused: %v\n%s", err, suffix)
		}
	}
}

func assertRootGlobalSectionsAccept(t *testing.T, stack string) {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal([]byte(stack), &document); err != nil {
		t.Fatal(err)
	}
	if err := validateRootStackGlobalSections(document); err != nil {
		t.Fatalf("rendered stack is refused by the root helper: %v\n%s", err, stack)
	}
}

// A stack the host already retains left with the policy of its time: refusing it
// here would block the rollback or the recovery of an application that serves.
func TestRetainedRootStackKeepsItsPolicyWhileAnEnteringStackDoesNot(t *testing.T) {
	legacy := validRootStack() + "volumes:\n  data: {driver_opts: {type: nfs}}\n"
	if err := validateRetainedRootStack([]byte(legacy)); err != nil {
		t.Fatalf("retained stack refused: %v", err)
	}
	if err := validateRootStack([]byte(legacy)); err == nil {
		t.Fatal("entering stack accepted")
	}
	unsafe := strings.Replace(validRootStack(), "    read_only: true\n", "    privileged: true\n    read_only: true\n", 1)
	if err := validateRetainedRootStack([]byte(unsafe)); err == nil {
		t.Fatal("the checks of every release must still hold on a retained stack")
	}
}

func TestRootStackPolicyRejectsHostAttachedNetworkDrivers(t *testing.T) {
	for _, suffix := range []string{
		"networks:\n  lan: {driver: macvlan, driver_opts: {parent: eth0}}\n",
		"networks:\n  lan: {driver: vendor/plugin}\n",
		"networks: [lan]\n",
	} {
		if err := validateRootStack([]byte(validRootStack() + suffix)); err == nil {
			t.Fatalf("host-attached network accepted:\n%s", suffix)
		}
	}
	for _, suffix := range []string{
		"networks:\n  app: {driver: overlay}\n",
		"networks:\n  app: {driver: bridge}\n",
		"networks:\n  app:\n",
		"networks:\n  app: {external: true, name: app}\n",
		"configs: {}\n",
	} {
		if err := validateRootStack([]byte(validRootStack() + suffix)); err != nil {
			t.Fatalf("plain section refused: %v\n%s", err, suffix)
		}
	}
}

// The renderer drops env_file, so the client check must not refuse a compose
// file for it, while a global section reaches the helper unchanged.
func TestComposeFileGlobalSectionsAreRefusedBeforeTheBuild(t *testing.T) {
	var parsed map[string]any
	compose := "services:\n  web:\n    env_file: [.env]\nvolumes:\n  data: {driver_opts: {type: nfs}}\n"
	if err := yaml.Unmarshal([]byte(compose), &parsed); err != nil {
		t.Fatal(err)
	}
	if err := validateRootStackGlobalSections(parsed); err == nil || !strings.Contains(err.Error(), "volume data") {
		t.Fatalf("got %v", err)
	}
	delete(parsed, "volumes")
	if err := validateRootStackGlobalSections(parsed); err != nil {
		t.Fatalf("env_file must stay usable in a compose file: %v", err)
	}
}

func TestRootStackPolicyNamesTheFirstEnvFileServiceInOrder(t *testing.T) {
	service := strings.TrimPrefix(validRootStack(), "services:\n  web:\n")
	body := "services:\n  zeta:\n    env_file: [a]\n" + service + "  alpha:\n    env_file: [a]\n" + service
	for range 20 {
		err := validateRootStack([]byte(body))
		if err == nil || !strings.Contains(err.Error(), "service alpha") {
			t.Fatalf("refusal is not deterministic: %v", err)
		}
	}
}
