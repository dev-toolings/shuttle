package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backuplifecycle"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/readiness"
	"gopkg.in/yaml.v3"
)

const backupLifecycleSchema = "shuttle.application-backup-status/v2"

type serviceReplica struct {
	Name     string
	Replicas string
	Image    string
}

const sharedCaddyService = "shuttle-edge_caddy"

const (
	rootApplicationState = "/var/lib/shuttle/apps"
	maxCurrentStackBytes = 1 << 20
)

type stackService struct {
	Image       string             `yaml:"image"`
	Deploy      stackServiceDeploy `yaml:"deploy"`
	Healthcheck map[string]any     `yaml:"healthcheck"`
}

type stackServiceDeploy struct {
	Replicas *int `yaml:"replicas"`
}

type stackInventory struct {
	Services map[string]stackService `yaml:"services"`
}

func (e Engine) expectedStack() (stackInventory, error) {
	var inventory stackInventory
	path := filepath.Join(rootApplicationState, e.App, "current.yml")
	body, err := e.Adapters.Read(path)
	if err != nil {
		return inventory, fmt.Errorf("read expected application inventory: %w", err)
	}
	if len(body) == 0 || len(body) > maxCurrentStackBytes {
		return inventory, fmt.Errorf("expected application inventory is empty or exceeds %d bytes", maxCurrentStackBytes)
	}
	if err := yaml.Unmarshal(body, &inventory); err != nil {
		return inventory, fmt.Errorf("parse expected application inventory: %w", err)
	}
	if len(inventory.Services) == 0 {
		return inventory, fmt.Errorf("expected application inventory contains no services")
	}
	for name, service := range inventory.Services {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(service.Image) == "" {
			return inventory, fmt.Errorf("expected application inventory has an incomplete service")
		}
	}
	return inventory, nil
}

func expectedReplicas(service stackService) (int, bool) {
	if service.Deploy.Replicas == nil {
		return 1, false
	}
	return *service.Deploy.Replicas, true
}

func parseReplicaValue(value string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return 0, 0, fmt.Errorf("replica value must be current/desired")
	}
	current, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || current < 0 {
		return 0, 0, fmt.Errorf("invalid current replica count")
	}
	desired, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || desired < 0 {
		return 0, 0, fmt.Errorf("invalid desired replica count")
	}
	return current, desired, nil
}

func parseServiceRoster(body string) (map[string]serviceReplica, error) {
	services := map[string]serviceReplica{}
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, fmt.Errorf("service roster is empty")
	}
	for _, line := range strings.Split(trimmed, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 && len(fields) != 3 {
			return nil, fmt.Errorf("service roster row is malformed")
		}
		name := strings.TrimSpace(fields[0])
		replicas := strings.TrimSpace(fields[1])
		if name == "" {
			return nil, fmt.Errorf("service roster has an empty service name")
		}
		if _, _, err := parseReplicaValue(replicas); err != nil {
			return nil, err
		}
		if _, exists := services[name]; exists {
			return nil, fmt.Errorf("service roster contains duplicate service %q", name)
		}
		image := ""
		if len(fields) == 3 {
			image = strings.TrimSpace(fields[2])
		}
		services[name] = serviceReplica{Name: name, Replicas: replicas, Image: image}
	}
	return services, nil
}

func lookupService(roster map[string]serviceReplica, app, expected string) (serviceReplica, bool) {
	if service, ok := roster[expected]; ok {
		return service, true
	}
	service, ok := roster[app+"_"+expected]
	return service, ok
}

func parseTaskEvidence(body string) (running, unhealthy int, err error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return 0, 0, fmt.Errorf("task evidence is empty")
	}
	for _, line := range strings.Split(trimmed, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || len(fields) > 3 {
			return 0, 0, fmt.Errorf("task evidence row is malformed")
		}
		current := strings.ToLower(strings.TrimSpace(fields[0]))
		desired := strings.ToLower(strings.TrimSpace(fields[1]))
		taskError := ""
		if len(fields) == 3 {
			taskError = strings.TrimSpace(fields[2])
		}
		if strings.HasPrefix(current, "running") && desired == "running" && taskError == "" {
			running++
		} else {
			unhealthy++
		}
	}
	return running, unhealthy, nil
}

type observedServiceTask struct {
	ID      string
	Current string
	Desired string
	Error   string
}

func parseDesiredRunningTasks(body string) ([]observedServiceTask, error) {
	// docker service ps --format '{{.ID}}\t{{.CurrentState}}\t{{.DesiredState}}\t{{.Error}}'
	// emits a trailing empty Error column. TrimSpace on the whole body would
	// drop that final tab and turn a healthy running row into three fields.
	normalized := strings.ReplaceAll(body, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	if strings.Trim(normalized, "\n") == "" {
		return nil, fmt.Errorf("task evidence is empty")
	}
	tasks := make([]observedServiceTask, 0)
	seen := map[string]bool{}
	for _, line := range strings.Split(normalized, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, fmt.Errorf("task evidence row is malformed")
		}
		id := strings.TrimSpace(fields[0])
		if !containerIDPattern.MatchString(id) || seen[id] {
			return nil, fmt.Errorf("task evidence contains an invalid or duplicate id")
		}
		seen[id] = true
		tasks = append(tasks, observedServiceTask{
			ID:      id,
			Current: strings.ToLower(strings.TrimSpace(fields[1])),
			Desired: strings.ToLower(strings.TrimSpace(fields[2])),
			Error:   strings.TrimSpace(fields[3]),
		})
	}
	if len(tasks) == 0 {
		return nil, fmt.Errorf("task evidence is empty")
	}
	return tasks, nil
}

func taskRunningHealthy(task observedServiceTask) bool {
	return strings.HasPrefix(task.Current, "running") && task.Desired == "running" && task.Error == ""
}

// taskConverging is a task Swarm is still bringing up (a rolling update or a
// restart) with no error yet. It is not a failure: Swarm itself fails the
// task, or the update, if it never reaches running. Counting it as unhealthy
// paged the operator for every start-first rollout on 2026-10-28.
func taskConverging(task observedServiceTask) bool {
	if task.Desired != "running" || task.Error != "" {
		return false
	}
	for _, state := range []string{"new", "pending", "assigned", "accepted", "preparing", "ready", "starting"} {
		if strings.HasPrefix(task.Current, state) {
			return true
		}
	}
	return false
}

func parseExecutedImage(body string) (string, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed == "null" {
		return "", fmt.Errorf("executed image identity is missing")
	}
	var image string
	if json.Unmarshal([]byte(trimmed), &image) == nil {
		image = strings.TrimSpace(image)
		if image == "" {
			return "", fmt.Errorf("executed image identity is missing")
		}
		return image, nil
	}
	var inspect struct {
		Spec struct {
			ContainerSpec struct {
				Image string `json:"Image"`
			} `json:"ContainerSpec"`
		} `json:"Spec"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
		Image string `json:"Image"`
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	if decoder.Decode(&inspect) != nil {
		return "", fmt.Errorf("executed image evidence was malformed")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", fmt.Errorf("executed image evidence contains more than one JSON value")
	}
	for _, candidate := range []string{inspect.Spec.ContainerSpec.Image, inspect.Config.Image} {
		if value := strings.TrimSpace(candidate); value != "" {
			return value, nil
		}
	}
	return "", fmt.Errorf("executed image identity is missing")
}

func imageRepoDigest(image string) string {
	_, digest, ok := strings.Cut(strings.TrimSpace(image), "@")
	digest = strings.TrimSpace(digest)
	if !ok || !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return ""
	}
	hex := digest[len("sha256:"):]
	for _, r := range hex {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return digest
}

func executedImageMatchesExpected(expected, actual string) (matched bool, identity bool) {
	expectedDigest := imageRepoDigest(expected)
	actualDigest := imageRepoDigest(actual)
	if expectedDigest == "" || actualDigest == "" {
		return false, false
	}
	return expectedDigest == actualDigest, true
}

var containerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$`)

func parseContainerIDs(body string) ([]string, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, fmt.Errorf("container inventory is empty")
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, line := range strings.Split(trimmed, "\n") {
		id := strings.TrimSpace(line)
		if !containerIDPattern.MatchString(id) || seen[id] {
			return nil, fmt.Errorf("container inventory contains an invalid or duplicate id")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

func parseContainerHealth(body string) (string, error) {
	var health struct {
		Status string `json:"Status"`
	}
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(body)))
	if err := decoder.Decode(&health); err != nil {
		return "", err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", fmt.Errorf("container health contains more than one JSON value")
	}
	if strings.TrimSpace(body) == "null" || strings.TrimSpace(health.Status) == "" {
		return "", fmt.Errorf("container health is unavailable")
	}
	return strings.ToLower(strings.TrimSpace(health.Status)), nil
}

func (e Engine) inspectContainerHealth(ctx context.Context, serviceName string, required bool, expectedTasks int) (string, string, map[string]any) {
	if !required {
		return StateHealthy, "No container healthcheck is declared for this service", nil
	}
	output, err := e.Adapters.Run(ctx, "docker", "ps", "--filter", "label=com.docker.swarm.service.name="+serviceName, "--format", "{{.ID}}")
	if err != nil {
		return StateUnavailable, commandFailureSummary("Container health inventory could not be inspected", err), withCommandError(nil, err)
	}
	ids, err := parseContainerIDs(string(output))
	if err != nil {
		return StateUnavailable, "Container health inventory was malformed", nil
	}
	if len(ids) < expectedTasks {
		return StateUnavailable, "Fewer healthy container records were observable than running tasks", map[string]any{"containers": len(ids), "running_tasks": expectedTasks}
	}
	statuses := map[string]int{}
	for _, id := range ids {
		body, inspectErr := e.Adapters.Run(ctx, "docker", "inspect", id, "--format", "{{json .State.Health}}")
		if inspectErr != nil {
			return StateUnavailable, commandFailureSummary("Container health could not be inspected", inspectErr), withCommandError(map[string]any{"container": id}, inspectErr)
		}
		status, parseErr := parseContainerHealth(string(body))
		if parseErr != nil {
			return StateUnavailable, "Container health evidence was malformed or absent", map[string]any{"container": id}
		}
		statuses[status]++
		// "starting" is Docker's healthcheck start period: the container has
		// not failed, and Docker turns it into "unhealthy" itself if the check
		// never passes. Only a reported failure is a degradation.
		if status != "healthy" && status != "starting" {
			return StateDegraded, "At least one running container reports an unhealthy healthcheck", map[string]any{"container": id, "health": status, "health_counts": statuses}
		}
	}
	return StateHealthy, "Running containers report healthy healthchecks", map[string]any{"containers": len(ids), "health_counts": statuses}
}

func (e Engine) inspectService(ctx context.Context, serviceName string, expected stackService) (string, string, map[string]any) {
	body, err := e.Adapters.Run(ctx, "docker", "service", "inspect", serviceName, "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}\t{{if .Spec.Mode.Replicated}}{{.Spec.Mode.Replicated.Replicas}}{{end}}")
	if err != nil {
		return StateUnavailable, commandFailureSummary("Service specification could not be inspected", err), withCommandError(map[string]any{"service": serviceName}, err)
	}
	fields := strings.Split(strings.TrimSpace(string(body)), "\t")
	if len(fields) != 2 || strings.TrimSpace(fields[0]) == "" {
		return StateUnavailable, "Service specification evidence was malformed", map[string]any{"service": serviceName}
	}
	image := strings.TrimSpace(fields[0])
	expectedReplicas, explicitZero := expectedReplicas(expected)
	if image != strings.TrimSpace(expected.Image) {
		return StateDegraded, "Running service image differs from the retained expected image", map[string]any{"service": serviceName, "expected_image": expected.Image, "actual_image": image}
	}
	if strings.TrimSpace(fields[1]) != "" {
		actualReplicas, parseErr := strconv.Atoi(strings.TrimSpace(fields[1]))
		if parseErr != nil || actualReplicas < 0 || actualReplicas != expectedReplicas {
			return StateDegraded, "Running service desired replicas differ from the retained expected replicas", map[string]any{"service": serviceName, "expected_replicas": expectedReplicas, "actual_replicas": strings.TrimSpace(fields[1])}
		}
	} else if explicitZero || expectedReplicas != 1 {
		return StateUnavailable, "Service desired replica evidence was absent", map[string]any{"service": serviceName}
	}
	return "", "", nil
}

func (e Engine) serviceHealth(ctx context.Context, serviceName string, expected stackService) (string, string, map[string]any) {
	output, runErr := e.Adapters.Run(ctx, "docker", "service", "ps", serviceName, "--filter", "desired-state=running", "--format", "{{.ID}}\t{{.CurrentState}}\t{{.DesiredState}}\t{{.Error}}")
	if runErr != nil {
		return StateUnavailable, commandFailureSummary("Service task health could not be inspected", runErr), withCommandError(map[string]any{"service": serviceName}, runErr)
	}
	tasks, parseErr := parseDesiredRunningTasks(string(output))
	if parseErr != nil {
		return StateUnavailable, "Service task health evidence was malformed", map[string]any{"service": serviceName}
	}
	running, unhealthy, converging := 0, 0, 0
	runningIDs := make([]string, 0, len(tasks))
	for _, task := range tasks {
		if taskRunningHealthy(task) {
			running++
			runningIDs = append(runningIDs, task.ID)
			continue
		}
		if taskConverging(task) {
			converging++
			continue
		}
		unhealthy++
	}
	_, explicitZero := expectedReplicas(expected)
	expectedCount, _ := expectedReplicas(expected)
	if expectedCount == 0 && explicitZero {
		return StateHealthy, "The service is explicitly configured with zero replicas", map[string]any{"service": serviceName, "running_tasks": running, "expected_replicas": 0}
	}
	if running != expectedCount || unhealthy > 0 {
		summary := "Service task health does not match the retained expected replicas"
		if unhealthy == 0 && converging > 0 && running < expectedCount {
			summary = "Service tasks are still starting"
		}
		return StateDegraded, summary, map[string]any{"service": serviceName, "running_tasks": running, "unhealthy_tasks": unhealthy, "starting_tasks": converging, "expected_replicas": expectedCount}
	}
	if image := strings.TrimSpace(expected.Image); image != "" {
		oldImage, missingIdentity := 0, 0
		actualImages := map[string]int{}
		for _, id := range runningIDs {
			body, inspectErr := e.Adapters.Run(ctx, "docker", "inspect", id, "--format", "{{json .Spec.ContainerSpec.Image}}")
			if inspectErr != nil {
				return StateUnavailable, commandFailureSummary("Running task image identity could not be inspected", inspectErr), withCommandError(map[string]any{"service": serviceName, "task": id}, inspectErr)
			}
			actual, parseImageErr := parseExecutedImage(string(body))
			if parseImageErr != nil {
				missingIdentity++
				return StateUnavailable, "Running task image identity was malformed or absent", map[string]any{"service": serviceName, "task": id}
			}
			actualImages[actual]++
			matched, identity := executedImageMatchesExpected(image, actual)
			if !identity {
				missingIdentity++
				return StateUnavailable, "Running task image is missing a full digest identity", map[string]any{"service": serviceName, "task": id, "actual_image": actual, "expected_image": image}
			}
			if !matched {
				oldImage++
				return StateDegraded, "A running task still executes an image other than the retained manifest", map[string]any{"service": serviceName, "task": id, "actual_image": actual, "expected_image": image, "old_image_tasks": oldImage}
			}
		}
		if oldImage > 0 || missingIdentity > 0 {
			return StateDegraded, "Running tasks do not all execute the retained manifest image", map[string]any{"service": serviceName, "old_image_tasks": oldImage, "missing_identity_tasks": missingIdentity, "actual_images": actualImages}
		}
	}
	return e.inspectContainerHealth(ctx, serviceName, len(expected.Healthcheck) > 0, running)
}

func (e Engine) composeUnmanaged() bool {
	return e.DeployStrategy == config.StrategyCompose
}

func (e Engine) application(ctx context.Context) (string, string, map[string]any) {
	if e.App == "" {
		return StateNotApplicable, "No application was configured", nil
	}
	if e.composeUnmanaged() {
		return StateNotApplicable, "Compose applications are unmanaged by Swarm monitoring", map[string]any{"reason": "unmanaged", "deploy_strategy": config.StrategyCompose}
	}
	expected, err := e.expectedStack()
	if err != nil {
		return StateUnavailable, "Expected application inventory could not be inspected", map[string]any{"error": err.Error()}
	}
	output, err := e.Adapters.Run(ctx, "docker", "stack", "services", e.App, "--format", "{{.Name}}\t{{.Replicas}}")
	if err != nil {
		return StateUnavailable, commandFailureSummary("Application services could not be inspected", err), withCommandError(nil, err)
	}
	roster, err := parseServiceRoster(string(output))
	if err != nil {
		return StateUnavailable, "Application service inventory was malformed", nil
	}
	serviceNames := make([]string, 0, len(expected.Services))
	for name := range expected.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)
	for _, name := range serviceNames {
		service, ok := lookupService(roster, e.App, name)
		if !ok {
			return StateUnavailable, "An expected application service is missing from the running inventory", map[string]any{"service": name}
		}
		current, desired, parseErr := parseReplicaValue(service.Replicas)
		expectedCount, explicit := expectedReplicas(expected.Services[name])
		if parseErr != nil || desired != expectedCount || current != desired || (desired == 0 && !explicit) {
			return StateDegraded, "Application service replicas do not match retained expected inventory", map[string]any{"service": name, "replicas": service.Replicas, "expected_replicas": expectedCount}
		}
		if desired == 0 && explicit {
			continue
		}
		state, summary, evidence := e.inspectService(ctx, service.Name, expected.Services[name])
		if state != "" {
			return state, summary, evidence
		}
		state, summary, evidence = e.serviceHealth(ctx, service.Name, expected.Services[name])
		if state != StateHealthy {
			return state, summary, evidence
		}
	}
	return StateHealthy, "All retained application services match running tasks, images and healthchecks", map[string]any{"expected_services": len(expected.Services), "observed_services": len(roster)}
}

// These small parsing helpers remain available to package-local diagnostics.
// The collectors above use the strict variants because a malformed row must be
// unavailable rather than silently omitted.
func parseReplicas(body string) []serviceReplica {
	services := []serviceReplica{}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(fields) != 2 || fields[0] == "" {
			continue
		}
		services = append(services, serviceReplica{Name: fields[0], Replicas: fields[1]})
	}
	return services
}

func atoi(value string) int {
	var result int
	_, _ = fmt.Sscanf(value, "%d", &result)
	return result
}

func runningTaskCounts(body string) (running, unhealthy int) {
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 2 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(fields[0])), "running") && strings.EqualFold(strings.TrimSpace(fields[1]), "running") {
			running++
		} else if strings.TrimSpace(fields[0]) != "" {
			unhealthy++
		}
	}
	return running, unhealthy
}

func (e Engine) docker(ctx context.Context) (string, string, map[string]any) {
	if _, err := e.Adapters.Run(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		return StateUnavailable, commandFailureSummary("Docker daemon is unavailable", err), withCommandError(nil, err)
	}
	return StateHealthy, "Docker daemon answered a read-only info request", nil
}

func (e Engine) caddy(ctx context.Context) (string, string, map[string]any) {
	body, err := e.Adapters.Run(ctx, "docker", "service", "inspect", sharedCaddyService, "--format", "{{json .Spec.TaskTemplate.RestartPolicy}}")
	if err != nil {
		return StateUnavailable, commandFailureSummary("Caddy service could not be inspected", err), withCommandError(nil, err)
	}
	var policy struct {
		Condition string `json:"Condition"`
	}
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(string(body))))
	if err := decoder.Decode(&policy); err != nil {
		return StateUnavailable, "Caddy restart policy evidence was invalid", nil
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || strings.TrimSpace(policy.Condition) == "" {
		return StateUnavailable, "Caddy restart policy evidence was invalid", nil
	}
	if strings.ToLower(policy.Condition) != "any" {
		return StateDegraded, "Caddy does not have restart any configured", map[string]any{"restart_condition": policy.Condition}
	}
	replicas, err := e.Adapters.Run(ctx, "docker", "service", "ls", "--filter", "name="+sharedCaddyService, "--format", "{{.Name}}\t{{.Replicas}}")
	if err != nil {
		return StateUnavailable, commandFailureSummary("Caddy service inventory could not be inspected", err), withCommandError(nil, err)
	}
	services, parseErr := parseServiceRoster(string(replicas))
	if parseErr != nil || len(services) != 1 {
		return StateUnavailable, "Caddy service inventory was malformed or missing", map[string]any{"service": sharedCaddyService}
	}
	service, ok := services[sharedCaddyService]
	if !ok {
		return StateUnavailable, "The shared Caddy service is missing from the running inventory", map[string]any{"service": sharedCaddyService}
	}
	current, desired, replicaErr := parseReplicaValue(service.Replicas)
	if replicaErr != nil || desired == 0 {
		return StateDegraded, "Caddy does not report a configured service", map[string]any{"restart_condition": policy.Condition}
	}
	if current != desired {
		return StateDegraded, "Caddy replicas are not converged", map[string]any{"restart_condition": policy.Condition, "replicas": service.Replicas}
	}
	state, summary, evidence := e.serviceHealth(ctx, sharedCaddyService, stackService{Deploy: stackServiceDeploy{Replicas: &desired}, Healthcheck: map[string]any{"required": true}})
	if state != StateHealthy {
		return state, summary, evidence
	}
	return StateHealthy, "Shared Caddy service is converged with restart any", map[string]any{"restart_condition": policy.Condition, "service": sharedCaddyService, "replicas": service.Replicas}
}

func (e Engine) registry(ctx context.Context) (string, string, map[string]any) {
	body, err := e.Adapters.Run(ctx, "docker", "inspect", "shuttle-registry", "--format", "{{json .State}}")
	if err != nil {
		return StateUnavailable, commandFailureSummary("The loopback registry could not be inspected", err), withCommandError(nil, err)
	}
	var state struct {
		Running bool `json:"Running"`
		Health  *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	}
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(string(body))))
	if err := decoder.Decode(&state); err != nil {
		return StateUnavailable, "Registry state evidence was invalid", nil
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return StateUnavailable, "Registry state evidence was invalid", nil
	}
	if !state.Running || state.Health == nil || strings.ToLower(state.Health.Status) != "healthy" {
		return StateDegraded, "The loopback registry is not healthy", map[string]any{"running": state.Running}
	}
	bindingBody, bindingErr := e.Adapters.Run(ctx, "docker", "inspect", "shuttle-registry", "--format", "{{json .HostConfig}}")
	var hostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	}
	if bindingErr != nil {
		return StateUnavailable, commandFailureSummary("Registry Docker binding could not be inspected", bindingErr), withCommandError(nil, bindingErr)
	}
	var rawHostConfig map[string]json.RawMessage
	hostDecoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(string(bindingBody))))
	if hostDecoder.Decode(&rawHostConfig) != nil || hostDecoder.Decode(&extra) != io.EOF || rawHostConfig == nil {
		return StateUnavailable, "Registry Docker binding evidence was invalid", nil
	}
	if _, ok := rawHostConfig["RestartPolicy"]; !ok {
		return StateUnavailable, "Registry Docker binding evidence omitted restart policy", nil
	}
	if _, ok := rawHostConfig["PortBindings"]; !ok {
		return StateUnavailable, "Registry Docker binding evidence omitted port bindings", nil
	}
	if json.Unmarshal([]byte(strings.TrimSpace(string(bindingBody))), &hostConfig) != nil {
		return StateUnavailable, "Registry Docker binding evidence was invalid", nil
	}
	if hostConfig.RestartPolicy.Name != "always" || !registryBindingsExact(hostConfig.PortBindings) {
		return StateDegraded, "The registry is not bound only to the loopback address", nil
	}
	listeners, listenerErr := e.Adapters.Run(ctx, "ss", "-lntH")
	if listenerErr != nil {
		return StateUnavailable, commandFailureSummary("Host listener evidence for the registry was unavailable or malformed", listenerErr), withCommandError(nil, listenerErr)
	}
	if !readiness.MonitoringValidListenerEvidence(string(listeners)) {
		return StateUnavailable, "Host listener evidence for the registry was unavailable or malformed", nil
	}
	if !registryListenerExact(string(listeners)) {
		return StateDegraded, "The registry has an unexpected host listener on port 5000", nil
	}
	return StateHealthy, "The registry is running, restartable and bound only to 127.0.0.1:5000", map[string]any{"loopback_port": 5000, "restart": hostConfig.RestartPolicy.Name}
}

func registryBindingsExact(bindings map[string][]struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}) bool {
	if len(bindings) != 1 {
		return false
	}
	wanted := bindings["5000/tcp"]
	if len(wanted) != 1 || wanted[0].HostIP != "127.0.0.1" || wanted[0].HostPort != "5000" {
		return false
	}
	for key, values := range bindings {
		for _, value := range values {
			if key != "5000/tcp" || value.HostIP != "127.0.0.1" || value.HostPort != "5000" {
				return false
			}
		}
	}
	return true
}

func registryListenerExact(body string) bool {
	seen := false
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		endpoint := readiness.MonitoringLocalListenerEndpoint(line)
		if endpoint == "" || !strings.HasSuffix(endpoint, ":5000") {
			continue
		}
		seen = true
		host := strings.TrimSuffix(endpoint, ":5000")
		host = strings.Trim(host, "[]")
		if host != "127.0.0.1" {
			return false
		}
	}
	return seen
}

func (e Engine) postgres(ctx context.Context) (string, string, map[string]any) {
	if e.PostgresVersion == 0 {
		return StateNotApplicable, "Native PostgreSQL is not configured for this application", nil
	}
	if _, err := e.Adapters.Run(ctx, "systemctl", "is-active", "postgresql"); err != nil {
		return StateUnavailable, commandFailureSummary("Native PostgreSQL systemd service is not active", err), withCommandError(nil, err)
	}
	cluster := e.PostgresCluster
	if cluster == "" {
		cluster = "main"
	}
	clusters, err := e.Adapters.Run(ctx, "pg_lsclusters", "--no-header")
	if err != nil {
		return StateUnavailable, commandFailureSummary("Native PostgreSQL cluster inventory could not be inspected", err), withCommandError(nil, err)
	}
	port, status, found := postgresClusterEvidence(string(clusters), e.PostgresVersion, cluster)
	if !found {
		return StateUnavailable, "The configured native PostgreSQL cluster was not found", map[string]any{"version": e.PostgresVersion, "cluster": cluster}
	}
	if status != "online" {
		return StateDegraded, "The configured native PostgreSQL cluster is not online", map[string]any{"version": e.PostgresVersion, "cluster": cluster, "status": status}
	}
	if _, err := e.Adapters.Run(ctx, "pg_isready", "-h", "/var/run/postgresql", "-p", fmt.Sprint(port)); err != nil {
		return StateUnavailable, commandFailureSummary("Native PostgreSQL did not accept a readiness probe", err), withCommandError(map[string]any{"version": e.PostgresVersion, "cluster": cluster, "port": port}, err)
	}
	return StateHealthy, "The configured native PostgreSQL cluster is active and ready", map[string]any{"transport": "native-unix-socket", "version": e.PostgresVersion, "cluster": cluster, "port": port}
}

func postgresClusterEvidence(body string, version int, cluster string) (port int, status string, found bool) {
	port, status, _, found = postgresClusterRow(body, version, cluster)
	return port, status, found
}

func postgresClusterRow(body string, version int, cluster string) (port int, status, dataDir string, found bool) {
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != strconv.Itoa(version) || fields[1] != cluster {
			continue
		}
		parsedPort, err := strconv.Atoi(fields[2])
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return 0, "", "", false
		}
		status := strings.ToLower(fields[3])
		if status == "" {
			return 0, "", "", false
		}
		dataDir := ""
		if len(fields) >= 6 && strings.HasPrefix(fields[5], "/") {
			dataDir = fields[5]
		}
		return parsedPort, status, dataDir, true
	}
	return 0, "", "", false
}

func (e Engine) optionalService(ctx context.Context, service string, expected bool) (string, string, map[string]any) {
	if e.composeUnmanaged() {
		return StateNotApplicable, service + " is unmanaged on Compose hosts", map[string]any{"reason": "unmanaged", "deploy_strategy": config.StrategyCompose}
	}
	inventory, err := e.expectedStack()
	if err != nil {
		return StateUnavailable, "Expected application inventory could not be inspected", map[string]any{"error": err.Error()}
	}
	expectedService, configuredInInventory := inventory.Services[service]
	if !configuredInInventory {
		if !expected {
			return StateNotApplicable, service + " is not configured", nil
		}
		return StateUnavailable, service + " is configured but missing from the retained expected inventory", nil
	}
	rosterOutput, rosterErr := e.Adapters.Run(ctx, "docker", "stack", "services", e.App, "--format", "{{.Name}}\t{{.Replicas}}")
	if rosterErr != nil {
		return StateUnavailable, commandFailureSummary("Configured service inventory could not be inspected", rosterErr), withCommandError(nil, rosterErr)
	}
	roster, rosterParseErr := parseServiceRoster(string(rosterOutput))
	if rosterParseErr != nil {
		return StateUnavailable, "Configured service inventory was malformed", nil
	}
	actual, found := lookupService(roster, e.App, service)
	if !found {
		return StateUnavailable, service + " is configured but missing from the running inventory", nil
	}
	current, desired, replicaErr := parseReplicaValue(actual.Replicas)
	expectedReplicasValue, explicit := expectedReplicas(expectedService)
	if replicaErr != nil || desired != expectedReplicasValue || current != desired || (desired == 0 && !explicit) {
		return StateDegraded, service + " replicas do not match its retained expected inventory", map[string]any{"replicas": actual.Replicas, "expected_replicas": expectedReplicasValue}
	}
	if desired == 0 && explicit {
		return StateHealthy, service + " is explicitly configured with zero replicas", map[string]any{"replicas": actual.Replicas}
	}
	state, summary, evidence := e.inspectService(ctx, actual.Name, expectedService)
	if state != "" {
		return state, summary, evidence
	}
	return e.serviceHealth(ctx, actual.Name, expectedService)
}

func (e Engine) diskChecks(ctx context.Context) []Result {
	data := e.Config.Disk.Data
	images := e.Config.Disk.ImagesRegistry
	cache := e.Config.Disk.Cache
	backups := e.Config.Disk.Backups
	now := e.Adapters.Now().UTC()
	checks := []Result{
		e.runCheck(ctx, "disk.data", "Disk data", "data", func(ctx context.Context) (string, string, map[string]any) {
			return e.inspectDisk(ctx, configDiskTarget{path: data.Path, free: data.MinFreePercent, inodes: data.MinFreeInodesPercent}, nil)
		}),
	}
	if e.PostgresVersion != 0 {
		checks = append(checks, e.runCheck(ctx, "disk.data.postgresql", "Disk data", "data", func(ctx context.Context) (string, string, map[string]any) {
			pgPath, observed, reason, commandErr := e.observedPostgresDataDir(ctx)
			if ctx.Err() != nil {
				return StateUnavailable, "Disk check timed out", nil
			}
			if !observed || pgPath == "" {
				return StateUnavailable, commandFailureSummary("Disk filesystem path is unknown", commandErr), withCommandError(map[string]any{"path": pgPath, "source": "pg_lsclusters", "reason": reason}, commandErr)
			}
			return e.inspectDisk(ctx, configDiskTarget{path: pgPath, free: data.MinFreePercent, inodes: data.MinFreeInodesPercent}, map[string]any{"source": "pg_lsclusters"})
		}))
	}
	checks = append(checks, e.runCheck(ctx, "disk.images_registry", "Disk images_registry", "images_registry", func(ctx context.Context) (string, string, map[string]any) {
		imagePath := images.Path
		evidence := map[string]any{}
		if !explicitDiskPath(images.Path, config.DefaultMonitoringImagesPath) {
			root, rootErr := e.observedDockerRootDir(ctx)
			if ctx.Err() != nil {
				return StateUnavailable, "Disk check timed out", nil
			}
			if rootErr != nil || root == "" {
				return StateUnavailable, commandFailureSummary("Disk filesystem path is unknown", rootErr), withCommandError(map[string]any{"reason": "docker_root_dir_unobserved"}, rootErr)
			}
			imagePath = root
			evidence["source"] = "docker_info_root_dir"
		}
		return e.inspectDisk(ctx, configDiskTarget{path: imagePath, free: images.MinFreePercent, inodes: images.MinFreeInodesPercent}, evidence)
	}))
	if !explicitDiskPath(images.Path, config.DefaultMonitoringImagesPath) {
		checks = append(checks, e.runCheck(ctx, "disk.images_registry.volume", "Disk images_registry", "images_registry", func(ctx context.Context) (string, string, map[string]any) {
			registryPath, ok, reason, commandErr := e.observedRegistryDataPath(ctx)
			if ctx.Err() != nil {
				return StateUnavailable, "Disk check timed out", nil
			}
			if !ok || registryPath == "" {
				return StateUnavailable, commandFailureSummary("Registry storage filesystem could not be inspected", commandErr), withCommandError(map[string]any{"reason": reason, "source": "registry_mount"}, commandErr)
			}
			return e.inspectDisk(ctx, configDiskTarget{path: registryPath, free: images.MinFreePercent, inodes: images.MinFreeInodesPercent}, map[string]any{"source": "registry_mount"})
		}))
	}
	if !config.DiskCachePathInVPSScope(cache.Path) {
		checks = append(checks, e.result(now, "disk.cache", "Disk cache", "cache", StateNotApplicable, "BuildKit laptop and remote cache are outside VPS monitoring scope", "VPS monitoring does not treat host /var/cache as BuildKit cache", map[string]any{
			"scope":    "vps",
			"observed": "not_observed",
			"reason":   "buildkit_remote_cache_not_in_vps_scope",
			"path":     cache.Path,
		}))
	} else {
		checks = append(checks, e.runCheck(ctx, "disk.cache", "Disk cache", "cache", func(ctx context.Context) (string, string, map[string]any) {
			return e.inspectDisk(ctx, configDiskTarget{path: cache.Path, free: cache.MinFreePercent, inodes: cache.MinFreeInodesPercent}, nil)
		}))
	}
	if !e.Config.Backup.Expected {
		checks = append(checks, e.result(now, "disk.backups", "Disk backups", "backups", StateNotApplicable, "Backup disk monitoring is not expected", "Enable monitoring.backup.expected to monitor the backup filesystem", nil))
	} else {
		checks = append(checks, e.runCheck(ctx, "disk.backups", "Disk backups", "backups", func(ctx context.Context) (string, string, map[string]any) {
			return e.inspectDisk(ctx, configDiskTarget{path: backups.Path, free: backups.MinFreePercent, inodes: backups.MinFreeInodesPercent}, nil)
		}))
	}
	return checks
}

func (e Engine) inspectDisk(ctx context.Context, target configDiskTarget, extra map[string]any) (string, string, map[string]any) {
	if ctx.Err() != nil {
		return StateUnavailable, "Disk check timed out", extra
	}
	if strings.TrimSpace(target.path) == "" || !strings.HasPrefix(target.path, "/") {
		evidence := map[string]any{}
		for key, value := range extra {
			evidence[key] = value
		}
		return StateUnavailable, "Disk filesystem path is unknown", evidence
	}
	stats, err := e.Adapters.Statfs(target.path)
	if err != nil || stats.Blocks == 0 || stats.Files == 0 {
		return StateUnavailable, "Disk filesystem could not be inspected", map[string]any{"path": target.path}
	}
	free := stats.Bavail * 100 / stats.Blocks
	inodes := stats.Ffree * 100 / stats.Files
	evidence := map[string]any{"path": target.path, "free_percent": free, "free_inodes_percent": inodes, "min_free_percent": target.free, "min_free_inodes_percent": target.inodes}
	for key, value := range extra {
		if _, exists := evidence[key]; !exists {
			evidence[key] = value
		}
	}
	if int(free) < target.free || int(inodes) < target.inodes {
		return StateDegraded, "Disk or inode free space is below its configured threshold", evidence
	}
	return StateHealthy, "Disk and inode free space are above their configured thresholds", evidence
}

func explicitDiskPath(path, defaultPath string) bool {
	return strings.TrimSpace(path) != "" && filepath.Clean(path) != filepath.Clean(defaultPath)
}

// The command error is returned apart from the reason so the incident carries
// the real cause (DEV-DEPL-59 review), not only "pg_lsclusters_unobserved".
func (e Engine) observedPostgresDataDir(ctx context.Context) (string, bool, string, error) {
	cluster := e.PostgresCluster
	if cluster == "" {
		cluster = "main"
	}
	body, err := e.Adapters.Run(ctx, "pg_lsclusters", "--no-header")
	if err != nil {
		return "", false, "pg_lsclusters_unobserved", err
	}
	_, _, dataDir, found := postgresClusterRow(string(body), e.PostgresVersion, cluster)
	if !found {
		return "", false, "cluster_row_missing", nil
	}
	if dataDir == "" || !strings.HasPrefix(dataDir, "/") {
		return "", false, "data_directory_missing", nil
	}
	return dataDir, true, "", nil
}

func (e Engine) observedDockerRootDir(ctx context.Context) (string, error) {
	body, err := e.Adapters.Run(ctx, "docker", "info", "--format", "{{.DockerRootDir}}")
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(body))
	if root == "" || !strings.HasPrefix(root, "/") {
		return "", fmt.Errorf("docker root directory is unknown")
	}
	return root, nil
}

func (e Engine) observedRegistryDataPath(ctx context.Context) (string, bool, string, error) {
	body, err := e.Adapters.Run(ctx, "docker", "inspect", "shuttle-registry", "--format", "{{json .Mounts}}")
	if err != nil {
		return "", false, "registry_mounts_unobserved", err
	}
	var mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(string(body))), &mounts) != nil {
		return "", false, "registry_mounts_invalid", nil
	}
	match := ""
	found := false
	for _, mount := range mounts {
		if mount.Destination != "/var/lib/registry" {
			continue
		}
		if mount.Type != "bind" && mount.Type != "volume" {
			continue
		}
		if strings.TrimSpace(mount.Source) == "" || !strings.HasPrefix(mount.Source, "/") {
			continue
		}
		if found {
			return "", false, "registry_mount_ambiguous", nil
		}
		match = mount.Source
		found = true
	}
	if !found {
		return "", false, "registry_data_destination_missing", nil
	}
	return match, true, "", nil
}

type configDiskTarget struct {
	path   string
	free   int
	inodes int
}

type backupStatus struct {
	Schema        string `json:"schema"`
	App           string `json:"app"`
	AttemptID     string `json:"attempt_id"`
	State         string `json:"state"`
	CreatedAt     string `json:"created_at"`
	Phase         string `json:"phase"`
	Host          string `json:"host"`
	HostKey       string `json:"host_key"`
	ArchiveSHA256 string `json:"archive_sha256"`
	SourceCapture string `json:"source_capture"`
	Encryption    string `json:"encryption"`
	Receipt       string `json:"receipt"`
	Cloud         string `json:"cloud"`
}

func (e Engine) backup(ctx context.Context) (string, string, map[string]any) {
	if !e.Config.Backup.Expected {
		return StateNotApplicable, "Backups are not configured as expected", nil
	}
	if ctx.Err() != nil {
		return StateUnavailable, "Backup check timed out", nil
	}
	statusPath := backuplifecycle.DefaultStatusPath(e.App)
	body, err := e.Adapters.Read(statusPath)
	if err != nil {
		return StateDegraded, "No authenticated VPS backup lifecycle status is available", map[string]any{"status_path": statusPath, "outcome": "missing"}
	}
	journal, err := backuplifecycle.DecodeJournal(body)
	if err != nil || journal.App != e.App {
		return StateDegraded, "The VPS backup lifecycle journal is malformed or bound to another application", map[string]any{"status_path": statusPath, "outcome": "invalid"}
	}
	if journal.LastSuccess == nil {
		if journal.LatestAttempt != nil && journal.LatestAttempt.State == backuplifecycle.StateFailed {
			return StateDegraded, "The latest backup attempt failed and no successful local receipt is retained", backupJournalEvidence(statusPath, journal)
		}
		return StateDegraded, "No successful encrypted local backup receipt is retained", backupJournalEvidence(statusPath, journal)
	}
	last := journal.LastSuccess
	receivedAt := journal.LastSuccessReceived
	received, err := time.Parse(time.RFC3339Nano, receivedAt)
	if err != nil || received.After(e.Adapters.Now().UTC()) {
		return StateDegraded, "The last successful backup receipt has an invalid server timestamp", backupJournalEvidence(statusPath, journal)
	}
	age := e.Adapters.Now().UTC().Sub(received)
	evidence := backupJournalEvidence(statusPath, journal)
	evidence["age_seconds"] = int64(age.Seconds())
	evidence["max_age_seconds"] = e.Config.Backup.MaxAgeSeconds
	if journal.LatestAttempt != nil && journal.LatestAttempt.State == backuplifecycle.StateFailed {
		if journal.LatestAttempt.Cloud == backuplifecycle.CloudFailed && backuplifecycle.LocalArtifactSuccess(*journal.LatestAttempt) {
			return StateDegraded, "The local encrypted backup succeeded but the configured cloud export failed", evidence
		}
		return StateDegraded, "The latest backup attempt failed; the previous local receipt remains available", evidence
	}
	if journal.LatestAttempt != nil && journal.LatestAttempt.State == backuplifecycle.StatePending && journal.LatestAttempt.AttemptID != last.AttemptID {
		return StateDegraded, "The latest backup attempt is still in progress; the previous local receipt remains available", evidence
	}
	if age < 0 || age > time.Duration(e.Config.Backup.MaxAgeSeconds)*time.Second {
		return StateDegraded, "The last successful backup is older than its configured maximum age", evidence
	}
	if e.Config.Backup.CloudRequired && last.Cloud != backuplifecycle.CloudComplete {
		return StateDegraded, "The last successful local backup has no completed required cloud receipt", evidence
	}
	if !e.Config.Backup.CloudEnabled {
		evidence["cloud"] = "not_configured"
	}
	return StateHealthy, "The last successful backup has a fresh authenticated and verified lifecycle receipt", evidence
}

func backupJournalEvidence(path string, journal backuplifecycle.Journal) map[string]any {
	evidence := map[string]any{"status_path": path, "outcome": "journal"}
	if journal.LatestAttempt != nil {
		evidence["latest_attempt"] = map[string]any{"attempt_id": journal.LatestAttempt.AttemptID, "state": journal.LatestAttempt.State, "phase": journal.LatestAttempt.Phase, "source_capture": journal.LatestAttempt.SourceCapture, "encryption": journal.LatestAttempt.Encryption, "receipt": journal.LatestAttempt.Receipt, "cloud": journal.LatestAttempt.Cloud}
	}
	if journal.LastSuccess != nil {
		evidence["last_success"] = map[string]any{"attempt_id": journal.LastSuccess.AttemptID, "updated_at": journal.LastSuccess.UpdatedAt, "source_capture": journal.LastSuccess.SourceCapture, "encryption": journal.LastSuccess.Encryption, "receipt": journal.LastSuccess.Receipt, "cloud": journal.LastSuccess.Cloud, "archive_sha256": journal.LastSuccess.ArchiveSHA256}
	}
	return evidence
}

func hexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func validHostKey(value string) bool {
	return strings.HasPrefix(value, "SHA256:") && len(value) == len("SHA256:")+43
}

func (e Engine) https(ctx context.Context) (string, string, map[string]any) {
	if e.Config.TLS.URL == "" {
		return StateNotApplicable, "HTTPS monitoring is not configured", nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.Config.TLS.URL, nil)
	if err != nil {
		return StateUnavailable, "HTTPS request could not be created", nil
	}
	response, err := e.Adapters.HTTP.Do(request)
	if err != nil {
		return StateUnavailable, "HTTPS endpoint is unavailable", nil
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return StateDegraded, "HTTPS endpoint redirected instead of proving the configured endpoint", map[string]any{"status": response.StatusCode}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return StateDegraded, "HTTPS endpoint returned a non-success status", map[string]any{"status": response.StatusCode}
	}
	return StateHealthy, "HTTPS endpoint returned a success status", map[string]any{"status": response.StatusCode}
}

func (e Engine) tlsExpiry(ctx context.Context) (string, string, map[string]any) {
	if e.Config.TLS.URL == "" {
		return StateNotApplicable, "TLS expiry monitoring is not configured", nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.Config.TLS.URL, nil)
	if err != nil {
		return StateUnavailable, "TLS request could not be created", nil
	}
	response, err := e.Adapters.HTTP.Do(request)
	if err != nil {
		return StateUnavailable, "TLS certificate could not be observed", nil
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return StateDegraded, "TLS endpoint redirected instead of proving the configured endpoint", map[string]any{"status": response.StatusCode}
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return StateUnavailable, "HTTPS returned no peer certificate", nil
	}
	certificate := response.TLS.PeerCertificates[0]
	// Use the injected clock so a scheduled run and its tests share one time
	// source rather than mixing wall-clock observations.
	days := int(certificate.NotAfter.Sub(e.Adapters.Now().UTC()).Hours() / 24)
	evidence := map[string]any{"not_after": certificate.NotAfter.UTC().Format(time.RFC3339), "days_remaining": days, "min_days": e.Config.TLS.MinDays}
	if days < e.Config.TLS.MinDays {
		return StateDegraded, "TLS certificate is too close to expiry", evidence
	}
	return StateHealthy, "TLS certificate has sufficient remaining lifetime", evidence
}

type readinessCommandAdapter struct {
	ctx context.Context
	run CommandRunner
}

func (a readinessCommandAdapter) Run(command string, timeout time.Duration) execx.Result {
	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()
	body, err := a.run(ctx, "sh", "-lc", command)
	if err != nil {
		if ctx.Err() != nil {
			return execx.Result{ExitCode: 124, Stderr: ctx.Err().Error()}
		}
		return execx.Result{ExitCode: 1, Stdout: string(body), Stderr: err.Error()}
	}
	return execx.Result{Stdout: string(body)}
}

func sshdEffectiveContext(user string, port int, listenAddr, peerHost, peerAddr string) string {
	parts := []string{"user=" + user}
	if strings.TrimSpace(peerHost) != "" {
		parts = append(parts, "host="+strings.TrimSpace(peerHost))
	}
	if strings.TrimSpace(peerAddr) != "" {
		parts = append(parts, "addr="+strings.TrimSpace(peerAddr))
	}
	if strings.TrimSpace(listenAddr) != "" {
		parts = append(parts, "laddr="+strings.TrimSpace(listenAddr))
	}
	if port > 0 {
		parts = append(parts, "lport="+strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

func sshdEffectiveArgs(user string, port int, listenAddr, peerHost, peerAddr string) []string {
	return []string{"sshd", "-T", "-C", sshdEffectiveContext(user, port, listenAddr, peerHost, peerAddr)}
}

func readinessResult(title string, result readiness.CheckResult) (string, string, map[string]any) {
	if result.Status == readiness.Passed {
		return StateHealthy, result.Summary, result.Evidence
	}
	if result.Status == readiness.Failed {
		return StateDegraded, result.Summary, result.Evidence
	}
	if result.SkipReason == readiness.NotApplicable {
		return StateNotApplicable, result.Summary, result.Evidence
	}
	summary := result.Summary
	if summary == "" {
		summary = title + " evidence is unavailable"
	}
	return StateUnavailable, summary, result.Evidence
}

func (e Engine) securityChecks(ctx context.Context) []Result {
	checks := []Result{}
	if e.Config.Security.CheckSSH {
		checks = append(checks, e.runCheck(ctx, "security.ssh", "SSH posture", "security", func(ctx context.Context) (string, string, map[string]any) {
			port := e.Config.Security.ExpectedSSHPort
			if port == 0 {
				port = e.SSHPort
			}
			users := e.Config.Security.MonitoringSecurityUsers()
			if len(users) == 0 {
				return StateUnavailable, "Expected SSH accounts were not materialized from trusted project settings", nil
			}
			access := readiness.AccessConfig{SSHPort: port, DeployUser: "deploy", AllowedSSHUsers: users}
			portResult := readiness.MonitoringCheckSSHPortForAccess(readinessCommandAdapter{ctx: ctx, run: e.Adapters.Run}, access)
			portState, portSummary, portEvidence := readinessResult("SSH port", portResult)
			if portState != StateHealthy {
				return portState, portSummary, map[string]any{"port_check": portEvidence}
			}
			listenAddr := strings.TrimSpace(e.Config.Security.SSHListenAddress)
			peerAddr := strings.TrimSpace(e.Config.Security.SSHPeerAddress)
			peerHost := strings.TrimSpace(e.Config.Security.SSHPeerHost)
			peerObserved := peerAddr != "" || peerHost != ""
			contexts := map[string]any{}
			for _, user := range users {
				args := sshdEffectiveArgs(user, port, listenAddr, peerHost, peerAddr)
				body, err := e.Adapters.Run(ctx, args...)
				if err != nil {
					return StateUnavailable, commandFailureSummary("Effective SSH configuration could not be inspected for every required account", err), withCommandError(map[string]any{"user": user, "argv": args}, err)
				}
				matched := readiness.MonitoringSSHMatches(string(body), users, port)
				contexts[user] = map[string]any{"matched": matched, "context": sshdEffectiveContext(user, port, listenAddr, peerHost, peerAddr)}
				if !matched {
					return StateDegraded, "At least one required SSH account has an unsafe or drifted effective context", map[string]any{"user": user, "contexts": contexts, "argv": args}
				}
			}
			evidence := map[string]any{"contexts": contexts, "port": port, "listen_address": listenAddr, "argv_shape": "sshd -T -C <comma-separated-context>"}
			if peerObserved {
				evidence["peer_context"] = "observed"
				evidence["peer_address"] = peerAddr
				evidence["peer_host"] = peerHost
			} else {
				evidence["peer_context"] = "not_observed"
			}
			return StateHealthy, "Every required SSH account matches the key-only effective posture", evidence
		}))
	}
	if e.Config.Security.CheckUFW {
		checks = append(checks, e.runCheck(ctx, "security.ufw", "UFW posture", "security", func(ctx context.Context) (string, string, map[string]any) {
			body, err := e.Adapters.Run(ctx, "ufw", "status", "verbose")
			if err != nil {
				return StateUnavailable, commandFailureSummary("UFW posture could not be inspected", err), withCommandError(nil, err)
			}
			if !e.Config.Security.RequireUFW {
				return StateNotApplicable, "UFW posture is not required", nil
			}
			text := string(body)
			if !readiness.MonitoringUFWAllowsOnlySafeDefaults(text) {
				return StateDegraded, "UFW is inactive or has an unsafe default policy", nil
			}
			allowed := map[string]bool{}
			for _, value := range e.Config.Security.AllowedTCPPorts {
				allowed[value] = true
			}
			private := e.Config.Security.PrivateInterface
			port := e.Config.Security.ExpectedSSHPort
			if port == 0 {
				port = e.SSHPort
			}
			if private != "" {
				privateRule, violations := readiness.MonitoringSSHPrivateUFWRules(text, private, port)
				if !privateRule || len(violations) > 0 {
					return StateDegraded, "UFW does not keep SSH on the configured private interface", map[string]any{"private_rule": privateRule, "ssh_violations": violations}
				}
			}
			if private == "" && port > 0 {
				// Without a private interface SSH is necessarily public. The live
				// recette VPS reported its own 22/tcp rule as unexpected on every
				// cycle, a permanent false incident that doctor never raised.
				allowed[strconv.Itoa(port)] = true
			}
			unexpected := readiness.MonitoringPublicUFWTCPRules(text, allowed, private)
			if len(unexpected) > 0 {
				return StateDegraded, "UFW has unexpected public TCP rules", map[string]any{"unexpected_rules": unexpected}
			}
			return StateHealthy, "UFW is active with safe defaults and expected TCP rules", map[string]any{"private_interface": private, "allowed_tcp_ports": e.Config.Security.AllowedTCPPorts}
		}))
	}
	if e.Config.Security.CheckDockerUser {
		checks = append(checks, e.runCheck(ctx, "security.docker_user", "Docker-USER firewall chain", "security", func(ctx context.Context) (string, string, map[string]any) {
			result := readiness.MonitoringCheckDockerUserPolicy(readinessCommandAdapter{ctx: ctx, run: e.Adapters.Run})
			return readinessResult("Docker-USER firewall chain", result)
		}))
	}
	if e.Config.Security.CheckFail2ban {
		checks = append(checks, e.runCheck(ctx, "security.fail2ban", "fail2ban posture", "security", func(ctx context.Context) (string, string, map[string]any) {
			if _, err := e.Adapters.Run(ctx, "systemctl", "is-active", "fail2ban"); err != nil {
				return StateDegraded, commandFailureSummary("fail2ban daemon is not active", err), withCommandError(nil, err)
			}
			port := e.Config.Security.ExpectedSSHPort
			if port == 0 {
				port = e.SSHPort
			}
			adapter := readinessCommandAdapter{ctx: ctx, run: e.Adapters.Run}
			jail := readiness.MonitoringCheckFail2banSSHDJail(adapter)
			jailState, jailSummary, jailEvidence := readinessResult("fail2ban sshd jail", jail)
			if jailState != StateHealthy {
				return jailState, jailSummary, map[string]any{"jail": jailEvidence}
			}
			portResult := readiness.MonitoringCheckFail2banSSHDPort(adapter, readiness.AccessConfig{SSHPort: port})
			portState, portSummary, portEvidence := readinessResult("fail2ban SSH port", portResult)
			if portState != StateHealthy {
				return portState, portSummary, map[string]any{"port": portEvidence}
			}
			return StateHealthy, "fail2ban protects the effective SSHD jail and port", map[string]any{"jail": jailEvidence, "port": portEvidence, "effective_port": port}
		}))
	}
	return checks
}

func (e Engine) operations(ctx context.Context) (string, string, map[string]any) {
	if ctx.Err() != nil {
		return StateUnavailable, "Operation state check timed out", nil
	}
	entries, err := e.Adapters.ReadDir(e.Config.OperationsStateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return StateNotApplicable, "No shared operation state directory exists", nil
		}
		return StateUnavailable, "Shared operation state could not be inspected", nil
	}
	active := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		body, readErr := e.Adapters.Read(filepath.Join(e.Config.OperationsStateDir, entry.Name()))
		if readErr != nil {
			return StateUnavailable, "Shared operation state could not be read", nil
		}
		var value struct {
			RecoveryRequired bool   `json:"recovery_required"`
			Status           string `json:"status"`
		}
		if json.Unmarshal(body, &value) != nil {
			return StateUnavailable, "Shared operation state was not valid JSON", nil
		}
		if value.RecoveryRequired || strings.EqualFold(value.Status, "recovery_required") {
			active = append(active, entry.Name())
		}
	}
	if len(active) > 0 {
		sort.Strings(active)
		return StateDegraded, "An operation requires explicit recovery", map[string]any{"operations": active}
	}
	return StateHealthy, "No operation requires recovery", nil
}
