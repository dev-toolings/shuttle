package cli

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/output"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

// serviceMemoryLimit is one service of the stack about to be applied, with the
// memory limit its generated Swarm task spec declares. Every service carries
// one — swarm_stack.go writes deploy.resources.limits.memory from
// cfg.ServiceLimits for each service, and root_stack_validation.go refuses a
// stack where any of them is missing — so this is the figure the daemon will
// actually enforce, not an estimate.
type serviceMemoryLimit struct {
	Name  string
	Bytes int64
	// Replicas is the replica count the rendered stack gives the service. 0 reads
	// as 1: the callers that never needed it (and the tests that predate it)
	// describe single-replica services.
	Replicas int
	// Copies is how many extra copies of the limit a rolling update holds at the
	// same time: the replacement tasks started beside their predecessors. 0 reads
	// as 1, the one-at-a-time rollout. rollingOverlapLimits sets it from
	// update_parallelism and Replicas.
	Copies int
}

// overlapCopies is Copies with its zero value read as one.
func (limit serviceMemoryLimit) overlapCopies() int64 {
	if limit.Copies < 1 {
		return 1
	}
	return int64(limit.Copies)
}

// memoryBudgetDecision is the outcome of the pre-deploy memory guard: what the
// rolling update will ask the host for, what the host has, and which services
// make up the ask.
type memoryBudgetDecision struct {
	TotalBytes     int64
	AvailableBytes int64
	RequiredBytes  int64
	// Services is sorted by name, so the same stack always produces the same
	// message (invariant 2: never let map iteration pick).
	Services []serviceMemoryLimit
	Refused  bool
}

// evaluateMemoryBudget decides whether the host can absorb the next rolling
// update. Pure: no I/O, no globals, no clock.
//
// The required figure is the sum of every service's memory limit, because
// update_config is `order: start-first, parallelism: 1` (swarm_stack.go): the
// new task of a service starts, and is waited on, before the old one is
// stopped, so each updated service costs one extra copy of its limit for the
// length of the update. `docker stack deploy` updates services in parallel with
// each other, so in the worst case every service of the stack is doubled at the
// same moment. That worst case is the sum of the limits, on top of everything
// already running — which is exactly what MemAvailable measures.
//
// The comparison is strict: available == required passes. The limits are
// ceilings the daemon enforces, not the resident size tasks are expected to
// reach, so a host with exactly enough headroom for the ceilings has enough for
// the update. Refusing at equality would move the guard from "cannot fit" to
// "might be tight", which is a judgement the operator did not ask for.
func evaluateMemoryBudget(totalBytes, availableBytes int64, limits []serviceMemoryLimit) memoryBudgetDecision {
	services := make([]serviceMemoryLimit, len(limits))
	copy(services, limits)
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })

	var required int64
	for _, service := range services {
		required += service.Bytes * service.overlapCopies()
	}
	return memoryBudgetDecision{
		TotalBytes:     totalBytes,
		AvailableBytes: availableBytes,
		RequiredBytes:  required,
		Services:       services,
		Refused:        availableBytes < required,
	}
}

// Err returns the refusal, naming both figures and every service that makes up
// the requirement with its own limit, so the operator can see what to lower or
// how much memory to add without reading the generated stack.
func (d memoryBudgetDecision) Err() error {
	if !d.Refused {
		return nil
	}
	return fmt.Errorf("deployment refused: %s", d.Shortfall())
}

// Shortfall states the figures without a verdict, for the callers that only
// warn: a warning that opens with "deployment refused" reads as a failed
// deploy in a log where the deploy went on and succeeded.
func (d memoryBudgetDecision) Shortfall() string {
	parts := make([]string, 0, len(d.Services))
	for _, service := range d.Services {
		if copies := service.overlapCopies(); copies > 1 {
			parts = append(parts, fmt.Sprintf("%s %s x%d", service.Name, formatMemoryBytes(service.Bytes), copies))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s", service.Name, formatMemoryBytes(service.Bytes)))
	}
	return fmt.Sprintf("the rolling update needs %s of free memory (%s), host has %s available of %s",
		formatMemoryBytes(d.RequiredBytes), strings.Join(parts, ", "),
		formatMemoryBytes(d.AvailableBytes), formatMemoryBytes(d.TotalBytes))
}

// Summary is what a passing guard reports. A budget that only ever speaks when
// it refuses teaches nobody how close the host is to the edge (invariant 6:
// budgets measure).
func (d memoryBudgetDecision) Summary() string {
	return fmt.Sprintf("Memory budget: %s available of %s, rolling update needs %s across %d services",
		formatMemoryBytes(d.AvailableBytes), formatMemoryBytes(d.TotalBytes),
		formatMemoryBytes(d.RequiredBytes), len(d.Services))
}

func formatMemoryBytes(bytes int64) string {
	if bytes >= 1<<30 {
		return fmt.Sprintf("%.2f GiB", float64(bytes)/float64(1<<30))
	}
	return fmt.Sprintf("%d MiB", bytes>>20)
}

// parseMemInfo reads MemTotal and MemAvailable out of /proc/meminfo.
//
// Strict on purpose: a missing, empty, duplicated or non-numeric field is an
// error, never a zero that would let the guard wave a deploy through on a host
// it could not measure. MemAvailable is the kernel's own estimate of what can
// be handed to a new workload without swapping, which is the figure the guard
// needs; MemFree would ignore reclaimable page cache and refuse healthy hosts.
func parseMemInfo(raw string) (totalBytes int64, availableBytes int64, err error) {
	wanted := map[string]*int64{"MemTotal": &totalBytes, "MemAvailable": &availableBytes}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		separator := strings.Index(line, ":")
		if separator < 0 {
			continue
		}
		key := strings.TrimSpace(line[:separator])
		target, ok := wanted[key]
		if !ok {
			continue
		}
		if seen[key] {
			return 0, 0, fmt.Errorf("%s is declared twice", key)
		}
		seen[key] = true
		fields := strings.Fields(line[separator+1:])
		// The kernel writes "<number> kB" for both of these. Anything else is
		// not the file this parser was written against.
		if len(fields) != 2 || !strings.EqualFold(fields[1], "kB") {
			return 0, 0, fmt.Errorf("%s is not a kB value", key)
		}
		kilobytes, convErr := strconv.ParseInt(fields[0], 10, 64)
		if convErr != nil || kilobytes < 0 || kilobytes > (1<<62)/1024 {
			return 0, 0, fmt.Errorf("%s is not a number", key)
		}
		*target = kilobytes * 1024
	}
	for _, key := range []string{"MemAvailable", "MemTotal"} {
		if !seen[key] {
			return 0, 0, fmt.Errorf("%s is missing", key)
		}
	}
	if totalBytes <= 0 {
		return 0, 0, errors.New("MemTotal is zero")
	}
	return totalBytes, availableBytes, nil
}

// stackMemoryLimits lists every service the stack about to be applied will
// contain, with the memory limit it will carry.
//
// Two sources, matching secureStack: the application services of the parsed
// compose file, and the infrastructure services secureStack adds for an active
// production.redis / production.rabbitmq. Both go through cfg.ServiceLimits,
// which is the same call that writes the limit into the stack, so this guard
// cannot disagree with what is deployed. Leaving the infrastructure services
// out would make the guard under-count by their limits on exactly the stacks
// that need it most.
func stackMemoryLimits(parsed *composeFile, cfg *config.Config) ([]serviceMemoryLimit, error) {
	names := make([]string, 0, len(parsed.Services)+2)
	for name := range parsed.Services {
		names = append(names, name)
	}
	if cfg.Production.Redis {
		names = append(names, "redis")
	}
	if cfg.Production.RabbitMQ {
		names = append(names, "rabbitmq")
	}
	sort.Strings(names)

	limits := make([]serviceMemoryLimit, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			// A compose file that already declares redis or rabbitmq itself:
			// the stack holds one service, so the budget counts one.
			continue
		}
		seen[name] = true
		declared := cfg.ServiceLimits(name).Memory
		bytes, err := config.ParseByteSize(declared)
		if err != nil {
			return nil, fmt.Errorf("service %s memory limit %q: %w", name, declared, err)
		}
		limits = append(limits, serviceMemoryLimit{Name: name, Bytes: bytes, Replicas: renderedReplicas(parsed, cfg, name)})
	}
	if len(limits) == 0 {
		return nil, errors.New("stack declares no services")
	}
	return limits, nil
}

// renderedReplicas is the replica count the Swarm stack gives a service. The
// published service is always rendered with one replica (swarm_stack.go: a second
// adds no failure domain on a single node); every other service keeps the
// deploy.replicas its compose file declares, and one when it declares none.
// Infrastructure services secureStack adds have no compose entry and run one.
func renderedReplicas(parsed *composeFile, cfg *config.Config, name string) int {
	if name == cfg.PrimaryServiceName() || parsed == nil {
		return 1
	}
	services, _ := parsed.Raw["services"].(map[string]any)
	service, _ := services[name].(map[string]any)
	deploy, _ := service["deploy"].(map[string]any)
	if replicas, ok := deploy["replicas"].(int); ok && replicas > 1 {
		return replicas
	}
	return 1
}

// memoryBudgetPolicy says what a swarm deploy does when the overlap ceiling
// does not fit: refuse (the default), or report it and go on. The second is an
// explicit operator choice per invocation, never a threshold the guard picks on
// its own: the ceilings are the only figure it can stand behind, and on a small
// host they can exceed MemAvailable while the tasks' real resident size fits
// several times over.
type memoryBudgetPolicy string

const (
	memoryBudgetStrict memoryBudgetPolicy = "strict"
	memoryBudgetWarn   memoryBudgetPolicy = "warn"
)

func parseMemoryBudgetPolicy(value string) (memoryBudgetPolicy, error) {
	switch policy := memoryBudgetPolicy(strings.TrimSpace(value)); policy {
	case memoryBudgetStrict, memoryBudgetWarn:
		return policy, nil
	}
	return "", fmt.Errorf("--memory-budget must be %q or %q, got %q", memoryBudgetStrict, memoryBudgetWarn, value)
}

// rollingOverlapLimits keeps the services a swarm rolling update runs twice at
// once. A stop-first service stops its old task before starting the new one
// (swarm_stack.go writes cfg.UpdateOrder into update_config), so it never adds
// a second copy and does not belong in the overlap. Compose recreates in place
// and keeps using the full list as a ceiling the host must hold.
//
// A start-first service holds as many replacement tasks beside their
// predecessors as it replaces at once: min(update_parallelism, replicas), where
// parallelism 0 means every replica of the rendered stack. Each of them is a
// full extra copy of the service's memory limit, so the service enters the
// overlap that many times (Copies).
func rollingOverlapLimits(limits []serviceMemoryLimit, cfg *config.Config) []serviceMemoryLimit {
	overlap := make([]serviceMemoryLimit, 0, len(limits))
	for _, service := range limits {
		if cfg.UpdateOrder(service.Name) == config.UpdateOrderStopFirst {
			continue
		}
		service.Copies = rollingOverlapCopies(cfg.UpdateParallelism(service.Name), service.Replicas)
		overlap = append(overlap, service)
	}
	return overlap
}

// rollingOverlapCopies is how many replacement tasks one service runs at once.
func rollingOverlapCopies(parallelism, replicas int) int {
	if replicas < 1 {
		replicas = 1
	}
	switch {
	case parallelism == 0:
		return replicas
	case parallelism < 0:
		return 1
	default:
		return min(parallelism, replicas)
	}
}

// ensureRemoteMemoryBudget refuses a deploy the host cannot hold in memory,
// before anything is built, pushed or promoted.
//
// Without it the only memory check in the product is doctor's advisory
// system.memory_low, and an over-committed stack fails as OOM kills in
// production long after the command returned success. Reading /proc/meminfo
// needs no docker access, so the unprivileged deploy account can do it.
//
// Under memoryBudgetWarn an overlap that does not fit is reported and the
// deploy goes on. A configuration it cannot read and a host it cannot measure
// stay errors under both policies: warn accepts an overcommit the operator can
// see, not a guard that measured nothing.
func ensureRemoteMemoryBudget(client *ssh.Client, parsed *composeFile, cfg *config.Config, policy memoryBudgetPolicy) error {
	limits, err := stackMemoryLimits(parsed, cfg)
	if err != nil {
		return err
	}
	limits = rollingOverlapLimits(limits, cfg)
	result := client.Run("cat /proc/meminfo")
	if result.Code != 0 {
		return errors.New("cannot verify remote memory budget")
	}
	totalBytes, availableBytes, err := parseMemInfo(result.Stdout)
	if err != nil {
		return fmt.Errorf("cannot verify remote memory budget: %w", err)
	}
	decision := evaluateMemoryBudget(totalBytes, availableBytes, limits)
	if decision.Refused {
		if policy == memoryBudgetWarn {
			output.Attn("Memory budget exceeded, deploying anyway (--memory-budget=warn): %s. These are ceilings; the tasks' resident size is what has to fit", decision.Shortfall())
			return nil
		}
		return decision.Err()
	}
	output.Detail("%s", decision.Summary())
	return nil
}
