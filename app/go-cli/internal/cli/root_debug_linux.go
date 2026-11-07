//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

const (
	rootDebugTimeout     = 15 * time.Second
	rootDebugOutputLimit = 1 << 20
)

type limitedDebugOutput struct {
	body      []byte
	limit     int
	truncated bool
}

func (output *limitedDebugOutput) Write(payload []byte) (int, error) {
	written := len(payload)
	remaining := output.limit - len(output.body)
	if remaining > 0 {
		if remaining > len(payload) {
			remaining = len(payload)
		}
		output.body = append(output.body, payload[:remaining]...)
	}
	if remaining < len(payload) {
		output.truncated = true
	}
	return written, nil
}

func rootDebugDocker(args ...string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rootDebugTimeout)
	defer cancel()
	return rootDebugDockerContext(ctx, args...)
}

func rootDebugDockerContext(ctx context.Context, args ...string) (string, bool, error) {
	output := &limitedDebugOutput{limit: rootDebugOutputLimit}
	command := exec.CommandContext(ctx, "/usr/bin/docker", args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	body := sanitizeRootDebugText(string(output.body))
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return body, output.truncated, fmt.Errorf("Docker diagnostic exceeded %s", rootDebugTimeout)
	}
	if err != nil {
		return body, output.truncated, fmt.Errorf("Docker diagnostic failed: %s", strings.TrimSpace(body))
	}
	return body, output.truncated, nil
}

func sanitizeRootDebugText(body string) string {
	return strings.Map(func(value rune) rune {
		switch value {
		case '\n', '\t':
			return value
		}
		if unicode.Is(unicode.C, value) {
			return '\uFFFD'
		}
		return value
	}, body)
}

func boundedRootDebugText(body string, truncated bool) string {
	if truncated {
		return body + "\n[output truncated at 1 MiB by shuttle-root]\n"
	}
	return body
}

func debugRootOperation(audit rootplan.AuditOperation) (string, error) {
	switch audit.Mode {
	case "debug-ps":
		body, truncated, err := rootDebugDocker("ps", "--filter", "label=com.docker.stack.namespace="+audit.App, "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}")
		return boundedRootDebugText(body, truncated), err
	case "debug-services":
		body, truncated, err := rootDebugDocker("stack", "services", audit.App, "--format", "{{.Name}}\t{{.Mode}}\t{{.Replicas}}\t{{.Image}}\t{{.Ports}}")
		return boundedRootDebugText(body, truncated), err
	case "debug-tasks":
		service, err := rootDebugScopedService(audit.App, audit.Service)
		if err != nil {
			return "", err
		}
		body, truncated, err := rootDebugDocker("service", "ps", "--no-trunc", "--no-resolve", "--format", "{{.ID}}\t{{.Name}}\t{{.Image}}\t{{.Node}}\t{{.DesiredState}}\t{{.CurrentState}}\t{{.Error}}", service)
		return boundedRootDebugText(body, truncated), err
	case "debug-inspect":
		service, err := rootDebugScopedService(audit.App, audit.Service)
		if err != nil {
			return "", err
		}
		body, truncated, err := rootDebugDocker("service", "inspect", service)
		if err != nil {
			return "", err
		}
		if truncated {
			return "", errors.New("Docker service inspect exceeded the 1 MiB diagnostic limit")
		}
		return sanitizeRootServiceInspect([]byte(body))
	case "debug-network":
		return debugRootNetworks(audit.App)
	case "debug-logs":
		service, err := rootDebugScopedService(audit.App, audit.Service)
		if err != nil {
			return "", err
		}
		body, truncated, err := rootDebugDocker("service", "logs", "--raw", "--tail", fmt.Sprint(audit.Lines), service)
		return boundedRootDebugText(body, truncated), err
	default:
		return "", errors.New("unsupported read-only Docker diagnostic")
	}
}

func rootDebugScopedService(app, service string) (string, error) {
	if !rootAppName.MatchString(app) || !rootServiceName.MatchString(service) {
		return "", errors.New("invalid application-scoped Docker service")
	}
	fullName := app + "_" + service
	body, truncated, err := rootDebugDocker("service", "inspect", fullName, "--format", "{{index .Spec.Labels \"com.docker.stack.namespace\"}}")
	if err != nil {
		return "", err
	}
	if truncated || strings.TrimSpace(body) != app {
		return "", fmt.Errorf("service %s is not part of application %s", service, app)
	}
	return fullName, nil
}

func selectedDebugFields(source map[string]any, names ...string) map[string]any {
	target := map[string]any{}
	for _, name := range names {
		if value, ok := source[name]; ok {
			target[name] = value
		}
	}
	return target
}

// sanitizeRootServiceInspect constructs a positive allow-list. Removing a few
// known-sensitive keys is not enough: Docker adds fields over time, and a new
// credential-bearing field would then become public by default.
func sanitizeRootServiceInspect(payload []byte) (string, error) {
	var documents []map[string]any
	if err := json.Unmarshal(payload, &documents); err != nil || len(documents) != 1 {
		return "", errors.New("Docker returned an invalid service inspect document")
	}
	document := documents[0]
	safe := selectedDebugFields(document, "ID", "Version", "CreatedAt", "UpdatedAt", "UpdateStatus")
	if spec, ok := document["Spec"].(map[string]any); ok {
		safeSpec := selectedDebugFields(spec, "Name", "Mode", "UpdateConfig", "RollbackConfig", "EndpointSpec")
		if task, ok := spec["TaskTemplate"].(map[string]any); ok {
			safeTask := selectedDebugFields(task, "Resources", "RestartPolicy", "Placement", "Networks", "ForceUpdate", "Runtime")
			if container, ok := task["ContainerSpec"].(map[string]any); ok {
				safeTask["ContainerSpec"] = selectedDebugFields(container, "Image", "Hostname", "User", "ReadOnly")
			}
			safeSpec["TaskTemplate"] = safeTask
		}
		safe["Spec"] = safeSpec
	}
	if endpoint, ok := document["Endpoint"].(map[string]any); ok {
		safe["Endpoint"] = selectedDebugFields(endpoint, "Spec", "VirtualIPs")
	}
	body, err := json.MarshalIndent(safe, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body) + "\n", nil
}

type rootDebugNetworkAttachment struct {
	Target   string   `json:"target"`
	Aliases  []string `json:"aliases,omitempty"`
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	Scope    string   `json:"scope"`
	Internal bool     `json:"internal"`
}

func debugRootNetworks(app string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rootDebugTimeout)
	defer cancel()
	listed, truncated, err := rootDebugDockerContext(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+app, "--format", "{{.Name}}")
	if err != nil {
		return "", err
	}
	if truncated {
		return "", errors.New("application service list exceeded the diagnostic limit")
	}
	services := strings.Fields(listed)
	if len(services) == 0 {
		return "", fmt.Errorf("application %s has no deployed services", app)
	}
	if len(services) > 128 {
		return "", errors.New("application service list exceeds the diagnostic bound")
	}
	sort.Strings(services)
	result := map[string][]rootDebugNetworkAttachment{}
	encodedBytes := 0
	for _, fullName := range services {
		prefix := app + "_"
		if !strings.HasPrefix(fullName, prefix) {
			return "", errors.New("Docker returned a service outside the requested application")
		}
		shortName := strings.TrimPrefix(fullName, prefix)
		if _, err := rootDebugScopedService(app, shortName); err != nil {
			return "", err
		}
		body, wasTruncated, err := rootDebugDockerContext(ctx, "service", "inspect", fullName, "--format", "{{json .Spec.TaskTemplate.Networks}}")
		if err != nil {
			return "", fmt.Errorf("inspect networks of %s: %w", shortName, err)
		}
		if wasTruncated {
			return "", fmt.Errorf("inspect networks of %s exceeded the diagnostic limit", shortName)
		}
		var attachments []rootDebugNetworkAttachment
		if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &attachments); err != nil {
			return "", fmt.Errorf("decode networks of %s: %w", shortName, err)
		}
		for index := range attachments {
			metadata, metadataTruncated, err := rootDebugDockerContext(ctx, "network", "inspect", attachments[index].Target, "--format", "{{.Name}}\t{{.Driver}}\t{{.Scope}}\t{{.Internal}}")
			if err != nil {
				return "", fmt.Errorf("inspect a network of %s: %w", shortName, err)
			}
			if metadataTruncated {
				return "", fmt.Errorf("inspect a network of %s exceeded the diagnostic limit", shortName)
			}
			fields := strings.Split(strings.TrimSpace(metadata), "\t")
			if len(fields) != 4 {
				return "", fmt.Errorf("Docker returned malformed network metadata for %s", shortName)
			}
			attachments[index].Name, attachments[index].Driver, attachments[index].Scope = fields[0], fields[1], fields[2]
			attachments[index].Internal = fields[3] == "true"
		}
		encoded, err := json.Marshal(attachments)
		if err != nil {
			return "", err
		}
		encodedBytes += len(shortName) + len(encoded)
		if encodedBytes > rootDebugOutputLimit {
			return "", errors.New("application network report exceeds the 1 MiB diagnostic limit")
		}
		result[shortName] = attachments
	}
	body, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	if len(body)+1 > rootDebugOutputLimit {
		return "", errors.New("application network report exceeds the 1 MiB diagnostic limit")
	}
	return string(body) + "\n", nil
}
