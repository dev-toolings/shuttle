package readiness

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
	"gopkg.in/yaml.v3"
)

// composeSearchCommand emits `__compose__=<path>` followed by the file body
// for the first readable compose file found in standard locations.
const composeSearchCommand = `for f in docker-compose.prod.yml compose.prod.yml docker-compose.yml compose.yml /opt/shuttle/*/docker-compose.prod.yml /opt/shuttle/*/docker-compose.yml; do if [ -r "$f" ]; then echo __compose__="$f"; cat "$f"; exit $?; fi; done; exit 1`

// composeSnapshot is the result of a single compose lookup.
type composeSnapshot struct {
	Found bool
	Path  string
	Body  string
}

func loadCompose(adapter execx.Adapter) composeSnapshot {
	res := adapter.Run(composeSearchCommand, 3*time.Second)
	if res.ExitCode != 0 {
		return composeSnapshot{}
	}
	path := capture(res.Stdout, `__compose__=([^\n]+)`)
	body := strings.TrimPrefix(res.Stdout, "__compose__="+path+"\n")
	var document struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if strings.TrimSpace(path) == "" || yaml.Unmarshal([]byte(body), &document) != nil || len(document.Services) == 0 {
		return composeSnapshot{}
	}
	return composeSnapshot{Found: true, Path: strings.TrimSpace(path), Body: body}
}

type composeServiceEvidence struct {
	Image    string `yaml:"image"`
	EnvFile  any    `yaml:"env_file"`
	MemLimit any    `yaml:"mem_limit"`
	CPUs     any    `yaml:"cpus"`
	CPUCount any    `yaml:"cpu_count"`
	Deploy   struct {
		Resources struct {
			Limits map[string]any `yaml:"limits"`
		} `yaml:"resources"`
	} `yaml:"deploy"`
	Volumes []any `yaml:"volumes"`
}

func composeServices(snap composeSnapshot) (map[string]composeServiceEvidence, bool) {
	var document struct {
		Services map[string]composeServiceEvidence `yaml:"services"`
	}
	err := yaml.Unmarshal([]byte(snap.Body), &document)
	return document.Services, err == nil && len(document.Services) > 0
}

// checkComposeMissingProdFile is applicability-aware: a host without a
// Compose workload is not defective merely because Compose is not installed.
func checkComposeMissingProdFile(snap composeSnapshot) CheckResult {
	if snap.Found {
		return CheckResult{
			ID: "compose.missing_prod_file", Title: "Production compose file is present",
			Category: "compose", Severity: Medium, Status: Passed,
			Summary:  "Detected compose file: " + snap.Path + ".",
			Evidence: map[string]any{"composeFile": snap.Path},
		}
	}
	return CheckResult{
		ID: "compose.missing_prod_file", Title: "Production compose file is present",
		Category: "compose", Severity: Medium, Status: Skipped,
		Summary: "No Compose workload detected; production Compose checks are not applicable.",
	}
}

// checkComposeEnvFileMissing fails when an env_file reference points to a file
// that does not exist on the target.
func checkComposeEnvFileMissing(adapter execx.Adapter, snap composeSnapshot) CheckResult {
	if !snap.Found {
		return CheckResult{
			ID: "compose.env_file_missing", Title: "compose env_file references resolve",
			Category: "compose", Severity: Medium, Status: Skipped,
			Summary: "No compose file detected; cannot verify env_file references.",
		}
	}
	services, ok := composeServices(snap)
	if !ok {
		return collectionUnavailable("compose.env_file_missing", "compose env_file references resolve", "compose", Medium)
	}
	references := []string{}
	for _, service := range services {
		var entries []any
		switch value := service.EnvFile.(type) {
		case nil:
			continue
		case string:
			entries = []any{value}
		case []any:
			entries = value
		default:
			return collectionUnavailable("compose.env_file_missing", "compose env_file references resolve", "compose", Medium)
		}
		for _, entry := range entries {
			path, ok := entry.(string)
			if !ok {
				return collectionUnavailable("compose.env_file_missing", "compose env_file references resolve", "compose", Medium)
			}
			if path == "" || strings.Contains(path, "$") {
				return collectionUnavailable("compose.env_file_missing", "compose env_file references resolve", "compose", Medium)
			}
			references = append(references, path)
		}
	}
	sort.Strings(references)
	if len(references) == 0 {
		return CheckResult{
			ID: "compose.env_file_missing", Title: "compose env_file references resolve",
			Category: "compose", Severity: Medium, Status: Passed,
			Summary:  "No env_file references in " + snap.Path + ".",
			Evidence: map[string]any{"composeFile": snap.Path},
		}
	}
	missing := []string{}
	composeDir := dirOf(snap.Path)
	for _, ref := range references {
		probe := ref
		if !strings.HasPrefix(probe, "/") {
			probe = composeDir + "/" + ref
		}
		if adapter.Run("test -f "+shellQuote(probe), time.Second).ExitCode != 0 {
			missing = append(missing, ref)
		}
	}
	status := Passed
	summary := "All env_file references resolve."
	if len(missing) > 0 {
		status = Failed
		summary = fmt.Sprintf("%d env_file reference(s) point to missing files: %s.", len(missing), strings.Join(missing, ", "))
	}
	return CheckResult{
		ID: "compose.env_file_missing", Title: "compose env_file references resolve",
		Category: "compose", Severity: Medium, Status: status,
		Summary:     summary,
		Remediation: "Create the referenced env file(s) or update the compose file to point at the correct path.",
		Evidence:    map[string]any{"composeFile": snap.Path, "references": references, "missing": missing},
	}
}

// checkComposeLatestTag flags images using ':latest' or no explicit tag.
func checkComposeLatestTag(snap composeSnapshot) CheckResult {
	if !snap.Found {
		return CheckResult{
			ID: "compose.latest_tag_used", Title: "Production compose pins image tags",
			Category: "compose", Severity: Medium, Status: Skipped,
			Summary: "No compose file detected.",
		}
	}
	services, ok := composeServices(snap)
	if !ok {
		return collectionUnavailable("compose.latest_tag_used", "Production compose pins image tags", "compose", Medium)
	}
	offenders := []string{}
	for _, service := range services {
		image := service.Image
		if image == "" || strings.Contains(image, "$") {
			return collectionUnavailable("compose.latest_tag_used", "Production compose pins image tags", "compose", Medium)
		}
		// Strip any registry prefix so the colon in 'registry:5000/foo' is not
		// mistaken for a tag separator.
		nameAndTag := image
		if slash := strings.LastIndex(image, "/"); slash >= 0 {
			nameAndTag = image[slash+1:]
		}
		tag := ""
		if idx := strings.LastIndex(nameAndTag, ":"); idx > 0 {
			tag = nameAndTag[idx+1:]
		}
		if tag == "" || tag == "latest" {
			offenders = append(offenders, image)
		}
	}
	sort.Strings(offenders)
	if len(offenders) == 0 {
		return CheckResult{
			ID: "compose.latest_tag_used", Title: "Production compose pins image tags",
			Category: "compose", Severity: Medium, Status: Passed,
			Summary:  "All image references in " + snap.Path + " are pinned.",
			Evidence: map[string]any{"composeFile": snap.Path},
		}
	}
	return CheckResult{
		ID: "compose.latest_tag_used", Title: "Production compose pins image tags",
		Category: "compose", Severity: Medium, Status: Failed,
		Summary:     fmt.Sprintf("%d compose image(s) use ':latest' or no tag: %s.", len(offenders), strings.Join(offenders, ", ")),
		Remediation: "Pin every production image to an explicit immutable tag or digest so deploys are reproducible.",
		Evidence:    map[string]any{"composeFile": snap.Path, "offenders": offenders},
	}
}

// checkComposeNoResourceLimits warns when no service declares cpu/memory limits.
func checkComposeNoResourceLimits(snap composeSnapshot) CheckResult {
	if !snap.Found {
		return CheckResult{
			ID: "compose.no_resource_limits", Title: "compose services declare resource limits",
			Category: "compose", Severity: Low, Status: Skipped,
			Summary: "No compose file detected.",
		}
	}
	services, ok := composeServices(snap)
	if !ok {
		return collectionUnavailable("compose.no_resource_limits", "compose services declare resource limits", "compose", Low)
	}
	hasLimits := true
	for _, service := range services {
		present := false
		for _, value := range []any{service.MemLimit, service.CPUs, service.CPUCount, service.Deploy.Resources.Limits["memory"], service.Deploy.Resources.Limits["cpus"]} {
			if value != nil && regexp.MustCompile(`^[0-9]*[1-9][0-9]*(\.[0-9]+)?[a-zA-Z]*$|^0\.[0-9]*[1-9][0-9]*$`).MatchString(fmt.Sprint(value)) {
				present = true
			}
		}
		hasLimits = hasLimits && present
	}
	if hasLimits {
		return CheckResult{
			ID: "compose.no_resource_limits", Title: "compose services declare resource limits",
			Category: "compose", Severity: Low, Status: Passed,
			Summary:  "Every Compose service declares a CPU or memory limit.",
			Evidence: map[string]any{"composeFile": snap.Path, "serviceCount": len(services)},
		}
	}
	return CheckResult{
		ID: "compose.no_resource_limits", Title: "compose services declare resource limits",
		Category: "compose", Severity: Low, Status: Failed,
		Summary:     fmt.Sprintf("At least one of %d Compose services has no positive CPU or memory limit.", len(services)),
		Remediation: "Add 'deploy.resources.limits' (Swarm) or 'mem_limit' / 'cpus' (classic) so a runaway container cannot starve the host.",
		Evidence:    map[string]any{"composeFile": snap.Path, "serviceCount": len(services)},
	}
}

// checkComposeBindMountSensitivePaths flags risky host bind mounts.
func checkComposeBindMountSensitivePaths(snap composeSnapshot) CheckResult {
	if !snap.Found {
		return CheckResult{
			ID: "compose.bind_mount_sensitive_paths", Title: "compose does not bind-mount sensitive host paths",
			Category: "compose", Severity: High, Status: Skipped,
			Summary: "No compose file detected.",
		}
	}
	services, ok := composeServices(snap)
	if !ok {
		return collectionUnavailable("compose.bind_mount_sensitive_paths", "compose does not bind-mount sensitive host paths", "compose", High)
	}
	hits := []string{}
	for name, service := range services {
		for _, volume := range service.Volumes {
			var source string
			switch entry := volume.(type) {
			case string:
				source, _, _ = strings.Cut(entry, ":")
			case map[string]any:
				source, _ = entry["source"].(string)
			default:
				return collectionUnavailable("compose.bind_mount_sensitive_paths", "compose does not bind-mount sensitive host paths", "compose", High)
			}
			if strings.Contains(source, "$") {
				return collectionUnavailable("compose.bind_mount_sensitive_paths", "compose does not bind-mount sensitive host paths", "compose", High)
			}
			for _, sensitive := range []string{"/", "/etc", "/root", "/proc", "/sys", "/var/run/docker.sock", "/run/docker.sock"} {
				if source == sensitive || (sensitive != "/" && strings.HasPrefix(source, sensitive+"/")) {
					hits = append(hits, name+": "+source)
					break
				}
			}
		}
	}
	sort.Strings(hits)
	if len(hits) == 0 {
		return CheckResult{
			ID: "compose.bind_mount_sensitive_paths", Title: "compose does not bind-mount sensitive host paths",
			Category: "compose", Severity: High, Status: Passed,
			Summary:  "No sensitive host bind mounts in " + snap.Path + ".",
			Evidence: map[string]any{"composeFile": snap.Path},
		}
	}
	return CheckResult{
		ID: "compose.bind_mount_sensitive_paths", Title: "compose does not bind-mount sensitive host paths",
		Category: "compose", Severity: High, Status: Failed,
		Summary:     fmt.Sprintf("%d compose mount(s) reference sensitive host paths.", len(hits)),
		Remediation: "Remove host bind mounts of /var/run/docker.sock (without explicit allow-list), /etc, /root, /proc, /sys, or root '/'. Use named volumes instead.",
		Evidence:    map[string]any{"composeFile": snap.Path, "lines": hits},
	}
}

func dirOf(path string) string {
	if idx := strings.LastIndex(path, "/"); idx > 0 {
		return path[:idx]
	}
	return "."
}

// shellQuote mirrors the harden-package helper but kept local to avoid an import cycle.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
