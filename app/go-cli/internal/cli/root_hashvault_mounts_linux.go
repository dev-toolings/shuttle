//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Confirming a preparation tells the vault "this release is what serves now".
// The convergence wait cannot back that sentence on its own: it compares task
// images and replica counts, and a secret rotation, a rollback or a deferred
// `shuttle secrets sync` usually keeps every image unchanged. The old tasks
// then pass the wait on its first poll, still mounting the previous secret
// objects, and the vault would record a publication no container reads yet.
//
// So the confirmation is gated on the mounts themselves: every task Swarm
// wants running must carry exactly the secret files the retained signed stack
// declares (object name, target, owner and mode). The stack file is the only
// source of what is wanted; docker only reports what is.
// rootHashvaultStack decodes only what the confirmation reads. The full
// swarmStackFile types volumes as strings, but hardenService always adds a
// tmpfs volume in long syntax, so every production stack failed to decode and
// no release was ever confirmed. Labels stay untyped: a stack that is not a
// Hashvault release may write them as a list, and must not fail here.
type rootHashvaultStack struct {
	Services map[string]struct {
		Labels  any   `yaml:"labels"`
		Secrets []any `yaml:"secrets"`
	} `yaml:"services"`
	Secrets map[string]any `yaml:"secrets"`
}

// rootSecretMount is one secret file as Swarm materialises it inside a task.
type rootSecretMount struct {
	Name   string
	Target string
	UID    string
	GID    string
	Mode   uint32
}

// rootStackSecretMounts resolves every service's secret references the way
// `docker stack deploy` does: target defaults to the source, owner to 0:0 and
// mode to 0444; an external secret keeps its key (or its explicit name), any
// other one is prefixed with the stack name.
func rootStackSecretMounts(app string, body []byte) (map[string][]rootSecretMount, error) {
	var stack rootHashvaultStack
	if err := yaml.Unmarshal(body, &stack); err != nil {
		return nil, err
	}
	names := map[string]string{}
	for key, raw := range stack.Secrets {
		definition, _ := raw.(map[string]any)
		name, _ := definition["name"].(string)
		// The deprecated `external: {name: x}` form is still accepted by the
		// docker loader, which resolves it to x. Reading it as an internal
		// secret would wait forever for an `<app>_<key>` object.
		external := definition["external"] == true
		if legacy, ok := definition["external"].(map[string]any); ok {
			external = true
			if legacyName, _ := legacy["name"].(string); strings.TrimSpace(name) == "" {
				name = legacyName
			}
		}
		switch {
		case strings.TrimSpace(name) != "":
		case external:
			name = key
		default:
			name = app + "_" + key
		}
		names[key] = name
	}
	result := map[string][]rootSecretMount{}
	for service, definition := range stack.Services {
		mounts := []rootSecretMount{}
		for _, raw := range definition.Secrets {
			mount := rootSecretMount{UID: "0", GID: "0", Mode: 0o444}
			source := ""
			switch reference := raw.(type) {
			case string:
				source = reference
			case map[string]any:
				source, _ = reference["source"].(string)
				mount.Target, _ = reference["target"].(string)
				if value, ok := reference["uid"]; ok {
					mount.UID = fmt.Sprint(value)
				}
				if value, ok := reference["gid"]; ok {
					mount.GID = fmt.Sprint(value)
				}
				if value, ok := reference["mode"]; ok {
					mode, ok := rootSecretMode(value)
					if !ok {
						return nil, fmt.Errorf("service %s declares an invalid secret mode", service)
					}
					mount.Mode = mode
				}
			default:
				return nil, fmt.Errorf("service %s declares an invalid secret reference", service)
			}
			name, ok := names[source]
			if !ok {
				return nil, fmt.Errorf("service %s mounts undeclared secret %q", service, source)
			}
			mount.Name = name
			if mount.Target == "" {
				mount.Target = source
			}
			mounts = append(mounts, mount)
		}
		sortRootSecretMounts(mounts)
		result[service] = mounts
	}
	return result, nil
}

func rootSecretMode(value any) (uint32, bool) {
	switch typed := value.(type) {
	case int:
		return uint32(typed), typed >= 0 && typed <= 0o777
	case int64:
		return uint32(typed), typed >= 0 && typed <= 0o777
	case uint64:
		return uint32(typed), typed <= 0o777
	}
	return 0, false
}

func sortRootSecretMounts(mounts []rootSecretMount) {
	sort.Slice(mounts, func(i, j int) bool {
		if mounts[i].Target != mounts[j].Target {
			return mounts[i].Target < mounts[j].Target
		}
		return mounts[i].Name < mounts[j].Name
	})
}

// parseRootTaskSecrets reads one line of
// `docker inspect --type task --format '{{json .Spec.ContainerSpec.Secrets}}'`.
func parseRootTaskSecrets(line string) ([]rootSecretMount, error) {
	var raw []struct {
		SecretName string
		File       *struct {
			Name string
			UID  string
			GID  string
			Mode uint32
		}
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &raw); err != nil {
		return nil, fmt.Errorf("task secrets are unreadable: %w", err)
	}
	mounts := make([]rootSecretMount, 0, len(raw))
	for _, item := range raw {
		if item.File == nil {
			return nil, errors.New("task mounts a secret without a file target")
		}
		mounts = append(mounts, rootSecretMount{Name: item.SecretName, Target: item.File.Name, UID: item.File.UID, GID: item.File.GID, Mode: item.File.Mode})
	}
	sortRootSecretMounts(mounts)
	return mounts, nil
}

// rootSecretMountsDiffer names the first difference, or returns "".
func rootSecretMountsDiffer(want, got []rootSecretMount) string {
	for i := 0; i < len(want) || i < len(got); i++ {
		switch {
		case i >= len(got):
			return fmt.Sprintf("misses %s at %s", want[i].Name, want[i].Target)
		case i >= len(want):
			return fmt.Sprintf("still mounts %s at %s", got[i].Name, got[i].Target)
		case want[i] != got[i]:
			return fmt.Sprintf("mounts %s at %s (%s:%s %04o), the applied stack asks for %s at %s (%s:%s %04o)",
				got[i].Name, got[i].Target, got[i].UID, got[i].GID, got[i].Mode,
				want[i].Name, want[i].Target, want[i].UID, want[i].GID, want[i].Mode)
		}
	}
	return ""
}

// rootHashvaultMountsPending returns why the release is not serving the
// declared mounts yet, or "" once it is.
//
// The convergence verdict is re-evaluated first, on every poll: matching
// secrets on a task that is still Preparing or Starting, or on no task at all,
// is not "serving". Only once a service has its replicas running on the
// applied image are their mounts compared.
func rootHashvaultMountsPending(ctx context.Context, app string, wanted []rootStackService, mounts map[string][]rootSecretMount) (string, error) {
	roster, err := rootServiceRosterNow(ctx, app)
	if err != nil {
		return "", err
	}
	for _, want := range wanted {
		tasks, err := rootServiceTasksNow(ctx, want.Service)
		if err != nil {
			return "", err
		}
		entry, listed := roster[want.Service]
		if verdict := evaluateRootServiceConvergence(want, entry, listed, tasks); !verdict.Converged {
			return want.Name + ": " + verdict.Reason, nil
		}
		ids := []string{}
		for _, task := range tasks {
			if !rootTaskStateIs(task.DesiredState, "running") {
				continue
			}
			// The ID reaches an argument list: one starting with a dash would
			// become a flag.
			if !rootTaskID.MatchString(task.ID) {
				return "", fmt.Errorf("service %s lists an invalid task id", want.Name)
			}
			ids = append(ids, task.ID)
		}
		if len(ids) == 0 {
			// Converged with nothing wanted running: scaled to zero.
			continue
		}
		args := append([]string{"inspect", "--type", "task", "--format", "{{json .Spec.ContainerSpec.Secrets}}"}, ids...)
		body, err := rootDockerRead(ctx, args...)
		if err != nil {
			return "", err
		}
		lines := strings.Split(strings.TrimSpace(body), "\n")
		if len(lines) != len(ids) {
			return "", fmt.Errorf("service %s: docker described %d of %d tasks", want.Name, len(lines), len(ids))
		}
		for i, line := range lines {
			got, err := parseRootTaskSecrets(line)
			if err != nil {
				return "", err
			}
			if reason := rootSecretMountsDiffer(mounts[want.Name], got); reason != "" {
				return fmt.Sprintf("task %s of %s %s", ids[i], want.Name, reason), nil
			}
		}
	}
	return "", nil
}

// waitRootHashvaultMounts polls until the release serves its declared mounts
// or ctx expires. The caller owns the deadline: it is part of a budget the
// client's transport timeout already accounts for.
func waitRootHashvaultMounts(ctx context.Context, app string, body []byte) error {
	mounts, err := rootStackSecretMounts(app, body)
	if err != nil {
		return err
	}
	wanted, err := rootStackServices(app, body)
	if err != nil {
		return err
	}
	start := time.Now()
	for {
		reason, err := rootHashvaultMountsPending(ctx, app, wanted, mounts)
		if err == nil && reason == "" {
			return nil
		}
		if err == nil {
			err = errors.New("the release is not serving the prepared secrets yet: " + reason)
		}
		select {
		case <-ctx.Done():
			// Rolling tasks or a transient docker read: retryable.
			return deferHashvault(err)
		case <-time.After(rootStackPollInterval(time.Since(start))):
		}
	}
}
