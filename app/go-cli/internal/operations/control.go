package operations

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Root returns the journal directory for stores sharing this coordinator's
// flock. It does not create or inspect any filesystem entry.
func (c *Coordinator) Root() string { return c.root }

// RequireLive returns a reservation only while its active lease and host boot
// identity remain valid. Unlike a phase transition, this read never turns a
// stale record into recovery_required.
func (c *Coordinator) RequireLive(ctx context.Context, id string) (Record, error) {
	if !identifierPattern.MatchString(id) {
		return Record{}, errors.New("invalid operation id")
	}
	var record Record
	err := c.withLock(ctx, func() error {
		var err error
		record, err = c.readRecord(id)
		if err != nil {
			return err
		}
		if record.State != "active" || record.RecoveryRequired {
			return errors.New("operation reservation is not live and active")
		}
		boot, err := c.bootID()
		if err != nil {
			return err
		}
		if stale(record, c.now().UTC(), boot) {
			return errors.New("operation lease or host boot is stale")
		}
		return nil
	})
	return record, err
}

// WithWriterInventory keeps restrictive closure available after a phase fails.
// Only admitting a new writer requires a live lease; closing existing writers
// never revives the reservation or changes recovery_required to success.
func (c *Coordinator) WithWriterInventory(ctx context.Context, request PhaseRequest, admit bool, update func(Record) error) error {
	if err := validatePhaseRequest(request); err != nil {
		return err
	}
	return c.withLock(ctx, func() error {
		record, err := c.readRecord(request.ID)
		if err != nil {
			return err
		}
		if record.Principal != request.Principal || record.Kind != request.Kind || record.App != request.App || record.OwnerKeyFingerprint != request.OwnerKeyFingerprint || record.Host != request.Host {
			return errors.New("writer inventory identity does not match the reservation")
		}
		now := c.now().UTC()
		if !request.PlanExpiresAt.After(now) || request.HostIdentity == "" || request.HostIdentity != record.Host {
			return errors.New("writer inventory request expired or belongs to another host")
		}
		if request.Validate != nil {
			if err := request.Validate(record); err != nil {
				return err
			}
		}
		if record.State != "active" && record.State != RecoveryRequired {
			return errors.New("writer inventory operation is already terminal")
		}
		if admit {
			boot, err := c.bootID()
			if err != nil {
				return err
			}
			if record.State != "active" || record.RecoveryRequired || stale(record, now, boot) {
				return errors.New("new writers require a live active reservation")
			}
		}
		if err := update(record); err != nil {
			return err
		}
		record.UpdatedAt = now.Format(time.RFC3339Nano)
		c.appendEvent(&record, now, request.Name, "", record.RecoveryRequired)
		return c.writeRecord(record)
	})
}

// Control validates a freshly signed client control under the same flock as
// the durable transition. It never revives an expired or recovered owner.
func (c *Coordinator) Control(ctx context.Context, request PhaseRequest, action, result string) error {
	return c.ControlWithLockedCompletion(ctx, request, action, result, nil)
}

// ControlWithLockedCompletion runs the narrow local completion hook only after
// the terminal journal is durable, while the same coordinator flock is held.
func (c *Coordinator) ControlWithLockedCompletion(ctx context.Context, request PhaseRequest, action, result string, completed func(Record) error) error {
	if err := validatePhaseRequest(request); err != nil {
		return err
	}
	if action != "renew" && action != "finish" && action != "abort" && action != "refuse" {
		return errors.New("unknown operation control")
	}
	return c.withLock(ctx, func() error {
		record, err := c.readRecord(request.ID)
		if err != nil {
			return err
		}
		if err := c.validatePhaseIdentity(record, request); err != nil {
			return err
		}
		now := c.now().UTC()
		if request.PlanExpiresAt.IsZero() || !request.PlanExpiresAt.After(now) {
			return errors.New("signed operation control expired before lock acquisition")
		}
		if request.HostIdentity == "" || request.HostIdentity != record.Host {
			return errors.New("operation control host identity mismatch")
		}
		if request.Validate != nil {
			if err := request.Validate(record); err != nil {
				return err
			}
		}
		if record.State != "active" || record.RecoveryRequired {
			return errors.New("operation control requires a live active reservation")
		}
		boot, err := c.bootID()
		if err != nil {
			return err
		}
		if stale(record, now, boot) {
			if action == "refuse" {
				return errors.New("operation refuse requires a live reservation")
			}
			record, err = c.markStale(record, now)
			if err != nil {
				return err
			}
			if err := c.writeRecord(record); err != nil {
				return err
			}
			return errors.New("operation lease or boot expired; recovery required")
		}
		if hasKnownFailedCommand(record) {
			if action == "finish" {
				return errors.New("operation finish cannot complete a known failed operation")
			}
			if action == "renew" && request.Name != "client-renew" {
				return errors.New("a known failed operation permits only a phase-less client renew")
			}
		}
		record.UpdatedAt = now.Format(time.RFC3339Nano)
		if action == "refuse" {
			switch record.Kind {
			case "run":
				if !runRefusalPhasesValid(record) {
					return errors.New("operation refuse requires a run with only completed writers-initialize phases")
				}
			case "helper-update":
				// A scan has no phase. A completed, known policy refusal also
				// precedes replacement; uncertain probes never carry Known.
				if len(record.Phases) != 0 && !(len(record.Phases) == 1 && record.Phases[0].Name == "helper-update" && record.Phases[0].Known && record.Phases[0].EndedAt != "" && record.Phases[0].Error != "") {
					return errors.New("operation refuse requires a helper-update with no mutation phase or a known candidate refusal")
				}
			case "destroy":
				if !destroyRefusalPhasesValid(record) {
					return errors.New("destroy refusal requires a settled helper outcome")
				}
			case "deploy":
				if !DeployRefusalPhasesValid(record) {
					return errors.New("operation refuse requires a deploy with only completed no-mutation phases")
				}
			default:
				return fmt.Errorf("operation refuse is not valid for kind %s", record.Kind)
			}
		}
		switch action {
		case "renew":
			record.LeaseUntil = now.Add(c.lease).Format(time.RFC3339Nano)
			if request.Name != "client-renew" {
				record.Phases = append(record.Phases, Phase{Name: request.Name, StartedAt: now.Format(time.RFC3339Nano), EndedAt: now.Format(time.RFC3339Nano), Result: cleanReason(result)})
			}
			c.appendEvent(&record, now, "client-renew", "", false)
		case "finish":
			record.State = "completed"
			record.Result = cleanReason(result)
			record.LeaseUntil = ""
			c.appendEvent(&record, now, "completed", "", false)
		case "abort":
			record.State = RecoveryRequired
			record.RecoveryRequired = true
			record.Result = cleanReason(result)
			record.LeaseUntil = ""
			record.RecoveryActions = []string{"observe actual service state", "verify registry health and retained releases", "confirm all writers stopped"}
			c.appendEvent(&record, now, RecoveryRequired, "", true)
		case "refuse":
			record.State = "failed"
			record.RecoveryRequired = false
			record.Result = cleanReason(result)
			record.LeaseUntil = ""
			c.appendEvent(&record, now, "refused", "", false)
		}
		if err := c.writeRecord(record); err != nil {
			return err
		}
		if action == "finish" && completed != nil {
			return completed(record)
		}
		return nil
	})
}

func runRefusalPhasesValid(record Record) bool {
	if record.Kind != "run" || len(record.Phases) == 0 {
		return false
	}
	writers := 0
	for i, phase := range record.Phases {
		if i == len(record.Phases)-1 && phase.Name == "run" {
			return writers > 0 && phase.EndedAt != "" && phase.Error != "" && phase.Known
		}
		if phase.Name != "writers-initialize" || phase.EndedAt == "" || phase.Error != "" || phase.Known {
			return false
		}
		writers++
	}
	return writers > 0
}

// DeployRefusalPhasesValid accepts only journal evidence that a deploy never
// reached a helper mutation. stack-reclaim may remove superseded images and
// set Swarm task history, but it makes no service or stack mutation. A secrets
// phase publishes Docker objects, so it and every unknown or stack-apply phase
// disqualify a refusal. The client progress phases are accepted only with
// their exact terminal results, and a completed writers initialization is
// always required before the helper may release the reservation.
func DeployRefusalPhasesValid(record Record) bool {
	if record.Kind != "deploy" || len(record.Phases) == 0 {
		return false
	}
	writers := 0
	for _, phase := range record.Phases {
		if phase.EndedAt == "" || phase.Error != "" || phase.Known {
			return false
		}
		switch phase.Name {
		case "writers-initialize":
			writers++
		case "stack-reclaim":
			// This sweep may delete superseded images and set the Swarm task
			// history limit, but it makes no service or stack mutation.
		case "client-promotion":
			if phase.Result != "not-started" {
				return false
			}
		case "client-cleanup":
			if phase.Result != "completed" {
				return false
			}
		default:
			return false
		}
	}
	return writers > 0
}

// A destroy may fail before mutation or finish while keeping databases after a
// failed dump. Only the helper's durable known outcome allows release in both
// cases; an arbitrary client error must still require explicit recovery.
func destroyRefusalPhasesValid(record Record) bool {
	writers := 0
	for i, phase := range record.Phases {
		if i == len(record.Phases)-1 && phase.Name == "stack-apply" {
			return writers > 0 && phase.EndedAt != "" && phase.Error != "" && phase.Known
		}
		if phase.Name != "writers-initialize" || phase.EndedAt == "" || phase.Error != "" || phase.Known {
			return false
		}
		writers++
	}
	return false
}
