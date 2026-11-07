package operations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// RegistryReplacement retains the approved image and the observed data volume
// before stop/rm. The container cannot supply either proof after a crash in the
// replacement gap. VolumeSHA256 binds stable Docker volume metadata; the name,
// loopback port and hardening remain fixed helper policy, not journal inputs.
type RegistryReplacement struct {
	Image        string `json:"image"`
	VolumeSHA256 string `json:"volume_sha256"`
}

var registryReplacementImage = regexp.MustCompile(`^registry:[0-9][A-Za-z0-9._-]*@sha256:[0-9a-f]{64}$`)

func (intent RegistryReplacement) Validate() error {
	if len(intent.Image) > 256 || !registryReplacementImage.MatchString(intent.Image) || !digestPattern.MatchString(intent.VolumeSHA256) {
		return errors.New("registry replacement image or volume proof is invalid")
	}
	return nil
}

// JournalRegistryReplacement must precede the sole-operation callback: a
// concurrent phase needs the journal flock to persist this proof, whereas that
// callback already holds it. A deferred replacement may retain an unused intent;
// recovery still requires a missing container and the exact observed volume.
func JournalRegistryReplacement(ctx context.Context, intent RegistryReplacement) error {
	journal, ok := ctx.Value(phaseJournalKey{}).(*phaseJournal)
	if !ok || journal == nil {
		return errors.New("registry replacement can be journaled only from inside an executing phase")
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	c := journal.c
	return journal.hold(func() error {
		c.lockJournal("registry-replacement")
		defer c.unlockJournal()
		latest, err := c.readRecord(journal.request.ID)
		if err != nil {
			return err
		}
		if err := c.validatePhaseIdentity(latest, journal.request); err != nil {
			return err
		}
		if journal.request.Kind != "deploy" || journal.request.Name != "stack-apply" || len(latest.Phases) == 0 || latest.Phases[len(latest.Phases)-1].Name != "stack-apply" || latest.Phases[len(latest.Phases)-1].EndedAt != "" {
			return errors.New("registry replacement requires an open deploy stack-apply phase")
		}
		if latest.RegistryReplacement != nil {
			if *latest.RegistryReplacement == intent {
				return nil
			}
			return errors.New("registry replacement is already journaled for this operation")
		}
		latest.RegistryReplacement = &intent
		latest.UpdatedAt = c.now().UTC().Format(time.RFC3339Nano)
		if err := c.writeRecordLocked(latest); err != nil {
			return fmt.Errorf("durably record registry replacement: %w", err)
		}
		return nil
	})
}
