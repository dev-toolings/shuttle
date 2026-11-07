//go:build linux

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
)

var helperMigrationWriterTemporarySuffix = regexp.MustCompile(`^[a-f0-9]{24}\.tmp$`)

// readMigrationWriterProof validates the complete typed closure inventory.
// The returned summary is not the proof itself; Validate verifies every
// receipt, signature, generation and canonical inventory digest first.
func readMigrationWriterProof(path string) (helperMigrationWriterProof, error) {
	return readMigrationWriterProofWithFS(path, newOSHelperMigrationFS())
}

func readMigrationWriterProofWithFS(path string, fs helperMigrationFS) (helperMigrationWriterProof, error) {
	entries, err := fs.readDir(path)
	if err != nil {
		return helperMigrationWriterProof{}, err
	}
	proof := helperMigrationWriterProof{Schema: helperMigrationWriterProofSchema}
	for _, entry := range entries {
		// createStateTemp publishes by rename. A crash before that rename
		// leaves an uncommitted file, not an extra writer or a closure proof.
		// Rejecting it prevented every future helper update after such a crash.
		if strings.HasPrefix(entry.Name(), ".") {
			id, suffix, _ := strings.Cut(entry.Name()[1:], ".")
			if helperMigrationOperationIDPattern.MatchString(id) && helperMigrationWriterTemporarySuffix.MatchString(suffix) {
				if _, err := helperMigrationRegularRootFile(fs, filepath.Join(path, entry.Name()), 0o600, operationwriters.MaxStateBytes); err != nil {
					return proof, err
				}
				continue
			}
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !helperMigrationOperationIDPattern.MatchString(id) {
			return proof, errors.New("unexpected writer inventory entry")
		}
		body, err := readPrivateMigrationJSON(fs, filepath.Join(path, entry.Name()), operationwriters.MaxStateBytes)
		if err != nil {
			return proof, err
		}
		state, err := operationwriters.DecodeState(body)
		if err != nil {
			return proof, err
		}
		if err := state.Validate(); err != nil {
			return proof, err
		}
		if state.Binding.OperationID != id {
			return proof, errors.New("writer inventory filename does not match its operation")
		}
		if _, err := state.ClosedProofHash(); err != nil {
			return proof, fmt.Errorf("writer closure remains unresolved: %w", err)
		}
		journal, err := readPrivateMigrationJSON(fs, filepath.Join(filepath.Dir(path), id+".json"), 256<<10)
		if err != nil {
			return proof, err
		}
		record, err := decodeMigrationJournalRecord(journal)
		if err != nil {
			return proof, err
		}
		if !migrationWriterRecordTerminal(record, id, state.Binding) {
			return proof, errors.New("writer closure does not match a terminal host operation")
		}
		origin := "no-writers"
		for _, writer := range state.Writers {
			switch writer.Kind {
			case operationwriters.WriterKindLocalGroup:
				if origin == "no-writers" {
					origin = "local-vps"
				}
			case operationwriters.WriterKindRemoteRunner:
				if origin != "client-origin" {
					origin = "remote-runner"
				}
			default:
				origin = "client-origin"
			}
		}
		proof.Writers = append(proof.Writers, helperMigrationWriterRecord{OperationID: id, State: "closed", Origin: origin})
	}
	return proof, nil
}

// migrationWriterRecordTerminal says whether the journal record owning a closed
// writer inventory is over. recovery_required counts: the operation has ended
// and only its host state awaits observation, while the closure proof is what
// shows no writer can still act. Refusing it made a helper update impossible
// on exactly the host that needed one to recover (see operations.conflict).
func migrationWriterRecordTerminal(record helperMigrationOperationRecord, id string, binding operationwriters.Binding) bool {
	if record.ID != id || record.Schema != helperMigrationOperationSchema || record.Host != binding.HostKey || record.HostBootID != binding.BootID {
		return false
	}
	switch {
	case record.State == "recovery_required":
		return record.RecoveryRequired
	case record.RecoveryRequired:
		return false
	default:
		return record.State == "completed" || record.State == "failed" || record.State == "recovered"
	}
}

// decodeMigrationJournalRecord reads the complete coordinator record strictly.
// The narrow migration struct refused the "revision" field every modern
// journal carries, so on the recette VPS a helper holding any closed writer
// inventory refused every signed helper update and left a recovery_required
// reservation behind.
func decodeMigrationJournalRecord(body []byte) (helperMigrationOperationRecord, error) {
	var full coord.Record
	if err := decodeSingleJSON(body, &full); err != nil {
		return helperMigrationOperationRecord{}, err
	}
	return helperMigrationOperationRecord{Schema: full.Schema, ID: full.ID, Kind: full.Kind, State: full.State, RecoveryRequired: full.RecoveryRequired, OwnerKeyFingerprint: full.OwnerKeyFingerprint, Principal: full.Principal, LeaseUntil: full.LeaseUntil, Host: full.Host, HostBootID: full.HostBootID}, nil
}

func readPrivateMigrationJSON(fs helperMigrationFS, path string, max int64) ([]byte, error) {
	if _, err := helperMigrationRegularRootFile(fs, path, 0o600, max); err != nil {
		return nil, err
	}
	return helperMigrationReadFile(fs, path, max)
}
