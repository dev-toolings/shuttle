package operationwriters

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// InitializeLocked creates the state before the first writer is allowed to
// mutate. Calling it again with the exact binding and baseline is idempotent.
// The caller must already hold /run/shuttle-root.lock or its equivalent.
func (s *Store) InitializeLocked(binding Binding, baseline Baseline) (State, error) {
	if err := validateBinding(binding); err != nil {
		return State{}, err
	}
	if err := validateBaseline(baseline); err != nil {
		return State{}, err
	}
	dir, err := openWriterDir(s.root)
	if err != nil {
		return State{}, err
	}
	defer dir.Close()

	state, err := s.readLocked(dir, binding)
	if err == nil {
		if sameBinding(state.Binding, binding) && sameBaseline(state.Baseline, baseline) {
			return state, nil
		}
		return State{}, fmt.Errorf("%w: operation already has a different binding or baseline", ErrConflict)
	}
	if !errors.Is(err, ErrNotFound) {
		return State{}, err
	}
	state = State{
		Schema: Schema, Binding: binding, Revision: 1, Admissions: AdmissionsOpen,
		Writers: []Writer{}, Baseline: baseline,
	}
	if err := validateState(state); err != nil {
		return State{}, err
	}
	if err := writeStateAt(dir, binding.OperationID, state, s.maxBytes, s.sync); err != nil {
		return State{}, err
	}
	return state, nil
}

// RegisterLocked durably records a writer before the caller starts its first
// mutation. A repeated exact registration is idempotent. Once admissions are
// closed, an unregistered writer cannot be added.
func (s *Store) RegisterLocked(binding Binding, writer Writer) (State, error) {
	if err := validateBinding(binding); err != nil {
		return State{}, err
	}
	if err := validateWriter(writer); err != nil {
		return State{}, err
	}
	dir, err := openWriterDir(s.root)
	if err != nil {
		return State{}, err
	}
	defer dir.Close()
	state, err := s.readLocked(dir, binding)
	if err != nil {
		return State{}, err
	}
	for _, existing := range state.Writers {
		if existing.ID != writer.ID {
			continue
		}
		if sameWriter(existing, writer) {
			return state, nil
		}
		return State{}, fmt.Errorf("%w: writer id %q was registered with different identity", ErrConflict, writer.ID)
	}
	if state.Admissions == AdmissionsClosed {
		return State{}, fmt.Errorf("%w: writer %q arrived after closure", ErrAdmissionsClosed, writer.ID)
	}
	state.Writers = append(state.Writers, writer)
	state.Revision++
	if err := validateState(state); err != nil {
		return State{}, err
	}
	if err := writeStateAt(dir, binding.OperationID, state, s.maxBytes, s.sync); err != nil {
		return State{}, err
	}
	return state, nil
}

// CloseAdmissionsLocked makes the registered inventory immutable. It is an
// irreversible transition. Repeating it returns the existing state.
func (s *Store) CloseAdmissionsLocked(binding Binding) (State, error) {
	if err := validateBinding(binding); err != nil {
		return State{}, err
	}
	dir, err := openWriterDir(s.root)
	if err != nil {
		return State{}, err
	}
	defer dir.Close()
	state, err := s.readLocked(dir, binding)
	if err != nil {
		return State{}, err
	}
	if state.Admissions == AdmissionsClosed {
		return state, nil
	}
	state.Admissions = AdmissionsClosed
	state.Revision++
	if err := validateState(state); err != nil {
		return State{}, err
	}
	if err := writeStateAt(dir, binding.OperationID, state, s.maxBytes, s.sync); err != nil {
		return State{}, err
	}
	return state, nil
}

// CommitClosureLocked stores a complete terminal inventory. Every registered
// writer needs one typed receipt for the same generation. A repeated semantic
// proof is idempotent, even when its observation timestamps differ; timestamps
// are freshness evidence and are excluded from the canonical proof digest.
func (s *Store) CommitClosureLocked(binding Binding, receipts []Receipt) (State, error) {
	if err := validateBinding(binding); err != nil {
		return State{}, err
	}
	dir, err := openWriterDir(s.root)
	if err != nil {
		return State{}, err
	}
	defer dir.Close()
	state, err := s.readLocked(dir, binding)
	if err != nil {
		return State{}, err
	}
	if state.Admissions != AdmissionsClosed {
		return State{}, fmt.Errorf("%w: closure cannot precede admissions closure", ErrConflict)
	}
	if err := validateReceipts(binding, state.Writers, receipts, s.nowUTC(), s.receiptMaxAge, s.clockSkew); err != nil {
		return State{}, err
	}
	proofHash, err := canonicalProofHash(binding, state.Baseline, state.Writers, receipts)
	if err != nil {
		return State{}, fmt.Errorf("%w: canonical proof: %v", ErrInvalidReceipt, err)
	}
	if state.Closure != nil {
		if state.Closure.ProofHash == proofHash {
			return state, nil
		}
		return State{}, fmt.Errorf("%w: a different terminal inventory is already committed", ErrConflict)
	}
	state.Closure = &Closure{
		Generation: binding.Generation,
		ClosedAt:   formatTime(s.nowUTC()),
		Receipts:   append([]Receipt{}, receipts...),
		ProofHash:  proofHash,
	}
	state.Revision++
	if err := validateState(state); err != nil {
		return State{}, err
	}
	if err := writeStateAt(dir, binding.OperationID, state, s.maxBytes, s.sync); err != nil {
		return State{}, err
	}
	return state, nil
}

// Read obtains one validated state. It does not acquire the coordination
// flock. Callers that need a coherent transition must keep their existing
// global lock while calling Read.
func (s *Store) Read(binding Binding) (State, error) {
	if err := validateBinding(binding); err != nil {
		return State{}, err
	}
	dir, err := openWriterDirMode(s.root, false)
	if err != nil {
		return State{}, err
	}
	defer dir.Close()
	return s.readLocked(dir, binding)
}

func (s *Store) readLocked(dir *writerDir, binding Binding) (State, error) {
	data, err := readStateAt(dir, binding.OperationID, s.maxBytes)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return State{}, ErrNotFound
		}
		return State{}, err
	}
	state, err := decodeState(data)
	if err != nil {
		return State{}, err
	}
	if err := validateState(state); err != nil {
		return State{}, err
	}
	if !sameBinding(state.Binding, binding) {
		return State{}, fmt.Errorf("%w: state binding does not match requested operation", ErrConflict)
	}
	return state, nil
}

func decodeState(data []byte) (State, error) {
	data, err := stripHistoricalNestedNotes(data)
	if err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state State
	if err = decoder.Decode(&state); err != nil {
		if len(data) >= MaxStateBytes {
			return State{}, fmt.Errorf("%w: decode limit reached: %v", ErrTooLarge, err)
		}
		return State{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return State{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidState)
		}
		return State{}, fmt.Errorf("%w: trailing data: %v", ErrInvalidState, err)
	}
	return state, nil
}

// DecodeState is the shared strict reader for writer state. It accepts the
// historical informational note field wherever an old helper placed it, then
// keeps rejecting every other unknown field.
func DecodeState(data []byte) (State, error) { return decodeState(data) }

func stripHistoricalNestedNotes(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, fmt.Errorf("trailing JSON data: %v", err)
	}
	removeNestedNotes(value, false)
	return json.Marshal(value)
}

func removeNestedNotes(value any, nested bool) {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if nested && key == "note" {
				delete(item, key)
				continue
			}
			removeNestedNotes(child, true)
		}
	case []any:
		for _, child := range item {
			removeNestedNotes(child, true)
		}
	}
}

// jsonState is the on-disk form of a writer state: the canonical encoding plus
// a trailing newline. It lives beside marshalState, outside the platform files,
// because both the Linux store and the portable store write it; kept in
// store_linux.go it left every non-Linux build without it.
func jsonState(state State) ([]byte, error) {
	data, err := marshalState(state)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func marshalState(state State) ([]byte, error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal writer state: %w", err)
	}
	return data, nil
}
