package operationwriters

import (
	"context"
	"fmt"
	"sort"
)

type localFenceInput struct {
	binding          Binding
	generation       uint64
	admissionsClosed bool
	groups           []LocalGroup
	writerIDs        []string
	procRoot         string
}

func normalizeLocalSnapshot(snapshot any) (localFenceInput, error) {
	var input localFenceInput
	skippedClientOrigin := false
	switch value := snapshot.(type) {
	case State:
		if err := validateState(value); err != nil {
			return input, err
		}
		input.binding = value.Binding
		input.generation = value.Binding.Generation
		input.admissionsClosed = value.Admissions == AdmissionsClosed
		for _, writer := range value.Writers {
			switch writer.Kind {
			case WriterKindLocalGroup:
				input.writerIDs = append(input.writerIDs, writer.ID)
				input.groups = append(input.groups, *writer.Local)
			case WriterKindClientOrigin:
				skippedClientOrigin = true
			}
		}
	case *State:
		if value == nil {
			return input, fmt.Errorf("%w: nil local state", ErrInvalidState)
		}
		return normalizeLocalSnapshot(*value)
	case LocalSnapshot:
		input.binding = value.Binding
		input.generation = value.Generation
		if input.generation == 0 {
			input.generation = value.Binding.Generation
		}
		if value.Binding != (Binding{}) {
			if err := validateBinding(value.Binding); err != nil {
				return input, err
			}
			if value.Generation != 0 && value.Generation != value.Binding.Generation {
				return input, fmt.Errorf("%w: local snapshot generation does not match binding", ErrInvalidState)
			}
		}
		input.admissionsClosed = value.AdmissionsClosed
		input.groups = append(input.groups, value.Groups...)
		input.procRoot = value.ProcRoot
	case *LocalSnapshot:
		if value == nil {
			return input, fmt.Errorf("%w: nil local snapshot", ErrInvalidState)
		}
		return normalizeLocalSnapshot(*value)
	case []LocalGroup:
		input.groups = append(input.groups, value...)
	case LocalGroup:
		input.groups = []LocalGroup{value}
	default:
		return input, fmt.Errorf("%w: expected State or LocalSnapshot", ErrInvalidState)
	}
	if input.procRoot == "" {
		input.procRoot = "/proc"
	}
	if len(input.groups) == 0 {
		if skippedClientOrigin {
			return input, fmt.Errorf("%w: client_origin groups are not VPS-local and cannot be inspected or fenced", ErrInvalidState)
		}
		return input, fmt.Errorf("%w: no local groups were registered", ErrInvalidState)
	}
	if input.generation == 0 {
		return input, fmt.Errorf("%w: local snapshot has no generation", ErrInvalidState)
	}
	seenGroups := make(map[LocalGroup]struct{}, len(input.groups))
	for _, group := range input.groups {
		if err := validateLocalGroup(group); err != nil {
			return input, err
		}
		if _, exists := seenGroups[group]; exists {
			return input, fmt.Errorf("%w: duplicate local group", ErrInvalidState)
		}
		seenGroups[group] = struct{}{}
	}
	if len(input.writerIDs) == 0 {
		input.writerIDs = make([]string, len(input.groups))
		for i := range input.groups {
			input.writerIDs[i] = fmt.Sprintf("local-group-%d", i)
		}
	}
	if len(input.writerIDs) != len(input.groups) {
		return input, fmt.Errorf("%w: local writer inventory and group inventory differ", ErrInvalidState)
	}
	return input, nil
}

func localInspectionSort(inspection *LocalInspection) {
	sort.Slice(inspection.Groups, func(i, j int) bool {
		return inspection.Groups[i].Group.LeaderPID < inspection.Groups[j].Group.LeaderPID
	})
	for i := range inspection.Groups {
		sort.Slice(inspection.Groups[i].Members, func(left, right int) bool {
			return inspection.Groups[i].Members[left].PID < inspection.Groups[i].Members[right].PID
		})
	}
}

func contextWithFenceDeadline(ctx context.Context) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, DefaultFenceTimeout)
}
