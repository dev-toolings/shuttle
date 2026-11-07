//go:build !linux

package operationwriters

import (
	"context"
	"fmt"
)

func inspectLocalGroups(ctx context.Context, snapshot any) (LocalInspection, error) {
	if _, err := normalizeLocalSnapshot(snapshot); err != nil {
		return LocalInspection{}, err
	}
	return LocalInspection{}, fmt.Errorf("%w: local process-group inspection requires Linux /proc and pidfds", ErrUnsupported)
}

func fenceLocalGroups(ctx context.Context, snapshot any) ([]Receipt, error) {
	if _, err := normalizeLocalSnapshot(snapshot); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: local process-group fencing requires Linux /proc and pidfds", ErrUnsupported)
}
