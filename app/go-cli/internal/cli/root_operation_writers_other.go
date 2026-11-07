//go:build !linux

package cli

import (
	"context"
	"errors"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
)

func controlRootOperationWriters(context.Context, rootplan.Plan) ([]byte, error) {
	return nil, errors.New("root writer inventory requires Linux")
}
