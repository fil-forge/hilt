package usage

import (
	"fmt"

	"github.com/fil-forge/hilt/pkg/store"
)

func invalid(reason string) error {
	return fmt.Errorf("egress count: %s: %w", reason, store.ErrInvalidArgument)
}
