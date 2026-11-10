package collector

import (
	"context"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
)

// Collector defines the contract for raw HTTP metadata collection.
// Implementations must NOT perform any analysis — raw data only.
type Collector interface {
	Collect(ctx context.Context, target models.Target) (*models.CollectedData, error)
}
