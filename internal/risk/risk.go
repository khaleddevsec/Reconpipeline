package risk

import (
	"context"

	"github.com/khaleddevsec/Reconpipeline/models"
)

// Engine calculates risk scores and produces remediation recommendations.
type Engine interface {
	Score(ctx context.Context, result *models.ScanResult) (float64, error)
	Recommend(ctx context.Context, finding models.Finding) (string, error)
}
