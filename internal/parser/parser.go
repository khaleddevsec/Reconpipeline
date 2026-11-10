package parser

import (
	"context"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
)

// Parser normalises raw CollectedData into clean, enriched internal models.
type Parser interface {
	Parse(ctx context.Context, data *models.CollectedData) (*models.CollectedData, error)
}
