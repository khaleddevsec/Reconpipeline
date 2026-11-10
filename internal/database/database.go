package database

import (
	"context"

	"github.com/khaleddevsec/Reconpipeline/models"
)

// Store persists and retrieves scan results.
type Store interface {
	SaveResult(ctx context.Context, result *models.ScanResult) error
	GetResult(ctx context.Context, id string) (*models.ScanResult, error)
	ListResults(ctx context.Context) ([]models.ScanResult, error)
	Close() error
}
