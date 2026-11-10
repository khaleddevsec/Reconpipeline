package fingerprint

import (
	"context"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
)

// Engine identifies technologies (server, framework, CMS, CDN, WAF) from collected data.
type Engine interface {
	Identify(ctx context.Context, data *models.CollectedData) ([]models.Fingerprint, error)
}
