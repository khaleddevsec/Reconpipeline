package knowledge

import (
	"github.com/khaleddevsec/Reconpipeline/models"
)

// DB defines the interface for the offline knowledge database.
// All lookups are local — no live internet calls are made during a scan.
type DB interface {
	// FindingsForHeader returns findings for a response header name/value pair.
	FindingsForHeader(name, value string) ([]models.Finding, error)
	// FindingsForFingerprint returns findings for a detected technology.
	FindingsForFingerprint(fp models.Fingerprint) ([]models.Finding, error)
	// FindingsForTLS returns findings for a TLS configuration.
	FindingsForTLS(tls *models.TLSInfo) ([]models.Finding, error)
	// Integrity verifies the DB files have not been corrupted or tampered with.
	Integrity() error
	// Version returns the knowledge DB version string.
	Version() string
}
