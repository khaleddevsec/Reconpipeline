package correlation

import (
	"context"
	"fmt"
	"strings"

	"github.com/khaleddevsec/Reconpipeline/internal/knowledge"
	"github.com/khaleddevsec/Reconpipeline/models"
	"go.uber.org/zap"
)

// HeaderCorrelator implements Engine by correlating missing headers,
// weak TLS, and fingerprinted technologies with the knowledge DB.
type HeaderCorrelator struct {
	db  knowledge.DB
	log *zap.Logger
}

// NewHeaderCorrelator constructs a HeaderCorrelator.
func NewHeaderCorrelator(db knowledge.DB, log *zap.Logger) *HeaderCorrelator {
	return &HeaderCorrelator{db: db, log: log}
}

// Correlate examines collected data and fingerprints and returns findings.
func (c *HeaderCorrelator) Correlate(_ context.Context, result *models.ScanResult) ([]models.Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("correlation: nil scan result")
	}

	var rawFindings []models.Finding

	// correlate missing/misconfigured security headers (injected by the parser as _missing_<name>)
	for key := range result.CollectedData.Headers {
		if !strings.HasPrefix(key, "_missing_") {
			continue
		}
		headerName := strings.TrimPrefix(key, "_missing_")
		// convert back to canonical form for DB lookup
		canonical := canonicalHeader(headerName)
		dbFindings, err := c.db.FindingsForHeader(canonical, "")
		if err != nil {
			c.log.Warn("correlation: header lookup failed",
				zap.String("header", canonical), zap.Error(err))
			continue
		}
		rawFindings = append(rawFindings, dbFindings...)
	}

	// correlate TLS weaknesses
	if result.CollectedData.TLS != nil {
		tlsFindings, err := c.db.FindingsForTLS(result.CollectedData.TLS)
		if err != nil {
			c.log.Warn("correlation: TLS lookup failed", zap.Error(err))
		} else {
			rawFindings = append(rawFindings, tlsFindings...)
		}
	}

	// correlate fingerprints
	for _, fp := range result.Fingerprints {
		fpFindings, err := c.db.FindingsForFingerprint(fp)
		if err != nil {
			c.log.Warn("correlation: fingerprint lookup failed",
				zap.String("name", fp.Name), zap.Error(err))
			continue
		}
		rawFindings = append(rawFindings, fpFindings...)
	}

	// deduplicate findings by ID
	seen := make(map[string]bool, len(rawFindings))
	var findings []models.Finding
	for _, f := range rawFindings {
		if f.ID != "" && seen[f.ID] {
			continue
		}
		if f.ID != "" {
			seen[f.ID] = true
		}
		findings = append(findings, f)
	}

	c.log.Debug("correlated",
		zap.String("target", result.Target.URL),
		zap.Int("findings", len(findings)))
	return findings, nil
}

// canonicalHeader converts a lowercase header key to its canonical title case form.
func canonicalHeader(lower string) string {
	parts := strings.Split(lower, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}
