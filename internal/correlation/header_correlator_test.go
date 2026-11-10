package correlation_test

import (
	"context"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/correlation"
	"github.com/khaleddevsec/Reconpipeline/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// stubDB is a minimal knowledge.DB for testing.
type stubDB struct{}

func (s *stubDB) FindingsForHeader(name, _ string) ([]models.Finding, error) {
	if name == "Content-Security-Policy" {
		return []models.Finding{{ID: "CSP-MISSING", Title: "Missing CSP", Severity: models.SeverityHigh}}, nil
	}
	return nil, nil
}
func (s *stubDB) FindingsForFingerprint(_ models.Fingerprint) ([]models.Finding, error) {
	return nil, nil
}
func (s *stubDB) FindingsForTLS(tls *models.TLSInfo) ([]models.Finding, error) {
	if tls != nil && tls.WeakProtocol {
		return []models.Finding{{ID: "TLS-WEAK", Title: "Weak TLS", Severity: models.SeverityHigh}}, nil
	}
	return nil, nil
}
func (s *stubDB) Integrity() error { return nil }
func (s *stubDB) Version() string  { return "test" }

func TestHeaderCorrelator_MissingCSP(t *testing.T) {
	result := &models.ScanResult{
		Target: models.Target{URL: "http://example.com"},
		CollectedData: models.CollectedData{
			Headers: map[string][]string{
				"_missing_content-security-policy": {""},
			},
		},
	}

	c := correlation.NewHeaderCorrelator(&stubDB{}, zap.NewNop())
	findings, err := c.Correlate(context.Background(), result)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "CSP-MISSING", findings[0].ID)
}

func TestHeaderCorrelator_WeakTLS(t *testing.T) {
	result := &models.ScanResult{
		Target: models.Target{URL: "https://example.com"},
		CollectedData: models.CollectedData{
			Headers: map[string][]string{},
			TLS:     &models.TLSInfo{Version: "TLS 1.0", WeakProtocol: true},
		},
	}

	c := correlation.NewHeaderCorrelator(&stubDB{}, zap.NewNop())
	findings, err := c.Correlate(context.Background(), result)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "TLS-WEAK", findings[0].ID)
}
