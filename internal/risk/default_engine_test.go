package risk_test

import (
	"context"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/risk"
	"github.com/khaleddevsec/Reconpipeline/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultEngine_Score_Empty(t *testing.T) {
	result := &models.ScanResult{Target: models.Target{URL: "http://example.com"}}
	score, err := risk.NewDefaultEngine(zap.NewNop()).Score(context.Background(), result)
	require.NoError(t, err)
	assert.Equal(t, 0.0, score)
}

func TestDefaultEngine_Score_AllHigh(t *testing.T) {
	result := &models.ScanResult{
		Target: models.Target{URL: "http://example.com"},
		Findings: []models.Finding{
			{ID: "F1", Severity: models.SeverityHigh, Confidence: 1.0},
			{ID: "F2", Severity: models.SeverityHigh, Confidence: 1.0},
		},
	}
	score, err := risk.NewDefaultEngine(zap.NewNop()).Score(context.Background(), result)
	require.NoError(t, err)
	// First HIGH = 7.5, second HIGH adds 7.5 * 0.15 = 1.125 -> 8.625
	assert.InDelta(t, 8.625, score, 0.01)
}

func TestDefaultEngine_Score_NoSeverityDilution(t *testing.T) {
	eng := risk.NewDefaultEngine(zap.NewNop())

	singleCrit := &models.ScanResult{
		Target: models.Target{URL: "http://example.com"},
		Findings: []models.Finding{
			{ID: "C1", Severity: models.SeverityCritical, Confidence: 1.0},
		},
	}
	critWithLows := &models.ScanResult{
		Target: models.Target{URL: "http://example.com"},
		Findings: []models.Finding{
			{ID: "C1", Severity: models.SeverityCritical, Confidence: 1.0},
			{ID: "L1", Severity: models.SeverityLow, Confidence: 0.8},
			{ID: "L2", Severity: models.SeverityLow, Confidence: 0.8},
			{ID: "L3", Severity: models.SeverityLow, Confidence: 0.8},
		},
	}

	s1, err := eng.Score(context.Background(), singleCrit)
	require.NoError(t, err)
	s2, err := eng.Score(context.Background(), critWithLows)
	require.NoError(t, err)

	assert.Equal(t, 10.0, s1)
	assert.GreaterOrEqual(t, s2, s1, "adding low-severity findings must never lower the risk score")
}

func TestDefaultEngine_Recommend_UsesFindingRemediation(t *testing.T) {
	finding := models.Finding{ID: "CSP-MISSING", Title: "Missing CSP", Remediation: "Add CSP header"}
	rec, err := risk.NewDefaultEngine(zap.NewNop()).Recommend(context.Background(), finding)
	require.NoError(t, err)
	assert.Equal(t, "Add CSP header", rec)
}
