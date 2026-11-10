package database_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/khaleddevsec/Reconpipeline/v2/internal/database"
	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSQLiteStore_SaveAndGet(t *testing.T) {
	store := database.NewSQLiteStore(zap.NewNop())
	require.NoError(t, store.Open(filepath.Join(t.TempDir(), "test.db")))
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	result := &models.ScanResult{
		ID:          "scan-001",
		Target:      models.Target{URL: "https://example.com"},
		CollectedAt: now,
		AnalysedAt:  now,
		RiskScore:   7.5,
		Findings: []models.Finding{
			{ID: "CSP-MISSING", Title: "Missing CSP", Severity: models.SeverityHigh, Confidence: 1.0},
		},
	}

	require.NoError(t, store.SaveResult(context.Background(), result))

	got, err := store.GetResult(context.Background(), "scan-001")
	require.NoError(t, err)
	assert.Equal(t, "scan-001", got.ID)
	assert.Equal(t, "https://example.com", got.Target.URL)
	assert.Equal(t, 7.5, got.RiskScore)
	require.Len(t, got.Findings, 1)
	assert.Equal(t, "CSP-MISSING", got.Findings[0].ID)
}

func TestSQLiteStore_ListResults(t *testing.T) {
	store := database.NewSQLiteStore(zap.NewNop())
	require.NoError(t, store.Open(filepath.Join(t.TempDir(), "test.db")))
	defer store.Close()

	now := time.Now().UTC()
	for _, id := range []string{"r1", "r2"} {
		require.NoError(t, store.SaveResult(context.Background(), &models.ScanResult{
			ID:          id,
			Target:      models.Target{URL: "http://x.com"},
			CollectedAt: now,
			AnalysedAt:  now,
			Findings:    []models.Finding{},
		}))
	}

	results, err := store.ListResults(context.Background())
	require.NoError(t, err)
	assert.Len(t, results, 2)
}
