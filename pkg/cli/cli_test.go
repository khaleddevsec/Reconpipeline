package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectTargets_DeduplicatesAndReadsFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "targets.txt")
	content := "# comment\nhttps://example.com\nhttps://test.org\nhttps://example.com\n"
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0600))

	targets, err := collectTargets(
		[]string{"https://example.com", "https://cli.org"},
		tmp,
		[]string{"https://cfg.org", "https://test.org"},
	)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"https://example.com",
		"https://cli.org",
		"https://test.org",
		"https://cfg.org",
	}, targets)
}

func TestCheckFailThreshold(t *testing.T) {
	rep := &models.Report{
		Summary: models.ReportSummary{
			BySeverity: map[models.Severity]int{
				models.SeverityHigh: 1,
				models.SeverityLow:  2,
			},
		},
	}

	exceeded, err := checkFailThreshold(rep, "high")
	require.NoError(t, err)
	assert.True(t, exceeded)

	exceeded, err = checkFailThreshold(rep, "critical")
	require.NoError(t, err)
	assert.False(t, exceeded)

	_, err = checkFailThreshold(rep, "unknown")
	assert.Error(t, err)
}

