package report_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/khaleddevsec/Reconpipeline/v2/internal/report"
	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func sampleReport() *models.Report {
	return &models.Report{
		Title:       "Test Report",
		Version:     "1.0.0",
		GeneratedAt: time.Now(),
		Results: []models.ScanResult{
			{
				ID:     "scan-001",
				Target: models.Target{URL: "https://example.com"},
				Findings: []models.Finding{
					{ID: "CSP-MISSING", Title: "Missing CSP", Severity: models.SeverityHigh},
				},
				RiskScore: 7.5,
			},
		},
		Summary: models.ReportSummary{
			TotalTargets:  1,
			TotalFindings: 1,
			RiskScore:     7.5,
		},
	}
}

func TestJSONReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewJSONReporter(zap.NewNop()).Generate(context.Background(), sampleReport(), &buf)
	require.NoError(t, err)

	var got models.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "Test Report", got.Title)
	require.Len(t, got.Results, 1)
	assert.Equal(t, "CSP-MISSING", got.Results[0].Findings[0].ID)
}

func TestMarkdownReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewMarkdownReporter(zap.NewNop()).Generate(context.Background(), sampleReport(), &buf)
	require.NoError(t, err)

	output := buf.String()
	assert.True(t, strings.Contains(output, "ThreatLens Report"))
	assert.True(t, strings.Contains(output, "https://example.com"))
	assert.True(t, strings.Contains(output, "Missing CSP"))
}

func TestJSONReporter_Generate_NilReport(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewJSONReporter(zap.NewNop()).Generate(context.Background(), nil, &buf)
	assert.Error(t, err)
}

func TestHTMLReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewHTMLReporter(zap.NewNop()).Generate(context.Background(), sampleReport(), &buf)
	require.NoError(t, err)
	html := buf.String()
	assert.Contains(t, html, "ThreatLens Report")
	assert.Contains(t, html, "https://example.com")
	assert.Contains(t, html, "Missing CSP")
}

func TestHTMLReporter_Generate_NilReport(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewHTMLReporter(zap.NewNop()).Generate(context.Background(), nil, &buf)
	assert.Error(t, err)
}

func TestCSVReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewCSVReporter(zap.NewNop()).Generate(context.Background(), sampleReport(), &buf)
	require.NoError(t, err)
	csv := buf.String()
	assert.Contains(t, csv, "target")
	assert.Contains(t, csv, "https://example.com")
	assert.Contains(t, csv, "CSP-MISSING")
}

func TestCSVReporter_Generate_NilReport(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewCSVReporter(zap.NewNop()).Generate(context.Background(), nil, &buf)
	assert.Error(t, err)
}

func TestSARIFReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewSARIFReporter(zap.NewNop()).Generate(context.Background(), sampleReport(), &buf)
	require.NoError(t, err)
	sarif := buf.String()
	assert.Contains(t, sarif, `"version": "2.1.0"`)
	assert.Contains(t, sarif, "CSP-MISSING")
	assert.Contains(t, sarif, "https://example.com")
}

func TestSARIFReporter_Generate_NilReport(t *testing.T) {
	var buf bytes.Buffer
	err := report.NewSARIFReporter(zap.NewNop()).Generate(context.Background(), nil, &buf)
	assert.Error(t, err)
}

func TestGeneratorFor_ReturnsCorrectType(t *testing.T) {
	log := zap.NewNop()
	assert.Equal(t, models.ReportFormatJSON, report.GeneratorFor(models.ReportFormatJSON, log).Format())
	assert.Equal(t, models.ReportFormatMarkdown, report.GeneratorFor(models.ReportFormatMarkdown, log).Format())
	assert.Equal(t, models.ReportFormatHTML, report.GeneratorFor(models.ReportFormatHTML, log).Format())
	assert.Equal(t, models.ReportFormatCSV, report.GeneratorFor(models.ReportFormatCSV, log).Format())
	assert.Equal(t, models.ReportFormatSARIF, report.GeneratorFor(models.ReportFormatSARIF, log).Format())
	// unknown format falls back to JSON
	assert.Equal(t, models.ReportFormatJSON, report.GeneratorFor("unknown", log).Format())
}
