package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/khaleddevsec/Reconpipeline/v2/internal/collector"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/config"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/correlation"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/fingerprint"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/knowledge"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/parser"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/report"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/risk"
	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"github.com/khaleddevsec/Reconpipeline/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// knowledgeDir points to the project knowledge/ directory.
const knowledgeDir = "../knowledge"

func setupServer(headers map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>test</body></html>"))
	}))
}

// TestFullPipeline_NoSecurityHeaders runs the complete pipeline against a test
// server that returns no security headers and verifies findings are generated.
func TestFullPipeline_NoSecurityHeaders(t *testing.T) {
	srv := setupServer(map[string]string{
		"Server":       "nginx/1.25.0",
		"Content-Type": "text/html",
	})
	defer srv.Close()

	log := zap.NewNop()
	cfg := config.Default()
	ctx := context.Background()

	target, err := utils.NormalizeURL(srv.URL)
	require.NoError(t, err)

	// Collect
	col, err := collector.NewHTTPCollector(cfg, log)
	require.NoError(t, err)
	data, err := col.Collect(ctx, target)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, data.StatusCode)

	// Parse
	data, err = parser.NewHTTPParser(log).Parse(ctx, data)
	require.NoError(t, err)
	// all six security headers should be marked missing
	missingCount := 0
	for k := range data.Headers {
		if strings.HasPrefix(k, "_missing_") {
			missingCount++
		}
	}
	assert.GreaterOrEqual(t, missingCount, 6)

	// Fingerprint
	fps, err := fingerprint.NewHeaderEngine(log).Identify(ctx, data)
	require.NoError(t, err)
	require.NotEmpty(t, fps)
	assert.Equal(t, "nginx", fps[0].Name)

	// Knowledge DB
	kdb := knowledge.NewYAMLDatabase(log)
	err = kdb.Load(knowledgeDir)
	if err != nil {
		t.Skipf("knowledge dir not accessible: %v", err)
	}

	// Correlate
	result := &models.ScanResult{
		ID:            utils.NewID(),
		Target:        target,
		CollectedData: *data,
		Fingerprints:  fps,
		CollectedAt:   time.Now(),
	}
	findings, err := correlation.NewHeaderCorrelator(kdb, log).Correlate(ctx, result)
	require.NoError(t, err)
	// at minimum: 6 missing headers + server disclosure = 7 findings
	assert.GreaterOrEqual(t, len(findings), 7)
	result.Findings = findings

	// Risk
	score, err := risk.NewDefaultEngine(log).Score(ctx, result)
	require.NoError(t, err)
	assert.Greater(t, score, 0.0)
	assert.LessOrEqual(t, score, 10.0)

	// Report — JSON
	rep := &models.Report{
		Title:       "Integration Test",
		Version:     "test",
		GeneratedAt: time.Now(),
		Results:     []models.ScanResult{*result},
		Summary: models.ReportSummary{
			TotalTargets:  1,
			TotalFindings: len(findings),
			RiskScore:     score,
		},
	}

	var jsonBuf bytes.Buffer
	err = report.NewJSONReporter(log).Generate(ctx, rep, &jsonBuf)
	require.NoError(t, err)
	var parsed models.Report
	require.NoError(t, json.Unmarshal(jsonBuf.Bytes(), &parsed))
	assert.Equal(t, "Integration Test", parsed.Title)
	assert.Len(t, parsed.Results, 1)

	// Report — Markdown
	var mdBuf bytes.Buffer
	err = report.NewMarkdownReporter(log).Generate(ctx, rep, &mdBuf)
	require.NoError(t, err)
	assert.Contains(t, mdBuf.String(), srv.URL)

	// Report — HTML
	var htmlBuf bytes.Buffer
	err = report.NewHTMLReporter(log).Generate(ctx, rep, &htmlBuf)
	require.NoError(t, err)
	assert.Contains(t, htmlBuf.String(), "ThreatLens Report")

	// Report — CSV
	var csvBuf bytes.Buffer
	err = report.NewCSVReporter(log).Generate(ctx, rep, &csvBuf)
	require.NoError(t, err)
	assert.Contains(t, csvBuf.String(), "target")

	// Report — SARIF
	var sarifBuf bytes.Buffer
	err = report.NewSARIFReporter(log).Generate(ctx, rep, &sarifBuf)
	require.NoError(t, err)
	assert.Contains(t, sarifBuf.String(), "2.1.0")
}
