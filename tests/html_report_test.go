package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/comparison"
	"github.com/frozeniceee/Reconpipeline/internal/pipeline"
	"github.com/frozeniceee/Reconpipeline/internal/reporting"
)

func TestHTMLReport_Generation(t *testing.T) {
	now := time.Now()
	rep := &reporting.Report{
		ScanID:      "scan-20260827-183042",
		Target:      "example.com",
		Version:     "v2.5.2",
		Mode:        "full",
		StartTime:   now,
		EndTime:     &now,
		Duration:    "06m 42s",
		StateStatus: "completed",
		Counters: pipeline.Counters{
			Subdomains:       1284,
			LiveHosts:        213,
			UniqueURLs:       31492,
			APIURLs:          421,
			JavaScriptURLs:   187,
			ParamURLs:        632,
			URLClusters:      45,
			HighPriorityURLs: 88,
			XSSMatches:       12,
			SQLiMatches:      3,
			LFIMatches:       2,
			SSRFMatches:      1,
			RedirectMatches:  8,
		},
		Stages: []pipeline.StageInfo{
			{Name: "subdomain-discovery", Status: pipeline.StatusCompleted},
			{Name: "live-host-detection", Status: pipeline.StatusCompleted},
			{Name: "active-crawling", Status: pipeline.StatusCompleted},
			{Name: "historical-url-discovery", Status: pipeline.StatusCompleted},
			{Name: "url-processing", Status: pipeline.StatusCompleted},
			{Name: "pattern-analysis", Status: pipeline.StatusCompleted},
		},
	}

	comp := &comparison.Result{
		HasPrevious:    true,
		PreviousScanID: "scan-20260826-120000",
		PreviousTime:   "2026-08-26 12:00:00",
		NewSubdomains:  []string{"api.example.com", "admin.example.com"},
		NewHosts:       []string{"https://api.example.com"},
		NewURLs:        []string{"https://api.example.com/v1/users"},
		ChangedAssets: []comparison.AssetChange{
			{URL: "https://api.example.com", OldStatus: 403, NewStatus: 200},
		},
	}

	htmlContent := reporting.GenerateHTML(rep, comp)

	if !strings.Contains(htmlContent, "example.com") {
		t.Error("HTML report missing target domain")
	}
	if !strings.Contains(htmlContent, "scan-20260827-183042") {
		t.Error("HTML report missing scan ID")
	}
	if !strings.Contains(htmlContent, "1,284") {
		t.Error("HTML report missing formatted subdomain count")
	}
	if !strings.Contains(htmlContent, "Changes Since Previous Scan") {
		t.Error("HTML report missing change section")
	}
	if !strings.Contains(htmlContent, "scan-20260826-120000") {
		t.Error("HTML report missing previous scan ID")
	}
	if !strings.Contains(htmlContent, "status: 403 &rarr; 200") {
		t.Error("HTML report missing status change detail")
	}
}
