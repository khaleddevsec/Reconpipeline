package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/comparison"
	"github.com/khaleddevsec/Reconpipeline/internal/pipeline"
	"github.com/khaleddevsec/Reconpipeline/internal/reporting"
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

func TestHTMLReport_XSSPrevention(t *testing.T) {
	now := time.Now()
	rep := &reporting.Report{
		ScanID:      "scan-<script>alert('xss-scanid')</script>",
		Target:      "test.com\"><script>alert('xss-target')</script>",
		Version:     "v2.5.2",
		Mode:        "full",
		StartTime:   now,
		StateStatus: "completed",
	}

	comp := &comparison.Result{
		HasPrevious:    true,
		PreviousScanID: "scan-prev<img src=x onerror=alert('prev')>",
		PreviousTime:   "2026-08-26 12:00:00",
		ChangedAssets: []comparison.AssetChange{
			{
				URL:       "https://test.com/login?redirect=<script>alert('url')</script>",
				OldStatus: 200,
				NewStatus: 200,
				OldTitle:  "<title><script>alert('old-title')</script></title>",
				NewTitle:  "<svg/onload=alert('new-title')>",
				OldServer: "nginx/<script>alert('old-srv')</script>",
				NewServer: "Apache/<script>alert('new-srv')</script>",
			},
		},
	}

	htmlContent := reporting.GenerateHTML(rep, comp)

	dangerousPayloads := []string{
		"<script>alert('xss-scanid')</script>",
		"<script>alert('xss-target')</script>",
		"<img src=x onerror=alert('prev')>",
		"<script>alert('old-title')</script>",
		"<svg/onload=alert('new-title')>",
		"<script>alert('old-srv')</script>",
		"<script>alert('new-srv')</script>",
	}

	for _, payload := range dangerousPayloads {
		if strings.Contains(htmlContent, payload) {
			t.Errorf("Raw unescaped XSS payload found in HTML report: %s", payload)
		}
	}

	// Verify properly escaped entity representations
	if !strings.Contains(htmlContent, "&lt;script&gt;alert(&#39;old-title&#39;)&lt;/script&gt;") {
		t.Error("Expected escaped script tags in title change")
	}
	if !strings.Contains(htmlContent, "&lt;svg/onload=alert(&#39;new-title&#39;)&gt;") {
		t.Error("Expected escaped svg tag in new title")
	}
}
