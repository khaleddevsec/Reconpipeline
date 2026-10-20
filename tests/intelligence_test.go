package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/asset"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/dns"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/status"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/tech"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/urlengine"
)

func TestAssetClassifier(t *testing.T) {
	c := asset.NewClassifier()

	tests := []struct {
		hostname string
		expected asset.Classification
	}{
		{"api.example.com", asset.ClassAPI},
		{"api-v2.example.com", asset.ClassAPI},
		{"admin.example.com", asset.ClassAdmin},
		{"dashboard.example.com", asset.ClassAdmin},
		{"dev.example.com", asset.ClassDevelopment},
		{"test.example.com", asset.ClassDevelopment},
		{"staging.example.com", asset.ClassStaging},
		{"stage-app.example.com", asset.ClassStaging},
		{"auth.example.com", asset.ClassAuth},
		{"sso.example.com", asset.ClassAuth},
		{"cdn.example.com", asset.ClassCDN},
		{"static.example.com", asset.ClassCDN},
		{"mail.example.com", asset.ClassMail},
		{"smtp.example.com", asset.ClassMail},
		{"www.example.com", asset.ClassStatic},
		{"docs.example.com", asset.ClassStatic},
		{"example.com", asset.ClassProduction},
	}

	for _, tt := range tests {
		meta := c.ClassifyHostname(tt.hostname, "test")
		if meta.Classification != tt.expected {
			t.Errorf("ClassifyHostname(%q) = %q, want %q", tt.hostname, meta.Classification, tt.expected)
		}
	}
}

func TestAssetClassifier_ProcessSubdomains(t *testing.T) {
	dir := t.TempDir()
	subFile := filepath.Join(dir, "subdomains.txt")
	content := "api.example.com\nadmin.example.com\ndev.example.com\n"
	if err := os.WriteFile(subFile, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}

	c := asset.NewClassifier()
	metas, err := c.ProcessSubdomains(subFile, dir)
	if err != nil {
		t.Fatalf("ProcessSubdomains failed: %v", err)
	}

	if len(metas) != 3 {
		t.Errorf("expected 3 metas, got %d", len(metas))
	}

	// Verify classified folder files
	if _, err := os.Stat(filepath.Join(dir, "classified", "api.txt")); os.IsNotExist(err) {
		t.Error("api.txt not created in classified dir")
	}
	if _, err := os.Stat(filepath.Join(dir, "metadata.json")); os.IsNotExist(err) {
		t.Error("metadata.json not created")
	}
}

func TestDNSIntelligence(t *testing.T) {
	dir := t.TempDir()
	subFile := filepath.Join(dir, "subdomains.txt")
	if err := os.WriteFile(subFile, []byte("localhost\n"), 0640); err != nil {
		t.Fatal(err)
	}

	engine := dns.NewEngine(5)
	records, err := engine.ProcessSubdomains(context.Background(), subFile, filepath.Join(dir, "dns"))
	if err != nil {
		t.Fatalf("ProcessSubdomains failed: %v", err)
	}

	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}

	if _, err := os.Stat(filepath.Join(dir, "dns", "dns-records.json")); os.IsNotExist(err) {
		t.Error("dns-records.json was not created")
	}
}

func TestTechnologyIntelligence(t *testing.T) {
	dir := t.TempDir()
	metaFile := filepath.Join(dir, "metadata.json")
	metaJSON := `[
		{"url": "https://nginx.example.com", "server": "nginx/1.18.0"},
		{"url": "https://apache.example.com", "server": "Apache/2.4.41"},
		{"url": "https://blog.example.com", "title": "My WordPress Site", "technology": "WordPress"},
		{"url": "https://app.example.com", "server": "Express", "technology": "Node.js"},
		{"url": "https://cdn.example.com", "server": "cloudflare"}
	]`
	if err := os.WriteFile(metaFile, []byte(metaJSON), 0640); err != nil {
		t.Fatal(err)
	}

	engine := tech.NewEngine()
	groups, err := engine.ProcessMetadata(metaFile, filepath.Join(dir, "technologies"))
	if err != nil {
		t.Fatalf("ProcessMetadata failed: %v", err)
	}

	if len(groups) == 0 {
		t.Fatal("expected technology groups, got 0")
	}

	// Verify tech file creation
	if _, err := os.Stat(filepath.Join(dir, "technologies", "nginx.txt")); os.IsNotExist(err) {
		t.Error("nginx.txt not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "technologies", "wordpress.txt")); os.IsNotExist(err) {
		t.Error("wordpress.txt not created")
	}
}

func TestHTTPStatusIntelligence(t *testing.T) {
	dir := t.TempDir()
	metaFile := filepath.Join(dir, "metadata.json")
	metaJSON := `[
		{"url": "https://ok.example.com", "status_code": 200},
		{"url": "https://redir.example.com", "status_code": 302, "location": "https://target.com"},
		{"url": "https://forbidden.example.com", "status_code": 403},
		{"url": "https://error.example.com", "status_code": 500}
	]`
	if err := os.WriteFile(metaFile, []byte(metaJSON), 0640); err != nil {
		t.Fatal(err)
	}

	engine := status.NewEngine()
	summary, err := engine.ProcessMetadata(metaFile, filepath.Join(dir, "status"))
	if err != nil {
		t.Fatalf("ProcessMetadata failed: %v", err)
	}

	if len(summary.Class2xx) != 1 {
		t.Errorf("expected 1 2xx host, got %d", len(summary.Class2xx))
	}
	if len(summary.InterestingStatus) != 2 { // 403 and 500
		t.Errorf("expected 2 interesting status hosts, got %d", len(summary.InterestingStatus))
	}

	if _, err := os.Stat(filepath.Join(dir, "status", "status.json")); os.IsNotExist(err) {
		t.Error("status.json not created")
	}
}

func TestSmartURLNormalizer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://EXAMPLE.COM/path/", "https://example.com/path/"},
		{"http://example.com:80/api", "http://example.com/api"},
		{"https://example.com:443/api", "https://example.com/api"},
		{"https://example.com/test#section", "https://example.com/test"},
		{"https://example.com/search?b=2&a=1", "https://example.com/search?b=2&a=1"},
	}

	for _, tt := range tests {
		got := urlengine.NormalizeURL(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestURLNormalizationComprehensive(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantNorm      string
		wantCanonical string
	}{
		{
			name:          "Trailing slash preservation",
			input:         "https://example.com/admin/",
			wantNorm:      "https://example.com/admin/",
			wantCanonical: "https://example.com/admin/",
		},
		{
			name:          "No trailing slash preservation",
			input:         "https://example.com/admin",
			wantNorm:      "https://example.com/admin",
			wantCanonical: "https://example.com/admin",
		},
		{
			name:          "Default HTTP port removal",
			input:         "http://example.com:80/path",
			wantNorm:      "http://example.com/path",
			wantCanonical: "http://example.com/path",
		},
		{
			name:          "Non-default port preservation",
			input:         "https://example.com:8443/api",
			wantNorm:      "https://example.com:8443/api",
			wantCanonical: "https://example.com:8443/api",
		},
		{
			name:          "Reordered query parameters preserved in norm but canonicalized in CanonicalKey",
			input:         "https://example.com/search?z=9&a=1&m=5",
			wantNorm:      "https://example.com/search?z=9&a=1&m=5",
			wantCanonical: "https://example.com/search?a=1&m=5&z=9",
		},
		{
			name:          "Duplicate query parameters preserved",
			input:         "https://example.com/filter?tag=go&tag=security",
			wantNorm:      "https://example.com/filter?tag=go&tag=security",
			wantCanonical: "https://example.com/filter?tag=go&tag=security",
		},
		{
			name:          "Empty query value",
			input:         "https://example.com/items?debug&view=true",
			wantNorm:      "https://example.com/items?debug&view=true",
			wantCanonical: "https://example.com/items?debug=&view=true",
		},
		{
			name:          "Path case sensitivity preserved",
			input:         "https://example.com/API/v1/Users",
			wantNorm:      "https://example.com/API/v1/Users",
			wantCanonical: "https://example.com/API/v1/Users",
		},
		{
			name:          "Hostname case normalized to lowercase",
			input:         "https://API.SUB.EXAMPLE.COM/test",
			wantNorm:      "https://api.sub.example.com/test",
			wantCanonical: "https://api.sub.example.com/test",
		},
		{
			name:          "Client-side fragment stripped",
			input:         "https://example.com/docs#installation",
			wantNorm:      "https://example.com/docs",
			wantCanonical: "https://example.com/docs",
		},
		{
			name:          "Relative path traversal dot-segments resolved while keeping trailing slash",
			input:         "https://example.com/static/../api/v1/",
			wantNorm:      "https://example.com/api/v1/",
			wantCanonical: "https://example.com/api/v1/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm := urlengine.NormalizeURL(tt.input)
			if norm != tt.wantNorm {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, norm, tt.wantNorm)
			}
			canon := urlengine.CanonicalKey(tt.input)
			if canon != tt.wantCanonical {
				t.Errorf("CanonicalKey(%q) = %q, want %q", tt.input, canon, tt.wantCanonical)
			}
		})
	}
}

func TestURLClustering(t *testing.T) {
	urls := []string{
		"https://example.com/api/user/1",
		"https://example.com/api/user/2",
		"https://example.com/api/user/999",
		"https://example.com/item/123e4567-e89b-12d3-a456-426614174000",
		"https://example.com/download/5d41402abc4b2a76b9719d911017c592",
	}

	clusters, patterns := urlengine.ClusterURLs(urls)
	if len(clusters) < 3 {
		t.Errorf("expected at least 3 clusters, got %d", len(clusters))
	}

	foundUserCluster := false
	for _, p := range patterns {
		if p == "https://example.com/api/user/{id}" {
			foundUserCluster = true
			break
		}
	}
	if !foundUserCluster {
		t.Error("expected cluster https://example.com/api/user/{id} not found")
	}
}

func TestParameterIntelligence(t *testing.T) {
	urls := []string{
		"https://example.com/view?id=123",
		"https://example.com/redirect?url=https://other.com",
		"https://example.com/load?file=test.php",
		"https://example.com/auth?token=xyz987",
	}

	paramURLs, analyses := urlengine.AnalyzeParameters(urls)
	if len(paramURLs) != 4 {
		t.Errorf("expected 4 parameterized URLs, got %d", len(paramURLs))
	}

	for _, a := range analyses {
		if a.URL == "https://example.com/view?id=123" {
			if a.Parameters["id"] != "identifier" {
				t.Errorf("expected param 'id' category 'identifier', got %q", a.Parameters["id"])
			}
		}
		if a.URL == "https://example.com/redirect?url=https://other.com" {
			if a.Parameters["url"] != "url" {
				t.Errorf("expected param 'url' category 'url', got %q", a.Parameters["url"])
			}
		}
	}
}

func TestURLPrioritization(t *testing.T) {
	urls := []string{
		"https://example.com/admin/dashboard",
		"https://example.com/api/v1/users?token=secret",
		"https://example.com/static/logo.png",
	}

	assessments, high, _, low := urlengine.PrioritizeURLs(urls)
	if len(assessments) != 3 {
		t.Errorf("expected 3 assessments, got %d", len(assessments))
	}

	if len(high) < 2 {
		t.Errorf("expected at least 2 high priority URLs, got %d", len(high))
	}

	foundLogoLow := false
	for _, l := range low {
		if l == "https://example.com/static/logo.png" {
			foundLogoLow = true
			break
		}
	}
	if !foundLogoLow {
		t.Error("expected logo.png to be low priority")
	}
}
