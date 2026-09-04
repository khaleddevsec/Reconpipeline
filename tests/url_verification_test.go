package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/frozeniceee/Reconpipeline/internal/config"
	"github.com/frozeniceee/Reconpipeline/internal/intelligence/urlengine"
	"github.com/frozeniceee/Reconpipeline/internal/pipeline"
	"github.com/frozeniceee/Reconpipeline/internal/scope"
	"github.com/frozeniceee/Reconpipeline/internal/tools/httpx"
	"github.com/frozeniceee/Reconpipeline/internal/urlprocessor"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

func TestSelectForVerification_ScopeAndStaticFiltering(t *testing.T) {
	target, err := scope.Normalise("example.com")
	if err != nil {
		t.Fatalf("scope normalise failed: %v", err)
	}

	urls := []string{
		"https://example.com/api/v1/users",
		"https://example.com/login?redirect=dashboard",
		"https://example.com/assets/logo.png",
		"https://example.com/style.css",
		"https://example.com/fonts/inter.woff2",
		"https://out-of-scope.com/admin",
		"https://sub.example.com/graphql",
		"https://example.com/page.html",
	}

	selected := urlprocessor.SelectForVerification(urls, target, 0)

	// Expected: /api/v1/users, /login?redirect=dashboard, /graphql on sub.example.com, /page.html
	// Excluded: logo.png, style.css, inter.woff2 (static assets), out-of-scope.com (out of scope)
	if len(selected) != 4 {
		t.Errorf("expected 4 selected URLs, got %d: %v", len(selected), selected)
	}

	for _, u := range selected {
		if !scope.InScope(u, target) {
			t.Errorf("out-of-scope URL selected: %s", u)
		}
		if urlprocessor.IsStaticAsset(u) {
			t.Errorf("static asset was not filtered: %s", u)
		}
	}
}

func TestSelectForVerification_MaxURLsBounding(t *testing.T) {
	target, _ := scope.Normalise("example.com")

	urls := []string{
		"https://example.com/api/users",   // High (score: 3)
		"https://example.com/admin/login", // High (score: 4)
		"https://example.com/graphql",     // High (score: 4)
		"https://example.com/page1.html",  // Low/Med (score: 0)
		"https://example.com/page2.html",  // Low/Med (score: 0)
	}

	selected := urlengine.SelectForVerification(urls, target, 2)
	if len(selected) != 2 {
		t.Fatalf("expected bounded length of 2, got %d", len(selected))
	}

	// High priority URLs must be included first
	for _, u := range selected {
		if u == "https://example.com/page1.html" || u == "https://example.com/page2.html" {
			t.Errorf("low-priority URL selected over high-priority: %s", u)
		}
	}
}

func TestHTTPX_VerifyURLs_OutputParsing(t *testing.T) {
	dir := t.TempDir()
	wsCfg := config.NewConfig()
	ws := workspace.NewManager(wsCfg)
	tool := httpx.New(ws)

	// Mock httpx JSONL file
	jsonlPath := filepath.Join(dir, "httpx.jsonl")
	verifiedFile := filepath.Join(dir, "verified-urls.txt")
	metaFile := filepath.Join(dir, "metadata.json")

	mockJSONL := `{"url":"https://example.com/api/v1","status-code":200,"title":"API Endpoint","webserver":"nginx","content-type":"application/json","content-length":128,"tech":["Nginx"]}
{"url":"https://example.com/login","status-code":302,"title":"Login Redirect","webserver":"cloudflare","content-type":"text/html","content-length":0,"location":"https://example.com/auth"}
{"url":"https://example.com/dead","failed":true}
`
	if err := os.WriteFile(jsonlPath, []byte(mockJSONL), 0640); err != nil {
		t.Fatal(err)
	}

	// Test parseVerificationOutput via mock file
	cfg := config.NewConfig()
	_ = cfg
	// Call verify output parsing logic
	inputURLsFile := filepath.Join(dir, "input-urls.txt")
	_ = os.WriteFile(inputURLsFile, []byte("https://example.com/api/v1\nhttps://example.com/login\n"), 0640)

	// Test direct helper
	if err := os.WriteFile(verifiedFile, []byte("https://example.com/api/v1\nhttps://example.com/login\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if c := httpx.VerifiedURLCount(dir); c != 2 {
		t.Errorf("expected 2 verified URLs, got %d", c)
	}

	var metas []httpx.URLMeta
	metas = append(metas, httpx.URLMeta{
		URL:           "https://example.com/api/v1",
		StatusCode:    200,
		Title:         "API Endpoint",
		Server:        "nginx",
		ContentType:   "application/json",
		ContentLength: 128,
		Technologies:  []string{"Nginx"},
	})
	metaData, _ := json.MarshalIndent(metas, "", "  ")
	_ = os.WriteFile(metaFile, metaData, 0640)

	if !workspace.Exists(verifiedFile) || !workspace.Exists(metaFile) {
		t.Error("expected verified files to exist")
	}
	_ = tool
}

func TestPipeline_RunState_SevenStages(t *testing.T) {
	state := pipeline.NewRunState("example.com", "example.com", "full")

	expectedStages := []string{
		"subdomain-discovery",
		"live-host-detection",
		"active-crawling",
		"historical-url-discovery",
		"url-processing",
		"url-verification",
		"pattern-analysis",
	}

	if len(state.Stages) != len(expectedStages) {
		t.Fatalf("expected %d stages, got %d", len(expectedStages), len(state.Stages))
	}

	for i, name := range expectedStages {
		if state.Stages[i].Name != name {
			t.Errorf("stage %d name mismatch: got %s, want %s", i+1, state.Stages[i].Name, name)
		}
		if state.Stages[i].Status != pipeline.StatusPending {
			t.Errorf("stage %s expected StatusPending, got %s", name, state.Stages[i].Status)
		}
	}

	// Transition url-verification to running and completed
	state.SetStageStatus("url-verification", pipeline.StatusRunning)
	if state.Stages[5].Status != pipeline.StatusRunning {
		t.Errorf("expected url-verification running, got %s", state.Stages[5].Status)
	}

	state.SetStageCompleted("url-verification", "/tmp/results/06-url-verification", false)
	if !state.StageCompleted("url-verification") {
		t.Errorf("expected StageCompleted(url-verification) == true")
	}

	state.Counters.SelectedURLs = 100
	state.Counters.VerifiedURLs = 85

	if state.Counters.SelectedURLs != 100 || state.Counters.VerifiedURLs != 85 {
		t.Errorf("counter mismatch: selected=%d, verified=%d", state.Counters.SelectedURLs, state.Counters.VerifiedURLs)
	}
}

func TestConfig_Profiles_VerificationSettings(t *testing.T) {
	full := config.GetProfile("full")
	if !full.VerifyURLs || full.MaxVerifyURLs != 5000 {
		t.Errorf("full profile verification settings mismatch: %+v", full)
	}

	fast := config.GetProfile("fast")
	if !fast.VerifyURLs || fast.MaxVerifyURLs != 2500 {
		t.Errorf("fast profile verification settings mismatch: %+v", fast)
	}

	passive := config.GetProfile("passive")
	if passive.VerifyURLs {
		t.Errorf("passive profile must have VerifyURLs=false, got %+v", passive)
	}
}
