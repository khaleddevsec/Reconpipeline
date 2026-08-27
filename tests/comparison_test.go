package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/comparison"
	"github.com/frozeniceee/Reconpipeline/internal/history"
)

func TestComparison_FirstScan(t *testing.T) {
	dir := t.TempDir()
	currScanDir := filepath.Join(dir, "history", "scan-1")
	_ = os.MkdirAll(currScanDir, 0750)

	engine := comparison.NewEngine()
	currMeta := &history.ScanMeta{
		ScanID:    "scan-1",
		Target:    "example.com",
		StartTime: time.Now(),
	}

	res, err := engine.CompareScans("", currScanDir, dir, nil, currMeta)
	if err != nil {
		t.Fatalf("CompareScans failed: %v", err)
	}

	if res.HasPrevious {
		t.Error("first scan should not report having a previous scan")
	}

	if _, err := os.Stat(filepath.Join(dir, "comparison", "comparison.json")); os.IsNotExist(err) {
		t.Error("comparison.json was not created for first scan")
	}
}

func TestComparison_DeltaDetection(t *testing.T) {
	dir := t.TempDir()
	prevScanDir := filepath.Join(dir, "history", "scan-1")
	currScanDir := filepath.Join(dir, "history", "scan-2")
	_ = os.MkdirAll(prevScanDir, 0750)
	_ = os.MkdirAll(currScanDir, 0750)

	// Previous scan files
	_ = os.WriteFile(filepath.Join(prevScanDir, "subdomains.txt"), []byte("api.example.com\nold.example.com\nwww.example.com\n"), 0640)
	_ = os.WriteFile(filepath.Join(prevScanDir, "live-hosts.txt"), []byte("https://api.example.com\nhttps://old.example.com\n"), 0640)
	_ = os.WriteFile(filepath.Join(prevScanDir, "unique-urls.txt"), []byte("https://api.example.com/v1/users\nhttps://old.example.com/login\n"), 0640)
	_ = os.WriteFile(filepath.Join(prevScanDir, "hosts-metadata.json"), []byte(`[
		{"url": "https://api.example.com", "status_code": 403, "title": "Access Denied", "server": "nginx"}
	]`), 0640)

	// Current scan files
	_ = os.WriteFile(filepath.Join(currScanDir, "subdomains.txt"), []byte("api.example.com\nadmin.example.com\nwww.example.com\n"), 0640)
	_ = os.WriteFile(filepath.Join(currScanDir, "live-hosts.txt"), []byte("https://api.example.com\nhttps://admin.example.com\n"), 0640)
	_ = os.WriteFile(filepath.Join(currScanDir, "unique-urls.txt"), []byte("https://api.example.com/v1/users\nhttps://admin.example.com/dashboard\n"), 0640)
	_ = os.WriteFile(filepath.Join(currScanDir, "hosts-metadata.json"), []byte(`[
		{"url": "https://api.example.com", "status_code": 200, "title": "API Gateway", "server": "nginx/1.20"}
	]`), 0640)

	prevMeta := &history.ScanMeta{ScanID: "scan-1", StartTime: time.Now().Add(-1 * time.Hour)}
	currMeta := &history.ScanMeta{ScanID: "scan-2", StartTime: time.Now()}

	engine := comparison.NewEngine()
	res, err := engine.CompareScans(prevScanDir, currScanDir, dir, prevMeta, currMeta)
	if err != nil {
		t.Fatalf("CompareScans failed: %v", err)
	}

	if !res.HasPrevious {
		t.Error("expected HasPrevious to be true")
	}

	// Check new and removed subdomains
	if len(res.NewSubdomains) != 1 || res.NewSubdomains[0] != "admin.example.com" {
		t.Errorf("unexpected NewSubdomains: %+v", res.NewSubdomains)
	}
	if len(res.RemovedSubdomains) != 1 || res.RemovedSubdomains[0] != "old.example.com" {
		t.Errorf("unexpected RemovedSubdomains: %+v", res.RemovedSubdomains)
	}

	// Check new and removed live hosts
	if len(res.NewHosts) != 1 || res.NewHosts[0] != "https://admin.example.com" {
		t.Errorf("unexpected NewHosts: %+v", res.NewHosts)
	}
	if len(res.RemovedHosts) != 1 || res.RemovedHosts[0] != "https://old.example.com" {
		t.Errorf("unexpected RemovedHosts: %+v", res.RemovedHosts)
	}

	// Check new and removed URLs
	if len(res.NewURLs) != 1 || res.NewURLs[0] != "https://admin.example.com/dashboard" {
		t.Errorf("unexpected NewURLs: %+v", res.NewURLs)
	}
	if len(res.RemovedURLs) != 1 || res.RemovedURLs[0] != "https://old.example.com/login" {
		t.Errorf("unexpected RemovedURLs: %+v", res.RemovedURLs)
	}

	// Check asset changes (403 -> 200, title, server change)
	if len(res.ChangedAssets) != 1 {
		t.Fatalf("expected 1 changed asset, got %d", len(res.ChangedAssets))
	}
	ca := res.ChangedAssets[0]
	if ca.URL != "https://api.example.com" {
		t.Errorf("unexpected changed asset URL: %q", ca.URL)
	}
	if ca.OldStatus != 403 || ca.NewStatus != 200 {
		t.Errorf("expected status change 403 -> 200, got %d -> %d", ca.OldStatus, ca.NewStatus)
	}

	// Check comparison files in dir/comparison/
	for _, f := range []string{"new-subdomains.txt", "removed-subdomains.txt", "new-hosts.txt", "removed-hosts.txt", "new-urls.txt", "removed-urls.txt", "changed-assets.json", "comparison.json", "comparison.txt"} {
		path := filepath.Join(dir, "comparison", f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected comparison file %q to be created", path)
		}
	}
}
