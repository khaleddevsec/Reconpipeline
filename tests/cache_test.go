package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/frozeniceee/Reconpipeline/internal/cache"
)

func TestCache_Put_Get_Restore(t *testing.T) {
	cacheDir := t.TempDir()
	mgr := cache.NewManager(cacheDir, true)

	target := "example.com"
	stage := "subdomain-discovery"
	inputHash := cache.ComputeHash("seed-data")

	files := map[string][]byte{
		"subdomains.txt": []byte("api.example.com\nwww.example.com\n"),
		"metadata.json":  []byte(`{"total": 2}`),
	}
	counts := map[string]int{
		"subdomains": 2,
	}

	// Save to cache
	if err := mgr.Put(target, stage, inputHash, files, counts); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Retrieve from cache
	entry, entryDir, found := mgr.Get(target, stage, inputHash)
	if !found || entry == nil {
		t.Fatal("expected cache entry to be found")
	}
	if entry.Target != target || entry.Stage != stage {
		t.Errorf("unexpected entry values: %+v", entry)
	}

	// Restore artifacts
	destDir := t.TempDir()
	if err := mgr.RestoreArtifacts(entryDir, destDir); err != nil {
		t.Fatalf("RestoreArtifacts failed: %v", err)
	}

	restoredSub, err := os.ReadFile(filepath.Join(destDir, "subdomains.txt"))
	if err != nil {
		t.Fatalf("failed to read restored subdomains.txt: %v", err)
	}
	if string(restoredSub) != "api.example.com\nwww.example.com\n" {
		t.Errorf("unexpected restored content: %q", string(restoredSub))
	}
}

func TestCache_InvalidateTarget(t *testing.T) {
	cacheDir := t.TempDir()
	mgr := cache.NewManager(cacheDir, true)

	target := "example.com"
	stage := "subdomain-discovery"
	inputHash := cache.ComputeHash("seed-data")

	files := map[string][]byte{
		"subdomains.txt": []byte("api.example.com\n"),
	}

	_ = mgr.Put(target, stage, inputHash, files, nil)

	// Invalidate target
	if err := mgr.InvalidateTarget(target); err != nil {
		t.Fatalf("InvalidateTarget failed: %v", err)
	}

	// Check cache miss
	_, _, found := mgr.Get(target, stage, inputHash)
	if found {
		t.Error("expected cache entry to be purged after invalidation")
	}
}

func TestCache_DisabledBypass(t *testing.T) {
	cacheDir := t.TempDir()
	mgr := cache.NewManager(cacheDir, false)

	target := "example.com"
	stage := "subdomain-discovery"
	inputHash := cache.ComputeHash("seed-data")

	_ = mgr.Put(target, stage, inputHash, map[string][]byte{"sub.txt": []byte("test")}, nil)

	_, _, found := mgr.Get(target, stage, inputHash)
	if found {
		t.Error("expected cache miss when caching is disabled")
	}
}
