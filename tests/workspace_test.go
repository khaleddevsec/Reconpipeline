package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/config"
	"github.com/khaleddevsec/Reconpipeline/internal/workspace"
)

func TestWorkspace_Init(t *testing.T) {
	// Use a temp home-like dir.
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
	if err := ws.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	for _, d := range []string{cfg.ToolsDir, cfg.VersionsDir, cfg.CacheDir, cfg.ConfigDir, cfg.LogsDir} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			t.Errorf("expected directory %q to exist", d)
		}
	}
}

func TestWorkspace_TargetDir(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		WorkDir:    dir,
		ResultsDir: filepath.Join(dir, "results"),
	}
	ws := workspace.NewManager(cfg)

	got := ws.TargetDir("", "example.com")
	expected := filepath.Join(cfg.ResultsDir, "example.com")
	if got != expected {
		t.Errorf("TargetDir = %q, want %q", got, expected)
	}
}

func TestWorkspace_TargetDir_CustomOutput(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		WorkDir:    dir,
		ResultsDir: filepath.Join(dir, "results"),
	}
	ws := workspace.NewManager(cfg)

	custom := filepath.Join(dir, "my-output")
	got := ws.TargetDir(custom, "example.com")
	expected := filepath.Join(custom, "example.com")
	if got != expected {
		t.Errorf("TargetDir (custom) = %q, want %q", got, expected)
	}
}

func TestWorkspace_ToolBinaryPath(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		WorkDir:  dir,
		ToolsDir: filepath.Join(dir, "tools"),
	}
	ws := workspace.NewManager(cfg)

	got := ws.ToolBinaryPath("subfinder")
	expected := filepath.Join(dir, "tools", "subfinder", "subfinder")
	if got != expected {
		t.Errorf("ToolBinaryPath = %q, want %q", got, expected)
	}
}

func TestWorkspace_Exists(t *testing.T) {
	dir := t.TempDir()
	if !workspace.Exists(dir) {
		t.Error("Exists should return true for existing directory")
	}
	if workspace.Exists(filepath.Join(dir, "nonexistent")) {
		t.Error("Exists should return false for nonexistent path")
	}
}

func TestWorkspace_InitTargetDirs(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		WorkDir:    dir,
		ResultsDir: filepath.Join(dir, "results"),
	}
	ws := workspace.NewManager(cfg)

	targetDir := filepath.Join(dir, "results", "example.com")
	if err := ws.InitTargetDirs(targetDir); err != nil {
		t.Fatalf("InitTargetDirs failed: %v", err)
	}

	expectedDirs := []string{
		"01-subdomain-discovery",
		"02-live-host-detection",
		"03-active-crawling",
		"04-historical-url-discovery",
		"05-url-processing",
		"06-pattern-analysis",
	}
	for _, d := range expectedDirs {
		full := filepath.Join(targetDir, d)
		if _, err := os.Stat(full); os.IsNotExist(err) {
			t.Errorf("expected stage directory %q to exist", full)
		}
	}
}
