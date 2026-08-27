package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/pipeline"
	"github.com/frozeniceee/Reconpipeline/internal/reporting"
)

func TestGenerate_CreatesFiles(t *testing.T) {
	dir := t.TempDir()

	now := time.Now()
	state := &pipeline.RunState{
		Target:           "example.com",
		NormalisedTarget: "example.com",
		Mode:             "full",
		Version:          "v2.5.0",
		StartTime:        now,
		EndTime:          &now,
		Duration:         "1m0s",
		Stages: []pipeline.StageInfo{
			{Name: "subdomain-discovery", Status: pipeline.StatusCompleted},
			{Name: "live-host-detection", Status: pipeline.StatusCompleted},
			{Name: "active-crawling", Status: pipeline.StatusCompleted},
			{Name: "historical-url-discovery", Status: pipeline.StatusCompleted},
			{Name: "url-processing", Status: pipeline.StatusCompleted},
			{Name: "pattern-analysis", Status: pipeline.StatusCompleted},
		},
		Counters: pipeline.Counters{
			Subdomains: 100,
			LiveHosts:  50,
			UniqueURLs: 1000,
		},
		Completed: true,
	}

	if err := reporting.Generate(state, dir); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	for _, f := range []string{"report.txt", "report.json"} {
		path := filepath.Join(dir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %q to be created", path)
		}
	}
}

func TestGenerate_ReportContentsTarget(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	state := &pipeline.RunState{
		Target:           "example.com",
		NormalisedTarget: "example.com",
		Mode:             "full",
		StartTime:        now,
		Stages:           []pipeline.StageInfo{},
	}

	if err := reporting.Generate(state, dir); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !contains(content, "example.com") {
		t.Error("report.txt does not contain target domain")
	}
	if !contains(content, "Pattern matches indicate potential") {
		t.Error("report.txt missing disclaimer about pattern matches")
	}
}

func TestRunState_StageCompletion(t *testing.T) {
	state := pipeline.NewRunState("example.com", "example.com", "full")

	if state.StageCompleted("subdomain-discovery") {
		t.Error("stage should not be completed before running")
	}

	state.SetStageStatus("subdomain-discovery", pipeline.StatusCompleted)

	if !state.StageCompleted("subdomain-discovery") {
		t.Error("stage should be completed after SetStageStatus(Completed)")
	}
}

func TestRunState_MarkInterrupted(t *testing.T) {
	state := pipeline.NewRunState("example.com", "example.com", "full")
	state.SetStageStatus("subdomain-discovery", pipeline.StatusRunning)
	state.MarkInterrupted()

	if state.Completed {
		t.Error("interrupted state should not be marked completed")
	}
	if !state.Interrupted {
		t.Error("interrupted state must have Interrupted=true")
	}
}

func TestRunState_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")

	state := pipeline.NewRunState("example.com", "example.com", "full")
	state.SetStageStatus("subdomain-discovery", pipeline.StatusCompleted)

	if err := state.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := pipeline.Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !loaded.StageCompleted("subdomain-discovery") {
		t.Error("loaded state should show subdomain-discovery as completed")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
