package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/history"
	"github.com/frozeniceee/Reconpipeline/internal/pipeline"
)

func TestGenerateScanID(t *testing.T) {
	now := time.Date(2026, 8, 27, 18, 30, 42, 0, time.UTC)
	scanID := history.GenerateScanID(now)
	expected := "scan-20260827-183042"
	if scanID != expected {
		t.Errorf("GenerateScanID() = %q, want %q", scanID, expected)
	}
}

func TestSaveScan_And_ListScans(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "example.com")
	_ = os.MkdirAll(targetDir, 0750)

	t1 := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	end1 := t1.Add(5 * time.Minute)
	state1 := &pipeline.RunState{
		ScanID:           "scan-20260827-100000",
		Target:           "example.com",
		NormalisedTarget: "example.com",
		Mode:             "full",
		Version:          "v2.5.2",
		StartTime:        t1,
		EndTime:          &end1,
		Duration:         "05m 00s",
		Counters: pipeline.Counters{
			Subdomains: 10,
			LiveHosts:  5,
			UniqueURLs: 50,
		},
		Completed: true,
	}

	meta1, scanDir1, err := history.SaveScan(targetDir, state1)
	if err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}
	if meta1.ScanID != "scan-20260827-100000" {
		t.Errorf("unexpected scanID: %q", meta1.ScanID)
	}
	if _, err := os.Stat(filepath.Join(scanDir1, "scan.json")); os.IsNotExist(err) {
		t.Error("scan.json was not created in history folder")
	}

	// Save a second scan
	t2 := time.Date(2026, 8, 28, 11, 0, 0, 0, time.UTC)
	end2 := t2.Add(4 * time.Minute)
	state2 := &pipeline.RunState{
		ScanID:           "scan-20260828-110000",
		Target:           "example.com",
		NormalisedTarget: "example.com",
		Mode:             "full",
		Version:          "v2.5.2",
		StartTime:        t2,
		EndTime:          &end2,
		Duration:         "04m 00s",
		Counters: pipeline.Counters{
			Subdomains: 15,
			LiveHosts:  7,
			UniqueURLs: 75,
		},
		Completed: true,
	}

	_, _, err = history.SaveScan(targetDir, state2)
	if err != nil {
		t.Fatalf("SaveScan 2 failed: %v", err)
	}

	// List scans
	scans, err := history.ListScans(targetDir)
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(scans))
	}
	if scans[0].ScanID != "scan-20260827-100000" || scans[1].ScanID != "scan-20260828-110000" {
		t.Errorf("unexpected scan ordering: %+v", scans)
	}

	// Test GetLatestScan
	latest, _, err := history.GetLatestScan(targetDir)
	if err != nil || latest == nil {
		t.Fatalf("GetLatestScan failed: %v", err)
	}
	if latest.ScanID != "scan-20260828-110000" {
		t.Errorf("GetLatestScan ID = %q, want scan-20260828-110000", latest.ScanID)
	}

	// Test GetPreviousScan
	prev, _, err := history.GetPreviousScan(targetDir, latest.ScanID)
	if err != nil || prev == nil {
		t.Fatalf("GetPreviousScan failed: %v", err)
	}
	if prev.ScanID != "scan-20260827-100000" {
		t.Errorf("GetPreviousScan ID = %q, want scan-20260827-100000", prev.ScanID)
	}
}

func TestTargetIsolation(t *testing.T) {
	dir := t.TempDir()
	targetA := filepath.Join(dir, "target-a.com")
	targetB := filepath.Join(dir, "target-b.com")
	_ = os.MkdirAll(targetA, 0750)
	_ = os.MkdirAll(targetB, 0750)

	stateA := &pipeline.RunState{
		ScanID:    "scan-a-1",
		Target:    "target-a.com",
		StartTime: time.Now(),
		Completed: true,
	}
	stateB := &pipeline.RunState{
		ScanID:    "scan-b-1",
		Target:    "target-b.com",
		StartTime: time.Now(),
		Completed: true,
	}

	_, _, _ = history.SaveScan(targetA, stateA)
	_, _, _ = history.SaveScan(targetB, stateB)

	scansA, _ := history.ListScans(targetA)
	scansB, _ := history.ListScans(targetB)

	if len(scansA) != 1 || scansA[0].ScanID != "scan-a-1" {
		t.Errorf("target A isolation breached: %+v", scansA)
	}
	if len(scansB) != 1 || scansB[0].ScanID != "scan-b-1" {
		t.Errorf("target B isolation breached: %+v", scansB)
	}
}

func TestFailedAndInterruptedScanStatus(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "example.com")
	_ = os.MkdirAll(targetDir, 0750)

	stateFailed := &pipeline.RunState{
		ScanID:    "scan-failed",
		Target:    "example.com",
		StartTime: time.Now(),
		Stages: []pipeline.StageInfo{
			{Name: "subdomain-discovery", Status: pipeline.StatusCompleted},
			{Name: "live-host-detection", Status: pipeline.StatusFailed},
		},
		Completed: false,
	}

	meta, _, err := history.SaveScan(targetDir, stateFailed)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Status != "failed" || meta.FailedStage != "live-host-detection" {
		t.Errorf("expected failed status with failed stage live-host-detection, got status %q failedStage %q", meta.Status, meta.FailedStage)
	}

	stateInterrupted := &pipeline.RunState{
		ScanID:      "scan-interrupted",
		Target:      "example.com",
		StartTime:   time.Now(),
		Interrupted: true,
		Completed:   false,
	}
	metaInt, _, err := history.SaveScan(targetDir, stateInterrupted)
	if err != nil {
		t.Fatal(err)
	}
	if metaInt.Status != "interrupted" {
		t.Errorf("expected interrupted status, got %q", metaInt.Status)
	}
}
