package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/pipeline"
	"github.com/khaleddevsec/Reconpipeline/internal/workspace"
)

func TestOrchestrator_LifecycleStates(t *testing.T) {
	state := pipeline.NewRunState("example.com", "example.com", "full")

	// Verify initial state is pending
	for _, s := range state.Stages {
		if s.Status != pipeline.StatusPending {
			t.Errorf("expected stage %s to be pending, got %s", s.Name, s.Status)
		}
	}

	// Transition to running
	state.SetStageStatus("subdomain-discovery", pipeline.StatusRunning)
	if state.Stages[0].Status != pipeline.StatusRunning || state.Stages[0].StartedAt == nil {
		t.Error("expected subdomain-discovery to be running with StartedAt set")
	}

	// Transition to completed
	state.SetStageCompleted("subdomain-discovery", "/tmp/results/01-subdomain-discovery", false)
	if state.Stages[0].Status != pipeline.StatusCompleted || state.Stages[0].EndedAt == nil {
		t.Error("expected subdomain-discovery to be completed with EndedAt set")
	}

	// Transition to failed
	state.SetStageStatus("live-host-detection", pipeline.StatusRunning)
	state.SetStageError("live-host-detection", os.ErrNotExist)
	if state.Stages[1].Status != pipeline.StatusFailed || state.Stages[1].Error == "" {
		t.Error("expected live-host-detection to be failed with Error recorded")
	}

	// Mark interrupted
	state.MarkInterrupted()
	if !state.Interrupted || state.Completed {
		t.Error("expected state to be interrupted and not completed")
	}
}

func TestWorkspace_WriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "nested", "atomic.txt")

	data := []byte("hello atomic world")
	if err := workspace.WriteFileAtomic(filePath, data, 0640); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	readData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(readData) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", string(readData), string(data))
	}

	// Overwrite atomically
	newData := []byte("updated atomic content")
	if err := workspace.WriteFileAtomic(filePath, newData, 0640); err != nil {
		t.Fatalf("WriteFileAtomic overwrite failed: %v", err)
	}

	readUpdated, _ := os.ReadFile(filePath)
	if string(readUpdated) != string(newData) {
		t.Errorf("updated content mismatch: got %q, want %q", string(readUpdated), string(newData))
	}
}
