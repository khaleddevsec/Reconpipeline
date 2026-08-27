// Package subfinder provides the Subfinder tool adapter for Reconpipeline.
package subfinder

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/frozeniceee/Reconpipeline/internal/executor"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

const toolName = "subfinder"

// Tool is the Subfinder tool adapter.
type Tool struct {
	binPath string
}

// New creates a Subfinder adapter using the managed binary path.
func New(ws *workspace.Manager) *Tool {
	return &Tool{binPath: ws.ToolBinaryPath(toolName)}
}

// Name returns the tool name.
func (t *Tool) Name() string { return toolName }

// BinaryPath returns the absolute path to the managed binary.
func (t *Tool) BinaryPath() string { return t.binPath }

// Available returns true if the managed binary exists and is executable.
func (t *Tool) Available() bool { return workspace.IsExecutable(t.binPath) }

// Run executes subfinder against the target domain, writing discovered
// subdomains to outFile.
func (t *Tool) Run(ctx context.Context, domain string, outFile string, threads int) error {
	if !t.Available() {
		return fmt.Errorf("subfinder binary not found at %q", t.binPath)
	}

	args := []string{
		"-d", domain,
		"-o", outFile,
		"-silent",
		"-t", fmt.Sprintf("%d", threads),
	}

	result := executor.Run(ctx, t.binPath, args, executor.Options{})
	if result.Error != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("subfinder failed: %w", result.Error)
	}

	// subfinder exit 0 even with no results; that's fine.
	_ = filepath.Clean(outFile)
	return nil
}
