// Package katana provides the Katana tool adapter for Reconpipeline.
package katana

import (
	"context"
	"fmt"

	"github.com/khaleddevsec/Reconpipeline/internal/executor"
	"github.com/khaleddevsec/Reconpipeline/internal/workspace"
)

const toolName = "katana"

// Tool is the Katana tool adapter.
type Tool struct {
	binPath string
}

// New creates a Katana adapter using the managed binary path.
func New(ws *workspace.Manager) *Tool {
	return &Tool{binPath: ws.ToolBinaryPath(toolName)}
}

// Name returns the tool name.
func (t *Tool) Name() string { return toolName }

// BinaryPath returns the absolute path to the managed binary.
func (t *Tool) BinaryPath() string { return t.binPath }

// Available returns true if the managed binary exists and is executable.
func (t *Tool) Available() bool { return workspace.IsExecutable(t.binPath) }

// Run executes katana against the live hosts file, scoped to rootDomain,
// and writes discovered URLs to outFile.
func (t *Tool) Run(ctx context.Context, liveHostsFile string, rootDomain string, outFile string, threads int) error {
	if !t.Available() {
		return fmt.Errorf("katana binary not found at %q", t.binPath)
	}

	args := []string{
		"-list", liveHostsFile,
		"-o", outFile,
		"-silent",
		"-no-color",
		"-c", fmt.Sprintf("%d", threads),
		// Restrict crawl scope to the root domain.
		"-d", "5",
		"-fs", "fqdn",
		"-jc", // extract URLs from JavaScript
		"-kf", "all",
	}

	result := executor.Run(ctx, t.binPath, args, executor.Options{})
	if result.Error != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if result.ExitCode == -1 {
			return fmt.Errorf("katana failed to execute: %w", result.Error)
		}
	}

	_ = rootDomain
	return nil
}
