// Package gau provides the GAU (Get All URLs) tool adapter for Reconpipeline.
package gau

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/frozeniceee/Reconpipeline/internal/executor"
	"github.com/frozeniceee/Reconpipeline/internal/scope"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

const toolName = "gau"

// Tool is the GAU tool adapter.
type Tool struct {
	binPath string
}

// New creates a GAU adapter using the managed binary path.
func New(ws *workspace.Manager) *Tool {
	return &Tool{binPath: ws.ToolBinaryPath(toolName)}
}

// Name returns the tool name.
func (t *Tool) Name() string { return toolName }

// BinaryPath returns the absolute path to the managed binary.
func (t *Tool) BinaryPath() string { return t.binPath }

// Available returns true if the managed binary exists and is executable.
func (t *Tool) Available() bool { return workspace.IsExecutable(t.binPath) }

// Run executes gau against the root domain and domain to discover historical URLs.
func (t *Tool) Run(ctx context.Context, liveHostsFile string, domain string, outFile string, threads int) error {
	if !t.Available() {
		return fmt.Errorf("gau binary not found at %q", t.binPath)
	}

	rootDomain := scope.RootDomain(domain)

	// gau accepts a domain as argument. We run against the root domain with --subs
	// to retrieve all historical URLs associated with it and all its subdomains.
	args := []string{
		"--threads", fmt.Sprintf("%d", threads),
		"--subs",
		"--o", outFile,
		rootDomain,
	}

	result := executor.Run(ctx, t.binPath, args, executor.Options{})
	if result.Error != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if result.ExitCode == -1 {
			return fmt.Errorf("gau failed to execute: %w", result.Error)
		}
		// GAU can return non-zero when there are no results — that is acceptable.
	}

	// If gau wrote nothing, ensure the file exists so downstream doesn't fail.
	ensureFileExists(outFile)
	_ = liveHostsFile
	return nil
}

// ensureFileExists creates the file if it does not exist.
func ensureFileExists(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_ = os.WriteFile(path, []byte{}, 0640)
	}
}

// countLines returns the number of non-empty lines in a file.
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if scanner.Text() != "" {
			n++
		}
	}
	return n
}

// URLCount returns the number of URLs discovered by GAU in the output file.
func URLCount(outFile string) int {
	return countLines(outFile)
}
