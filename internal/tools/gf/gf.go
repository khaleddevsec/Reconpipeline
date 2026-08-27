// Package gf provides the GF (grep-like pattern matching) tool adapter for Reconpipeline.
package gf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

const toolName = "gf"

// Pattern represents a GF pattern name and output file.
type Pattern struct {
	Name    string
	OutFile string
}

// DefaultPatterns are the pattern analysis targets.
var DefaultPatterns = []Pattern{
	{Name: "xss", OutFile: "xss.txt"},
	{Name: "sqli", OutFile: "sqli.txt"},
	{Name: "lfi", OutFile: "lfi.txt"},
	{Name: "ssrf", OutFile: "ssrf.txt"},
	{Name: "redirect", OutFile: "redirect.txt"},
}

// Tool is the GF tool adapter.
type Tool struct {
	binPath string
}

// New creates a GF adapter using the managed binary path.
func New(ws *workspace.Manager) *Tool {
	return &Tool{binPath: ws.ToolBinaryPath(toolName)}
}

// Name returns the tool name.
func (t *Tool) Name() string { return toolName }

// BinaryPath returns the absolute path to the managed binary.
func (t *Tool) BinaryPath() string { return t.binPath }

// Available returns true if the managed binary exists and is executable.
func (t *Tool) Available() bool { return workspace.IsExecutable(t.binPath) }

// RunPattern executes gf with a single pattern, reading URLs from urlsFile
// and writing matches to outFile.
func (t *Tool) RunPattern(ctx context.Context, pattern string, urlsFile string, outFile string) error {
	if !t.Available() {
		return fmt.Errorf("gf binary not found at %q", t.binPath)
	}

	inFile, err := os.Open(urlsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(outFile, []byte{}, 0640)
		}
		return fmt.Errorf("failed to open URLs file: %w", err)
	}
	defer inFile.Close()

	outF, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer outF.Close()

	// gf reads from stdin when given a pattern argument.
	// Use exec.CommandContext directly to attach stdin/stdout.
	cmd := exec.CommandContext(ctx, t.binPath, pattern) //nolint:gosec — path is from managed tools dir
	cmd.Stdin = inFile
	cmd.Stdout = outF
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// gf returns non-zero when there are no matches — that is acceptable.
	}
	return nil
}

// RunAll runs all default patterns against the URLs file, writing each
// result to the output directory. Returns a map of pattern name → match count.
func (t *Tool) RunAll(ctx context.Context, urlsFile string, outDir string) (map[string]int, error) {
	counts := make(map[string]int)

	for _, p := range DefaultPatterns {
		select {
		case <-ctx.Done():
			return counts, ctx.Err()
		default:
		}

		outFile := filepath.Join(outDir, p.OutFile)
		if err := t.RunPattern(ctx, p.Name, urlsFile, outFile); err != nil {
			counts[p.Name] = 0
			continue
		}
		counts[p.Name] = countFile(outFile)
	}

	// Write other-patterns.txt placeholder.
	otherFile := filepath.Join(outDir, "other-patterns.txt")
	_ = os.WriteFile(otherFile, []byte("# Additional pattern matches\n"), 0640)

	return counts, nil
}

func countFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				n++
			}
			start = i + 1
		}
	}
	if start < len(data) {
		n++
	}
	return n
}
