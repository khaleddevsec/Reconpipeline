package katana

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/khaleddevsec/Reconpipeline/internal/executor"
	"github.com/khaleddevsec/Reconpipeline/internal/scope"
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
func (t *Tool) Run(ctx context.Context, liveHostsFile string, rootDomain string, outFile string, threads int, optionalDepth ...int) error {
	if !t.Available() {
		return fmt.Errorf("katana binary not found at %q", t.binPath)
	}

	crawlDepth := 3
	if len(optionalDepth) > 0 && optionalDepth[0] > 0 {
		crawlDepth = optionalDepth[0]
	}

	args := []string{
		"-list", liveHostsFile,
		"-o", outFile,
		"-silent",
		"-no-color",
		"-c", fmt.Sprintf("%d", threads),
		// Restrict crawl scope to the root domain.
		"-d", fmt.Sprintf("%d", crawlDepth),
		"-cs", regexp.QuoteMeta(rootDomain),
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

	// Secondary scope enforcement: filter any URLs that escaped crawl boundaries
	filterOutOfScopeURLs(outFile, rootDomain)
	return nil
}

func filterOutOfScopeURLs(path string, rootDomain string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}

	policy := scope.NewPolicy(&scope.Target{Domain: rootDomain})
	var filtered []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && policy.IsURLInScope(line) {
			filtered = append(filtered, line)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range filtered {
		fmt.Fprintln(w, l)
	}
	_ = w.Flush()
}
