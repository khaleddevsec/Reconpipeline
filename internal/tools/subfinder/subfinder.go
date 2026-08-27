// Package subfinder provides the Subfinder tool adapter for Reconpipeline.
package subfinder

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/frozeniceee/Reconpipeline/internal/executor"
	"github.com/frozeniceee/Reconpipeline/internal/scope"
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

// Run executes subfinder against the target domain and its root domain,
// writing discovered subdomains to outFile, ensuring target domain is included.
func (t *Tool) Run(ctx context.Context, domain string, outFile string, threads int) error {
	if !t.Available() {
		return fmt.Errorf("subfinder binary not found at %q", t.binPath)
	}

	rootDomain := scope.RootDomain(domain)
	targetDomains := []string{rootDomain}
	if domain != rootDomain {
		targetDomains = append(targetDomains, domain)
	}

	// Run subfinder with root domain for maximum discovery
	args := []string{
		"-d", rootDomain,
		"-o", outFile,
		"-silent",
		"-t", fmt.Sprintf("%d", threads),
	}

	result := executor.Run(ctx, t.binPath, args, executor.Options{})
	if result.Error != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Subfinder may exit non-zero if no subdomains found or rate limited, continue
	}

	// Ensure target domain and root domain are present in subdomains.txt
	return t.ensureHosts(outFile, targetDomains)
}

func (t *Tool) ensureHosts(outFile string, requiredHosts []string) error {
	seen := make(map[string]bool)
	var lines []string

	for _, h := range requiredHosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" && !seen[h] {
			seen[h] = true
			lines = append(lines, h)
		}
	}

	data, err := os.ReadFile(outFile)
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			host := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if host != "" && !seen[host] {
				seen[host] = true
				lines = append(lines, host)
			}
		}
	}

	sort.Strings(lines)

	f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("failed to write subdomains file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}
