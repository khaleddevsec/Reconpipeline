// Package gf provides the GF (grep-like pattern matching) tool adapter for Reconpipeline.
package gf

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

const toolName = "gf"

// Pattern represents a GF pattern name and output file.
type Pattern struct {
	Name    string
	OutFile string
}

// DefaultPatterns are the pattern analysis targets (original 5 first, followed by extended categories).
var DefaultPatterns = []Pattern{
	// Classic Vulnerability Candidates
	{Name: "xss", OutFile: "xss.txt"},
	{Name: "sqli", OutFile: "sqli.txt"},
	{Name: "lfi", OutFile: "lfi.txt"},
	{Name: "ssrf", OutFile: "ssrf.txt"},
	{Name: "redirect", OutFile: "redirect.txt"},

	// Extended Vulnerability Candidates
	{Name: "rfi", OutFile: "rfi.txt"},
	{Name: "ssti", OutFile: "ssti.txt"},
	{Name: "xxe", OutFile: "xxe.txt"},
	{Name: "cmdi", OutFile: "cmdi.txt"},
	{Name: "traversal", OutFile: "traversal.txt"},
	{Name: "crlf", OutFile: "crlf.txt"},
	{Name: "proto-pollution", OutFile: "proto-pollution.txt"},
	{Name: "deserialization", OutFile: "deserialization.txt"},

	// API Intelligence
	{Name: "api-rest", OutFile: "api-rest.txt"},
	{Name: "api-graphql", OutFile: "api-graphql.txt"},
	{Name: "api-swagger", OutFile: "api-swagger.txt"},
	{Name: "api-websocket", OutFile: "api-websocket.txt"},

	// Authentication Intelligence
	{Name: "auth-login", OutFile: "auth-login.txt"},
	{Name: "auth-reset", OutFile: "auth-reset.txt"},
	{Name: "auth-mfa", OutFile: "auth-mfa.txt"},
	{Name: "auth-oauth", OutFile: "auth-oauth.txt"},
	{Name: "auth-register", OutFile: "auth-register.txt"},

	// Authorization / Resource Candidates
	{Name: "idor-candidate", OutFile: "idor-candidate.txt"},

	// Administrative Intelligence
	{Name: "admin", OutFile: "admin.txt"},

	// Debug & Metrics Intelligence
	{Name: "debug", OutFile: "debug.txt"},
	{Name: "actuator", OutFile: "actuator.txt"},

	// Sensitive File Intelligence
	{Name: "sensitive-env", OutFile: "sensitive-env.txt"},
	{Name: "sensitive-git", OutFile: "sensitive-git.txt"},
	{Name: "sensitive-sql", OutFile: "sensitive-sql.txt"},
	{Name: "sensitive-log", OutFile: "sensitive-log.txt"},
	{Name: "sensitive-config", OutFile: "sensitive-config.txt"},

	// Backup & Legacy Intelligence
	{Name: "backup", OutFile: "backup.txt"},
	{Name: "legacy", OutFile: "legacy.txt"},

	// Secret & Credential Indicator
	{Name: "secret-token", OutFile: "secret-token.txt"},
	{Name: "secret-key", OutFile: "secret-key.txt"},

	// Cloud Infrastructure Intelligence
	{Name: "cloud-s3", OutFile: "cloud-s3.txt"},
	{Name: "cloud-azure", OutFile: "cloud-azure.txt"},
	{Name: "cloud-gcp", OutFile: "cloud-gcp.txt"},
	{Name: "cloud-cloudfront", OutFile: "cloud-cloudfront.txt"},

	// File Operations Intelligence
	{Name: "file-upload", OutFile: "file-upload.txt"},
	{Name: "file-download", OutFile: "file-download.txt"},
}

// Tool is the GF tool adapter.
type Tool struct {
	binPath string
	engine  *Engine
}

// New creates a GF adapter using the managed binary path.
func New(ws *workspace.Manager) *Tool {
	EnsurePatternFiles()
	return &Tool{
		binPath: ws.ToolBinaryPath(toolName),
		engine:  NewEngine(),
	}
}

// Name returns the tool name.
func (t *Tool) Name() string { return toolName }

// BinaryPath returns the absolute path to the managed binary.
func (t *Tool) BinaryPath() string { return t.binPath }

// Available returns true if the managed binary exists and is executable or built-in engine is available.
func (t *Tool) Available() bool { return true }

// RunIntelligence executes the full Pattern Intelligence Layer with context enrichment and takeover analysis.
func (t *Tool) RunIntelligence(ctx context.Context, actx *AnalysisContext, urlsFile string, outDir string) (*IntelligenceSummary, map[string]int, error) {
	if t.engine == nil {
		t.engine = NewEngine()
	}
	return t.engine.RunAnalysis(ctx, actx, urlsFile, outDir)
}

// RunPattern executes pattern matching against urlsFile and writes matches to outFile.
func (t *Tool) RunPattern(ctx context.Context, pattern string, urlsFile string, outFile string) error {
	inFile, err := os.Open(urlsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(outFile, []byte{}, 0640)
		}
		return fmt.Errorf("failed to open URLs file: %w", err)
	}
	defer inFile.Close()

	// If external gf binary is available and executable, try executing it.
	if workspace.IsExecutable(t.binPath) {
		outF, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
		if err == nil {
			cmd := exec.CommandContext(ctx, t.binPath, pattern)
			cmd.Stdin = inFile
			cmd.Stdout = outF
			cmd.Stderr = nil
			if runErr := cmd.Run(); runErr == nil {
				outF.Close()
				return nil
			}
			outF.Close()
		}
		// Reset inFile seek if external run failed
		_, _ = inFile.Seek(0, 0)
	}

	// Native Pure-Go Pattern Matcher
	return t.runNativePattern(ctx, pattern, inFile, outFile)
}

// runNativePattern performs regex pattern analysis in pure Go.
func (t *Tool) runNativePattern(ctx context.Context, pattern string, inFile *os.File, outFile string) error {
	var re *regexp.Regexp
	if def, found := FindDefinition(pattern); found {
		re = def.Regex
	} else {
		// Generic fallback pattern matching query parameters
		re = regexp.MustCompile(fmt.Sprintf(`(?i)[?&](%s)=`, regexp.QuoteMeta(pattern)))
	}

	outF, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer outF.Close()

	scanner := bufio.NewScanner(inFile)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	w := bufio.NewWriter(outF)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		if re.MatchString(line) {
			fmt.Fprintln(w, line)
		}
	}

	return w.Flush()
}

// RunAll runs all default patterns against the URLs file, writing each
// result to the output directory. Returns a map of pattern name -> match count.
func (t *Tool) RunAll(ctx context.Context, urlsFile string, outDir string) (map[string]int, error) {
	actx := &AnalysisContext{
		VerifiedURLsFile: urlsFile,
	}
	_, counts, err := t.RunIntelligence(ctx, actx, urlsFile, outDir)
	return counts, err
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
