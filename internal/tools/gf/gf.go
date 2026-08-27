// Package gf provides the GF (grep-like pattern matching) tool adapter for Reconpipeline.
package gf

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

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

// Built-in pattern regexes matching standard GF patterns for parameter analysis.
var builtInPatterns = map[string]*regexp.Regexp{
	"xss":      regexp.MustCompile(`(?i)(access_token|action|admin|adm|alter|app|auth|authentication|backup|b|base|bot|browse|buy|callback|category|change|char|checkout|city|clear|code|command|config|confirm|contact|content|continue|control|create|database|db|debug|delete|dest|dir|direction|display|do|domain|download|edit|email|end|enter|error|eval|exec|exit|export|field|file|filter|find|first|flush|format|forward|from|goto|grant|group|handle|hash|head|help|history|host|id|image|img|include|index|insert|into|item|join|key|lang|language|last|link|load|log|login|logout|lookup|mail|make|master|message|mode|modify|module|name|nav|navigation|new|next|num|number|open|order|out|page|pass|password|path|phone|pid|post|preview|price|print|process|profile|query|read|redirect|ref|refresh|register|remove|report|request|reset|response|return|role|root|run|save|scan|search|select|send|service|session|set|setup|show|site|sort|source|sql|src|start|state|status|stop|sub|submit|table|tag|target|task|test|theme|title|to|token|topic|total|track|transfer|type|uid|update|upload|url|user|username|val|valid|validate|value|var|view|vote|web|window|zip)=`),
	"sqli":     regexp.MustCompile(`(?i)(id|select|insert|update|delete|drop|union|order|group|limit|waitfor|benchmark|sleep|table|column|admin|auth|token|query|sort|order_by|filter|dir|search|field|row|page|column_name)=`),
	"lfi":      regexp.MustCompile(`(?i)(file|document|folder|root|path|pg|style|pdf|template|php_path|doc|page|include|location|read|view|item|dir|load|filename)=`),
	"ssrf":     regexp.MustCompile(`(?i)(dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open)=`),
	"redirect": regexp.MustCompile(`(?i)(redirect|url|next|target|dest|destination|uri|path|continue|return|checkout_url|goto|link|view|to|out|image_url|next_url|return_url|redirect_url|forward)=`),
}

// Tool is the GF tool adapter.
type Tool struct {
	binPath string
}

// New creates a GF adapter using the managed binary path.
func New(ws *workspace.Manager) *Tool {
	EnsurePatternFiles()
	return &Tool{binPath: ws.ToolBinaryPath(toolName)}
}

// Name returns the tool name.
func (t *Tool) Name() string { return toolName }

// BinaryPath returns the absolute path to the managed binary.
func (t *Tool) BinaryPath() string { return t.binPath }

// Available returns true if the managed binary exists and is executable or built-in engine is available.
func (t *Tool) Available() bool { return true }

// EnsurePatternFiles creates the default JSON pattern files in ~/.gf and ~/.reconpipeline/patterns.
func EnsurePatternFiles() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}

	dirs := []string{
		filepath.Join(home, ".gf"),
		filepath.Join(home, ".config", "gf"),
		filepath.Join(home, ".reconpipeline", "patterns"),
	}

	patterns := map[string]string{
		"xss.json":      `{"flags":"-iE","pattern":"(\\?|&)(access_token|action|admin|adm|alter|app|auth|authentication|backup|b|base|bot|browse|buy|callback|category|change|char|checkout|city|clear|code|command|config|confirm|contact|content|continue|control|create|database|db|debug|delete|dest|dir|direction|display|do|domain|download|edit|email|end|enter|error|eval|exec|exit|export|field|file|filter|find|first|flush|format|forward|from|goto|grant|group|handle|hash|head|help|history|host|id|image|img|include|index|insert|into|item|join|key|lang|language|last|link|load|log|login|logout|lookup|mail|make|master|message|mode|modify|module|name|nav|navigation|new|next|num|number|open|order|out|page|pass|password|path|phone|pid|post|preview|price|print|process|profile|query|read|redirect|ref|refresh|register|remove|report|request|reset|response|return|role|root|run|save|scan|search|select|send|service|session|set|setup|show|site|sort|source|sql|src|start|state|status|stop|sub|submit|table|tag|target|task|test|theme|title|to|token|topic|total|track|transfer|type|uid|update|upload|url|user|username|val|valid|validate|value|var|view|vote|web|window|zip)="}`,
		"sqli.json":     `{"flags":"-iE","pattern":"(\\?|&)(id|select|insert|update|delete|drop|union|order|group|limit|waitfor|benchmark|sleep|table|column|admin|auth|token|query|sort|order_by|filter)="}`,
		"lfi.json":      `{"flags":"-iE","pattern":"(\\?|&)(file|document|folder|root|path|pg|style|pdf|template|php_path|doc|page|include|location|read|view|item)="}`,
		"ssrf.json":     `{"flags":"-iE","pattern":"(\\?|&)(dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open)="}`,
		"redirect.json": `{"flags":"-iE","pattern":"(\\?|&)(redirect|url|next|target|dest|destination|uri|path|continue|return|checkout_url|goto|link|view|to|out|image_url|next_url|return_url|redirect_url)="}`,
	}

	for _, d := range dirs {
		_ = os.MkdirAll(d, 0750)
		for filename, content := range patterns {
			p := filepath.Join(d, filename)
			if _, err := os.Stat(p); os.IsNotExist(err) {
				_ = os.WriteFile(p, []byte(content+"\n"), 0640)
			}
		}
	}
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
	re, ok := builtInPatterns[strings.ToLower(pattern)]
	if !ok {
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
