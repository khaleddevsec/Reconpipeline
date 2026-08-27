// Package httpx provides the HTTPX tool adapter for Reconpipeline.
package httpx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/frozeniceee/Reconpipeline/internal/executor"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

const toolName = "httpx"

// Tool is the HTTPX tool adapter.
type Tool struct {
	binPath string
}

// New creates an HTTPX adapter using the managed binary path.
func New(ws *workspace.Manager) *Tool {
	return &Tool{binPath: ws.ToolBinaryPath(toolName)}
}

// Name returns the tool name.
func (t *Tool) Name() string { return toolName }

// BinaryPath returns the absolute path to the managed binary.
func (t *Tool) BinaryPath() string { return t.binPath }

// Available returns true if the managed binary exists and is executable.
func (t *Tool) Available() bool { return workspace.IsExecutable(t.binPath) }

// HostMeta holds metadata collected for a live host.
type HostMeta struct {
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	Title       string `json:"title"`
	Server      string `json:"server"`
	ContentType string `json:"content_type"`
	Technology  string `json:"technology"`
	Location    string `json:"location"`
}

// Run executes httpx against the subdomains file and writes:
//   - live-hosts.txt: one URL per line
//   - metadata.json: array of HostMeta
func (t *Tool) Run(ctx context.Context, subdomainsFile string, outDir string, threads int) error {
	if !t.Available() {
		return fmt.Errorf("httpx binary not found at %q", t.binPath)
	}

	jsonOutFile := filepath.Join(outDir, "httpx-raw.jsonl")
	liveHostsFile := filepath.Join(outDir, "live-hosts.txt")
	metaFile := filepath.Join(outDir, "metadata.json")

	args := []string{
		"-l", subdomainsFile,
		"-o", jsonOutFile,
		"-silent",
		"-json",
		"-status-code",
		"-title",
		"-server",
		"-content-type",
		"-location",
		"-threads", fmt.Sprintf("%d", threads),
		"-no-color",
	}

	result := executor.Run(ctx, t.binPath, args, executor.Options{})
	if result.Error != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// httpx may exit non-zero with no results — only fail on hard error.
		if result.ExitCode == -1 {
			return fmt.Errorf("httpx failed to execute: %w", result.Error)
		}
	}

	// Parse JSONL output and write structured files.
	return t.parseOutput(jsonOutFile, liveHostsFile, metaFile)
}

// parseOutput reads httpx JSON-lines output and writes clean output files.
func (t *Tool) parseOutput(jsonlFile, liveHostsFile, metaFile string) error {
	f, err := os.Open(jsonlFile)
	if os.IsNotExist(err) {
		// No output — write empty files.
		_ = os.WriteFile(liveHostsFile, []byte{}, 0640)
		_ = os.WriteFile(metaFile, []byte("[]"), 0640)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to open httpx output: %w", err)
	}
	defer f.Close()

	var hosts []string
	var metas []HostMeta

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// httpx JSON output fields.
		var raw struct {
			URL         string `json:"url"`
			StatusCode  int    `json:"status-code"`
			Title       string `json:"title"`
			WebServer   string `json:"webserver"`
			ContentType string `json:"content-type"`
			Location    string `json:"location"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}
		if raw.URL == "" {
			continue
		}
		hosts = append(hosts, raw.URL)
		metas = append(metas, HostMeta{
			URL:         raw.URL,
			StatusCode:  raw.StatusCode,
			Title:       raw.Title,
			Server:      raw.WebServer,
			ContentType: raw.ContentType,
			Location:    raw.Location,
		})
	}

	// Write live-hosts.txt.
	lf, err := os.OpenFile(liveHostsFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("failed to write live-hosts.txt: %w", err)
	}
	for _, h := range hosts {
		fmt.Fprintln(lf, h)
	}
	lf.Close()

	// Write metadata.json.
	metaData, _ := json.MarshalIndent(metas, "", "  ")
	_ = os.WriteFile(metaFile, metaData, 0640)

	return nil
}

// LiveHosts returns the count of live hosts from the output directory.
func LiveHostCount(outDir string) int {
	return countLines(filepath.Join(outDir, "live-hosts.txt"))
}

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
