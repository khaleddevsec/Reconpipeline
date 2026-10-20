// Package status organizes live hosts by HTTP response status codes.
package status

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/khaleddevsec/Reconpipeline/internal/tools/httpx"
)

// Summary holds status code distribution and grouped URLs.
type Summary struct {
	Class2xx          []string    `json:"2xx"`
	Class3xx          []string    `json:"3xx"`
	Class4xx          []string    `json:"4xx"`
	Class5xx          []string    `json:"5xx"`
	InterestingStatus []string    `json:"interesting_status"`
	Distribution      map[int]int `json:"distribution"`
}

// Engine groups live hosts by HTTP response status.
type Engine struct{}

// NewEngine creates a new HTTP Status Intelligence Engine.
func NewEngine() *Engine {
	return &Engine{}
}

// ProcessMetadata parses HTTPX metadata and generates status-based groups in statusDir.
func (e *Engine) ProcessMetadata(metadataFile, statusDir string) (*Summary, error) {
	if err := os.MkdirAll(statusDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create status directory: %w", err)
	}

	data, err := os.ReadFile(metadataFile)
	if os.IsNotExist(err) {
		return &Summary{Distribution: make(map[int]int)}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metas []httpx.HostMeta
	if err := json.Unmarshal(data, &metas); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	summary := &Summary{
		Distribution: make(map[int]int),
	}

	for _, m := range metas {
		code := m.StatusCode
		if code == 0 {
			continue
		}

		summary.Distribution[code]++
		line := fmt.Sprintf("%s [%d]", m.URL, code)

		switch {
		case code >= 200 && code < 300:
			summary.Class2xx = append(summary.Class2xx, line)
		case code >= 300 && code < 400:
			if m.Location != "" {
				line = fmt.Sprintf("%s [%d -> %s]", m.URL, code, m.Location)
			}
			summary.Class3xx = append(summary.Class3xx, line)
		case code >= 400 && code < 500:
			summary.Class4xx = append(summary.Class4xx, line)
			if isInterestingStatus(code) {
				summary.InterestingStatus = append(summary.InterestingStatus, line)
			}
		case code >= 500 && code < 600:
			summary.Class5xx = append(summary.Class5xx, line)
			summary.InterestingStatus = append(summary.InterestingStatus, line)
		}
	}

	sort.Strings(summary.Class2xx)
	sort.Strings(summary.Class3xx)
	sort.Strings(summary.Class4xx)
	sort.Strings(summary.Class5xx)
	sort.Strings(summary.InterestingStatus)

	_ = writeLines(filepath.Join(statusDir, "2xx.txt"), summary.Class2xx)
	_ = writeLines(filepath.Join(statusDir, "3xx.txt"), summary.Class3xx)
	_ = writeLines(filepath.Join(statusDir, "4xx.txt"), summary.Class4xx)
	_ = writeLines(filepath.Join(statusDir, "5xx.txt"), summary.Class5xx)
	_ = writeLines(filepath.Join(statusDir, "interesting-status.txt"), summary.InterestingStatus)

	// Write status.json
	jsonData, _ := json.MarshalIndent(summary, "", "  ")
	_ = os.WriteFile(filepath.Join(statusDir, "status.json"), jsonData, 0640)

	return summary, nil
}

func isInterestingStatus(code int) bool {
	switch code {
	case 401, 403, 405, 407, 418, 429, 451:
		return true
	default:
		return false
	}
}

func writeLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}
