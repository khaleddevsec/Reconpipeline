// Package history manages persistent scan records, historical metadata, and scan isolation.
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/pipeline"
	"github.com/khaleddevsec/Reconpipeline/internal/version"
)

// ScanMeta represents the structured metadata of a recorded scan.
type ScanMeta struct {
	ScanID           string            `json:"scan_id"`
	Target           string            `json:"target"`
	NormalisedTarget string            `json:"normalised_target"`
	Version          string            `json:"version"`
	Mode             string            `json:"mode"`
	StartTime        time.Time         `json:"start_time"`
	EndTime          *time.Time        `json:"end_time,omitempty"`
	Duration         string            `json:"duration,omitempty"`
	Status           string            `json:"status"` // "completed", "partial", "interrupted", "failed"
	FailedStage      string            `json:"failed_stage,omitempty"`
	Counters         pipeline.Counters `json:"counters"`
	Warnings         []string          `json:"warnings,omitempty"`
	Errors           []string          `json:"errors,omitempty"`
}

// GenerateScanID produces a deterministic, human-readable scan identifier based on timestamp.
func GenerateScanID(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return fmt.Sprintf("scan-%s", t.Format("20060102-150405"))
}

// HistoryDir returns the path to the history directory within a target's result root.
func HistoryDir(targetDir string) string {
	return filepath.Join(targetDir, "history")
}

// SaveScan records a scan's metadata, snapshots, and summaries into target history.
func SaveScan(targetDir string, state *pipeline.RunState) (*ScanMeta, string, error) {
	if state == nil {
		return nil, "", fmt.Errorf("cannot save nil run state")
	}

	histDir := HistoryDir(targetDir)
	if err := os.MkdirAll(histDir, 0750); err != nil {
		return nil, "", fmt.Errorf("failed to create history directory: %w", err)
	}

	scanID := state.ScanID
	if scanID == "" {
		scanID = GenerateScanID(state.StartTime)
		state.ScanID = scanID
	}

	scanDir := filepath.Join(histDir, scanID)
	if err := os.MkdirAll(scanDir, 0750); err != nil {
		return nil, "", fmt.Errorf("failed to create scan history directory: %w", err)
	}

	status := "completed"
	failedStage := ""
	if state.Interrupted {
		status = "interrupted"
	} else if !state.Completed {
		status = "partial"
	}

	for _, s := range state.Stages {
		if s.Status == pipeline.StatusFailed {
			status = "failed"
			failedStage = s.Name
			break
		}
	}

	meta := &ScanMeta{
		ScanID:           scanID,
		Target:           state.Target,
		NormalisedTarget: state.NormalisedTarget,
		Version:          version.Version,
		Mode:             state.Mode,
		StartTime:        state.StartTime,
		EndTime:          state.EndTime,
		Duration:         state.Duration,
		Status:           status,
		FailedStage:      failedStage,
		Counters:         state.Counters,
		Warnings:         state.Warnings,
		Errors:           state.Errors,
	}

	// 1. Write scan.json
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal scan metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(scanDir, "scan.json"), metaData, 0640); err != nil {
		return nil, "", fmt.Errorf("failed to write scan.json: %w", err)
	}

	// 2. Write summary.json
	summaryData, _ := json.MarshalIndent(meta.Counters, "", "  ")
	_ = os.WriteFile(filepath.Join(scanDir, "summary.json"), summaryData, 0640)

	// 3. Write summary.txt
	summaryTxt := fmt.Sprintf("Reconpipeline %s\nTarget: %s\nScan ID: %s\nStatus: %s\nDuration: %s\n\nSubdomains: %d\nLive Hosts: %d\nUnique URLs: %d\nAPI URLs: %d\nJavaScript: %d\nParameters: %d\n",
		meta.Version, meta.Target, meta.ScanID, meta.Status, meta.Duration,
		meta.Counters.Subdomains, meta.Counters.LiveHosts, meta.Counters.UniqueURLs,
		meta.Counters.APIURLs, meta.Counters.JavaScriptURLs, meta.Counters.ParamURLs)
	_ = os.WriteFile(filepath.Join(scanDir, "summary.txt"), []byte(summaryTxt), 0640)

	// 4. Snapshot key artifacts for fast comparison without traversing complex folders
	snapshotArtifacts(targetDir, scanDir)

	return meta, scanDir, nil
}

// snapshotArtifacts copies key lists (subdomains, live hosts, unique URLs, metadata) into scanDir.
func snapshotArtifacts(targetDir, scanDir string) {
	filesToCopy := []struct {
		srcRel string
		dst    string
	}{
		{filepath.Join("01-subdomain-discovery", "subdomains.txt"), "subdomains.txt"},
		{filepath.Join("02-live-host-detection", "live-hosts.txt"), "live-hosts.txt"},
		{filepath.Join("02-live-host-detection", "metadata.json"), "hosts-metadata.json"},
		{filepath.Join("05-url-processing", "unique-urls.txt"), "unique-urls.txt"},
		{filepath.Join("05-url-processing", "api-urls.txt"), "api-urls.txt"},
		{filepath.Join("05-url-processing", "javascript-urls.txt"), "javascript-urls.txt"},
		{filepath.Join("05-url-processing", "parameterized-urls.txt"), "parameterized-urls.txt"},
		{filepath.Join("05-url-processing", "interesting-urls.txt"), "interesting-urls.txt"},
		{filepath.Join("summary", "statistics.json"), "statistics.json"},
	}

	for _, f := range filesToCopy {
		srcPath := filepath.Join(targetDir, f.srcRel)
		if data, err := os.ReadFile(srcPath); err == nil {
			_ = os.WriteFile(filepath.Join(scanDir, f.dst), data, 0640)
		}
	}
}

// ListScans returns all recorded scans for a target, ordered chronologically.
func ListScans(targetDir string) ([]ScanMeta, error) {
	histDir := HistoryDir(targetDir)
	entries, err := os.ReadDir(histDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read history directory: %w", err)
	}

	var scans []ScanMeta
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		scanJSONPath := filepath.Join(histDir, entry.Name(), "scan.json")
		data, err := os.ReadFile(scanJSONPath)
		if err != nil {
			continue
		}
		var sm ScanMeta
		if err := json.Unmarshal(data, &sm); err != nil {
			continue
		}
		scans = append(scans, sm)
	}

	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartTime.Before(scans[j].StartTime)
	})

	return scans, nil
}

// GetScan retrieves a specific scan by scanID.
func GetScan(targetDir, scanID string) (*ScanMeta, string, error) {
	scanDir := filepath.Join(HistoryDir(targetDir), scanID)
	scanJSONPath := filepath.Join(scanDir, "scan.json")
	data, err := os.ReadFile(scanJSONPath)
	if err != nil {
		return nil, "", fmt.Errorf("scan %q not found: %w", scanID, err)
	}
	var sm ScanMeta
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, "", fmt.Errorf("corrupt scan metadata for %q: %w", scanID, err)
	}
	return &sm, scanDir, nil
}

// GetLatestScan returns the most recent scan in target history.
func GetLatestScan(targetDir string) (*ScanMeta, string, error) {
	scans, err := ListScans(targetDir)
	if err != nil {
		return nil, "", err
	}
	if len(scans) == 0 {
		return nil, "", nil
	}
	latest := scans[len(scans)-1]
	scanDir := filepath.Join(HistoryDir(targetDir), latest.ScanID)
	return &latest, scanDir, nil
}

// GetPreviousScan returns the scan that immediately preceded the given currentScanID.
func GetPreviousScan(targetDir, currentScanID string) (*ScanMeta, string, error) {
	scans, err := ListScans(targetDir)
	if err != nil {
		return nil, "", err
	}
	if len(scans) <= 1 {
		return nil, "", nil
	}

	for i := len(scans) - 1; i >= 0; i-- {
		if scans[i].ScanID == currentScanID {
			if i > 0 {
				prev := scans[i-1]
				return &prev, filepath.Join(HistoryDir(targetDir), prev.ScanID), nil
			}
			return nil, "", nil
		}
	}

	// If currentScanID wasn't matched (e.g. running in memory before saving), return the last saved scan
	last := scans[len(scans)-1]
	return &last, filepath.Join(HistoryDir(targetDir), last.ScanID), nil
}

// FormatDuration formats a time duration into a compact readable string.
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m == 0 {
		return fmt.Sprintf("%02ds", s)
	}
	return fmt.Sprintf("%02dm %02ds", m, s)
}

// FormatTime formats a timestamp into standard human readable date.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

// Capitalize returns capitalized status string.
func Capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
