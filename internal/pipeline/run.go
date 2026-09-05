// Package pipeline defines scan run state tracking (run.json).
package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/version"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

// StageStatus represents the completion state of a pipeline stage.
type StageStatus string

const (
	StatusPending     StageStatus = "pending"
	StatusRunning     StageStatus = "running"
	StatusCompleted   StageStatus = "completed"
	StatusFailed      StageStatus = "failed"
	StatusSkipped     StageStatus = "skipped"
	StatusInterrupted StageStatus = "interrupted"
)

// StageInfo holds state and metadata for a single pipeline stage.
type StageInfo struct {
	Name           string      `json:"name"`
	Status         StageStatus `json:"status"`
	StartedAt      *time.Time  `json:"started_at,omitempty"`
	EndedAt        *time.Time  `json:"ended_at,omitempty"`
	Duration       string      `json:"duration,omitempty"`
	OutputLocation string      `json:"output_location,omitempty"`
	Error          string      `json:"error,omitempty"`
	FromCache      bool        `json:"from_cache,omitempty"`
}

// Counters holds the final scan statistics.
type Counters struct {
	Subdomains      int `json:"subdomains"`
	LiveHosts       int `json:"live_hosts"`
	KatanaURLs      int `json:"katana_urls"`
	GAUURLs         int `json:"gau_urls"`
	TotalURLs       int `json:"total_urls"`
	UniqueURLs      int `json:"unique_urls"`
	APIURLs         int `json:"api_urls"`
	JavaScriptURLs  int `json:"javascript_urls"`
	ParamURLs       int `json:"parameterized_urls"`
	InterestingURLs int `json:"interesting_urls"`

	// V2.0 Intelligent Core Metrics
	DNSResolved          int `json:"dns_resolved,omitempty"`
	AssetsClassified     int `json:"assets_classified,omitempty"`
	TechnologiesDetected int `json:"technologies_detected,omitempty"`
	URLClusters          int `json:"url_clusters,omitempty"`
	HighPriorityURLs     int `json:"high_priority_urls,omitempty"`
	MediumPriorityURLs   int `json:"medium_priority_urls,omitempty"`
	LowPriorityURLs      int `json:"low_priority_urls,omitempty"`

	// V2.6 Smart URL Verification Metrics
	SelectedURLs int `json:"selected_urls,omitempty"`
	VerifiedURLs int `json:"verified_urls,omitempty"`

	// Pattern match counts.
	XSSMatches      int `json:"xss_matches"`
	SQLiMatches     int `json:"sqli_matches"`
	LFIMatches      int `json:"lfi_matches"`
	SSRFMatches     int `json:"ssrf_matches"`
	RedirectMatches int `json:"redirect_matches"`

	// V2.8 Pattern Intelligence Layer Metrics
	TotalCandidates          int `json:"total_candidates,omitempty"`
	HighConfidenceCandidates int `json:"high_confidence_candidates,omitempty"`
	TakeoverCandidates       int `json:"takeover_candidates,omitempty"`
	APICandidates            int `json:"api_candidates,omitempty"`
	AuthCandidates           int `json:"auth_candidates,omitempty"`
	AdminCandidates          int `json:"admin_candidates,omitempty"`
	SensitiveFileCandidates  int `json:"sensitive_file_candidates,omitempty"`
}

// RunState is the per-scan state written to run.json.
type RunState struct {
	ScanID           string      `json:"scan_id"`
	Target           string      `json:"target"`
	NormalisedTarget string      `json:"normalised_target"`
	Mode             string      `json:"mode"`
	Profile          string      `json:"profile,omitempty"`
	Version          string      `json:"version"`
	OS               string      `json:"os"`
	Architecture     string      `json:"architecture"`
	StartTime        time.Time   `json:"start_time"`
	EndTime          *time.Time  `json:"end_time,omitempty"`
	Duration         string      `json:"duration,omitempty"`
	Stages           []StageInfo `json:"stages"`
	Counters         Counters    `json:"counters"`
	Warnings         []string    `json:"warnings,omitempty"`
	Errors           []string    `json:"errors,omitempty"`
	Completed        bool        `json:"completed"`
	Interrupted      bool        `json:"interrupted"`
}

// NewRunState creates an initialised RunState.
func NewRunState(target, normalisedTarget, mode string) *RunState {
	now := time.Now().UTC()
	scanID := fmt.Sprintf("scan-%s", now.Format("20060102-150405"))

	stages := []StageInfo{
		{Name: "subdomain-discovery", Status: StatusPending},
		{Name: "live-host-detection", Status: StatusPending},
		{Name: "active-crawling", Status: StatusPending},
		{Name: "historical-url-discovery", Status: StatusPending},
		{Name: "url-processing", Status: StatusPending},
		{Name: "url-verification", Status: StatusPending},
		{Name: "pattern-analysis", Status: StatusPending},
	}

	return &RunState{
		ScanID:           scanID,
		Target:           target,
		NormalisedTarget: normalisedTarget,
		Mode:             mode,
		Profile:          mode,
		Version:          version.Version,
		OS:               runtime.GOOS,
		Architecture:     runtime.GOARCH,
		StartTime:        now,
		Stages:           stages,
	}
}

// Load reads a RunState from disk.
func Load(path string) (*RunState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read run state: %w", err)
	}
	var rs RunState
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("failed to parse run state: %w", err)
	}
	return &rs, nil
}

// Save writes the RunState to disk atomically.
func (rs *RunState) Save(path string) error {
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal run state: %w", err)
	}
	return workspace.WriteFileAtomic(path, data, 0640)
}

// SetStageStatus updates the status of a named stage.
func (rs *RunState) SetStageStatus(name string, status StageStatus) {
	now := time.Now().UTC()
	for i := range rs.Stages {
		if rs.Stages[i].Name == name {
			rs.Stages[i].Status = status
			if status == StatusRunning {
				rs.Stages[i].StartedAt = &now
			} else if status == StatusCompleted || status == StatusFailed || status == StatusSkipped {
				rs.Stages[i].EndedAt = &now
				if rs.Stages[i].StartedAt != nil {
					rs.Stages[i].Duration = now.Sub(*rs.Stages[i].StartedAt).Round(time.Millisecond).String()
				}
			}
			return
		}
	}
}

// SetStageCompleted marks a stage completed with duration and output directory.
func (rs *RunState) SetStageCompleted(name, outputLocation string, fromCache bool) {
	now := time.Now().UTC()
	for i := range rs.Stages {
		if rs.Stages[i].Name == name {
			rs.Stages[i].Status = StatusCompleted
			rs.Stages[i].EndedAt = &now
			rs.Stages[i].OutputLocation = outputLocation
			rs.Stages[i].FromCache = fromCache
			if rs.Stages[i].StartedAt != nil {
				rs.Stages[i].Duration = now.Sub(*rs.Stages[i].StartedAt).Round(time.Millisecond).String()
			}
			return
		}
	}
}

// SetStageError records an error for a stage.
func (rs *RunState) SetStageError(name string, err error) {
	now := time.Now().UTC()
	for i := range rs.Stages {
		if rs.Stages[i].Name == name {
			rs.Stages[i].Status = StatusFailed
			rs.Stages[i].EndedAt = &now
			if err != nil {
				rs.Stages[i].Error = err.Error()
			}
			if rs.Stages[i].StartedAt != nil {
				rs.Stages[i].Duration = now.Sub(*rs.Stages[i].StartedAt).Round(time.Millisecond).String()
			}
			return
		}
	}
}

// StageCompleted returns true if the named stage has completed successfully.
func (rs *RunState) StageCompleted(name string) bool {
	for _, s := range rs.Stages {
		if s.Name == name {
			return s.Status == StatusCompleted
		}
	}
	return false
}

// AddWarning appends a warning message.
func (rs *RunState) AddWarning(msg string) {
	rs.Warnings = append(rs.Warnings, msg)
}

// AddError appends an error message.
func (rs *RunState) AddError(msg string) {
	rs.Errors = append(rs.Errors, msg)
}

// Finish marks the run as complete and records timing.
func (rs *RunState) Finish() {
	now := time.Now().UTC()
	rs.EndTime = &now
	rs.Duration = now.Sub(rs.StartTime).Round(time.Second).String()
	rs.Completed = true
}

// MarkInterrupted marks the run as interrupted.
func (rs *RunState) MarkInterrupted() {
	now := time.Now().UTC()
	rs.EndTime = &now
	rs.Duration = now.Sub(rs.StartTime).Round(time.Second).String()
	rs.Interrupted = true
	rs.Completed = false

	for i := range rs.Stages {
		if rs.Stages[i].Status == StatusRunning {
			rs.Stages[i].Status = StatusInterrupted
			rs.Stages[i].EndedAt = &now
		}
	}
}
