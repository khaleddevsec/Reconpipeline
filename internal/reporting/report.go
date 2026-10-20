// Package reporting generates scan reports in text, JSON, and HTML formats.
package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/comparison"
	"github.com/khaleddevsec/Reconpipeline/internal/pipeline"
	"github.com/khaleddevsec/Reconpipeline/internal/version"
)

// Report holds all data for the final scan report.
type Report struct {
	ScanID      string               `json:"scan_id"`
	Target      string               `json:"target"`
	Version     string               `json:"version"`
	Mode        string               `json:"mode"`
	StartTime   time.Time            `json:"start_time"`
	EndTime     *time.Time           `json:"end_time,omitempty"`
	Duration    string               `json:"duration,omitempty"`
	StateStatus string               `json:"status,omitempty"`
	Counters    pipeline.Counters    `json:"counters"`
	Comparison  *comparison.Result   `json:"comparison,omitempty"`
	Warnings    []string             `json:"warnings,omitempty"`
	Errors      []string             `json:"errors,omitempty"`
	Stages      []pipeline.StageInfo `json:"stages"`
	Note        string               `json:"note"`
}

// Generate creates report.txt, report.json, and report.html in targetDir from the run state and comparison.
func Generate(state *pipeline.RunState, targetDir string, comp *comparison.Result) error {
	status := "completed"
	if state.Interrupted {
		status = "interrupted"
	} else if !state.Completed {
		status = "partial"
	}
	for _, s := range state.Stages {
		if s.Status == pipeline.StatusFailed {
			status = "failed"
			break
		}
	}

	r := &Report{
		ScanID:      state.ScanID,
		Target:      state.NormalisedTarget,
		Version:     version.Version,
		Mode:        state.Mode,
		StartTime:   state.StartTime,
		EndTime:     state.EndTime,
		Duration:    state.Duration,
		StateStatus: status,
		Counters:    state.Counters,
		Comparison:  comp,
		Warnings:    state.Warnings,
		Errors:      state.Errors,
		Stages:      state.Stages,
		Note:        "Pattern matches indicate potential areas of interest, not confirmed vulnerabilities.",
	}

	if err := writeTXT(r, filepath.Join(targetDir, "report.txt"), comp); err != nil {
		return fmt.Errorf("failed to write report.txt: %w", err)
	}
	if err := writeJSON(r, filepath.Join(targetDir, "report.json")); err != nil {
		return fmt.Errorf("failed to write report.json: %w", err)
	}

	htmlContent := GenerateHTML(r, comp)
	if err := os.WriteFile(filepath.Join(targetDir, "report.html"), []byte(htmlContent), 0640); err != nil {
		return fmt.Errorf("failed to write report.html: %w", err)
	}

	return nil
}

func writeTXT(r *Report, path string, comp *comparison.Result) error {
	var sb strings.Builder

	sb.WriteString("Reconpipeline Report\n")
	sb.WriteString("====================\n\n")
	sb.WriteString(fmt.Sprintf("Target       : %s\n", r.Target))
	sb.WriteString(fmt.Sprintf("Scan ID      : %s\n", r.ScanID))
	sb.WriteString(fmt.Sprintf("Version      : %s\n", r.Version))
	sb.WriteString(fmt.Sprintf("Mode         : %s\n", titleCase(r.Mode)))
	sb.WriteString(fmt.Sprintf("Status       : %s\n", titleCase(r.StateStatus)))
	if r.EndTime != nil {
		sb.WriteString(fmt.Sprintf("Completed    : %s\n", r.EndTime.Format(time.RFC3339)))
	}
	if r.Duration != "" {
		sb.WriteString(fmt.Sprintf("Duration     : %s\n", r.Duration))
	}
	sb.WriteString("\n")

	sb.WriteString("Discovery & Intelligence\n")
	sb.WriteString("------------------------\n")
	sb.WriteString(fmt.Sprintf("Subdomains   : %s\n", formatCount(r.Counters.Subdomains)))
	sb.WriteString(fmt.Sprintf("Assets Class : %s\n", formatCount(r.Counters.AssetsClassified)))
	sb.WriteString(fmt.Sprintf("DNS Resolved : %s\n", formatCount(r.Counters.DNSResolved)))
	sb.WriteString(fmt.Sprintf("Live Hosts   : %s\n", formatCount(r.Counters.LiveHosts)))
	sb.WriteString(fmt.Sprintf("Technologies : %s\n", formatCount(r.Counters.TechnologiesDetected)))
	sb.WriteString(fmt.Sprintf("Unique URLs  : %s\n", formatCount(r.Counters.UniqueURLs)))
	sb.WriteString(fmt.Sprintf("Selected URLs: %s\n", formatCount(r.Counters.SelectedURLs)))
	sb.WriteString(fmt.Sprintf("Verified URLs: %s\n", formatCount(r.Counters.VerifiedURLs)))
	sb.WriteString("\n")

	sb.WriteString("URL Intelligence & Clustering\n")
	sb.WriteString("-----------------------------\n")
	sb.WriteString(fmt.Sprintf("API URLs     : %s\n", formatCount(r.Counters.APIURLs)))
	sb.WriteString(fmt.Sprintf("JavaScript   : %s\n", formatCount(r.Counters.JavaScriptURLs)))
	sb.WriteString(fmt.Sprintf("Parameterised: %s\n", formatCount(r.Counters.ParamURLs)))
	sb.WriteString(fmt.Sprintf("URL Clusters : %s\n", formatCount(r.Counters.URLClusters)))
	sb.WriteString(fmt.Sprintf("High Priority: %s\n", formatCount(r.Counters.HighPriorityURLs)))
	sb.WriteString(fmt.Sprintf("Med Priority : %s\n", formatCount(r.Counters.MediumPriorityURLs)))
	sb.WriteString(fmt.Sprintf("Low Priority : %s\n", formatCount(r.Counters.LowPriorityURLs)))
	sb.WriteString("\n")

	sb.WriteString("Potential Pattern Matches\n")
	sb.WriteString("-------------------------\n")
	sb.WriteString(fmt.Sprintf("XSS          : %s\n", formatCount(r.Counters.XSSMatches)))
	sb.WriteString(fmt.Sprintf("SQLi         : %s\n", formatCount(r.Counters.SQLiMatches)))
	sb.WriteString(fmt.Sprintf("LFI          : %s\n", formatCount(r.Counters.LFIMatches)))
	sb.WriteString(fmt.Sprintf("SSRF         : %s\n", formatCount(r.Counters.SSRFMatches)))
	sb.WriteString(fmt.Sprintf("Open Redirect: %s\n", formatCount(r.Counters.RedirectMatches)))
	if r.Counters.TotalCandidates > 0 {
		sb.WriteString(fmt.Sprintf("Total Cand   : %s\n", formatCount(r.Counters.TotalCandidates)))
		sb.WriteString(fmt.Sprintf("High Conf    : %s\n", formatCount(r.Counters.HighConfidenceCandidates)))
		sb.WriteString(fmt.Sprintf("Takeovers    : %s\n", formatCount(r.Counters.TakeoverCandidates)))
		sb.WriteString(fmt.Sprintf("APIs         : %s\n", formatCount(r.Counters.APICandidates)))
		sb.WriteString(fmt.Sprintf("Auth Flows   : %s\n", formatCount(r.Counters.AuthCandidates)))
		sb.WriteString(fmt.Sprintf("Admin Panels : %s\n", formatCount(r.Counters.AdminCandidates)))
		sb.WriteString(fmt.Sprintf("Sensitive Fls: %s\n", formatCount(r.Counters.SensitiveFileCandidates)))
	}
	sb.WriteString("\n")

	if comp != nil && comp.HasPrevious {
		sb.WriteString("Changes Since Previous Scan\n")
		sb.WriteString("---------------------------\n")
		sb.WriteString(fmt.Sprintf("Previous Scan : %s (%s)\n", comp.PreviousScanID, comp.PreviousTime))
		sb.WriteString(fmt.Sprintf("New Subdomains: %d\n", len(comp.NewSubdomains)))
		sb.WriteString(fmt.Sprintf("New Live Hosts: %d\n", len(comp.NewHosts)))
		sb.WriteString(fmt.Sprintf("New URLs      : %d\n", len(comp.NewURLs)))
		sb.WriteString(fmt.Sprintf("New APIs      : %d\n", len(comp.NewAPIs)))
		sb.WriteString(fmt.Sprintf("Asset Changes : %d\n", len(comp.ChangedAssets)))
		sb.WriteString("\n")
	}

	sb.WriteString("Note: Pattern matches indicate potential areas of interest,\n")
	sb.WriteString("not confirmed vulnerabilities.\n")
	sb.WriteString("\n")

	if len(r.Warnings) > 0 {
		sb.WriteString("Warnings\n")
		sb.WriteString("--------\n")
		for _, w := range r.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Stages\n")
	sb.WriteString("------\n")
	for i, s := range r.Stages {
		sb.WriteString(fmt.Sprintf("  [%02d] %-35s %s\n", i+1, s.Name, strings.ToUpper(string(s.Status))))
	}

	return os.WriteFile(path, []byte(sb.String()), 0640)
}

func writeJSON(r *Report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

// formatCount formats an integer with thousands separators.
func formatCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	out := ""
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(ch)
	}
	return out
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
