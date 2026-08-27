// Package reporting generates scan reports in text and JSON formats.
package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/pipeline"
	"github.com/frozeniceee/Reconpipeline/internal/version"
)

// Report holds all data for the final scan report.
type Report struct {
	Target    string               `json:"target"`
	Version   string               `json:"version"`
	Mode      string               `json:"mode"`
	StartTime time.Time            `json:"start_time"`
	EndTime   *time.Time           `json:"end_time,omitempty"`
	Duration  string               `json:"duration,omitempty"`
	Counters  pipeline.Counters    `json:"counters"`
	Warnings  []string             `json:"warnings,omitempty"`
	Errors    []string             `json:"errors,omitempty"`
	Stages    []pipeline.StageInfo `json:"stages"`
	Note      string               `json:"note"`
}

// Generate creates report.txt and report.json in targetDir from the run state.
func Generate(state *pipeline.RunState, targetDir string) error {
	r := &Report{
		Target:    state.NormalisedTarget,
		Version:   version.Version,
		Mode:      state.Mode,
		StartTime: state.StartTime,
		EndTime:   state.EndTime,
		Duration:  state.Duration,
		Counters:  state.Counters,
		Warnings:  state.Warnings,
		Errors:    state.Errors,
		Stages:    state.Stages,
		Note:      "Pattern matches indicate potential areas of interest, not confirmed vulnerabilities.",
	}

	if err := writeTXT(r, filepath.Join(targetDir, "report.txt")); err != nil {
		return fmt.Errorf("failed to write report.txt: %w", err)
	}
	if err := writeJSON(r, filepath.Join(targetDir, "report.json")); err != nil {
		return fmt.Errorf("failed to write report.json: %w", err)
	}
	return nil
}

func writeTXT(r *Report, path string) error {
	var sb strings.Builder

	sb.WriteString("Reconpipeline Report\n")
	sb.WriteString("====================\n\n")
	sb.WriteString(fmt.Sprintf("Target       : %s\n", r.Target))
	sb.WriteString(fmt.Sprintf("Version      : %s\n", r.Version))
	sb.WriteString(fmt.Sprintf("Mode         : %s\n", titleCase(r.Mode)))
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
	sb.WriteString("\n")

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
	// Insert commas.
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
