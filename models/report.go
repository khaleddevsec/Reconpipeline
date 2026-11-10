package models

import "time"

// ReportFormat represents a supported output format.
type ReportFormat string

const (
	ReportFormatHTML     ReportFormat = "html"
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatMarkdown ReportFormat = "markdown"
	ReportFormatCSV      ReportFormat = "csv"
	ReportFormatSARIF    ReportFormat = "sarif"
)

// IsValidFormat returns true when f is one of the supported report formats.
func IsValidFormat(f ReportFormat) bool {
	switch f {
	case ReportFormatHTML, ReportFormatJSON, ReportFormatMarkdown, ReportFormatCSV, ReportFormatSARIF:
		return true
	default:
		return false
	}
}

// Report represents a complete analysis report over one or more targets.
type Report struct {
	Title       string
	Version     string
	GeneratedAt time.Time
	Results     []ScanResult
	Summary     ReportSummary
}

// ReportSummary holds aggregate statistics across all results.
type ReportSummary struct {
	TotalTargets  int
	FailedTargets int
	TotalFindings int
	BySeverity    map[Severity]int
	RiskScore     float64
}
