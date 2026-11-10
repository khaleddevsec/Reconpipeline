package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"go.uber.org/zap"
)

// JSONReporter implements Generator for JSON output.
type JSONReporter struct {
	log *zap.Logger
}

// NewJSONReporter constructs a JSONReporter.
func NewJSONReporter(log *zap.Logger) *JSONReporter {
	return &JSONReporter{log: log}
}

func (r *JSONReporter) Format() models.ReportFormat { return models.ReportFormatJSON }

// Generate marshals the report to JSON and writes it to w.
func (r *JSONReporter) Generate(_ context.Context, rep *models.Report, w io.Writer) error {
	if rep == nil {
		return fmt.Errorf("report: nil report")
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("report: marshal: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("report: write: %w", err)
	}
	r.log.Info("JSON report written",
		zap.Int("results", len(rep.Results)),
		zap.Time("generated_at", rep.GeneratedAt))
	return nil
}

// MarkdownReporter implements Generator for Markdown output.
type MarkdownReporter struct {
	log *zap.Logger
}

// NewMarkdownReporter constructs a MarkdownReporter.
func NewMarkdownReporter(log *zap.Logger) *MarkdownReporter {
	return &MarkdownReporter{log: log}
}

func (r *MarkdownReporter) Format() models.ReportFormat { return models.ReportFormatMarkdown }

var mdTmpl = template.Must(template.New("md").Funcs(template.FuncMap{
	"now": time.Now,
}).Parse(`# ThreatLens Report

**Generated:** {{ .GeneratedAt.Format "2006-01-02 15:04:05 UTC" }}
**Version:** {{ .Version }}

## Summary

| Metric | Value |
|--------|-------|
| Total Targets | {{ .Summary.TotalTargets }} |
| Total Findings | {{ .Summary.TotalFindings }} |
| Overall Risk Score | {{ printf "%.2f" .Summary.RiskScore }} |

{{ range .Results }}
---
## Target: {{ .Target.URL }}

**Risk Score:** {{ printf "%.2f" .RiskScore }}

### Findings ({{ len .Findings }})

{{ range .Findings }}
#### [{{ .Severity }}] {{ .Title }}

{{ .Description }}

**Remediation:** {{ .Remediation }}

{{ end }}
{{ end }}
`))

// Generate writes the report as Markdown to w.
func (r *MarkdownReporter) Generate(_ context.Context, rep *models.Report, w io.Writer) error {
	if rep == nil {
		return fmt.Errorf("report: nil report")
	}
	if err := mdTmpl.Execute(w, rep); err != nil {
		return fmt.Errorf("report: render markdown: %w", err)
	}
	r.log.Info("Markdown report written", zap.Int("results", len(rep.Results)))
	return nil
}
