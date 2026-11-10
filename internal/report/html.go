package report

import (
	"context"
	"fmt"
	"html/template"
	"io"

	"github.com/khaleddevsec/Reconpipeline/models"
	"go.uber.org/zap"
)

// HTMLReporter implements Generator for HTML output.
type HTMLReporter struct {
	log *zap.Logger
}

// NewHTMLReporter constructs an HTMLReporter.
func NewHTMLReporter(log *zap.Logger) *HTMLReporter {
	return &HTMLReporter{log: log}
}

func (r *HTMLReporter) Format() models.ReportFormat { return models.ReportFormatHTML }

func (r *HTMLReporter) Generate(_ context.Context, rep *models.Report, w io.Writer) error {
	if rep == nil {
		return fmt.Errorf("report: nil report")
	}
	if err := htmlTmpl.Execute(w, rep); err != nil {
		return fmt.Errorf("report: render html: %w", err)
	}
	r.log.Info("HTML report written", zap.Int("results", len(rep.Results)))
	return nil
}

var htmlTmpl = template.Must(template.New("html").Funcs(template.FuncMap{
	"severityClass": func(s models.Severity) string {
		switch s {
		case models.SeverityCritical:
			return "critical"
		case models.SeverityHigh:
			return "high"
		case models.SeverityMedium:
			return "medium"
		case models.SeverityLow:
			return "low"
		default:
			return "info"
		}
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatLens — {{.Title}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}
h1{color:#58a6ff;margin-bottom:.5rem}
.meta{color:#8b949e;font-size:.85rem;margin-bottom:2rem}
.summary{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:2rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem}
.stat{text-align:center}.stat .value{font-size:2rem;font-weight:700;color:#58a6ff}.stat .label{color:#8b949e;font-size:.8rem}
.target{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
.target h2{color:#58a6ff;margin-bottom:.5rem;font-size:1rem}
.risk{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.8rem;font-weight:600;background:#21262d}
table{width:100%;border-collapse:collapse;margin-top:1rem}
th{background:#21262d;padding:.5rem;text-align:left;font-size:.8rem;color:#8b949e}
td{padding:.5rem;border-bottom:1px solid #21262d;font-size:.85rem;vertical-align:top}
.critical{color:#ff7b72}.high{color:#f0883e}.medium{color:#d29922}.low{color:#3fb950}.info{color:#8b949e}
a{color:#58a6ff}
</style>
</head>
<body>
<h1>🔍 ThreatLens Report</h1>
<p class="meta">{{.Title}} · Generated {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}} · v{{.Version}}</p>

<div class="summary">
  <div class="stat"><div class="value">{{.Summary.TotalTargets}}</div><div class="label">Targets</div></div>
  <div class="stat"><div class="value">{{.Summary.TotalFindings}}</div><div class="label">Findings</div></div>
  <div class="stat"><div class="value">{{printf "%.1f" .Summary.RiskScore}}</div><div class="label">Avg Risk Score</div></div>
</div>

{{range .Results}}
<div class="target">
  <h2><a href="{{.Target.URL}}" target="_blank">{{.Target.URL}}</a></h2>
  <span class="risk">Risk Score: {{printf "%.2f" .RiskScore}}/10</span>

  {{if .Fingerprints}}
  <p style="margin-top:.5rem;color:#8b949e;font-size:.8rem">
    Technologies: {{range .Fingerprints}}{{.Category}}/{{.Name}}{{if .Version}} {{.Version}}{{end}} &nbsp;{{end}}
  </p>
  {{end}}

  {{if .Findings}}
  <table>
    <tr><th>Severity</th><th>ID</th><th>Title</th><th>Remediation</th></tr>
    {{range .Findings}}
    <tr>
      <td class="{{severityClass .Severity}}">{{.Severity}}</td>
      <td>{{.ID}}</td>
      <td>{{.Title}}</td>
      <td>{{.Remediation}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <p style="color:#3fb950;margin-top:.5rem">✓ No findings</p>
  {{end}}
</div>
{{end}}
<footer style="margin-top:3rem;text-align:center;color:#8b949e;font-size:.8rem">
  Made with ❤️ by <a href="https://github.com/khaleddevsec/Reconpipeline" target="_blank">KhaledDevSec</a>
</footer>
</body>
</html>`))
