// Package reporting provides text, JSON, and standalone HTML dashboard generation.
package reporting

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/comparison"
	"github.com/khaleddevsec/Reconpipeline/internal/version"
)

// GenerateHTML renders a self-contained, responsive HTML reconnaissance dashboard.
func GenerateHTML(r *Report, comp *comparison.Result) string {
	var sb strings.Builder

	statusClass := "status-completed"
	statusText := "Completed"
	if r.StateStatus != "" {
		statusText = strings.ToUpper(r.StateStatus[:1]) + r.StateStatus[1:]
		if r.StateStatus == "failed" || r.StateStatus == "interrupted" {
			statusClass = "status-failed"
		} else if r.StateStatus == "partial" {
			statusClass = "status-partial"
		}
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reconpipeline Dashboard - ` + html.EscapeString(r.Target) + `</title>
<style>
:root {
  --bg-primary: #0b0f19;
  --bg-secondary: #111827;
  --bg-card: #1f2937;
  --bg-card-hover: #283548;
  --border: #374151;
  --text-primary: #f9fafb;
  --text-secondary: #9ca3af;
  --text-muted: #6b7280;
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --accent-green: #10b981;
  --accent-amber: #f59e0b;
  --accent-rose: #f43f5e;
  --accent-purple: #8b5cf6;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.5;
  padding: 24px;
}
.container { max-width: 1200px; margin: 0 auto; }
.header {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
}
.header-title h1 { font-size: 24px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.5px; }
.header-title p { font-size: 14px; color: var(--text-secondary); margin-top: 4px; }
.badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 9999px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.status-completed { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #059669; }
.status-partial { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid #d97706; }
.status-failed { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid #e11d48; }

.grid-kpi {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.kpi-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  transition: transform 0.15s ease, background 0.15s ease;
}
.kpi-card:hover { transform: translateY(-2px); background: var(--bg-card); }
.kpi-label { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; }
.kpi-value { font-size: 28px; font-weight: 700; margin-top: 8px; color: var(--text-primary); }
.kpi-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

.section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 24px;
}
.section-header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 12px;
  margin-bottom: 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.section-header h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); }

table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
th { padding: 10px 12px; background: var(--bg-card); color: var(--text-secondary); font-weight: 600; border-bottom: 1px solid var(--border); }
td { padding: 10px 12px; border-bottom: 1px solid var(--border); color: var(--text-primary); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255, 255, 255, 0.02); }

.pill {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  margin-right: 4px;
}
.pill-cyan { background: rgba(6, 182, 212, 0.15); color: #22d3ee; }
.pill-blue { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
.pill-green { background: rgba(16, 185, 129, 0.15); color: #34d399; }
.pill-amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
.pill-rose { background: rgba(244, 63, 94, 0.15); color: #fb7185; }

.diff-box {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 16px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  line-height: 1.6;
}
.diff-added { color: #34d399; }
.diff-removed { color: #fb7185; }
.diff-changed { color: #fbbf24; }
.footer {
  text-align: center;
  font-size: 13px;
  color: var(--text-muted);
  margin-top: 32px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-title">
      <h1>Reconpipeline Intelligence Dashboard</h1>
      <p>Target: <strong>` + html.EscapeString(r.Target) + `</strong> &bull; Scan ID: <code>` + html.EscapeString(r.ScanID) + `</code></p>
    </div>
    <div>
      <span class="badge ` + statusClass + `">` + statusText + `</span>
    </div>
  </div>

  <!-- KPI Grid -->
  <div class="grid-kpi">
    <div class="kpi-card">
      <div class="kpi-label">Subdomains</div>
      <div class="kpi-value">` + formatCount(r.Counters.Subdomains) + `</div>
      <div class="kpi-sub">Assets: ` + formatCount(r.Counters.AssetsClassified) + ` | DNS: ` + formatCount(r.Counters.DNSResolved) + `</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Live Hosts</div>
      <div class="kpi-value">` + formatCount(r.Counters.LiveHosts) + `</div>
      <div class="kpi-sub">Tech Groups: ` + formatCount(r.Counters.TechnologiesDetected) + `</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Verified URLs</div>
      <div class="kpi-value">` + formatCount(r.Counters.VerifiedURLs) + `</div>
      <div class="kpi-sub">Unique: ` + formatCount(r.Counters.UniqueURLs) + ` | Selected: ` + formatCount(r.Counters.SelectedURLs) + `</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">API Endpoints</div>
      <div class="kpi-value">` + formatCount(r.Counters.APIURLs) + `</div>
      <div class="kpi-sub">JavaScript URLs: ` + formatCount(r.Counters.JavaScriptURLs) + `</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Parameters</div>
      <div class="kpi-value">` + formatCount(r.Counters.ParamURLs) + `</div>
      <div class="kpi-sub">URL Clusters: ` + formatCount(r.Counters.URLClusters) + `</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">High Priority</div>
      <div class="kpi-value">` + formatCount(r.Counters.HighPriorityURLs) + `</div>
      <div class="kpi-sub">Med: ` + formatCount(r.Counters.MediumPriorityURLs) + ` | Low: ` + formatCount(r.Counters.LowPriorityURLs) + `</div>
    </div>
  </div>

  <!-- Scan Information Section -->
  <div class="section">
    <div class="section-header">
      <h2>Scan Information</h2>
    </div>
    <table>
      <tr><th>Property</th><th>Value</th></tr>
      <tr><td>Target Domain</td><td><code>` + html.EscapeString(r.Target) + `</code></td></tr>
      <tr><td>Scan Identifier</td><td><code>` + html.EscapeString(r.ScanID) + `</code></td></tr>
      <tr><td>Reconpipeline Version</td><td>` + html.EscapeString(r.Version) + `</td></tr>
      <tr><td>Scan Mode</td><td>` + html.EscapeString(titleCase(r.Mode)) + `</td></tr>
      <tr><td>Started At</td><td>` + html.EscapeString(r.StartTime.Format(time.RFC3339)) + `</td></tr>`)

	if r.EndTime != nil {
		sb.WriteString(`<tr><td>Completed At</td><td>` + html.EscapeString(r.EndTime.Format(time.RFC3339)) + `</td></tr>`)
	}
	if r.Duration != "" {
		sb.WriteString(`<tr><td>Duration</td><td>` + html.EscapeString(r.Duration) + `</td></tr>`)
	}

	sb.WriteString(`</table>
  </div>

  <!-- Changes Since Previous Scan Section -->
  <div class="section">
    <div class="section-header">
      <h2>Changes Since Previous Scan</h2>
    </div>`)

	if comp == nil || !comp.HasPrevious {
		sb.WriteString(`<p style="color: var(--text-secondary); font-size: 14px;">No previous scan available for comparison. This scan establishes the baseline.</p>`)
	} else {
		sb.WriteString(`<div class="diff-box">
      <p style="margin-bottom: 12px; color: var(--text-secondary);">Comparing with previous scan: <strong>` + html.EscapeString(comp.PreviousScanID) + `</strong> (` + html.EscapeString(comp.PreviousTime) + `)</p>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; margin-bottom: 12px;">
        <div class="diff-added">+ ` + fmt.Sprintf("%d", len(comp.NewSubdomains)) + ` New Subdomains</div>
        <div class="diff-removed">- ` + fmt.Sprintf("%d", len(comp.RemovedSubdomains)) + ` Removed Subdomains</div>
        <div class="diff-added">+ ` + fmt.Sprintf("%d", len(comp.NewHosts)) + ` New Live Hosts</div>
        <div class="diff-removed">- ` + fmt.Sprintf("%d", len(comp.RemovedHosts)) + ` Removed Live Hosts</div>
        <div class="diff-added">+ ` + fmt.Sprintf("%d", len(comp.NewURLs)) + ` New Unique URLs</div>
        <div class="diff-removed">- ` + fmt.Sprintf("%d", len(comp.RemovedURLs)) + ` Removed URLs</div>
        <div class="diff-added">+ ` + fmt.Sprintf("%d", len(comp.NewAPIs)) + ` New API Endpoints</div>
        <div class="diff-changed">~ ` + fmt.Sprintf("%d", len(comp.ChangedAssets)) + ` Asset Changes</div>
      </div>`)

		if len(comp.ChangedAssets) > 0 {
			sb.WriteString(`<div style="margin-top: 12px; border-top: 1px solid var(--border); padding-top: 8px;"><strong>Observed Asset Modifications:</strong><ul style="margin-left: 20px; margin-top: 4px;">`)
			for _, ca := range comp.ChangedAssets {
				sb.WriteString(`<li class="diff-changed">` + html.EscapeString(ca.URL))
				var details []string
				if ca.OldStatus != ca.NewStatus && ca.OldStatus != 0 && ca.NewStatus != 0 {
					details = append(details, fmt.Sprintf("status: %d &rarr; %d", ca.OldStatus, ca.NewStatus))
				}
				if ca.OldTitle != ca.NewTitle && ca.OldTitle != "" && ca.NewTitle != "" {
					details = append(details, fmt.Sprintf("title: %q &rarr; %q", ca.OldTitle, ca.NewTitle))
				}
				if len(details) > 0 {
					sb.WriteString(` (` + strings.Join(details, ", ") + `)`)
				}
				sb.WriteString(`</li>`)
			}
			sb.WriteString(`</ul></div>`)
		}
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</div>

  <!-- Potential Pattern Matches Section -->
  <div class="section">
    <div class="section-header">
      <h2>Potential Pattern Matches (GF)</h2>
    </div>
    <table>
      <tr><th>Pattern Category</th><th>Matches</th><th>Security Focus</th></tr>
      <tr><td>Cross-Site Scripting (XSS)</td><td><span class="pill pill-amber">` + formatCount(r.Counters.XSSMatches) + `</span></td><td>Context reflection, parameter injection</td></tr>
      <tr><td>SQL Injection (SQLi)</td><td><span class="pill pill-rose">` + formatCount(r.Counters.SQLiMatches) + `</span></td><td>Database parameter manipulation</td></tr>
      <tr><td>Local File Inclusion (LFI)</td><td><span class="pill pill-rose">` + formatCount(r.Counters.LFIMatches) + `</span></td><td>File path traversal parameters</td></tr>
      <tr><td>Server-Side Request Forgery (SSRF)</td><td><span class="pill pill-purple">` + formatCount(r.Counters.SSRFMatches) + `</span></td><td>Outbound URL and host parameters</td></tr>
      <tr><td>Open Redirect</td><td><span class="pill pill-blue">` + formatCount(r.Counters.RedirectMatches) + `</span></td><td>Redirect and forward parameters</td></tr>`)
	if r.Counters.TotalCandidates > 0 {
		sb.WriteString(`
      <tr><td>Subdomain Takeovers</td><td><span class="pill pill-rose">` + formatCount(r.Counters.TakeoverCandidates) + `</span></td><td>Dangling DNS CNAME / unclaimed third-party services</td></tr>
      <tr><td>API Intelligence</td><td><span class="pill pill-blue">` + formatCount(r.Counters.APICandidates) + `</span></td><td>REST, GraphQL, Swagger / OpenAPI endpoints</td></tr>
      <tr><td>Authentication Portals</td><td><span class="pill pill-purple">` + formatCount(r.Counters.AuthCandidates) + `</span></td><td>Login, MFA, OAuth, SSO, password reset workflows</td></tr>
      <tr><td>Administrative Consoles</td><td><span class="pill pill-amber">` + formatCount(r.Counters.AdminCandidates) + `</span></td><td>Admin, dashboard, internal control interfaces</td></tr>
      <tr><td>Sensitive File Exposure</td><td><span class="pill pill-rose">` + formatCount(r.Counters.SensitiveFileCandidates) + `</span></td><td>.env, .git, database dumps, server configuration</td></tr>`)
	}
	sb.WriteString(`
    </table>
    <p style="font-size: 12px; color: var(--text-muted); margin-top: 12px;">Note: Pattern matches indicate potential areas of interest, not confirmed vulnerabilities.</p>
  </div>

  <!-- Pipeline Stages Section -->
  <div class="section">
    <div class="section-header">
      <h2>Pipeline Stages</h2>
    </div>
    <table>
      <tr><th>#</th><th>Stage</th><th>Status</th></tr>`)

	for i, s := range r.Stages {
		pClass := "pill-green"
		if s.Status == "failed" || s.Status == "interrupted" {
			pClass = "pill-rose"
		} else if s.Status == "skipped" {
			pClass = "pill-amber"
		}
		sb.WriteString(fmt.Sprintf(`<tr><td>%02d</td><td>%s</td><td><span class="pill %s">%s</span></td></tr>`,
			i+1, html.EscapeString(s.Name), pClass, strings.ToUpper(string(s.Status))))
	}

	sb.WriteString(`</table>
  </div>

  <!-- Footer -->
  <div class="footer">
    Reconpipeline ` + version.Version + ` &bull; Made by khaleddevsec &bull; Generated on ` + time.Now().Format("2006-01-02 15:04:05") + `
  </div>

</div>
</body>
</html>`)

	return sb.String()
}
