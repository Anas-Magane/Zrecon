package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type templateData struct {
	Meta        metaInfo
	Target      models.Target
	Result      *models.ScanResult
	Summary     summaryInfo
	GeneratedAt string
}

type metaInfo struct {
	ToolName    string
	Version     string
	Author      string
	GitHubURL   string
	LinkedInURL string
}

type summaryInfo struct {
	Duration           string
	DNSRecords         int
	Subdomains         int
	ResolvedSubdomains int
	UniqueIPs          int
	OpenPorts          int
	Services           int
	LiveWebServices    int
	Technologies       int
	TLSCertificates    int
}

// WriteHTML generates a standalone HTML report.
func WriteHTML(dir string, result *models.ScanResult) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"join":    strings.Join,
		"fmtTime": func(t time.Time) string { return t.Format("2006-01-02") },
		"fmtFull": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"statusClass": func(code int) string {
			switch {
			case code >= 200 && code < 300:
				return "badge-success"
			case code >= 300 && code < 400:
				return "badge-warning"
			case code >= 400:
				return "badge-danger"
			default:
				return "badge-secondary"
			}
		},
		"headerClass": func(status string) string {
			switch status {
			case "present":
				return "badge-success"
			case "missing":
				return "badge-danger"
			default:
				return "badge-warning"
			}
		},
		"confidenceClass": func(c string) string {
			switch c {
			case "high":
				return "badge-success"
			case "medium":
				return "badge-warning"
			default:
				return "badge-secondary"
			}
		},
		"safeHTML": func(s string) template.HTML { return template.HTML(template.HTMLEscapeString(s)) },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	resolved := 0
	for _, s := range result.Subdomains {
		if s.Resolved {
			resolved++
		}
	}

	data := templateData{
		Meta: metaInfo{
			ToolName:    metadata.ToolName,
			Version:     metadata.Version,
			Author:      metadata.Author,
			GitHubURL:   metadata.GitHubURL,
			LinkedInURL: metadata.LinkedInURL,
		},
		Target: result.Target,
		Result: result,
		Summary: summaryInfo{
			Duration:           formatDur(result.CompletedAt.Sub(result.StartedAt)),
			DNSRecords:         len(result.DNSRecords),
			Subdomains:         len(result.Subdomains),
			ResolvedSubdomains: resolved,
			UniqueIPs:          len(result.IPAddresses),
			OpenPorts:          len(result.Ports),
			Services:           len(result.Services),
			LiveWebServices:    len(result.HTTPServices),
			Technologies:       len(result.Technologies),
			TLSCertificates:    len(result.Certificates),
		},
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	f, err := os.Create(filepath.Join(dir, "report.html"))
	if err != nil {
		return fmt.Errorf("create HTML file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func formatDur(d time.Duration) string {
	d = d.Round(time.Second)
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02dm %02ds", m, s)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Meta.ToolName}} Report - {{.Target.Raw}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:20px}
header{background:linear-gradient(135deg,#161b22,#0d1117);border-bottom:1px solid #30363d;padding:30px 0;margin-bottom:30px}
.header-inner{max-width:1200px;margin:0 auto;padding:0 20px}
.logo{font-family:monospace;color:#58a6ff;font-size:1.4em;font-weight:bold;letter-spacing:2px}
.subtitle{color:#8b949e;margin-top:5px}
.meta-row{display:flex;gap:20px;margin-top:15px;flex-wrap:wrap}
.meta-item{color:#8b949e;font-size:.9em}
.meta-item span{color:#c9d1d9}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px}
.card-title{color:#58a6ff;font-size:1.1em;font-weight:600;margin-bottom:15px;padding-bottom:8px;border-bottom:1px solid #21262d}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px}
.summary-item{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:15px;text-align:center}
.summary-num{font-size:2em;font-weight:bold;color:#58a6ff}
.summary-label{font-size:.8em;color:#8b949e;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:.9em}
th{background:#21262d;color:#8b949e;font-weight:600;text-align:left;padding:10px 12px;border-bottom:1px solid #30363d}
td{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-word}
tr:hover td{background:#1c2129}
.search-box{width:100%;padding:8px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;margin-bottom:12px;font-size:.9em}
.search-box:focus{outline:none;border-color:#58a6ff}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.78em;font-weight:600}
.badge-success{background:#1a3a1a;color:#3fb950}
.badge-danger{background:#3a1a1a;color:#f85149}
.badge-warning{background:#3a2f1a;color:#d29922}
.badge-secondary{background:#21262d;color:#8b949e}
.section-title{color:#58a6ff;font-size:1.3em;font-weight:700;margin:30px 0 15px;padding-bottom:8px;border-bottom:2px solid #21262d}
.warn-box{background:#2d2208;border:1px solid #d29922;border-radius:6px;padding:15px;margin-bottom:20px;color:#d29922}
.warn-box strong{display:block;margin-bottom:5px}
code{background:#21262d;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.85em}
footer{text-align:center;padding:30px 0;color:#8b949e;font-size:.85em;border-top:1px solid #21262d;margin-top:40px}
</style>
</head>
<body>
<header>
<div class="header-inner">
  <div class="logo">▶ {{.Meta.ToolName}} — Reconnaissance Report</div>
  <div class="subtitle">{{.Meta.ToolName}} v{{.Meta.Version}} · {{.Meta.Author}} · Generated {{.GeneratedAt}}</div>
  <div class="meta-row">
    <div class="meta-item">Target: <span>{{.Target.Raw}}</span></div>
    <div class="meta-item">Type: <span>{{.Target.Type}}</span></div>
    <div class="meta-item">Started: <span>{{fmtFull .Result.StartedAt}}</span></div>
    <div class="meta-item">Duration: <span>{{.Summary.Duration}}</span></div>
  </div>
</div>
</header>

<div class="container">

<div class="warn-box">
  <strong>⚠ Authorization Notice</strong>
  This report was generated by an automated reconnaissance tool. Use only on systems you own or have explicit written permission to test. Unauthorized scanning may violate laws and regulations.
</div>

<div class="section-title">Executive Summary</div>
<div class="summary-grid">
  <div class="summary-item"><div class="summary-num">{{.Summary.DNSRecords}}</div><div class="summary-label">DNS Records</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.Subdomains}}</div><div class="summary-label">Subdomains</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.ResolvedSubdomains}}</div><div class="summary-label">Resolved</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.UniqueIPs}}</div><div class="summary-label">IP Addresses</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.OpenPorts}}</div><div class="summary-label">Open Ports</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.Services}}</div><div class="summary-label">Services</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.LiveWebServices}}</div><div class="summary-label">Web Services</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.Technologies}}</div><div class="summary-label">Technologies</div></div>
  <div class="summary-item"><div class="summary-num">{{.Summary.TLSCertificates}}</div><div class="summary-label">Certificates</div></div>
</div>

{{if .Result.DNSRecords}}
<div class="section-title">DNS Records</div>
<div class="card">
  <input type="text" class="search-box" placeholder="Search DNS records..." onkeyup="filterTable(this,'dns-table')">
  <table id="dns-table">
    <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr></thead>
    <tbody>
    {{range .Result.DNSRecords}}
    <tr><td><code>{{.Type}}</code></td><td>{{.Name}}</td><td>{{.Value}}</td><td>{{.TTL}}</td></tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.Subdomains}}
<div class="section-title">Subdomains ({{len .Result.Subdomains}})</div>
<div class="card">
  <input type="text" class="search-box" placeholder="Search subdomains..." onkeyup="filterTable(this,'sub-table')">
  <table id="sub-table">
    <thead><tr><th>Subdomain</th><th>IPs</th><th>CNAME</th><th>Sources</th><th>Resolved</th></tr></thead>
    <tbody>
    {{range .Result.Subdomains}}
    <tr>
      <td>{{.Name}}</td>
      <td>{{join .IPs ", "}}</td>
      <td>{{.CNAME}}</td>
      <td>{{join .Sources ", "}}</td>
      <td>{{if .Resolved}}<span class="badge badge-success">yes</span>{{else}}<span class="badge badge-secondary">no</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.IPAddresses}}
<div class="section-title">IP Addresses ({{len .Result.IPAddresses}})</div>
<div class="card">
  <table>
    <thead><tr><th>Address</th><th>Hostnames</th><th>PTR</th></tr></thead>
    <tbody>
    {{range .Result.IPAddresses}}
    <tr><td>{{.Address}}</td><td>{{join .Hostnames ", "}}</td><td>{{.PTR}}</td></tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.Ports}}
<div class="section-title">Open Ports ({{len .Result.Ports}})</div>
<div class="card">
  <input type="text" class="search-box" placeholder="Search ports..." onkeyup="filterTable(this,'port-table')">
  <table id="port-table">
    <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>State</th><th>Response Time</th></tr></thead>
    <tbody>
    {{range .Result.Ports}}
    <tr>
      <td>{{.Host}}</td>
      <td>{{.Number}}</td>
      <td>{{.Protocol}}</td>
      <td><span class="badge badge-success">{{.State}}</span></td>
      <td>{{.ResponseTime}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.Services}}
<div class="section-title">Services ({{len .Result.Services}})</div>
<div class="card">
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Banner</th></tr></thead>
    <tbody>
    {{range .Result.Services}}
    <tr>
      <td>{{.Host}}</td>
      <td>{{.Port}}</td>
      <td><code>{{.Name}}</code></td>
      <td>{{.Product}} {{.Version}}</td>
      <td><code>{{.Banner}}</code></td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.HTTPServices}}
<div class="section-title">Web Services ({{len .Result.HTTPServices}})</div>
<div class="card">
  <input type="text" class="search-box" placeholder="Search web services..." onkeyup="filterTable(this,'web-table')">
  <table id="web-table">
    <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Content-Type</th></tr></thead>
    <tbody>
    {{range .Result.HTTPServices}}
    <tr>
      <td><a href="{{.FinalURL}}" target="_blank">{{.FinalURL}}</a></td>
      <td><span class="badge {{statusClass .StatusCode}}">{{.StatusCode}}</span></td>
      <td>{{.Title}}</td>
      <td><code>{{.Server}}</code></td>
      <td>{{.ContentType}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.Technologies}}
<div class="section-title">Technologies ({{len .Result.Technologies}})</div>
<div class="card">
  <table>
    <thead><tr><th>Technology</th><th>Category</th><th>URL</th><th>Evidence</th><th>Confidence</th></tr></thead>
    <tbody>
    {{range .Result.Technologies}}
    <tr>
      <td><strong>{{.Name}}</strong></td>
      <td>{{.Category}}</td>
      <td>{{.URL}}</td>
      <td>{{.Evidence}}</td>
      <td><span class="badge {{confidenceClass .Confidence}}">{{.Confidence}}</span></td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.SecurityHeaders}}
<div class="section-title">Security Headers</div>
<div class="card">
  <table>
    <thead><tr><th>URL</th><th>Header</th><th>Status</th><th>Value</th><th>Note</th></tr></thead>
    <tbody>
    {{range .Result.SecurityHeaders}}
    <tr>
      <td>{{.URL}}</td>
      <td><code>{{.Name}}</code></td>
      <td><span class="badge {{headerClass .Status}}">{{.Status}}</span></td>
      <td><code>{{.Value}}</code></td>
      <td>{{.Note}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Result.Certificates}}
<div class="section-title">TLS Certificates ({{len .Result.Certificates}})</div>
<div class="card">
  <table>
    <thead><tr><th>Host</th><th>Subject</th><th>Issuer</th><th>Valid Until</th><th>TLS</th><th>Status</th></tr></thead>
    <tbody>
    {{range .Result.Certificates}}
    <tr>
      <td>{{.Host}}</td>
      <td>{{.Subject}}</td>
      <td>{{.Issuer}}</td>
      <td>{{fmtTime .ValidUntil}}</td>
      <td><code>{{.TLSVersion}}</code></td>
      <td>
        {{if .Expired}}<span class="badge badge-danger">Expired</span>
        {{else if .ExpiringSoon}}<span class="badge badge-warning">Expiring Soon</span>
        {{else if .SelfSigned}}<span class="badge badge-warning">Self-Signed</span>
        {{else}}<span class="badge badge-success">Valid</span>{{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<div class="section-title">Limitations</div>
<div class="card">
  <p>This report is based on passive and active reconnaissance only. Results depend on what is publicly accessible at scan time. No exploitation, brute force, or vulnerability scanning was performed. Manual review is required to validate findings and assess actual risk.</p>
</div>

</div>

<footer>
  Generated by <strong>{{.Meta.ToolName}} v{{.Meta.Version}}</strong> · Author: {{.Meta.Author}} ·
  <a href="{{.Meta.GitHubURL}}">GitHub</a> · <a href="{{.Meta.LinkedInURL}}">LinkedIn</a>
</footer>

<script>
function filterTable(input, tableId) {
  var filter = input.value.toLowerCase();
  var table = document.getElementById(tableId);
  if (!table) return;
  var rows = table.getElementsByTagName('tr');
  for (var i = 1; i < rows.length; i++) {
    var text = rows[i].textContent.toLowerCase();
    rows[i].style.display = text.includes(filter) ? '' : 'none';
  }
}
</script>
</body>
</html>`
