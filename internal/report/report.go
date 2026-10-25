// Package report renders scan results as JSON (for CI) or text (for humans).
package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	htmlpkg "html"
	"io"
	"strings"
	"time"

	"lanternfish/internal/kb"
	"lanternfish/internal/scan"
)

// Report is the top-level result document.
type Report struct {
	Tool      string        `json:"tool"`
	Version   string        `json:"version"`
	Target    string        `json:"target"`
	StartedAt time.Time     `json:"started_at"`
	Duration  string        `json:"duration"`
	Issues    []*scan.Issue `json:"issues"`
	Summary   Summary       `json:"summary"`
}

// Summary counts issues by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Build assembles a Report from collected issues.
func Build(version, target string, started time.Time, issues []*scan.Issue) *Report {
	r := &Report{
		Tool: "lanternfish", Version: version, Target: target,
		StartedAt: started, Duration: time.Since(started).Round(time.Millisecond).String(),
		Issues: issues,
	}
	r.Summary.Total = len(issues)
	for _, is := range issues {
		switch is.Severity {
		case scan.SeverityCritical:
			r.Summary.Critical++
		case scan.SeverityHigh:
			r.Summary.High++
		case scan.SeverityMedium:
			r.Summary.Medium++
		case scan.SeverityLow:
			r.Summary.Low++
		default:
			r.Summary.Info++
		}
	}
	return r
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteXML writes the report as XML.
func (r *Report) WriteXML(w io.Writer) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(r)
}

// WriteHTML writes a self-contained HTML report.
func (r *Report) WriteHTML(w io.Writer) error {
	esc := htmlpkg.EscapeString
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=utf-8><title>Lanternfish report</title><style>")
	b.WriteString("body{font:14px system-ui,sans-serif;margin:24px;color:#1c2430}h1{font-size:20px}")
	b.WriteString(".sev{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:12px}")
	b.WriteString(".critical{background:#c0392b}.high{background:#e67e22}.medium{background:#d4ac0d;color:#111}.low{background:#2e86de}.info{background:#7f8c8d}")
	b.WriteString(".issue{border:1px solid #dde;border-radius:6px;padding:12px;margin:10px 0}code{background:#f2f4f7;padding:1px 4px;border-radius:3px}")
	b.WriteString(".learn{margin-top:8px;border-left:3px solid #2e86de;padding-left:10px}.learn summary{cursor:pointer;color:#2e86de}.learn a{color:#2e86de}")
	b.WriteString(".chips{margin:12px 0}.chip{cursor:pointer;border:1px solid #cdd;border-radius:14px;padding:3px 12px;margin-right:6px;font-size:13px;user-select:none}.chip.off{opacity:.4}.chip.active{outline:2px solid #1c2430}")
	b.WriteString("</style></head><body>")
	fmt.Fprintf(&b, "<h1>Lanternfish scan report</h1><p>Target: <code>%s</code> · %s · completed in %s</p>",
		esc(r.Target), r.StartedAt.Format("2006-01-02 15:04"), esc(r.Duration))
	// Clickable severity filter chips (click to show only that severity; click
	// "all" to reset). Pure inline JS so the report works offline.
	fmt.Fprintf(&b, `<div class="chips"><span class="chip active" data-f="all" onclick="lf('all',this)">All %d</span>`, r.Summary.Total)
	for _, s := range []struct {
		key   string
		count int
	}{{"critical", r.Summary.Critical}, {"high", r.Summary.High}, {"medium", r.Summary.Medium}, {"low", r.Summary.Low}, {"info", r.Summary.Info}} {
		if s.count > 0 {
			fmt.Fprintf(&b, `<span class="chip sev %s" data-f="%s" onclick="lf('%s',this)">%s %d</span>`, s.key, s.key, s.key, upper(s.key), s.count)
		}
	}
	b.WriteString(`</div>`)
	for _, is := range r.Issues {
		fmt.Fprintf(&b, `<div class="issue" data-sev="%s"><span class="sev %s">%s</span> <b>%s</b> <span style="color:#888">%s %s</span>`,
			esc(is.SeverityStr), esc(is.SeverityStr), esc(upper(is.SeverityStr)), esc(is.Name), esc(is.ConfStr), esc(is.CWE))
		fmt.Fprintf(&b, `<div><code>%s</code>%s</div>`, esc(is.URL), paramHTML(is.Param))
		fmt.Fprintf(&b, `<p>%s</p>`, esc(is.Detail))
		if is.Evidence != "" {
			fmt.Fprintf(&b, `<p>Evidence: <code>%s</code></p>`, esc(oneLine(is.Evidence)))
		}
		if is.Remediation != "" {
			fmt.Fprintf(&b, `<p><b>Fix:</b> %s</p>`, esc(is.Remediation))
		}
		if e, ok := kb.Lookup(is.Check); ok {
			b.WriteString(`<details class="learn"><summary>Learn about this</summary>`)
			if e.Why != "" {
				fmt.Fprintf(&b, `<p><b>Why it matters:</b> %s</p>`, esc(e.Why))
			}
			if e.Confirm != "" {
				fmt.Fprintf(&b, `<p><b>How to confirm:</b> %s</p>`, esc(e.Confirm))
			}
			if e.Exploit != "" {
				fmt.Fprintf(&b, `<p><b>How to exploit (in a lab you own):</b> %s</p>`, esc(e.Exploit))
			}
			for _, ref := range e.Refs {
				fmt.Fprintf(&b, `<p>↗ <a href="%s" target="_blank" rel="noopener">%s</a></p>`, esc(ref), esc(ref))
			}
			b.WriteString(`</details>`)
		}
		b.WriteString("</div>")
	}
	b.WriteString(`<script>function lf(f,el){` +
		`document.querySelectorAll('.issue').forEach(function(d){d.style.display=(f==='all'||d.getAttribute('data-sev')===f)?'':'none'});` +
		`document.querySelectorAll('.chip').forEach(function(c){c.classList.toggle('active',c.getAttribute('data-f')===f)});}</script>`)
	b.WriteString("</body></html>")
	_, err := io.WriteString(w, b.String())
	return err
}

func paramHTML(p string) string {
	if p == "" {
		return ""
	}
	return " parameter <code>" + htmlpkg.EscapeString(p) + "</code>"
}

// WriteText writes a human-readable summary.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "Lanternfish scan of %s\n", r.Target)
	fmt.Fprintf(w, "Completed in %s\n\n", r.Duration)
	if len(r.Issues) == 0 {
		fmt.Fprintln(w, "No issues found.")
		return
	}
	for _, is := range r.Issues {
		fmt.Fprintf(w, "[%s/%s] %s\n", upper(is.SeverityStr), is.ConfStr, is.Name)
		fmt.Fprintf(w, "    url:    %s\n", is.URL)
		if is.Param != "" {
			fmt.Fprintf(w, "    param:  %s\n", is.Param)
		}
		if is.CWE != "" {
			fmt.Fprintf(w, "    cwe:    %s\n", is.CWE)
		}
		fmt.Fprintf(w, "    detail: %s\n", is.Detail)
		if is.Evidence != "" {
			fmt.Fprintf(w, "    evidence: %s\n", oneLine(is.Evidence))
		}
		if is.Remediation != "" {
			fmt.Fprintf(w, "    fix:    %s\n", is.Remediation)
		}
		// Teaching content from the knowledge base.
		if e, ok := kb.Lookup(is.Check); ok {
			if e.Why != "" {
				fmt.Fprintf(w, "    why:    %s\n", e.Why)
			}
			if e.Confirm != "" {
				fmt.Fprintf(w, "    confirm: %s\n", e.Confirm)
			}
			for i, ref := range e.Refs {
				if i == 0 {
					fmt.Fprintf(w, "    learn:  %s\n", ref)
				} else {
					fmt.Fprintf(w, "            %s\n", ref)
				}
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Summary: %d issue(s) — critical=%d high=%d medium=%d low=%d info=%d\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		out = append(out, r)
	}
	if len(out) > 160 {
		out = append(out[:160], []rune("…")...)
	}
	return string(out)
}
