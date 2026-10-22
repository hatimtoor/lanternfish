package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lanternfish/internal/scan"
)

func TestBuildSummaryCounts(t *testing.T) {
	issues := []*scan.Issue{
		{Name: "a", Severity: scan.SeverityCritical},
		{Name: "b", Severity: scan.SeverityHigh},
		{Name: "c", Severity: scan.SeverityHigh},
		{Name: "d", Severity: scan.SeverityLow},
		{Name: "e", Severity: scan.SeverityInfo},
	}
	for _, i := range issues {
		i.SeverityStr = i.Severity.String()
	}
	r := Build("0.1", "http://t", time.Now(), issues)
	if r.Summary.Total != 5 || r.Summary.Critical != 1 || r.Summary.High != 2 || r.Summary.Low != 1 || r.Summary.Info != 1 {
		t.Errorf("summary counts wrong: %+v", r.Summary)
	}
}

func TestWriteJSONValid(t *testing.T) {
	r := Build("0.1", "http://t", time.Now(), []*scan.Issue{{Name: "x", Severity: scan.SeverityHigh, SeverityStr: "high"}})
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if back["tool"] != "lanternfish" {
		t.Error("json missing tool field")
	}
}

func TestWriteTextContainsFindings(t *testing.T) {
	r := Build("0.1", "http://t", time.Now(), []*scan.Issue{{Name: "Reflected XSS", Severity: scan.SeverityHigh, SeverityStr: "high", ConfStr: "firm", URL: "http://t/x"}})
	var buf bytes.Buffer
	r.WriteText(&buf)
	out := buf.String()
	if !strings.Contains(out, "Reflected XSS") || !strings.Contains(out, "HIGH") {
		t.Errorf("text report missing content:\n%s", out)
	}
}

func TestWriteHTMLAndXML(t *testing.T) {
	r := Build("0.1", "http://t", time.Now(), []*scan.Issue{{Name: "Reflected XSS", Severity: scan.SeverityHigh, SeverityStr: "high", ConfStr: "firm", URL: "http://t/x?q=<script>", CWE: "CWE-79"}})
	var html bytes.Buffer
	if err := r.WriteHTML(&html); err != nil {
		t.Fatal(err)
	}
	h := html.String()
	if !strings.Contains(h, "Reflected XSS") || !strings.Contains(h, "<!doctype html>") {
		t.Error("HTML report missing content")
	}
	if strings.Contains(h, "q=<script>") {
		t.Error("HTML report did not escape the URL")
	}
	var x bytes.Buffer
	if err := r.WriteXML(&x); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(x.String(), "<?xml") || !strings.Contains(x.String(), "Reflected XSS") {
		t.Error("XML report missing content")
	}
}

func TestWriteTextNoIssues(t *testing.T) {
	r := Build("0.1", "http://t", time.Now(), nil)
	var buf bytes.Buffer
	r.WriteText(&buf)
	if !strings.Contains(buf.String(), "No issues found") {
		t.Error("empty report should say no issues")
	}
}
