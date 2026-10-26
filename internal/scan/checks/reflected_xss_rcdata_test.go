package checks

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

// Mirrors the VAmPI/Werkzeug case: the marker is reflected unencoded but only
// inside a <textarea> (a debug page's traceback box). It is not executable XSS,
// so it must NOT be reported as reflected-xss.
func TestReflectedXSSSuppressedInsideTextarea(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		v := r.URL.Query().Get("q") // reflected raw, but inside a textarea
		h := http.Header{}
		h.Set("Content-Type", "text/html")
		body := "<html><body><form><textarea readonly name=code>Traceback: SELECT ... " + v + " ...</textarea></form></body></html>"
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte(body)}
	}}
	base, p := xssPoint(t, "http://x/p?q=hi")
	if issues := (ReflectedXSS{}).Active(context.Background(), sender, base, p); len(issues) != 0 {
		t.Errorf("reflection only inside a <textarea> is not executable XSS; got %v", issues)
	}
}

// Control: the same marker reflected in normal HTML body IS reported.
func TestReflectedXSSReportedInBody(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		v := r.URL.Query().Get("q")
		h := http.Header{}
		h.Set("Content-Type", "text/html")
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte("<html><body><div>" + v + "</div></body></html>")}
	}}
	base, p := xssPoint(t, "http://x/p?q=hi")
	issues := (ReflectedXSS{}).Active(context.Background(), sender, base, p)
	if len(issues) == 0 || !strings.Contains(issues[0].Name, "cross-site") {
		t.Errorf("executable body reflection should be reported; got %v", issues)
	}
}
