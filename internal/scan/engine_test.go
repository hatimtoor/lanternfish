package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/client"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
	"lanternfish/internal/scan/checks"
)

// vulnHandler mirrors the deliberately-vulnerable fixtures used in manual
// testing so the bundled checks have a known target.
func vulnHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Reflect verbatim (vulnerable).
		w.Write([]byte("<html><body>" + r.URL.Query().Get("q") + "</body></html>"))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(r.URL.Query().Get("name"), "'") {
			w.Write([]byte("You have an error in your SQL syntax; near ''"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.Write([]byte("file"))
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	return mux
}

func scanURL(t *testing.T, srv *httptest.Server, path string) []*scan.Issue {
	t.Helper()
	u, err := url.Parse(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	up := client.New(client.Options{FollowRedirects: false})
	eng := scan.NewEngine(checks.Passive(), checks.Active())
	col := scan.NewCollector()
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
	eng.Audit(context.Background(), up, base, col)
	return col.Issues()
}

func hasCheck(issues []*scan.Issue, id string) bool {
	for _, is := range issues {
		if is.Check == id {
			return true
		}
	}
	return false
}

func TestChecksDetectVulnerableEndpoints(t *testing.T) {
	srv := httptest.NewServer(vulnHandler())
	defer srv.Close()

	cases := []struct {
		path  string
		check string
	}{
		{"/search?q=hi", "reflected-xss"},
		{"/user?name=bob", "sqli-error"},
		{"/download?file=a.pdf", "path-traversal"},
		{"/go?next=/home", "open-redirect"},
	}
	for _, c := range cases {
		issues := scanURL(t, srv, c.path)
		if !hasCheck(issues, c.check) {
			t.Errorf("%s: expected check %q to fire, got %d issues", c.path, c.check, len(issues))
		}
	}
}

func TestNoFalsePositiveOnSafeEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Properly encode reflected input.
		w.Write([]byte("<html><body>query received</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	issues := scanURL(t, srv, "/safe?q=hi")
	if hasCheck(issues, "reflected-xss") {
		t.Error("reflected-xss should not fire when input is not reflected")
	}
	if hasCheck(issues, "sqli-error") {
		t.Error("sqli-error should not fire without a DB error")
	}
}

func TestInsertionPointsCoverQueryAndBody(t *testing.T) {
	u, _ := url.Parse("http://x/p?a=1&b=2")
	h := http.Header{}
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	base := &httpmsg.Request{Method: "POST", URL: u, Scheme: "http", Host: "x", Header: h, Body: []byte("c=3")}
	pts := scan.InsertionPoints(base)
	if got := countKind(pts, scan.KindQuery); got != 2 {
		t.Fatalf("expected 2 query points (a,b), got %d", got)
	}
	if got := countKind(pts, scan.KindBody); got != 1 {
		t.Fatalf("expected 1 body point (c), got %d", got)
	}
	// The "/p" path also yields one path segment under the expanded taxonomy.
	if got := countKind(pts, scan.KindPath); got != 1 {
		t.Fatalf("expected 1 path point, got %d", got)
	}
}

func countKind(pts []scan.InsertionPoint, k scan.Kind) int {
	n := 0
	for _, p := range pts {
		if p.Kind == k {
			n++
		}
	}
	return n
}

func TestInsertionPointsJSON(t *testing.T) {
	u, _ := url.Parse("http://x/api")
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	base := &httpmsg.Request{Method: "POST", URL: u, Scheme: "http", Host: "x", Header: h,
		Body: []byte(`{"user":{"name":"bob","age":5},"tags":["x","y"]}`)}
	pts := scan.InsertionPoints(base)
	if got := countKind(pts, scan.KindJSON); got != 4 {
		t.Fatalf("expected 4 JSON leaves (name,age,tags[0],tags[1]), got %d", got)
	}
	// Mutating the "name" leaf must yield valid JSON with the value replaced.
	for _, p := range pts {
		if p.Kind == scan.KindJSON && p.Name == "name" {
			req := p.Mutate("INJ'\"")
			if !strings.Contains(string(req.Body), `"name":"INJ'`) {
				t.Fatalf("name not replaced in body: %s", req.Body)
			}
			if !strings.Contains(string(req.Body), `"age":5`) {
				t.Fatalf("mutation corrupted sibling: %s", req.Body)
			}
		}
	}
}

func TestInsertionPointsXMLMultipartName(t *testing.T) {
	// XML: text node + attribute value.
	xu, _ := url.Parse("http://x/soap")
	xh := http.Header{}
	xh.Set("Content-Type", "application/xml")
	xbase := &httpmsg.Request{Method: "POST", URL: xu, Scheme: "http", Host: "x", Header: xh,
		Body: []byte(`<order id="7"><item>book</item></order>`)}
	xpts := scan.InsertionPoints(xbase)
	if got := countKind(xpts, scan.KindXML); got < 2 {
		t.Fatalf("expected >=2 XML points (id attr, item text), got %d", got)
	}
	for _, p := range xpts {
		if p.Kind == scan.KindXML && p.Base == "book" {
			req := p.Mutate("a<b&c")
			if !strings.Contains(string(req.Body), "a&lt;b&amp;c") {
				t.Fatalf("xml text not escaped/replaced: %s", req.Body)
			}
			if !strings.Contains(string(req.Body), `id="7"`) {
				t.Fatalf("xml mutation corrupted siblings: %s", req.Body)
			}
		}
	}

	// Multipart: two form fields.
	body := "--B\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nbob\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n--B--\r\n"
	mh := http.Header{}
	mh.Set("Content-Type", `multipart/form-data; boundary=B`)
	mbase := &httpmsg.Request{Method: "POST", URL: xu, Scheme: "http", Host: "x", Header: mh, Body: []byte(body)}
	mpts := scan.InsertionPoints(mbase)
	if got := countKind(mpts, scan.KindMultipart); got != 2 {
		t.Fatalf("expected 2 multipart points, got %d", got)
	}
	for _, p := range mpts {
		if p.Kind == scan.KindMultipart && p.Name == "user" {
			req := p.Mutate("INJ")
			if !strings.Contains(string(req.Body), "INJ") || !strings.Contains(string(req.Body), "admin") {
				t.Fatalf("multipart mutation wrong: %s", req.Body)
			}
		}
	}

	// Parameter name fuzzing on a query param.
	qu, _ := url.Parse("http://x/p?id=1")
	qbase := &httpmsg.Request{Method: "GET", URL: qu, Scheme: "http", Host: "x", Header: http.Header{}}
	qpts := scan.InsertionPoints(qbase)
	if got := countKind(qpts, scan.KindParamName); got != 1 {
		t.Fatalf("expected 1 param-name point, got %d", got)
	}
	for _, p := range qpts {
		if p.Kind == scan.KindParamName {
			req := p.Mutate("evil")
			if !strings.Contains(req.URL.RawQuery, "evil=1") {
				t.Fatalf("param-name mutation wrong: %s", req.URL.RawQuery)
			}
		}
	}
}

func TestInsertionPointsCookieHeaderPath(t *testing.T) {
	u, _ := url.Parse("http://x/api/users/42")
	h := http.Header{}
	h.Set("Cookie", "sid=abc; theme=dark")
	h.Set("User-Agent", "lanternfish")
	h.Set("Referer", "http://x/")
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: h}
	pts := scan.InsertionPoints(base)
	if got := countKind(pts, scan.KindCookie); got != 2 {
		t.Fatalf("expected 2 cookie points, got %d", got)
	}
	if got := countKind(pts, scan.KindHeader); got != 2 {
		t.Fatalf("expected 2 header points (UA, Referer), got %d", got)
	}
	if got := countKind(pts, scan.KindPath); got != 3 {
		t.Fatalf("expected 3 path segments, got %d", got)
	}
	// A cookie mutation must keep the other cookie intact.
	for _, p := range pts {
		if p.Kind == scan.KindCookie && p.Name == "sid" {
			req := p.Mutate("X")
			if c := req.Header.Get("Cookie"); !strings.Contains(c, "sid=X") || !strings.Contains(c, "theme=dark") {
				t.Fatalf("cookie mutation wrong: %q", c)
			}
		}
		// A path mutation must preserve a traversal payload verbatim.
		if p.Kind == scan.KindPath && p.Base == "42" {
			req := p.Mutate("..%2f..%2fetc")
			if !strings.Contains(req.URL.EscapedPath(), "..%2f..%2fetc") {
				t.Fatalf("path payload not preserved: %s", req.URL.EscapedPath())
			}
		}
	}
}
