package scan_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"lanternfish/internal/client"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/oast"
	"lanternfish/internal/scan"
	"lanternfish/internal/scan/checks"
)

var tplEval = regexp.MustCompile(`(?:\{\{|\$\{|#\{|<%=\s*)(\d+)\s*\*\s*(\d+)(?:\}\}|\}|\s*%>)`)

// fullVulnServer exposes an endpoint per vulnerability class.
func fullVulnServer(t *testing.T) (*httptest.Server, *oast.Server) {
	oastSrv := oast.New("")
	if _, err := oastSrv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>" + r.URL.Query().Get("q") + "</html>"))
	})
	mux.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.Write([]byte("You have an error in your SQL syntax near ''"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/path", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.Write([]byte("file"))
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	mux.HandleFunc("/tpl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		v := r.URL.Query().Get("name")
		v = tplEval.ReplaceAllStringFunc(v, func(m string) string {
			sub := tplEval.FindStringSubmatch(m)
			a, _ := strconv.Atoi(sub[1])
			b, _ := strconv.Atoi(sub[2])
			return strconv.Itoa(a * b)
		})
		w.Write([]byte("<html>" + v + "</html>"))
	})
	mux.HandleFunc("/cors", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("/ssrf", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if u != "" {
			if !strings.HasPrefix(u, "http") {
				u = "http://" + u
			}
			c := &http.Client{Timeout: 2 * time.Second}
			if resp, err := c.Get(u); err == nil {
				resp.Body.Close()
			}
		}
		w.Write([]byte("fetched"))
	})
	mux.HandleFunc("/ldap", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("u"), "*()&|") {
			w.Write([]byte("javax.naming.directory.InvalidSearchFilterException: Bad search filter"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/xpath", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("q"), "'\"") {
			w.Write([]byte("org.apache.xpath.XPathException: A closing bracket expected in"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/hosthdr", func(w http.ResponseWriter, r *http.Request) {
		// Reflect X-Forwarded-Host into a link (password-reset poisoning style).
		xfh := r.Header.Get("X-Forwarded-Host")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><a href="https://` + xfh + `/reset">reset</a></html>`))
	})
	// Boolean-based blind SQLi: false condition returns a shorter body.
	mux.HandleFunc("/bsqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2") || strings.Contains(id, `"1"="2`) {
			w.Write([]byte("no results"))
			return
		}
		w.Write([]byte(strings.Repeat("row data ", 200))) // long baseline + true
	})
	// Time-based blind SQLi.
	mux.HandleFunc("/tsqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if m := regexp.MustCompile(`(?i)(?:sleep|pg_sleep|delay '0:0:)(?:\()?(\d+)`).FindStringSubmatch(id); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n > 12 {
				n = 12
			}
			time.Sleep(time.Duration(n) * time.Second)
		}
		w.Write([]byte("ok"))
	})
	// LFI via php://filter: return base64 of PHP source.
	mux.HandleFunc("/lfi", func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("f")
		if strings.HasPrefix(f, "php://filter") {
			w.Write([]byte(base64.StdEncoding.EncodeToString([]byte("<?php $secret='x'; // app source ?>"))))
			return
		}
		w.Write([]byte("file"))
	})
	// In-band command injection: evaluate echo tag$((a*b))tag.
	mux.HandleFunc("/cmdi", func(w http.ResponseWriter, r *http.Request) {
		h := r.URL.Query().Get("h")
		m := regexp.MustCompile(`echo (ar[0-9a-f]+)\$\(\((\d+)\*(\d+)\)\)(ar[0-9a-f]+)`).FindStringSubmatch(h)
		if m != nil {
			a, _ := strconv.Atoi(m[2])
			b, _ := strconv.Atoi(m[3])
			w.Write([]byte(m[1] + strconv.Itoa(a*b) + m[4]))
			return
		}
		w.Write([]byte("pong"))
	})
	// NoSQL injection error.
	mux.HandleFunc("/nosql", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("u"), `'"[]`) {
			w.Write([]byte("MongoError: unexpected token in JSON"))
			return
		}
		w.Write([]byte("ok"))
	})
	// Dangerous methods via OPTIONS.
	mux.HandleFunc("/methods", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, POST, PUT, DELETE, TRACE")
		w.Write([]byte("ok"))
	})
	// GraphQL introspection.
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}`))
	})
	// Exposed sensitive file for content discovery; unregistered paths 404.
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
	})
	mux.HandleFunc("/neutral", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("h")
		if m := regexp.MustCompile(`sleep\s+(\d+)`).FindStringSubmatch(host); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n > 12 {
				n = 12
			}
			time.Sleep(time.Duration(n) * time.Second)
		}
		w.Write([]byte("pong"))
	})
	return httptest.NewServer(mux), oastSrv
}

func auditURL(t *testing.T, rawurl string, oastSrv *oast.Server) []*scan.Issue {
	t.Helper()
	u, _ := url.Parse(rawurl)
	up := client.New(client.Options{FollowRedirects: false})
	eng := scan.NewEngine(checks.Passive(), checks.Active()).WithRequestChecks(checks.Request())
	col := scan.NewCollector()
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
	ctx := context.Background()
	if oastSrv != nil {
		ctx = scan.WithInteractor(ctx, oastSrv)
	}
	eng.Audit(ctx, up, base, col)
	return col.Issues()
}

func has(issues []*scan.Issue, check string) bool {
	for _, i := range issues {
		if i.Check == check {
			return true
		}
	}
	return false
}

func TestEngineDetectsEachClass(t *testing.T) {
	srv, oastSrv := fullVulnServer(t)
	defer srv.Close()

	cases := []struct {
		path, check string
	}{
		{"/xss?q=hi", "reflected-xss"},
		{"/sqli?id=1", "sqli-error"},
		{"/path?file=a.txt", "path-traversal"},
		{"/redir?next=/home", "open-redirect"},
		{"/tpl?name=hi", "ssti"},
		{"/cors", "cors-misconfig"},
		{"/ssrf?url=http://example.com", "blind-ssrf"},
		{"/ldap?u=admin", "ldap-injection"},
		{"/xpath?q=1", "xpath-injection"},
		{"/hosthdr?p=1", "host-header-injection"},
		{"/bsqli?id=1", "sqli-boolean-blind"},
		{"/lfi?f=index", "lfi"},
		{"/cmdi?h=127.0.0.1", "command-injection-inband"},
		{"/nosql?u=admin", "nosql-injection"},
		{"/methods", "dangerous-http-methods"},
		{"/graphql", "graphql-introspection"},
		{"/neutral", "content-discovery"},
	}
	for _, c := range cases {
		c := c
		t.Run(strings.TrimPrefix(strings.SplitN(c.path, "?", 2)[0], "/"), func(t *testing.T) {
			issues := auditURL(t, srv.URL+c.path, oastSrv)
			if !has(issues, c.check) {
				t.Errorf("%s: expected %q, got %v", c.path, c.check, checkNames(issues))
			}
		})
	}
}

func TestEngineCommandInjectionTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-based check is slow")
	}
	srv, _ := fullVulnServer(t)
	defer srv.Close()
	issues := auditURL(t, srv.URL+"/cmd?h=127.0.0.1", nil)
	if !has(issues, "command-injection") {
		t.Errorf("expected command-injection, got %v", checkNames(issues))
	}
}

func TestEngineTimeBlindSQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-based check is slow")
	}
	srv, _ := fullVulnServer(t)
	defer srv.Close()
	issues := auditURL(t, srv.URL+"/tsqli?id=1", nil)
	if !has(issues, "sqli-time-blind") {
		t.Errorf("expected sqli-time-blind, got %v", checkNames(issues))
	}
}

func checkNames(issues []*scan.Issue) []string {
	var out []string
	for _, i := range issues {
		out = append(out, i.Check)
	}
	return out
}

var _ = fmt.Sprint
