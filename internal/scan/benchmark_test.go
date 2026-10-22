package scan_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"lanternfish/internal/oast"
	"lanternfish/internal/scan"
	"lanternfish/internal/scan/checks"
	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

// benchServer is a kitchen-sink target: a vulnerable endpoint per check, plus
// a "passive" page that trips many passive rules at once, plus safe endpoints
// used to catch false positives.
func benchServer(t *testing.T) (*httptest.Server, *oast.Server) {
	oastSrv := oast.New("")
	if _, err := oastSrv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	reSleep := regexp.MustCompile(`(?i)(?:sleep|pg_sleep|delay '0:0:|timeout /t )\(?(\d+)`)
	sleepIf := func(s string) {
		if m := reSleep.FindStringSubmatch(s); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n > 10 {
				n = 10
			}
			time.Sleep(time.Duration(n) * time.Second)
		}
	}
	html := func(w http.ResponseWriter) http.ResponseWriter { w.Header().Set("Content-Type", "text/html"); return w }

	// --- Active, per-parameter ---
	mux.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		html(w).Write([]byte("<html>" + r.URL.Query().Get("q") + "</html>"))
	})
	mux.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.Write([]byte("You have an error in your SQL syntax near ''"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/mysql", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), `'"`) {
			w.Write([]byte("check the manual that corresponds to your MySQL server version"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/postgres", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), `'"`) {
			w.Write([]byte("PostgreSQL ERROR: unterminated quoted string"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/mssql", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), `'"`) {
			w.Write([]byte("System.Data.SqlClient.SqlException: Unclosed quotation mark after the character string"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/oracle", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), `'"`) {
			w.Write([]byte("ORA-01756: quoted string not properly terminated"))
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
	mux.HandleFunc("/lfi", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("f"), "php://filter") {
			src := "<?php $config = array('db' => 'prod', 'key' => 'supersecret', 'debug' => false); // application configuration file ?>"
			w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(src))))
			return
		}
		w.Write([]byte("file"))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("console.log('x');\n//# sourceMappingURL=app.js.map\n"))
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	mux.HandleFunc("/ssti", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("name")
		v = regexp.MustCompile(`(?:\{\{|\$\{|#\{|<%=\s*)(\d+)\s*\*\s*(\d+)(?:\}\}|\}|\s*%>)`).ReplaceAllStringFunc(v, func(m string) string {
			s := regexp.MustCompile(`(\d+)\s*\*\s*(\d+)`).FindStringSubmatch(m)
			a, _ := strconv.Atoi(s[1])
			b, _ := strconv.Atoi(s[2])
			return strconv.Itoa(a * b)
		})
		html(w).Write([]byte("<html>" + v + "</html>"))
	})
	mux.HandleFunc("/spel", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("x"), "${") || strings.Contains(r.URL.Query().Get("x"), "#{") {
			w.Write([]byte("EL1008E: Property or field cannot be found"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/crlf", func(w http.ResponseWriter, r *http.Request) {
		// Emulate a header reflected from the param (Go server can't inject real CRLF,
		// so decode and set a header if the marker is present).
		v := r.URL.Query().Get("x")
		if strings.Contains(v, "Lanternfish-Crlf") {
			w.Header().Set("Lanternfish-Crlf-Check", "1")
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/cmdtime", func(w http.ResponseWriter, r *http.Request) { sleepIf(r.URL.Query().Get("h")); w.Write([]byte("pong")) })
	mux.HandleFunc("/cmdinband", func(w http.ResponseWriter, r *http.Request) {
		m := regexp.MustCompile(`echo (ar[0-9a-f]+)\$\(\((\d+)\*(\d+)\)\)(ar[0-9a-f]+)`).FindStringSubmatch(r.URL.Query().Get("h"))
		if m != nil {
			a, _ := strconv.Atoi(m[2])
			b, _ := strconv.Atoi(m[3])
			w.Write([]byte(m[1] + strconv.Itoa(a*b) + m[4]))
			return
		}
		w.Write([]byte("pong"))
	})
	mux.HandleFunc("/ldap", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("u"), "*()") {
			w.Write([]byte("javax.naming.directory.InvalidSearchFilterException: Bad search filter"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/xpath", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("q"), `'"`) {
			w.Write([]byte("org.apache.xpath.XPathException: A closing bracket expected"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/nosql", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("u"), `'"[]`) {
			w.Write([]byte("MongoError: unexpected token in JSON"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/bsqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2") {
			w.Write([]byte("no results"))
			return
		}
		w.Write([]byte(strings.Repeat("row ", 300)))
	})
	mux.HandleFunc("/ssrf", func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
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

	// --- Request-level ---
	mux.HandleFunc("/cors", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("/hosthdr", func(w http.ResponseWriter, r *http.Request) {
		html(w).Write([]byte(`<a href="https://` + r.Header.Get("X-Forwarded-Host") + `/reset">r</a>`))
	})
	mux.HandleFunc("/methods", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, POST, PUT, DELETE, TRACE")
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}`))
	})
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("[core]\n")) })

	// --- Passive kitchen sink: trips many passive rules at once ---
	mux.HandleFunc("/passive", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "Apache/2.4.49")
		w.Header().Add("Set-Cookie", "SESSION=abc; Path=/")
		jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`)) + "."
		w.Write([]byte(`<html><head>
<script>/* jQuery v1.7.2 */</script>
<script>//# sourceMappingURL=app.js.map</script>
</head><body>
<!-- TODO: remove hardcoded password before ship -->
internal host 192.168.1.50 contact admin@corp.test
card 4111 1111 1111 1111
stripe sk_live_` + `abcdefghijklmnop0123456789
jwt=` + jwt + `
<form action="http://corp.test/login" method="post"><input type="password" name="p"></form>
<a href="/next?jsessionid=ABCDEF0123456789">x</a>
</body></html>`))
	})

	// --- Safe endpoints (must NOT trip the paired check) ---
	mux.HandleFunc("/safe/xss", func(w http.ResponseWriter, r *http.Request) {
		html(w).Write([]byte("<html>query received</html>")) // not reflected
	})
	mux.HandleFunc("/safe/sqli", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/safe/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Write([]byte("<html><body>nothing sensitive here, just text</body></html>"))
	})
	return httptest.NewServer(mux), oastSrv
}

func benchScan(t *testing.T, svc *service.Service, url string) map[string]bool {
	t.Helper()
	res, err := svc.ScanURL(context.Background(), url)
	if err != nil {
		t.Fatalf("scan %s: %v", url, err)
	}
	fired := map[string]bool{}
	for _, i := range res.Issues {
		fired[i.Check] = true
	}
	return fired
}

// TestBenchmarkCoverage scans a kitchen-sink target and reports, per check,
// whether it fired where expected (true positive) and whether any check fired
// on a safe page (false positive). It fails on misses or false positives.
func TestBenchmarkCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark runs the full active scanner; slow")
	}
	srv, oastSrv := benchServer(t)
	defer srv.Close()
	sess := session.New()
	svc := service.New(sess, false)
	svc.OAST = oastSrv

	// Each vulnerable endpoint and the check it should produce.
	type tc struct{ path, want string }
	cases := []tc{
		{"/xss?q=x", "reflected-xss"},
		{"/sqli?id=1", "sqli-error"},
		{"/mysql?id=1", "sqli-mysql"},
		{"/postgres?id=1", "sqli-postgres"},
		{"/mssql?id=1", "sqli-mssql"},
		{"/oracle?id=1", "sqli-oracle"},
		{"/path?file=a", "path-traversal"},
		{"/lfi?f=index", "lfi"},
		{"/redir?next=/x", "open-redirect"},
		{"/ssti?name=x", "ssti"},
		{"/spel?x=1", "ssti-spel"},
		{"/cmdinband?h=1", "command-injection-inband"},
		{"/ldap?u=a", "ldap-injection"},
		{"/xpath?q=1", "xpath-injection"},
		{"/nosql?u=a", "nosql-injection"},
		{"/bsqli?id=1", "sqli-boolean-blind"},
		{"/ssrf?url=http://x", "blind-ssrf"},
		{"/cors", "cors-misconfig"},
		{"/hosthdr?a=1", "host-header-injection"},
		{"/methods", "dangerous-http-methods"},
		{"/graphql", "graphql-introspection"},
		{"/neutral", "content-discovery"}, // probes root /.git/config
	}

	type result struct {
		name   string
		status string
	}
	var matrix []result
	for _, c := range cases {
		fired := benchScan(t, svc, srv.URL+c.path)
		if fired[c.want] {
			matrix = append(matrix, result{c.want, "PASS (detected)"})
		} else {
			matrix = append(matrix, result{c.want, "FAIL (missed)"})
			t.Errorf("MISS: %s did not fire on %s", c.want, c.path)
		}
	}

	// Passive kitchen-sink: expect this broad set.
	passiveWant := []string{
		"security-headers", "banner-disclosure", "cookie-samesite",
		"sensitive-comment", "private-ip-disclosure", "email-disclosure", "pii-credit-card",
		"insecure-form", "session-token-in-url", "jwt-weakness", "vulnerable-js-library",
		"additional-headers", "cacheable-sensitive", "secret-stripe-secret", "fingerprint-apache",
	}
	// jsessionid in the request URL exercises session-token-in-url (a
	// request-URL check); the response body is unchanged.
	pfired := benchScan(t, svc, srv.URL+"/passive?jsessionid=ABCDEF0123456789")

	// source-map-disclosure only inspects JS/JSON responses.
	if benchScan(t, svc, srv.URL+"/app.js")["source-map-disclosure"] {
		matrix = append(matrix, result{"source-map-disclosure", "PASS (detected)"})
	} else {
		matrix = append(matrix, result{"source-map-disclosure", "FAIL (missed)"})
		t.Error("MISS: source-map-disclosure did not fire on app.js")
	}
	for _, w := range passiveWant {
		if pfired[w] {
			matrix = append(matrix, result{w, "PASS (detected)"})
		} else {
			matrix = append(matrix, result{w, "FAIL (missed)"})
			t.Errorf("MISS: passive %s did not fire on /passive", w)
		}
	}

	// False-positive checks on safe endpoints.
	safe := benchScan(t, svc, srv.URL+"/safe/page?q=1")
	for _, fp := range []string{"reflected-xss", "sqli-error", "security-headers", "additional-headers", "pii-credit-card", "sensitive-comment", "banner-disclosure"} {
		if safe[fp] {
			matrix = append(matrix, result{fp + " (safe page)", "FAIL (false positive)"})
			t.Errorf("FALSE POSITIVE: %s fired on the safe page", fp)
		} else {
			matrix = append(matrix, result{fp + " (safe page)", "PASS (no FP)"})
		}
	}
	safeXSS := benchScan(t, svc, srv.URL+"/safe/xss?q=x")
	if safeXSS["reflected-xss"] {
		t.Error("FALSE POSITIVE: reflected-xss fired on non-reflecting endpoint")
	}

	sort.Slice(matrix, func(i, j int) bool { return matrix[i].name < matrix[j].name })
	var b strings.Builder
	b.WriteString("\n=== Lanternfish check benchmark matrix ===\n")
	for _, m := range matrix {
		fmt.Fprintf(&b, "  %-40s %s\n", m.name, m.status)
	}
	t.Log(b.String())
}

// TestBenchmarkTimingChecks exercises the slow time-based checks separately.
func TestBenchmarkTimingChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("timing checks are slow")
	}
	srv, _ := benchServer(t)
	defer srv.Close()
	svc := service.New(session.New(), false)
	for _, c := range []struct{ path, want string }{
		{"/cmdtime?h=127.0.0.1", "command-injection"},
		{"/bsqli?id=1", "sqli-boolean-blind"},
	} {
		if !benchScan(t, svc, srv.URL+c.path)[c.want] {
			t.Errorf("timing MISS: %s on %s", c.want, c.path)
		}
	}
	_ = scan.SeverityHigh
	_ = checks.Passive
}
