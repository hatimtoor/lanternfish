// Command lanternfish-testbed is a deliberately vulnerable web app for exercising
// Lanternfish end to end. It binds to loopback only and must never be exposed. Every
// endpoint is intentionally insecure; do not copy any of this into real code.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func html(w http.ResponseWriter) { w.Header().Set("Content-Type", "text/html") }

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "loopback listen address")
	flag.Parse()
	if !strings.HasPrefix(*addr, "127.0.0.1") && !strings.HasPrefix(*addr, "localhost") {
		fmt.Println("refusing to bind a deliberately vulnerable app to a non-loopback address")
		return
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		html(w)
		fmt.Fprint(w, `<html><head><title>Lanternfish Testbed</title></head><body>
<h1>Lanternfish Testbed — deliberately vulnerable</h1>
<ul>
<li><a href="/search?q=hello">Reflected XSS</a></li>
<li><a href="/product?id=1">SQL injection (MySQL error)</a></li>
<li><a href="/lookup?id=1">Blind SQL injection</a></li>
<li><a href="/download?file=report.pdf">Path traversal</a></li>
<li><a href="/include?f=home">Local file inclusion</a></li>
<li><a href="/go?next=/home">Open redirect</a></li>
<li><a href="/render?name=Guest">Server-side template injection</a></li>
<li><a href="/dir?u=admin">LDAP injection</a></li>
<li><a href="/find?q=1">XPath injection</a></li>
<li><a href="/users?u=admin">NoSQL injection</a></li>
<li><a href="/fetch?url=http://example.com">Blind SSRF</a></li>
<li><a href="/api/graphql">GraphQL introspection</a></li>
<li><a href="/cors">CORS misconfiguration</a></li>
<li><a href="/leaky">Information disclosure (secrets, PII, old libs)</a></li>
<li><a href="/app.js">Source map disclosure</a></li>
<li><a href="/login">Login form (autocomplete, insecure)</a></li>
<li><a href="/track">Header-based reflected XSS (User-Agent)</a></li>
<li><a href="/files/report.pdf">Path-segment traversal</a></li>
<li><a href="/account">Cookie-based SQL injection (sid cookie)</a></li>
<li><a href="/api/profile">JSON body injection (POST name)</a></li>
</ul>
<form action="/product" method="get"><input name="id" value="1"><input type="submit" value="Lookup"></form>
</body></html>`)
	})

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		fmt.Fprintf(w, "<html><body><h2>Results for %s</h2></body></html>", r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/product", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), `'"`) {
			w.Write([]byte("Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
			return
		}
		html(w)
		fmt.Fprint(w, "<html><body>Product 1</body></html>")
	})
	mux.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2") {
			w.Write([]byte("no results"))
			return
		}
		if m := regexp.MustCompile(`(?i)sleep\((\d+)\)`).FindStringSubmatch(id); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n > 10 {
				n = 10
			}
			time.Sleep(time.Duration(n) * time.Second)
		}
		w.Write([]byte(strings.Repeat("record ", 200)))
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.Write([]byte("contents"))
	})
	mux.HandleFunc("/include", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("f"), "php://filter") {
			src := "<?php $config = array('db'=>'prod','secret'=>'s3cr3t','debug'=>true); // main application config loaded here ?>"
			w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(src))))
			return
		}
		html(w)
		fmt.Fprint(w, "<html><body>home page</body></html>")
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	mux.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("name")
		v = regexp.MustCompile(`(?:\{\{|\$\{|#\{|<%=\s*)(\d+)\s*\*\s*(\d+)(?:\}\}|\}|\s*%>)`).ReplaceAllStringFunc(v, func(m string) string {
			s := regexp.MustCompile(`(\d+)\s*\*\s*(\d+)`).FindStringSubmatch(m)
			a, _ := strconv.Atoi(s[1])
			b, _ := strconv.Atoi(s[2])
			return strconv.Itoa(a * b)
		})
		html(w)
		fmt.Fprintf(w, "<html><body>Hello %s</body></html>", v)
	})
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("u"), "*()") {
			w.Write([]byte("javax.naming.directory.InvalidSearchFilterException: Bad search filter"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("q"), `'"`) {
			w.Write([]byte("org.apache.xpath.XPathException: A closing bracket expected in the expression"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("u"), `'"[]`) {
			w.Write([]byte("MongoError: unexpected token in JSON at position 1"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			if !strings.HasPrefix(u, "http") {
				u = "http://" + u
			}
			c := &http.Client{Timeout: 3 * time.Second}
			if resp, err := c.Get(u); err == nil {
				resp.Body.Close()
			}
		}
		w.Write([]byte("fetched"))
	})
	mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"},{"name":"Order"}]}}}`))
	})
	mux.HandleFunc("/cors", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("/* jQuery v1.7.2 */\nconsole.log('app');\n//# sourceMappingURL=app.js.map\n"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		fmt.Fprint(w, `<html><body><form action="http://`+*addr+`/login" method="post">
<input name="user"><input type="password" name="pass"><input type="submit"></form></body></html>`)
	})
	// JSON body injection: reflects a JSON field unescaped (XSS) and errors on
	// a SQL metacharacter (SQLi) — exercises the JSON insertion point.
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var in struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(body, &in)
		if strings.ContainsAny(in.Name, `'"`) {
			w.Write([]byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
			return
		}
		html(w)
		fmt.Fprintf(w, "<html><body>Hello %s</body></html>", in.Name)
	})
	// Cookie-based SQL injection: errors on a SQL metacharacter in the sid cookie.
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil && strings.ContainsAny(c.Value, `'"`) {
			w.Write([]byte("Warning: pg_query(): Query failed: ERROR: unterminated quoted string"))
			return
		}
		w.Write([]byte("account page"))
	})
	// Header-based reflected XSS: reflects the User-Agent unescaped.
	mux.HandleFunc("/track", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		fmt.Fprintf(w, "<html><body>UA: %s</body></html>", r.UserAgent())
	})
	// Path-segment traversal: the last path segment is used as a filename.
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		seg := strings.TrimPrefix(r.URL.Path, "/files/")
		if strings.Contains(seg, "passwd") || strings.Contains(seg, "..") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.Write([]byte("file contents"))
	})

	// DOM sinks + client-side prototype pollution + a postMessage sink, all
	// reachable from the URL, for the headless DOM probe.
	mux.HandleFunc("/dom", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		fmt.Fprint(w, `<html><body><div id="out"></div><script>
// Unsafe: reflect location data straight into innerHTML (DOM XSS).
document.getElementById('out').innerHTML = location.hash + location.search;
// Unsafe: merge query params into an object without guarding __proto__.
var p={}; location.search.slice(1).split('&').forEach(function(kv){
  var i=kv.indexOf('='); var k=decodeURIComponent(kv.slice(0,i)); var v=decodeURIComponent(kv.slice(i+1));
  var parts=k.replace(/\]/g,'').split('['); var o=p;
  for(var j=0;j<parts.length-1;j++){ o=o[parts[j]]=o[parts[j]]||{}; }
  o[parts[parts.length-1]]=v;
});
// Unsafe: sink postMessage data into innerHTML.
window.addEventListener('message',function(e){ document.getElementById('out').innerHTML=e.data; });
</script></body></html>`)
	})

	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/example/app.git\n"))
	})
	mux.HandleFunc("/leaky", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		w.Header().Set("Server", "Apache/2.4.49 (Unix) PHP/7.4.3")
		w.Header().Add("Set-Cookie", "SESSIONID=abc123; Path=/")
		jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) + "."
		// Fake example keys, assembled at runtime so no literal secret lives in
		// source (keeps this public repo clean of secret-scanner matches while
		// still exercising detection against the served response).
		stripeKey := "sk_live_" + "abcdefghijklmnop0123456789"
		awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
		fmt.Fprintf(w, `<html><head><script>/* jQuery v1.7.2 */</script></head><body>
<!-- TODO: remove hardcoded admin password before launch -->
Internal host: 10.0.0.42. Support: admin@corp.local
Card on file: 4111 1111 1111 1111
Stripe key: %s
AWS: %s
token=%s
</body></html>`, stripeKey, awsKey, jwt)
	})

	fmt.Printf("Lanternfish Testbed (deliberately vulnerable) listening on http://%s/\n", *addr)
	fmt.Println("Loopback only. Point Lanternfish (proxy/scan/crawl) at it, or open it in a browser.")
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Println("error:", err)
	}
}
