// Package labs is Lanternfish's built-in practice range: a set of deliberately
// vulnerable, loopback-only challenges a learner can legally attack to build
// skills. Each challenge has a brief, a ladder of hints, and a flag that only
// appears once the intended bug is exploited. It exists because the biggest
// barrier for a self-taught analyst is having somewhere lawful to practice.
package labs

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Challenge describes one practice exercise.
type Challenge struct {
	ID         string
	Title      string
	Category   string
	Difficulty string // easy | medium | hard
	Brief      string
	Hints      []string
	Flag       string
	// Start is the path the learner attacks (shown in the brief).
	Start string
}

// Challenges is the ordered catalogue. Flags are static so verification is
// deterministic; this is a learning range, not a scored competition.
var Challenges = []Challenge{
	{
		ID: "xss", Title: "Reflected XSS", Category: "Cross-site scripting", Difficulty: "easy",
		Start: "/lab/xss?name=world",
		Brief: "The greeting reflects the name parameter straight into the page. Get your input to break out and inject an HTML element (for example an <img> with an onerror handler).",
		Hints: []string{
			"Try putting < and > in the name and view the page source. Are they encoded?",
			"Close nothing, just inject a tag: name=<img src=x onerror=alert(1)>",
			"Any input containing a working HTML/JS injection reveals the flag.",
		},
		Flag: "FLAG{reflected_xss_breakout}",
	},
	{
		ID: "sqli", Title: "SQL injection login bypass", Category: "SQL injection", Difficulty: "easy",
		Start: "/lab/login",
		Brief: "Log in as admin without knowing the password. The login builds a SQL query by pasting your input straight in.",
		Hints: []string{
			"What happens if the username contains a single quote?",
			"Make the WHERE clause always true and comment out the rest.",
			"Username: admin'-- (with a trailing space) and any password.",
		},
		Flag: "FLAG{sql_injection_auth_bypass}",
	},
	{
		ID: "idor", Title: "Insecure direct object reference", Category: "Access control", Difficulty: "easy",
		Start: "/lab/account?id=1",
		Brief: "You are user 1. Read another user's account. The id in the URL is trusted with no ownership check.",
		Hints: []string{
			"The id parameter maps directly to an account.",
			"Try changing id to a different number.",
			"The admin is id=2.",
		},
		Flag: "FLAG{idor_horizontal_access}",
	},
	{
		ID: "traversal", Title: "Path traversal", Category: "Path traversal", Difficulty: "medium",
		Start: "/lab/file?name=welcome.txt",
		Brief: "The file viewer serves files from a folder. Escape the folder and read the secret file stored at the server root as secret.txt.",
		Hints: []string{
			"The name is joined onto a directory path with no checks.",
			"Use ../ to climb out of the folder.",
			"name=../secret.txt",
		},
		Flag: "FLAG{path_traversal_escape}",
	},
	{
		ID: "cmdi", Title: "OS command injection", Category: "Command injection", Difficulty: "medium",
		Start: "/lab/ping?host=127.0.0.1",
		Brief: "The ping tool runs a shell command with your host value. Inject a second command.",
		Hints: []string{
			"The host is placed into a shell command line.",
			"Shell metacharacters like ; | && chain commands.",
			"host=127.0.0.1; id",
		},
		Flag: "FLAG{os_command_injection}",
	},
	{
		ID: "ssrf", Title: "Server-side request forgery", Category: "SSRF", Difficulty: "medium",
		Start: "/lab/fetch?url=https://example.com",
		Brief: "The fetcher downloads any URL you give it from the server. Make it request the internal-only endpoint at /lab/internal to read a secret the server trusts only itself to see.",
		Hints: []string{
			"The server makes the request, not your browser.",
			"Point url at the app's own internal path.",
			"url=http://127.0.0.1:PORT/lab/internal (use this server's port)",
		},
		Flag: "FLAG{ssrf_internal_access}",
	},
	{
		ID: "redirect", Title: "Open redirect", Category: "Open redirect", Difficulty: "easy",
		Start: "/lab/go?next=/home",
		Brief: "The redirector sends you wherever next points. Make it send a victim to an external site you control — the hallmark of an open redirect used in phishing.",
		Hints: []string{
			"next is used as the redirect target with no validation.",
			"Try an absolute URL instead of a path.",
			"next=https://evil.example/",
		},
		Flag: "FLAG{open_redirect_external}",
	},
	{
		ID: "ssti", Title: "Server-side template injection", Category: "Template injection", Difficulty: "medium",
		Start: "/lab/greet?name=friend",
		Brief: "The greeting is rendered through a server-side template. Inject template syntax that the engine evaluates, proving you control the template.",
		Hints: []string{
			"The name goes straight into a template string.",
			"Template engines evaluate {{ ... }}. Try a math expression.",
			"name={{7*7}} — if you see 49, the engine evaluated it.",
		},
		Flag: "FLAG{server_side_template_injection}",
	},
	{
		ID: "storedxss", Title: "Stored XSS", Category: "Cross-site scripting", Difficulty: "medium",
		Start: "/lab/guestbook",
		Brief: "The guestbook saves comments and shows them to every visitor without encoding. Store a comment that would run script in another visitor's browser.",
		Hints: []string{
			"POST a comment, then load the page and view the source.",
			"Your comment is rendered as raw HTML.",
			"Post a comment containing <script>alert(1)</script> or an <img onerror> payload.",
		},
		Flag: "FLAG{stored_xss_persisted}",
	},
	{
		ID: "jwt", Title: "JWT alg:none bypass", Category: "Authentication", Difficulty: "hard",
		Start: "/lab/portal",
		Brief: "The portal trusts a JWT in the token parameter but does not verify its signature. Forge a token that makes you an admin.",
		Hints: []string{
			"A JWT is three base64url parts: header.payload.signature.",
			"Set the header alg to \"none\" and drop the signature (leave it empty after the last dot).",
			"header {\"alg\":\"none\"} . payload {\"role\":\"admin\"} . (empty) — base64url-encode each part.",
		},
		Flag: "FLAG{jwt_alg_none_forgery}",
	},
}

// Handler returns the labs HTTP handler. selfBase is this server's own base URL
// (e.g. http://127.0.0.1:9000), used by the SSRF lab for same-origin fetches.
func Handler(selfBase string) http.Handler {
	mux := http.NewServeMux()
	byID := map[string]Challenge{}
	for _, c := range Challenges {
		byID[c.ID] = c
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/lab" && r.URL.Path != "/lab/" {
			http.NotFound(w, r)
			return
		}
		htmlCT(w)
		w.Write([]byte(indexPage(selfBase)))
	})

	// Verify a submitted flag.
	mux.HandleFunc("/lab/verify", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		flag := strings.TrimSpace(r.URL.Query().Get("flag"))
		c, ok := byID[id]
		w.Header().Set("Content-Type", "application/json")
		if ok && flag == c.Flag {
			fmt.Fprint(w, `{"solved":true,"message":"Correct — challenge solved."}`)
			return
		}
		fmt.Fprint(w, `{"solved":false,"message":"Not quite. Keep going."}`)
	})

	// Reflected XSS: reflects name; reveals the flag when input injects a tag.
	mux.HandleFunc("/lab/xss", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		htmlCT(w)
		flag := ""
		if looksLikeXSS(name) {
			flag = "<p>You injected executable markup. " + byID["xss"].Flag + "</p>"
		}
		fmt.Fprintf(w, "<html><body><h2>Hello %s</h2>%s</body></html>", name, flag)
	})

	// SQL injection login bypass against a simulated query.
	mux.HandleFunc("/lab/login", func(w http.ResponseWriter, r *http.Request) {
		htmlCT(w)
		if r.Method == "POST" {
			_ = r.ParseForm()
			user := r.PostFormValue("username")
			if sqlInjectsTrue(user) {
				fmt.Fprintf(w, "<html><body>Logged in as admin. %s</body></html>", byID["sqli"].Flag)
				return
			}
			fmt.Fprint(w, "<html><body>Invalid credentials. <a href=/lab/login>back</a></body></html>")
			return
		}
		fmt.Fprint(w, `<html><body><form method=post>
<input name=username placeholder=username> <input name=password type=password placeholder=password>
<button>Log in</button></form></body></html>`)
	})

	// IDOR: id maps to an account with no ownership check.
	mux.HandleFunc("/lab/account", func(w http.ResponseWriter, r *http.Request) {
		htmlCT(w)
		switch r.URL.Query().Get("id") {
		case "1", "":
			fmt.Fprint(w, "<html><body>Account 1 (you): balance $10</body></html>")
		case "2":
			fmt.Fprintf(w, "<html><body>Account 2 (admin): balance $999999. %s</body></html>", byID["idor"].Flag)
		default:
			fmt.Fprint(w, "<html><body>No such account</body></html>")
		}
	})

	// Path traversal: serves from a virtual folder; ../secret.txt escapes it.
	mux.HandleFunc("/lab/file", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		clean := strings.ReplaceAll(name, "\\", "/")
		if strings.Contains(clean, "../secret") || clean == "../secret.txt" {
			fmt.Fprintf(w, "secret.txt: %s", byID["traversal"].Flag)
			return
		}
		if clean == "welcome.txt" || clean == "" {
			fmt.Fprint(w, "welcome.txt: Welcome to the file viewer. Try reading other files.")
			return
		}
		fmt.Fprint(w, "file not found")
	})

	// Command injection: host is placed into a shell command (simulated).
	mux.HandleFunc("/lab/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if shellInjects(host) {
			fmt.Fprintf(w, "PING %s\nuid=0(root) gid=0(root)\n%s\n", host, byID["cmdi"].Flag)
			return
		}
		fmt.Fprintf(w, "PING %s: 64 bytes, time=0.1 ms\n", host)
	})

	// SSRF: fetches a URL server-side; reaching /lab/internal reveals the flag.
	mux.HandleFunc("/lab/fetch", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if strings.Contains(u, "/lab/internal") {
			fmt.Fprintf(w, "fetched internal endpoint:\n%s", byID["ssrf"].Flag)
			return
		}
		fmt.Fprintf(w, "fetched %s (nothing sensitive here)", u)
	})
	mux.HandleFunc("/lab/internal", func(w http.ResponseWriter, r *http.Request) {
		// "Internal only" by convention; the point is the fetcher reaches it.
		fmt.Fprint(w, "internal service: the secret is only meant for the server")
	})

	// Open redirect: next is used as the redirect target with no validation.
	mux.HandleFunc("/lab/go", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if isExternalURL(next) {
			htmlCT(w)
			fmt.Fprintf(w, "<html><body>Redirecting you off-site to %s — this is an open redirect. %s</body></html>",
				htmlEsc(next), byID["redirect"].Flag)
			return
		}
		htmlCT(w)
		fmt.Fprintf(w, "<html><body>Welcome back (would redirect to %s)</body></html>", htmlEsc(next))
	})

	// SSTI: the name is rendered through a (toy) template that evaluates {{a*b}}.
	mux.HandleFunc("/lab/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		rendered, evaluated := renderTemplate(name)
		htmlCT(w)
		flag := ""
		if evaluated {
			flag = " " + byID["ssti"].Flag
		}
		fmt.Fprintf(w, "<html><body>Hello %s%s</body></html>", rendered, flag)
	})

	// Stored XSS: comments are saved and shown to everyone without encoding.
	var gbMu sync.Mutex
	var guestbook []string
	mux.HandleFunc("/lab/guestbook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = r.ParseForm()
			c := r.PostFormValue("comment")
			gbMu.Lock()
			if len(guestbook) < 100 {
				guestbook = append(guestbook, c)
			}
			gbMu.Unlock()
			http.Redirect(w, r, "/lab/guestbook", http.StatusSeeOther)
			return
		}
		htmlCT(w)
		gbMu.Lock()
		stored := append([]string(nil), guestbook...)
		gbMu.Unlock()
		flag := ""
		for _, c := range stored {
			if looksLikeXSS(c) {
				flag = "<p>A stored comment contains executable markup that would run for every visitor. " + byID["storedxss"].Flag + "</p>"
				break
			}
		}
		fmt.Fprint(w, `<html><body><h2>Guestbook</h2><form method=post><input name=comment size=50><button>Post</button></form>`)
		for _, c := range stored {
			fmt.Fprintf(w, "<div class=comment>%s</div>", c) // intentionally unescaped
		}
		fmt.Fprint(w, flag+`</body></html>`)
	})

	// JWT alg:none: the portal trusts an unsigned token.
	mux.HandleFunc("/lab/portal", func(w http.ResponseWriter, r *http.Request) {
		htmlCT(w)
		tok := r.URL.Query().Get("token")
		if tok == "" {
			fmt.Fprint(w, `<html><body>Portal. Provide ?token=&lt;jwt&gt;. You are a guest.</body></html>`)
			return
		}
		if jwtIsAdminNone(tok) {
			fmt.Fprintf(w, "<html><body>Welcome, admin. %s</body></html>", byID["jwt"].Flag)
			return
		}
		fmt.Fprint(w, `<html><body>Token rejected or not admin.</body></html>`)
	})

	return mux
}

func htmlCT(w http.ResponseWriter) { w.Header().Set("Content-Type", "text/html") }

// looksLikeXSS reports whether input contains a working HTML/JS injection.
func looksLikeXSS(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "<script") ||
		strings.Contains(l, "onerror=") || strings.Contains(l, "onload=") ||
		(strings.Contains(l, "<img") && strings.Contains(l, "on")) ||
		strings.Contains(l, "<svg")
}

// sqlInjectsTrue reports whether a username is an auth-bypass injection.
func sqlInjectsTrue(user string) bool {
	l := strings.ToLower(user)
	if !strings.Contains(l, "'") {
		return false
	}
	return strings.Contains(l, "--") || strings.Contains(l, "or '1'='1") ||
		strings.Contains(l, "or 1=1") || strings.Contains(l, "or '1' = '1")
}

// shellInjects reports whether a value chains a shell command.
func shellInjects(s string) bool {
	return strings.ContainsAny(s, ";|&`") && strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz")
}

// isExternalURL reports whether next points off-site (absolute or scheme-relative).
func isExternalURL(next string) bool {
	l := strings.ToLower(strings.TrimSpace(next))
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "//")
}

var ttiExpr = regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`)

// renderTemplate is a toy template engine: it evaluates {{a*b}}. It returns the
// rendered string and whether any expression was actually evaluated.
func renderTemplate(name string) (string, bool) {
	evaluated := false
	out := ttiExpr.ReplaceAllStringFunc(name, func(m string) string {
		s := ttiExpr.FindStringSubmatch(m)
		a, _ := strconv.Atoi(s[1])
		b, _ := strconv.Atoi(s[2])
		evaluated = true
		return strconv.Itoa(a * b)
	})
	return out, evaluated
}

// jwtIsAdminNone reports whether tok is an unsigned (alg:none) JWT claiming an
// admin role — the classic signature-not-verified bypass.
func jwtIsAdminNone(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return false
	}
	dec := func(s string) string {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			if b2, e2 := base64.StdEncoding.DecodeString(s); e2 == nil {
				return string(b2)
			}
			return ""
		}
		return string(b)
	}
	header := strings.ToLower(dec(parts[0]))
	payload := strings.ToLower(dec(parts[1]))
	noneAlg := strings.Contains(header, `"alg":"none"`) || strings.Contains(header, `"alg": "none"`)
	admin := strings.Contains(payload, `"role":"admin"`) || strings.Contains(payload, `"role": "admin"`) ||
		strings.Contains(payload, `"admin":true`)
	return noneAlg && admin
}

func htmlEsc(s string) string { return html.EscapeString(s) }
