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
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Challenge describes one practice exercise and its place in the curriculum.
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

	// Curriculum fields.
	OWASP     string // mapped OWASP Top 10 (2021) category
	Objective string // what you'll learn
	Solution  string // worked solution, revealed after (or on demand)
	Resource  string // a free place to learn more
}

// curriculum fills the learning fields for each challenge by id. Kept separate
// so the challenge definitions above stay focused on the exercise itself.
var curriculum = map[string]struct{ owasp, objective, solution, resource string }{
	"xss": {
		"A03:2021 Injection (XSS)",
		"Learn how unencoded output lets attacker HTML/JS run in a victim's browser, and why contextual output encoding is the fix.",
		"Set name to <img src=x onerror=alert(1)>. The handler runs because the value is written into the page without encoding < > and quotes.",
		"https://portswigger.net/web-security/cross-site-scripting",
	},
	"sqli": {
		"A03:2021 Injection (SQL)",
		"Learn how string-built SQL lets you change a query's meaning, and why parameterized queries stop it.",
		"Username: admin'--  (trailing space), any password. The quote closes the string and -- comments out the password check, so the WHERE matches admin.",
		"https://portswigger.net/web-security/sql-injection",
	},
	"idor": {
		"A01:2021 Broken Access Control",
		"Learn that trusting a client-supplied id without an ownership check lets you read other users' data.",
		"Change id=1 to id=2. The server never checks that the account belongs to you.",
		"https://portswigger.net/web-security/access-control/idor",
	},
	"traversal": {
		"A01:2021 Broken Access Control (Path Traversal)",
		"Learn how ../ sequences escape an intended directory to read arbitrary files, and why paths must be validated.",
		"Set name=../secret.txt to climb out of the serving folder and read the secret at the root.",
		"https://portswigger.net/web-security/file-path-traversal",
	},
	"cmdi": {
		"A03:2021 Injection (OS Command)",
		"Learn how user input reaching a shell lets you append your own commands, and why you must never build shell strings from input.",
		"Set host=127.0.0.1; id — the ; chains a second command the shell runs.",
		"https://portswigger.net/web-security/os-command-injection",
	},
	"ssrf": {
		"A10:2021 Server-Side Request Forgery",
		"Learn how a server fetching a user-supplied URL can be made to reach internal-only systems.",
		"Point url at the app's own internal path, e.g. url=http://127.0.0.1:PORT/lab/internal (use this server's port).",
		"https://portswigger.net/web-security/ssrf",
	},
	"redirect": {
		"A01:2021 Broken Access Control (Open Redirect)",
		"Learn how an unvalidated redirect target powers convincing phishing from a trusted domain.",
		"Set next=https://evil.example/ — the app redirects anywhere, so a link on the trusted site sends victims off-site.",
		"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
	},
	"ssti": {
		"A03:2021 Injection (Template)",
		"Learn how input rendered as a template gets evaluated by the engine, which can reach code execution.",
		"Set name={{7*7}} and look for 49 — proof the template engine evaluated your expression.",
		"https://portswigger.net/web-security/server-side-template-injection",
	},
	"storedxss": {
		"A03:2021 Injection (Stored XSS)",
		"Learn how input saved and shown to others without encoding runs for every visitor — more dangerous than reflected XSS.",
		"Post a comment containing <script>alert(1)</script> (or <img src=x onerror=alert(1)>), then load the page.",
		"https://portswigger.net/web-security/cross-site-scripting/stored",
	},
	"jwt": {
		"A07:2021 Identification and Authentication Failures",
		"Learn how a JWT whose signature isn't verified can be forged to impersonate anyone.",
		"Base64url-encode header {\"alg\":\"none\"} and payload {\"role\":\"admin\"}, join with a dot and a trailing dot (empty signature): <header>.<payload>. — pass it as token.",
		"https://portswigger.net/web-security/jwt",
	},
	"cors": {
		"A05:2021 Security Misconfiguration",
		"Learn why reflecting the Origin header while allowing credentials breaks the same-origin policy and lets a malicious site read authenticated responses.",
		"Send Origin: https://evil.example. The response echoes it in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true, so script on evil.example can read the logged-in response.",
		"https://portswigger.net/web-security/cors",
	},
	"graphql": {
		"A05:2021 Security Misconfiguration",
		"Learn how leaving GraphQL introspection enabled hands attackers the full schema to map the API.",
		"Query {__schema{types{name fields{name}}}} to dump the schema, discover the 'secret' field, then query {secret}.",
		"https://portswigger.net/web-security/graphql",
	},
}

func init() {
	for i := range Challenges {
		if c, ok := curriculum[Challenges[i].ID]; ok {
			Challenges[i].OWASP = c.owasp
			Challenges[i].Objective = c.objective
			Challenges[i].Solution = c.solution
			Challenges[i].Resource = c.resource
		}
	}
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
	{
		ID: "cors", Title: "CORS misconfiguration", Category: "CORS", Difficulty: "medium",
		Start: "/lab/api/me",
		Brief: "The API reflects whatever Origin you send and allows credentials, so a malicious site can read a logged-in user's data cross-origin. Send a request with an attacker Origin header and read the authorized response.",
		Hints: []string{
			"Add an Origin header pointing at a site you control, e.g. Origin: https://evil.example",
			"Watch the response Access-Control-Allow-Origin: it echoes your origin, and Allow-Credentials is true.",
			"That combination lets script on your origin read this response with the victim's cookies.",
		},
		Flag: "FLAG{cors_origin_reflected_with_credentials}",
	},
	{
		ID: "graphql", Title: "GraphQL introspection", Category: "API", Difficulty: "easy",
		Start: "/lab/graphql?query={__typename}",
		Brief: "The GraphQL endpoint left introspection enabled. Query the schema to discover the hidden field, then read it.",
		Hints: []string{
			"Send query={__schema{types{name fields{name}}}} to dump the schema.",
			"Introspection reveals a field named secret on the Query type.",
			"Then request query={secret} to read it.",
		},
		Flag: "FLAG{graphql_introspection_schema_dump}",
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

	// CORS: reflects any Origin with credentials; reveals the flag when an
	// attacker origin is reflected (what a cross-origin read would expose).
	mux.HandleFunc("/lab/api/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		origin := r.Header.Get("Origin")
		body := `{"user":"you","email":"you@example.com"}`
		if origin != "" && !strings.Contains(origin, "127.0.0.1") && !strings.Contains(origin, "localhost") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			body = `{"user":"you","email":"you@example.com","note":"A page at ` + origin + ` could read this with your cookies. ` + byID["cors"].Flag + `"}`
		}
		fmt.Fprint(w, body)
	})

	// GraphQL: introspection enabled; a schema dump or reading the hidden field
	// reveals the flag.
	mux.HandleFunc("/lab/graphql", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if q == "" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			q = string(body)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "__schema"):
			fmt.Fprintf(w, `{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"__typename"},{"name":"secret"}]}]}}}`)
		case strings.Contains(q, "secret"):
			fmt.Fprintf(w, `{"data":{"secret":"%s"}}`, byID["graphql"].Flag)
		default:
			fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
		}
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
