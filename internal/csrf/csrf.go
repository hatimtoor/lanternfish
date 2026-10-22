// Package csrf generates a cross-site request forgery proof-of-concept HTML
// page for a given request, the equivalent of Burp's CSRF PoC generator.
package csrf

import (
	"fmt"
	"html"
	"net/url"
	"strings"
)

// Generate returns a self-contained HTML page that reproduces the request from
// an attacker's origin. Form-encoded requests produce an auto-submitting form;
// other content types produce a fetch() PoC.
func Generate(method, rawURL, contentType, body string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	ct := strings.ToLower(contentType)
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html>\n<body>\n")
	b.WriteString("<!-- Lanternfish CSRF proof-of-concept. Open in a browser while authenticated to the target. -->\n")

	switch {
	case method == "GET":
		b.WriteString(fmt.Sprintf("<form action=%q method=\"GET\">\n", attrURLBase(rawURL)))
		for k, v := range queryValues(rawURL) {
			b.WriteString(hiddenField(k, v))
		}
		b.WriteString("<input type=\"submit\" value=\"Submit\">\n</form>\n")
	case strings.Contains(ct, "x-www-form-urlencoded"):
		b.WriteString(fmt.Sprintf("<form action=%q method=\"POST\">\n", html.EscapeString(rawURL)))
		if vals, err := url.ParseQuery(body); err == nil {
			for k, vs := range vals {
				for _, v := range vs {
					b.WriteString(hiddenField(k, v))
				}
			}
		}
		b.WriteString("<input type=\"submit\" value=\"Submit\">\n</form>\n")
		b.WriteString("<script>document.forms[0].submit();</script>\n")
	default:
		// JSON or other body: use fetch with credentials.
		b.WriteString("<script>\nfetch(")
		b.WriteString(jsString(rawURL))
		b.WriteString(", {\n  method: ")
		b.WriteString(jsString(method))
		b.WriteString(",\n  credentials: 'include',\n  headers: {'Content-Type': ")
		b.WriteString(jsString(contentType))
		b.WriteString("},\n  body: ")
		b.WriteString(jsString(body))
		b.WriteString("\n});\n</script>\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

func hiddenField(k, v string) string {
	return fmt.Sprintf("<input type=\"hidden\" name=%q value=%q>\n", html.EscapeString(k), html.EscapeString(v))
}

func attrURLBase(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		u.RawQuery = ""
		return html.EscapeString(u.String())
	}
	return html.EscapeString(rawURL)
}

func queryValues(rawURL string) map[string]string {
	out := map[string]string{}
	if u, err := url.Parse(rawURL); err == nil {
		for k, vs := range u.Query() {
			if len(vs) > 0 {
				out[k] = vs[0]
			}
		}
	}
	return out
}

// jsString produces a safe single-quoted JS string literal.
func jsString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`, "<", `\x3c`, ">", `\x3e`)
	return "'" + r.Replace(s) + "'"
}
