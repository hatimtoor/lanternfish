// Package decoder implements Lanternfish's Decoder tool: reversible transforms
// (base64, URL, hex, HTML, ASCII-hex) plus one-way hashes and a best-effort
// smart decode, the equivalent of Burp's Decoder.
package decoder

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// Ops lists the supported operation names.
var Ops = []string{
	"base64-encode", "base64-decode",
	"url-encode", "url-decode",
	"hex-encode", "hex-decode",
	"html-encode", "html-decode",
	"ascii-hex-encode", "ascii-hex-decode",
	"md5", "sha1", "sha256",
	"smart-decode",
}

// Transform applies op to input and returns the result or an error.
func Transform(input, op string) (string, error) {
	switch op {
	case "base64-encode":
		return base64.StdEncoding.EncodeToString([]byte(input)), nil
	case "base64-decode":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
		if err != nil {
			// tolerate URL-safe / unpadded variants
			if b2, e2 := base64.RawURLEncoding.DecodeString(strings.TrimSpace(input)); e2 == nil {
				return string(b2), nil
			}
			return "", err
		}
		return string(b), nil
	case "url-encode":
		return url.QueryEscape(input), nil
	case "url-decode":
		s, err := url.QueryUnescape(input)
		return s, err
	case "hex-encode":
		return hex.EncodeToString([]byte(input)), nil
	case "hex-decode":
		b, err := hex.DecodeString(strings.TrimSpace(input))
		return string(b), err
	case "html-encode":
		return html.EscapeString(input), nil
	case "html-decode":
		return html.UnescapeString(input), nil
	case "ascii-hex-encode":
		var sb strings.Builder
		for _, c := range []byte(input) {
			fmt.Fprintf(&sb, "%02x", c)
		}
		return sb.String(), nil
	case "ascii-hex-decode":
		b, err := hex.DecodeString(strings.TrimSpace(input))
		return string(b), err
	case "md5":
		return fmt.Sprintf("%x", md5.Sum([]byte(input))), nil
	case "sha1":
		return fmt.Sprintf("%x", sha1.Sum([]byte(input))), nil
	case "sha256":
		return fmt.Sprintf("%x", sha256.Sum256([]byte(input))), nil
	case "smart-decode":
		return smartDecode(input), nil
	default:
		return "", fmt.Errorf("unknown operation %q", op)
	}
}

var (
	looksURLEncoded = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	looksHex        = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	looksBase64     = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	looksHTML       = regexp.MustCompile(`&(#\d+|#x[0-9A-Fa-f]+|\w+);`)
)

// smartDecode guesses the encoding and decodes one layer.
func smartDecode(input string) string {
	s := strings.TrimSpace(input)
	switch {
	case looksURLEncoded.MatchString(s):
		if d, err := url.QueryUnescape(s); err == nil {
			return d
		}
	case looksHTML.MatchString(s):
		return html.UnescapeString(s)
	case len(s) >= 8 && len(s)%2 == 0 && looksHex.MatchString(s):
		if b, err := hex.DecodeString(s); err == nil && isMostlyPrintable(b) {
			return string(b)
		}
	case len(s) >= 8 && looksBase64.MatchString(s):
		if b, err := base64.StdEncoding.DecodeString(s); err == nil && isMostlyPrintable(b) {
			return string(b)
		}
	}
	return input
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*100/len(b) >= 85
}
