package scan

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"lanternfish/internal/httpmsg"
)

// This file derives the richer insertion points that bring Lanternfish in line with
// Burp's fuzzable-input taxonomy (confirmed from the shipped Montoya API
// AuditInsertionPointType): JSON body values, cookies, selected headers, and
// URL path segments. The engine runs every active check against every point,
// so these builders widen the reach of all active checks at once. The logic is
// an independent, clean-room implementation — no Burp code is used.

// maxJSONPoints bounds how many JSON leaves a single request contributes, so a
// large document cannot explode the active-scan request count.
const maxJSONPoints = 60

// jsonPoints yields one insertion point per scalar leaf in a JSON body.
func jsonPoints(base *httpmsg.Request) []InsertionPoint {
	ct := strings.ToLower(base.Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") || len(base.Body) == 0 {
		return nil
	}
	var root any
	if err := json.Unmarshal(base.Body, &root); err != nil {
		return nil
	}
	var pts []InsertionPoint
	var walk func(v any, addr []any, name string)
	walk = func(v any, addr []any, name string) {
		if len(pts) >= maxJSONPoints {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				walk(child, appendAddr(addr, k), k)
			}
		case []any:
			for i, child := range t {
				walk(child, appendAddr(addr, i), name+"["+strconv.Itoa(i)+"]")
			}
		default: // scalar: string, float64, bool, or nil
			leaf := append([]any(nil), addr...)
			ptName := name
			if ptName == "" {
				ptName = "json"
			}
			pts = append(pts, InsertionPoint{
				Kind: KindJSON, Name: ptName, Base: scalarToString(t),
				build: func(value string) *httpmsg.Request {
					c := base.Clone()
					var r any
					if json.Unmarshal(base.Body, &r) != nil {
						return c
					}
					if setJSONAddr(&r, leaf, value) {
						if b, err := json.Marshal(r); err == nil {
							c.Body = b
						}
					}
					return c
				},
			})
		}
	}
	walk(root, nil, "")
	return pts
}

func appendAddr(a []any, step any) []any {
	out := make([]any, len(a)+1)
	copy(out, a)
	out[len(a)] = step
	return out
}

// setJSONAddr sets the scalar at addr within *r to value (as a string),
// returning whether it succeeded.
func setJSONAddr(r *any, addr []any, value string) bool {
	if len(addr) == 0 {
		*r = value
		return true
	}
	cur := *r
	for i := 0; i < len(addr)-1; i++ {
		switch step := addr[i].(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return false
			}
			cur = m[step]
		case int:
			s, ok := cur.([]any)
			if !ok || step < 0 || step >= len(s) {
				return false
			}
			cur = s[step]
		}
	}
	switch last := addr[len(addr)-1].(type) {
	case string:
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		m[last] = value
	case int:
		s, ok := cur.([]any)
		if !ok || last < 0 || last >= len(s) {
			return false
		}
		s[last] = value
	}
	return true
}

func scalarToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return ""
	}
}

// cookiePoints yields one insertion point per cookie in the Cookie header.
func cookiePoints(base *httpmsg.Request) []InsertionPoint {
	raw := base.Header.Get("Cookie")
	if raw == "" {
		return nil
	}
	type kv struct{ name, val string }
	var cookies []kv
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		cookies = append(cookies, kv{strings.TrimSpace(name), val})
	}
	var pts []InsertionPoint
	for idx, c := range cookies {
		idx, name, orig := idx, c.name, c.val
		pts = append(pts, InsertionPoint{
			Kind: KindCookie, Name: name, Base: orig,
			build: func(value string) *httpmsg.Request {
				nc := base.Clone()
				var b strings.Builder
				for i, ck := range cookies {
					if i > 0 {
						b.WriteString("; ")
					}
					b.WriteString(ck.name)
					b.WriteByte('=')
					if i == idx {
						b.WriteString(value)
					} else {
						b.WriteString(ck.val)
					}
				}
				nc.Header.Set("Cookie", b.String())
				return nc
			},
		})
	}
	return pts
}

// fuzzableHeaders are request headers worth fuzzing when present: they are
// commonly reflected, trusted, or used in backend lookups. Fuzzing is limited
// to this curated set to keep the request count and noise bounded.
var fuzzableHeaders = []string{
	"User-Agent", "Referer", "Origin", "X-Forwarded-For", "X-Forwarded-Host",
	"X-Real-IP", "True-Client-IP", "X-Client-IP", "Forwarded", "X-Api-Version",
}

// skipHeaders are structural, transport, or auth headers that must not be
// fuzzed (mutating them breaks the request or the session rather than testing
// the app). Any other present header is a candidate — custom/application
// headers are a real injection vector.
var skipHeaders = map[string]bool{
	"host": true, "content-length": true, "content-type": true, "connection": true,
	"transfer-encoding": true, "accept": true, "accept-encoding": true, "accept-language": true,
	"accept-charset": true, "cookie": true, "authorization": true, "proxy-authorization": true,
	"upgrade": true, "cache-control": true, "pragma": true, "date": true, "range": true,
	"expect": true, "te": true, "trailer": true,
}

// maxHeaderPoints bounds how many headers one request contributes.
const maxHeaderPoints = 12

// headerPoints yields insertion points for the curated headers and for any
// other non-structural header present on the request (custom application
// headers are a real injection vector, as scanner benchmarks show).
func headerPoints(base *httpmsg.Request) []InsertionPoint {
	var pts []InsertionPoint
	seen := map[string]bool{}
	add := func(name, orig string) {
		if orig == "" || seen[strings.ToLower(name)] || len(pts) >= maxHeaderPoints {
			return
		}
		seen[strings.ToLower(name)] = true
		pts = append(pts, InsertionPoint{
			Kind: KindHeader, Name: name, Base: orig,
			build: func(value string) *httpmsg.Request {
				c := base.Clone()
				c.Header.Set(name, value)
				return c
			},
		})
	}
	for _, h := range fuzzableHeaders {
		add(h, base.Header.Get(h))
	}
	// Any other present, non-structural header (e.g. a custom X-* or an
	// application-specific header).
	for name, vals := range base.Header {
		if skipHeaders[strings.ToLower(name)] {
			continue
		}
		add(name, firstOr(vals, ""))
	}
	return pts
}

// pathPoints yields one insertion point per non-empty URL path segment. The
// last segment is the filename (URL_PATH_FILENAME); the rest are folders
// (URL_PATH_FOLDER). Payloads are inserted into the raw path so traversal
// sequences survive.
func pathPoints(base *httpmsg.Request) []InsertionPoint {
	if base.URL == nil {
		return nil
	}
	path := base.URL.EscapedPath()
	if path == "" || path == "/" {
		return nil
	}
	trimmed := strings.Trim(path, "/")
	segs := strings.Split(trimmed, "/")
	if len(segs) == 0 {
		return nil
	}
	leadSlash := strings.HasPrefix(path, "/")
	trailSlash := strings.HasSuffix(path, "/")
	var pts []InsertionPoint
	for i := range segs {
		if segs[i] == "" {
			continue
		}
		idx := i
		name := "path[" + strconv.Itoa(i) + "]"
		pts = append(pts, InsertionPoint{
			Kind: KindPath, Name: name, Base: segs[idx],
			build: func(value string) *httpmsg.Request {
				c := base.Clone()
				parts := append([]string(nil), segs...)
				parts[idx] = value
				np := strings.Join(parts, "/")
				if leadSlash {
					np = "/" + np
				}
				if trailSlash {
					np += "/"
				}
				c.URL.Path = rawToPath(np)
				c.URL.RawPath = np
				return c
			},
		})
	}
	return pts
}

// rawToPath returns a best-effort decoded path for the URL.Path field while the
// verbatim payload lives in RawPath. If decoding fails, the raw form is used.
func rawToPath(raw string) string {
	if dec, err := url.PathUnescape(raw); err == nil {
		return dec
	}
	return raw
}

// maxXMLPoints / maxMultipartPoints bound how many points a single XML or
// multipart body contributes, mirroring the JSON cap.
const (
	maxXMLPoints       = 60
	maxMultipartPoints = 40
)

var (
	xmlTextRe = regexp.MustCompile(`>([^<>&]+)<`)           // text between tags
	xmlAttrRe = regexp.MustCompile(`([\w:.-]+)="([^"<]*)"`) // attr="value"
)

// xmlPoints yields insertion points for element text and attribute values in an
// XML body. Mutations splice the raw bytes at exact match offsets, so repeated
// values and document structure are preserved without re-serializing the XML.
func xmlPoints(base *httpmsg.Request) []InsertionPoint {
	ct := strings.ToLower(base.Header.Get("Content-Type"))
	if !strings.Contains(ct, "xml") || len(base.Body) == 0 {
		return nil
	}
	body := base.Body
	var pts []InsertionPoint

	// Element text nodes.
	for _, m := range xmlTextRe.FindAllSubmatchIndex(body, -1) {
		if len(pts) >= maxXMLPoints {
			break
		}
		vs, ve := m[2], m[3] // the captured text range
		text := strings.TrimSpace(string(body[vs:ve]))
		if text == "" {
			continue
		}
		s0, e0 := vs, ve
		pts = append(pts, spliceXMLPoint(base, "xml-text", text, s0, e0))
	}
	// Attribute values.
	for _, m := range xmlAttrRe.FindAllSubmatchIndex(body, -1) {
		if len(pts) >= maxXMLPoints {
			break
		}
		name := string(body[m[2]:m[3]])
		vs, ve := m[4], m[5]
		pts = append(pts, spliceXMLPoint(base, name, string(body[vs:ve]), vs, ve))
	}
	return pts
}

// spliceXMLPoint builds an XML insertion point that replaces bytes [s0,e0) of
// the original body with a payload (minimally XML-escaped).
func spliceXMLPoint(base *httpmsg.Request, name, orig string, s0, e0 int) InsertionPoint {
	body := append([]byte(nil), base.Body...)
	return InsertionPoint{
		Kind: KindXML, Name: name, Base: orig,
		build: func(value string) *httpmsg.Request {
			c := base.Clone()
			esc := xmlEscape(value)
			nb := make([]byte, 0, len(body)-(e0-s0)+len(esc))
			nb = append(nb, body[:s0]...)
			nb = append(nb, esc...)
			nb = append(nb, body[e0:]...)
			c.Body = nb
			return c
		},
	}
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// multipartPoints yields one insertion point per form field value in a
// multipart/form-data body. The body is re-encoded with the target field
// replaced, preserving the other fields and the boundary.
func multipartPoints(base *httpmsg.Request) []InsertionPoint {
	ct := base.Header.Get("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "multipart/form-data" || params["boundary"] == "" || len(base.Body) == 0 {
		return nil
	}
	boundary := params["boundary"]

	type field struct {
		name, val string
		filename  string
		ctype     string
	}
	var fields []field
	mr := multipart.NewReader(bytes.NewReader(base.Body), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		val, _ := io.ReadAll(io.LimitReader(part, 1<<20))
		fields = append(fields, field{
			name: part.FormName(), val: string(val),
			filename: part.FileName(), ctype: part.Header.Get("Content-Type"),
		})
		part.Close()
		if len(fields) >= maxMultipartPoints {
			break
		}
	}

	var pts []InsertionPoint
	for idx, f := range fields {
		if f.filename != "" || f.name == "" {
			continue // skip file parts and unnamed parts
		}
		idx, name, orig := idx, f.name, f.val
		pts = append(pts, InsertionPoint{
			Kind: KindMultipart, Name: name, Base: orig,
			build: func(value string) *httpmsg.Request {
				c := base.Clone()
				var buf bytes.Buffer
				mw := multipart.NewWriter(&buf)
				_ = mw.SetBoundary(boundary)
				for i, ff := range fields {
					v := ff.val
					if i == idx {
						v = value
					}
					_ = mw.WriteField(ff.name, v)
				}
				mw.Close()
				c.Body = buf.Bytes()
				c.Header.Set("Content-Type", mw.FormDataContentType())
				return c
			},
		})
	}
	return pts
}

// paramNamePoints yields points that fuzz the *name* of each query and form
// parameter (Burp PARAM_NAME_URL / PARAM_NAME_BODY), keeping the value. It has
// its own kind so wait-heavy checks skip it.
func paramNamePoints(base *httpmsg.Request) []InsertionPoint {
	var pts []InsertionPoint
	if base.URL != nil {
		q := base.URL.Query()
		for name, vals := range q {
			name, val := name, firstOr(vals, "")
			pts = append(pts, InsertionPoint{
				Kind: KindParamName, Name: name, Base: name,
				build: func(value string) *httpmsg.Request {
					c := base.Clone()
					nq := c.URL.Query()
					nq.Del(name)
					nq.Set(value, val)
					c.URL.RawQuery = nq.Encode()
					return c
				},
			})
		}
	}
	if ct := base.Header.Get("Content-Type"); isFormURLEncoded(ct) && len(base.Body) > 0 {
		if form, err := url.ParseQuery(string(base.Body)); err == nil {
			for name, vals := range form {
				name, val := name, firstOr(vals, "")
				pts = append(pts, InsertionPoint{
					Kind: KindParamName, Name: name, Base: name,
					build: func(value string) *httpmsg.Request {
						c := base.Clone()
						nf, _ := url.ParseQuery(string(c.Body))
						nf.Del(name)
						nf.Set(value, val)
						c.Body = []byte(nf.Encode())
						return c
					},
				})
			}
		}
	}
	return pts
}
