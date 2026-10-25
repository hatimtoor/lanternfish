package openapi

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Postman collection (v2.x) models. Only the fields needed to reconstruct
// requests are decoded; everything else is ignored.
type pmCollection struct {
	Info struct {
		Schema string `json:"schema"`
		Name   string `json:"name"`
	} `json:"info"`
	Item []pmItem `json:"item"`
}

type pmItem struct {
	Name    string          `json:"name"`
	Item    []pmItem        `json:"item"` // folders nest items
	Request json.RawMessage `json:"request"`
}

type pmRequest struct {
	Method string          `json:"method"`
	Header []pmKV          `json:"header"`
	URL    json.RawMessage `json:"url"` // string or object
	Body   *struct {
		Mode       string `json:"mode"`
		Raw        string `json:"raw"`
		URLEncoded []pmKV `json:"urlencoded"`
	} `json:"body"`
}

type pmKV struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

type pmURLObj struct {
	Raw   string   `json:"raw"`
	Path  []string `json:"path"`
	Query []pmKV   `json:"query"`
}

// IsPostman reports whether data looks like a Postman collection.
func IsPostman(data []byte) bool {
	var probe struct {
		Info struct {
			Schema string `json:"schema"`
		} `json:"info"`
		Item json.RawMessage `json:"item"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return false
	}
	return len(probe.Item) > 0 && (strings.Contains(probe.Info.Schema, "getpostman.com") || strings.Contains(probe.Info.Schema, "schema.postman"))
}

// ParsePostman converts a Postman collection into operations the scanner can
// replay. Folders are walked recursively. Path params and {{variables}} are
// left as-is; supply concrete values with the base URL / environment if needed.
func ParsePostman(data []byte) ([]Operation, error) {
	var c pmCollection
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	var ops []Operation
	var walk func(items []pmItem)
	walk = func(items []pmItem) {
		for _, it := range items {
			if len(it.Item) > 0 {
				walk(it.Item)
			}
			if len(it.Request) == 0 {
				continue
			}
			if o, ok := postmanOp(it.Request); ok {
				ops = append(ops, o)
			}
		}
	}
	walk(c.Item)
	return ops, nil
}

func postmanOp(raw json.RawMessage) (Operation, bool) {
	var r pmRequest
	if err := json.Unmarshal(raw, &r); err != nil {
		return Operation{}, false
	}
	o := Operation{
		Method:  strings.ToUpper(firstNonBlank(r.Method, "GET")),
		Query:   map[string]string{},
		Headers: map[string]string{},
	}
	// URL: string or object.
	var path string
	if len(r.URL) > 0 {
		var s string
		if json.Unmarshal(r.URL, &s) == nil && s != "" {
			if u, err := url.Parse(s); err == nil {
				path = u.Path
				for k, vs := range u.Query() {
					if len(vs) > 0 {
						o.Query[k] = vs[0]
					}
				}
			} else {
				path = s
			}
		} else {
			var uo pmURLObj
			if json.Unmarshal(r.URL, &uo) == nil {
				if len(uo.Path) > 0 {
					path = "/" + strings.Join(uo.Path, "/")
				} else if uo.Raw != "" {
					if u, err := url.Parse(uo.Raw); err == nil {
						path = u.Path
					}
				}
				for _, q := range uo.Query {
					if !q.Disabled {
						o.Query[q.Key] = q.Value
					}
				}
			}
		}
	}
	if path == "" {
		path = "/"
	}
	o.Path = path
	for _, h := range r.Header {
		if !h.Disabled && h.Key != "" {
			o.Headers[h.Key] = h.Value
		}
	}
	if r.Body != nil {
		switch r.Body.Mode {
		case "raw":
			o.Body = r.Body.Raw
			if looksJSON(r.Body.Raw) {
				o.ContentType = "application/json"
			}
		case "urlencoded":
			form := url.Values{}
			for _, kv := range r.Body.URLEncoded {
				if !kv.Disabled {
					form.Set(kv.Key, kv.Value)
				}
			}
			o.Body = form.Encode()
			o.ContentType = "application/x-www-form-urlencoded"
		}
	}
	return o, true
}

func firstNonBlank(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func looksJSON(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

// ParseAny parses either an OpenAPI/Swagger document or a Postman collection,
// auto-detecting the format.
func ParseAny(data []byte) ([]Operation, error) {
	if IsPostman(data) {
		return ParsePostman(data)
	}
	return Parse(data)
}
