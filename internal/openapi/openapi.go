// Package openapi turns an OpenAPI 3 or Swagger 2 specification into concrete
// HTTP operations the scanner can audit, so pointing Lanternfish at an API spec
// seeds every documented endpoint — the modern-app equivalent of crawling.
package openapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Operation is one documented API call, with sample values filled in so the
// endpoint responds and the scanner has insertion points to fuzz.
type Operation struct {
	Method      string
	Path        string            // path params filled with a sample
	Query       map[string]string // query params with sample values
	Headers     map[string]string // header params with sample values
	Body        string            // request body (JSON) when the operation takes one
	ContentType string
}

type spec struct {
	OpenAPI string                     `json:"openapi"`
	Swagger string                     `json:"swagger"`
	Paths   map[string]map[string]*op  `json:"paths"`
	Defs    map[string]json.RawMessage `json:"definitions"` // swagger 2 (unused refs tolerated)
}

type op struct {
	Parameters  []param `json:"parameters"`
	RequestBody *struct {
		Content map[string]struct {
			Schema schema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
}

type param struct {
	Name   string `json:"name"`
	In     string `json:"in"` // query | path | header | cookie | body (swagger)
	Schema schema `json:"schema"`
	Type   string `json:"type"` // swagger 2 inline type
}

type schema struct {
	Type       string            `json:"type"`
	Properties map[string]schema `json:"properties"`
}

var methods = []string{"get", "post", "put", "patch", "delete"}

// Parse reads an OpenAPI/Swagger JSON document and returns its operations.
func Parse(data []byte) ([]Operation, error) {
	var s spec
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	if s.OpenAPI == "" && s.Swagger == "" {
		return nil, fmt.Errorf("not an OpenAPI/Swagger document (no openapi/swagger version)")
	}
	var ops []Operation
	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		for _, m := range methods {
			o, ok := s.Paths[p][m]
			if !ok || o == nil {
				continue
			}
			ops = append(ops, buildOp(m, p, o))
		}
	}
	return ops, nil
}

func buildOp(method, path string, o *op) Operation {
	out := Operation{Method: strings.ToUpper(method), Path: path, Query: map[string]string{}, Headers: map[string]string{}}
	for _, pr := range o.Parameters {
		switch pr.In {
		case "query":
			out.Query[pr.Name] = scalarSample(pr.Schema.Type + pr.Type)
		case "header":
			out.Headers[pr.Name] = scalarSample(pr.Schema.Type + pr.Type)
		case "path":
			out.Path = strings.ReplaceAll(out.Path, "{"+pr.Name+"}", scalarSample(pr.Schema.Type+pr.Type))
		case "body": // swagger 2 body parameter
			if b := jsonSample(pr.Schema); b != "" {
				out.Body, out.ContentType = b, "application/json"
			}
		}
	}
	// OpenAPI 3 request body.
	if o.RequestBody != nil {
		if c, ok := o.RequestBody.Content["application/json"]; ok {
			out.Body, out.ContentType = jsonSample(c.Schema), "application/json"
		}
	}
	// Any remaining {placeholders} get a sample so the path is valid.
	for strings.Contains(out.Path, "{") {
		i := strings.IndexByte(out.Path, '{')
		j := strings.IndexByte(out.Path[i:], '}')
		if j < 0 {
			break
		}
		out.Path = out.Path[:i] + "1" + out.Path[i+j+1:]
	}
	return out
}

// scalarSample returns a benign sample value for a parameter type.
func scalarSample(t string) string {
	t = strings.ToLower(t)
	if strings.Contains(t, "int") || strings.Contains(t, "number") {
		return "1"
	}
	if strings.Contains(t, "bool") {
		return "true"
	}
	return "test"
}

// jsonSample builds a minimal JSON object matching a schema's properties.
func jsonSample(s schema) string {
	v := sampleValue(s, 0)
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func sampleValue(s schema, depth int) any {
	if depth > 4 {
		return "test"
	}
	switch strings.ToLower(s.Type) {
	case "object", "":
		if len(s.Properties) == 0 {
			return map[string]any{}
		}
		m := map[string]any{}
		for name, ps := range s.Properties {
			m[name] = sampleValue(ps, depth+1)
		}
		return m
	case "array":
		return []any{}
	case "integer", "number":
		return 1
	case "boolean":
		return true
	default:
		return "test"
	}
}
