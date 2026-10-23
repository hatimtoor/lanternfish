package openapi

import (
	"strings"
	"testing"
)

func TestParseOpenAPI3(t *testing.T) {
	spec := `{
      "openapi": "3.0.0",
      "paths": {
        "/users/{id}": {"get": {"parameters": [{"name":"id","in":"path","schema":{"type":"integer"}}]}},
        "/search": {"get": {"parameters": [{"name":"q","in":"query","schema":{"type":"string"}}]}},
        "/profile": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type":"object","properties":{"name":{"type":"string"},"age":{"type":"integer"}}}}}}}}
      }
    }`
	ops, err := Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("want 3 operations, got %d", len(ops))
	}
	byPath := map[string]Operation{}
	for _, o := range ops {
		byPath[o.Method+" "+o.Path] = o
	}
	if _, ok := byPath["GET /users/1"]; !ok {
		t.Fatalf("path param not filled: %v", byPath)
	}
	if byPath["GET /search"].Query["q"] == "" {
		t.Fatal("query sample not set")
	}
	prof := byPath["POST /profile"]
	if prof.ContentType != "application/json" || !strings.Contains(prof.Body, `"name"`) {
		t.Fatalf("json body sample wrong: %q", prof.Body)
	}
}

func TestParseRejectsNonSpec(t *testing.T) {
	if _, err := Parse([]byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("should reject a non-OpenAPI document")
	}
}
