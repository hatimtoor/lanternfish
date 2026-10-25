package openapi

import "testing"

const samplePostman = `{
  "info": {"name":"demo","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item": [
    {"name":"search","request":{"method":"GET","header":[{"key":"X-Api-Key","value":"abc"}],
      "url":{"raw":"https://api.example.com/search?q=test","path":["search"],"query":[{"key":"q","value":"test"}]}}},
    {"name":"folder","item":[
      {"name":"create","request":{"method":"POST",
        "url":{"raw":"https://api.example.com/users","path":["users"]},
        "body":{"mode":"raw","raw":"{\"name\":\"bob\"}"}}}
    ]}
  ]
}`

func TestIsPostmanAndParse(t *testing.T) {
	if !IsPostman([]byte(samplePostman)) {
		t.Fatal("should detect a Postman collection")
	}
	ops, err := ParseAny([]byte(samplePostman))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(ops))
	}
	var get, post *Operation
	for i := range ops {
		switch ops[i].Method {
		case "GET":
			get = &ops[i]
		case "POST":
			post = &ops[i]
		}
	}
	if get == nil || get.Path != "/search" || get.Query["q"] != "test" || get.Headers["X-Api-Key"] != "abc" {
		t.Errorf("GET op wrong: %+v", get)
	}
	if post == nil || post.Path != "/users" || post.ContentType != "application/json" || post.Body == "" {
		t.Errorf("POST op wrong: %+v", post)
	}
}

func TestParseAnyStillHandlesOpenAPI(t *testing.T) {
	// A trivial OpenAPI 3 doc must still route to the OpenAPI parser.
	doc := `{"openapi":"3.0.0","paths":{"/ping":{"get":{}}}}`
	ops, err := ParseAny([]byte(doc))
	if err != nil || len(ops) != 1 || ops[0].Path != "/ping" {
		t.Errorf("OpenAPI routing broke: ops=%+v err=%v", ops, err)
	}
}
