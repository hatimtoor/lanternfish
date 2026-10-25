package checks

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

func gqlReq() *httpmsg.Request {
	u, _ := url.Parse("http://x/graphql")
	return &httpmsg.Request{Method: "POST", URL: u, Scheme: "http", Host: "x", Header: http.Header{}}
}

func TestGraphQLSuggestionsAndBatching(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		b := string(r.Body)
		var body string
		switch {
		case strings.HasPrefix(strings.TrimSpace(b), "["):
			body = `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`
		case strings.Contains(b, "__typenam"):
			body = `{"errors":[{"message":"Cannot query field \"__typenam\". Did you mean \"__typename\"?"}]}`
		default:
			body = `{"data":{}}` // introspection disabled
		}
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(body)}
	}}
	issues := (GraphQLIntrospection{}).Request(context.Background(), sender, gqlReq())
	var sawSug, sawBatch bool
	for _, is := range issues {
		if is.Check == "graphql-suggestions" {
			sawSug = true
		}
		if is.Check == "graphql-batching" {
			sawBatch = true
		}
	}
	if !sawSug {
		t.Errorf("expected graphql-suggestions, got %v", issues)
	}
	if !sawBatch {
		t.Errorf("expected graphql-batching, got %v", issues)
	}
}

func TestGraphQLNonEndpointSkipped(t *testing.T) {
	u, _ := url.Parse("http://x/api/users")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: http.Header{}}
	called := false
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		called = true
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("{}")}
	}}
	(GraphQLIntrospection{}).Request(context.Background(), sender, req)
	if called {
		t.Error("non-graphql path should not be probed")
	}
}
