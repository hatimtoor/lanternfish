package macro

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMacroLoginFlow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "SESSION", Value: "sess-xyz", Path: "/"})
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("SESSION"); err != nil || c.Value != "sess-xyz" {
			w.WriteHeader(401)
			w.Write([]byte("no session"))
			return
		}
		w.Write([]byte(`{"csrf":"tok-42"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Run(context.Background(), Macro{
		Steps: []Step{
			{Method: "POST", URL: srv.URL + "/login", Body: "u=a&p=b"},
			{Method: "GET", URL: srv.URL + "/token"},
		},
		ExtractRegex: `"csrf":"([^"]+)"`,
		ExtractInto:  "X-CSRF-Token",
	}, false)

	if len(res.Steps) != 2 || res.Steps[0].Status != 200 || res.Steps[1].Status != 200 {
		t.Fatalf("steps wrong: %+v", res.Steps)
	}
	if res.Cookies == "" || res.Headers["Cookie"] == "" {
		t.Error("cookies should be carried into the session")
	}
	if res.Extracted != "tok-42" {
		t.Errorf("token extraction failed: %q", res.Extracted)
	}
	if res.Headers["X-CSRF-Token"] != "tok-42" {
		t.Error("extracted token should be set as the configured header")
	}
}
