package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBrowserLoginCapturesSessionCookie(t *testing.T) {
	if !Available() {
		t.Skip("no Chromium-family browser available")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			if r.FormValue("username") == "alice" && r.FormValue("password") == "s3cret" {
				http.SetCookie(w, &http.Cookie{Name: "lfsession", Value: "loggedin-token", Path: "/"})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			w.Write([]byte("bad creds"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
<form method="POST" action="/login">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Log in</button>
</form></body></html>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("home")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cookies, err := Login(Creds{LoginURL: srv.URL + "/login", User: "alice", Pass: "s3cret"}, 2*time.Second)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	var found bool
	for _, c := range cookies {
		if c.Name == "lfsession" && c.Value == "loggedin-token" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected lfsession cookie after login, got %+v", cookies)
	}
}
