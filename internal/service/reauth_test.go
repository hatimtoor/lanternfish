package service

import (
	"net/http"
	"testing"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/session"
)

func resp(status int, loc, body string) *httpmsg.Response {
	h := http.Header{}
	if loc != "" {
		h.Set("Location", loc)
	}
	return &httpmsg.Response{StatusCode: status, Header: h, Body: []byte(body)}
}

func TestLooksLoggedOut(t *testing.T) {
	cases := []struct {
		name string
		r    *httpmsg.Response
		want bool
	}{
		{"401", resp(401, "", "nope"), true},
		{"403", resp(403, "", "forbidden"), true},
		{"redirect-to-login", resp(302, "https://x/login?next=/a", ""), true},
		{"login-form-200", resp(200, "", `<form>Please sign in <input type="password"></form>`), true},
		{"normal-200", resp(200, "", "<h1>Dashboard</h1> welcome back"), false},
		{"redirect-elsewhere", resp(302, "https://x/home", ""), false},
	}
	for _, c := range cases {
		if got := looksLoggedOut(c.r); got != c.want {
			t.Errorf("%s: looksLoggedOut = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMaybeReauthCooldownAndGating(t *testing.T) {
	svc := New(session.New(), false)
	n := 0
	svc.SetReauth(func() error { n++; return nil })

	if !svc.maybeReauth(resp(401, "", "")) {
		t.Fatal("first logged-out response should re-auth")
	}
	if n != 1 {
		t.Fatalf("reauth count = %d, want 1", n)
	}
	// Immediately again: cooldown must block it.
	if svc.maybeReauth(resp(401, "", "")) || n != 1 {
		t.Errorf("second call within cooldown should not re-auth (n=%d)", n)
	}
	// A healthy response never re-auths.
	svc2 := New(session.New(), false)
	m := 0
	svc2.SetReauth(func() error { m++; return nil })
	if svc2.maybeReauth(resp(200, "", "ok")) || m != 0 {
		t.Errorf("healthy response should not re-auth (m=%d)", m)
	}
	// No reauth configured: never fires.
	svc3 := New(session.New(), false)
	if svc3.maybeReauth(resp(401, "", "")) {
		t.Error("no reauth configured should not fire")
	}
}
