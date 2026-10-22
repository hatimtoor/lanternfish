package session

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// waitHeld polls until exactly one request is held, returning its id (0 if the
// deadline passes).
func waitHeld(ic *Intercept) int64 {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if p := ic.List(); len(p) == 1 {
			return p[0].ID
		}
		time.Sleep(2 * time.Millisecond)
	}
	return 0
}

func mkReq(method, rawurl string) *httpmsg.Request {
	u, _ := url.Parse(rawurl)
	return &httpmsg.Request{Method: method, URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
}

func mkTx(method, rawurl string, status int) *httpmsg.Transaction {
	return &httpmsg.Transaction{
		Request:  mkReq(method, rawurl),
		Response: &httpmsg.Response{StatusCode: status, Header: http.Header{}, Body: []byte("x")},
	}
}

func TestHistoryAssignsIDsAndOrders(t *testing.T) {
	s := New()
	for i := 0; i < 5; i++ {
		s.Add(SourceProxy, mkTx("GET", "http://h/p", 200))
	}
	h := s.History(0)
	if len(h) != 5 {
		t.Fatalf("want 5, got %d", len(h))
	}
	if h[0].ID != 5 || h[4].ID != 1 {
		t.Errorf("history should be newest-first with sequential ids, got %d..%d", h[0].ID, h[4].ID)
	}
	if s.Get(3) == nil || s.Get(99) != nil {
		t.Error("Get by id broken")
	}
	if got := s.History(2); len(got) != 2 {
		t.Errorf("limit ignored: %d", len(got))
	}
}

func TestConcurrentAddAndRead(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Add(SourceProxy, mkTx("GET", "http://h/p", 200))
			_ = s.History(10)
			_ = s.SiteMap()
			_ = s.Stats()
		}()
	}
	wg.Wait()
	if len(s.History(0)) != 50 {
		t.Errorf("lost records under concurrency: %d", len(s.History(0)))
	}
}

func TestSiteMap(t *testing.T) {
	s := New()
	s.Add(SourceProxy, mkTx("GET", "http://a.test/one", 200))
	s.Add(SourceProxy, mkTx("POST", "http://a.test/two", 404))
	s.Add(SourceProxy, mkTx("GET", "https://b.test/x", 500))
	m := s.SiteMap()
	if len(m) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(m))
	}
	if m["http://a.test"] == nil || len(m["http://a.test"].Paths) != 2 {
		t.Errorf("a.test paths wrong: %+v", m["http://a.test"])
	}
}

func TestInterceptForwardModified(t *testing.T) {
	ic := newIntercept()
	ic.SetEnabled(true)
	orig := mkReq("GET", "http://h/a")
	done := make(chan *httpmsg.Request, 1)
	go func() {
		send, drop := ic.Hold(orig)
		if drop {
			done <- nil
			return
		}
		done <- send
	}()
	id := waitHeld(ic)
	if id == 0 {
		t.Fatal("request never held")
	}
	mod := mkReq("GET", "http://h/b")
	if !ic.Forward(id, mod) {
		t.Fatal("forward failed")
	}
	got := <-done
	if got == nil || got.URL.Path != "/b" {
		t.Errorf("forward did not deliver modified request: %+v", got)
	}
}

func TestInterceptDropAndDisable(t *testing.T) {
	ic := newIntercept()
	ic.SetEnabled(true)
	res := make(chan bool, 1)
	go func() {
		_, drop := ic.Hold(mkReq("GET", "http://h/a"))
		res <- drop
	}()
	id := waitHeld(ic)
	if id == 0 {
		t.Fatal("request never held")
	}
	ic.Drop(id)
	if !<-res {
		t.Error("drop should have returned drop=true")
	}
	// Disable releases a held request (forwards it, drop=false).
	ic.SetEnabled(true)
	res2 := make(chan bool, 1)
	go func() { _, drop := ic.Hold(mkReq("GET", "http://h/c")); res2 <- drop }()
	if waitHeld(ic) == 0 {
		t.Fatal("request never held before disable")
	}
	ic.SetEnabled(false)
	if <-res2 {
		t.Error("disable should forward (drop=false), not drop")
	}
	// When disabled, Hold passes through immediately.
	send, drop := ic.Hold(mkReq("GET", "http://h/d"))
	if drop || send == nil {
		t.Error("disabled intercept must pass through")
	}
}

func TestRewriteRules(t *testing.T) {
	s := New()
	if _, err := s.Rewrite.Add("header", "(", "x", true); err == nil {
		t.Error("bad regex should error")
	}
	r, err := s.Rewrite.Add("header", "secret", "REDACTED", true)
	if err != nil {
		t.Fatal(err)
	}
	req := mkReq("GET", "http://h/a")
	req.Header.Set("X-Test", "my secret value")
	s.Rewrite.Apply(req)
	if req.Header.Get("X-Test") != "my REDACTED value" {
		t.Errorf("header rewrite failed: %q", req.Header.Get("X-Test"))
	}
	// URL rewrite.
	s.Rewrite.Add("url", "/a", "/b", true)
	req2 := mkReq("GET", "http://h/a")
	s.Rewrite.Apply(req2)
	if req2.URL.Path != "/b" {
		t.Errorf("url rewrite failed: %q", req2.URL.Path)
	}
	// Toggle off then apply = no change.
	s.Rewrite.Toggle(r.ID, false)
	req3 := mkReq("GET", "http://h/a")
	req3.Header.Set("X-Test", "secret")
	// disable the url rule too
	for _, rule := range s.Rewrite.List() {
		s.Rewrite.Toggle(rule.ID, false)
	}
	s.Rewrite.Apply(req3)
	if req3.Header.Get("X-Test") != "secret" {
		t.Error("disabled rules should not apply")
	}
}

func TestAuthHeaders(t *testing.T) {
	s := New()
	s.SetAuthHeader("Authorization", "Bearer tok")
	s.SetAuthHeader("X-Del", "v")
	s.SetAuthHeader("X-Del", "") // delete
	h := http.Header{}
	h.Set("Authorization", "existing")
	s.ApplyAuth(h)
	if h.Get("Authorization") != "existing" {
		t.Error("ApplyAuth must not overwrite existing header")
	}
	h2 := http.Header{}
	s.ApplyAuth(h2)
	if h2.Get("Authorization") != "Bearer tok" {
		t.Error("ApplyAuth should set configured header")
	}
	if _, ok := s.AuthHeaders()["X-Del"]; ok {
		t.Error("empty value should delete the header")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	s := New()
	s.Add(SourceProxy, mkTx("GET", "http://a.test/p?q=1", 200))
	s.AddIssues(&scan.Issue{Check: "x", Name: "n", URL: "http://a.test/p", Severity: scan.SeverityHigh})
	s.Scope.Include("a.test", "")
	snap := s.Export()

	s2 := New()
	s2.Import(snap)
	if len(s2.History(0)) != 1 {
		t.Error("history not restored")
	}
	if len(s2.Issues()) != 1 {
		t.Error("issues not restored")
	}
	if !s2.Scope.InScope(mustURL("http://a.test/x")) {
		t.Error("scope not restored")
	}
	// Next added record should not collide with restored id.
	rec := s2.Add(SourceProxy, mkTx("GET", "http://a.test/q", 200))
	if rec.ID <= 1 {
		t.Errorf("nextID not advanced after import: %d", rec.ID)
	}
}

func TestWSLog(t *testing.T) {
	s := New()
	s.WS.Add("ws://h/x", "c2s", 1, []byte("hello"))
	s.WS.Add("ws://h/x", "s2c", 2, []byte{0, 1, 2})
	if s.WS.Count() != 2 {
		t.Fatal("ws count wrong")
	}
	msgs := s.WS.Messages(0)
	if msgs[0].Direction != "s2c" || msgs[0].Opcode != 2 {
		t.Error("ws newest-first ordering wrong")
	}
	if msgs[1].Text != "hello" {
		t.Error("text frame not decoded")
	}
	if msgs[0].Text != "" {
		t.Error("binary frame should not be stored as text")
	}
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }
