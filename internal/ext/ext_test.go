package ext

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/session"
)

func tx() *httpmsg.Transaction {
	u, _ := url.Parse("http://h.test/p")
	return &httpmsg.Transaction{
		Request:  &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "h.test", Header: http.Header{}},
		Response: &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("hi")},
	}
}

func TestAddListRemove(t *testing.T) {
	m := New(session.New())
	e := m.Add("http://x/hook", "demo")
	if len(m.List()) != 1 || e.ID == 0 {
		t.Fatal("add failed")
	}
	if !m.Remove(e.ID) || len(m.List()) != 0 {
		t.Fatal("remove failed")
	}
	if m.Remove(999) {
		t.Error("removing unknown should return false")
	}
}

func TestDispatchAddsIssues(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issues":[{"name":"ext finding","severity":"high","confidence":"firm","url":"http://h.test/p","cwe":"CWE-1"}]}`))
	}))
	defer hook.Close()

	sess := session.New()
	m := New(sess)
	m.Add(hook.URL, "demo")
	m.Dispatch(tx())

	// Dispatch is async; wait briefly.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(sess.Issues()) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	issues := sess.Issues()
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue from extension, got %d", len(issues))
	}
	if issues[0].Check != "ext:demo" || issues[0].SeverityStr != "high" {
		t.Errorf("extension issue mapped wrong: %+v", issues[0])
	}
}

func TestDispatchNoExtensionsIsNoop(t *testing.T) {
	sess := session.New()
	m := New(sess)
	m.Dispatch(tx()) // should not panic or block
	if len(sess.Issues()) != 0 {
		t.Error("no extensions should add no issues")
	}
}
