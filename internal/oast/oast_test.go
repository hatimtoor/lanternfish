package oast

import (
	"net/http"
	"testing"
)

func TestPayloadUniqueAndEmbedsToken(t *testing.T) {
	s := New("http://oast.test")
	t1, u1 := s.NewPayload()
	t2, u2 := s.NewPayload()
	if t1 == t2 || u1 == u2 {
		t.Error("payloads should be unique")
	}
	if u1 != "http://oast.test/"+t1 {
		t.Errorf("url should embed token: %s", u1)
	}
}

func TestRecordAndMatch(t *testing.T) {
	s := New("")
	base, err := s.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token, url := s.NewPayload()
	if base == "" || url == "" {
		t.Fatal("start/payload empty")
	}
	// Simulate the target calling back.
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if s.Hits(token) != 1 {
		t.Errorf("expected 1 hit for token, got %d", s.Hits(token))
	}
	if s.Hits("nonexistent") != 0 {
		t.Error("unknown token should have 0 hits")
	}
	if len(s.HitDetails(token)) != 1 {
		t.Error("hit details missing")
	}
	if len(s.All()) != 1 {
		t.Error("All() should list the interaction")
	}
}
