package oast_test

import (
	"net/http"
	"testing"
	"time"

	"lanternfish/internal/oast"
)

func TestHostedCollaboratorRoundTrip(t *testing.T) {
	srv := oast.New("")
	base, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}
	defer srv.Close()
	ctrl, err := srv.ServeControl("127.0.0.1:0", "s3cr3t")
	if err != nil {
		t.Fatalf("start control: %v", err)
	}

	r := oast.NewRemote(base, "http://"+ctrl, "s3cr3t")
	token, callback := r.NewPayload()

	// No callback yet.
	if n := r.Hits(token); n != 0 {
		t.Fatalf("expected 0 hits, got %d", n)
	}

	// Simulate the target calling the payload URL.
	resp, err := http.Get(callback)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp.Body.Close()

	// Poll via the remote client (retry briefly for the record to land).
	got := 0
	for i := 0; i < 20; i++ {
		if got = r.Hits(token); got > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got == 0 {
		t.Fatalf("remote collaborator did not observe the callback")
	}
	if d := r.HitDetails(token); len(d) == 0 {
		t.Fatalf("expected hit details")
	}
}

func TestHostedCollaboratorAuth(t *testing.T) {
	srv := oast.New("")
	if _, err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()
	ctrl, err := srv.ServeControl("127.0.0.1:0", "right")
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	// Wrong secret must not retrieve interactions.
	bad := oast.NewRemote("http://x", "http://"+ctrl, "wrong")
	if n := bad.Hits("oaXYZ"); n != 0 {
		t.Fatalf("auth bypass: got %d", n)
	}
}
