package fuzz

import (
	"context"
	"net/http"
	"testing"

	"lanternfish/internal/httpmsg"
)

// echoSender returns a body echoing the request so grep-extract can be tested.
// It is stateless, so it is trivially safe for the concurrent calls RunAttack makes.
type echoSender struct{}

func newEcho() *echoSender { return &echoSender{} }

func (e *echoSender) Send(_ context.Context, r *httpmsg.Request) (*httpmsg.Response, error) {
	body := "PATH=" + r.URL.Path + " TOKEN=abc123 BODY=" + string(r.Body)
	return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(body)}, nil
}

const tmpl = "GET /u/§1§?x=§a§ HTTP/1.1\r\nHost: h\r\n\r\n"

func TestSniperCount(t *testing.T) {
	// 2 positions × 2 payloads = 4 requests.
	res := RunAttack(context.Background(), newEcho(), Attack{
		Scheme: "http", Host: "h", Template: tmpl, Type: Sniper,
		PayloadSets: [][]string{{"p1", "p2"}},
	})
	if res.Positions != 2 {
		t.Fatalf("positions = %d, want 2", res.Positions)
	}
	if res.Count != 4 {
		t.Errorf("sniper count = %d, want 4", res.Count)
	}
}

func TestBatteringRamSamePayloadEverywhere(t *testing.T) {
	res := RunAttack(context.Background(), newEcho(), Attack{
		Scheme: "http", Host: "h", Template: tmpl, Type: BatteringRam,
		PayloadSets: [][]string{{"X", "Y"}},
	})
	if res.Count != 2 {
		t.Fatalf("batteringram count = %d, want 2", res.Count)
	}
	for _, row := range res.Rows {
		if row.Payloads[0] != row.Payloads[1] {
			t.Errorf("battering ram should use same payload in all positions: %v", row.Payloads)
		}
	}
}

func TestPitchforkLockstep(t *testing.T) {
	res := RunAttack(context.Background(), newEcho(), Attack{
		Scheme: "http", Host: "h", Template: tmpl, Type: Pitchfork,
		PayloadSets: [][]string{{"a1", "a2", "a3"}, {"b1", "b2"}},
	})
	if res.Count != 2 { // min(3,2)
		t.Fatalf("pitchfork count = %d, want 2", res.Count)
	}
	if res.Rows[0].Payloads[0] != "a1" || res.Rows[0].Payloads[1] != "b1" {
		t.Errorf("pitchfork lockstep wrong: %v", res.Rows[0].Payloads)
	}
}

func TestClusterBombProduct(t *testing.T) {
	res := RunAttack(context.Background(), newEcho(), Attack{
		Scheme: "http", Host: "h", Template: tmpl, Type: ClusterBomb,
		PayloadSets: [][]string{{"a1", "a2"}, {"b1", "b2", "b3"}},
	})
	if res.Count != 6 { // 2 × 3
		t.Fatalf("clusterbomb count = %d, want 6", res.Count)
	}
}

func TestGrepExtract(t *testing.T) {
	res := RunAttack(context.Background(), newEcho(), Attack{
		Scheme: "http", Host: "h", Template: tmpl, Type: BatteringRam,
		PayloadSets: [][]string{{"X"}}, GrepExtract: `TOKEN=(\w+)`,
	})
	if len(res.Rows) != 1 || res.Rows[0].Extracted != "abc123" {
		t.Errorf("grep-extract failed: %+v", res.Rows)
	}
}

func TestRenderSubstitutes(t *testing.T) {
	got := render("a=§1§&b=§2§", []string{"X", "Y"})
	if got != "a=X&b=Y" {
		t.Errorf("render wrong: %q", got)
	}
}
