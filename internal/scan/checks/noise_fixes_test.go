package checks

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

func TestExposedSecretsJWTSkippedOnAuthPath(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.abcdefghij"
	// On a login endpoint the JWT is expected -> no finding.
	txLogin := txFull("http://x/users/v1/login", "application/json", `{"token":"`+jwt+`"}`, nil)
	if iss := (ExposedSecrets{}).Passive(txLogin); len(iss) != 0 {
		t.Errorf("JWT on a login endpoint should not be flagged, got %v", iss)
	}
	// On a non-auth endpoint a JWT in the body is still worth flagging.
	txData := txFull("http://x/api/orders", "application/json", `{"t":"`+jwt+`"}`, nil)
	if iss := (ExposedSecrets{}).Passive(txData); len(iss) == 0 {
		t.Errorf("JWT on a non-auth endpoint should still be flagged")
	}
}

func methodSender(allow string) fakeSender {
	return fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		h := http.Header{}
		h.Set("Allow", allow)
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte("")}
	}}
}

func TestDangerousMethodsSeverity(t *testing.T) {
	u, _ := url.Parse("http://x/users/v1/:username")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: http.Header{}}
	// DELETE only -> informational (normal REST method).
	iss := (DangerousMethods{}).Request(context.Background(), methodSender("GET, OPTIONS, DELETE"), req)
	if len(iss) == 0 || iss[0].Severity != scan.SeverityInfo {
		t.Errorf("PUT/DELETE should be info, got %v", iss)
	}
	// TRACE -> medium.
	iss2 := (DangerousMethods{}).Request(context.Background(), methodSender("GET, TRACE"), req)
	if len(iss2) == 0 || iss2[0].Severity != scan.SeverityMedium {
		t.Errorf("TRACE should be medium, got %v", iss2)
	}
}
