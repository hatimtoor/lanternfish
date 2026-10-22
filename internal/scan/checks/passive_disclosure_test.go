package checks

import (
	"net/http"
	"net/url"
	"testing"

	"lanternfish/internal/httpmsg"
)

func tx(body string) *httpmsg.Transaction {
	u, _ := url.Parse("http://x/")
	return &httpmsg.Transaction{
		Request:  &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: http.Header{}},
		Response: &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(body)},
	}
}

func TestExposedSecretsDetectsKeys(t *testing.T) {
	cases := map[string]string{
		"aws":     "config = AKIA" + "IOSFODNN7EXAMPLE end",
		"private": "-----BEGIN RSA " + "PRIVATE KEY-----\nMII...",
		"jwt":     "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456",
	}
	for name, body := range cases {
		if got := (ExposedSecrets{}).Passive(tx(body)); len(got) == 0 {
			t.Errorf("%s: expected a secret finding", name)
		}
	}
	if got := (ExposedSecrets{}).Passive(tx("nothing secret here, just text")); len(got) != 0 {
		t.Errorf("expected no findings on benign body, got %d", len(got))
	}
}

func TestVerboseErrorDetectsStackTrace(t *testing.T) {
	body := "Traceback (most recent call last):\n  File app.py line 10"
	if got := (VerboseError{}).Passive(tx(body)); len(got) == 0 {
		t.Error("expected a verbose-error finding")
	}
	if got := (VerboseError{}).Passive(tx("<html>ok</html>")); len(got) != 0 {
		t.Error("expected no verbose-error finding on clean body")
	}
}
