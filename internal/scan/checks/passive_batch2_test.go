package checks

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"lanternfish/internal/httpmsg"
)

func txReqResp(reqBody string, reqHeaders http.Header, respBody string, respHeaders http.Header) *httpmsg.Transaction {
	u, _ := url.Parse("http://x/app")
	if reqHeaders == nil {
		reqHeaders = http.Header{}
	}
	if respHeaders == nil {
		respHeaders = http.Header{}
	}
	return &httpmsg.Transaction{
		Request:  &httpmsg.Request{Method: "POST", URL: u, Scheme: "http", Host: "x", Header: reqHeaders, Body: []byte(reqBody)},
		Response: &httpmsg.Response{StatusCode: 200, Header: respHeaders, Body: []byte(respBody)},
	}
}

func TestInsecureDeserialization(t *testing.T) {
	if len((InsecureDeserialization{}).Passive(txReqResp("data=rO0ABXNy", nil, "", nil))) == 0 {
		t.Error("should flag Java serialized marker")
	}
	if len((InsecureDeserialization{}).Passive(txReqResp(`a:O:8:"stdClass":1:{}`, nil, "", nil))) == 0 {
		t.Error("should flag PHP serialized object")
	}
	if len((InsecureDeserialization{}).Passive(txReqResp("plain=1", nil, "ok", nil))) != 0 {
		t.Error("should not flag benign traffic")
	}
}

func TestJWTWeakness(t *testing.T) {
	// header {"alg":"none","typ":"JWT"}
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890"}`))
	tok := hdr + "." + pay + "."
	rh := http.Header{}
	rh.Set("Authorization", "Bearer "+tok)
	if len((JWTWeakness{}).Passive(txReqResp("", rh, "", nil))) == 0 {
		t.Error("should flag alg=none JWT")
	}
	// A normal HS256 token should not fire.
	hdr2 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	rh2 := http.Header{}
	rh2.Set("Authorization", "Bearer "+hdr2+"."+pay+".sig")
	if len((JWTWeakness{}).Passive(txReqResp("", rh2, "", nil))) != 0 {
		t.Error("should not flag HS256 JWT")
	}
}

func TestEmailDisclosure(t *testing.T) {
	if len((EmailDisclosure{}).Passive(txReqResp("", nil, "contact admin@example.com", nil))) == 0 {
		t.Error("should flag email")
	}
}

func TestCacheableSensitive(t *testing.T) {
	rh := http.Header{}
	rh.Add("Set-Cookie", "SESSION=abc")
	if len((CacheableSensitive{}).Passive(txReqResp("", nil, "ok", rh))) == 0 {
		t.Error("cookie without no-store should be flagged")
	}
	rh2 := http.Header{}
	rh2.Add("Set-Cookie", "SESSION=abc")
	rh2.Set("Cache-Control", "no-store")
	if len((CacheableSensitive{}).Passive(txReqResp("", nil, "ok", rh2))) != 0 {
		t.Error("no-store should suppress the finding")
	}
}

func TestAdditionalHeaders(t *testing.T) {
	rh := http.Header{}
	rh.Set("Content-Type", "text/html")
	if n := len((AdditionalHeaders{}).Passive(txReqResp("", nil, "<html></html>", rh))); n != 2 {
		t.Errorf("expected missing Referrer-Policy + Permissions-Policy, got %d", n)
	}
}
