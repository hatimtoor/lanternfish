package checks

import (
	"net/http"
	"net/url"
	"testing"

	"lanternfish/internal/httpmsg"
)

func txFull(rawurl, ctype, body string, respHeaders http.Header) *httpmsg.Transaction {
	u, _ := url.Parse(rawurl)
	if respHeaders == nil {
		respHeaders = http.Header{}
	}
	if ctype != "" {
		respHeaders.Set("Content-Type", ctype)
	}
	return &httpmsg.Transaction{
		Request:  &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}},
		Response: &httpmsg.Response{StatusCode: 200, Header: respHeaders, Body: []byte(body)},
	}
}

func TestSessionTokenInURL(t *testing.T) {
	if len((SessionTokenInURL{}).Passive(txFull("http://x/app?jsessionid=ABC123", "", "", nil))) == 0 {
		t.Error("should flag session id in URL")
	}
	if len((SessionTokenInURL{}).Passive(txFull("http://x/app?page=1", "", "", nil))) != 0 {
		t.Error("should not flag benign query")
	}
}

func TestBannerDisclosure(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Apache/2.4.49")
	h.Set("X-Powered-By", "PHP/7.4.3")
	if n := len((BannerDisclosure{}).Passive(txFull("http://x/", "", "", h))); n < 2 {
		t.Errorf("should flag both version banners, got %d", n)
	}
}

func TestCookieSameSite(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "a=1; Path=/")
	if len((CookieSameSite{}).Passive(txFull("http://x/", "", "", h))) == 0 {
		t.Error("should flag missing SameSite")
	}
	h2 := http.Header{}
	h2.Add("Set-Cookie", "a=1; SameSite=Lax")
	if len((CookieSameSite{}).Passive(txFull("http://x/", "", "", h2))) != 0 {
		t.Error("should not flag cookie with SameSite")
	}
}

func TestSourceMapDisclosure(t *testing.T) {
	if len((SourceMapDisclosure{}).Passive(txFull("http://x/app.js", "application/javascript", "code();\n//# sourceMappingURL=app.js.map", nil))) == 0 {
		t.Error("should flag source map reference")
	}
}

func TestSensitiveComment(t *testing.T) {
	if len((SensitiveComment{}).Passive(txFull("http://x/", "text/html", "<html><!-- TODO: remove hardcoded password --></html>", nil))) == 0 {
		t.Error("should flag sensitive comment")
	}
	if len((SensitiveComment{}).Passive(txFull("http://x/", "text/html", "<html><!-- nav --></html>", nil))) != 0 {
		t.Error("should not flag benign comment")
	}
}

func TestCreditCardLuhn(t *testing.T) {
	// 4111111111111111 is a Luhn-valid test Visa number.
	if len((CreditCardDisclosure{}).Passive(txFull("http://x/", "text/html", "card: 4111 1111 1111 1111", nil))) == 0 {
		t.Error("should flag Luhn-valid card number")
	}
	// Non-Luhn number should not fire.
	if len((CreditCardDisclosure{}).Passive(txFull("http://x/", "text/html", "id: 1234567812345678", nil))) != 0 {
		t.Error("should not flag non-Luhn digits")
	}
}

func TestInsecureForm(t *testing.T) {
	if len((InsecureFormTarget{}).Passive(txFull("https://x/", "text/html", `<form action="http://x/login" method=post>`, nil))) == 0 {
		t.Error("should flag http form action")
	}
}

func TestVulnerableJSLibrary(t *testing.T) {
	// jQuery 1.7.2 is well below 3.5.0.
	if len((VulnerableJSLibrary{}).Passive(txFull("http://x/", "text/html", "<script>/* jQuery v1.7.2 */</script>", nil))) == 0 {
		t.Error("should flag old jQuery")
	}
	// Current jQuery should not fire.
	if len((VulnerableJSLibrary{}).Passive(txFull("http://x/", "text/html", "jQuery JavaScript Library v3.7.1", nil))) != 0 {
		t.Error("should not flag current jQuery")
	}
}

func TestVersionLess(t *testing.T) {
	if !versionLess("1.7.2", []int{3, 5, 0}) {
		t.Error("1.7.2 < 3.5.0")
	}
	if versionLess("3.7.1", []int{3, 5, 0}) {
		t.Error("3.7.1 not < 3.5.0")
	}
	if versionLess("3.5.0", []int{3, 5, 0}) {
		t.Error("equal is not less")
	}
}
