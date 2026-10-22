package decoder

import "testing"

func TestRoundTrips(t *testing.T) {
	cases := []struct{ enc, dec string }{
		{"base64-encode", "base64-decode"},
		{"url-encode", "url-decode"},
		{"hex-encode", "hex-decode"},
		{"html-encode", "html-decode"},
		{"ascii-hex-encode", "ascii-hex-decode"},
	}
	in := "hello <world> & 'friends' ?a=1"
	for _, c := range cases {
		enc, err := Transform(in, c.enc)
		if err != nil {
			t.Fatalf("%s: %v", c.enc, err)
		}
		dec, err := Transform(enc, c.dec)
		if err != nil {
			t.Fatalf("%s: %v", c.dec, err)
		}
		if dec != in {
			t.Errorf("%s/%s round trip failed: %q -> %q -> %q", c.enc, c.dec, in, enc, dec)
		}
	}
}

func TestHashes(t *testing.T) {
	if h, _ := Transform("abc", "sha256"); h != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("sha256 wrong: %s", h)
	}
	if h, _ := Transform("abc", "md5"); h != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("md5 wrong: %s", h)
	}
}

func TestSmartDecode(t *testing.T) {
	if got := Transform2("%3Cscript%3E", "smart-decode"); got != "<script>" {
		t.Errorf("smart url-decode failed: %q", got)
	}
	if got := Transform2("SGVsbG8gd29ybGQh", "smart-decode"); got != "Hello world!" {
		t.Errorf("smart base64-decode failed: %q", got)
	}
	if got := Transform2("&lt;b&gt;", "smart-decode"); got != "<b>" {
		t.Errorf("smart html-decode failed: %q", got)
	}
}

func TestUnknownOp(t *testing.T) {
	if _, err := Transform("x", "nope"); err == nil {
		t.Error("unknown op should error")
	}
}

func Transform2(in, op string) string { s, _ := Transform(in, op); return s }
