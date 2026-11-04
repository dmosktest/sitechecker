package ssrf

import (
	"net"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	d, err := NormalizeDomain("HTTPS://Example.COM./path")
	if err != nil || d != "example.com" {
		t.Fatalf("got %q %v", d, err)
	}
	if _, err := NormalizeDomain("127.0.0.1"); err == nil {
		t.Fatal("expected error for IP")
	}
	if _, err := NormalizeDomain("user:pass@evil.com"); err == nil {
		t.Fatal("expected error for userinfo")
	}
}

func TestIsBlockedIP(t *testing.T) {
	cases := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "172.16.0.1", "::1", "0.0.0.0"}
	for _, c := range cases {
		if !IsBlockedIP(net.ParseIP(c)) {
			t.Fatalf("%s should be blocked", c)
		}
	}
	if IsBlockedIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("8.8.8.8 should be allowed")
	}
}

func TestCookiesFromJSBody(t *testing.T) {
	beget := []byte(`<html><head><script>function set_cookie(){var now = new Date();document.cookie='beget=begetok'+'; expires='+now.toGMTString()+'; path=/';}set_cookie();location.reload();</script></head><body></body></html>`)
	cs := cookiesFromJSBody(beget)
	if len(cs) != 1 || cs[0].Name != "beget" || cs[0].Value != "begetok" {
		t.Fatalf("beget cookies=%v", cs)
	}
	other := []byte(`<script>document.cookie="gate=ok; path=/"; location.reload();</script>`)
	cs = cookiesFromJSBody(other)
	if len(cs) != 1 || cs[0].Name != "gate" || cs[0].Value != "ok" {
		t.Fatalf("gate cookies=%v", cs)
	}
	if cookiesFromJSBody([]byte(`<html>no cookies here</html>`)) != nil {
		t.Fatal("expected nil")
	}
}
