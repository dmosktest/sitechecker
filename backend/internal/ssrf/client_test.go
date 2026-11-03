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
