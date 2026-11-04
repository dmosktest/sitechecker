package checks

import "testing"

func TestAuthDNSNilReceiverDoesNotPanic(t *testing.T) {
	var a *authDNS
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on nil receiver: %v", r)
		}
	}()
	_ = a.NSLabel()
}

func TestAuthDNSNsLabel(t *testing.T) {
	a := &authDNS{NSHosts: []string{"ns1.example.com.", "ns2.example.com"}}
	got := a.NSLabel()
	want := "ns1.example.com, ns2.example.com"
	if got != want {
		t.Fatalf("nsLabel=%q want %q", got, want)
	}
}
