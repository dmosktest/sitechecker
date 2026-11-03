package pow

import "testing"

func TestIssueAndVerify(t *testing.T) {
	ch, err := Issue("secret", 0)
	if err != nil {
		t.Fatal(err)
	}
	sol := Solution{Token: ch.Token, ExpiresAt: ch.ExpiresAt}
	if !Verify("secret", sol, 0) {
		t.Fatal("verify failed")
	}
	if Verify("other", sol, 0) {
		t.Fatal("expected fail for wrong secret")
	}
	raw, err := DecodeSolution(EncodeSolution(sol))
	if err != nil || !Verify("secret", raw, 0) {
		t.Fatal("roundtrip failed")
	}
}
