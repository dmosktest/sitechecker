package score

import (
	"testing"

	"sitechecker/internal/domain"
)

func TestComputeCriticalCapsAtD(t *testing.T) {
	findings := []domain.Finding{
		{ID: "T2", Status: domain.StatusFail, Severity: domain.SeverityCritical},
	}
	sc, grade, top := Compute(findings)
	if sc != 70 {
		t.Fatalf("score=%d", sc)
	}
	if grade != "D" {
		t.Fatalf("grade=%s", grade)
	}
	if len(top) != 1 || top[0] != "T2" {
		t.Fatalf("top=%v", top)
	}
}
