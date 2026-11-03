package score

import "sitechecker/internal/domain"

func Deduction(sev domain.Severity, status domain.Status) int {
	if status != domain.StatusFail && status != domain.StatusWarn {
		return 0
	}
	base := 0
	switch sev {
	case domain.SeverityCritical:
		base = 30
	case domain.SeverityHigh:
		base = 12
	case domain.SeverityMedium:
		base = 5
	case domain.SeverityLow:
		base = 2
	default:
		return 0
	}
	if status == domain.StatusWarn {
		return base / 2
	}
	return base
}

func Compute(findings []domain.Finding) (score int, grade string, top []string) {
	score = 100
	criticalFail := false
	type ranked struct {
		id  string
		ded int
	}
	var ranks []ranked
	for _, f := range findings {
		d := Deduction(f.Severity, f.Status)
		if d > 0 {
			score -= d
			ranks = append(ranks, ranked{id: f.ID, ded: d})
		}
		if f.Severity == domain.SeverityCritical && f.Status == domain.StatusFail {
			criticalFail = true
		}
	}
	if score < 0 {
		score = 0
	}
	for i := 0; i < len(ranks); i++ {
		for j := i + 1; j < len(ranks); j++ {
			if ranks[j].ded > ranks[i].ded {
				ranks[i], ranks[j] = ranks[j], ranks[i]
			}
		}
	}
	for i := 0; i < len(ranks) && i < 3; i++ {
		top = append(top, ranks[i].id)
	}
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 65:
		grade = "C"
	case score >= 50:
		grade = "D"
	default:
		grade = "F"
	}
	if criticalFail && grade < "D" {
		// grade is letter; force max D
	}
	if criticalFail {
		if grade == "A" || grade == "B" || grade == "C" {
			grade = "D"
		}
	}
	return score, grade, top
}
