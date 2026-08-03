// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestFuzzyScore(t *testing.T) {
	tests := []struct {
		query, cand string
		match       bool
	}{
		{"", "anything", false},       // empty query never matches
		{"git", "GitHub Token", true}, // case-insensitive subsequence
		{"gittok", "GitHub Token", true},
		{"gt", "GitHub Token", true},
		{"xyz", "GitHub Token", false}, // not a subsequence
		{"h", "GitHub Token", true},
		{"gh", "GitHub Token", true},
	}
	for _, tc := range tests {
		score, spans := fuzzyScore(tc.query, tc.cand)
		qt.Assert(t, (score > 0) == tc.match, qt.IsTrue,
			qt.Commentf("query=%q cand=%q score=%d", tc.query, tc.cand, score))
		if tc.match {
			// Spans must point at matching characters in the candidate.
			for _, off := range spans {
				qt.Assert(t, off < len(tc.cand), qt.IsTrue)
			}
			qt.Assert(t, len(spans), qt.Equals, len(tc.query))
		}
	}
}

func TestFuzzyScoreBonusOrdering(t *testing.T) {
	// Start-of-string and word-boundary matches score higher than
	// buried matches; consecutive runs score higher than gappy ones.
	startScore, _ := fuzzyScore("gt", "github token")
	boundaryScore, _ := fuzzyScore("gt", "my github token")
	buriedScore, _ := fuzzyScore("gt", "mygithub token")
	qt.Assert(t, startScore > boundaryScore, qt.IsTrue)
	qt.Assert(t, boundaryScore > buriedScore, qt.IsTrue)

	consecutive, _ := fuzzyScore("tok", "token")
	gappy, _ := fuzzyScore("tok", "trick-or-kick")
	qt.Assert(t, consecutive > gappy, qt.IsTrue)
}

func TestFuzzyScoreUTF8Spans(t *testing.T) {
	// "Café au Lait" — é is two bytes, so byte offsets diverge from rune
	// offsets. Greedy leftmost match: c→C(0), a→a(1), l→L(9).
	cand := "Café au Lait"
	score, spans := fuzzyScore("cal", cand)
	qt.Assert(t, score > 0, qt.IsTrue)
	qt.Assert(t, spans, qt.DeepEquals, []int{0, 1, 9})
	// Sanity: slicing the candidate at span offsets yields the matched chars.
	for _, off := range spans {
		qt.Assert(t, cand[off] >= 'A' && cand[off] <= 'z', qt.IsTrue)
	}
}

func TestFuzzyRank(t *testing.T) {
	cands := []string{"GitHub Token", "Gmail", "GitLab", "AWS Key"}
	ranked := fuzzyRank("git", cands)
	qt.Assert(t, len(ranked), qt.Equals, 2)
	qt.Assert(t, ranked[0].name, qt.Equals, "GitHub Token")
	qt.Assert(t, ranked[1].name, qt.Equals, "GitLab")

	// Alphabetical tie-break.
	ranked = fuzzyRank("g", []string{"gmail", "github", "gitlab"})
	qt.Assert(t, len(ranked), qt.Equals, 3)
	qt.Assert(t, ranked[0].name, qt.Equals, "github")

	// No matches.
	ranked = fuzzyRank("zzz", cands)
	qt.Assert(t, len(ranked), qt.Equals, 0)
}

func TestFuzzyBest(t *testing.T) {
	cands := []string{"GitHub Token", "Gmail"}
	best, ok := fuzzyBest("git", cands)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, best.name, qt.Equals, "GitHub Token")

	_, ok = fuzzyBest("zzz", cands)
	qt.Assert(t, ok, qt.IsFalse)
}
