// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"sort"
	"strings"
	"unicode"
)

// fuzzyScore ranks query against candidate (case-insensitive, subsequence
// matching, fzf-style scoring): bonuses for matches at the start of the
// candidate, at word boundaries, and for consecutive runs; penalties for
// gaps. It returns the score and the byte offsets of the matched characters
// in candidate (for highlight rendering). A score of 0 means the query does
// not appear as a subsequence of the candidate.
func fuzzyScore(query, candidate string) (int, []int) {
	if query == "" {
		return 0, nil
	}
	q := []rune(strings.ToLower(query))
	c := []rune(strings.ToLower(candidate))

	// byteOffset maps a rune index in candidate to its byte offset.
	byteOffset := make([]int, 0, len(c))
	off := 0
	for _, r := range candidate {
		byteOffset = append(byteOffset, off)
		off += len(string(r))
	}

	var spans []int
	score := 0
	cursor := 0
	prevMatch := -1
	for _, qr := range q {
		found := -1
		for i := cursor; i < len(c); i++ {
			if c[i] == qr {
				found = i
				break
			}
		}
		if found == -1 {
			return 0, nil
		}
		if prevMatch >= 0 {
			gap := found - prevMatch - 1
			if gap == 0 {
				score += 8 // consecutive run
			} else {
				score -= 2 + (gap - 1) // gap start + extension
			}
		} else if found == 0 {
			score += 8 // match at start of candidate
		} else {
			if isWordBoundary(candidate, found) {
				score += 5
			}
			score -= 2
		}
		spans = append(spans, byteOffset[found])
		prevMatch = found
		cursor = found + 1
	}
	return score, spans
}

// isWordBoundary reports whether the rune at index i in s starts a word
// (alphanumeric preceded by a non-alphanumeric, or an uppercase letter
// preceded by a lowercase letter — camelCase boundaries).
func isWordBoundary(s string, i int) bool {
	if i <= 0 {
		return true
	}
	r := []rune(s)
	prev, cur := r[i-1], r[i]
	prevAlpha := unicode.IsLetter(prev) || unicode.IsDigit(prev)
	curAlpha := unicode.IsLetter(cur) || unicode.IsDigit(cur)
	if !prevAlpha && curAlpha {
		return true
	}
	return unicode.IsLower(prev) && unicode.IsUpper(cur)
}

// rankedMatch is a fuzzy match result: the candidate, its score, and the
// byte offsets to highlight.
type rankedMatch struct {
	name  string
	score int
	spans []int
}

// fuzzyRank returns all candidates matching query, ranked by score
// (descending, ties broken alphabetically).
func fuzzyRank(query string, candidates []string) []rankedMatch {
	var out []rankedMatch
	for _, cand := range candidates {
		score, spans := fuzzyScore(query, cand)
		if score > 0 {
			out = append(out, rankedMatch{name: cand, score: score, spans: spans})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].name < out[j].name
	})
	return out
}

// fuzzyBest returns the best fuzzy match for query among candidates, if any.
func fuzzyBest(query string, candidates []string) (rankedMatch, bool) {
	ranked := fuzzyRank(query, candidates)
	if len(ranked) == 0 {
		return rankedMatch{}, false
	}
	return ranked[0], true
}
