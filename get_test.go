// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import "testing"

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "''"},
		{"   ", "'   '"},
		{"don't", "'don'\\''t'"},
		{"$(echo evil)", "'$(echo evil)'"},
		{"hello\nworld", "'hello\nworld'"},
		{"simple", "'simple'"},
		{"with\"double", "'with\"double'"},
	}
	for _, tc := range tests {
		got := shellQuote(tc.in)
		if got != tc.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsValidShellIdent(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"GITHUB_TOKEN", true},
		{"OPENAI_BASE_URL", true},
		{"_private", true},
		{"x", true},
		{"x;evil", false},
		{"foo bar", false},
		{"1abc", false},
		{"", false},
		{"has-dash", false},
	}
	for _, tc := range tests {
		got := isValidShellIdent(tc.in)
		if got != tc.want {
			t.Errorf("isValidShellIdent(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
