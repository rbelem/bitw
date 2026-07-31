// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestTwoFactorPrompt_NoProviders verifies that twoFactorPrompt returns an
// error when the API requests 2FA but no providers are available.
func TestTwoFactorPrompt_NoProviders(t *testing.T) {
	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{},
	}

	_, _, err := twoFactorPrompt(resp)
	qt.Assert(t, err, qt.ErrorMatches, "API requested 2fa but has no available providers")
}

// TestTwoFactorPrompt_SingleProvider verifies that twoFactorPrompt auto-selects
// the single available provider and prompts for the token.
func TestTwoFactorPrompt_SingleProvider(t *testing.T) {
	oldReadLine := readLineFunc
	oldPasswordPrompt := passwordPromptFunc
	readLineFunc = func(prompt string) ([]byte, error) {
		t.Fatal("readLineFunc should not be called for single provider")
		return nil, nil
	}
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		qt.Assert(t, prompt, qt.Contains, "Two-factor code")
		return []byte("123456"), nil
	}
	t.Cleanup(func() {
		readLineFunc = oldReadLine
		passwordPromptFunc = oldPasswordPrompt
	})

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
		},
	}

	selected, token, err := twoFactorPrompt(resp)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, selected, qt.Equals, Authenticator)
	qt.Assert(t, string(token), qt.Equals, "123456")
}

// TestTwoFactorPrompt_MultipleProviders_ValidSelection verifies that
// twoFactorPrompt lists providers and accepts a valid selection.
func TestTwoFactorPrompt_MultipleProviders_ValidSelection(t *testing.T) {
	oldReadLine := readLineFunc
	oldPasswordPrompt := passwordPromptFunc
	readLineFunc = func(prompt string) ([]byte, error) {
		qt.Assert(t, prompt, qt.Contains, "Select a two-factor auth provider")
		return []byte("1"), nil
	}
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		return []byte("654321"), nil
	}
	t.Cleanup(func() {
		readLineFunc = oldReadLine
		passwordPromptFunc = oldPasswordPrompt
	})

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
			Email:         {"Email": "test@example.com"},
		},
	}

	stderr := captureStderr(t, func() {
		selected, token, err := twoFactorPrompt(resp)
		qt.Assert(t, err, qt.IsNil)
		// First provider in iteration order (Authenticator=0)
		qt.Assert(t, selected, qt.Equals, Authenticator)
		qt.Assert(t, string(token), qt.Equals, "654321")
	})

	// Verify providers were listed on stderr
	qt.Assert(t, stderr, qt.Contains, "1)")
	qt.Assert(t, stderr, qt.Contains, "2)")
}

// TestTwoFactorPrompt_MultipleProviders_InvalidSelection verifies that
// twoFactorPrompt rejects out-of-range selections.
func TestTwoFactorPrompt_MultipleProviders_InvalidSelection(t *testing.T) {
	oldReadLine := readLineFunc
	readLineFunc = func(prompt string) ([]byte, error) {
		return []byte("99"), nil
	}
	t.Cleanup(func() { readLineFunc = oldReadLine })

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
			Email:         {"Email": "test@example.com"},
		},
	}

	captureStderr(t, func() {
		_, _, err := twoFactorPrompt(resp)
		qt.Assert(t, err, qt.ErrorMatches, "selected option 99 is not within the range.*")
	})
}

// TestTwoFactorPrompt_MultipleProviders_ZeroSelection verifies that
// twoFactorPrompt rejects zero as a selection.
func TestTwoFactorPrompt_MultipleProviders_ZeroSelection(t *testing.T) {
	oldReadLine := readLineFunc
	readLineFunc = func(prompt string) ([]byte, error) {
		return []byte("0"), nil
	}
	t.Cleanup(func() { readLineFunc = oldReadLine })

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
			Email:         {"Email": "test@example.com"},
		},
	}

	captureStderr(t, func() {
		_, _, err := twoFactorPrompt(resp)
		qt.Assert(t, err, qt.ErrorMatches, "selected option 0 is not within the range.*")
	})
}

// TestTwoFactorPrompt_MultipleProviders_ReadLineError verifies that
// twoFactorPrompt propagates readLineFunc errors.
func TestTwoFactorPrompt_MultipleProviders_ReadLineError(t *testing.T) {
	oldReadLine := readLineFunc
	readLineFunc = func(prompt string) ([]byte, error) {
		return nil, fmt.Errorf("readline failed")
	}
	t.Cleanup(func() { readLineFunc = oldReadLine })

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
			Email:         {"Email": "test@example.com"},
		},
	}

	captureStderr(t, func() {
		_, _, err := twoFactorPrompt(resp)
		qt.Assert(t, err, qt.ErrorMatches, "readline failed")
	})
}

// TestTwoFactorPrompt_MultipleProviders_AtoiError verifies that
// twoFactorPrompt rejects non-numeric input.
func TestTwoFactorPrompt_MultipleProviders_AtoiError(t *testing.T) {
	oldReadLine := readLineFunc
	readLineFunc = func(prompt string) ([]byte, error) {
		return []byte("abc"), nil
	}
	t.Cleanup(func() { readLineFunc = oldReadLine })

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
			Email:         {"Email": "test@example.com"},
		},
	}

	captureStderr(t, func() {
		_, _, err := twoFactorPrompt(resp)
		qt.Assert(t, err, qt.ErrorMatches, ".*invalid syntax.*")
	})
}

// TestTwoFactorPrompt_MultipleProviders_PasswordPromptError verifies that
// twoFactorPrompt propagates passwordPromptFunc errors.
func TestTwoFactorPrompt_MultipleProviders_PasswordPromptError(t *testing.T) {
	oldReadLine := readLineFunc
	oldPasswordPrompt := passwordPromptFunc
	readLineFunc = func(prompt string) ([]byte, error) {
		return []byte("1"), nil
	}
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		return nil, fmt.Errorf("password prompt failed")
	}
	t.Cleanup(func() {
		readLineFunc = oldReadLine
		passwordPromptFunc = oldPasswordPrompt
	})

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
		},
	}

	captureStderr(t, func() {
		_, _, err := twoFactorPrompt(resp)
		qt.Assert(t, err, qt.ErrorMatches, "password prompt failed")
	})
}

// TestTwoFactorPrompt_SingleProvider_PasswordPromptError verifies that
// twoFactorPrompt propagates passwordPromptFunc errors even for single provider.
func TestTwoFactorPrompt_SingleProvider_PasswordPromptError(t *testing.T) {
	oldPasswordPrompt := passwordPromptFunc
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		return nil, fmt.Errorf("password prompt failed")
	}
	t.Cleanup(func() { passwordPromptFunc = oldPasswordPrompt })

	resp := &twoFactorResponse{
		TwoFactorProviders2: map[TwoFactorProvider]map[string]interface{}{
			Authenticator: {},
		},
	}

	_, _, err := twoFactorPrompt(resp)
	qt.Assert(t, err, qt.ErrorMatches, "password prompt failed")
}
