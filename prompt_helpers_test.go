// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// init runs before any test in the package. It forces isTerminalFunc to
// return false so promptWithAskpass takes the zenity/kdialog/SSH_ASKPASS
// path (skipping the term.ReadPassword fallback that would block on a TTY
// when `go test` is run interactively).
//
// When neither zenity, kdialog, nor SSH_ASKPASS is available, prompts
// fall through to termPasswordPrompt's default case and return
// "need a terminal to prompt for a password" — matching the existing
// behavior in non-interactive environments and what scripts like
// testdata/scripts/dump.txt explicitly expect.
//
// SSH_ASKPASS is intentionally NOT set globally: doing so short-circuits
// the chain with a canned value and breaks tests that expect the prompt
// to fail with "need a terminal". Tests that need a specific prompt
// response should call setupSSHAskpass with the desired value, or mock
// passwordPromptFunc directly. Tests that need to test the real terminal
// path (tty_test.go) explicitly override isTerminalFunc and
// readPasswordFunc, so they continue to work.
func init() {
	isTerminalFunc = func(int) bool { return false }
}

// setupSSHAskpass installs a per-test SSH_ASKPASS script that echoes value,
// for tests that need to assert a specific prompt response. Cleans up
// automatically via t.Setenv.
//
// Example:
//
//	func TestClientId_PromptFallback(t *testing.T) {
//	    setupSSHAskpass(t, "test-client-id")
//	    // ... rest of test
//	}
func setupSSHAskpass(t *testing.T, value string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "askpass")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho "+value+"\n"), 0o755); err != nil {
		t.Fatalf("setupSSHAskpass: write script: %v", err)
	}
	t.Setenv("SSH_ASKPASS", script)
}
