// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// init runs before any test in the package. It neutralizes all external
// sources of interactive prompts so that `go test` (run interactively or
// in CI) never blocks waiting for stdin, GUI dialogs, or external
// SSH_ASKPASS programs.
//
// Four pieces of state are configured:
//
//  1. isTerminalFunc is forced to return false so promptWithAskpass
//     takes the zenity/kdialog/SSH_ASKPASS path (skipping the
//     term.ReadPassword fallback that would block on a TTY when `go test`
//     is run interactively).
//
//  2. A custom SSH_ASKPASS script is written to a temp dir and set as
//     SSH_ASKPASS globally (overriding any user-inherited value such as
//     ksshaskpass). The script echoes $TEST_ASKPASS_VALUE if set (so
//     tests can control the prompt response via t.Setenv), otherwise
//     exits non-zero so promptWithAskpass falls through to
//     termPasswordPrompt and returns "need a terminal to prompt for a
//     password" — matching the existing behavior in non-interactive
//     environments and what scripts like testdata/scripts/dump.txt
//     explicitly expect.
//
//  3. shell is wrapped in a blockingExec that makes LookPath fail for
//     "zenity", "kdialog", and "ksshaskpass". Even with our SSH_ASKPASS
//     installed, promptWithAskpass still tries zenity/kdialog first;
//     these GUI prompt tools would pop a dialog or block waiting for
//     the user. The wrapper makes LookPath return "not found" so those
//     branches are skipped. Output/CombinedOutput delegate to the real
//     osExec so other tests (e.g. secret-tool PATH-stub tests) keep
//     working.
//
//  4. The user's external SSH_ASKPASS is overridden by our custom script
//     (step 2 above), so environment-inherited prompts are bypassed.
//
// Tests that need a specific prompt response should call
// setupSSHAskpass(t, value) (which sets TEST_ASKPASS_VALUE for the
// test's scope via t.Setenv). Tests that need to test the real terminal
// path (tty_test.go) explicitly override isTerminalFunc and
// readPasswordFunc, so they continue to work. Tests that explicitly
// test the SSH_ASKPASS path or zenity/kdialog paths (exec_test.go) swap
// shell via useFakeExec, which overrides the blockingExec wrapper.
func init() {
	isTerminalFunc = func(int) bool { return false }

	// Override any external SSH_ASKPASS (e.g. ksshaskpass from the
	// user's shell environment) with our custom script. If the script
	// couldn't be written we leave SSH_ASKPASS unset — that also works
	// (the SSH_ASKPASS branch is skipped, falls through to
	// termPasswordPrompt's default).
	if scriptPath := installCustomSSHAskpass(); scriptPath != "" {
		os.Setenv("SSH_ASKPASS", scriptPath)
	}

	shell = &blockingExec{
		real: osExec{},
		blocked: map[string]bool{
			"zenity":      true,
			"kdialog":     true,
			"ksshaskpass": true,
		},
	}
}

// installCustomSSHAskpass writes a shell script to a temp dir that
// echoes $TEST_ASKPASS_VALUE if set, otherwise exits 1 with no output.
// The exit-1 behavior causes promptWithAskpass to fall through to
// termPasswordPrompt, which then returns "need a terminal to prompt for
// a password" — letting tests like dump.txt exercise their expected
// error path. Returns the script path, or "" if the file couldn't be
// written (in which case the caller leaves SSH_ASKPASS unset).
func installCustomSSHAskpass() string {
	dir, err := os.MkdirTemp("", "bitw-test-askpass-*")
	if err != nil {
		return ""
	}
	script := filepath.Join(dir, "askpass")
	content := "#!/bin/sh\n" +
		"# Custom SSH_ASKPASS for bitw tests.\n" +
		"# Echoes $TEST_ASKPASS_VALUE if set; otherwise exits 1 so the\n" +
		"# prompt chain falls through to termPasswordPrompt's default case.\n" +
		"if [ -n \"$TEST_ASKPASS_VALUE\" ]; then\n" +
		"    echo \"$TEST_ASKPASS_VALUE\"\n" +
		"    exit 0\n" +
		"fi\n" +
		"exit 1\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		return ""
	}
	return script
}

// blockingExec wraps osExec and makes LookPath fail for any name listed
// in the blocked map. Everything else (Output, CombinedOutput, LookPath
// for non-blocked names) delegates to the real osExec. This lets tests
// skip GUI prompt tools like zenity/kdialog/ksshaskpass without breaking
// the rest of the exec layer.
type blockingExec struct {
	real    osExec
	blocked map[string]bool
}

func (b *blockingExec) LookPath(name string) (string, error) {
	if b.blocked[name] {
		return "", fmt.Errorf("blocked by test init: %s", name)
	}
	return b.real.LookPath(name)
}

func (b *blockingExec) Output(env []string, name string, args ...string) ([]byte, error) {
	return b.real.Output(env, name, args...)
}

func (b *blockingExec) CombinedOutput(stdin []byte, name string, args ...string) ([]byte, error) {
	return b.real.CombinedOutput(stdin, name, args...)
}

// setupSSHAskpass sets TEST_ASKPASS_VALUE for the test's scope, which the
// custom SSH_ASKPASS script (installed by init) reads to determine what
// value to return for password prompts. Cleans up automatically via
// t.Setenv.
//
// Example:
//
//	func TestClientId_PromptFallback(t *testing.T) {
//	    setupSSHAskpass(t, "test-client-id")
//	    // ... rest of test
//	}
func setupSSHAskpass(t *testing.T, value string) {
	t.Helper()
	t.Setenv("TEST_ASKPASS_VALUE", value)
}
