// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"io"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestTermPasswordPrompt_Terminal verifies that termPasswordPrompt reads from
// the terminal when isTerminalFunc returns true.
func TestTermPasswordPrompt_Terminal(t *testing.T) {
	oldIs, oldRead := isTerminalFunc, readPasswordFunc
	isTerminalFunc = func(int) bool { return true }
	readPasswordFunc = func(int) ([]byte, error) { return []byte("hunter2"), nil }
	t.Cleanup(func() { isTerminalFunc, readPasswordFunc = oldIs, oldRead })

	stderr := captureStderr(t, func() {
		pw, err := termPasswordPrompt("Password")
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, string(pw), qt.Equals, "hunter2")
	})

	qt.Assert(t, stderr, qt.Contains, "Password: ")
}

// TestTermPasswordPrompt_TerminalEmpty verifies that termPasswordPrompt returns
// io.ErrUnexpectedEOF when the terminal returns an empty password.
func TestTermPasswordPrompt_TerminalEmpty(t *testing.T) {
	oldIs, oldRead := isTerminalFunc, readPasswordFunc
	isTerminalFunc = func(int) bool { return true }
	readPasswordFunc = func(int) ([]byte, error) { return []byte{}, nil }
	t.Cleanup(func() { isTerminalFunc, readPasswordFunc = oldIs, oldRead })

	captureStderr(t, func() {
		_, err := termPasswordPrompt("Password")
		qt.Assert(t, err, qt.Equals, io.ErrUnexpectedEOF)
	})
}

// TestTermPasswordPrompt_TerminalError verifies that termPasswordPrompt
// propagates errors from readPasswordFunc.
func TestTermPasswordPrompt_TerminalError(t *testing.T) {
	oldIs, oldRead := isTerminalFunc, readPasswordFunc
	isTerminalFunc = func(int) bool { return true }
	readPasswordFunc = func(int) ([]byte, error) { return nil, io.EOF }
	t.Cleanup(func() { isTerminalFunc, readPasswordFunc = oldIs, oldRead })

	captureStderr(t, func() {
		_, err := termPasswordPrompt("Password")
		qt.Assert(t, err, qt.Equals, io.EOF)
	})
}

// TestTermPasswordPrompt_ForceStdin verifies that termPasswordPrompt reads
// from stdin via readLineFunc when FORCE_STDIN_PROMPTS=true and not a terminal.
func TestTermPasswordPrompt_ForceStdin(t *testing.T) {
	oldIs := isTerminalFunc
	oldReadLine := readLineFunc
	isTerminalFunc = func(int) bool { return false }
	readLineFunc = func(prompt string) ([]byte, error) { return []byte("stdin-password"), nil }
	t.Setenv("FORCE_STDIN_PROMPTS", "true")
	t.Cleanup(func() {
		isTerminalFunc = oldIs
		readLineFunc = oldReadLine
	})

	pw, err := termPasswordPrompt("Password")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(pw), qt.Equals, "stdin-password")
}

// TestTermPasswordPrompt_NoTerminal verifies that termPasswordPrompt returns
// an error when not a terminal and FORCE_STDIN_PROMPTS is not set.
func TestTermPasswordPrompt_NoTerminal(t *testing.T) {
	oldIs := isTerminalFunc
	isTerminalFunc = func(int) bool { return false }
	t.Setenv("FORCE_STDIN_PROMPTS", "")
	t.Cleanup(func() { isTerminalFunc = oldIs })

	_, err := termPasswordPrompt("Password")
	qt.Assert(t, err, qt.ErrorMatches, "need a terminal to prompt for a password")
}

// TestReadLine_EOFWithPartialLine verifies that readLine returns the partial
// line when EOF is encountered before a newline.
func TestReadLine_EOFWithPartialLine(t *testing.T) {
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()

	r, w, err := os.Pipe()
	qt.Assert(t, err, qt.IsNil)
	os.Stdin = r

	go func() {
		defer w.Close()
		w.WriteString("partial")
	}()

	line, err := readLine("prompt")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(line), qt.Equals, "partial")
}
