// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

// The tests below mutate package globals (os.Args, os.Stdout via
// captureStdout, and the showVersion flag via main1 → flagSet.Parse).
// Do NOT add t.Parallel() to these tests or to any sibling test touching
// os.Args/main1/os.Stdout — it would race on the globals.

// TestMain1_Version verifies that `bitw --version` prints the version and
// exits 0 without touching the config (no CONFIG_DIR is set, so a config
// load would fail — the short-circuit must happen before run()).
func TestMain1_Version(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"bitw", "--version"}

	var code int
	output := captureStdout(t, func() {
		code = main1(&bytes.Buffer{})
	})
	qt.Assert(t, code, qt.Equals, 0)
	qt.Assert(t, output, qt.Equals, "bitw "+version+"\n")
}

// TestMain1_VersionShortForm verifies the single-dash form, which the Go
// flag package accepts as an alias.
func TestMain1_VersionShortForm(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"bitw", "-version"}

	var code int
	output := captureStdout(t, func() {
		code = main1(&bytes.Buffer{})
	})
	qt.Assert(t, code, qt.Equals, 0)
	qt.Assert(t, output, qt.Equals, "bitw "+version+"\n")
}
