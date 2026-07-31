// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestMain1_NoArgs verifies that main1 returns 2 when no args are provided
// (triggers flag.ErrHelp via run).
func TestMain1_NoArgs(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	os.Args = []string{"bitw"}
	code := main1(&bytes.Buffer{})
	qt.Assert(t, code, qt.Equals, 2)
}

// TestMain1_Help verifies that main1 returns 2 when "help" is provided
// (triggers flag.ErrHelp via run).
func TestMain1_Help(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	os.Args = []string{"bitw", "help"}
	code := main1(&bytes.Buffer{})
	qt.Assert(t, code, qt.Equals, 2)
}

// TestMain1_UnknownCommand verifies that main1 returns 2 when an unknown
// command is provided (triggers flag.ErrHelp via run).
func TestMain1_UnknownCommand(t *testing.T) {
	origArgs := os.Args
	origConfigDir := os.Getenv("CONFIG_DIR")
	t.Cleanup(func() {
		os.Args = origArgs
		os.Setenv("CONFIG_DIR", origConfigDir)
	})

	tmpDir := t.TempDir()
	os.Setenv("CONFIG_DIR", tmpDir)

	// Create empty config
	err := os.WriteFile(tmpDir+"/config", []byte(""), 0o600)
	qt.Assert(t, err, qt.IsNil)

	os.Args = []string{"bitw", "unknown-command"}
	code := main1(&bytes.Buffer{})
	qt.Assert(t, code, qt.Equals, 2)
}

// TestMain1_FlagParseError verifies that main1 returns 2 when flag parsing fails.
func TestMain1_FlagParseError(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	// Set an invalid flag to trigger parse error
	os.Args = []string{"bitw", "-invalid-flag"}
	code := main1(&bytes.Buffer{})
	qt.Assert(t, code, qt.Equals, 2)
}
