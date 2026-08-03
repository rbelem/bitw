// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestCompletions_Bash verifies the bash script contains the required
// commands, flags, totp keyword, COMPREPLY usage, and CONFIG_DIR/names
// fallback logic with the resolveConfigDir()-computed default path.
func TestCompletions_Bash(t *testing.T) {
	c := qt.New(t)
	defaultDir, err := resolveConfigDir()
	c.Assert(err, qt.IsNil)

	stdout := captureStdout(t, func() {
		err := cmdCompletions(context.Background(), []string{"bash"})
		c.Assert(err, qt.IsNil)
	})
	for _, cmd := range completionCommands {
		c.Assert(strings.Contains(stdout, cmd), qt.IsTrue,
			qt.Commentf("bash script missing command %q", cmd))
	}
	c.Assert(strings.Contains(stdout, "totp"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "COMPREPLY"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "names"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "CONFIG_DIR"), qt.IsTrue)
	// Script must embed the resolveConfigDir()-computed default path.
	c.Assert(strings.Contains(stdout, defaultDir), qt.IsTrue,
		qt.Commentf("bash script missing embedded default dir %q", defaultDir))
	c.Assert(strings.Contains(stdout, "--env-name"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "--json"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "--field"), qt.IsTrue)
}

// TestCompletions_Zsh verifies the zsh script contains the required
// commands, flags, totp keyword, compadd usage, and CONFIG_DIR/names
// fallback logic with the resolveConfigDir()-computed default path.
func TestCompletions_Zsh(t *testing.T) {
	c := qt.New(t)
	defaultDir, err := resolveConfigDir()
	c.Assert(err, qt.IsNil)

	stdout := captureStdout(t, func() {
		err := cmdCompletions(context.Background(), []string{"zsh"})
		c.Assert(err, qt.IsNil)
	})
	for _, cmd := range completionCommands {
		c.Assert(strings.Contains(stdout, cmd), qt.IsTrue,
			qt.Commentf("zsh script missing command %q", cmd))
	}
	c.Assert(strings.Contains(stdout, "totp"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "compadd"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "names"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "CONFIG_DIR"), qt.IsTrue)
	// Script must embed the resolveConfigDir()-computed default path.
	c.Assert(strings.Contains(stdout, defaultDir), qt.IsTrue,
		qt.Commentf("zsh script missing embedded default dir %q", defaultDir))
	c.Assert(strings.Contains(stdout, "--env-name"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "--json"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "--field"), qt.IsTrue)
}

// TestCompletions_Fish verifies the fish script contains the required
// commands, flags, totp keyword, __bitw_names function, and
// CONFIG_DIR/names fallback logic with the resolveConfigDir()-computed
// default path.
func TestCompletions_Fish(t *testing.T) {
	c := qt.New(t)
	defaultDir, err := resolveConfigDir()
	c.Assert(err, qt.IsNil)

	stdout := captureStdout(t, func() {
		err := cmdCompletions(context.Background(), []string{"fish"})
		c.Assert(err, qt.IsNil)
	})
	for _, cmd := range completionCommands {
		c.Assert(strings.Contains(stdout, cmd), qt.IsTrue,
			qt.Commentf("fish script missing command %q", cmd))
	}
	c.Assert(strings.Contains(stdout, "totp"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "__bitw_names"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "names"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "CONFIG_DIR"), qt.IsTrue)
	// Script must embed the resolveConfigDir()-computed default path.
	c.Assert(strings.Contains(stdout, defaultDir), qt.IsTrue,
		qt.Commentf("fish script missing embedded default dir %q", defaultDir))
	c.Assert(strings.Contains(stdout, "--env-name"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "--json"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "--field"), qt.IsTrue)
}

// TestCompletions_UnknownShell verifies that an unknown shell name
// returns a usage error.
func TestCompletions_UnknownShell(t *testing.T) {
	c := qt.New(t)
	err := cmdCompletions(context.Background(), []string{"powershell"})
	c.Assert(err, qt.ErrorMatches, "usage:.*")
}

// TestCompletions_NoArgs verifies that missing arguments returns a
// usage error.
func TestCompletions_NoArgs(t *testing.T) {
	c := qt.New(t)
	err := cmdCompletions(context.Background(), nil)
	c.Assert(err, qt.ErrorMatches, "usage:.*")
}

// TestCompletions_BashExecution verifies the bash completion script
// actually works by sourcing it, setting up COMP_WORDS/COMP_CWORD,
// calling the _bitw function, and checking COMPREPLY. This catches
// syntactically broken scripts that substring tests would miss.
// Skipped if bash is not available.
func TestCompletions_BashExecution(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	c := qt.New(t)

	// Create a temp dir with a names file containing a spaced name.
	tmpDir := t.TempDir()
	namesFile := filepath.Join(tmpDir, "names")
	err := os.WriteFile(namesFile, []byte("GitHub Token\nsimple\n"), 0o600)
	c.Assert(err, qt.IsNil)

	// Build the bash script.
	var script string
	scriptOut := captureStdout(t, func() {
		err := cmdCompletions(context.Background(), []string{"bash"})
		c.Assert(err, qt.IsNil)
	})
	script = scriptOut

	// Write the script to a temp file.
	scriptFile := filepath.Join(tmpDir, "completion.bash")
	err = os.WriteFile(scriptFile, []byte(script), 0o600)
	c.Assert(err, qt.IsNil)

	// Run bash with a harness that sources the script, sets up completion
	// state, calls _bitw, and prints COMPREPLY.
	harness := `
source "$1"
COMP_WORDS=(bitw get "GitH")
COMP_CWORD=2
_bitw
printf '%s\n' "${COMPREPLY[@]}"
`
	cmd := exec.Command("bash", "-c", harness, "bash", scriptFile)
	cmd.Env = append(os.Environ(), "CONFIG_DIR="+tmpDir)
	out, err := cmd.CombinedOutput()
	c.Assert(err, qt.IsNil, qt.Commentf("bash output: %s", string(out)))

	// Assert the output contains "GitHub Token" — verifies array-element
	// handling of spaces AND that the file is actually read.
	c.Assert(strings.Contains(string(out), "GitHub Token"), qt.IsTrue,
		qt.Commentf("bash completion output missing 'GitHub Token'; got: %s", string(out)))
}
