// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"os/exec"
)

// execRunner abstracts os/exec so command execution can be faked in tests.
// The production implementation (osExec) is byte-for-byte identical to the
// current direct exec.Command calls.
type execRunner interface {
	// LookPath reports whether name is on PATH (exec.LookPath).
	LookPath(name string) (string, error)

	// Output runs name with args and returns stdout (exec.Cmd.Output).
	// If env != nil it replaces the child's environment (exec.Cmd.Env).
	Output(env []string, name string, args ...string) ([]byte, error)

	// CombinedOutput runs name with args, feeding stdin, and returns
	// combined stdout+stderr (exec.Cmd.CombinedOutput with Cmd.Stdin set).
	CombinedOutput(stdin []byte, name string, args ...string) ([]byte, error)
}

type osExec struct{}

func (osExec) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (osExec) Output(env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	return cmd.Output()
}

func (osExec) CombinedOutput(stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.CombinedOutput()
}

// shell is the process-wide command runner; tests swap it (house style —
// same pattern as passwordPromptFunc/readLineFunc at auth.go:137-138).
var shell execRunner = osExec{}
