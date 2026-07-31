// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"fmt"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

// fakeExec is a test double for execRunner that records calls and returns
// canned responses.
type fakeExec struct {
	lookPathFn func(string) (string, error)
	outputFn   func(env []string, name string, args ...string) ([]byte, error)
	combinedFn func(stdin []byte, name string, args ...string) ([]byte, error)
	calls      [][]string // recorded argv per Output/CombinedOutput call
	stdins     [][]byte   // recorded stdin per CombinedOutput call
	envs       [][]string // recorded env per Output call (nil = inherit)
}

func (f *fakeExec) LookPath(n string) (string, error) {
	if f.lookPathFn != nil {
		return f.lookPathFn(n)
	}
	return "", fmt.Errorf("not found: %s", n)
}

func (f *fakeExec) Output(env []string, n string, a ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{n}, a...))
	f.envs = append(f.envs, env)
	if f.outputFn != nil {
		return f.outputFn(env, n, a...)
	}
	return nil, nil
}

func (f *fakeExec) CombinedOutput(stdin []byte, n string, a ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{n}, a...))
	f.stdins = append(f.stdins, stdin)
	if f.combinedFn != nil {
		return f.combinedFn(stdin, n, a...)
	}
	return nil, nil
}

// useFakeExec swaps the global shell var with a fake and restores it on cleanup.
func useFakeExec(t *testing.T, f *fakeExec) {
	t.Helper()
	old := shell
	shell = f
	t.Cleanup(func() { shell = old })
}

// TestStorePasswordLibsecret_StoreFailure verifies that storePasswordLibsecret
// warns when secret-tool fails to store the password.
func TestStorePasswordLibsecret_StoreFailure(t *testing.T) {
	fake := &fakeExec{
		lookPathFn: func(name string) (string, error) {
			if name == "secret-tool" {
				return "/usr/bin/secret-tool", nil
			}
			return "", fmt.Errorf("not found")
		},
		combinedFn: func(stdin []byte, name string, args ...string) ([]byte, error) {
			return []byte("error output"), fmt.Errorf("store failed")
		},
	}
	useFakeExec(t, fake)

	stderr := captureStderr(t, func() {
		storePasswordLibsecret([]byte("test-password"))
	})

	qt.Assert(t, stderr, qt.Contains, "could not store master password")
	qt.Assert(t, stderr, qt.Contains, "store failed")
	qt.Assert(t, len(fake.calls), qt.Equals, 1)
	qt.Assert(t, fake.calls[0][0], qt.Equals, "secret-tool")
	// Verify stdin includes the password + newline
	qt.Assert(t, string(fake.stdins[0]), qt.Equals, "test-password\n")
}

// TestStorePasswordLibsecret_Success verifies that storePasswordLibsecret
// calls secret-tool with the correct argv and stdin.
func TestStorePasswordLibsecret_Success(t *testing.T) {
	fake := &fakeExec{
		lookPathFn: func(name string) (string, error) {
			if name == "secret-tool" {
				return "/usr/bin/secret-tool", nil
			}
			return "", fmt.Errorf("not found")
		},
		combinedFn: func(stdin []byte, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	useFakeExec(t, fake)

	captureStderr(t, func() {
		storePasswordLibsecret([]byte("my-password"))
	})

	qt.Assert(t, len(fake.calls), qt.Equals, 1)
	qt.Assert(t, fake.calls[0], qt.DeepEquals, []string{
		"secret-tool", "store", "--label=Bitwarden", "bitwarden", "master-password",
	})
	qt.Assert(t, string(fake.stdins[0]), qt.Equals, "my-password\n")
}

// TestPromptWithAskpass_Zenity verifies that promptWithAskpass tries zenity
// first and returns its output.
func TestPromptWithAskpass_Zenity(t *testing.T) {
	fake := &fakeExec{
		lookPathFn: func(name string) (string, error) {
			if name == "zenity" {
				return "/usr/bin/zenity", nil
			}
			return "", fmt.Errorf("not found")
		},
		outputFn: func(env []string, name string, args ...string) ([]byte, error) {
			return []byte("zenity-password\n"), nil
		},
	}
	useFakeExec(t, fake)

	pw, err := promptWithAskpass("Enter password")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(pw), qt.Equals, "zenity-password")
	qt.Assert(t, len(fake.calls), qt.Equals, 1)
	qt.Assert(t, fake.calls[0][0], qt.Equals, "/usr/bin/zenity")
	qt.Assert(t, fake.calls[0][1], qt.Equals, "--password")
	qt.Assert(t, fake.calls[0][2], qt.Equals, "--title=Enter password")
}

// TestPromptWithAskpass_Kdialog verifies that promptWithAskpass falls back to
// kdialog when zenity is not found.
func TestPromptWithAskpass_Kdialog(t *testing.T) {
	fake := &fakeExec{
		lookPathFn: func(name string) (string, error) {
			if name == "kdialog" {
				return "/usr/bin/kdialog", nil
			}
			return "", fmt.Errorf("not found")
		},
		outputFn: func(env []string, name string, args ...string) ([]byte, error) {
			return []byte("kdialog-password\n"), nil
		},
	}
	useFakeExec(t, fake)

	pw, err := promptWithAskpass("Enter password")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(pw), qt.Equals, "kdialog-password")
	qt.Assert(t, len(fake.calls), qt.Equals, 1)
	qt.Assert(t, fake.calls[0][0], qt.Equals, "/usr/bin/kdialog")
	qt.Assert(t, fake.calls[0][1], qt.Equals, "--password")
	qt.Assert(t, fake.calls[0][2], qt.Equals, "Enter password")
}

// TestPromptWithAskpass_SSH_ASKPASS verifies that promptWithAskpass falls back
// to SSH_ASKPASS when zenity and kdialog are not found.
func TestPromptWithAskpass_SSH_ASKPASS(t *testing.T) {
	origAskpass := os.Getenv("SSH_ASKPASS")
	origDisplay := os.Getenv("DISPLAY")
	t.Cleanup(func() {
		os.Setenv("SSH_ASKPASS", origAskpass)
		os.Setenv("DISPLAY", origDisplay)
	})

	os.Setenv("SSH_ASKPASS", "/usr/bin/my-askpass")
	os.Unsetenv("DISPLAY") // Should default to :0

	fake := &fakeExec{
		lookPathFn: func(name string) (string, error) {
			if name == "/usr/bin/my-askpass" {
				return "/usr/bin/my-askpass", nil
			}
			return "", fmt.Errorf("not found")
		},
		outputFn: func(env []string, name string, args ...string) ([]byte, error) {
			return []byte("ssh-askpass-secret\n"), nil
		},
	}
	useFakeExec(t, fake)

	pw, err := promptWithAskpass("Enter password")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(pw), qt.Equals, "ssh-askpass-secret")
	qt.Assert(t, len(fake.calls), qt.Equals, 1)
	qt.Assert(t, fake.calls[0][0], qt.Equals, "/usr/bin/my-askpass")
	qt.Assert(t, fake.calls[0][1], qt.Equals, "Enter password")
	// Verify DISPLAY env was set to :0
	qt.Assert(t, len(fake.envs), qt.Equals, 1)
	hasDisplay := false
	for _, e := range fake.envs[0] {
		if string(e) == "DISPLAY=:0" {
			hasDisplay = true
			break
		}
	}
	qt.Assert(t, hasDisplay, qt.IsTrue)
}

// TestPromptWithAskpass_SSH_ASKPASS_Failure verifies that promptWithAskpass
// falls through to terminal when SSH_ASKPASS fails.
func TestPromptWithAskpass_SSH_ASKPASS_Failure(t *testing.T) {
	origAskpass := os.Getenv("SSH_ASKPASS")
	t.Cleanup(func() {
		os.Setenv("SSH_ASKPASS", origAskpass)
	})

	os.Setenv("SSH_ASKPASS", "/usr/bin/failing-askpass")

	fake := &fakeExec{
		lookPathFn: func(name string) (string, error) {
			if name == "/usr/bin/failing-askpass" {
				return "/usr/bin/failing-askpass", nil
			}
			return "", fmt.Errorf("not found")
		},
		outputFn: func(env []string, name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("askpass failed")
		},
	}
	useFakeExec(t, fake)

	// This will fall through to termPasswordPrompt, which will fail because
	// we're not in a terminal. That's expected.
	stderr := captureStderr(t, func() {
		_, _ = promptWithAskpass("Enter password")
	})

	qt.Assert(t, stderr, qt.Contains, "SSH_ASKPASS=/usr/bin/failing-askpass failed")
}

// TestMirrorLibsecretVars_Success verifies that mirrorLibsecretVars calls
// secret-tool with the correct argv and stdin.
func TestMirrorLibsecretVars_Success(t *testing.T) {
	fake := &fakeExec{
		combinedFn: func(stdin []byte, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	useFakeExec(t, fake)

	values := map[string]string{
		"BW_CLIENTSECRET": "my-client-secret",
		"BW_CLIENTID":     "my-client-id",
	}

	captureStderr(t, func() {
		mirrorLibsecretVars("BW_CLIENTSECRET,BW_CLIENTID", values)
	})

	qt.Assert(t, len(fake.calls), qt.Equals, 2)
	// First call: BW_CLIENTSECRET
	qt.Assert(t, fake.calls[0], qt.DeepEquals, []string{
		"secret-tool", "store", "--label=Bitwarden API key", "bitwarden", "api-key-secret",
	})
	qt.Assert(t, string(fake.stdins[0]), qt.Equals, "my-client-secret")
	// Second call: BW_CLIENTID
	qt.Assert(t, fake.calls[1], qt.DeepEquals, []string{
		"secret-tool", "store", "--label=Bitwarden API key", "bitwarden", "api-key-client-id",
	})
	qt.Assert(t, string(fake.stdins[1]), qt.Equals, "my-client-id")
}

// TestMirrorLibsecretVars_MissingValue verifies that mirrorLibsecretVars warns
// when a requested var is not in the values map.
func TestMirrorLibsecretVars_MissingValue(t *testing.T) {
	fake := &fakeExec{}
	useFakeExec(t, fake)

	values := map[string]string{} // Empty

	stderr := captureStderr(t, func() {
		mirrorLibsecretVars("BW_CLIENTSECRET", values)
	})

	qt.Assert(t, stderr, qt.Contains, "not decrypted by this run")
	qt.Assert(t, len(fake.calls), qt.Equals, 0) // No exec calls
}

// TestMirrorLibsecretVars_UnknownAttr verifies that mirrorLibsecretVars warns
// when a var has no semantic attribute mapping.
func TestMirrorLibsecretVars_UnknownAttr(t *testing.T) {
	fake := &fakeExec{
		combinedFn: func(stdin []byte, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	useFakeExec(t, fake)

	values := map[string]string{
		"UNKNOWN_VAR": "some-value",
	}

	stderr := captureStderr(t, func() {
		mirrorLibsecretVars("UNKNOWN_VAR", values)
	})

	qt.Assert(t, stderr, qt.Contains, "no semantic libsecret attribute mapping")
	qt.Assert(t, len(fake.calls), qt.Equals, 1)
	// Should still write under the env var name itself
	qt.Assert(t, fake.calls[0], qt.DeepEquals, []string{
		"secret-tool", "store", "--label=Bitwarden API key", "bitwarden", "UNKNOWN_VAR",
	})
}

// TestMirrorLibsecretVars_StoreFailure verifies that mirrorLibsecretVars warns
// when secret-tool fails.
func TestMirrorLibsecretVars_StoreFailure(t *testing.T) {
	fake := &fakeExec{
		combinedFn: func(stdin []byte, name string, args ...string) ([]byte, error) {
			return []byte("mirror error"), fmt.Errorf("mirror failed")
		},
	}
	useFakeExec(t, fake)

	values := map[string]string{
		"BW_CLIENTSECRET": "my-secret",
	}

	stderr := captureStderr(t, func() {
		mirrorLibsecretVars("BW_CLIENTSECRET", values)
	})

	qt.Assert(t, stderr, qt.Contains, "could not mirror")
	qt.Assert(t, stderr, qt.Contains, "mirror failed")
}
