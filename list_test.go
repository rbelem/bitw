// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

// setupListTest initializes secrets and globalData for cmdList tests.
// Mirrors the setup pattern from cmdget_test.go.
func setupListTest(t *testing.T) {
	t.Helper()
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	if err := secrets.initKeys(); err != nil {
		t.Fatalf("initKeys: %v", err)
	}
}

// TestList_SortedOutput_MixedTypes verifies that cmdList prints a TSV header
// and one row per cipher sorted by name, with correct type labels and
// decrypted usernames.
func TestList_SortedOutput_MixedTypes(t *testing.T) {
	setupListTest(t)

	loginCipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Zebra Login"),
		Login: &Login{
			Username: encryptStr(t, "zebra-user"),
			Password: encryptStr(t, "pw"),
		},
	}
	noteCipher := Cipher{
		Type: CipherNote,
		Name: encryptStr(t, "Alpha Note"),
	}
	sshCipher := Cipher{
		Type: CipherSshKey,
		Name: encryptStr(t, "Middle SSH"),
		SshKey: &SshKey{
			PrivateKey: encryptStr(t, "key"),
		},
	}
	loginNoUser := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Beta NoUser"),
		Login: &Login{
			Password: encryptStr(t, "pw"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{loginCipher, noteCipher, sshCipher, loginNoUser},
		},
	}

	stdout := captureStdout(t, func() {
		err := cmdList(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	qt.Assert(t, lines[0], qt.Equals, "name\tusername\ttype")
	qt.Assert(t, len(lines), qt.Equals, 5) // header + 4 ciphers
	// Sorted by name: Alpha Note, Beta NoUser, Middle SSH, Zebra Login
	qt.Assert(t, lines[1], qt.Equals, "Alpha Note\t\tnote")
	qt.Assert(t, lines[2], qt.Equals, "Beta NoUser\t\tlogin")
	qt.Assert(t, lines[3], qt.Equals, "Middle SSH\t\tssh")
	qt.Assert(t, lines[4], qt.Equals, "Zebra Login\tzebra-user\tlogin")
}

// TestList_NamesOnly verifies that --names-only prints just sorted names,
// one per line, with no header.
func TestList_NamesOnly(t *testing.T) {
	setupListTest(t)

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{Type: CipherLogin, Name: encryptStr(t, "Charlie"), Login: &Login{}},
				{Type: CipherNote, Name: encryptStr(t, "Alpha")},
				{Type: CipherLogin, Name: encryptStr(t, "Bravo"), Login: &Login{}},
			},
		},
	}

	stdout := captureStdout(t, func() {
		err := cmdList(context.Background(), []string{"--names-only"})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stdout, qt.Equals, "Alpha\nBravo\nCharlie\n")
}

// TestList_NamesFile verifies that cmdList writes the sorted names to
// resolveConfigDir()/names with 0600 permissions.
func TestList_NamesFile(t *testing.T) {
	setupListTest(t)

	dir := t.TempDir()
	origConfigDir := os.Getenv("CONFIG_DIR")
	os.Setenv("CONFIG_DIR", dir)
	t.Cleanup(func() { os.Setenv("CONFIG_DIR", origConfigDir) })

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{Type: CipherLogin, Name: encryptStr(t, "Gamma"), Login: &Login{}},
				{Type: CipherNote, Name: encryptStr(t, "Alpha")},
				{Type: CipherLogin, Name: encryptStr(t, "Beta"), Login: &Login{}},
			},
		},
	}

	captureStdout(t, func() {
		err := cmdList(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})

	namesPath := filepath.Join(dir, "names")
	data, err := ioutil.ReadFile(namesPath)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(data), qt.Equals, "Alpha\nBeta\nGamma\n")

	info, err := os.Stat(namesPath)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, info.Mode().Perm(), qt.Equals, os.FileMode(0o600))
}

// TestList_DecryptFailureWarning verifies that a cipher whose name cannot be
// decrypted produces a warning on stderr and is skipped from output.
func TestList_DecryptFailureWarning(t *testing.T) {
	setupListTest(t)

	goodCipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Good Cipher"),
		Login: &Login{
			Username: encryptStr(t, "user"),
		},
	}
	badCipher := corruptNameCipher(t, "pw")

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{goodCipher, badCipher},
		},
	}

	stdout := captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			err := cmdList(context.Background(), nil)
			qt.Assert(t, err, qt.IsNil)
		})
		qt.Assert(t, stderr, qt.Contains, "warning: could not decrypt name of cipher")
		qt.Assert(t, stderr, qt.Contains, "00000000-0000-0000-0000-000000000bad")
	})

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	qt.Assert(t, len(lines), qt.Equals, 2) // header + 1 good cipher
	qt.Assert(t, lines[1], qt.Equals, "Good Cipher\tuser\tlogin")
}

// TestList_EmptyVault verifies that an empty vault prints only the header
// (or nothing for --names-only), writes an empty names file, and exits 0.
func TestList_EmptyVault(t *testing.T) {
	setupListTest(t)

	dir := t.TempDir()
	origConfigDir := os.Getenv("CONFIG_DIR")
	os.Setenv("CONFIG_DIR", dir)
	t.Cleanup(func() { os.Setenv("CONFIG_DIR", origConfigDir) })

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: nil,
		},
	}

	// Default mode: header only.
	stdout := captureStdout(t, func() {
		err := cmdList(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, stdout, qt.Equals, "name\tusername\ttype\n")

	// Names file should be empty.
	data, err := ioutil.ReadFile(filepath.Join(dir, "names"))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(data), qt.Equals, "")

	// --names-only mode: nothing.
	stdout = captureStdout(t, func() {
		err := cmdList(context.Background(), []string{"--names-only"})
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, stdout, qt.Equals, "")
}

// TestList_UnknownType verifies that unknown cipher types get "type-N" labels.
func TestList_UnknownType(t *testing.T) {
	setupListTest(t)

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{Type: CipherCard, Name: encryptStr(t, "My Card")},
				{Type: CipherIdentity, Name: encryptStr(t, "My ID")},
			},
		},
	}

	stdout := captureStdout(t, func() {
		err := cmdList(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stdout, qt.Contains, "My Card\t\ttype-3")
	qt.Assert(t, stdout, qt.Contains, "My ID\t\ttype-4")
}

// TestList_ControlCharsInNames verifies that control characters (newlines, tabs)
// in cipher names are sanitized to spaces in both TSV output and names file.
func TestList_ControlCharsInNames(t *testing.T) {
	setupListTest(t)

	dir := t.TempDir()
	origConfigDir := os.Getenv("CONFIG_DIR")
	os.Setenv("CONFIG_DIR", dir)
	t.Cleanup(func() { os.Setenv("CONFIG_DIR", origConfigDir) })

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{Type: CipherLogin, Name: encryptStr(t, "foo\nbar"), Login: &Login{}},
				{Type: CipherNote, Name: encryptStr(t, "baz\tqux")},
				{Type: CipherLogin, Name: encryptStr(t, "normal"), Login: &Login{}},
			},
		},
	}

	stdout := captureStdout(t, func() {
		err := cmdList(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})

	// TSV output should have exactly 4 lines (header + 3 ciphers).
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	qt.Assert(t, len(lines), qt.Equals, 4)
	// No raw newlines in the output (each line should be a single TSV row).
	for _, line := range lines {
		qt.Assert(t, strings.Contains(line, "\n"), qt.IsFalse)
	}
	// Control chars should be replaced with spaces.
	qt.Assert(t, lines[1], qt.Equals, "baz qux\t\tnote")
	qt.Assert(t, lines[2], qt.Equals, "foo bar\t\tlogin")
	qt.Assert(t, lines[3], qt.Equals, "normal\t\tlogin")

	// Names file should have exactly 3 lines (sanitized).
	data, err := ioutil.ReadFile(filepath.Join(dir, "names"))
	qt.Assert(t, err, qt.IsNil)
	namesLines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	qt.Assert(t, len(namesLines), qt.Equals, 3)
	qt.Assert(t, namesLines[0], qt.Equals, "baz qux")
	qt.Assert(t, namesLines[1], qt.Equals, "foo bar")
	qt.Assert(t, namesLines[2], qt.Equals, "normal")
}

// TestList_NamesFileAtomicity verifies that the names file is written atomically
// and that permissions are set to 0600 even if the file pre-exists with 0644.
func TestList_NamesFileAtomicity(t *testing.T) {
	setupListTest(t)

	dir := t.TempDir()
	origConfigDir := os.Getenv("CONFIG_DIR")
	os.Setenv("CONFIG_DIR", dir)
	t.Cleanup(func() { os.Setenv("CONFIG_DIR", origConfigDir) })

	// Pre-create names file with loose permissions.
	namesPath := filepath.Join(dir, "names")
	err := ioutil.WriteFile(namesPath, []byte("old\n"), 0o644)
	qt.Assert(t, err, qt.IsNil)

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{Type: CipherLogin, Name: encryptStr(t, "NewCipher"), Login: &Login{}},
			},
		},
	}

	captureStdout(t, func() {
		err := cmdList(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})

	// Verify permissions are now 0600.
	info, err := os.Stat(namesPath)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, info.Mode().Perm(), qt.Equals, os.FileMode(0o600))

	// Verify content was updated.
	data, err := ioutil.ReadFile(namesPath)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(data), qt.Equals, "NewCipher\n")
}

// TestList_MkdirAllFailure verifies that when MkdirAll fails (e.g., parent is a file),
// the command still succeeds but warns on stderr.
func TestList_MkdirAllFailure(t *testing.T) {
	setupListTest(t)

	// Create a blocker file so MkdirAll(dir/blocker/names) fails.
	blockerDir := t.TempDir()
	blockerFile := filepath.Join(blockerDir, "blocker")
	err := ioutil.WriteFile(blockerFile, []byte("I am a file"), 0o644)
	qt.Assert(t, err, qt.IsNil)

	// Point CONFIG_DIR at a path that requires MkdirAll through the blocker file.
	badConfigDir := filepath.Join(blockerFile, "names")
	origConfigDir := os.Getenv("CONFIG_DIR")
	os.Setenv("CONFIG_DIR", badConfigDir)
	t.Cleanup(func() { os.Setenv("CONFIG_DIR", origConfigDir) })

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{Type: CipherLogin, Name: encryptStr(t, "Test"), Login: &Login{}},
			},
		},
	}

	stdout := captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			err := cmdList(context.Background(), nil)
			qt.Assert(t, err, qt.IsNil) // Command should still succeed.
		})
		// Should warn about MkdirAll failure.
		qt.Assert(t, stderr, qt.Contains, "warning: could not create config dir")
	})

	// Output should still be produced.
	qt.Assert(t, stdout, qt.Contains, "Test")
}
