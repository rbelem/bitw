// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

// TestCmdCache_DecryptError verifies that cmdCache returns errCacheFailed when
// a cipher's password field fails to decrypt.
func TestCmdCache_DecryptError(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		corruptCipher(t, "cipher-a"),
	}

	manifest := writeManifest(t, dir, `
[cache]
cipher-a = VAR_A
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.Equals, errCacheFailed)
	})

	qt.Assert(t, stderr, qt.Contains, "decrypt field password")
	qt.Assert(t, stderr, qt.Contains, "0/1 items cached, 1 failed")
}

// TestCmdCache_CipherNotFound verifies that cmdCache returns errCacheFailed
// when a cipher in the manifest is not found in the vault.
func TestCmdCache_CipherNotFound(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{}

	manifest := writeManifest(t, dir, `
[cache]
nonexistent = VAR_A
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.Equals, errCacheFailed)
	})

	qt.Assert(t, stderr, qt.Contains, "cipher not found")
	qt.Assert(t, stderr, qt.Contains, "0/1 items cached, 1 failed")
}

// TestCmdCache_NoItems verifies that cmdCache returns errCacheFailed when the
// manifest has no items to cache.
func TestCmdCache_NoItems(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{}

	manifest := writeManifest(t, dir, `
[cache]
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.Equals, errCacheFailed)
	})

	qt.Assert(t, stderr, qt.Contains, "0/0 items cached, 0 failed")
}

// TestCmdCache_Timeout verifies that cmdCache respects the --timeout flag.
func TestCmdCache_Timeout(t *testing.T) {
	dir := setupCacheTest(t)

	// Set up a slow server that delays /sync
	oldApiURL := apiURL
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		json.NewEncoder(w).Encode(SyncData{})
	}))
	apiURL = slowServer.URL
	t.Cleanup(func() {
		apiURL = oldApiURL
		slowServer.Close()
	})

	manifest := writeManifest(t, dir, `
[cache]
cipher-a = VAR_A
`)
	output := filepath.Join(dir, "out.sh")

	err := cmdCache(context.Background(), []string{
		"-config", manifest,
		"-output", output,
		"-timeout", "100ms",
	})
	qt.Assert(t, err, qt.IsNotNil)
}

// TestCmdCache_MirrorLibsecret verifies that cmdCache calls mirrorLibsecretVars
// when --mirror-libsecret is set.
func TestCmdCache_MirrorLibsecret(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "cipher-a", "secret-a"),
	}

	manifest := writeManifest(t, dir, `
[cache]
cipher-a = BW_CLIENTSECRET
`)
	output := filepath.Join(dir, "out.sh")

	// Use fakeExec to mock secret-tool
	fake := &fakeExec{
		combinedFn: func(stdin []byte, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	useFakeExec(t, fake)

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
			"-mirror-libsecret", "BW_CLIENTSECRET",
		})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stderr, qt.Contains, "1/1 items cached, 0 failed")
	qt.Assert(t, len(fake.calls), qt.Equals, 1)
	qt.Assert(t, fake.calls[0][0], qt.Equals, "secret-tool")
}

// TestCmdCache_FieldsSection verifies that cmdCache processes the [cache-fields]
// section correctly.
func TestCmdCache_FieldsSection(t *testing.T) {
	dir := setupCacheTest(t)

	fName := encryptStr(t, "EXTRA_FIELD")
	fVal := encryptStr(t, "extra-val")
	globalData.Sync.Ciphers = []Cipher{
		{
			Type: CipherLogin,
			Name: encryptStr(t, "cipher-a"),
			Login: &Login{
				Password: encryptStr(t, "secret-a"),
			},
			Fields: []Field{
				{Name: fName, Value: fVal},
			},
		},
	}

	manifest := writeManifest(t, dir, `
[cache-fields]
cipher-a = EXTRA_FIELD
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stderr, qt.Contains, "1/1 items cached, 0 failed")

	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, content, qt.Contains, "export EXTRA_FIELD=")
}

// TestCmdCache_AliasesSection verifies that cmdCache processes the [cache-aliases]
// section correctly.
func TestCmdCache_AliasesSection(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "cipher-a", "secret-a"),
	}

	manifest := writeManifest(t, dir, `
[cache]
cipher-a = VAR_A

[cache-aliases]
ALIAS_A = VAR_A
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stderr, qt.Contains, "1/1 items cached, 0 failed")

	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, content, qt.Contains, "export ALIAS_A=$VAR_A")
}

// TestCmdCache_InvalidAliasName verifies that cmdCache skips aliases with
// invalid shell identifier names.
func TestCmdCache_InvalidAliasName(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "cipher-a", "secret-a"),
	}

	manifest := writeManifest(t, dir, `
[cache]
cipher-a = VAR_A

[cache-aliases]
invalid-alias = VAR_A
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stderr, qt.Contains, "1/1 items cached, 0 failed")

	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, content, qt.Not(qt.Contains), "invalid-alias")
}

// TestCmdCache_OutputDirCreation verifies that cmdCache creates the output
// directory if it doesn't exist.
func TestCmdCache_OutputDirCreation(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "cipher-a", "secret-a"),
	}

	manifest := writeManifest(t, dir, `
[cache]
cipher-a = VAR_A
`)
	output := filepath.Join(dir, "subdir", "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stderr, qt.Contains, "1/1 items cached, 0 failed")

	// Verify the file was created
	_, err := os.Stat(output)
	qt.Assert(t, err, qt.IsNil)
}

// TestCmdCache_ParseError verifies that cmdCache returns an error when flag
// parsing fails.
func TestCmdCache_ParseError(t *testing.T) {
	setupCacheTest(t)

	err := cmdCache(context.Background(), []string{"-invalid-flag"})
	qt.Assert(t, err, qt.IsNotNil)
}
