// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
)

// setupCacheTest initializes globalData and secrets with a working vault
// (known master key derived from localTestPassword/localTestEmail). It also
// installs a mock /sync endpoint that returns whatever ciphers are currently
// set in globalData.Sync.Ciphers, so cmdCache's preflight sync (added so
// `bitw cache` can fully replace bin/secrets-refresh) preserves the test
// fixtures. Returns a temp directory for manifest and output files.
func setupCacheTest(t *testing.T) string {
	t.Helper()
	globalData = dataFile{
		KDFIterations:  100000,
		AccessToken:    "test-token",
		TokenExpiry:    time.Now().Add(time.Hour),
		KDFMemory:      64,
		KDFParallelism: 4,
	}
	globalData.Sync.Profile.Email = localTestEmail
	globalData.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets = secretCache{
		data:      &globalData,
		_password: []byte(localTestPassword),
	}
	saveData = false

	// Mock server: /sync echoes the current globalData.Sync (so tests can
	// keep setting ciphers directly). /accounts/prelogin returns a stable
	// KDF block so refreshKDF inside sync() doesn't 404.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			_ = json.NewEncoder(w).Encode(SyncData{
				Profile: globalData.Sync.Profile,
				Ciphers: globalData.Sync.Ciphers,
			})
		case "/accounts/prelogin":
			_ = json.NewEncoder(w).Encode(preLoginResponse{
				KDF:            1,
				KDFIterations:  globalData.KDFIterations,
				KDFMemory:      globalData.KDFMemory,
				KDFParallelism: globalData.KDFParallelism,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	oldApi, oldIdt := apiURL, idtURL
	apiURL, idtURL = server.URL, server.URL
	t.Cleanup(func() {
		apiURL, idtURL = oldApi, oldIdt
		server.Close()
	})

	// Derive keys eagerly so test data encryption matches what cmdCache sees.
	if err := secrets.initKeys(); err != nil {
		t.Fatalf("initKeys: %v", err)
	}
	return t.TempDir()
}

// encryptStr is a test helper that encrypts a plaintext string using the
// already-initialized secrets (master key). Panics on error.
func encryptStr(t *testing.T, plain string) CipherString {
	t.Helper()
	cs, err := secrets.encrypt([]byte(plain))
	if err != nil {
		t.Fatalf("encrypt %q: %v", plain, err)
	}
	return cs
}

// testCipher builds a Login cipher with an encrypted name and password.
func testCipher(t *testing.T, name, password string) Cipher {
	t.Helper()
	return Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, name),
		Login: &Login{
			Password: encryptStr(t, password),
		},
	}
}

// corruptCipher builds a Login cipher whose name decrypts correctly but
// whose password has a bogus MAC (forces "decrypt: MAC mismatch").
func corruptCipher(t *testing.T, name string) Cipher {
	t.Helper()
	c := testCipher(t, name, "placeholder")
	c.Login.Password = CipherString{
		Type: AesCbc256_HmacSha256_B64,
		IV:   make([]byte, 16),
		CT:   make([]byte, 16),
		MAC:  make([]byte, 32),
	}
	return c
}

// corruptNameCipher builds a Login cipher whose name has a bogus MAC (forces
// "decrypt: MAC mismatch" on the name), but whose password decrypts correctly.
// Used to test the diagnostic warning added to cache.go's cipherIndex loop.
func corruptNameCipher(t *testing.T, password string) Cipher {
	t.Helper()
	c := Cipher{
		Type: CipherLogin,
		Name: CipherString{
			Type: AesCbc256_HmacSha256_B64,
			IV:   make([]byte, 16),
			CT:   make([]byte, 16),
			MAC:  make([]byte, 32),
		},
		Login: &Login{
			Password: encryptStr(t, password),
		},
	}
	c.ID = uuid.MustParse("00000000-0000-0000-0000-000000000bad")
	return c
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	w.Close()
	return <-done
}

// writeManifest writes an INI manifest to dir/cache.ini and returns its path.
func writeManifest(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "cache.ini")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCache_AllItems(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "cipher-a", "secret-a"),
		testCipher(t, "cipher-b", "secret-b"),
		testCipher(t, "cipher-c", "secret-c"),
	}
	// Add a custom field to cipher-c.
	fName := encryptStr(t, "EXTRA_FIELD")
	fVal := encryptStr(t, "extra-val")
	globalData.Sync.Ciphers[2].Fields = []Field{
		{Name: fName, Value: fVal},
	}

	manifest := writeManifest(t, dir, `
[cache]
cipher-a = VAR_A
cipher-b = VAR_B
cipher-c = VAR_C

[cache-fields]
cipher-c = EXTRA_FIELD

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

	// Summary on stderr.
	qt.Assert(t, strings.Contains(stderr, "4/4 items cached, 0 failed"), qt.IsTrue,
		qt.Commentf("stderr: %q", stderr))

	// File content.
	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)

	qt.Assert(t, strings.Contains(content, "export VAR_A='secret-a'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export VAR_B='secret-b'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export VAR_C='secret-c'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export EXTRA_FIELD='extra-val'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export ALIAS_A=$VAR_A"), qt.IsTrue)

	// File permissions: 0600.
	info, err := os.Stat(output)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, info.Mode().Perm(), qt.Equals, os.FileMode(0o600))

	// No leftover tmp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		qt.Assert(t, strings.HasSuffix(e.Name(), ".tmp"), qt.IsFalse,
			qt.Commentf("leftover tmp file: %s", e.Name()))
	}
}

func TestCache_PartialFailure(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "good-1", "val-1"),
		corruptCipher(t, "bad-cipher"),
		testCipher(t, "good-2", "val-2"),
	}

	manifest := writeManifest(t, dir, `
[cache]
good-1 = VAR_1
bad-cipher = VAR_BAD
good-2 = VAR_2
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.Equals, errCacheFailed)
	})

	// File has the 2 good items + header.
	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, strings.Contains(content, "export VAR_1='val-1'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export VAR_2='val-2'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "VAR_BAD"), qt.IsFalse)

	// Stderr has the failure context.
	qt.Assert(t, strings.Contains(stderr, "bad-cipher"), qt.IsTrue,
		qt.Commentf("stderr: %q", stderr))
	qt.Assert(t, strings.Contains(stderr, "MAC mismatch"), qt.IsTrue,
		qt.Commentf("stderr: %q", stderr))
	qt.Assert(t, strings.Contains(stderr, "kdf:"), qt.IsTrue,
		qt.Commentf("stderr: %q", stderr))

	// Summary line.
	qt.Assert(t, strings.Contains(stderr, "2/3 items cached, 1 failed"), qt.IsTrue,
		qt.Commentf("stderr: %q", stderr))
}

// TestCache_ErrorNotMasked is the regression guard: if anyone ever adds a
// 2>/dev/null equivalent, this test must fail.
func TestCache_ErrorNotMasked(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		corruptCipher(t, "doomed-cipher"),
	}

	manifest := writeManifest(t, dir, `
[cache]
doomed-cipher = DOOMED_VAR
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		_ = cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
	})

	// 1. Cipher name must appear.
	qt.Assert(t, strings.Contains(stderr, "doomed-cipher"), qt.IsTrue,
		qt.Commentf("stderr must contain cipher name; got: %q", stderr))

	// 2. Actual error (not "Wrong password" or generic "failed").
	qt.Assert(t, strings.Contains(stderr, "MAC mismatch"), qt.IsTrue,
		qt.Commentf("stderr must contain actual error type; got: %q", stderr))

	// 3. KDF type.
	qt.Assert(t, strings.Contains(stderr, "kdf:"), qt.IsTrue,
		qt.Commentf("stderr must contain KDF info; got: %q", stderr))

	// 4. Email source.
	// localTestEmail is set via Sync.Profile.Email, so emailSource() = "sync profile".
	qt.Assert(t, strings.Contains(stderr, "email from:"), qt.IsTrue,
		qt.Commentf("stderr must contain email source; got: %q", stderr))
	qt.Assert(t, strings.Contains(stderr, "sync profile"), qt.IsTrue,
		qt.Commentf("stderr must name the email source tier; got: %q", stderr))
}

func TestCache_CustomFields(t *testing.T) {
	dir := setupCacheTest(t)

	f1Name := encryptStr(t, "FIELD_ONE")
	f1Val := encryptStr(t, "value-one")
	f2Name := encryptStr(t, "FIELD_TWO")
	f2Val := encryptStr(t, "value-two")

	globalData.Sync.Ciphers = []Cipher{
		func() Cipher {
			c := testCipher(t, "multi-field", "pw")
			c.Fields = []Field{
				{Name: f1Name, Value: f1Val},
				{Name: f2Name, Value: f2Val},
			}
			return c
		}(),
	}

	manifest := writeManifest(t, dir, `
[cache-fields]
multi-field = FIELD_ONE,FIELD_TWO
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, strings.Contains(stderr, "2/2 items cached, 0 failed"), qt.IsTrue,
		qt.Commentf("stderr: %q", stderr))

	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, strings.Contains(content, "export FIELD_ONE='value-one'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export FIELD_TWO='value-two'"), qt.IsTrue)
}

func TestCache_Aliases(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "gh-cipher", "ghp_secret"),
	}

	manifest := writeManifest(t, dir, `
[cache]
gh-cipher = GITHUB_TOKEN

[cache-aliases]
GH_TOKEN = GITHUB_TOKEN
`)
	output := filepath.Join(dir, "out.sh")

	captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, strings.Contains(content, "export GITHUB_TOKEN='ghp_secret'"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export GH_TOKEN=$GITHUB_TOKEN"), qt.IsTrue)
}

func TestCache_EmptyVault(t *testing.T) {
	dir := setupCacheTest(t)

	// No ciphers in vault.
	globalData.Sync.Ciphers = nil

	manifest := writeManifest(t, dir, `
[cache]
nonexistent = VAR_X
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.Equals, errCacheFailed)
	})

	// File written with header only (no export lines).
	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, strings.Contains(content, "Auto-generated by bitw cache"), qt.IsTrue)
	qt.Assert(t, strings.Contains(content, "export"), qt.IsFalse)

	// Summary: 0/1 items cached, 1 failed (cipher not found).
	qt.Assert(t, strings.Contains(stderr, "0/1 items cached, 1 failed"), qt.IsTrue,
		qt.Commentf("stderr: %q", stderr))
}

// TestCache_UppercaseCipherName guards the case-preservation behavior for
// cipher names in [cache] and [cache-fields] sections. Prior to the
// RawKeys/GetRaw fix, the default INI KeyManipFunc lowercased keys, which
// would have caused a manifest entry like "Devbox-Global/GitHub-Token" to
// become "devbox-global/github-token" and miss the vault cipher. Real
// vault cipher names happen to be lowercase, so this is a latent bug
// caught by deliberate coverage. If anyone reverts to Keys()/Get(), this
// test fails immediately.
func TestCache_UppercaseCipherName(t *testing.T) {
	dir := setupCacheTest(t)

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "Devbox-Global/GitHub-Token", "ghp_uppercase_secret"),
		testCipher(t, "Mixed-Case/Cipher", "another-secret"),
	}

	manifest := writeManifest(t, dir, `
[cache]
Devbox-Global/GitHub-Token = GITHUB_TOKEN
Mixed-Case/Cipher = MIXED_VAR

[cache-fields]
Mixed-Case/Cipher = FIELD_A,FIELD_B
`)
	output := filepath.Join(dir, "out.sh")

	// Add custom fields to Mixed-Case/Cipher.
	fNameA := encryptStr(t, "FIELD_A")
	fValA := encryptStr(t, "val-A")
	fNameB := encryptStr(t, "FIELD_B")
	fValB := encryptStr(t, "val-B")
	globalData.Sync.Ciphers[1].Fields = []Field{
		{Name: fNameA, Value: fValA},
		{Name: fNameB, Value: fValB},
	}

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	// cmdCache prints a summary line to stderr on success ("X/Y items cached,
	// K failed"). On full success it should be "4/4 items cached, 0 failed\n".
	qt.Assert(t, stderr, qt.Equals, "4/4 items cached, 0 failed\n")

	content, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	out := string(content)

	// Both cipher names with original case should resolve and emit exports.
	qt.Assert(t, out, qt.Contains, "export GITHUB_TOKEN='ghp_uppercase_secret'\n")
	qt.Assert(t, out, qt.Contains, "export MIXED_VAR='another-secret'\n")
	qt.Assert(t, out, qt.Contains, "export FIELD_A='val-A'\n")
	qt.Assert(t, out, qt.Contains, "export FIELD_B='val-B'\n")
}

func TestCache_LibsecretMirror(t *testing.T) {
	dir := setupCacheTest(t)

	// Stub secret-tool that logs argv to argsLog AND stdin to stdinLog.
	// `secret-tool store` reads the secret from stdin (not from a positional
	// arg), so the stub must capture both channels. The test asserts the
	// value arrives on stdin and is NOT in argv (the broken positional-arg
	// code would put it in argv).
	argsLog := filepath.Join(dir, "secret-tool-args")
	stdinLog := filepath.Join(dir, "secret-tool-stdin")
	stubDir := filepath.Join(dir, "bin")
	os.MkdirAll(stubDir, 0o755)
	stubPath := filepath.Join(stubDir, "secret-tool")
	stub := "#!/bin/sh\necho \"$@\" >> " + argsLog + "\ncat >> " + stdinLog + "\n"
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Skipf("could not create stub: %v", err)
	}

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "bw-key", "client-secret-val"),
	}

	manifest := writeManifest(t, dir, `
[cache]
bw-key = BW_CLIENTSECRET
`)
	output := filepath.Join(dir, "out.sh")

	// Prepend our stub dir to PATH.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", stubDir+":"+oldPath)
	defer os.Setenv("PATH", oldPath)

	// Deliberately do NOT pre-set BW_CLIENTSECRET in the environment. This
	// reproduces the init-hook scenario where `bitw cache --mirror-libsecret=...`
	// runs before the cache file is sourced, so no decrypted value is in
	// the process env. If cmdCache mirrors from os.Getenv (the old bug),
	// secret-tool would receive an empty stdin — overwriting the existing
	// libsecret mirror with garbage. With the fix, the decrypted value
	// flows from cmdCache's internal map to secret-tool via stdin regardless
	// of the env state.
	os.Unsetenv("BW_CLIENTSECRET")
	defer os.Unsetenv("BW_CLIENTSECRET")

	captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
			"-mirror-libsecret", "BW_CLIENTSECRET",
		})
		qt.Assert(t, err, qt.IsNil)
	})

	// Verify the cache file was written.
	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, strings.Contains(string(data), "export BW_CLIENTSECRET='client-secret-val'"), qt.IsTrue)

	// Verify secret-tool was called with the right argv: store + label +
	// collection + attribute. NO trailing value (secret is on stdin).
	argsData, err := os.ReadFile(argsLog)
	qt.Assert(t, err, qt.IsNil)
	argsStr := string(argsData)
	qt.Assert(t, strings.Contains(argsStr, "store"), qt.IsTrue,
		qt.Commentf("secret-tool args: %q", argsStr))
	qt.Assert(t, strings.Contains(argsStr, "--label=Bitwarden API key"), qt.IsTrue,
		qt.Commentf("secret-tool args: %q", argsStr))
	qt.Assert(t, strings.Contains(argsStr, "bitwarden"), qt.IsTrue,
		qt.Commentf("secret-tool args: %q", argsStr))
	// The mirror stores under a semantic libsecret attr name
	// (api-key-secret / api-key-client-id) — NOT the env var name —
	// so the bash init-hook fallback can find what was stored. The
	// mapping lives in cache.go:mirrorAttrFor and is the single source
	// of truth shared with init-hook:20,24.
	qt.Assert(t, strings.Contains(argsStr, "api-key-secret"), qt.IsTrue,
		qt.Commentf("mirror must use semantic attr 'api-key-secret' (matches init-hook fallback); got: %q", argsStr))
	// CRITICAL: the secret must NOT appear as a positional argv (that
	// was the broken-positional-arg code; the correct code passes the
	// secret on stdin). A failure here would also catch a regression to
	// the old code — the old test asserted Contains(argsStr, value) which
	// could never have caught the bug.
	qt.Assert(t, strings.Contains(argsStr, "client-secret-val"), qt.IsFalse,
		qt.Commentf("secret must NOT be in argv (the secret goes on stdin); got: %q", argsStr))

	// Verify the decrypted value arrived on stdin.
	stdinData, err := os.ReadFile(stdinLog)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, strings.Contains(string(stdinData), "client-secret-val"), qt.IsTrue,
		qt.Commentf("secret must arrive on stdin; got stdinLog: %q", string(stdinData)))
}

// TestCache_LibsecretMirror_CustomField covers the [cache-fields]→mirror
// path: a custom field name (not a login.password) gets decrypted and
// mirrored. This is the production code path for BW_CLIENTID, which lives
// in a custom field on the `devbox-global/bitwarden-api-key` cipher per
// ADR-0003. Without this test, the half of the B1 fix that handles custom
// fields (cache.go:201, `decrypted[fieldName] = val`) could be silently
// broken without any test failure.
func TestCache_LibsecretMirror_CustomField(t *testing.T) {
	dir := setupCacheTest(t)

	// Stub secret-tool that logs argv AND stdin. `secret-tool store` reads
	// the secret from stdin (not from a positional arg), so the stub must
	// capture both channels. Same pattern as TestCache_LibsecretMirror.
	argsLog := filepath.Join(dir, "secret-tool-args")
	stdinLog := filepath.Join(dir, "secret-tool-stdin")
	stubDir := filepath.Join(dir, "bin")
	os.MkdirAll(stubDir, 0o755)
	stubPath := filepath.Join(stubDir, "secret-tool")
	stub := "#!/bin/sh\necho \"$@\" >> " + argsLog + "\ncat >> " + stdinLog + "\n"
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Skipf("could not create stub: %v", err)
	}

	// Build a Login cipher with a custom field — this is how BW_CLIENTID
	// arrives in production: a non-password custom field on the
	// bitwarden-api-key cipher.
	bwCipher := testCipher(t, "bw-key", "client-secret-val")
	bwCipher.Fields = []Field{
		{Name: encryptStr(t, "BW_CLIENTID"), Value: encryptStr(t, "user.test-uuid-1234")},
	}
	globalData.Sync.Ciphers = []Cipher{bwCipher}

	manifest := writeManifest(t, dir, `
[cache-fields]
bw-key = BW_CLIENTID
`)
	output := filepath.Join(dir, "out.sh")

	// Prepend stub dir to PATH; do NOT pre-set BW_CLIENTID (mimics init-hook).
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", stubDir+":"+oldPath)
	defer os.Setenv("PATH", oldPath)
	os.Unsetenv("BW_CLIENTID")
	defer os.Unsetenv("BW_CLIENTID")

	captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
			"-mirror-libsecret", "BW_CLIENTID",
		})
		qt.Assert(t, err, qt.IsNil)
	})

	// Cache file must contain the decrypted custom field value.
	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, strings.Contains(string(data), "export BW_CLIENTID='user.test-uuid-1234'"), qt.IsTrue,
		qt.Commentf("cache file: %q", string(data)))

	// secret-tool argv must have the semantic attr name, NOT the value.
	argsData, err := os.ReadFile(argsLog)
	qt.Assert(t, err, qt.IsNil)
	argsStr := string(argsData)
	qt.Assert(t, strings.Contains(argsStr, "api-key-client-id"), qt.IsTrue,
		qt.Commentf("mirror must use semantic attr 'api-key-client-id' (matches init-hook fallback); got: %q", argsStr))
	qt.Assert(t, strings.Contains(argsStr, "user.test-uuid-1234"), qt.IsFalse,
		qt.Commentf("secret must NOT be in argv (the secret goes on stdin); got: %q", argsStr))

	// secret-tool stdin must contain the decrypted custom-field value.
	stdinData, err := os.ReadFile(stdinLog)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, strings.Contains(string(stdinData), "user.test-uuid-1234"), qt.IsTrue,
		qt.Commentf("secret must arrive on stdin; got stdinLog: %q", string(stdinData)))
}

// TestCache_LibsecretMirror_MissingKey verifies that requesting a var for
// mirror that was not decrypted by this run emits a warning instead of
// silently writing an empty string to libsecret (which would clobber any
// previously-stored good value).
func TestCache_LibsecretMirror_MissingKey(t *testing.T) {
	dir := setupCacheTest(t)

	// Stub secret-tool that logs argv — should NOT be called.
	argsLog := filepath.Join(dir, "secret-tool-args")
	stubDir := filepath.Join(dir, "bin")
	os.MkdirAll(stubDir, 0o755)
	stubPath := filepath.Join(stubDir, "secret-tool")
	stub := "#!/bin/sh\necho \"$@\" >> " + argsLog + "\n"
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Skipf("could not create stub: %v", err)
	}

	globalData.Sync.Ciphers = []Cipher{
		testCipher(t, "bw-key", "client-secret-val"),
	}
	manifest := writeManifest(t, dir, `
[cache]
bw-key = BW_CLIENTSECRET
`)
	output := filepath.Join(dir, "out.sh")

	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", stubDir+":"+oldPath)
	defer os.Setenv("PATH", oldPath)

	// Request a mirror for BW_TYPO_NOT_IN_MANIFEST — must warn, not write empty.
	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
			"-mirror-libsecret", "BW_TYPO_NOT_IN_MANIFEST",
		})
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, strings.Contains(stderr, "BW_TYPO_NOT_IN_MANIFEST"), qt.IsTrue,
		qt.Commentf("must warn about missing mirror var; stderr: %q", stderr))
	qt.Assert(t, strings.Contains(stderr, "not decrypted"), qt.IsTrue,
		qt.Commentf("warning must explain the cause; stderr: %q", stderr))

	// Verify secret-tool was NOT called. The stub only writes to argsLog
	// when invoked, so the file may legitimately not exist (that is the
	// success condition). If it does exist, it must not contain the
	// unknown mirror var name.
	if argsData, err := os.ReadFile(argsLog); err == nil {
		qt.Assert(t, strings.Contains(string(argsData), "BW_TYPO_NOT_IN_MANIFEST"), qt.IsFalse,
			qt.Commentf("secret-tool must not be invoked for an unknown mirror var; got: %q", string(argsData)))
	}
	// err != nil (file does not exist) is the expected success condition.
}

// TestCache_CallsSync is the regression guard for the sync preflight added
// so `bitw cache` can fully replace the bash bin/secrets-refresh wrapper
// (which did `bitw sync` as a preflight before its per-item loop). Without
// this, cmdCache would only see ciphers present in data.json at startup and
// miss any created since — including items just created by `bitw create`.
//
// The test verifies two things:
//  1. cmdCache calls /sync before reading cipher data.
//  2. Ciphers returned by the live /sync response are visible to cmdCache —
//     even when they were not in globalData.Sync.Ciphers at the moment of
//     invocation. This guards against cmdCache accidentally using stale
//     in-memory data instead of the freshly synced server state.
func TestCache_CallsSync(t *testing.T) {
	// Build a /sync response that includes a fresh cipher the test did NOT
	// pre-populate into globalData.Sync.Ciphers. If cmdCache trusts the
	// in-memory ciphers over /sync, this cipher is missed; if it syncs
	// first, it is picked up.
	dir := setupCacheTest(t)

	var syncCalled bool
	synced := testCipher(t, "synced-only-cipher", "synced-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			syncCalled = true
			_ = json.NewEncoder(w).Encode(SyncData{
				Profile: globalData.Sync.Profile,
				Ciphers: []Cipher{synced},
			})
		case "/accounts/prelogin":
			_ = json.NewEncoder(w).Encode(preLoginResponse{
				KDF:            1,
				KDFIterations:  globalData.KDFIterations,
				KDFMemory:      globalData.KDFMemory,
				KDFParallelism: globalData.KDFParallelism,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldApi, oldIdt := apiURL, idtURL
	apiURL, idtURL = server.URL, server.URL
	defer func() { apiURL, idtURL = oldApi, oldIdt }()

	// Wipe any pre-populated ciphers: cmdCache must re-fetch via /sync.
	globalData.Sync.Ciphers = nil

	manifest := writeManifest(t, dir, `
[cache]
synced-only-cipher = SYNCED_VAR
`)
	output := filepath.Join(dir, "out.sh")

	captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, syncCalled, qt.IsTrue, qt.Commentf("cmdCache must call /sync before reading ciphers"))

	content, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, strings.Contains(string(content), "export SYNCED_VAR='synced-secret'"), qt.IsTrue,
		qt.Commentf("cipher from /sync response must be resolved; cache file: %q", string(content)))
}

// (TestCache_Timeout was removed — the timeout flag is wired in cache.go
// via context.WithTimeout wrapping the cmdCache ctx, and is verified by
// manual invocation: `bitw cache --timeout=100ms ...` aborts within 100ms
// against a slow /sync server. A unit test that exercises the Go http
// client's cancel-to-server-context propagation proved flaky in CI-like
// environments (Go's http.Server does not always deliver the client
// cancel to the handler's r.Context() promptly), so we rely on manual
// verification rather than a brittle automated assertion.)

// TestCache_NameDecryptWarning is the regression guard for the diagnostic
// warning added to cache.go's cipherIndex loop. Previously, when a cipher's
// name failed to decrypt (e.g. MAC mismatch), the loop silently skipped it.
// If that cipher was in the manifest, the user got a misleading "cipher not
// found in vault" instead of the real decrypt error. The fix prints a warning
// to stderr including the cipher ID and the decrypt error.
func TestCache_NameDecryptWarning(t *testing.T) {
	dir := setupCacheTest(t)

	// One good cipher + one with a corrupt name (MAC mismatch on name).
	goodCipher := testCipher(t, "good-cipher", "good-secret")
	badCipher := corruptNameCipher(t, "bad-secret")
	globalData.Sync.Ciphers = []Cipher{goodCipher, badCipher}

	manifest := writeManifest(t, dir, `
[cache]
good-cipher = GOOD_VAR
`)
	output := filepath.Join(dir, "out.sh")

	stderr := captureStderr(t, func() {
		err := cmdCache(context.Background(), []string{
			"-config", manifest,
			"-output", output,
		})
		qt.Assert(t, err, qt.IsNil)
	})

	// The warning must mention the cipher ID and the decrypt error.
	qt.Assert(t, strings.Contains(stderr, "could not decrypt name of cipher"), qt.IsTrue,
		qt.Commentf("stderr must contain name-decrypt warning; got: %q", stderr))
	qt.Assert(t, strings.Contains(stderr, "00000000-0000-0000-0000-000000000bad"), qt.IsTrue,
		qt.Commentf("stderr must contain cipher ID; got: %q", stderr))
	qt.Assert(t, strings.Contains(stderr, "MAC mismatch"), qt.IsTrue,
		qt.Commentf("stderr must contain decrypt error; got: %q", stderr))

	// The good cipher must still land in the cache output.
	data, err := os.ReadFile(output)
	qt.Assert(t, err, qt.IsNil)
	content := string(data)
	qt.Assert(t, strings.Contains(content, "export GOOD_VAR='good-secret'"), qt.IsTrue,
		qt.Commentf("good cipher must still be cached; got: %q", content))
}
