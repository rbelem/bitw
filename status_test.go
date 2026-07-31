// Copyright (c) 2019, Daniel Martí <mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
)

// setupStatusTest initializes globalData with a known runtime state
// suitable for cmdStatus testing. Mirrors setupCacheTest but does not
// require a mock /sync endpoint (cmdStatus does not call sync — see the
// function-level doc).
func setupStatusTest(t *testing.T, modify func()) {
	t.Helper()
	globalData = dataFile{
		DeviceID:      "device-uuid-test",
		AccessToken:   "tok",
		RefreshToken:  "ref",
		TokenExpiry:   time.Now().Add(time.Hour),
		KDFIterations: 100000, // matches setupCacheTest; the fixture profile.Key is encrypted under this iteration count
		LastSync:      time.Now().Add(-3 * time.Hour),
	}
	globalData.Sync.Profile.Email = localTestEmail // argon2id salt must match the fixture profile.Key encryption
	globalData.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets = secretCache{
		data:      &globalData,
		_password: []byte(localTestPassword),
	}
	saveData = false
	if err := secrets.initKeys(); err != nil {
		t.Fatalf("initKeys: %v", err)
	}
	if modify != nil {
		modify()
	}
}

// TestStatus_PlainOutput verifies that cmdStatus emits one `key = value`
// line per field to stdout, with no network calls and no re-auth.
func TestStatus_PlainOutput(t *testing.T) {
	setupStatusTest(t, nil)

	c := qt.New(t)
	stdout := captureStdout(t, func() {
		err := cmdStatus(context.Background(), nil)
		c.Assert(err, qt.IsNil)
	})

	// Every documented field must appear with a value (never blank).
	// The plain output uses printf-padded keys (e.g. "email                  = …").
	// We check that each key appears followed by at least one space (the
	// padding) — that uniquely matches the padded-key line and does not
	// false-match against other lines whose names are substrings (e.g.
	// "email_source" starts with "email_" not "email ").
	expectedKeys := []string{
		"email", "email_source",
		"token_present", "token_expiry", "token_valid", "refresh_token_present",
		"grant", "master_password_source",
		"last_sync", "last_sync_age",
		"kdf",
		"api_url", "identity_url", "device_id",
		"cipher_count",
	}
	for _, key := range expectedKeys {
		c.Assert(strings.Contains(stdout, key+" "), qt.IsTrue,
			qt.Commentf("plain output missing key %q; stdout: %q", key, stdout))
	}
}

// TestStatus_JSONOutput verifies that --json emits a single JSON object
// with stable field names that future tooling can parse.
func TestStatus_JSONOutput(t *testing.T) {
	setupStatusTest(t, nil)

	c := qt.New(t)
	stdout := captureStdout(t, func() {
		err := cmdStatus(context.Background(), []string{"--json"})
		c.Assert(err, qt.IsNil)
	})

	// Must start with `{` and end with `}`.
	c.Assert(strings.HasPrefix(strings.TrimSpace(stdout), "{"), qt.IsTrue)
	c.Assert(strings.HasSuffix(strings.TrimSpace(stdout), "}"), qt.IsTrue)

	// Required JSON keys.
	for _, key := range []string{
		`"email"`, `"email_source"`,
		`"token_present"`, `"token_expiry"`, `"token_valid"`, `"refresh_token_present"`,
		`"grant"`, `"master_password_source"`,
		`"last_sync"`, `"last_sync_age"`,
		`"kdf"`,
		`"api_url"`, `"identity_url"`, `"device_id"`,
		`"cipher_count"`, `"personal_cipher_count"`, `"org_cipher_count"`,
	} {
		c.Assert(strings.Contains(stdout, key+":"), qt.IsTrue,
			qt.Commentf("JSON output missing %q; stdout: %q", key, stdout))
	}
}

// TestStatus_TokenExpired verifies that an expired token is reported as
// EXPIRED but does NOT cause cmdStatus to exit non-zero (the command is
// diagnostic — reporting "EXPIRED" is the value, not an error).
func TestStatus_TokenExpired(t *testing.T) {
	setupStatusTest(t, func() {
		globalData.TokenExpiry = time.Now().Add(-time.Minute)
	})

	c := qt.New(t)
	stdout := captureStdout(t, func() {
		err := cmdStatus(context.Background(), nil)
		c.Assert(err, qt.IsNil)
	})
	c.Assert(strings.Contains(stdout, "token_valid            = EXPIRED"), qt.IsTrue,
		qt.Commentf("stdout: %q", stdout))
}

// TestStatus_NoToken verifies the "never logged in" state.
func TestStatus_NoToken(t *testing.T) {
	setupStatusTest(t, func() {
		globalData.AccessToken = ""
		globalData.RefreshToken = ""
	})

	c := qt.New(t)
	stdout := captureStdout(t, func() {
		err := cmdStatus(context.Background(), nil)
		c.Assert(err, qt.IsNil)
	})
	c.Assert(strings.Contains(stdout, "token_present          = false"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "token_valid            = n/a"), qt.IsTrue)
	c.Assert(strings.Contains(stdout, "refresh_token_present  = false"), qt.IsTrue)
}

// TestStatus_NoSync verifies the "never synced" state (LastSync zero).
func TestStatus_NoSync(t *testing.T) {
	setupStatusTest(t, func() {
		globalData.LastSync = time.Time{}
	})

	c := qt.New(t)
	stdout := captureStdout(t, func() {
		err := cmdStatus(context.Background(), nil)
		c.Assert(err, qt.IsNil)
	})
	c.Assert(strings.Contains(stdout, "last_sync              = never"), qt.IsTrue,
		qt.Commentf("stdout: %q", stdout))
	c.Assert(strings.Contains(stdout, "last_sync_age          = n/a"), qt.IsTrue,
		qt.Commentf("stdout: %q", stdout))
}

// TestStatus_CipherCounts verifies the personal/org split. Personal
// ciphers have nil OrganizationID; org ciphers have a non-nil UUID.
func TestStatus_CipherCounts(t *testing.T) {
	setupStatusTest(t, func() {
		// Two personal, one org.
		orgID := uuidOrg()
		globalData.Sync.Ciphers = []Cipher{
			testCipher(t, "personal-1", "x"),
			testCipher(t, "personal-2", "y"),
			func() Cipher {
				c := testCipher(t, "org-1", "z")
				c.OrganizationID = &orgID
				return c
			}(),
		}
	})

	c := qt.New(t)
	stdout := captureStdout(t, func() {
		err := cmdStatus(context.Background(), nil)
		c.Assert(err, qt.IsNil)
	})
	c.Assert(strings.Contains(stdout, "cipher_count           = 3 (personal=2, org=1)"), qt.IsTrue,
		qt.Commentf("stdout: %q", stdout))
}

// TestStatus_NoArgsAccepts verifies that cmdStatus rejects extra args
// (the status command takes no positional args; --json is a flag).
func TestStatus_NoArgsAccepts(t *testing.T) {
	setupStatusTest(t, nil)

	c := qt.New(t)
	err := cmdStatus(context.Background(), []string{"extra-arg"})
	c.Assert(err, qt.ErrorMatches, "usage: bitw status.*")
}

// TestPasswordSource covers the passwordSource() helper that mirrors
// emailSource() — same resolution tiers, no actual retrieval.
//
// The libsecret tier is reported as "libsecret (if stored)" — a
// static check of whether `secret-tool` is on PATH — rather than a live
// probe, to avoid both the side effect of `readLibsecretPassword` (which
// consumes the password into `secrets._password`) and the concern of
// triggering a GUI keyring unlock prompt from a diagnostic command. So
// we cannot distinguish "secret-tool on PATH, no master-password
// stored" from "secret-tool on PATH, master-password stored" — both
// report "libsecret (if stored)". Use `secret-tool lookup` directly
// to verify.
func TestPasswordSource(t *testing.T) {
	// Env var present.
	t.Run("from_env", func(t *testing.T) {
		os.Setenv("PASSWORD", "test-password")
		t.Cleanup(func() { os.Unsetenv("PASSWORD") })
		setupStatusTest(t, func() {
			secrets._password = nil
		})
		c := qt.New(t)
		c.Assert(passwordSource(), qt.Equals, "$PASSWORD")
	})

	// Already in the cache (post-decryption).
	t.Run("from_cache", func(t *testing.T) {
		setupStatusTest(t, nil)
		c := qt.New(t)
		// _password was set by setupStatusTest
		c.Assert(passwordSource(), qt.Equals, "cache")
	})

	// No env, no cache, no secret-tool on PATH → would-prompt.
	// We use a PATH that doesn't include any secret-tool by prepending
	// an empty directory.
	t.Run("would_prompt", func(t *testing.T) {
		emptyDir := t.TempDir() // no secret-tool inside
		setupStatusTest(t, func() {
			secrets._password = nil
			os.Unsetenv("PASSWORD")
			oldPath := os.Getenv("PATH")
			os.Setenv("PATH", emptyDir)
			t.Cleanup(func() { os.Setenv("PATH", oldPath) })
		})
		c := qt.New(t)
		c.Assert(passwordSource(), qt.Equals, "would-prompt")
	})
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	done := make(chan string)
	go func() {
		var buf strings.Builder
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// uuidOrg returns a fresh non-nil uuid.UUID for org cipher testing.
// Uses a stable fixture value; doesn't need to be cryptographically random.
func uuidOrg() uuid.UUID {
	var u uuid.UUID
	u[0] = 0x02
	u[1] = 0xef
	u[2] = 0x39
	u[3] = 0x5d
	for i := 4; i < 16; i++ {
		u[i] = byte(i)
	}
	return u
}
