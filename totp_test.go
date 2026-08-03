// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

// TestTotpRFC6238Vectors checks TOTP against the RFC 6238 Appendix B test
// vectors (SHA-1 secret "12345678901234567890"). The RFC publishes 8-digit
// values; the last 6 digits of each are the 6-digit codes.
func TestTotpRFC6238Vectors(t *testing.T) {
	key, err := totpSecret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	qt.Assert(t, err, qt.IsNil)
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, v := range vectors {
		got := totpCode(key, time.Unix(v.unix, 0))
		qt.Assert(t, got, qt.Equals, v.want, qt.Commentf("T=%d", v.unix))
	}
}

// TestTotpSecretParsing checks that totpSecret accepts the RFC secret in the
// representations Bitwarden stores: bare base32, otpauth:// URLs and steam://
// URLs, with whitespace and case normalization.
func TestTotpSecretParsing(t *testing.T) {
	want := []byte("12345678901234567890")
	tests := []struct {
		in      string
		wantErr string
	}{
		{"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", ""},
		{"gezdgnbvgy3tqojqgezdgnbvgy3tqojq", ""},
		{" GEZD GN BVGY 3TQO JQGE ZDGN BVGY 3TQO JQ ", ""},
		{"otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example", ""},
		{"otpauth://totp/Example?digits=6", "otpauth URI has no secret parameter"},
		{"https://example.com/secret", "invalid TOTP secret"},
	}
	for _, tc := range tests {
		got, err := totpSecret(tc.in)
		if tc.wantErr != "" {
			qt.Assert(t, err, qt.ErrorMatches, ".*"+regexp.QuoteMeta(tc.wantErr)+".*")
			continue
		}
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, got, qt.DeepEquals, want)
	}
}

// TestSteamCodeKAT checks steamCode against a known-answer vector computed
// independently (Python implementation of Steam's algorithm, secret
// CJ3H2Y7CKP6RKVX2 at T=1111111109 → FT9D6).
func TestSteamCodeKAT(t *testing.T) {
	key, err := totpSecret("CJ3H2Y7CKP6RKVX2")
	qt.Assert(t, err, qt.IsNil)
	got := steamCode(key, time.Unix(1111111109, 0))
	qt.Assert(t, got, qt.Equals, "FT9D6")
	qt.Assert(t, len(got), qt.Equals, 5)
	for _, r := range got {
		qt.Assert(t, strings.ContainsRune(steamTotpChars, r), qt.IsTrue)
	}
}

// setupTestSecrets installs the standard test secrets (password + KDF keys)
// and restores the previous globals on cleanup.
func setupTestSecrets(t *testing.T) {
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
	secrets.initKeys()
}

// TestCmdGet_TotpMode verifies that `bitw get totp <name>` generates and
// prints a 6-digit code for a login cipher with a TOTP secret. The secret is
// stored encrypted, as it is in real vaults.
func TestCmdGet_TotpMode(t *testing.T) {
	setupTestSecrets(t)

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Totp: encryptStr(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	output := captureStdout(t, func() {
		err := cmdGet(context.Background(), []string{"totp", "Test Cipher"})
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, regexp.MustCompile(`^\d{6}\n$`).MatchString(output), qt.IsTrue)
}

// TestCmdGet_TotpMode_Steam verifies that `bitw get totp` handles steam://
// keys, emitting a 5-character Steam guard code.
func TestCmdGet_TotpMode_Steam(t *testing.T) {
	setupTestSecrets(t)

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Totp: encryptStr(t, "steam://CJ3H2Y7CKP6RKVX2"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	output := captureStdout(t, func() {
		err := cmdGet(context.Background(), []string{"totp", "Test Cipher"})
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, regexp.MustCompile(`^[`+steamTotpChars+`]{5}\n$`).MatchString(output), qt.IsTrue)
}

// TestCmdGet_TotpMode_NoSecret verifies that `bitw get totp` fails with a
// clear error when the cipher has no TOTP secret.
func TestCmdGet_TotpMode_NoSecret(t *testing.T) {
	setupTestSecrets(t)

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Password: encryptStr(t, "testpass"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	err := cmdGet(context.Background(), []string{"totp", "Test Cipher"})
	qt.Assert(t, err, qt.ErrorMatches, "cipher \"Test Cipher\" has no TOTP secret")
}

// TestCmdGet_TotpMode_UsageError verifies that `bitw get totp` without a
// cipher name is a usage error, not a lookup for a cipher named "totp".
func TestCmdGet_TotpMode_UsageError(t *testing.T) {
	setupTestSecrets(t)

	err := cmdGet(context.Background(), []string{"totp"})
	qt.Assert(t, err, qt.ErrorMatches, "usage: bitw get.*")
}
