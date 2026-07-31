// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestSecretCache_ClientId verifies that clientId() correctly retrieves the
// client ID from env or prompts. This covers crypto.go:135 (20% coverage).
func TestSecretCache_ClientId(t *testing.T) {
	// Not parallel — mutates package-global env state.
	origClientId := os.Getenv("BW_CLIENTID")
	origSecrets := secrets
	t.Cleanup(func() {
		os.Setenv("BW_CLIENTID", origClientId)
		secrets = origSecrets
	})

	// Test 1: Cached value takes priority.
	secrets = secretCache{
		_clientId: []byte("cached-client-id"),
	}
	os.Setenv("BW_CLIENTID", "env-client-id")
	id, err := secrets.clientId()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(id), qt.Equals, "cached-client-id")

	// Test 2: Env var is used when no cached value.
	secrets = secretCache{}
	os.Setenv("BW_CLIENTID", "env-client-id")
	id, err = secrets.clientId()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(id), qt.Equals, "env-client-id")
	qt.Assert(t, string(secrets._clientId), qt.Equals, "env-client-id") // Should be cached now.
}

// TestSecretCache_ClientSecret verifies that clientSecret() correctly retrieves
// the client secret from env or prompts. This covers crypto.go:151 (20% coverage).
func TestSecretCache_ClientSecret(t *testing.T) {
	// Not parallel — mutates package-global env state.
	origClientSecret := os.Getenv("BW_CLIENTSECRET")
	origSecrets := secrets
	t.Cleanup(func() {
		os.Setenv("BW_CLIENTSECRET", origClientSecret)
		secrets = origSecrets
	})

	// Test 1: Cached value takes priority.
	secrets = secretCache{
		_clientSecret: []byte("cached-client-secret"),
	}
	os.Setenv("BW_CLIENTSECRET", "env-client-secret")
	secret, err := secrets.clientSecret()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(secret), qt.Equals, "cached-client-secret")

	// Test 2: Env var is used when no cached value.
	secrets = secretCache{}
	os.Setenv("BW_CLIENTSECRET", "env-client-secret")
	secret, err = secrets.clientSecret()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(secret), qt.Equals, "env-client-secret")
	qt.Assert(t, string(secrets._clientSecret), qt.Equals, "env-client-secret") // Should be cached now.
}

// TestSecretCache_EmailSource verifies that emailSource() correctly identifies
// the email source. This covers crypto.go:81 (44.4% coverage).
func TestSecretCache_EmailSource(t *testing.T) {
	// Not parallel — mutates package-global env state.
	origEmail := os.Getenv("EMAIL")
	origSecrets := secrets
	t.Cleanup(func() {
		os.Setenv("EMAIL", origEmail)
		secrets = origSecrets
	})

	// Test 1: $EMAIL takes priority.
	os.Setenv("EMAIL", "env@example.com")
	secrets = secretCache{
		_configEmail: "config@example.com",
		data: &dataFile{
			Sync: SyncData{
				Profile: Profile{Email: "profile@example.com"},
			},
			AccessToken: "jwt-with-email",
		},
	}
	qt.Assert(t, secrets.emailSource(), qt.Equals, "$EMAIL")

	// Test 2: Config file is second.
	os.Unsetenv("EMAIL")
	qt.Assert(t, secrets.emailSource(), qt.Equals, "config file")

	// Test 3: Sync profile is third.
	secrets._configEmail = ""
	qt.Assert(t, secrets.emailSource(), qt.Equals, "sync profile")

	// Test 4: JWT is fourth.
	secrets.data.Sync.Profile.Email = ""
	secrets.data.AccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Imp3dEBleGFtcGxlLmNvbSJ9.test"
	qt.Assert(t, secrets.emailSource(), qt.Equals, "JWT")

	// Test 5: Empty when no email available.
	secrets.data.AccessToken = ""
	qt.Assert(t, secrets.emailSource(), qt.Equals, "")
}

// TestSecretCache_Password verifies that password() correctly retrieves the
// password from env or prompts. This covers crypto.go:97 (53.8% coverage).
func TestSecretCache_Password(t *testing.T) {
	// Not parallel — mutates package-global env state.
	origPassword := os.Getenv("PASSWORD")
	origSecrets := secrets
	t.Cleanup(func() {
		os.Setenv("PASSWORD", origPassword)
		secrets = origSecrets
	})

	// Test 1: Cached value takes priority.
	secrets = secretCache{
		_password: []byte("cached-password"),
	}
	os.Setenv("PASSWORD", "env-password")
	pw, err := secrets.password()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(pw), qt.Equals, "cached-password")

	// Test 2: Env var is used when no cached value.
	secrets = secretCache{}
	os.Setenv("PASSWORD", "env-password")
	pw, err = secrets.password()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(pw), qt.Equals, "env-password")
	qt.Assert(t, string(secrets._password), qt.Equals, "env-password") // Should be cached now.
}

// TestDeviceTypeNum verifies that deviceTypeNum() returns the correct device
// type for the current OS. This covers auth.go:117 (40% coverage).
func TestDeviceTypeNum(t *testing.T) {
	// Just verify it returns a valid device type number.
	num := deviceTypeNum()
	qt.Assert(t, num > 0, qt.IsTrue)
}

// TestTwoFactorProvider_Line verifies that Line() returns the correct prompt
// for each two-factor provider. This covers auth.go:416 (40% coverage).
func TestTwoFactorProvider_Line(t *testing.T) {
	t.Parallel()

	tests := []struct {
		provider TwoFactorProvider
		extra    map[string]interface{}
		want     string
	}{
		{Authenticator, nil, "Six-digit authenticator token"},
		{Email, map[string]interface{}{"Email": "test@example.com"}, "Six-digit email token (test@example.com)"},
		{Duo, nil, "unsupported two factor auth provider 2"},
	}

	for _, tc := range tests {
		got := tc.provider.Line(tc.extra)
		qt.Assert(t, got, qt.Equals, tc.want)
	}
}

// TestResolveField verifies that resolveField() correctly resolves cipher
// fields. This covers get.go:128 (56.2% coverage).
func TestResolveField(t *testing.T) {
	// Not parallel — mutates package-global state.
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
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

	cipher := &Cipher{
		Login: &Login{
			Username: encryptForTest(t, "testuser"),
			Password: encryptForTest(t, "testpass"),
			URI:      encryptForTest(t, "https://example.com"),
			Totp:     "123456",
		},
		Notes: notesPtr(encryptForTest(t, "test notes")),
		Fields: []Field{
			{
				Name:  encryptForTest(t, "custom_field"),
				Value: encryptForTest(t, "custom_value"),
			},
		},
	}

	// Test built-in fields.
	val, err := resolveField(cipher, "username")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, val, qt.Equals, "testuser")

	val, err = resolveField(cipher, "password")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, val, qt.Equals, "testpass")

	val, err = resolveField(cipher, "uri")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, val, qt.Equals, "https://example.com")

	val, err = resolveField(cipher, "totp")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, val, qt.Equals, "123456")

	val, err = resolveField(cipher, "notes")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, val, qt.Equals, "test notes")

	// Test custom field.
	val, err = resolveField(cipher, "custom_field")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, val, qt.Equals, "custom_value")

	// Test non-existent field.
	_, err = resolveField(cipher, "nonexistent")
	qt.Assert(t, err, qt.ErrorMatches, "field .* not found.*")
}

// Helper function to create a pointer to a CipherString.
func notesPtr(cs CipherString) *CipherString {
	return &cs
}
