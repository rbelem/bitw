// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

// TestEnsureToken_RefreshToken verifies that ensureToken() correctly refreshes
// an expired token using the refresh_token grant. This covers main.go:412
// (55.6% coverage).
func TestEnsureToken_RefreshToken(t *testing.T) {
	// Not parallel — mutates package-global state.

	origData := globalData
	origSecrets := secrets
	origIdtURL := idtURL
	origClientID := os.Getenv("BW_CLIENTID")
	origClientSecret := os.Getenv("BW_CLIENTSECRET")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		idtURL = origIdtURL
		os.Setenv("BW_CLIENTID", origClientID)
		os.Setenv("BW_CLIENTSECRET", origClientSecret)
	})

	var tokenCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/connect/token":
			tokenCalled = true
			r.ParseForm()
			qt.Assert(t, r.FormValue("grant_type"), qt.Equals, "refresh_token")
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "refreshed-token",
				RefreshToken: "new-refresh",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	idtURL = server.URL

	globalData = dataFile{
		AccessToken:  "expired-token",
		RefreshToken: "valid-refresh-token",
		TokenExpiry:  time.Now().Add(-1 * time.Hour), // Expired
	}
	secrets = secretCache{
		data:          &globalData,
		_clientId:     []byte("test-client-id"),
		_clientSecret: []byte("test-client-secret"),
	}
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	err := ensureToken(context.Background())
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, tokenCalled, qt.IsTrue)
	qt.Assert(t, globalData.AccessToken, qt.Equals, "refreshed-token")
	qt.Assert(t, globalData.RefreshToken, qt.Equals, "new-refresh")
}

// TestEnsureToken_NoRefreshToken_NoLogin verifies that ensureToken() returns
// an error when the token is expired, no refresh token is available, and login
// fails.
func TestEnsureToken_NoRefreshToken_NoLogin(t *testing.T) {
	// Not parallel — mutates package-global state.
	origData := globalData
	origSecrets := secrets
	origIdtURL := idtURL
	origClientID := os.Getenv("BW_CLIENTID")
	origClientSecret := os.Getenv("BW_CLIENTSECRET")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		idtURL = origIdtURL
		os.Setenv("BW_CLIENTID", origClientID)
		os.Setenv("BW_CLIENTSECRET", origClientSecret)
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a failed login.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	idtURL = server.URL

	globalData = dataFile{
		AccessToken:  "expired-token",
		RefreshToken: "",                             // No refresh token
		TokenExpiry:  time.Now().Add(-1 * time.Hour), // Expired
	}
	secrets = secretCache{
		data: &globalData,
	}

	// Set env for API key login.
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	err := ensureToken(context.Background())
	qt.Assert(t, err, qt.IsNotNil)
}

// TestDeriveMasterKey verifies that deriveMasterKey() correctly derives a
// master key from password and email. This covers crypto.go:270 (40% coverage).
func TestDeriveMasterKey(t *testing.T) {
	t.Parallel()

	password := []byte("test-password")
	email := "test@example.com"

	// Test PBKDF2-SHA256 (KDF 0).
	key, err := deriveMasterKey(password, email, KDFTypePBKDF2, 100000, 0, 0)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(key), qt.Equals, 32)

	// Test Argon2id (KDF 1).
	key, err = deriveMasterKey(password, email, KDFTypeArgon2id, 3, 64, 4)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(key), qt.Equals, 32)

	// Test unsupported KDF type.
	_, err = deriveMasterKey(password, email, KDFType(99), 100000, 0, 0)
	qt.Assert(t, err, qt.ErrorMatches, "unsupported KDF type.*")
}

// TestInitKeys_UnsupportedCipherType verifies that initKeys() returns an error
// when the profile key cipher type is unsupported. This covers crypto.go:167
// (45.8% coverage).
func TestInitKeys_UnsupportedCipherType(t *testing.T) {
	// Not parallel — mutates package-global state.
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", "test@example.com")
	secrets = secretCache{
		_password: []byte("test-password"),
		data: &dataFile{
			KDFIterations: 100000,
			Sync: SyncData{
				Profile: Profile{
					Key: CipherString{Type: CipherStringType(99)}, // Unsupported type
				},
			},
		},
	}

	err := secrets.initKeys()
	qt.Assert(t, err, qt.ErrorMatches, "unsupported key cipher type.*")
}

// TestInitKeys_NoEmail verifies that initKeys() returns an error when no email
// is available.
func TestInitKeys_NoEmail(t *testing.T) {
	// Not parallel — mutates package-global state.
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Unsetenv("EMAIL")
	secrets = secretCache{
		_password: []byte("test-password"),
		data: &dataFile{
			KDFIterations: 100000,
			Sync: SyncData{
				Profile: Profile{
					Key: CipherString{Type: AesCbc256_B64},
				},
			},
		},
	}

	err := secrets.initKeys()
	qt.Assert(t, err, qt.ErrorMatches, "need a configured email.*")
}

// TestStorePasswordLibsecret_NoSecretTool verifies that storePasswordLibsecret()
// handles the case where secret-tool is not available. This covers auth.go:317
// (57.1% coverage).
func TestStorePasswordLibsecret_NoSecretTool(t *testing.T) {
	// Not parallel — mutates PATH.
	origPath := os.Getenv("PATH")
	t.Cleanup(func() {
		os.Setenv("PATH", origPath)
	})

	// Set PATH to empty so secret-tool is not found.
	os.Setenv("PATH", "")

	// This should not panic or error, just print a warning.
	storePasswordLibsecret([]byte("test-password"))
}

// TestUnpadPKCS7 verifies that unpadPKCS7() correctly removes PKCS7 padding.
// This covers crypto.go:402 (71.4% coverage).
func TestUnpadPKCS7(t *testing.T) {
	t.Parallel()

	// Test valid padding (16 bytes total: 13 bytes data + 3 bytes padding).
	data := []byte("test data 123\x03\x03\x03")
	unpadded, err := unpadPKCS7(data, 16)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(unpadded), qt.Equals, "test data 123")

	// Test invalid padding (data not multiple of block size - 15 bytes).
	data = []byte("test data 12345")
	_, err = unpadPKCS7(data, 16)
	qt.Assert(t, err, qt.ErrorMatches, "expected PKCS7 padding.*")

	// Test invalid padding (padding byte > data length).
	data = []byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
	_, err = unpadPKCS7(data, 16)
	qt.Assert(t, err, qt.ErrorMatches, "cannot unpad.*")
}

// TestSync_UnmarshalText_InvalidType verifies that CipherString.UnmarshalText()
// returns an error for invalid cipher string types. This covers sync.go:73
// (74.1% coverage).
func TestSync_UnmarshalText_InvalidType(t *testing.T) {
	t.Parallel()

	var cs CipherString
	err := cs.UnmarshalText([]byte("99.iv|ct|mac"))
	qt.Assert(t, err, qt.ErrorMatches, "unsupported cipher string type.*")
}

// TestSync_UnmarshalText_NoDot verifies that CipherString.UnmarshalText()
// returns an error when the cipher string doesn't contain a dot.
func TestSync_UnmarshalText_NoDot(t *testing.T) {
	t.Parallel()

	var cs CipherString
	err := cs.UnmarshalText([]byte("invalid"))
	qt.Assert(t, err, qt.ErrorMatches, "cipher string does not contain a type.*")
}

// TestSync_UnmarshalText_InvalidTypeNumber verifies that CipherString.UnmarshalText()
// returns an error when the type is not a number.
func TestSync_UnmarshalText_InvalidTypeNumber(t *testing.T) {
	t.Parallel()

	var cs CipherString
	err := cs.UnmarshalText([]byte("abc.iv|ct|mac"))
	qt.Assert(t, err, qt.ErrorMatches, "invalid cipher string type.*")
}
