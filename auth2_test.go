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

// TestLoginApiKey_Success verifies that loginApiKey succeeds when the server
// returns a valid token response.
func TestLoginApiKey_Success(t *testing.T) {
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
		switch r.URL.Path {
		case "/connect/token":
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	idtURL = server.URL
	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{data: &globalData}
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	err := loginApiKey(context.Background())
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, globalData.AccessToken, qt.Equals, "new-access-token")
}

// TestLoginApiKey_ServerError verifies that loginApiKey returns an error when
// the server returns an error response.
func TestLoginApiKey_ServerError(t *testing.T) {
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
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	idtURL = server.URL
	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{data: &globalData}
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	err := loginApiKey(context.Background())
	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Contains, "client_credentials login failed")
}

// TestBuildApiKeyGrant_EnvVars verifies that buildApiKeyGrant uses env vars
// when BW_CLIENTID and BW_CLIENTSECRET are set.
func TestBuildApiKeyGrant_EnvVars(t *testing.T) {
	origClientID := os.Getenv("BW_CLIENTID")
	origClientSecret := os.Getenv("BW_CLIENTSECRET")
	t.Cleanup(func() {
		os.Setenv("BW_CLIENTID", origClientID)
		os.Setenv("BW_CLIENTSECRET", origClientSecret)
	})

	os.Setenv("BW_CLIENTID", "env-client-id")
	os.Setenv("BW_CLIENTSECRET", "env-client-secret")

	values, err := buildApiKeyGrant()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, values.Get("client_id"), qt.Equals, "env-client-id")
	qt.Assert(t, values.Get("client_secret"), qt.Equals, "env-client-secret")
	qt.Assert(t, values.Get("grant_type"), qt.Equals, "client_credentials")
}

// TestBuildApiKeyGrant_PromptFallback verifies that buildApiKeyGrant falls back
// to prompts when env vars are not set.
func TestBuildApiKeyGrant_PromptFallback(t *testing.T) {
	origSecrets := secrets
	origClientID := os.Getenv("BW_CLIENTID")
	origClientSecret := os.Getenv("BW_CLIENTSECRET")
	t.Cleanup(func() {
		secrets = origSecrets
		os.Setenv("BW_CLIENTID", origClientID)
		os.Setenv("BW_CLIENTSECRET", origClientSecret)
	})

	os.Unsetenv("BW_CLIENTID")
	os.Unsetenv("BW_CLIENTSECRET")
	secrets = secretCache{}

	// Mock passwordPromptFunc to return credentials
	oldPrompt := passwordPromptFunc
	promptCount := 0
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		promptCount++
		if promptCount == 1 {
			return []byte("prompted-client-id"), nil
		}
		return []byte("prompted-client-secret"), nil
	}
	t.Cleanup(func() { passwordPromptFunc = oldPrompt })

	values, err := buildApiKeyGrant()
	qt.Assert(t, err, qt.IsNil)
	// The values should be the prompted credentials
	qt.Assert(t, values.Get("client_id"), qt.Not(qt.Equals), "")
	qt.Assert(t, values.Get("client_secret"), qt.Not(qt.Equals), "")
	qt.Assert(t, values.Get("grant_type"), qt.Equals, "client_credentials")
}

// TestRefreshToken_Success verifies that refreshToken succeeds when the server
// returns a valid token response.
func TestRefreshToken_Success(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origIdtURL := idtURL
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		idtURL = origIdtURL
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/connect/token":
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
		RefreshToken: "old-refresh-token",
	}
	secrets = secretCache{
		data:          &globalData,
		_clientId:     []byte("test-client-id"),
		_clientSecret: []byte("test-client-secret"),
	}

	err := refreshToken(context.Background())
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, globalData.AccessToken, qt.Equals, "refreshed-token")
	qt.Assert(t, globalData.RefreshToken, qt.Equals, "new-refresh")
}

// TestRefreshToken_ServerError verifies that refreshToken returns an error when
// the server returns an error response.
func TestRefreshToken_ServerError(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origIdtURL := idtURL
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		idtURL = origIdtURL
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	idtURL = server.URL
	globalData = dataFile{
		RefreshToken: "old-refresh-token",
	}
	secrets = secretCache{
		data:          &globalData,
		_clientId:     []byte("test-client-id"),
		_clientSecret: []byte("test-client-secret"),
	}

	err := refreshToken(context.Background())
	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Contains, "could not refresh token")
}

// TestSelectServer_Cloud verifies that selectServer accepts "cloud" as a choice.
func TestSelectServer_Cloud(t *testing.T) {
	origReadLine := readLineFunc
	origAPIURL := apiURL
	origIDTURL := idtURL
	t.Cleanup(func() {
		readLineFunc = origReadLine
		apiURL = origAPIURL
		idtURL = origIDTURL
	})

	// Reset to defaults
	apiURL = defaultApiURL
	idtURL = defaultIdtURL

	readLineFunc = func(prompt string) ([]byte, error) {
		return []byte("cloud"), nil
	}

	err := selectServer()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, apiURL, qt.Equals, defaultApiURL)
	qt.Assert(t, idtURL, qt.Equals, defaultIdtURL)
}

// TestSelectServer_SelfHosted verifies that selectServer accepts "self" as a
// choice and updates apiURL/idtURL.
func TestSelectServer_SelfHosted(t *testing.T) {
	origReadLine := readLineFunc
	origAPIURL := apiURL
	origIDTURL := idtURL
	t.Cleanup(func() {
		readLineFunc = origReadLine
		apiURL = origAPIURL
		idtURL = origIDTURL
	})

	// Reset to defaults
	apiURL = defaultApiURL
	idtURL = defaultIdtURL

	promptCount := 0
	readLineFunc = func(prompt string) ([]byte, error) {
		promptCount++
		if promptCount == 1 {
			return []byte("self"), nil
		}
		return []byte("https://bw.example.com"), nil
	}

	err := selectServer()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, apiURL, qt.Equals, "https://bw.example.com/api")
	qt.Assert(t, idtURL, qt.Equals, "https://bw.example.com/identity")
}

// TestSelectServer_EmptyBaseURL verifies that selectServer returns an error
// when the user provides an empty base URL for self-hosted.
func TestSelectServer_EmptyBaseURL(t *testing.T) {
	origReadLine := readLineFunc
	origAPIURL := apiURL
	origIDTURL := idtURL
	t.Cleanup(func() {
		readLineFunc = origReadLine
		apiURL = origAPIURL
		idtURL = origIDTURL
	})

	// Reset to defaults
	apiURL = defaultApiURL
	idtURL = defaultIdtURL

	promptCount := 0
	readLineFunc = func(prompt string) ([]byte, error) {
		promptCount++
		if promptCount == 1 {
			return []byte("self"), nil
		}
		return []byte(""), nil
	}

	err := selectServer()
	qt.Assert(t, err, qt.ErrorMatches, "no base URL provided")
}

// TestLoginInteractive_TTYGate verifies that loginInteractive returns an error
// when stdin is not a TTY and FORCE_STDIN_PROMPTS is not set.
func TestLoginInteractive_TTYGate(t *testing.T) {
	origForceStdin := os.Getenv("FORCE_STDIN_PROMPTS")
	t.Cleanup(func() {
		os.Setenv("FORCE_STDIN_PROMPTS", origForceStdin)
	})

	os.Unsetenv("FORCE_STDIN_PROMPTS")

	err := loginInteractive(context.Background())
	qt.Assert(t, err, qt.ErrorMatches, "interactive login requires a terminal.*")
}

// TestEnsureToken_LoginError verifies that ensureToken returns an error when
// login fails (no refresh token, expired access token).
func TestEnsureToken_LoginError(t *testing.T) {
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
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	idtURL = server.URL
	globalData = dataFile{
		AccessToken:  "expired-token",
		RefreshToken: "",                             // No refresh token
		TokenExpiry:  time.Now().Add(-1 * time.Hour), // Expired
	}
	secrets = secretCache{data: &globalData}
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	err := ensureToken(context.Background())
	qt.Assert(t, err, qt.IsNotNil)
}

// TestEnsureToken_RefreshTokenError verifies that ensureToken returns an error
// when refreshToken fails.
func TestEnsureToken_RefreshTokenError(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origIdtURL := idtURL
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		idtURL = origIdtURL
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
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

	err := ensureToken(context.Background())
	qt.Assert(t, err, qt.IsNotNil)
}

// TestTwoFactorProvider_UnmarshalText_Invalid verifies that TwoFactorProvider.UnmarshalText
// returns an error for invalid provider values.
func TestTwoFactorProvider_UnmarshalText_Invalid(t *testing.T) {
	t.Parallel()

	var p TwoFactorProvider
	err := p.UnmarshalText([]byte("invalid"))
	qt.Assert(t, err, qt.ErrorMatches, "invalid two-factor auth provider.*")

	err = p.UnmarshalText([]byte("-1"))
	qt.Assert(t, err, qt.ErrorMatches, "invalid two-factor auth provider.*")

	err = p.UnmarshalText([]byte("99"))
	qt.Assert(t, err, qt.ErrorMatches, "invalid two-factor auth provider.*")
}

// TestTwoFactorProvider_UnmarshalText_Valid verifies that TwoFactorProvider.UnmarshalText
// accepts valid provider values.
func TestTwoFactorProvider_UnmarshalText_Valid(t *testing.T) {
	t.Parallel()

	var p TwoFactorProvider
	err := p.UnmarshalText([]byte("0"))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, p, qt.Equals, Authenticator)

	err = p.UnmarshalText([]byte("1"))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, p, qt.Equals, Email)
}
