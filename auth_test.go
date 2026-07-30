// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestLogin_ClientCredentialsFirst verifies that when BW_CLIENTID is set,
// the client_credentials grant is attempted without prompting for a password.
// As of Phase 3a (email-skip), /accounts/prelogin is also skipped — it is
// only required for the password grant.
func TestLogin_ClientCredentialsFirst(t *testing.T) {
	// Set up a mock identity server that tracks which endpoints were called.
	var preloginCalled, tokenCalled bool
	var grantType, deviceTypeVal, deviceNameVal, deviceIdentifier string
	var hdrClientName, hdrClientVersion, hdrDeviceType, hdrUserAgent, hdrAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			preloginCalled = true
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
			tokenCalled = true
			r.ParseForm()
			grantType = r.FormValue("grant_type")
			deviceTypeVal = r.FormValue("deviceType")
			deviceNameVal = r.FormValue("deviceName")
			deviceIdentifier = r.FormValue("deviceIdentifier")
			hdrClientName = r.Header.Get("Bitwarden-Client-Name")
			hdrClientVersion = r.Header.Get("Bitwarden-Client-Version")
			hdrDeviceType = r.Header.Get("Device-Type")
			hdrUserAgent = r.Header.Get("User-Agent")
			hdrAccept = r.Header.Get("Accept")
			// Return a successful token response.
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Override the identity URL to point to our mock server.
	oldIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = oldIdtURL }()

	// Set up environment: BW_CLIENTID and BW_CLIENTSECRET present.
	// EMAIL is set to prove it is now ignored (Phase 3a email-skip).
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")
	os.Setenv("EMAIL", "test@example.com")
	defer func() {
		os.Unsetenv("BW_CLIENTID")
		os.Unsetenv("BW_CLIENTSECRET")
		os.Unsetenv("EMAIL")
	}()

	// Reset global state.
	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{data: &globalData}
	saveData = false

	// Call login.
	ctx := context.Background()
	err := login(ctx, false)
	qt.Assert(t, err, qt.IsNil)

	// Verify the flow.
	// Phase 3a: prelogin is NOT called when BW_CLIENTID is set (client_credentials
	// grant does not need KDF parameters).
	qt.Assert(t, preloginCalled, qt.IsFalse, qt.Commentf("prelogin must be skipped when BW_CLIENTID is set (Phase 3a email-skip)"))
	qt.Assert(t, tokenCalled, qt.IsTrue, qt.Commentf("token endpoint should be called"))
	qt.Assert(t, grantType, qt.Equals, "client_credentials", qt.Commentf("should use client_credentials grant"))

	// Verify body fields match upstream profile.
	qt.Assert(t, deviceTypeVal, qt.Equals, "25", qt.Commentf("deviceType should be 25 (LinuxCLI)"))
	qt.Assert(t, deviceNameVal, qt.Equals, "bitw", qt.Commentf("deviceName should be bitw"))
	qt.Assert(t, deviceIdentifier, qt.Equals, "test-device-id", qt.Commentf("deviceIdentifier should match"))

	// Verify central headers match upstream profile.
	qt.Assert(t, hdrClientName, qt.Equals, "cli")
	qt.Assert(t, hdrClientVersion, qt.Equals, "2026.7.0")
	qt.Assert(t, hdrDeviceType, qt.Equals, "25")
	qt.Assert(t, hdrUserAgent, qt.Equals, "Bitwarden_CLI/2026.7.0 (LINUX)")
	qt.Assert(t, hdrAccept, qt.Equals, "application/json")
}

// TestLogin_PasswordFallback verifies that when BW_CLIENTID is NOT set,
// the password grant is used.
func TestLogin_PasswordFallback(t *testing.T) {
	var grantType string
	var capturedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			capturedHeaders = r.Header.Clone()
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
			capturedHeaders = r.Header.Clone()
			r.ParseForm()
			grantType = r.FormValue("grant_type")
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = oldIdtURL }()

	// No BW_CLIENTID set.
	os.Unsetenv("BW_CLIENTID")
	os.Unsetenv("BW_CLIENTSECRET")
	os.Setenv("EMAIL", "test@example.com")
	os.Setenv("PASSWORD", "test-password")
	defer func() {
		os.Unsetenv("EMAIL")
		os.Unsetenv("PASSWORD")
	}()

	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{data: &globalData}
	saveData = false

	ctx := context.Background()
	err := login(ctx, false)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, grantType, qt.Equals, "password", qt.Commentf("should use password grant"))

	// Auth-Email must not be sent on the password grant request.
	// The live identity.bitwarden.com server rejects this header with
	// invalid_username_or_password, blocking password grant login.
	// See commit message for the empirical curl evidence.
	qt.Assert(t, capturedHeaders.Get("Auth-Email"), qt.Equals, "",
		qt.Commentf("Auth-Email header must not be sent (live server rejects it as invalid_username_or_password)"))
}

// TestLogin_CaptchaNoticeToStderr verifies that captcha-related messages
// are written to stderr, not stdout.
func TestLogin_CaptchaNoticeToStderr(t *testing.T) {
	var captchaAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
			r.ParseForm()
			grantType := r.FormValue("grant_type")
			if grantType == "password" && captchaAttempts == 0 {
				// First password attempt: return captcha error.
				captchaAttempts++
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Captcha required."))
				return
			}
			// Subsequent attempts (client_credentials retry): succeed.
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = oldIdtURL }()

	// No API keys, so password grant is tried first, hits captcha, then retries with client_credentials.
	os.Unsetenv("BW_CLIENTID")
	os.Unsetenv("BW_CLIENTSECRET")
	os.Setenv("EMAIL", "test@example.com")
	os.Setenv("PASSWORD", "test-password")
	defer func() {
		os.Unsetenv("EMAIL")
		os.Unsetenv("PASSWORD")
	}()

	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{data: &globalData}
	saveData = false

	// Capture stderr and stdout.
	oldStderr := os.Stderr
	oldStdout := os.Stdout
	rStderr, wStderr, _ := os.Pipe()
	rStdout, wStdout, _ := os.Pipe()
	os.Stderr = wStderr
	os.Stdout = wStdout
	defer func() {
		os.Stderr = oldStderr
		os.Stdout = oldStdout
	}()

	ctx := context.Background()
	err := login(ctx, false)
	// login will fail because after captcha it tries client_credentials,
	// but we don't have BW_CLIENTID set, so it will prompt and fail.
	// That's OK — we just want to verify the captcha message went to stderr.
	_ = err

	wStderr.Close()
	wStdout.Close()
	var stderrBuf, stdoutBuf bytes.Buffer
	io.Copy(&stderrBuf, rStderr)
	io.Copy(&stdoutBuf, rStdout)

	stderrOutput := stderrBuf.String()
	stdoutOutput := stdoutBuf.String()

	// Verify captcha messages are on stderr.
	qt.Assert(t, strings.Contains(stderrOutput, "captcha"), qt.IsTrue, qt.Commentf("stderr should contain captcha message, got: %q", stderrOutput))
	qt.Assert(t, strings.Contains(stdoutOutput, "captcha"), qt.IsFalse, qt.Commentf("stdout should NOT contain captcha message, got: %q", stdoutOutput))
}

// TestLogin_BothEnvAndLibsecret_EnvWins verifies that when BW_CLIENTID is set
// in env AND secretCache has different values (simulating libsecret), the env
// values are used in the request.
func TestLogin_BothEnvAndLibsecret_EnvWins(t *testing.T) {
	var receivedClientId, receivedClientSecret string
	var hdrClientName, hdrClientVersion, hdrDeviceType, hdrUserAgent, hdrAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
			r.ParseForm()
			receivedClientId = r.FormValue("client_id")
			receivedClientSecret = r.FormValue("client_secret")
			hdrClientName = r.Header.Get("Bitwarden-Client-Name")
			hdrClientVersion = r.Header.Get("Bitwarden-Client-Version")
			hdrDeviceType = r.Header.Get("Device-Type")
			hdrUserAgent = r.Header.Get("User-Agent")
			hdrAccept = r.Header.Get("Accept")
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = oldIdtURL }()

	// Set env vars to one value
	os.Setenv("BW_CLIENTID", "env-client-id")
	os.Setenv("BW_CLIENTSECRET", "env-client-secret")
	os.Setenv("EMAIL", "test@example.com")
	defer func() {
		os.Unsetenv("BW_CLIENTID")
		os.Unsetenv("BW_CLIENTSECRET")
		os.Unsetenv("EMAIL")
	}()

	// Set secretCache to different values (simulating libsecret)
	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{
		data:          &globalData,
		_clientId:     []byte("libsecret-client-id"),
		_clientSecret: []byte("libsecret-client-secret"),
	}
	saveData = false

	ctx := context.Background()
	err := login(ctx, false)
	qt.Assert(t, err, qt.IsNil)

	// Verify env values were used, not libsecret values
	qt.Assert(t, receivedClientId, qt.Equals, "env-client-id", qt.Commentf("should use env client_id, not libsecret"))
	qt.Assert(t, receivedClientSecret, qt.Equals, "env-client-secret", qt.Commentf("should use env client_secret, not libsecret"))

	// Verify central headers are set correctly.
	qt.Assert(t, hdrClientName, qt.Equals, "cli")
	qt.Assert(t, hdrClientVersion, qt.Equals, "2026.7.0")
	qt.Assert(t, hdrDeviceType, qt.Equals, "25")
	qt.Assert(t, hdrUserAgent, qt.Equals, "Bitwarden_CLI/2026.7.0 (LINUX)")
	qt.Assert(t, hdrAccept, qt.Equals, "application/json")
}

// TestLogin_NoEnv_LibsecretFallback verifies that when BW_CLIENTID is NOT set
// in env but secretCache has values (simulating libsecret), the libsecret
// values are used.
func TestLogin_NoEnv_LibsecretFallback(t *testing.T) {
	var receivedClientId, receivedClientSecret string
	var hdrClientName, hdrClientVersion, hdrDeviceType, hdrUserAgent, hdrAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
			r.ParseForm()
			receivedClientId = r.FormValue("client_id")
			receivedClientSecret = r.FormValue("client_secret")
			hdrClientName = r.Header.Get("Bitwarden-Client-Name")
			hdrClientVersion = r.Header.Get("Bitwarden-Client-Version")
			hdrDeviceType = r.Header.Get("Device-Type")
			hdrUserAgent = r.Header.Get("User-Agent")
			hdrAccept = r.Header.Get("Accept")
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = oldIdtURL }()

	// No env vars set
	os.Unsetenv("BW_CLIENTID")
	os.Unsetenv("BW_CLIENTSECRET")
	os.Setenv("EMAIL", "test@example.com")
	defer func() {
		os.Unsetenv("EMAIL")
	}()

	// Set secretCache values (simulating libsecret)
	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{
		data:          &globalData,
		_clientId:     []byte("libsecret-client-id"),
		_clientSecret: []byte("libsecret-client-secret"),
	}
	saveData = false

	// Manually trigger the client_credentials path by setting retryWithApiKey=true
	// (since env is not set, useApiKey would be false otherwise)
	ctx := context.Background()
	err := login(ctx, true) // retryWithApiKey=true forces client_credentials path
	qt.Assert(t, err, qt.IsNil)

	// Verify libsecret values were used
	qt.Assert(t, receivedClientId, qt.Equals, "libsecret-client-id", qt.Commentf("should use libsecret client_id when env is empty"))
	qt.Assert(t, receivedClientSecret, qt.Equals, "libsecret-client-secret", qt.Commentf("should use libsecret client_secret when env is empty"))

	// Verify central headers are set correctly.
	qt.Assert(t, hdrClientName, qt.Equals, "cli")
	qt.Assert(t, hdrClientVersion, qt.Equals, "2026.7.0")
	qt.Assert(t, hdrDeviceType, qt.Equals, "25")
	qt.Assert(t, hdrUserAgent, qt.Equals, "Bitwarden_CLI/2026.7.0 (LINUX)")
	qt.Assert(t, hdrAccept, qt.Equals, "application/json")
}

// TestLogin_HeadersMatchUpstream verifies that all 5 central headers on every
// request match the upstream Bitwarden CLI profile (bitwarden/clients):
//   - Accept: application/json
//   - User-Agent: Bitwarden_CLI/2026.7.0 (LINUX)
//   - Bitwarden-Client-Name: cli
//   - Bitwarden-Client-Version: 2026.7.0
//   - Device-Type: 25 (numeric LinuxCLI enum value)
//
// Bitwarden-Package-Type is intentionally NOT sent (CLI's packageType() returns null).
func TestLogin_HeadersMatchUpstream(t *testing.T) {
	var capturedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			capturedHeaders = r.Header.Clone()
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
			capturedHeaders = r.Header.Clone()
			r.ParseForm()
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = oldIdtURL }()

	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")
	os.Setenv("EMAIL", "test@example.com")
	defer func() {
		os.Unsetenv("BW_CLIENTID")
		os.Unsetenv("BW_CLIENTSECRET")
		os.Unsetenv("EMAIL")
	}()

	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{data: &globalData}
	saveData = false

	ctx := context.Background()
	err := login(ctx, false)
	qt.Assert(t, err, qt.IsNil)

	// Verify all 5 central headers match the upstream CLI profile.
	qt.Assert(t, capturedHeaders.Get("Accept"), qt.Equals, "application/json",
		qt.Commentf("Accept header must be application/json"))
	qt.Assert(t, capturedHeaders.Get("User-Agent"), qt.Equals, "Bitwarden_CLI/2026.7.0 (LINUX)",
		qt.Commentf("User-Agent must match upstream CLI format"))
	qt.Assert(t, capturedHeaders.Get("Bitwarden-Client-Name"), qt.Equals, "cli",
		qt.Commentf("Bitwarden-Client-Name must be cli"))
	qt.Assert(t, capturedHeaders.Get("Bitwarden-Client-Version"), qt.Equals, "2026.7.0",
		qt.Commentf("Bitwarden-Client-Version must be CalVer 2026.7.0"))
	qt.Assert(t, capturedHeaders.Get("Device-Type"), qt.Equals, "25",
		qt.Commentf("Device-Type header must be numeric 25 (LinuxCLI)"))

	// Bitwarden-Package-Type must NOT be sent (CLI omits it).
	qt.Assert(t, capturedHeaders.Get("Bitwarden-Package-Type"), qt.Equals, "",
		qt.Commentf("Bitwarden-Package-Type must not be sent (CLI omits it)"))
}

// TestEmailFromAccessToken verifies the JWT email-extraction helper used as
// the 4th fallback in secrets.email() (crypto.go). Lets client_credentials
// users decrypt without configuring $EMAIL, a config file entry, or waiting
// for /sync to populate the profile email.
func TestEmailFromAccessToken(t *testing.T) {
	// buildJWT constructs a minimal JWT with the given payload claims.
	// Signature is fake (we don't verify it — same as upstream CLI).
	buildJWT := func(claims map[string]interface{}) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payloadBytes, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
		return header + "." + payload + ".fake-signature"
	}

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "valid JWT with email claim",
			token: buildJWT(map[string]interface{}{"email": "test@example.com", "sub": "user-uuid"}),
			want:  "test@example.com",
		},
		{
			name:  "JWT without email claim",
			token: buildJWT(map[string]interface{}{"sub": "user-uuid"}),
			want:  "",
		},
		{
			name:  "JWT with empty email claim",
			token: buildJWT(map[string]interface{}{"email": "", "sub": "user-uuid"}),
			want:  "",
		},
		{
			name:  "not a JWT (no dots)",
			token: "opaque-token-string",
			want:  "",
		},
		{
			name:  "not a JWT (one dot only)",
			token: "header.payload",
			want:  "",
		},
		{
			name:  "empty token",
			token: "",
			want:  "",
		},
		{
			name:  "JWT with malformed base64 payload",
			token: "header.!!!not-base64!!!.signature",
			want:  "",
		},
		{
			name:  "JWT with invalid JSON payload",
			token: "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature",
			want:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := emailFromAccessToken(tc.token)
			if got != tc.want {
				t.Errorf("emailFromAccessToken(%q) = %q, want %q", tc.token, got, tc.want)
			}
		})
	}
}
