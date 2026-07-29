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
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestLogin_ClientCredentialsFirst verifies that when BW_CLIENTID is set,
// the client_credentials grant is attempted without prompting for a password.
func TestLogin_ClientCredentialsFirst(t *testing.T) {
	// Set up a mock identity server that tracks which endpoints were called.
	var preloginCalled, tokenCalled bool
	var grantType string
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
	qt.Assert(t, preloginCalled, qt.IsTrue, qt.Commentf("prelogin should be called"))
	qt.Assert(t, tokenCalled, qt.IsTrue, qt.Commentf("token endpoint should be called"))
	qt.Assert(t, grantType, qt.Equals, "client_credentials", qt.Commentf("should use client_credentials grant"))
}

// TestLogin_PasswordFallback verifies that when BW_CLIENTID is NOT set,
// the password grant is used.
func TestLogin_PasswordFallback(t *testing.T) {
	var grantType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
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
