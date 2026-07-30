// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

// resetLoginState resets global state and env vars for login tests.
// Returns a cleanup function.
func resetLoginState(t *testing.T) {
	t.Helper()
	globalData = dataFile{DeviceID: "test-device-id"}
	secrets = secretCache{data: &globalData}
	saveData = false

	// Save and restore defaults for URLs and prompt funcs.
	t.Cleanup(func() {
		os.Unsetenv("BW_CLIENTID")
		os.Unsetenv("BW_CLIENTSECRET")
		os.Unsetenv("EMAIL")
		os.Unsetenv("PASSWORD")
		os.Unsetenv("FORCE_STDIN_PROMPTS")
		os.Unsetenv("SSH_ASKPASS")
	})
}

// mockPromptFuncs installs mock prompt functions and returns a cleanup func.
func mockPromptFuncs(t *testing.T, password []byte, lines ...string) {
	t.Helper()
	lineIdx := 0
	readLineFunc = func(prompt string) ([]byte, error) {
		if lineIdx >= len(lines) {
			return nil, fmt.Errorf("unexpected readLine prompt: %s", prompt)
		}
		line := lines[lineIdx]
		lineIdx++
		return []byte(line), nil
	}
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		return password, nil
	}
	t.Cleanup(func() {
		readLineFunc = readLine
		passwordPromptFunc = promptWithAskpass
	})
}

// TestLogin_ApiKey_BothSet verifies that when both BW_CLIENTID and
// BW_CLIENTSECRET are set, the client_credentials grant is used.
func TestLogin_ApiKey_BothSet(t *testing.T) {
	var preloginCalled, tokenCalled bool
	var grantType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			preloginCalled = true
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		case "/connect/token":
			tokenCalled = true
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

	resetLoginState(t)
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, preloginCalled, qt.IsFalse, qt.Commentf("prelogin must be skipped for API key login"))
	qt.Assert(t, tokenCalled, qt.IsTrue)
	qt.Assert(t, grantType, qt.Equals, "client_credentials")
	qt.Assert(t, globalData.AccessToken, qt.Equals, "test-access-token")
}

// TestLogin_ApiKey_OnlyId verifies that setting only BW_CLIENTID produces an error.
func TestLogin_ApiKey_OnlyId(t *testing.T) {
	resetLoginState(t)
	os.Setenv("BW_CLIENTID", "test-client-id")

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.ErrorMatches, ".*both be set or both be empty.*")
}

// TestLogin_ApiKey_OnlySecret verifies that setting only BW_CLIENTSECRET produces an error.
func TestLogin_ApiKey_OnlySecret(t *testing.T) {
	resetLoginState(t)
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.ErrorMatches, ".*both be set or both be empty.*")
}

// TestLogin_Interactive_No2FA verifies the basic interactive flow without 2FA.
func TestLogin_Interactive_No2FA(t *testing.T) {
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
	oldApiURL := apiURL
	idtURL = server.URL
	apiURL = "http://localhost" // non-default, so selectServer skips prompt
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	os.Setenv("EMAIL", "test@example.com")
	mockPromptFuncs(t, []byte("test-password"))

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, preloginCalled, qt.IsTrue)
	qt.Assert(t, tokenCalled, qt.IsTrue)
	qt.Assert(t, grantType, qt.Equals, "password")
	qt.Assert(t, globalData.AccessToken, qt.Equals, "test-access-token")
	qt.Assert(t, globalData.KDFIterations, qt.Equals, 100000)
}

// TestLogin_Interactive_2FA verifies the interactive flow with 2FA.
func TestLogin_Interactive_2FA(t *testing.T) {
	var tokenCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:           0,
				KDFIterations: 100000,
			})
		case "/connect/token":
			r.ParseForm()
			tokenCalls++
			if tokenCalls == 1 {
				// First call: return 2FA required error.
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"TwoFactorProviders2": map[string]map[string]interface{}{
						"0": {"Email": "test@example.com"},
					},
				})
				return
			}
			// Second call: succeed.
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
	oldApiURL := apiURL
	idtURL = server.URL
	apiURL = "http://localhost"
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	os.Setenv("EMAIL", "test@example.com")

	// Mock prompts: master password + 2FA token
	promptCount := 0
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		promptCount++
		if promptCount == 1 {
			return []byte("test-password"), nil
		}
		return []byte("123456"), nil // 2FA token
	}
	t.Cleanup(func() { passwordPromptFunc = promptWithAskpass })

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, tokenCalls, qt.Equals, 2)
	qt.Assert(t, globalData.AccessToken, qt.Equals, "test-access-token")
}

// TestLogin_Interactive_SelfHosted verifies server selection for self-hosted.
func TestLogin_Interactive_SelfHosted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// After selectServer, paths are prefixed with /identity/.
		switch {
		case strings.HasSuffix(r.URL.Path, "/accounts/prelogin"):
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		case strings.HasSuffix(r.URL.Path, "/connect/token"):
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken: "tok", ExpiresIn: 3600, TokenType: "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Reset URLs to defaults so selectServer prompts.
	oldIdtURL := idtURL
	oldApiURL := apiURL
	idtURL = defaultIdtURL
	apiURL = defaultApiURL
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	os.Setenv("EMAIL", "test@example.com")

	// readLineFunc returns: "self" for server choice, then the base URL.
	// But the token endpoint will be at server.URL + "/identity/connect/token",
	// which doesn't exist. We need the mock server to handle it.
	// Actually, after selectServer sets idtURL, the prelogin and token calls
	// go to the new URL. Let's use the mock server's URL as the base.
	mockPromptFuncs(t, []byte("test-password"), "self", server.URL)

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, apiURL, qt.Equals, server.URL+"/api")
	qt.Assert(t, idtURL, qt.Equals, server.URL+"/identity")
}

// TestLogin_Interactive_ConfigURL_NoPrompt verifies that non-default URLs skip server selection.
func TestLogin_Interactive_ConfigURL_NoPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		case "/connect/token":
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken: "tok", ExpiresIn: 3600, TokenType: "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	oldApiURL := apiURL
	idtURL = server.URL
	apiURL = "http://localhost" // non-default
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	os.Setenv("EMAIL", "test@example.com")

	readLineCalled := false
	readLineFunc = func(prompt string) ([]byte, error) {
		readLineCalled = true
		return []byte(""), nil
	}
	t.Cleanup(func() { readLineFunc = readLine })
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		return []byte("test-password"), nil
	}
	t.Cleanup(func() { passwordPromptFunc = promptWithAskpass })

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, readLineCalled, qt.IsFalse, qt.Commentf("readLine must not be called when URLs are non-default"))
}

// TestLogin_Interactive_EmailPrompt verifies that email is prompted when not configured.
func TestLogin_Interactive_EmailPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		case "/connect/token":
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken: "tok", ExpiresIn: 3600, TokenType: "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	oldApiURL := apiURL
	idtURL = server.URL
	apiURL = "http://localhost"
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	// No EMAIL set — should prompt.

	var emailPromptCalled bool
	readLineFunc = func(prompt string) ([]byte, error) {
		if strings.Contains(prompt, "email") {
			emailPromptCalled = true
			return []byte("prompted@example.com"), nil
		}
		return []byte("cloud"), nil // server selection
	}
	t.Cleanup(func() { readLineFunc = readLine })
	passwordPromptFunc = func(prompt string) ([]byte, error) {
		return []byte("test-password"), nil
	}
	t.Cleanup(func() { passwordPromptFunc = promptWithAskpass })

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, emailPromptCalled, qt.IsTrue, qt.Commentf("email should be prompted when not configured"))
}

// TestLogin_Interactive_Captcha verifies that captcha returns an error suggesting API key.
func TestLogin_Interactive_Captcha(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		case "/connect/token":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Captcha required."))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	oldApiURL := apiURL
	idtURL = server.URL
	apiURL = "http://localhost"
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	os.Setenv("EMAIL", "test@example.com")
	mockPromptFuncs(t, []byte("test-password"))

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.ErrorMatches, ".*captcha.*")
	qt.Assert(t, err, qt.ErrorMatches, ".*API key.*")
}

// TestLogin_Interactive_NonTTY verifies that non-TTY stdin without FORCE_STDIN_PROMPTS fails.
func TestLogin_Interactive_NonTTY(t *testing.T) {
	resetLoginState(t)
	// FORCE_STDIN_PROMPTS is not set.
	// In test environment, stdin is not a terminal.
	os.Unsetenv("FORCE_STDIN_PROMPTS")

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.ErrorMatches, ".*requires a terminal.*")
}

// TestLogin_Interactive_StoresLibsecret verifies that the master password is
// stored in libsecret via secret-tool after successful interactive login.
func TestLogin_Interactive_StoresLibsecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		case "/connect/token":
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken: "tok", ExpiresIn: 3600, TokenType: "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldIdtURL := idtURL
	oldApiURL := apiURL
	idtURL = server.URL
	apiURL = "http://localhost"
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	os.Setenv("EMAIL", "test@example.com")
	mockPromptFuncs(t, []byte("my-master-password"))

	// Create a fake secret-tool on PATH that records its stdin.
	tmpDir := t.TempDir()
	fakeSecretTool := filepath.Join(tmpDir, "secret-tool")
	// The fake writes its stdin to a file so we can verify.
	outputFile := filepath.Join(tmpDir, "secret-tool-input")
	err := os.WriteFile(fakeSecretTool, []byte(fmt.Sprintf(`#!/bin/sh
cat > %s
`, outputFile)), 0o755)
	qt.Assert(t, err, qt.IsNil)

	// Prepend our tmpDir to PATH so our fake secret-tool is found first.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+oldPath)
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })

	ctx := context.Background()
	err = login(ctx)
	qt.Assert(t, err, qt.IsNil)

	// Verify secret-tool received the password on stdin.
	input, err := os.ReadFile(outputFile)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, strings.TrimSpace(string(input)), qt.Equals, "my-master-password")
}

// TestPromptWithAskpass_PriorityChain verifies the priority: zenity > kdialog > SSH_ASKPASS > terminal.
func TestPromptWithAskpass_PriorityChain(t *testing.T) {
	// Create fake executables in temp dirs.
	makeFake := func(dir, name, output string) {
		t.Helper()
		path := filepath.Join(dir, name)
		err := os.WriteFile(path, []byte(fmt.Sprintf("#!/bin/sh\necho %s\n", output)), 0o755)
		qt.Assert(t, err, qt.IsNil)
	}

	t.Run("zenity_wins", func(t *testing.T) {
		dir := t.TempDir()
		makeFake(dir, "zenity", "zenity-password")
		makeFake(dir, "kdialog", "kdialog-password")
		oldPath := os.Getenv("PATH")
		os.Setenv("PATH", dir+":"+oldPath)
		defer os.Setenv("PATH", oldPath)
		os.Unsetenv("SSH_ASKPASS")

		out, err := promptWithAskpass("test prompt")
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, string(out), qt.Equals, "zenity-password")
	})

	t.Run("kdialog_when_no_zenity", func(t *testing.T) {
		dir := t.TempDir()
		makeFake(dir, "kdialog", "kdialog-password")
		oldPath := os.Getenv("PATH")
		// Set PATH to only include our dir (no zenity).
		os.Setenv("PATH", dir)
		defer os.Setenv("PATH", oldPath)
		os.Unsetenv("SSH_ASKPASS")

		out, err := promptWithAskpass("test prompt")
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, string(out), qt.Equals, "kdialog-password")
	})

	t.Run("SSH_ASKPASS_when_no_gui", func(t *testing.T) {
		dir := t.TempDir()
		askpassScript := filepath.Join(dir, "my-askpass")
		err := os.WriteFile(askpassScript, []byte("#!/bin/sh\necho askpass-password\n"), 0o755)
		qt.Assert(t, err, qt.IsNil)

		oldPath := os.Getenv("PATH")
		os.Setenv("PATH", dir) // no zenity, no kdialog
		defer os.Setenv("PATH", oldPath)
		os.Setenv("SSH_ASKPASS", askpassScript)
		defer os.Unsetenv("SSH_ASKPASS")

		out, err := promptWithAskpass("test prompt")
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, string(out), qt.Equals, "askpass-password")
	})
}

// TestLogin_BothEnvAndLibsecret_EnvWins verifies that when BW_CLIENTID is set
// in env AND secretCache has different values (simulating libsecret), the env
// values are used in the request.
func TestLogin_BothEnvAndLibsecret_EnvWins(t *testing.T) {
	var receivedClientId, receivedClientSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/connect/token":
			r.ParseForm()
			receivedClientId = r.FormValue("client_id")
			receivedClientSecret = r.FormValue("client_secret")
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

	resetLoginState(t)
	os.Setenv("BW_CLIENTID", "env-client-id")
	os.Setenv("BW_CLIENTSECRET", "env-client-secret")

	// Set secretCache to different values (simulating libsecret)
	secrets = secretCache{
		data:          &globalData,
		_clientId:     []byte("libsecret-client-id"),
		_clientSecret: []byte("libsecret-client-secret"),
	}

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)

	qt.Assert(t, receivedClientId, qt.Equals, "env-client-id")
	qt.Assert(t, receivedClientSecret, qt.Equals, "env-client-secret")
}

// TestLogin_NoEnv_LibsecretFallback verifies that when BW_CLIENTID is NOT set
// in env but secretCache has values (simulating libsecret), the libsecret
// values are used via loginApiKey (called directly).
func TestLogin_NoEnv_LibsecretFallback(t *testing.T) {
	var receivedClientId, receivedClientSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/connect/token":
			r.ParseForm()
			receivedClientId = r.FormValue("client_id")
			receivedClientSecret = r.FormValue("client_secret")
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

	resetLoginState(t)
	// No env vars set.
	os.Unsetenv("BW_CLIENTID")
	os.Unsetenv("BW_CLIENTSECRET")

	// Set secretCache values (simulating libsecret)
	secrets = secretCache{
		data:          &globalData,
		_clientId:     []byte("libsecret-client-id"),
		_clientSecret: []byte("libsecret-client-secret"),
	}

	// Call loginApiKey directly since without env vars, login() dispatches
	// to loginInteractive. This test verifies buildApiKeyGrant's libsecret fallback.
	ctx := context.Background()
	err := loginApiKey(ctx)
	qt.Assert(t, err, qt.IsNil)

	qt.Assert(t, receivedClientId, qt.Equals, "libsecret-client-id")
	qt.Assert(t, receivedClientSecret, qt.Equals, "libsecret-client-secret")
}

// TestLogin_HeadersMatchUpstream verifies that all 5 central headers on every
// request match the upstream Bitwarden CLI profile.
func TestLogin_HeadersMatchUpstream(t *testing.T) {
	var capturedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
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

	resetLoginState(t)
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)

	qt.Assert(t, capturedHeaders.Get("Accept"), qt.Equals, "application/json")
	qt.Assert(t, capturedHeaders.Get("User-Agent"), qt.Equals, "Bitwarden_CLI/2026.7.0 (LINUX)")
	qt.Assert(t, capturedHeaders.Get("Bitwarden-Client-Name"), qt.Equals, "cli")
	qt.Assert(t, capturedHeaders.Get("Bitwarden-Client-Version"), qt.Equals, "2026.7.0")
	qt.Assert(t, capturedHeaders.Get("Device-Type"), qt.Equals, "25")
	qt.Assert(t, capturedHeaders.Get("Bitwarden-Package-Type"), qt.Equals, "")
}

// TestLogin_PasswordFallback verifies that the password grant is used in
// interactive mode (no API key env vars).
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
	oldApiURL := apiURL
	idtURL = server.URL
	apiURL = "http://localhost" // non-default, skip server prompt
	defer func() {
		idtURL = oldIdtURL
		apiURL = oldApiURL
	}()

	resetLoginState(t)
	os.Setenv("FORCE_STDIN_PROMPTS", "true")
	os.Setenv("EMAIL", "test@example.com")
	mockPromptFuncs(t, []byte("test-password"))

	ctx := context.Background()
	err := login(ctx)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, grantType, qt.Equals, "password")

	// Auth-Email must not be sent on the password grant request.
	qt.Assert(t, capturedHeaders.Get("Auth-Email"), qt.Equals, "",
		qt.Commentf("Auth-Email header must not be sent"))
}

// TestEmailFromAccessToken verifies the JWT email-extraction helper.
func TestEmailFromAccessToken(t *testing.T) {
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
