// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
)

// TestDispatch_Login_ApiKey verifies that dispatch("login") routes to
// loginApiKey when BW_CLIENTID/BW_CLIENTSECRET are set.
func TestDispatch_Login_ApiKey(t *testing.T) {
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

	err := dispatch(context.Background(), []string{"login"})
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, globalData.AccessToken, qt.Equals, "new-access-token")
}

// TestDispatch_Sync_WithValidToken verifies that dispatch("sync") succeeds
// when a valid token is cached.
func TestDispatch_Sync_WithValidToken(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origApiURL := apiURL
	origIdtURL := idtURL
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		apiURL = origApiURL
		idtURL = origIdtURL
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			json.NewEncoder(w).Encode(SyncData{
				Profile: Profile{Email: "test@example.com"},
			})
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	apiURL = server.URL
	idtURL = server.URL
	globalData = dataFile{
		AccessToken: "valid-token",
		TokenExpiry: time.Now().Add(time.Hour),
	}
	secrets = secretCache{data: &globalData}

	err := dispatch(context.Background(), []string{"sync"})
	qt.Assert(t, err, qt.IsNil)
}

// TestDispatch_Dump_NoCiphers verifies that dispatch("dump") succeeds with
// no ciphers (prints header only).
func TestDispatch_Dump_NoCiphers(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	globalData = dataFile{
		KDFIterations: 100000,
	}
	globalData.Sync.Profile.Email = localTestEmail
	globalData.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets = secretCache{
		data:      &globalData,
		_password: []byte(localTestPassword),
	}
	secrets.initKeys()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := dispatch(context.Background(), []string{"dump"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [1024]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	qt.Assert(t, output, qt.Contains, "# Logins:")
}

// TestDispatch_Get_NoCiphers verifies that dispatch("get") returns an error
// when the cipher is not found.
func TestDispatch_Get_NoCiphers(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	globalData = dataFile{
		KDFIterations: 100000,
	}
	globalData.Sync.Profile.Email = localTestEmail
	globalData.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets = secretCache{
		data:      &globalData,
		_password: []byte(localTestPassword),
	}
	secrets.initKeys()

	err := dispatch(context.Background(), []string{"get", "nonexistent"})
	qt.Assert(t, err, qt.ErrorMatches, "cipher .* not found")
}

// TestDispatch_Status verifies that dispatch("status") succeeds.
func TestDispatch_Status(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
	})

	globalData = dataFile{
		DeviceID:    "test-device-id",
		AccessToken: "test-token",
		TokenExpiry: time.Now().Add(time.Hour),
	}
	secrets = secretCache{data: &globalData}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := dispatch(context.Background(), []string{"status"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	qt.Assert(t, output, qt.Contains, "token_present")
}

// TestDispatch_Cache_NoManifest verifies that dispatch("cache") returns an
// error when the manifest file doesn't exist.
func TestDispatch_Cache_NoManifest(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origApiURL := apiURL
	origIdtURL := idtURL
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		apiURL = origApiURL
		idtURL = origIdtURL
		os.Setenv("EMAIL", origEmail)
	})

	// Set up a valid token so ensureToken doesn't try to re-auth
	os.Setenv("EMAIL", localTestEmail)
	globalData = dataFile{
		AccessToken:   "valid-token",
		TokenExpiry:   time.Now().Add(time.Hour),
		KDFIterations: 100000,
	}
	globalData.Sync.Profile.Email = localTestEmail
	globalData.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets = secretCache{
		data:      &globalData,
		_password: []byte(localTestPassword),
	}
	secrets.initKeys()

	// Mock server for sync/prelogin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			json.NewEncoder(w).Encode(SyncData{})
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	apiURL = server.URL
	idtURL = server.URL

	err := dispatch(context.Background(), []string{"cache", "-config", "/nonexistent/manifest.ini"})
	// cmdCache returns errCacheFailed when manifest can't be loaded
	qt.Assert(t, err, qt.Equals, errCacheFailed)
}

// TestDispatch_Create_NoPassword verifies that dispatch("create") returns an
// error when no password is available.
func TestDispatch_Create_NoPassword(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origApiURL := apiURL
	origIdtURL := idtURL
	origEmail := os.Getenv("EMAIL")
	origPassword := os.Getenv("PASSWORD")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		apiURL = origApiURL
		idtURL = origIdtURL
		os.Setenv("EMAIL", origEmail)
		os.Setenv("PASSWORD", origPassword)
	})

	os.Unsetenv("EMAIL")
	os.Unsetenv("PASSWORD")

	// Set up a valid token so ensureToken doesn't try to re-auth
	globalData = dataFile{
		AccessToken:   "valid-token",
		TokenExpiry:   time.Now().Add(time.Hour),
		KDFIterations: 100000,
	}
	secrets = secretCache{data: &globalData}

	// Mock server for sync/prelogin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			json.NewEncoder(w).Encode(SyncData{})
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	apiURL = server.URL
	idtURL = server.URL

	// Mock password prompt to return empty (simulating no password available)
	oldPrompt := passwordPromptFunc
	passwordPromptFunc = func(string) ([]byte, error) { return []byte(""), nil }
	t.Cleanup(func() { passwordPromptFunc = oldPrompt })

	err := dispatch(context.Background(), []string{"create", "test-cipher"})
	qt.Assert(t, err, qt.ErrorMatches, "empty secret.*")
}

// TestDispatch_UnknownCommand2 verifies that dispatch returns flag.ErrHelp
// for unknown commands (alternate name to avoid collision).
func TestDispatch_UnknownCommand2(t *testing.T) {
	stderr := captureStderr(t, func() {
		err := dispatch(context.Background(), []string{"unknown"})
		qt.Assert(t, err, qt.Equals, flag.ErrHelp)
	})

	qt.Assert(t, stderr, qt.Contains, "unknown command")
}

// TestDispatch_Create_HappyPath verifies that dispatch("create") succeeds
// with a valid setup.
func TestDispatch_Create_HappyPath(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origApiURL := apiURL
	origIdtURL := idtURL
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		apiURL = origApiURL
		idtURL = origIdtURL
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	globalData = dataFile{
		KDFIterations: 100000,
		AccessToken:   "test-token",
		TokenExpiry:   time.Now().Add(time.Hour),
	}
	globalData.Sync.Profile.Email = localTestEmail
	globalData.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets = secretCache{
		data:      &globalData,
		_password: []byte(localTestPassword),
	}
	secrets.initKeys()

	// Mock server for /sync and /ciphers/create
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			json.NewEncoder(w).Encode(SyncData{
				Profile: globalData.Sync.Profile,
				Ciphers: []Cipher{},
			})
		case "/ciphers/create":
			json.NewEncoder(w).Encode(Cipher{
				ID:   uuid.New(),
				Type: CipherLogin,
			})
		case "/accounts/prelogin":
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	apiURL = server.URL
	idtURL = server.URL

	// Mock password prompt
	oldPrompt := passwordPromptFunc
	passwordPromptFunc = func(string) ([]byte, error) { return []byte("test-secret"), nil }
	t.Cleanup(func() { passwordPromptFunc = oldPrompt })

	err := dispatch(context.Background(), []string{"create", "test-cipher"})
	qt.Assert(t, err, qt.IsNil)
}

// TestDispatch_Config2 verifies that dispatch handles the "config" command
// (though it's actually handled in run before dispatch is called).
func TestDispatch_Config2(t *testing.T) {
	// This test verifies that dispatch doesn't handle "config" - it's
	// handled in run() before dispatch is called. So dispatch("config")
	// should return flag.ErrHelp (unknown command).
	stderr := captureStderr(t, func() {
		err := dispatch(context.Background(), []string{"config"})
		qt.Assert(t, err, qt.Equals, flag.ErrHelp)
	})

	qt.Assert(t, stderr, qt.Contains, "unknown command")
}

// TestRun_ConfigCommand verifies that run("config") prints config and returns nil.
func TestRun_ConfigCommand(t *testing.T) {
	origData := globalData
	origSecrets := secrets
	origConfigDir := os.Getenv("CONFIG_DIR")
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
		os.Setenv("CONFIG_DIR", origConfigDir)
	})

	tmpDir := t.TempDir()
	os.Setenv("CONFIG_DIR", tmpDir)

	// Create empty config
	err := os.WriteFile(filepath.Join(tmpDir, "config"), []byte(""), 0o600)
	qt.Assert(t, err, qt.IsNil)

	globalData = dataFile{}
	secrets = secretCache{data: &globalData}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = run("config")
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [1024]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	qt.Assert(t, output, qt.Contains, "email")
	qt.Assert(t, output, qt.Contains, "apiURL")
}
