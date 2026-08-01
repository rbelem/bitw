// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestResolveConfigDir_EnvVar verifies that resolveConfigDir returns
// $CONFIG_DIR when set.
func TestResolveConfigDir_EnvVar(t *testing.T) {
	t.Setenv("CONFIG_DIR", "/tmp/test-config")

	dir, err := resolveConfigDir()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, dir, qt.Equals, "/tmp/test-config")
}

// TestResolveConfigDir_Default verifies that resolveConfigDir returns
// os.UserConfigDir()/bitw when $CONFIG_DIR is not set.
func TestResolveConfigDir_Default(t *testing.T) {
	t.Setenv("CONFIG_DIR", "")

	dir, err := resolveConfigDir()
	qt.Assert(t, err, qt.IsNil)

	expected, _ := os.UserConfigDir()
	expected = filepath.Join(expected, "bitw")
	qt.Assert(t, dir, qt.Equals, expected)
}

// TestLoadConfig_Valid verifies that loadConfig correctly parses a valid
// config file.
func TestLoadConfig_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	err := os.WriteFile(configPath, []byte(`
email = test@example.com
apiurl = https://api.example.com
identityurl = https://identity.example.com
`), 0o600)
	qt.Assert(t, err, qt.IsNil)

	origSecrets := secrets
	origAPIURL := apiURL
	origIDTURL := idtURL
	t.Cleanup(func() {
		secrets = origSecrets
		apiURL = origAPIURL
		idtURL = origIDTURL
	})

	secrets = secretCache{}
	err = loadConfig(tmpDir)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, secrets._configEmail, qt.Equals, "test@example.com")
	qt.Assert(t, apiURL, qt.Equals, "https://api.example.com")
	qt.Assert(t, idtURL, qt.Equals, "https://identity.example.com")
}

// TestLoadConfig_UnknownKey verifies that loadConfig returns an error for
// unknown config keys.
func TestLoadConfig_UnknownKey(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	err := os.WriteFile(configPath, []byte(`
unknownkey = value
`), 0o600)
	qt.Assert(t, err, qt.IsNil)

	err = loadConfig(tmpDir)
	qt.Assert(t, err, qt.ErrorMatches, "unknown config key.*")
}

// TestLoadConfig_Sections verifies that loadConfig returns an error when
// the config file has sections.
func TestLoadConfig_Sections(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	err := os.WriteFile(configPath, []byte(`
[section]
email = test@example.com
`), 0o600)
	qt.Assert(t, err, qt.IsNil)

	err = loadConfig(tmpDir)
	qt.Assert(t, err, qt.ErrorMatches, "sections are not used.*")
}

// TestCmdDump_Basic verifies that cmdDump prints login ciphers as TSV.
func TestCmdDump_Basic(t *testing.T) {
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

	cipher := Cipher{
		Name: encryptForTest(t, "Test Cipher"),
		Login: &Login{
			URI:      encryptForTest(t, "https://example.com"),
			Username: encryptForTest(t, "testuser"),
			Password: encryptForTest(t, "testpass"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdDump(context.Background())
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [1024]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	qt.Assert(t, output, qt.Contains, "# Logins:")
	qt.Assert(t, output, qt.Contains, "Test Cipher")
	qt.Assert(t, output, qt.Contains, "https://example.com")
	qt.Assert(t, output, qt.Contains, "testuser")
	qt.Assert(t, output, qt.Contains, "testpass")
}

// TestDispatch_UnknownCommand verifies that dispatch returns flag.ErrHelp
// for unknown commands.
func TestDispatch_UnknownCommand(t *testing.T) {
	stderr := captureStderr(t, func() {
		err := dispatch(context.Background(), []string{"unknown"})
		qt.Assert(t, err, qt.Equals, flag.ErrHelp)
	})

	qt.Assert(t, stderr, qt.Contains, "unknown command")
}

// TestDispatch_Login verifies that dispatch routes to login() correctly.
func TestDispatch_Login(t *testing.T) {
	// This test verifies that dispatch routes to login() correctly.
	// We set up env for API key login and verify it attempts to call the server.

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

	// Set up a failing server
	idtURL = "http://localhost:1" // Invalid port to force error

	globalData = dataFile{}
	secrets = secretCache{data: &globalData}
	os.Setenv("BW_CLIENTID", "test-client-id")
	os.Setenv("BW_CLIENTSECRET", "test-client-secret")

	err := dispatch(context.Background(), []string{"login"})
	qt.Assert(t, err, qt.IsNotNil)
}

// TestLoadConfig_ClientCredentials verifies that loadConfig accepts
// clientid/clientsecret keys and stores them in the secretCache.
func TestLoadConfig_ClientCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	err := os.WriteFile(configPath, []byte(`
email = test@example.com
clientid = config-client-id
clientsecret = config-client-secret
`), 0o600)
	qt.Assert(t, err, qt.IsNil)

	origSecrets := secrets
	t.Cleanup(func() {
		secrets = origSecrets
	})

	secrets = secretCache{}
	err = loadConfig(tmpDir)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, secrets._configEmail, qt.Equals, "test@example.com")
	qt.Assert(t, secrets._configClientID, qt.Equals, "config-client-id")
	qt.Assert(t, secrets._configClientSecret, qt.Equals, "config-client-secret")
}
