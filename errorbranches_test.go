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
)

// TestDispatch_Sync verifies that dispatch routes to sync() correctly.
func TestDispatch_Sync(t *testing.T) {
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
		AccessToken: "test-token",
		TokenExpiry: time.Now().Add(time.Hour), // Valid token
	}
	secrets = secretCache{data: &globalData}

	err := dispatch(context.Background(), []string{"sync"})
	qt.Assert(t, err, qt.IsNil)
}

// TestDispatch_Dump verifies that dispatch routes to cmdDump() correctly.
func TestDispatch_Dump(t *testing.T) {
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

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	err := dispatch(context.Background(), []string{"dump"})
	w.Close()
	qt.Assert(t, err, qt.IsNil)
}

// TestCmdGet_NoCiphers verifies that cmdGet returns an error when no ciphers
// are available.
func TestCmdGet_NoCiphers(t *testing.T) {
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

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{},
		},
	}

	err := cmdGet(context.Background(), []string{"nonexistent"})
	qt.Assert(t, err, qt.ErrorMatches, "cipher .* not found")
}

// TestCmdGet_CipherNotFound verifies that cmdGet returns an error when the
// cipher is not found.
func TestCmdGet_CipherNotFound(t *testing.T) {
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

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{},
		},
	}

	err := cmdGet(context.Background(), []string{"nonexistent"})
	qt.Assert(t, err, qt.ErrorMatches, "cipher .* not found")
}

// TestDecrypt_InvalidCipherString verifies that decrypt returns an error for
// invalid cipher strings.
func TestDecrypt_InvalidCipherString(t *testing.T) {
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

	// Invalid cipher string (bad MAC)
	cs := CipherString{
		Type: AesCbc256_HmacSha256_B64,
		IV:   []byte("1234567890123456"),
		CT:   []byte("1234567890123456"),
		MAC:  []byte("invalid-mac-value"),
	}

	_, err := secrets.decrypt(cs, nil)
	qt.Assert(t, err, qt.ErrorMatches, ".*MAC.*")
}

// TestSave_InvalidPath verifies that Save returns an error when the path is
// invalid.
func TestSave_InvalidPath(t *testing.T) {
	df := &dataFile{
		path: "/nonexistent/dir/data.json",
	}

	err := df.Save()
	qt.Assert(t, err, qt.IsNotNil)
}

// TestJsonGET_InvalidURL verifies that jsonGET returns an error for invalid URLs.
func TestJsonGET_InvalidURL(t *testing.T) {
	var result interface{}
	err := jsonGET(context.Background(), "http://localhost:1/invalid", &result)
	qt.Assert(t, err, qt.IsNotNil)
}

// TestSync_ErrorResponse verifies that sync returns an error when the server
// returns an error response.
func TestSync_ErrorResponse(t *testing.T) {
	origApiURL := apiURL
	origIdtURL := idtURL
	origData := globalData
	origSecrets := secrets
	t.Cleanup(func() {
		apiURL = origApiURL
		idtURL = origIdtURL
		globalData = origData
		secrets = origSecrets
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	apiURL = server.URL
	idtURL = server.URL

	globalData = dataFile{
		AccessToken: "test-token",
	}
	secrets = secretCache{data: &globalData}

	err := sync(context.Background())
	qt.Assert(t, err, qt.IsNotNil)
}

// TestSelectServer_InvalidChoice verifies that selectServer returns an error
// for invalid server choices.
func TestSelectServer_InvalidChoice(t *testing.T) {
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
		return []byte("invalid-choice"), nil
	}

	err := selectServer()
	qt.Assert(t, err, qt.ErrorMatches, "unknown server choice.*")
}

// TestRun_NoArgs verifies that run returns flag.ErrHelp when no args are provided.
func TestRun_NoArgs(t *testing.T) {
	err := run()
	qt.Assert(t, err, qt.Equals, flag.ErrHelp)
}

// TestRun_Help verifies that run returns flag.ErrHelp for "help" command.
func TestRun_Help(t *testing.T) {
	err := run("help")
	qt.Assert(t, err, qt.Equals, flag.ErrHelp)
}

// TestRun_UnknownCommand verifies that run returns flag.ErrHelp for unknown commands.
func TestRun_UnknownCommand(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CONFIG_DIR", tmpDir)

	// Create empty config
	err := os.WriteFile(filepath.Join(tmpDir, "config"), []byte(""), 0o600)
	qt.Assert(t, err, qt.IsNil)

	stderr := captureStderr(t, func() {
		err := run("unknown")
		qt.Assert(t, err, qt.Equals, flag.ErrHelp)
	})

	qt.Assert(t, stderr, qt.Contains, "unknown command")
}

// TestLoadDataFile_NotExist verifies that loadDataFile succeeds when the file
// doesn't exist (creates empty data).
func TestLoadDataFile_NotExist(t *testing.T) {
	origData := globalData
	t.Cleanup(func() { globalData = origData })

	globalData = dataFile{}
	err := loadDataFile("/nonexistent/data.json")
	qt.Assert(t, err, qt.IsNil)
}

// TestLoadDataFile_InvalidJSON verifies that loadDataFile returns an error for
// invalid JSON.
func TestLoadDataFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "data.json")
	err := os.WriteFile(path, []byte("invalid json"), 0o600)
	qt.Assert(t, err, qt.IsNil)

	origData := globalData
	t.Cleanup(func() { globalData = origData })

	globalData = dataFile{}
	err = loadDataFile(path)
	qt.Assert(t, err, qt.ErrorMatches, "invalid character.*")
}

// TestBuildPasswordGrant_InvalidKDF verifies that buildPasswordGrant returns
// an error for invalid KDF types.
func TestBuildPasswordGrant_InvalidKDF(t *testing.T) {
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() { os.Setenv("EMAIL", origEmail) })

	os.Setenv("EMAIL", "test@example.com")

	preLogin := preLoginResponse{
		KDF:           99, // Invalid
		KDFIterations: 100000,
	}

	_, err := buildPasswordGrant("test@example.com", preLogin, []byte("password"))
	qt.Assert(t, err, qt.ErrorMatches, ".*KDF.*")
}

// TestFindCipherByName_NoLogin verifies that findCipherByName skips ciphers
// without Login field.
func TestFindCipherByName_NoLogin(t *testing.T) {
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

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{Name: encryptForTest(t, "Test")}, // No Login field
			},
		},
	}

	_, err := findCipherByName("Test")
	qt.Assert(t, err, qt.ErrorMatches, "cipher .* not found")
}

// TestMatch_DecryptError verifies that Match returns false when decryption fails.
func TestMatch_DecryptError(t *testing.T) {
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
		Name: CipherString{
			Type: AesCbc256_HmacSha256_B64,
			IV:   []byte("invalid"),
			CT:   []byte("invalid"),
			MAC:  []byte("invalid"),
		},
		Login: &Login{},
	}

	stderr := captureStderr(t, func() {
		result := cipher.Match("name", "test")
		qt.Assert(t, result, qt.IsFalse)
	})

	qt.Assert(t, stderr, qt.Contains, "could not decrypt")
}

// TestUrlValues_OddPairs verifies that urlValues panics when given an odd
// number of arguments.
func TestUrlValues_OddPairs(t *testing.T) {
	defer func() {
		r := recover()
		qt.Assert(t, r, qt.IsNotNil)
		qt.Assert(t, r.(string), qt.Contains, "pairs must be of even length")
	}()

	urlValues("key1", "value1", "key2")
}

// TestB64decode_Invalid verifies that b64decode returns an error for invalid
// base64 strings.
func TestB64decode_Invalid(t *testing.T) {
	_, err := b64decode([]byte("invalid-base64!!!"))
	qt.Assert(t, err, qt.IsNotNil)
}

// TestUnauthenticatedAESCBCDecrypt_InvalidIV verifies that
// unauthenticatedAESCBCDecrypt returns an error for invalid IV length.
func TestUnauthenticatedAESCBCDecrypt_InvalidIV(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 8) // Invalid: should be 16
	ciphertext := make([]byte, 16)

	_, err := unauthenticatedAESCBCDecrypt(iv, ciphertext, key)
	qt.Assert(t, err, qt.ErrorMatches, "iv length does not match.*")
}

// TestUnauthenticatedAESCBCDecrypt_InvalidCiphertext verifies that
// unauthenticatedAESCBCDecrypt returns an error for invalid ciphertext length.
func TestUnauthenticatedAESCBCDecrypt_InvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	ciphertext := make([]byte, 15) // Invalid: not multiple of block size

	_, err := unauthenticatedAESCBCDecrypt(iv, ciphertext, key)
	qt.Assert(t, err, qt.ErrorMatches, "ciphertext is not a multiple.*")
}

// TestResolveField_DecryptError verifies that resolveField returns an error
// when decryption fails.
func TestResolveField_DecryptError(t *testing.T) {
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
			Password: CipherString{
				Type: AesCbc256_HmacSha256_B64,
				IV:   []byte("invalid"),
				CT:   []byte("invalid"),
				MAC:  []byte("invalid"),
			},
		},
	}

	_, err := resolveField(cipher, "password")
	qt.Assert(t, err, qt.ErrorMatches, ".*MAC.*")
}

// TestCmdDump_DecryptError verifies that cmdDump returns an error when
// decryption fails.
func TestCmdDump_DecryptError(t *testing.T) {
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

	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{
				{
					Name: CipherString{
						Type: AesCbc256_HmacSha256_B64,
						IV:   []byte("invalid"),
						CT:   []byte("invalid"),
						MAC:  []byte("invalid"),
					},
					Login: &Login{},
				},
			},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	err := cmdDump(context.Background())
	w.Close()
	qt.Assert(t, err, qt.ErrorMatches, ".*MAC.*")
}
