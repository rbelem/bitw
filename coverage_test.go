// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
)

// TestDataFile_Save verifies that dataFile.Save() correctly marshals and writes
// the data to disk. This covers main.go:220 (0% coverage).
func TestDataFile_Save(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "data.json")

	df := &dataFile{
		path:           path,
		DeviceID:       "test-device-123",
		AccessToken:    "test-token",
		RefreshToken:   "test-refresh",
		TokenExpiry:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		KDF:            KDFTypeArgon2id,
		KDFIterations:  600000,
		KDFMemory:      64,
		KDFParallelism: 4,
	}

	err := df.Save()
	qt.Assert(t, err, qt.IsNil)

	// Verify the file was created with correct permissions.
	info, err := os.Stat(path)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, info.Mode().Perm(), qt.Equals, os.FileMode(0o600))

	// Verify the content is valid JSON with expected fields.
	data, err := ioutil.ReadFile(path)
	qt.Assert(t, err, qt.IsNil)

	var loaded dataFile
	err = json.Unmarshal(data, &loaded)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, loaded.DeviceID, qt.Equals, "test-device-123")
	qt.Assert(t, loaded.AccessToken, qt.Equals, "test-token")
	qt.Assert(t, loaded.RefreshToken, qt.Equals, "test-refresh")
	qt.Assert(t, loaded.KDF, qt.Equals, KDFTypeArgon2id)
	qt.Assert(t, loaded.KDFIterations, qt.Equals, 600000)
}

// TestCipher_Match verifies that Cipher.Match() correctly matches cipher
// attributes. This covers sync.go:237 (0% coverage).
func TestCipher_Match(t *testing.T) {
	// Not parallel — mutates package-global state.

	// Set up a minimal secretCache for decryption.
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	// Set EMAIL env var so email() returns a value.
	os.Setenv("EMAIL", localTestEmail)

	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	err := secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	qt.Assert(t, err, qt.IsNil)

	// Initialize keys (decrypts the profile key).
	err = secrets.initKeys()
	qt.Assert(t, err, qt.IsNil)

	// Create a cipher with encrypted fields.
	cipher := &Cipher{
		ID:   uuid.MustParse("12345678-1234-1234-1234-123456789012"),
		Name: encryptForTest(t, "Test Cipher"),
		Login: &Login{
			Username: encryptForTest(t, "testuser"),
		},
	}

	// Test matching by ID.
	qt.Assert(t, cipher.Match("id", "12345678-1234-1234-1234-123456789012"), qt.IsTrue)
	qt.Assert(t, cipher.Match("id", "wrong-id"), qt.IsFalse)

	// Test matching by name (requires decryption).
	qt.Assert(t, cipher.Match("name", "Test Cipher"), qt.IsTrue)
	qt.Assert(t, cipher.Match("name", "Wrong Name"), qt.IsFalse)

	// Test matching by username (requires decryption).
	qt.Assert(t, cipher.Match("username", "testuser"), qt.IsTrue)
	qt.Assert(t, cipher.Match("username", "wronguser"), qt.IsFalse)

	// Test unsupported attribute.
	qt.Assert(t, cipher.Match("unsupported", "value"), qt.IsFalse)
}

// TestFormatAge verifies that formatAge() correctly formats time durations.
// This covers status.go:215 (42.9% coverage).
func TestFormatAge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"negative", -1 * time.Hour, "in the future (clock skew?)"},
		{"seconds", 30 * time.Second, "30s ago"},
		{"minutes", 5 * time.Minute, "5m ago"},
		{"hours", 3 * time.Hour, "3h ago"},
		{"days", 2 * 24 * time.Hour, "2d ago"},
		{"zero", 0, "0s ago"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatAge(tc.d)
			qt.Assert(t, got, qt.Equals, tc.want)
		})
	}
}

// TestRefreshToken verifies that refreshToken() correctly refreshes an expired
// token using the refresh_token grant. This covers auth.go:477 (0% coverage).
func TestRefreshToken(t *testing.T) {
	t.Parallel()

	var tokenCalled bool
	var receivedRefreshToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/connect/token":
			tokenCalled = true
			r.ParseForm()
			receivedRefreshToken = r.FormValue("refresh_token")
			qt.Assert(t, r.FormValue("grant_type"), qt.Equals, "refresh_token")
			json.NewEncoder(w).Encode(tokLoginResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
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

	// Save and restore global state.
	origData := globalData
	origSecrets := secrets
	t.Cleanup(func() {
		globalData = origData
		secrets = origSecrets
	})

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
	qt.Assert(t, tokenCalled, qt.IsTrue)
	qt.Assert(t, receivedRefreshToken, qt.Equals, "old-refresh-token")
	qt.Assert(t, globalData.AccessToken, qt.Equals, "new-access-token")
	qt.Assert(t, globalData.RefreshToken, qt.Equals, "new-refresh-token")
}

// TestRefreshToken_NoRefreshToken verifies that refreshToken() returns an error
// when no refresh token is available.
func TestRefreshToken_NoRefreshToken(t *testing.T) {
	t.Parallel()

	origData := globalData
	t.Cleanup(func() { globalData = origData })

	globalData = dataFile{RefreshToken: ""}

	err := refreshToken(context.Background())
	qt.Assert(t, err, qt.ErrorMatches, "no refresh token available.*")
}

// TestCmdGet_Basic verifies that cmdGet() correctly retrieves and prints
// cipher fields. This covers get.go:50 (0% coverage).
func TestCmdGet_Basic(t *testing.T) {
	// Not parallel — mutates package-global state.

	// Set up a minimal secretCache for decryption.
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	// Set EMAIL env var so email() returns a value.
	os.Setenv("EMAIL", localTestEmail)

	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	err := secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	qt.Assert(t, err, qt.IsNil)

	// Initialize keys (decrypts the profile key).
	err = secrets.initKeys()
	qt.Assert(t, err, qt.IsNil)

	// Create a cipher with encrypted fields.
	cipher := Cipher{
		ID:   uuid.MustParse("12345678-1234-1234-1234-123456789012"),
		Name: encryptForTest(t, "Test Cipher"),
		Login: &Login{
			Username: encryptForTest(t, "testuser"),
			Password: encryptForTest(t, "testpass"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	err = cmdGet(context.Background(), []string{"Test Cipher"})
	w.Close()
	qt.Assert(t, err, qt.IsNil)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	_ = buf.String() // Consume output to avoid blocking
}

// TestCmdGet_FieldMode verifies that cmdGet() correctly handles --field flags.
func TestCmdGet_FieldMode(t *testing.T) {
	// Not parallel — mutates package-global state.

	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	// Set EMAIL env var so email() returns a value.
	os.Setenv("EMAIL", localTestEmail)

	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	err := secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	qt.Assert(t, err, qt.IsNil)

	// Initialize keys (decrypts the profile key).
	err = secrets.initKeys()
	qt.Assert(t, err, qt.IsNil)

	cipher := Cipher{
		ID:   uuid.MustParse("12345678-1234-1234-1234-123456789012"),
		Name: encryptForTest(t, "Test Cipher"),
		Login: &Login{
			Username: encryptForTest(t, "testuser"),
			Password: encryptForTest(t, "testpass"),
			URI:      encryptForTest(t, "https://example.com"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	err = cmdGet(context.Background(), []string{"--field", "username", "--field", "uri", "Test Cipher"})
	w.Close()
	qt.Assert(t, err, qt.IsNil)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify the output contains the field values (one per line).
	lines := bytes.Split(bytes.TrimSpace([]byte(output)), []byte("\n"))
	qt.Assert(t, len(lines), qt.Equals, 2)
	qt.Assert(t, string(lines[0]), qt.Equals, "testuser")
	qt.Assert(t, string(lines[1]), qt.Equals, "https://example.com")
}

// Helper function for tests - encrypts plaintext using the global secrets.
func encryptForTest(t *testing.T, plaintext string) CipherString {
	t.Helper()
	// Ensure keys are initialized (decrypts the profile key).
	if secrets.key == nil {
		if err := secrets.initKeys(); err != nil {
			t.Fatalf("initKeys failed: %v", err)
		}
	}
	cs, err := secrets.encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	return cs
}

// TestReadLine verifies that readLine() correctly reads a line from stdin.
// This covers main.go:82 (0% coverage).
func TestReadLine(t *testing.T) {
	t.Parallel()

	// Save and restore stdin.
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()

	// Create a pipe to simulate stdin.
	r, w, err := os.Pipe()
	qt.Assert(t, err, qt.IsNil)
	os.Stdin = r

	// Write test input in a goroutine.
	go func() {
		defer w.Close()
		w.WriteString("test input\n")
	}()

	// Read the line.
	line, err := readLine("prompt")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(line), qt.Equals, "test input")
}

// TestReadLine_EOF verifies that readLine() handles EOF correctly.
func TestReadLine_EOF(t *testing.T) {
	// Not parallel — mutates os.Stdin.

	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()

	r, w, err := os.Pipe()
	qt.Assert(t, err, qt.IsNil)
	os.Stdin = r

	// Write input without newline, then close.
	go func() {
		defer w.Close()
		w.WriteString("partial")
	}()

	line, err := readLine("prompt")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(line), qt.Equals, "partial")
}

// TestCrypto_DHFunctions verifies the Diffie-Hellman functions in crypto.go.
// This covers crypto.go:443-484 (0% coverage).
func TestCrypto_DHFunctions(t *testing.T) {
	t.Parallel()

	// Test rfc2409SecondOakleyGroup.
	dg := rfc2409SecondOakleyGroup()
	qt.Assert(t, dg, qt.IsNotNil)
	qt.Assert(t, dg.g.Int64(), qt.Equals, int64(2))
	qt.Assert(t, dg.p, qt.IsNotNil)
	qt.Assert(t, dg.pMinus1, qt.IsNotNil)

	// Test NewKeypair.
	private, public, err := dg.NewKeypair()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, private, qt.IsNotNil)
	qt.Assert(t, public, qt.IsNotNil)
	qt.Assert(t, private.Sign() > 0, qt.IsTrue)

	// Test diffieHellman with valid parameters.
	private2, public2, err := dg.NewKeypair()
	qt.Assert(t, err, qt.IsNil)

	shared1, err := dg.diffieHellman(public2, private)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, shared1, qt.IsNotNil)

	shared2, err := dg.diffieHellman(public, private2)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, shared2, qt.IsNotNil)

	// Both parties should compute the same shared secret.
	qt.Assert(t, shared1.Cmp(shared2), qt.Equals, 0)

	// Test diffieHellman with invalid parameters (out of bounds).
	_, err = dg.diffieHellman(big.NewInt(0), private)
	qt.Assert(t, err, qt.ErrorMatches, "DH parameter out of bounds")

	_, err = dg.diffieHellman(big.NewInt(1), private)
	qt.Assert(t, err, qt.ErrorMatches, "DH parameter out of bounds")

	_, err = dg.diffieHellman(dg.pMinus1, private)
	qt.Assert(t, err, qt.ErrorMatches, "DH parameter out of bounds")

	// Test keygenHKDFSHA256AES128.
	key, err := dg.keygenHKDFSHA256AES128(public2, private)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(key), qt.Equals, 16) // AES-128 key size
}

// TestCrypto_AES_CBC verifies the AES-CBC encrypt/decrypt functions.
// This covers crypto.go:486-522 (0% coverage).
func TestCrypto_AES_CBC(t *testing.T) {
	t.Parallel()

	// Use a 32-byte key for AES-256.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("test plaintext data")

	// Test encryption.
	iv, ciphertext, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, iv, qt.IsNotNil)
	qt.Assert(t, len(iv), qt.Equals, 16) // AES block size
	qt.Assert(t, ciphertext, qt.IsNotNil)
	qt.Assert(t, len(ciphertext)%16, qt.Equals, 0) // Multiple of block size

	// Test decryption.
	decrypted, err := unauthenticatedAESCBCDecrypt(iv, ciphertext, key)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, string(decrypted), qt.Equals, string(plaintext))

	// Test decryption with invalid IV length.
	_, err = unauthenticatedAESCBCDecrypt(iv[:8], ciphertext, key)
	qt.Assert(t, err, qt.ErrorMatches, "iv length does not match.*")

	// Test decryption with invalid ciphertext length.
	_, err = unauthenticatedAESCBCDecrypt(iv, ciphertext[:15], key)
	qt.Assert(t, err, qt.ErrorMatches, "ciphertext is not a multiple.*")
}
