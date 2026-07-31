// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
)

// TestItemKeyDecryptRoundTrip verifies that a cipher with a per-item key
// (cipher.Key = 64-byte random key encrypted with the base key) correctly
// decrypts fields encrypted with the item key halves.
func TestItemKeyDecryptRoundTrip(t *testing.T) {
	setupCacheTest(t)

	// Generate a random 64-byte item key.
	itemKey := make([]byte, 64)
	_, err := rand.Read(itemKey)
	qt.Assert(t, err, qt.IsNil)

	// Encrypt the item key with the base (vault) key.
	encItemKey, err := encryptWith(itemKey, AesCbc256_HmacSha256_B64, secrets.key, secrets.macKey)
	qt.Assert(t, err, qt.IsNil)

	// Encrypt a name and password with the item key halves.
	encName, err := encryptWith([]byte("item-key-cipher"), AesCbc256_HmacSha256_B64, itemKey[:32], itemKey[32:64])
	qt.Assert(t, err, qt.IsNil)
	encPassword, err := encryptWith([]byte("item-key-password"), AesCbc256_HmacSha256_B64, itemKey[:32], itemKey[32:64])
	qt.Assert(t, err, qt.IsNil)

	cipher := Cipher{
		Type: CipherLogin,
		ID:   uuid.New(),
		Key:  encItemKey,
		Name: encName,
		Login: &Login{
			Password: encPassword,
		},
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	// decryptFieldStr should use the item key, not the base key.
	name, err := secrets.decryptFieldStr(&cipher, cipher.Name)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, name, qt.Equals, "item-key-cipher")

	password, err := secrets.decryptFieldStr(&cipher, cipher.Login.Password)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, password, qt.Equals, "item-key-password")
}

// TestItemKeyFallbackToBaseKey verifies that a cipher with no item key
// (cipher.Key zero) falls back to the base key for decryption.
func TestItemKeyFallbackToBaseKey(t *testing.T) {
	setupCacheTest(t)

	cipher := Cipher{
		Type: CipherLogin,
		ID:   uuid.New(),
		Name: encryptStr(t, "base-key-cipher"),
		Login: &Login{
			Password: encryptStr(t, "base-key-password"),
		},
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	name, err := secrets.decryptFieldStr(&cipher, cipher.Name)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, name, qt.Equals, "base-key-cipher")

	password, err := secrets.decryptFieldStr(&cipher, cipher.Login.Password)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, password, qt.Equals, "base-key-password")
}

// TestFindCipherByName_NonLogin verifies that findCipherByName finds
// non-login ciphers (secure notes, SSH keys).
func TestFindCipherByName_NonLogin(t *testing.T) {
	setupCacheTest(t)

	note := Cipher{
		Type: CipherNote,
		ID:   uuid.New(),
		Name: encryptStr(t, "my-secure-note"),
		Notes: func() *CipherString {
			n := encryptStr(t, "secret notes")
			return &n
		}(),
	}
	sshKey := Cipher{
		Type: CipherSshKey,
		ID:   uuid.New(),
		Name: encryptStr(t, "my-ssh-key"),
		SshKey: &SshKey{
			PrivateKey: encryptStr(t, "priv"),
			PublicKey:  encryptStr(t, "pub"),
		},
	}
	globalData.Sync.Ciphers = []Cipher{note, sshKey}

	found, err := findCipherByName("my-secure-note")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, found.Type, qt.Equals, CipherNote)

	found, err = findCipherByName("my-ssh-key")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, found.Type, qt.Equals, CipherSshKey)
}

// TestGetJSON_Login verifies that --json emits the correct schema for a
// login cipher.
func TestGetJSON_Login(t *testing.T) {
	setupCacheTest(t)

	cipher := Cipher{
		Type:         CipherLogin,
		ID:           uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		RevisionDate: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		Name:         encryptStr(t, "test-login"),
		Login: &Login{
			Username: encryptStr(t, "user@example.com"),
			Password: encryptStr(t, "s3cr3t"),
			URI:      encryptStr(t, "https://example.com"),
		},
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdGet(context.Background(), []string{"--json", "test-login"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	var out jsonCipherOutput
	qt.Assert(t, json.Unmarshal(buf.Bytes(), &out), qt.IsNil)

	qt.Assert(t, out.Type, qt.Equals, CipherLogin)
	qt.Assert(t, out.ID, qt.Equals, "11111111-1111-1111-1111-111111111111")
	qt.Assert(t, out.Name, qt.Equals, "test-login")
	qt.Assert(t, out.Notes, qt.Equals, "")
	qt.Assert(t, out.RevisionDate, qt.Equals, "2026-01-15T12:00:00Z")
	qt.Assert(t, out.Login, qt.IsNotNil)
	qt.Assert(t, out.Login.Username, qt.Equals, "user@example.com")
	qt.Assert(t, out.Login.Password, qt.Equals, "s3cr3t")
	qt.Assert(t, out.Login.URI, qt.Equals, "https://example.com")
	qt.Assert(t, out.SshKey, qt.IsNil)
}

// TestGetJSON_SecureNote verifies that --json emits the correct schema for
// a secure note cipher.
func TestGetJSON_SecureNote(t *testing.T) {
	setupCacheTest(t)

	notes := encryptStr(t, "my secret notes content")
	cipher := Cipher{
		Type:         CipherNote,
		ID:           uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		RevisionDate: time.Date(2026, 2, 20, 10, 30, 0, 0, time.UTC),
		Name:         encryptStr(t, "test-note"),
		Notes:        &notes,
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdGet(context.Background(), []string{"--json", "test-note"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	var out jsonCipherOutput
	qt.Assert(t, json.Unmarshal(buf.Bytes(), &out), qt.IsNil)

	qt.Assert(t, out.Type, qt.Equals, CipherNote)
	qt.Assert(t, out.Name, qt.Equals, "test-note")
	qt.Assert(t, out.Notes, qt.Equals, "my secret notes content")
	qt.Assert(t, out.Login, qt.IsNil)
	qt.Assert(t, out.SshKey, qt.IsNil)
}

// TestGetJSON_SshKey verifies that --json emits the correct schema for an
// SSH key cipher.
func TestGetJSON_SshKey(t *testing.T) {
	setupCacheTest(t)

	cipher := Cipher{
		Type:         CipherSshKey,
		ID:           uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		RevisionDate: time.Date(2026, 3, 25, 8, 15, 0, 0, time.UTC),
		Name:         encryptStr(t, "test-ssh-key"),
		SshKey: &SshKey{
			PrivateKey: encryptStr(t, "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"),
			PublicKey:  encryptStr(t, "ssh-ed25519 AAAA... fake"),
		},
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdGet(context.Background(), []string{"--json", "test-ssh-key"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	var out jsonCipherOutput
	qt.Assert(t, json.Unmarshal(buf.Bytes(), &out), qt.IsNil)

	qt.Assert(t, out.Type, qt.Equals, CipherSshKey)
	qt.Assert(t, out.Name, qt.Equals, "test-ssh-key")
	qt.Assert(t, out.SshKey, qt.IsNotNil)
	qt.Assert(t, strings.Contains(out.SshKey.PrivateKey, "OPENSSH PRIVATE KEY"), qt.IsTrue)
	qt.Assert(t, strings.HasPrefix(out.SshKey.PublicKey, "ssh-ed25519"), qt.IsTrue)
	qt.Assert(t, out.Login, qt.IsNil)
}

// TestGetJSON_ItemKeyCipher verifies that --json correctly decrypts a cipher
// with a per-item key.
func TestGetJSON_ItemKeyCipher(t *testing.T) {
	setupCacheTest(t)

	// Generate a random 64-byte item key.
	itemKey := make([]byte, 64)
	_, err := rand.Read(itemKey)
	qt.Assert(t, err, qt.IsNil)

	// Encrypt the item key with the base key.
	encItemKey, err := encryptWith(itemKey, AesCbc256_HmacSha256_B64, secrets.key, secrets.macKey)
	qt.Assert(t, err, qt.IsNil)

	// Encrypt fields with the item key.
	encName, _ := encryptWith([]byte("item-key-note"), AesCbc256_HmacSha256_B64, itemKey[:32], itemKey[32:64])
	encNotes, _ := encryptWith([]byte("secret note content"), AesCbc256_HmacSha256_B64, itemKey[:32], itemKey[32:64])

	cipher := Cipher{
		Type:         CipherNote,
		ID:           uuid.New(),
		RevisionDate: time.Now().UTC(),
		Key:          encItemKey,
		Name:         encName,
		Notes:        &encNotes,
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = cmdGet(context.Background(), []string{"--json", "item-key-note"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	var out jsonCipherOutput
	qt.Assert(t, json.Unmarshal(buf.Bytes(), &out), qt.IsNil)

	qt.Assert(t, out.Name, qt.Equals, "item-key-note")
	qt.Assert(t, out.Notes, qt.Equals, "secret note content")
}

// mockEditServer spins up an httptest server that:
//   - responds to GET /sync with the current globalData.Sync.Ciphers
//   - captures PUT /ciphers/{id} into `putBody`
//   - responds to PUT /ciphers/{id} with the same cipher (echo)
func mockEditServer(t *testing.T, putBody *[]byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sync":
			_ = json.NewEncoder(w).Encode(SyncData{
				Profile: globalData.Sync.Profile,
				Ciphers: globalData.Sync.Ciphers,
			})
		case r.URL.Path == "/accounts/prelogin":
			_ = json.NewEncoder(w).Encode(preLoginResponse{
				KDF:            1,
				KDFIterations:  globalData.KDFIterations,
				KDFMemory:      globalData.KDFMemory,
				KDFParallelism: globalData.KDFParallelism,
			})
		case strings.HasPrefix(r.URL.Path, "/ciphers/"):
			*putBody, _ = readAll(r.Body)
			// Echo back the cipher.
			var c Cipher
			_ = json.Unmarshal(*putBody, &c)
			_ = json.NewEncoder(w).Encode(c)
		default:
			http.NotFound(w, r)
		}
	}))
	oldURL := apiURL
	apiURL = server.URL
	t.Cleanup(func() { apiURL = oldURL })
	return server
}

// TestCmdEdit_NotesUpdate verifies that cmdEdit updates the notes field and
// PUTs the re-encrypted cipher to /ciphers/{id}.
func TestCmdEdit_NotesUpdate(t *testing.T) {
	setupCacheTest(t)

	notes := encryptStr(t, "old notes")
	cipher := Cipher{
		Type:  CipherNote,
		ID:    uuid.New(),
		Name:  encryptStr(t, "edit-test-note"),
		Notes: &notes,
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	var putBody []byte
	server := mockEditServer(t, &putBody)
	defer server.Close()

	err := cmdEdit(context.Background(), []string{"--notes", "new notes", "edit-test-note"})
	qt.Assert(t, err, qt.IsNil)

	// Verify the PUT body contains the re-encrypted notes.
	var parsed map[string]interface{}
	qt.Assert(t, json.Unmarshal(putBody, &parsed), qt.IsNil)
	notesStr, ok := parsed["notes"].(string)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, strings.HasPrefix(notesStr, "2."), qt.IsTrue)

	// Decrypt the notes to verify.
	var cs CipherString
	qt.Assert(t, cs.UnmarshalText([]byte(notesStr)), qt.IsNil)
	decNotes, err := secrets.decryptFieldStr(&cipher, cs)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, decNotes, qt.Equals, "new notes")
}

// TestCmdEdit_PasswordUpdate verifies that cmdEdit updates the login password
// and rejects --password-stdin for non-login ciphers.
func TestCmdEdit_PasswordUpdate(t *testing.T) {
	setupCacheTest(t)

	cipher := Cipher{
		Type: CipherLogin,
		ID:   uuid.New(),
		Name: encryptStr(t, "edit-test-login"),
		Login: &Login{
			Password: encryptStr(t, "old-password"),
		},
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	oldStdin := stdinReadAll
	stdinReadAll = func() ([]byte, error) { return []byte("new-password\n"), nil }
	t.Cleanup(func() { stdinReadAll = oldStdin })

	var putBody []byte
	server := mockEditServer(t, &putBody)
	defer server.Close()

	err := cmdEdit(context.Background(), []string{"--password-stdin", "edit-test-login"})
	qt.Assert(t, err, qt.IsNil)

	// Verify the PUT body contains the re-encrypted password.
	var parsed map[string]interface{}
	qt.Assert(t, json.Unmarshal(putBody, &parsed), qt.IsNil)
	loginMap, ok := parsed["login"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	pwStr, ok := loginMap["password"].(string)
	qt.Assert(t, ok, qt.IsTrue)

	var cs CipherString
	qt.Assert(t, cs.UnmarshalText([]byte(pwStr)), qt.IsNil)
	decPw, err := secrets.decryptFieldStr(&cipher, cs)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, decPw, qt.Equals, "new-password")
}

// TestCmdEdit_PasswordOnNonLogin verifies that --password-stdin is rejected
// for non-login ciphers.
func TestCmdEdit_PasswordOnNonLogin(t *testing.T) {
	setupCacheTest(t)

	notes := encryptStr(t, "some notes")
	cipher := Cipher{
		Type:  CipherNote,
		ID:    uuid.New(),
		Name:  encryptStr(t, "edit-test-note"),
		Notes: &notes,
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	err := cmdEdit(context.Background(), []string{"--password-stdin", "edit-test-note"})
	qt.Assert(t, err, qt.ErrorMatches, "--password-stdin is only valid for login ciphers.*")
}

// TestCmdEdit_NoModifierFlags verifies that cmdEdit requires at least one
// modifier flag.
func TestCmdEdit_NoModifierFlags(t *testing.T) {
	setupCacheTest(t)

	err := cmdEdit(context.Background(), []string{"some-cipher"})
	qt.Assert(t, err, qt.ErrorMatches, "at least one of --notes, --password-stdin, or --field is required")
}

// TestCmdEdit_PreservesItemKey verifies that cmdEdit preserves the cipher's
// item key (cipher.Key) on the wire.
func TestCmdEdit_PreservesItemKey(t *testing.T) {
	setupCacheTest(t)

	// Generate a random 64-byte item key.
	itemKey := make([]byte, 64)
	_, err := rand.Read(itemKey)
	qt.Assert(t, err, qt.IsNil)

	// Encrypt the item key with the base key.
	encItemKey, err := encryptWith(itemKey, AesCbc256_HmacSha256_B64, secrets.key, secrets.macKey)
	qt.Assert(t, err, qt.IsNil)

	// Encrypt fields with the item key.
	encName, _ := encryptWith([]byte("item-key-login"), AesCbc256_HmacSha256_B64, itemKey[:32], itemKey[32:64])
	encPw, _ := encryptWith([]byte("old-pw"), AesCbc256_HmacSha256_B64, itemKey[:32], itemKey[32:64])

	cipher := Cipher{
		Type: CipherLogin,
		ID:   uuid.New(),
		Key:  encItemKey,
		Name: encName,
		Login: &Login{
			Password: encPw,
		},
	}
	globalData.Sync.Ciphers = []Cipher{cipher}

	oldStdin := stdinReadAll
	stdinReadAll = func() ([]byte, error) { return []byte("new-pw\n"), nil }
	t.Cleanup(func() { stdinReadAll = oldStdin })

	var putBody []byte
	server := mockEditServer(t, &putBody)
	defer server.Close()

	err = cmdEdit(context.Background(), []string{"--password-stdin", "item-key-login"})
	qt.Assert(t, err, qt.IsNil)

	// Verify the PUT body contains the cipher.Key (item key).
	var parsed map[string]interface{}
	qt.Assert(t, json.Unmarshal(putBody, &parsed), qt.IsNil)
	keyStr, ok := parsed["key"].(string)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, keyStr, qt.Equals, encItemKey.String())
}

// TestCmdCreate_Type2_SecureNote verifies that create --type 2 creates a
// secure note cipher.
func TestCmdCreate_Type2_SecureNote(t *testing.T) {
	setupCacheTest(t)

	globalData.AccessToken = "test-token"
	globalData.TokenExpiry = futureTime()

	var createdBody []byte
	server := mockCreateServer(t, nil, &createdBody, Cipher{
		ID:   uuid.New(),
		Type: CipherNote,
		Name: encryptStr(t, "test-note"),
	})
	defer server.Close()

	err := cmdCreate(context.Background(), []string{"--type", "2", "--notes", "my secret notes", "test-note"})
	qt.Assert(t, err, qt.IsNil)

	// Verify the POST body.
	var parsed map[string]interface{}
	qt.Assert(t, json.Unmarshal(createdBody, &parsed), qt.IsNil)
	cipherMap, ok := parsed["cipher"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, cipherMap["type"], qt.Equals, float64(CipherNote))

	notesStr, ok := cipherMap["notes"].(string)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, strings.HasPrefix(notesStr, "2."), qt.IsTrue)

	// Verify secureNote metadata.
	secureNoteMap, ok := cipherMap["secureNote"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, secureNoteMap["type"], qt.Equals, float64(0))
}

// TestCmdCreate_Type5_SshKey verifies that create --type 5 creates an SSH key
// cipher.
func TestCmdCreate_Type5_SshKey(t *testing.T) {
	setupCacheTest(t)

	globalData.AccessToken = "test-token"
	globalData.TokenExpiry = futureTime()

	oldStdin := stdinReadAll
	stdinReadAll = func() ([]byte, error) {
		return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"), nil
	}
	t.Cleanup(func() { stdinReadAll = oldStdin })

	var createdBody []byte
	server := mockCreateServer(t, nil, &createdBody, Cipher{
		ID:   uuid.New(),
		Type: CipherSshKey,
		Name: encryptStr(t, "test-ssh-key"),
	})
	defer server.Close()

	err := cmdCreate(context.Background(), []string{
		"--type", "5",
		"--ssh-private-key-stdin",
		"--ssh-public-key", "ssh-ed25519 AAAA... fake",
		"test-ssh-key",
	})
	qt.Assert(t, err, qt.IsNil)

	// Verify the POST body.
	var parsed map[string]interface{}
	qt.Assert(t, json.Unmarshal(createdBody, &parsed), qt.IsNil)
	cipherMap, ok := parsed["cipher"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, cipherMap["type"], qt.Equals, float64(CipherSshKey))

	sshKeyMap, ok := cipherMap["sshKey"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	privStr, ok := sshKeyMap["privateKey"].(string)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, strings.HasPrefix(privStr, "2."), qt.IsTrue)
	pubStr, ok := sshKeyMap["publicKey"].(string)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, strings.HasPrefix(pubStr, "2."), qt.IsTrue)
}

// TestCmdCreate_Type2_RequiresNotes verifies that create --type 2 requires
// --notes.
func TestCmdCreate_Type2_RequiresNotes(t *testing.T) {
	setupCacheTest(t)

	globalData.AccessToken = "test-token"
	globalData.TokenExpiry = futureTime()

	err := cmdCreate(context.Background(), []string{"--type", "2", "test-note"})
	qt.Assert(t, err, qt.ErrorMatches, "--notes is required for type 2.*")
}

// TestCmdCreate_Type5_RequiresSSHKeys verifies that create --type 5 requires
// both --ssh-private-key-stdin and --ssh-public-key.
func TestCmdCreate_Type5_RequiresSSHKeys(t *testing.T) {
	setupCacheTest(t)

	globalData.AccessToken = "test-token"
	globalData.TokenExpiry = futureTime()

	// Missing --ssh-private-key-stdin.
	err := cmdCreate(context.Background(), []string{"--type", "5", "--ssh-public-key", "pub", "test-ssh"})
	qt.Assert(t, err, qt.ErrorMatches, "--ssh-private-key-stdin is required for type 5.*")

	// Missing --ssh-public-key.
	oldStdin := stdinReadAll
	stdinReadAll = func() ([]byte, error) { return []byte("priv\n"), nil }
	t.Cleanup(func() { stdinReadAll = oldStdin })
	err = cmdCreate(context.Background(), []string{"--type", "5", "--ssh-private-key-stdin", "test-ssh"})
	qt.Assert(t, err, qt.ErrorMatches, "--ssh-public-key is required for type 5.*")
}
