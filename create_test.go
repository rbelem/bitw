// Copyright (c) 2019, Daniel Martí <mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
)

// decryptFieldStr is a test helper that decrypts a CipherString field using
// the already-initialized secrets (master key). Panics on error.
func decryptFieldStr(t *testing.T, cs CipherString, label string) string {
	t.Helper()
	s, err := secrets.decryptStr(cs, nil)
	if err != nil {
		t.Fatalf("decrypt %s: %v", label, err)
	}
	return s
}

// TestBuildLoginCipher_Basic verifies that a bare Login cipher (name +
// password, no notes, no custom fields) round-trips through encrypt +
// decrypt.
func TestBuildLoginCipher_Basic(t *testing.T) {
	setupCacheTest(t)

	body, err := buildLoginCipher("devbox-global/github-token", "", []byte("s3cr3t"), nil)
	qt.Assert(t, err, qt.IsNil)

	qt.Assert(t, body["type"], qt.Equals, CipherLogin)

	nameCS, ok := body["name"].(CipherString)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, decryptFieldStr(t, nameCS, "name"), qt.Equals, "devbox-global/github-token")

	loginMap, ok := body["login"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)

	pwCS, ok := loginMap["password"].(CipherString)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, decryptFieldStr(t, pwCS, "password"), qt.Equals, "s3cr3t")

	// username must be nil on the wire — the server's [EncryptedString]
	// validator rejects an empty string with "Username is not a valid
	// encrypted string" (matches what bw sends for an absent username).
	qt.Assert(t, loginMap["username"], qt.IsNil)

	// notes and fields should be absent when not provided.
	_, hasNotes := body["notes"]
	qt.Assert(t, hasNotes, qt.IsFalse)
	_, hasFields := body["fields"]
	qt.Assert(t, hasFields, qt.IsFalse)
}

// TestBuildLoginCipher_WithNotes verifies notes encryption + presence in body.
func TestBuildLoginCipher_WithNotes(t *testing.T) {
	setupCacheTest(t)

	body, err := buildLoginCipher("foo", "free tier key", []byte("bar"), nil)
	qt.Assert(t, err, qt.IsNil)

	notesCS, ok := body["notes"].(CipherString)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, decryptFieldStr(t, notesCS, "notes"), qt.Equals, "free tier key")
}

// TestBuildLoginCipher_WithCustomFields verifies that each custom field's
// name and value is encrypted, that fields are type 0 (text), and that the
// plaintext round-trips back correctly.
func TestBuildLoginCipher_WithCustomFields(t *testing.T) {
	setupCacheTest(t)

	fields := []fieldPair{
		{name: "OPENAI_BASE_URL", value: "https://api.openai.com/v1"},
		{name: "OPENAI_MODEL", value: "gpt-4o"},
	}
	body, err := buildLoginCipher("devbox-global/openai-api-key", "", []byte("sk-xxx"), fields)
	qt.Assert(t, err, qt.IsNil)

	encFields, ok := body["fields"].([]map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, len(encFields), qt.Equals, 2)

	for i, f := range fields {
		qt.Assert(t, encFields[i]["type"], qt.Equals, 0)

		nameCS, ok := encFields[i]["name"].(CipherString)
		qt.Assert(t, ok, qt.IsTrue)
		qt.Assert(t, decryptFieldStr(t, nameCS, "field name"), qt.Equals, f.name)

		valueCS, ok := encFields[i]["value"].(CipherString)
		qt.Assert(t, ok, qt.IsTrue)
		qt.Assert(t, decryptFieldStr(t, valueCS, "field value"), qt.Equals, f.value)
	}
}

// TestBytesTrimNewline covers the small trim helper.
func TestBytesTrimNewline(t *testing.T) {
	qt.Assert(t, string(bytesTrimNewline([]byte("hi"))), qt.Equals, "hi")
	qt.Assert(t, string(bytesTrimNewline([]byte("hi\n"))), qt.Equals, "hi")
	qt.Assert(t, string(bytesTrimNewline([]byte(""))), qt.Equals, "")
	qt.Assert(t, string(bytesTrimNewline(nil)), qt.Equals, "")
}

// TestCmdCreate_BadFieldFormat rejects --field without NAME=VALUE syntax
// before doing anything else (no API call, no prompt).
func TestCmdCreate_BadFieldFormat(t *testing.T) {
	setupCacheTest(t)

	cases := []struct{ name, field string }{
		{"missing equals", "noequals"},
		{"empty name", "=value"},
		{"empty value", "name="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cmdCreate(context.Background(), []string{"--field", tc.field, "ciph"})
			qt.Assert(t, err, qt.ErrorMatches, "--field must be NAME=VALUE.*")
		})
	}
}

// TestCmdCreate_MissingCipherName verifies the usage error.
func TestCmdCreate_MissingCipherName(t *testing.T) {
	setupCacheTest(t)

	err := cmdCreate(context.Background(), nil)
	qt.Assert(t, err, qt.ErrorMatches, "usage: bitw create.*")
}

// mockCreateServer spins up an httptest server that:
//
//   - responds to GET  /sync                    with a SyncData containing
//     the provided existing ciphers (so idempotency checks can simulate
//     pre-existing items in the vault)
//   - captures POST /ciphers/create              into `createdPOSTBody`
//   - responds to POST /ciphers/create           with a synthetic Cipher JSON
//
// `apiURL` is repointed at the test server for the duration of the test.
func mockCreateServer(t *testing.T, existingCiphers []Cipher, createdPOSTBody *[]byte, returnedCipher Cipher) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			_ = json.NewEncoder(w).Encode(SyncData{Ciphers: existingCiphers})
		case "/ciphers/create":
			*createdPOSTBody, _ = readAll(r.Body)
			_ = json.NewEncoder(w).Encode(returnedCipher)
		default:
			http.NotFound(w, r)
		}
	}))
	oldURL := apiURL
	apiURL = server.URL
	t.Cleanup(func() { apiURL = oldURL })
	return server
}

// readAll is a tiny helper to keep the body read compact.
func readAll(r interface {
	Read(p []byte) (n int, err error)
}) ([]byte, error) {
	buf := bytes.Buffer{}
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}

// TestCmdCreate_HappyPath verifies that cmdCreate POSTs the expected JSON
// shape to /ciphers/create, prompts for the secret via passwordPromptFunc,
// and prints the created cipher ID.
func TestCmdCreate_HappyPath(t *testing.T) {
	setupCacheTest(t)

	// Pre-set a known access token + future expiry so ensureToken() is a no-op.
	globalData.AccessToken = "test-token"
	globalData.TokenExpiry = futureTime()

	// Stub the password prompt to return a known secret.
	oldPrompt := passwordPromptFunc
	passwordPromptFunc = func(string) ([]byte, error) { return []byte("the-secret\n"), nil }
	t.Cleanup(func() { passwordPromptFunc = oldPrompt })

	returnedID := uuid.New()
	var createdBody []byte
	server := mockCreateServer(t, nil, &createdBody, Cipher{
		ID:   returnedID,
		Type: CipherLogin,
		Name: encryptStr(t, "devbox-global/github-token"),
	})
	defer server.Close()

	stderr := captureStderr(t, func() {
		err := cmdCreate(context.Background(), []string{
			"--field", "OPENAI_BASE_URL=https://x",
			"--field", "OPENAI_MODEL=gpt-4o",
			"devbox-global/github-token",
		})
		qt.Assert(t, err, qt.IsNil)
	})

	// Verify the POST body shape. /ciphers/create requires the cipher
	// wrapped in a top-level "cipher" key.
	var parsed map[string]interface{}
	qt.Assert(t, json.Unmarshal(createdBody, &parsed), qt.IsNil)
	cipherMap, ok := parsed["cipher"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, cipherMap["type"], qt.Equals, float64(CipherLogin))

	// Every string field on the request must be an encrypted cipher string
	// ("2.iv|ct|mac"), never plaintext. The plaintext round-trips elsewhere.
	nameStr, ok := cipherMap["name"].(string)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, strings.HasPrefix(nameStr, "2."), qt.IsTrue)
	qt.Assert(t, strings.Contains(nameStr, "devbox-global/github-token"), qt.IsFalse,
		qt.Commentf("name must be encrypted, got: %q", nameStr))

	loginMap, ok := cipherMap["login"].(map[string]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, loginMap["username"], qt.IsNil,
		qt.Commentf("username must be null on the wire, got: %v", loginMap["username"]))
	pwStr, ok := loginMap["password"].(string)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, strings.Contains(pwStr, "the-secret"), qt.IsFalse,
		qt.Commentf("password must be encrypted, got: %q", pwStr))

	fieldsArr, ok := cipherMap["fields"].([]interface{})
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, len(fieldsArr), qt.Equals, 2)
	for _, f := range fieldsArr {
		fmap := f.(map[string]interface{})
		qt.Assert(t, fmap["type"], qt.Equals, float64(0))
		// Field name + value should both be encrypted strings.
		qt.Assert(t, strings.HasPrefix(fmap["name"].(string), "2."), qt.IsTrue)
		qt.Assert(t, strings.HasPrefix(fmap["value"].(string), "2."), qt.IsTrue)
	}

	// Stderr should mention the created cipher.
	qt.Assert(t, strings.Contains(stderr, "Created devbox-global/github-token"), qt.IsTrue)
	qt.Assert(t, strings.Contains(stderr, "+ 2 custom field"), qt.IsTrue)
}

// TestCmdCreate_IdempotencyRefusal verifies that cmdCreate refuses if a
// cipher with the same name already exists (no API call to /ciphers/create
// is made).
func TestCmdCreate_IdempotencyRefusal(t *testing.T) {
	setupCacheTest(t)
	globalData.AccessToken = "test-token"
	globalData.TokenExpiry = futureTime()

	// Mock /sync to return a pre-existing cipher with the same name so
	// findCipherByName sees it and cmdCreate refuses.
	existing := testCipher(t, "devbox-global/github-token", "existing-password")
	var createdBody []byte
	server := mockCreateServer(t, []Cipher{existing}, &createdBody, Cipher{})
	defer server.Close()

	err := cmdCreate(context.Background(), []string{"devbox-global/github-token"})
	qt.Assert(t, err, qt.ErrorMatches, `cipher "devbox-global/github-token" already exists.*`)
	qt.Assert(t, createdBody, qt.IsNil, qt.Commentf("must not POST /ciphers/create when item exists"))
}

// TestCmdCreate_EmptySecret verifies that an empty prompted secret is
// rejected before any API call.
func TestCmdCreate_EmptySecret(t *testing.T) {
	setupCacheTest(t)
	globalData.AccessToken = "test-token"
	globalData.TokenExpiry = futureTime()

	oldPrompt := passwordPromptFunc
	passwordPromptFunc = func(string) ([]byte, error) { return []byte("\n"), nil }
	t.Cleanup(func() { passwordPromptFunc = oldPrompt })

	var createdBody []byte
	server := mockCreateServer(t, nil, &createdBody, Cipher{})
	defer server.Close()

	err := cmdCreate(context.Background(), []string{"new-cipher"})
	qt.Assert(t, err, qt.ErrorMatches, "empty secret.*")
	qt.Assert(t, createdBody, qt.IsNil)
}

// futureTime returns a time well in the future so ensureToken() sees the
// cached access token as still valid and skips re-auth.
func futureTime() time.Time {
	return time.Now().Add(time.Hour)
}
